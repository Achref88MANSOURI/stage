"""`detection_rule_lookup` — fetches the detection rule that fired from the
Security Onion `so-detection` Elasticsearch index, and parses its original
rule content for the MITRE ATT&CK metadata the triage LLM needs.

Four things about the real backend that aren't obvious from the index shape
alone:

1. The index must be `so-detection` EXACTLY. The `so-detection*` wildcard
   also matches `so-detectionhistory` — hundreds of thousands of revision
   documents alongside the current rule set — so a wildcard query can return
   a superseded rule version.
2. `so_detection.language` is the rule language ("sigma", "suricata",
   "yara"); `so_detection.engine` is the *execution* engine (e.g.
   "elastalert"). `source_engine` comes from `language` — reading `engine`
   would send every rule down the wrong parse branch.
3. Doc-level `so_detection.tags` is `null`. MITRE lives only inside
   `so_detection.content`, the original pre-compilation rule text (Sigma
   YAML or Suricata's inline rule syntax) — the compiled/indexed rule strips
   it, so that content field must be parsed directly.
4. `falsepositives` is commonly the literal `["Unknown"]` — Sigma's
   placeholder for "none documented", not an actual false-positive
   condition.

Suricata rules arrive with `language="suricata"` and a `content` field that
is raw Suricata rule syntax, not YAML — `_parse_suricata_content` handles
that branch, pulling MITRE metadata out of the rule's inline `metadata:`
clause when one is present (roughly half of real Suricata rules carry one;
the rest legitimately have no ATT&CK mapping at all).

YARA rules (`language="yara"`) are not parsed for MITRE metadata: their
`meta:` block carries `author`/`description`/`reference`/`date`/`score`/hash
fields, never an ATT&CK reference, so there is nothing to extract.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time

import yaml

import config
from schemas import (
    Gap,
    LogSource,
    RuleContext,
    has_known_falsepositives,
    has_reliable_status,
)
from tools.es_client import describe_http_error, es_search

logger = logging.getLogger(__name__)

TOOL_NAME = "detection_rule_lookup"
SOURCE = "so-detection"

# ATT&CK technique ids as Sigma writes them: `attack.t1105`, `attack.t1059.001`.
_TECHNIQUE_RE = re.compile(r"^t\d{4}(?:\.\d{3})?$", re.IGNORECASE)
_GROUP_RE = re.compile(r"^g\d{4}$", re.IGNORECASE)
_SOFTWARE_RE = re.compile(r"^s\d{4}$", re.IGNORECASE)

# Suricata's `metadata:` clause is a single rule option among several
# semicolon-separated ones (`msg:...; content:...; classtype:...; sid:...;
# metadata:key val, key2 val2, ...;)`). Values are single underscore-joined
# tokens with no embedded commas or semicolons in every real rule inspected,
# so "up to the next `;`" is a safe, sufficient boundary — no need to parse
# the full rule grammar.
_SURICATA_METADATA_RE = re.compile(r"\bmetadata:\s*([^;]*)")

# Suricata's own severity vocabulary (`signature_severity`), distinct from
# Sigma's low/medium/high/critical. Mapped onto the same lowercase scale
# RuleContext.level otherwise carries so downstream code doesn't need to
# special-case the source engine. These four values cover the large majority
# of real Suricata rules with a signature_severity key; a rule with some
# other/malformed value falls through to the lowercased raw string.
_SURICATA_SEVERITY_MAP = {
    "informational": "informational",
    "minor": "low",
    "major": "high",
    "critical": "critical",
}


def _normalise_sigma_tags(tags: list) -> dict[str, list[str]]:
    """Split a Sigma `tags:` list into typed buckets.

    Sigma tags are lowercase and dotted. Real examples from the live rule and
    the wider Sigma ruleset:

        attack.t1105              -> technique  T1105
        attack.t1059.001          -> technique  T1059.001
        attack.command-and-control-> tactic     command-and-control
        attack.g0016             -> group      G0016
        attack.s0002             -> software   S0002
        cve.2021-44228           -> other
        car.2013-05-002          -> other

    Technique ids are upper-cased to the canonical ATT&CK form because that is
    what the Qdrant `mitre_techniques` payloads and the triage LLM's output
    schema both use. Tactic names are left in Sigma's hyphenated lowercase form,
    which matches ATT&CK's own shortname (`command-and-control`).

    Anything unrecognised lands in `other` rather than being discarded.
    """
    buckets: dict[str, list[str]] = {
        "techniques": [],
        "tactics": [],
        "groups": [],
        "software": [],
        "other": [],
    }
    for tag in tags or []:
        if not isinstance(tag, str):
            continue
        tag = tag.strip()
        if not tag:
            continue
        namespace, _, remainder = tag.partition(".")
        if namespace.lower() != "attack" or not remainder:
            buckets["other"].append(tag)
            continue
        if _TECHNIQUE_RE.match(remainder):
            buckets["techniques"].append(remainder.upper())
        elif _GROUP_RE.match(remainder):
            buckets["groups"].append(remainder.upper())
        elif _SOFTWARE_RE.match(remainder):
            buckets["software"].append(remainder.upper())
        else:
            buckets["tactics"].append(remainder.lower())

    for key, values in buckets.items():
        seen: set[str] = set()
        buckets[key] = [v for v in values if not (v in seen or seen.add(v))]
    return buckets


def _as_str_list(value) -> list[str]:
    """Sigma fields that are lists are routinely authored as a bare string when
    there is one entry (`falsepositives: Unknown`)."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value if v is not None]
    return [str(value)]


def _parse_sigma_content(content: str, context: RuleContext) -> None:
    """Parse the original Sigma YAML in-place onto `context`.

    `yaml.safe_load` only — the content is rule text from a community ruleset
    and must never be able to construct Python objects.

    A parse failure is recorded on `content_parse_error` and left non-fatal:
    the doc-level fields (title, severity, description, product, category)
    have already populated, so the rule is still usable, just without MITRE
    grounding from this source — RAG retrieval against the MITRE technique
    corpus covers that gap downstream.
    """
    try:
        parsed = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        context.content_parse_error = f"YAML parse failed: {str(exc)[:200]}"
        return

    if not isinstance(parsed, dict):
        context.content_parse_error = (
            f"Sigma content parsed to {type(parsed).__name__}, expected a mapping"
        )
        return

    buckets = _normalise_sigma_tags(_as_str_list(parsed.get("tags")))
    context.mitre_attack = buckets["techniques"]
    context.mitre_tactics = buckets["tactics"]
    context.mitre_groups = buckets["groups"]
    context.mitre_software = buckets["software"]
    context.other_tags = buckets["other"]

    context.level = parsed.get("level") or context.level
    context.status = parsed.get("status") or context.status
    context.has_reliable_status = has_reliable_status(context.status)
    context.references = _as_str_list(parsed.get("references"))

    falsepositives = _as_str_list(parsed.get("falsepositives"))
    context.falsepositives = falsepositives
    context.has_known_falsepositives = has_known_falsepositives(falsepositives)

    logsource = parsed.get("logsource")
    if isinstance(logsource, dict):
        context.logsource = LogSource(
            category=logsource.get("category"),
            product=logsource.get("product"),
            service=logsource.get("service"),
            definition=logsource.get("definition"),
        )

    # The YAML description is the authored one; the doc-level field is a copy
    # that Security Onion may have truncated. Prefer the YAML when present.
    if parsed.get("description"):
        context.description = parsed["description"]
    if parsed.get("title"):
        context.title = parsed["title"]


def _parse_suricata_content(content: str, context: RuleContext) -> None:
    """Parse a Suricata rule's inline `metadata:` clause in-place onto
    `context`.

    Real clause shape, verbatim from a live rule:
    `metadata:attack_target Client_Endpoint, created_at 2010_07_30, deployment
    Perimeter, signature_severity Minor, updated_at 2024_03_15, mitre_tactic_id
    TA0009, mitre_tactic_name Collection, mitre_technique_id T1005,
    mitre_technique_name Data_from_local_system;`

    `mitre_technique_id` feeds `mitre_attack` (the same list Sigma populates,
    so downstream code never needs to know which engine a technique came
    from). `mitre_tactic_name` feeds `mitre_tactics`, normalised to ATT&CK's
    own hyphenated-lowercase shortname convention (`Defense_Evasion` ->
    `defense-evasion`) for the same reason. Everything else Suricata's
    metadata carries (`mitre_tactic_id`, `mitre_technique_name`,
    `attack_target`, `deployment`, `created_at`, `updated_at`, and any future
    key) has no typed field of its own, so it lands in `other_tags` labeled
    `key:value` rather than being discarded — the same "no typed home yet"
    convention `_normalise_sigma_tags` uses for unrecognised Sigma tags.

    The absence of a `metadata:` clause is not an error: a large share of
    real Suricata rules have no MITRE mapping at all, and that's a
    legitimate, common shape, not a parse failure — `content_parse_error` is
    set only when the clause itself can't be found, so downstream code can
    distinguish "this rule genuinely carries no ATT&CK metadata" from
    "something about this content didn't parse".
    """
    match = _SURICATA_METADATA_RE.search(content)
    if not match:
        context.content_parse_error = "No metadata: clause found in Suricata rule text"
        return

    techniques: list[str] = []
    tactics: list[str] = []
    other: list[str] = []
    severity_value: str | None = None

    for entry in match.group(1).split(","):
        entry = entry.strip()
        if not entry or " " not in entry:
            continue
        key, _, value = entry.partition(" ")
        key, value = key.strip(), value.strip()
        if not key or not value:
            continue
        if key == "mitre_technique_id":
            techniques.append(value)
        elif key == "mitre_tactic_name":
            tactics.append(value.lower().replace("_", "-"))
        elif key == "signature_severity":
            severity_value = value
        else:
            other.append(f"{key}:{value}")

    def _dedupe(values: list[str]) -> list[str]:
        seen: set[str] = set()
        return [v for v in values if not (v in seen or seen.add(v))]

    context.mitre_attack = _dedupe(techniques)
    context.mitre_tactics = _dedupe(tactics)
    context.other_tags = other

    if severity_value and not context.level:
        context.level = _SURICATA_SEVERITY_MAP.get(severity_value.lower(), severity_value.lower())


def _build_rule_context(rule_uuid: str, document: dict) -> RuleContext:
    """Map a raw `so_detection` document onto RuleContext — see this module's
    docstring for the real field names and their quirks."""
    context = RuleContext(
        found=True,
        rule_uuid=document.get("publicId") or rule_uuid,
        title=document.get("title"),
        description=document.get("description"),
        author=document.get("author"),
        source_engine=(document.get("language") or "").lower() or None,
        execution_engine=(document.get("engine") or "").lower() or None,
        severity=document.get("severity"),
        is_enabled=document.get("isEnabled"),
        is_reporting=document.get("isReporting"),
        is_community=document.get("isCommunity"),
        ruleset=document.get("ruleset"),
        license=document.get("license"),
        source_created=document.get("sourceCreated"),
        source_updated=document.get("sourceUpdated"),
    )

    # Doc-level category/product are the fallback for logsource when the YAML
    # has no logsource block or fails to parse.
    if document.get("category") or document.get("product") or document.get("service"):
        context.logsource = LogSource(
            category=document.get("category"),
            product=document.get("product"),
            service=document.get("service"),
        )

    content = document.get("content")
    if isinstance(content, str) and content.strip():
        language = (document.get("language") or "").lower()
        if language == "sigma":
            _parse_sigma_content(content, context)
        elif language == "suricata":
            _parse_suricata_content(content, context)
        # yara: no MITRE parser — content_parse_error is deliberately NOT set
        # here (the content itself is real and present, there's just no
        # ATT&CK metadata in a YARA rule's meta: block to extract).
    else:
        context.content_parse_error = "so_detection.content was empty or absent"

    return context


async def detection_rule_lookup(
    rule_uuid: str, timeout: float | None = None
) -> tuple[RuleContext, Gap | None]:
    """Look up a detection rule by its uuid. Never raises.

    Returns `(RuleContext, Gap | None)`:

    - found        -> `(populated RuleContext, None)`
    - not in index -> `(RuleContext(found=False), Gap)` — a real, valid result,
                      not a failure. A rule can legitimately be absent (deleted,
                      or an alert from a ruleset since removed), and that is
                      different from the backend being unreachable, so the Gap
                      reason distinguishes them.
    - backend fail -> `(RuleContext(found=False), Gap)` with the transport error

    The caller also wraps this in its own timeout — this tool's internal
    timeout bounds the HTTP call, the caller's bounds total wall time
    including event-loop scheduling. Both are intentional.
    """
    timeout = timeout if timeout is not None else config.STAGE_1_TOOL_TIMEOUT_ES
    started = time.monotonic()

    def elapsed_ms() -> int:
        return int((time.monotonic() - started) * 1000)

    if not rule_uuid:
        return RuleContext(found=False), Gap(
            source=SOURCE,
            tool=TOOL_NAME,
            reason="No rule uuid on the alert — nothing to look up",
            duration_ms=elapsed_ms(),
        )

    body = {
        "size": 1,
        "query": {"term": {"so_detection.publicId": rule_uuid}},
        # Newest first, so that if the index ever holds more than one document
        # for a publicId we take the current one rather than an arbitrary hit.
        "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
    }

    try:
        payload = await asyncio.wait_for(
            es_search(config.ES_DETECTION_INDEX, body, timeout=timeout),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        logger.warning("%s timed out after %.1fs for %s", TOOL_NAME, timeout, rule_uuid)
        return RuleContext(found=False, rule_uuid=rule_uuid), Gap(
            source=SOURCE,
            tool=TOOL_NAME,
            reason=f"Timeout after {timeout}s querying {config.ES_DETECTION_INDEX}",
            duration_ms=elapsed_ms(),
        )
    except Exception as exc:  # noqa: BLE001 — a tool must never raise into gather
        logger.warning("%s failed for %s: %s", TOOL_NAME, rule_uuid, exc)
        return RuleContext(found=False, rule_uuid=rule_uuid), Gap(
            source=SOURCE,
            tool=TOOL_NAME,
            reason=describe_http_error(exc),
            duration_ms=elapsed_ms(),
        )

    hits = (payload.get("hits") or {}).get("hits") or []
    if not hits:
        return RuleContext(found=False, rule_uuid=rule_uuid), Gap(
            source=SOURCE,
            tool=TOOL_NAME,
            reason=(
                f"No document in {config.ES_DETECTION_INDEX} with "
                f"so_detection.publicId={rule_uuid}"
            ),
            duration_ms=elapsed_ms(),
        )

    document = (hits[0].get("_source") or {}).get("so_detection")
    if not isinstance(document, dict):
        return RuleContext(found=False, rule_uuid=rule_uuid), Gap(
            source=SOURCE,
            tool=TOOL_NAME,
            reason="Hit had no so_detection object — unexpected document shape",
            duration_ms=elapsed_ms(),
        )

    try:
        return _build_rule_context(rule_uuid, document), None
    except Exception as exc:  # noqa: BLE001
        logger.warning("%s could not map document for %s: %s", TOOL_NAME, rule_uuid, exc)
        return RuleContext(found=False, rule_uuid=rule_uuid), Gap(
            source=SOURCE,
            tool=TOOL_NAME,
            reason=f"Document mapping failed: {type(exc).__name__}: {exc}",
            duration_ms=elapsed_ms(),
        )
