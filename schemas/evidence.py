"""Gathered and RAG-enriched evidence boundary models.

`RawEvidence` is the gather stage's output; `EnrichedEvidence` adds RAG
context on top of it. Every evidence field is either populated or paired
with a `Gap` explaining why not, so "checked, found nothing" and "couldn't
check" are always distinguishable.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from schemas.alert import CanonicalAlert

# Sigma's placeholder values for "no false positives documented". A rule whose
# entire falsepositives list is placeholders has no real FP guidance, and
# feeding "Unknown" to the triage LLM as though it were an FP condition
# invites the model to reason about a false positive literally named
# "Unknown".
FALSEPOSITIVE_PLACEHOLDERS = {"unknown", "none", "unlikely", "n/a", "na", ""}


class Gap(BaseModel):
    """An explicit record of evidence that could not be gathered, and why.

    Every gap has a concrete reason — `Gap(source="itop",
    reason="Connection timeout after 5s")`, never `reason="unknown"`.
    """

    source: str
    reason: str
    tool: str | None = None
    duration_ms: int | None = None


class LogSource(BaseModel):
    """Sigma `logsource:` block. Also available as doc-level `so_detection.
    {category, product, service}` on the so-detection document — the YAML is
    authoritative, the doc-level fields are the fallback."""

    category: str | None = None
    product: str | None = None
    service: str | None = None
    definition: str | None = None


class RuleContext(BaseModel):
    """`detection_rule_lookup` output — metadata for the rule that fired.

    `source_engine` comes from the document's `language` field ("sigma"),
    not its `engine` field (the execution engine, e.g. "elastalert") —
    picking the wrong one would send every rule down the wrong parse
    branch. MITRE tags aren't on the document itself; they live inside the
    `content` field, the original pre-compilation Sigma YAML, as a single
    `tags:` list mixing techniques, tactics, groups and software, parsed
    and normalised here (`attack.t1105` -> `T1105`). `falsepositives` is
    often the literal `["Unknown"]`, Sigma's placeholder for "none
    documented" — `has_known_falsepositives` is the derived boolean
    downstream code reads; the raw list is kept for audit.
    """

    found: bool = False
    rule_uuid: str = ""

    # Identity
    title: str | None = None
    description: str | None = None
    author: str | None = None

    # Engine — see quirk 1 above
    source_engine: str | None = None
    execution_engine: str | None = None

    # Severity. `severity` is the so-detection doc field, `level` the Sigma
    # YAML one. They can agree but are distinct sources — both are kept.
    severity: str | None = None
    level: str | None = None

    # Maturity: Sigma `status:` — stable/test/experimental/deprecated/unsupported.
    # An experimental rule is more likely to be a false positive than a
    # stable one, and unlike get_fp_signal (which needs weeks of triage
    # history to say anything), this signal is available from the first
    # alert. has_reliable_status is the derived boolean downstream code
    # reads; the raw string is kept for audit. False covers both "below
    # stable" and "no status declared".
    status: str | None = None
    has_reliable_status: bool = False

    # Sigma's `tags:` list mixes more than techniques and tactics — it can
    # also carry ATT&CK group ids, software ids, CVE refs, and CAR analytics.
    # Each gets its own bucket rather than being forced into mitre_tactics.
    mitre_attack: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_groups: list[str] = Field(default_factory=list)
    mitre_software: list[str] = Field(default_factory=list)
    other_tags: list[str] = Field(default_factory=list)

    falsepositives: list[str] = Field(default_factory=list)
    has_known_falsepositives: bool = False

    logsource: LogSource | None = None
    references: list[str] = Field(default_factory=list)

    # Operational state. A disabled rule that somehow produced an alert, or a
    # non-reporting one, is worth surfacing rather than silently ignoring.
    is_enabled: bool | None = None
    is_reporting: bool | None = None
    is_community: bool | None = None
    ruleset: str | None = None
    license: str | None = None

    source_created: datetime | None = None
    source_updated: datetime | None = None

    # Set when the `content` field was present but did not parse as YAML. The
    # doc-level fields still populate, so a parse failure degrades the MITRE
    # mapping without losing the rest of the rule metadata.
    content_parse_error: str | None = None


class FPSignal(BaseModel):
    """`get_fp_signal` output — a per-rule false-positive history count, see
    `tools/fp_tracking.py`'s module docstring.

    Counts, not rates: `record_triage_outcome` only ever writes a row when an
    alert closes as `false_positive` (never on a true-positive close), so
    `fp_count / total_count` has no valid denominator. The count itself is
    the signal here, deliberately not normalized to 0.0-1.0."""

    rule_fp_count_24h: int = 0
    rule_fp_count_30d: int = 0


class OpenCTIRelation(BaseModel):
    """One STIX relationship from an OpenCTI indicator/observable to a related
    entity (malware, intrusion-set, threat-actor, campaign, ...). Graph
    context only — no score, no verdict label invented here."""

    relationship_type: str
    related_entity_type: str | None = None
    related_entity_name: str | None = None


class OpenCTIEnrichment(BaseModel):
    """`opencti_observable_enrichment` output (`tools/opencti.py`).

    Confirms whether an observable is a known indicator in OpenCTI's threat
    graph, and what it's related to. Distinct from the OpenCTI Cortex
    analyzer's taxonomy rows, which arrive separately via `CortexResult` —
    this is a direct GraphQL query for graph relationships, not an analyzer
    verdict.

    `found=False` with no `Gap` is a meaningful result on its own: the
    observable was checked and OpenCTI simply has no record of it, not a
    failure to look."""

    observable: str
    found: bool = False
    entity_type: str | None = None
    indicator_names: list[str] = Field(default_factory=list)
    # OpenCTI's own x_opencti_score, passed through verbatim, never computed
    # here — foreign data, same treatment as CortexResult.raw.
    opencti_score: int | None = None
    labels: list[str] = Field(default_factory=list)
    marking: list[str] = Field(default_factory=list)
    relations: list[OpenCTIRelation] = Field(default_factory=list)


class ShallowCase(BaseModel):
    """A TheHive case summary, kept deliberately shallow — the triage LLM
    judges merge/new from these without needing the full case body.

    `stage` and `status` are separate enumerations: `stage` is the case's
    lifecycle position (New/InProgress/Closed), `status` is its resolution
    (New/InProgress/TruePositive/FalsePositive/Duplicated/Indeterminate/
    Other). "Open" means `stage != "Closed"` — there's no "Closed" value in
    `status`, so filtering on the wrong field silently matches everything.

    `similar_observable_count` comes from TheHive's native `getAlert ->
    similarCases` query (`tools/thehive.py::_fetch_similar_cases`), the
    source of every `ShallowCase` this model produces.
    """

    case_id: str
    case_number: int | None = None
    title: str = ""
    severity: int | None = None
    stage: str | None = None
    status: str | None = None
    tags: list[str] = Field(default_factory=list)
    created_at: datetime | None = None
    observables: list[str] = Field(default_factory=list)
    similar_observable_count: int | None = None


class AssetContext(BaseModel):
    """`itop_asset_lookup` output.

    `criticality is None` with `found=True` means the asset exists in the
    CMDB but has no criticality assigned — a distinct, meaningful state from
    "asset not found at all". Several fields here (`network_zone`,
    `data_sensitivity`, `owner`, `asset_number`) may be unpopulated or
    unavailable depending on which iTop extensions and custom attributes are
    installed; that's a CMDB data question, not a code one, and the fields
    stay in the model so that populating them later needs no schema change.
    `ip_addresses` is empty whenever the instance has no IP data at all, in
    which case hostname is the only usable lookup key.
    """

    found: bool = False
    hostname: str | None = None

    # iTop's attribute is `business_criticity` (its spelling). Values are
    # low / medium / high. This tool returns the raw label; any
    # criticality -> numeric mapping is a downstream concern, not here.
    criticality: str | None = None

    owner: str | None = None
    organization: str | None = None
    services: list[str] = Field(default_factory=list)
    network_zone: str | None = None
    data_sensitivity: list[str] = Field(default_factory=list)
    asset_type: str | None = None
    ip_addresses: list[str] = Field(default_factory=list)

    # Identity and join keys.
    # `asset_number` holds the Elastic Agent host UUID and is tried FIRST as
    # a join key when populated — strictly better than hostname, which is
    # case-sensitive in OQL `=` and breaks on FQDN vs short name. Falls back
    # to hostname when asset_number isn't populated on the instance — see
    # the class docstring above and `tools/itop.py`.
    asset_number: str | None = None
    itop_class: str | None = None
    itop_id: str | None = None
    matched_by: str | None = None  # "asset_number" | "hostname"

    # Operational context that iTop does populate.
    status: str | None = None
    os_family: str | None = None
    os_version: str | None = None
    location: str | None = None
    obsolete: bool | None = None


class RawEvidence(BaseModel):
    """Gather-stage output.

    Optional fields mean "not gathered"; a corresponding entry in
    `investigation_gaps` says why. Empty lists are valid populated values and
    do NOT imply a gap.
    """

    canonical_alert: CanonicalAlert
    fp_signal: FPSignal | None = None
    rule_context: RuleContext | None = None
    open_cases: list[ShallowCase] = Field(default_factory=list)
    asset_context: AssetContext | None = None
    # Empty list is a real, checked-and-empty result, same convention as the
    # other gather-stage outputs on this model.
    opencti_enrichment: list[OpenCTIEnrichment] = Field(default_factory=list)
    investigation_gaps: list[Gap] = Field(default_factory=list)
    stage_1_duration_ms: int = 0

    @property
    def cortex_results(self):
        """Cortex reports are already on the CanonicalAlert, put there by
        alert_builder from hive_alert.observables[].reports — the gather
        stage never fetches them itself. Exposed here so downstream code
        reads one object."""
        return self.canonical_alert.cortex_results


class MitreCandidate(BaseModel):
    """A `mitre_techniques` Qdrant hit (697 points, 1024-dim Cosine, at
    `config.QDRANT_URL`). `tactic` is a list, not a single string — a
    technique can belong to more than one tactic."""

    technique_id: str
    technique_name: str = ""  # payload key is `name` — mapped in tools/qdrant.py
    tactic: list[str] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)
    is_sub_technique: bool = False
    parent_technique_id: str | None = None
    x_mitre_version: str | None = None
    detection_strategy_id: str | None = None
    analytic_ids: list[str] = Field(default_factory=list)
    log_sources: list[str] = Field(default_factory=list)
    score: float = 0.0


class EnrichedEvidence(RawEvidence):
    """Gathered evidence plus RAG context. Subclasses `RawEvidence` rather
    than re-declaring its fields, so a field added upstream can't silently
    go missing here. Carries only `mitre_candidates`, the RAG retrieval
    that grounds the triage call's MITRE reasoning against a real technique
    corpus.
    """

    mitre_candidates: list[MitreCandidate] = Field(default_factory=list)
    stage_2_duration_ms: int = 0


def has_reliable_status(status: str | None) -> bool:
    """True only for a Sigma rule explicitly marked `stable` — the only
    status value that means the rule has been vetted in production. A
    missing status is treated as unreliable."""
    return isinstance(status, str) and status.strip().lower() == "stable"


def has_known_falsepositives(entries: list[str] | None) -> bool:
    """True when the list contains at least one entry that is not a Sigma
    placeholder. See RuleContext difference 3."""
    for entry in entries or []:
        if isinstance(entry, str) and entry.strip().lower() not in FALSEPOSITIVE_PLACEHOLDERS:
            return True
    return False
