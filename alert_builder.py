from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from schemas import (
    CanonicalAlert,
    CortexResult,
    HashBundle,
    Host,
    OSInfo,
    Observables,
    Rule,
)

# A value starting with http(s):// is always a URL regardless of what the
# ingest pipeline stamped as dataType — that field is a known
# mis-classification source.
URL_RE = re.compile(r"^https?://", re.IGNORECASE)

RULE_RE = re.compile(r"Rule:\s*(.+?)\s*\(([0-9a-fA-F-]{8,})\)")
HOST_RE = re.compile(r"Host:\s*(\S+)\s*\(([\d.]+)\)")
ENGINE_TAG_RE = re.compile(r"^engine:(\w+)", re.IGNORECASE)

# Keyed on event.module. Both "strelka" and "yara" map to the same profile
# since either name could show up depending on the deployment.
PROFILE_BY_ENGINE = {
    "suricata": "network_threat",
    "strelka": "malicious_file",
    "yara": "malicious_file",
    "sigma": "endpoint_behavior",
}

# The only taxonomy levels that count as a verdict. "info" and "safe" rows
# never appear in CortexResult.verdict — their absence means "nothing
# adverse reported". We don't parse detection ratios ("N/M") to derive a
# verdict independently of this label; see _summarize_taxonomies for why.
_ADVERSE_LEVELS = ("malicious", "suspicious")

_HASH_FIELDS = {"md5", "sha1", "sha256", "sha512", "imphash"}


def _as_dict(value: Any) -> dict:
    """Coerces a value to a dict, or {} if it isn't one. Some fields collide
    across sources (n8n's envelope has a top-level "source" string, which is
    a different thing from Suricata's "source" object), so this keeps every
    nested lookup safe instead of raising AttributeError."""
    return value if isinstance(value, dict) else {}


def _classify_observable_type(data_type: str, value: str) -> str:
    if URL_RE.match(value or ""):
        return "url"
    data_type = (data_type or "").lower()
    if data_type in ("ip", "ip-src", "ip-dst"):
        return "ip"
    if data_type == "fqdn":
        return "domain"
    return data_type


def _source_engine(raw_alert: dict) -> str:
    """Determines which detection engine produced this alert.

    event.module is the authoritative field. event.dataset is a fallback
    when module is absent (taking the segment before the first dot, e.g.
    "sigma.alert" -> "sigma"); type/tags are older fallbacks for
    non-standard callers. Note: ioc.source_engine is intentionally not used
    here — it's derived from event.module by an upstream pipeline, so it
    can never independently confirm it."""
    engine = (_as_dict(raw_alert.get("event")).get("module") or "").lower()
    if engine:
        return engine
    dataset = (_as_dict(raw_alert.get("event")).get("dataset") or "").lower()
    if dataset:
        return dataset.split(".", 1)[0]
    engine = (raw_alert.get("type") or "").lower()
    if engine:
        return engine
    for tag in raw_alert.get("tags", []) or []:
        if not isinstance(tag, str):
            continue
        m = ENGINE_TAG_RE.match(tag)
        if m:
            return m.group(1).lower()
    return "unknown"


def _parse_rule(raw_alert: dict, description: str) -> Rule:
    """Parses rule identity from the alert.

    Reads the top-level rule dict first (rule.name/rule.uuid — for Suricata
    the uuid is the SID, for YARA it equals the rule name), falling back to
    regexing the description or tags for non-standard payloads.

    Important: this must read raw_alert["rule"], never event_data.rule. A
    Sysmon event can carry its own internal rule object at that nested path
    (a sysmonconfig.xml RuleName tag) that has nothing to do with the fired
    Sigma rule — one real alert had event_data.rule.name == "T1183,IFEO"
    while the actual rule was "Potential Persistence Via GlobalFlags"."""
    rule_data = _as_dict(raw_alert.get("rule"))
    name = rule_data.get("name") or ""
    uuid = rule_data.get("uuid") or ""

    if not name:
        m = RULE_RE.search(description)
        if m:
            name, uuid = m.group(1).strip(), m.group(2).strip()
    if not name:
        for tag in raw_alert.get("tags", []) or []:
            if tag.lower().startswith("rule:"):
                name = tag.split(":", 1)[1].strip()
                break
    if not name:
        name = raw_alert.get("title", "") or "unknown"

    level = raw_alert.get("sigma_level") or _as_dict(raw_alert.get("event")).get(
        "severity_label"
    )

    return Rule(
        name=name,
        uuid=str(uuid) if uuid else "",
        native_severity=_native_severity(raw_alert),
        level=level,
        product=rule_data.get("product"),
        category=rule_data.get("category"),
        service=rule_data.get("service"),
    )


def _native_severity(raw_alert: dict) -> int:
    """event.severity is the normalized field across engines. Suricata's own
    rule.severity is inverted (1=highest) and pre-normalization, so it's not
    used here. Top-level severity is just a fallback for non-standard
    payloads."""
    value = raw_alert.get("severity")
    if isinstance(value, int):
        return value
    event_severity = _as_dict(raw_alert.get("event")).get("severity")
    if isinstance(event_severity, int):
        return event_severity
    return 2


def _parse_host(raw_alert: dict, description: str) -> Host | None:
    m = HOST_RE.search(description)
    if m:
        return Host(hostname=m.group(1), ip=[m.group(2)])
    for tag in raw_alert.get("tags", []) or []:
        if re.match(r"^[a-zA-Z0-9-]+$", tag) and "-" in tag and "engine:" not in tag and "rule:" not in tag:
            # Bare hostname-shaped tag (e.g. "win-kvkmd51ggkq") — best-effort fallback.
            return Host(hostname=tag)
    return None


def _as_list(value: Any) -> list:
    """ECS fields typed as arrays in the mapping are frequently emitted as a
    bare scalar when there's exactly one value (host.ip, related.ip, args...).
    Normalizes both shapes to a list so callers never branch on it."""
    if value is None:
        return []
    if isinstance(value, list):
        return [v for v in value if v is not None]
    return [value]


def _extract_os_info(host_data: dict) -> OSInfo | None:
    """Parses event_data.host.os.* into an OSInfo model, if present."""
    os_data = _as_dict(host_data.get("os"))
    if not os_data:
        return None
    return OSInfo(
        name=os_data.get("name"),
        family=os_data.get("family"),
        full=os_data.get("full"),
        platform=os_data.get("platform"),
        type=os_data.get("type"),
        version=os_data.get("version"),
        build=os_data.get("build"),
        kernel=os_data.get("kernel"),
    )


def _extract_host_from_event_data(event_data: dict) -> Host | None:
    """Parses host identity from event_data.host.*.

    host.ip is often absent on endpoint.events.process alerts even though
    it's a valid field; when that happens, the agent's IP is recovered from
    the Logstash beats-input metadata at
    event_data.metadata.input.beats.host.ip instead."""
    host_data = _as_dict(event_data.get("host"))
    hostname = host_data.get("hostname") or host_data.get("name")
    if not hostname:
        return None

    ips = _as_list(host_data.get("ip"))
    if not ips:
        beats_host = _as_dict(
            _as_dict(_as_dict(_as_dict(event_data.get("metadata")).get("input")).get("beats")).get("host")
        )
        ips = _as_list(beats_host.get("ip"))

    return Host(
        hostname=hostname,
        ip=ips,
        mac=_as_list(host_data.get("mac")),
        os=_extract_os_info(host_data),
        host_id=host_data.get("id"),
        architecture=host_data.get("architecture"),
    )


def _extract_winlog_host(event_data: dict) -> Host | None:
    """Parses host identity for the native Windows Event Log (winlog)
    channel, a different telemetry shape from the Elastic-Defend/Sysmon one
    _extract_host_from_event_data handles. These alerts carry
    event_data.winlog.computer_name instead of event_data.host.*."""
    winlog = _as_dict(event_data.get("winlog"))
    computer_name = winlog.get("computer_name")
    if not computer_name:
        return None
    return Host(hostname=computer_name)


def _parse_timestamp(raw_alert: dict) -> datetime:
    """Parses the alert's own timestamp. @timestamp (ISO8601) is the
    standard field; date (epoch milliseconds) is a fallback for
    non-standard payloads."""
    raw_ts = raw_alert.get("@timestamp")
    if isinstance(raw_ts, str):
        try:
            return datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
        except ValueError:
            pass
    date_ms = raw_alert.get("date")
    if isinstance(date_ms, (int, float)):
        return datetime.fromtimestamp(date_ms / 1000, tz=timezone.utc)
    return datetime.now(timezone.utc)


def _parse_event_timestamp(event_data: dict) -> datetime | None:
    """Parses when the underlying event happened (event_data.@timestamp),
    as opposed to when the alert fired — these can differ by days. Returns
    None rather than defaulting to now() so "unknown" isn't mistaken for
    "just happened"."""
    raw_ts = event_data.get("@timestamp")
    if isinstance(raw_ts, str):
        try:
            return datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def _build_observables(hive_alert: dict | None) -> Observables:
    """Builds the Observables model from hive_alert, since the raw alert
    document never carries an observables list — that's a TheHive concept,
    populated before /triage is ever called. IOCs are never parsed out of
    raw_alert directly."""
    external_ips: list[str] = []
    domains: list[str] = []
    urls: list[str] = []
    hashes = HashBundle()

    for obs in (hive_alert or {}).get("observables", []) or []:
        value = obs.get("data", "")
        if not value:
            continue
        obs_type = _classify_observable_type(obs.get("dataType", ""), value)

        if obs_type == "ip":
            external_ips.append(value)
        elif obs_type == "domain":
            domains.append(value)
        elif obs_type == "url":
            urls.append(value)
        elif obs_type == "hash":
            tag = next(
                (t.lower() for t in (obs.get("tags") or []) if t.lower() in _HASH_FIELDS),
                None,
            )
            if tag:
                getattr(hashes, tag).append(value)
            # Unrecognized hash tag: leave it out rather than guess the wrong
            # bucket — the LLM call can still reason about it via raw_alert.

    return Observables(external_ips=external_ips, domains=domains, urls=urls, hashes=hashes)


def _dedupe_taxonomies(taxonomies: list[dict]) -> list[dict]:
    """Analyzers routinely emit the same taxonomy row twice — the real payload
    for the xordump URL carries `VT:GetReport=3/97` and `VT:Scan=1/92` each
    exactly twice. Duplicates would double-weight a single datapoint."""
    seen: set[tuple] = set()
    unique: list[dict] = []
    for t in taxonomies or []:
        if not isinstance(t, dict):
            continue
        key = (t.get("namespace"), t.get("predicate"), t.get("value"), t.get("level"))
        if key not in seen:
            seen.add(key)
            unique.append(t)
    return unique


def _summarize_taxonomies(taxonomies: list[dict]) -> tuple[list[str], str]:
    """Turns an analyzer's taxonomy rows into a verdict label list plus a
    details string, without picking a single "correct" row or parsing
    detection ratios like "3/97" ourselves.

    We rely entirely on each row's own `level`, because a report can carry
    a context row that looks adverse alongside the real verdict row. For
    example, VirusTotal's report for github.com has one row saying
    "56 resolution(s)" (level: malicious) and another saying "0/91"
    (level: info) — the real clean result. Since a row genuinely says
    "malicious", this function reports it; `details` keeps both rows so the
    LLM can weigh the context against the actual detection ratio itself."""
    taxonomies = _dedupe_taxonomies(taxonomies)
    if not taxonomies:
        return [], ""

    details = "; ".join(
        f"{t.get('namespace')}:{t.get('predicate')}={t.get('value')} ({t.get('level')})"
        for t in taxonomies
    )
    verdict = sorted({
        t.get("level") for t in taxonomies if t.get("level") in _ADVERSE_LEVELS
    })
    return verdict, details


def _build_cortex_results(hive_alert: dict | None) -> tuple[list[CortexResult], dict[str, Any]]:
    cortex_results: list[CortexResult] = []
    observable_ids: dict[str, Any] = {}

    for obs in (hive_alert or {}).get("observables", []) or []:
        obs_id = obs.get("_id", "")
        obs_data = obs.get("data", "")
        obs_type = obs.get("dataType", "")
        if obs_id and obs_data:
            observable_ids[obs_data] = obs_id

        for analyzer_name, report in (obs.get("reports") or {}).items():
            if not isinstance(report, dict):
                continue
            # Handle both response shapes: TheHive's stock query API returns
            # report["taxonomies"] directly, while Cortex's own API nests it
            # under report["summary"]["taxonomies"].
            taxonomies = report.get("taxonomies")
            if taxonomies is None:
                taxonomies = _as_dict(report.get("summary")).get("taxonomies")
            if not taxonomies:
                continue
            verdict, details = _summarize_taxonomies(taxonomies)
            cortex_results.append(CortexResult(
                observable=obs_data,
                type=obs_type,
                verdict=verdict,
                details=details,
                analyzer=analyzer_name,
                raw=report,
            ))

    return cortex_results, observable_ids


def build_canonical_alert(
    raw_alert: dict,
    hive_alert: dict | None,
    thehive_alert_id: str = "",
) -> CanonicalAlert:
    """Builds a CanonicalAlert from a raw Security Onion alert plus its
    matching TheHive record. This is a deterministic structural pass, not
    an LLM step — it extracts rule and host identity plus observables, and
    attaches the raw alert body verbatim so the LLM call can read anything
    else (process, network, user, file, registry detail) directly from it.

    Host identity is extracted the same way for Sigma and Sysmon alerts
    (event_data carries the matched source event, in one of a few shapes
    depending on the log source), falling back to the native Windows
    Event Log shape when needed. Suricata and YARA/Strelka alerts carry no
    event_data and no host/user fields at all.

    Observables always come from hive_alert, never parsed out of the raw
    alert — raw alert documents don't carry an observables list at all.
    Every extractor degrades to None or empty on a missing field rather
    than raising."""
    description = raw_alert.get("description", "") or ""
    source_engine = _source_engine(raw_alert)
    event_data = _as_dict(raw_alert.get("event_data"))

    cortex_results, observable_ids = _build_cortex_results(hive_alert)
    observables = _build_observables(hive_alert)

    host = (
        _extract_host_from_event_data(event_data)
        or _extract_winlog_host(event_data)
        or _parse_host(raw_alert, description)
    )

    inner_event = _as_dict(event_data.get("event"))
    # Sigma's matched event is nested (event_data.event.dataset); Suricata/YARA
    # have no event_data at all and carry the equivalent one level up, at
    # raw_alert.event.dataset (e.g. "suricata.alert") — the same top-level
    # object _source_engine() already reads for engine detection. Nested wins
    # when both somehow exist.
    top_level_event = _as_dict(raw_alert.get("event"))

    return CanonicalAlert(
        alert_id=(
            thehive_alert_id
            or raw_alert.get("sourceRef", "")
            or raw_alert.get("_id", "")
            or raw_alert.get("title", "unknown")
        ),
        timestamp=_parse_timestamp(raw_alert),
        event_timestamp=_parse_event_timestamp(event_data),
        source_engine=source_engine,
        investigation_profile=PROFILE_BY_ENGINE.get(source_engine, "generic"),
        event_dataset=inner_event.get("dataset") or top_level_event.get("dataset"),
        risk_score=inner_event.get("risk_score"),
        rule=_parse_rule(raw_alert, description),
        host=host,
        observables=observables,
        cortex_results=cortex_results,
        raw_alert=raw_alert,
        thehive_alert_id=thehive_alert_id,
        thehive_observable_ids=observable_ids,
    )
