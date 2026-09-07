"""Stage 0 boundary models: the raw n8n webhook payload and the CanonicalAlert
that every later stage reads.

Field coverage is derived from three sources of ground truth, never from guesses:

1. `sigma-alert-sample.json` — one REAL captured alert. Covers the
   `endpoint.events.process` dataset shape and only that one.
2. `ingest-templates.txt` — a live `logs-detections.alerts-so/_mapping` dump
   across 24 backing indices (2026.06.21 → 2026.07.16). 438 `event_data.*` leaf
   fields plus 29 top-level. Gives field *names and types*, never values.
3. `so-alert-reference/` — Security Onion's own ingest pipelines and ECS/SO
   component templates.

Architecture §18's model list (AlertWebhookPayload, CanonicalAlert, Observables,
Rule, Host, User, Process, Network, File) is illustrative of the core models, not
a ceiling. `OSInfo` is an addition covering real fields the live mapping proves
Security Onion can send. `CodeSignature`, `Library`, `MalwareVerdict`, `File`,
`Registry` and `RelatedEntities` existed here too (added across several 2026-08
sessions) but were removed 2026-09-06/07, user-directed — see `CanonicalAlert`'s
own docstring and `alert_builder.py`'s module docstring for the replacement
(`CanonicalAlert.raw_alert`). See CLAUDE.md "Deployment-specific decisions" for
that history.

Every field except the small required core is Optional with a safe default, so
`alert_builder.py` can stay presence-guarded and degrade to None rather than
raise on any shape not yet confirmed against real data.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

# The four values alert_builder.PROFILE_BY_ENGINE can emit. nodes/gather.py and
# nodes/rag.py switch on these for deterministic tool/retrieval selection
# (architecture §6-§7, implementation guide §1.1).
InvestigationProfile = Literal[
    "network_threat",
    "endpoint_behavior",
    "malicious_file",
    "generic",
]


class HashBundle(BaseModel):
    """Hashes are lists, not scalars: one alert can legitimately carry several
    of the same algorithm (process hash + file hash + dll hash). Extractors
    append, so every field needs a per-instance default_factory."""

    md5: list[str] = Field(default_factory=list)
    sha1: list[str] = Field(default_factory=list)
    sha256: list[str] = Field(default_factory=list)
    sha512: list[str] = Field(default_factory=list)
    imphash: list[str] = Field(default_factory=list)
    # ssdeep — fuzzy/similarity hash. Strelka-only (gap #7, added 2026-08-19).
    # `file.hash.ssdeep`, tier 3 (so-analysis/elasticsearch templates). No
    # real Strelka alert exists in this deployment yet — see File's docstring.
    ssdeep: list[str] = Field(default_factory=list)

    def is_empty(self) -> bool:
        return not any(
            (self.md5, self.sha1, self.sha256, self.sha512, self.imphash, self.ssdeep)
        )


class Observables(BaseModel):
    """The IOC surface. Per implementation guide §0.2 this is sourced from
    `hive_alert.observables` (n8n extracted them and Cortex scored them before
    /triage was called) — NEVER by regexing raw_alert text fields."""

    external_ips: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    hashes: HashBundle = Field(default_factory=HashBundle)


class OSInfo(BaseModel):
    """`event_data.host.os.*`. Typed rather than left as a raw dict so that
    Stage 3 sees a stable shape (architecture §12: no raw dicts across stage
    boundaries)."""

    name: str | None = None
    family: str | None = None
    full: str | None = None
    platform: str | None = None
    type: str | None = None
    version: str | None = None
    build: str | None = None
    kernel: str | None = None


class Rule(BaseModel):
    """The detection rule that fired.

    `uuid` is the join key for `detection_rule_lookup` against the so-detection
    index (`so_detection.publicId`) and for `get_fp_signal`. `native_severity`
    is the cross-engine-normalized `event.severity` integer; `level` is the
    engine's own textual level (`sigma_level` / `event.severity_label`), kept
    separately because the Sigma level string is
    what feeds `rule_severity_score` in architecture §10's formula."""

    name: str
    uuid: str = ""
    native_severity: int = 2
    level: str | None = None
    product: str | None = None
    category: str | None = None
    service: str | None = None


class Host(BaseModel):
    hostname: str
    ip: list[str] = Field(default_factory=list)
    mac: list[str] = Field(default_factory=list)
    os: OSInfo | None = None
    host_id: str | None = None
    architecture: str | None = None


class User(BaseModel):
    """`real_name`/`real_id` come from `event_data.user.Ext.real.*` — the
    account behind an impersonation, which differs from `name` when a process
    runs under an impersonated token."""

    name: str
    id: str | None = None
    domain: str | None = None
    real_name: str | None = None
    real_id: str | None = None


class Process(BaseModel):
    """Process telemetry — trimmed 2026-09-06/07, user-directed. Everything
    this model used to carry (parent-chain join keys, elevation/session
    context, PE version-resource metadata, code signatures, the
    injection-evidence `api`/target-process pairing) now reaches the single
    LLM call directly through `CanonicalAlert.raw_alert` instead of a typed
    field — see that field's docstring. `command_line` alone survives here
    because `nodes/rag.py::_most_specific_behavior_keyword` (Stage 2's Qdrant
    query builder) needs it as a structured field, not string-searched out of
    `raw_alert`."""

    command_line: str | None = None


class Network(BaseModel):
    """Network context.

    Suricata coverage is now REAL-FIXTURE VERIFIED (2026-08-18,
    `tests/fixtures/suricata-alert-real.json`) — `src_ip`/`dst_ip`/`src_port`/
    `dst_port`/`protocol` all confirmed populated on a real captured alert.
    The Sysmon network-connection path (via `_extract_network_from_event_data`)
    remains synthetic-only.

    `community_id` (added 2026-08-19, gap #5) is tier-1 verified on the same
    real Suricata fixture — `raw_alert["network"]["community_id"]`. It's the
    pivot key for correlating this alert against companion EVE-log documents
    (DNS/HTTP/TLS/flow) SO indexes as *separate* documents from the alert
    itself — see the planned `elasticsearch_suricata_flow_context` tool. Also
    populated by Sysmon network-connection events, nested at
    `event_data.network.community_id` rather than top-level."""

    src_ip: str | None = None
    dst_ip: str | None = None
    dst_ipv6: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    initiated: bool | None = None
    community_id: str | None = None


class CortexResult(BaseModel):
    """One analyzer's output for one observable, read from
    `hive_alert.observables[].reports`.

    This service never calls Cortex (architecture §6, §13) — the analyzers run
    before /triage is called and the reports arrive already attached.

    THIS MODEL CARRIES NO NUMBER. `CLAUDE.md`'s hard constraint is that
    `scoring.py` is the only place a number is computed, so no numeric score is
    derived here and none is stored. An earlier revision mapped taxonomy levels
    to 90/55/5 inside `alert_builder`; that pre-empted Stage 5 and was removed.

    `verdict` is a LIST, not a single label. An analyzer emits several taxonomy
    rows per observable and each carries its own level; collapsing them with a
    `max()` throws information away and forces an interpretation on Stage 5 that
    is Stage 5's to make. Only the adverse levels are kept — `malicious` and
    `suspicious`. `info` and `safe` are not verdicts and are not promoted into
    one; their absence from this list is what "nothing adverse" looks like.

    An empty `verdict` therefore means "no adverse taxonomy level was reported",
    NOT "clean" and NOT "unknown" — the distinction matters, and inventing a
    label for it here would be exactly the kind of premature judgement this
    model now avoids.

    `taxonomies` keeps every row verbatim — including `info`/`safe` rows and any
    detection ratios like `"0/91"` — so Stage 5 has the full evidence to score
    from without re-fetching or re-parsing `details`."""

    observable: str
    type: str = ""
    verdict: list[str] = Field(default_factory=list)
    details: str = ""
    analyzer: str = ""
    taxonomies: list[dict[str, Any]] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)


class CanonicalAlert(BaseModel):
    """The Stage 0 → Stage 1 contract. Every later stage reads this, never the
    raw payload.

    `timestamp` is the alert document's own `@timestamp`; `event_timestamp` is
    the underlying source event's `event_data.@timestamp`. These genuinely
    differ — by ~2 days in the one real captured sample — and architecture §10's
    `evidence_age_hours > 24` velocity branch does not say which it means. Both
    are carried so Stage 5 can make that choice explicitly rather than having it
    silently baked in here.

    `event_dataset` is the `event_data.event.dataset` discriminator
    (`endpoint.events.process`, `windows.sysmon_operational`, …). It records
    which shape this alert actually was, so a downstream gap can be attributed
    to the right extraction path.

    Trimmed 2026-09-06/07, user-directed (v6 single-call redesign): structured
    extraction of `process` (beyond `command_line`), `file`, `registry`,
    `target_process`, `library` and `related_entities` was removed outright,
    not replaced field-by-field. A repo-wide search before removal confirmed
    no Stage 1/2 tool ever read those fields — only the old two-LLM-call
    prompts did, plus `nodes/rag.py::_most_specific_behavior_keyword`, which
    now reads `process.command_line` only. `raw_alert` carries the original
    webhook body verbatim instead, so the single LLM call (`nodes/triage.py`,
    via `prompts/triage_agent.py::build_user_prompt`) reads that detail
    directly rather than through a typed intermediate only it consumed."""

    alert_id: str
    timestamp: datetime
    event_timestamp: datetime | None = None
    source_engine: str = "unknown"
    investigation_profile: InvestigationProfile = "generic"
    event_dataset: str | None = None
    risk_score: float | None = None

    rule: Rule
    host: Host | None = None
    user: User | None = None
    network: Network | None = None
    process: Process | None = None

    observables: Observables = Field(default_factory=Observables)
    cortex_results: list[CortexResult] = Field(default_factory=list)

    # Verbatim original webhook body — see this class's own docstring for why
    # this replaced structured process/file/registry/target_process/library/
    # related_entities extraction rather than sitting alongside it.
    raw_alert: dict[str, Any] = Field(default_factory=dict)

    # asset_context (a raw dict from the webhook payload) REMOVED 2026-09-06,
    # user-directed — it was set here but never read anywhere downstream; the
    # real asset context every consumer (Stage 4's prompt, case_action.py)
    # actually reads is EnrichedEvidence.asset_context (schemas/evidence.py::
    # AssetContext), Stage 1's own live itop_asset_lookup() result, entirely
    # independent of anything n8n sends. See main.py's module docstring.
    thehive_alert_id: str = ""
    thehive_observable_ids: dict[str, Any] = Field(default_factory=dict)


class AlertWebhookPayload(BaseModel):
    """What n8n POSTs to /triage (architecture §5).

    NOTE this is NOT the shape of `sigma-alert-sample.json`. That file is the
    n8n *webhook envelope* Security Onion sends INTO n8n —
    `[{headers, params, query, body, webhookUrl, executionMode}]`, where
    `[0]["body"]` is the raw alert. Unwrapping that envelope is n8n's job; by
    the time /triage is called, `raw_alert` is already the inner body.

    `asset_context` REMOVED 2026-09-06, user-directed — never used downstream;
    see `CanonicalAlert`'s docstring above for the real asset-context path."""

    thehive_alert_id: str
    raw_alert: dict[str, Any]
