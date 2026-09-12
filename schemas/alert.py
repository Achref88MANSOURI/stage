"""Boundary models for the incoming alert: the raw n8n webhook payload and
the normalized `CanonicalAlert` every later stage reads.

Structured extraction stays narrow on purpose. There's no dedicated model
for process, network, user, file, registry, or related-entity detail —
`CanonicalAlert.raw_alert` carries the original webhook body verbatim, and
the LLM call reads that detail directly instead (see `CanonicalAlert`).

Every field outside the small required core is optional with a safe
default, so `alert_builder.py` can degrade to `None` on an unfamiliar alert
shape instead of raising.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

# The four values alert_builder.PROFILE_BY_ENGINE can emit.
InvestigationProfile = Literal[
    "network_threat",
    "endpoint_behavior",
    "malicious_file",
    "generic",
]


class HashBundle(BaseModel):
    """A set of file/process hashes. Each field is a list rather than a
    scalar, since one alert can carry more than one hash of the same
    algorithm (e.g. a process hash and a separate file hash)."""

    md5: list[str] = Field(default_factory=list)
    sha1: list[str] = Field(default_factory=list)
    sha256: list[str] = Field(default_factory=list)
    sha512: list[str] = Field(default_factory=list)
    imphash: list[str] = Field(default_factory=list)
    # ssdeep — fuzzy/similarity hash, populated from Strelka file-scan results
    # (`file.hash.ssdeep`) when that pipeline is enabled.
    ssdeep: list[str] = Field(default_factory=list)

    def is_empty(self) -> bool:
        return not any(
            (self.md5, self.sha1, self.sha256, self.sha512, self.imphash, self.ssdeep)
        )


class Observables(BaseModel):
    """The alert's IOCs, sourced from `hive_alert.observables` — n8n extracts
    them and Cortex scores them before `/triage` is ever called."""

    external_ips: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    hashes: HashBundle = Field(default_factory=HashBundle)


class OSInfo(BaseModel):
    """Operating system details for a host, from `event_data.host.os.*`."""

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

    `uuid` is the join key used to look up the rule in Elasticsearch
    (`detection_rule_lookup`) and to look up its false-positive history
    (`get_fp_signal`). `native_severity` is the normalized integer severity
    shared across engines; `level` is the engine's own textual severity
    label — kept separately since they carry different information."""

    name: str
    uuid: str = ""
    native_severity: int = 2
    level: str | None = None
    product: str | None = None
    category: str | None = None
    service: str | None = None


class Host(BaseModel):
    """The endpoint the alert fired on."""

    hostname: str
    ip: list[str] = Field(default_factory=list)
    mac: list[str] = Field(default_factory=list)
    os: OSInfo | None = None
    host_id: str | None = None
    architecture: str | None = None


class CortexResult(BaseModel):
    """One analyzer's output for one observable, read from
    `hive_alert.observables[].reports`. This service never calls Cortex
    directly — analyzers run before `/triage` is called and their reports
    arrive already attached to the alert.

    This model never carries a numeric score; scoring is left to the LLM's
    own judgment. `verdict` is a list rather than a single label, since an
    analyzer can emit several taxonomy rows per observable, each with its
    own level — only the adverse ones (`malicious`, `suspicious`) are kept
    here. An empty list means no adverse level was reported, which is
    different from "clean": `info`/`safe` rows are context, not a verdict,
    so their absence isn't promoted into one.

    `taxonomies` keeps every row verbatim, including `info`/`safe` rows and
    raw detection ratios like `"0/91"`, so the LLM has the full picture
    without needing to re-parse `details`."""

    observable: str
    type: str = ""
    verdict: list[str] = Field(default_factory=list)
    details: str = ""
    analyzer: str = ""
    taxonomies: list[dict[str, Any]] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)


class CanonicalAlert(BaseModel):
    """The normalized alert. Every later stage reads this, never the raw
    webhook payload.

    `timestamp` is the alert's own `@timestamp`; `event_timestamp` is the
    underlying source event's timestamp. These can differ by days, so both
    are kept rather than collapsing to one and losing that distinction.

    `event_dataset` records which Elasticsearch dataset this alert came
    from (`endpoint.events.process`, `windows.sysmon_operational`, etc.),
    so a downstream gap can be traced to the right extraction path.

    No typed field exists for process, file, registry, network, or
    related-entity detail. `raw_alert` carries the original webhook body
    verbatim, and the LLM call (`stages/triage.py`, via
    `prompts/triage_agent.py::build_user_prompt`) reads that detail
    directly from it instead."""

    alert_id: str
    timestamp: datetime
    event_timestamp: datetime | None = None
    source_engine: str = "unknown"
    investigation_profile: InvestigationProfile = "generic"
    event_dataset: str | None = None
    risk_score: float | None = None

    rule: Rule
    host: Host | None = None

    observables: Observables = Field(default_factory=Observables)
    cortex_results: list[CortexResult] = Field(default_factory=list)

    # Verbatim original webhook body — see the class docstring for why
    # process/network/user/file/registry detail reaches the LLM through
    # here rather than a typed field.
    raw_alert: dict[str, Any] = Field(default_factory=dict)

    # Asset context isn't carried here. It's populated separately in Stage 1
    # (EnrichedEvidence.asset_context, from a live iTop lookup), independent
    # of anything the webhook itself sends.
    thehive_alert_id: str = ""
    thehive_observable_ids: dict[str, Any] = Field(default_factory=dict)


class AlertWebhookPayload(BaseModel):
    """What n8n POSTs to `/triage`. Not the raw Security Onion webhook
    envelope — n8n unwraps that itself, so `raw_alert` here is already the
    inner alert body."""

    thehive_alert_id: str
    raw_alert: dict[str, Any]
