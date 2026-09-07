"""Top-level triage result contract — v6 single-call redesign (2026-09-06),
building on v5 (`newdesign.md`).

**v7 response trim (2026-09-07, user-directed).** The `/triage` response is
the LLM's analysis + the case outcome, not the evidence behind it:
- `gathered_evidence` (the full `EnrichedEvidence` dump) REMOVED.
- `threat_intel` (flat `CortexResult` list) REMOVED — analyzer rows now hang
  off the observable they belong to, via the new `IocObservable` model, and
  only `ioc: true` observables are surfaced.
- `IocObservable` ADDED: `{observable_id, data_type, value, tags,
  analyzer_results}`, assembled in `main.py::_build_ioc_observables` from
  `hive_alert.observables` + `canonical_alert.cortex_results`. No OpenCTI
  graph data (user asked for analyzer result only).
- `CaseActionResult.case_narrative` (new field on that model) carries the
  Markdown written into TheHive.
- The case TITLE no longer contains the alert id (`nodes/case_action.py::
  _build_case_title`) — the alert is identified by `alert_id` here and by
  the description heading in TheHive.

**v5 deletes the numeric/matrix scoring stage entirely** — `scoring.py`,
`scoring_config.py`, `nodes/score.py`, and this module's former `PriorityScore`
class (SOC-3s Scoring System v3, `newscoresystem.md`) are all gone. Priority
determination lives directly in the single LLM call's output as
`TriageVerdict.priority_band` (P1-P5), with `priority_reasoning` as its
one-sentence, evidence-citing justification — no score, no matrix cell, no
formula. `nodes/triage.py::_apply_safety_backstop` is the one deterministic
computation left anywhere near priority: escalating one band when
`evidence_situation.overall_evidence_reliability` is `"low"` and the LLM
assigned P4/P5 anyway.

**v6 collapses the old Stage 3 (`ContextualAssessment`) + Stage 4
(`TriageVerdict`) split into one `TriageVerdict` (`schemas/verdict.py`)** —
`TriageResult` now assembles from that single object plus `EnrichedEvidence`,
not two separate stage outputs (`main.py::_build_triage_result` no longer
takes a `context` parameter). Corollary field changes:
- `extracted_observables` (the old raw 6-bucket extraction) REMOVED — v6
  never produces that shape any more, see `schemas/verdict.py`'s docstring.
- `runbook_matches` REMOVED — v6 never calls `retrieve_playbooks` any more.
  `tools/qdrant.py::retrieve_playbooks` and `schemas/evidence.py::
  PlaybookMatch` themselves are untouched, just unused for now.
- `stage_3_reasoning` renamed `correlation_reasoning` (sourced from
  `verdict.correlation_decision.reasoning` — no more "stage 3" to name it
  after).
- `stage_3_assessment` renamed `triage_assessment: TriageVerdict | None` —
  same "flat fields + full audit object" redundancy pattern as before, one
  object instead of two.
- `evidence_situation` now sources from `verdict.evidence_situation`
  directly (no more separate `context` object to read it from).
`stage_5_duration_ms` and `gathered_evidence` are unchanged — the assembly
step is still "stage 5" in this pipeline's numbering, and `EnrichedEvidence`
is still the complete Stage 1+2 audit trail.

Built by a thin, math-free function (`main.py::_build_triage_result`) — no
distinct Stage 5 node.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from schemas.alert import CortexResult
from schemas.assessment import EvidenceSituation, MitreMapping
from schemas.case_action import CaseActionResult
from schemas.verdict import ActionableObservable, TriageVerdict


class IocObservable(BaseModel):
    """One of the alert's IOC observables (from `hive_alert.observables`,
    flagged `ioc: true`) plus the Cortex analyzer output that ran against it
    before `/triage` was called.

    2026-09-07, user-directed: the `/triage` response used to carry a flat
    top-level `threat_intel: list[CortexResult]`. That's gone — the analyzer
    rows now hang off the observable they belong to, and only `ioc: true`
    observables are surfaced (hostname / endpoint-ip / other non-IOC rows on
    the alert are dropped from the response). The live-GraphQL OpenCTI
    enrichment (`OpenCTIEnrichment`) is deliberately NOT included here — the
    user asked for the analyzer result only, not the OpenCTI threat graph.

    `analyzer_results` joins `CortexResult` by observable value
    (`CortexResult.observable == this.value`) — assembled in
    `main.py::_build_ioc_observables`, not a stage boundary of its own."""

    observable_id: str
    data_type: str
    value: str
    tags: list[str] = Field(default_factory=list)
    analyzer_results: list[CortexResult] = Field(default_factory=list)


class TriageResult(BaseModel):
    """The top-level result of one alert's triage — what `main.py`'s
    `/triage` endpoint actually returns to n8n (architecture §3), wrapped in
    `TriageResponse` below.

    2026-09-07, user-directed trim: the response is the LLM's analysis plus
    the case outcome — NOT the evidence it reasoned over. `gathered_evidence`
    (the full `EnrichedEvidence` Stage 1+2 dump) and the flat `threat_intel`
    list are both removed. What stays: the flattened verdict fields, the
    alert's `ioc: true` observables with their analyzer results
    (`ioc_observables`), the LLM-extracted `actionable_observables` with the
    TheHive id each was written as, `evidence_situation` (the LLM's own
    per-source reliability read — an analysis output, not raw evidence),
    `triage_assessment` (the complete `TriageVerdict` object), and
    `case_action` (including `case_narrative`, the Markdown written into
    TheHive)."""

    alert_id: str
    # The TheHive case this alert ended up in — the newly-created case's id
    # when `is_new_case`, otherwise the id of the case it was merged into.
    # Both are surfaced at the top level (2026-09-07, user-directed) next to
    # `alert_id`; the full detail (number, severity, status, tags, the
    # written narrative, ...) stays on `case_action` below. Empty only when
    # case creation itself failed — a merge always carries its target id even
    # on failure, since that id is known before the call.
    case_id: str = ""
    case_number: int | None = None
    is_new_case: bool = False
    verdict: str
    recommended_action: str
    summary: str
    reasoning: str
    likelihood: str = ""
    impact_if_true: str = ""
    evidence_citations: list[str] = Field(default_factory=list)
    ioc_observables: list[IocObservable] = Field(default_factory=list)
    actionable_observables: list[ActionableObservable] = Field(default_factory=list)
    correlation_reasoning: str = ""
    refined_mitre_mapping: list[MitreMapping] = Field(default_factory=list)
    investigation_gaps: list[str] = Field(default_factory=list)
    # triage_assessment is the COMPLETE single-call output, not cherry-picked
    # fields — deliberately redundant with the flat fields above (e.g.
    # correlation_reasoning/refined_mitre_mapping are already reachable
    # through it). The flat fields stay for quick-glance access; this is the
    # full LLM-analysis object underneath them. It carries no raw evidence.
    triage_assessment: TriageVerdict | None = None
    priority_band: str = ""
    priority_reasoning: str = ""
    safety_gate_applied: bool = False
    evidence_situation: EvidenceSituation | None = None
    stage_5_duration_ms: int = 0
    # Set by nodes/case_action.py — see that node's module docstring for why
    # it's a separate node. None until the caller runs case_action and
    # assigns it; not a required constructor field, so a caller that never
    # runs case_action is unaffected.
    case_action: CaseActionResult | None = None


class TriageResponse(BaseModel):
    """`main.py`'s actual `/triage` HTTP response body. `success=False` with
    a partial `result` (or `None`) and `error`/`failed_stage` set is a valid
    HTTP 200 — this repo's chosen failure posture: n8n's workflow never gets
    an HTTP error from this endpoint, only a structured indication that
    something didn't complete."""

    success: bool
    result: TriageResult | None = None
    error: str | None = None
    failed_stage: str | None = None
