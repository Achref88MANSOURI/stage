"""Top-level triage result contract.

The `/triage` response carries the LLM's analysis and the case outcome, not
the raw evidence behind it. Cortex analyzer rows hang off the specific IOC
observable they belong to via `IocObservable` — only `ioc: true` observables
are surfaced.

`TriageResult` assembles from one `TriageVerdict` plus the gathered
evidence, via a thin, math-free function (`main.py::_build_triage_result`).
Priority comes directly from `TriageVerdict.priority_band` — there's no
numeric score or formula anywhere in this pipeline.
`stages/triage.py::_apply_safety_backstop` is the one deterministic
adjustment: it escalates the band by one step when evidence reliability is
low and the LLM assigned P4/P5 anyway.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from schemas.alert import CortexResult
from schemas.assessment import EvidenceSituation, MitreMapping
from schemas.case_action import CaseActionResult
from schemas.verdict import ActionableObservable, TriageVerdict


class IocObservable(BaseModel):
    """One of the alert's IOC observables plus the Cortex analyzer output
    that already ran against it before `/triage` was called. Non-IOC rows
    (hostname, endpoint IP, etc.) aren't included, and neither is OpenCTI's
    separate graph enrichment — just the Cortex result.

    `analyzer_results` is joined to `CortexResult` by observable value in
    `main.py::_build_ioc_observables`."""

    observable_id: str
    data_type: str
    value: str
    tags: list[str] = Field(default_factory=list)
    analyzer_results: list[CortexResult] = Field(default_factory=list)


class TriageResult(BaseModel):
    """The top-level result of one alert's triage — what `/triage` returns
    to n8n, wrapped in `TriageResponse` below. Carries the LLM's analysis
    and the case outcome, not the raw evidence: flattened verdict fields,
    the alert's IOC observables with their analyzer results, the judged
    actionable observables with each one's TheHive id, the complete
    `TriageVerdict` (`triage_assessment`), and the case-write outcome
    (`case_action`, including the Markdown narrative written into TheHive).
    """

    alert_id: str
    # The TheHive case this alert ended up in: the new case's id, or the id
    # of the case it merged into. Full detail stays on `case_action` below.
    # Empty only if case creation itself failed — a merge always carries its
    # target id even on failure, since that id is known before the call.
    case_id: str = ""
    case_number: int | None = None
    is_new_case: bool = False
    verdict: str
    recommended_action: str
    summary: str
    reasoning: str
    likelihood: str = ""
    impact_if_true: str = ""
    ioc_observables: list[IocObservable] = Field(default_factory=list)
    actionable_observables: list[ActionableObservable] = Field(default_factory=list)
    correlation_reasoning: str = ""
    refined_mitre_mapping: list[MitreMapping] = Field(default_factory=list)
    investigation_gaps: list[str] = Field(default_factory=list)
    # The complete verdict object, redundant with some of the flat fields
    # above (e.g. correlation_reasoning is already reachable through it).
    # The flat fields are for quick access; this is the full object.
    triage_assessment: TriageVerdict | None = None
    priority_band: str = ""
    priority_reasoning: str = ""
    safety_gate_applied: bool = False
    evidence_situation: EvidenceSituation | None = None
    stage_5_duration_ms: int = 0
    # Set by stages/case_action.py. None until that stage runs and assigns
    # it — not a required constructor field, so a caller that skips it is
    # unaffected.
    case_action: CaseActionResult | None = None


class TriageResponse(BaseModel):
    """The `/triage` HTTP response body. `success=False` with a partial (or
    `None`) `result` and `error`/`failed_stage` set is still a valid HTTP
    200 — the caller's workflow never gets an HTTP error from this
    endpoint, only a structured indication that something didn't
    complete."""

    success: bool
    result: TriageResult | None = None
    error: str | None = None
    failed_stage: str | None = None
