"""The triage LLM call's output contract, produced by
`stages/triage.py::single_stage_triage`. Reuses `MitreMapping`,
`CorrelationDecision`, and `EvidenceSituation` from `schemas/assessment.py`
as building blocks.

There's no filtering of the evidence before this call — the LLM reasons
over the full evidence dump for both the analytical read and the
operational judgment in one pass, so attacker-controlled fields (command
lines, file paths, rule descriptions) reach it unfiltered.
`stages/triage.py::_validate_actionable_observables` is the compensating
control: it catches fabricated observable values, though not manipulated
reasoning elsewhere in the response.

`recommended_action` and `correlation_decision.action` come from the same
response, so the schema can't always narrow `recommended_action` to the
branch matching `action` — `prompts/triage_agent.py::
build_triage_verdict_schema` leaves both the "new" and "merge" options
schema-legal whenever open cases exist. `stages/triage.py::
_validate_recommended_action` checks consistency after parsing and falls
back to `needs_review` on a mismatch.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from schemas.assessment import CorrelationDecision, EvidenceSituation, MitreMapping


class ActionableObservable(BaseModel):
    """One observable worth a response action — what a responder would need
    to act on right now, not a full inventory of every IOC present. An
    alert with nothing actionable produces an empty list, which is a valid
    and expected answer.

    `observable_type` covers process instances (`process-id`, killable) and
    executable paths (`process-path`, blockable/quarantinable) separately,
    alongside `ip`/`file-path`/`domain`/`url`/`hash`. `recommended_disposition`
    names the concrete action (`kill`/`block`/`collect`/`delete`), with
    `monitor` as the catch-all for a weak or uncertain signal that's still
    worth recording.

    `confidence` is required and always set by the LLM. `observable_id` is
    the opposite — never set by the LLM, and absent from the schema sent to
    it — it's filled in afterward by `stages/case_action.py` once the
    TheHive write (or id lookup for an existing observable) completes."""

    observable_type: Literal[
        "process-id", "process-path", "ip", "file-path", "domain", "url", "hash"
    ]
    value: str
    recommended_disposition: Literal["kill", "block", "collect", "delete", "monitor"]
    confidence: Literal["high", "medium", "low"]
    reasoning: str
    observable_id: str | None = None


class TriageVerdict(BaseModel):
    """The triage LLM call's output. Produced either by the real LLM call
    or by `_stage_fallback` on any failure — both paths share this exact
    schema, so nothing downstream can tell which one ran except by reading
    `evidence_situation`."""

    refined_mitre_mapping: list[MitreMapping] = Field(default_factory=list)
    correlation_decision: CorrelationDecision
    evidence_situation: EvidenceSituation

    likelihood: Literal["unlikely", "possible", "likely", "near_certain"]
    impact_if_true: Literal["minor", "moderate", "significant", "severe"]
    verdict: Literal["true_positive", "false_positive", "needs_review"]
    reasoning: str
    summary: str
    recommended_action: Literal[
        "create_case", "close_fp", "merge_quiet", "merge_and_retier", "needs_review"
    ]
    # The LLM's own narrative analysis of what the concrete evidence shows —
    # process/network/file activity, the Cortex analyzer results, the rule
    # match, correlation — rendered as the "Evidence analysis" section of
    # the case/alert narrative. Free text, not a list of field pointers.
    evidence_analysis: str = ""
    actionable_observables: list[ActionableObservable] = Field(default_factory=list)
    priority_band: Literal["P1", "P2", "P3", "P4", "P5"]
    priority_reasoning: str

    investigation_gaps: list[str] = Field(default_factory=list)
    stage_duration_ms: int = 0

    # Set post-hoc by stages/triage.py::_apply_safety_backstop (or forced True
    # by _stage_fallback), same pattern as stage_duration_ms above — not
    # LLM-facing (absent from prompts/triage_agent.py's _BASE_SCHEMA).
    safety_gate_applied: bool = False
