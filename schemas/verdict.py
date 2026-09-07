"""Single-call output contract — v6 redesign (SOC-3s v6 spec, 2026-09-06).

Collapses the old two-call Stage 3 (`ContextualAssessment`) + Stage 4
(`TriageVerdict`) split into one object, produced by the single LLM call in
`nodes/triage.py::single_stage_triage`. `MitreMapping`/`CorrelationDecision`/
`EvidenceSituation` (`schemas/assessment.py`) are reused as building blocks
— see that module's docstring, updated the same day.

Two merge decisions the v6 spec calls for explicitly:
- `additional_investigation_gaps` (old Stage 3) and `investigation_gaps`
  (old Stage 4) collapse into one `investigation_gaps: list[str]` — there's
  no longer a Stage 3 -> Stage 4 handoff where "gaps Stage 3 noticed" and
  "gaps Stage 4 noticed" are meaningfully different passes.
- `stage_3_duration_ms` + `stage_4_duration_ms` collapse into one
  `stage_duration_ms: int`.

`ExtractedObservable`/`ExtractedObservables` (the old 6-bucket raw-extraction
step) are GONE, not merged — v6 redefines the observable-extraction task to
directly produce `actionable_observables`, replacing both old Stage 3's
extraction AND old Stage 4's separate disposition judgment in one pass.
`runbook_matches` is also gone — v6 drops the pre-call `retrieve_playbooks`
fetch entirely (its natural query input, the *refined* MITRE mapping, no
longer exists as a separate pre-call artifact in a one-call design); revisit
later as a post-call Qdrant fetch if needed, not solved here.

**The prompt-injection firewall is gone.** Old Stage 4 deliberately saw a
sanitized summary, never raw evidence, to bound prompt-injection surface
from attacker-controlled fields (process command lines, file paths, rule
descriptions — all attacker-influenceable text that flows into
`EnrichedEvidence`). The single call now reasons over the full evidence dump
for both the analytical and the operational judgment in the same pass — an
explicit, accepted tradeoff, not an oversight. The hallucination-guard
discipline in `nodes/triage.py` (`_validate_actionable_observables`) is the
compensating control: it catches fabricated *values*, not manipulated
*reasoning* — something in raw evidence that could previously only corrupt
the old Stage 3's refinement (contained; Stage 4 never saw it raw) can now
directly influence `verdict`, `priority_band`, and `recommended_action` in
the same breath.

**A real, structural consequence of collapsing two calls into one, worth
naming explicitly**: the old two-call design got `recommended_action`
vs. `correlation_decision.action` cross-field consistency "for free" — Stage
4's schema was built AFTER Stage 3 had already decided `action`, so the
enum could be hard-constrained to the matching branch every time. In one
call, both fields are produced in the SAME response, so which branch will
be chosen isn't known before the schema is sent. When `evidence.open_cases`
is non-empty, `prompts/triage_agent.py::build_triage_verdict_schema` can no
longer narrow `recommended_action`'s enum to just one branch — both
`create_case` and `merge_quiet`/`merge_and_retier` remain schema-legal
regardless of which `correlation_decision.action` the model ultimately
picks. `nodes/triage.py::_validate_recommended_action` is the compensating
post-parse check (mirroring the old Stage 4 validator, just checking
self-consistency within one response instead of against a separate prior
stage's already-decided output) — falls back to `needs_review` on a genuine
mismatch, same as before.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from schemas.assessment import CorrelationDecision, EvidenceSituation, MitreMapping


class ActionableObservable(BaseModel):
    """One observable field requiring a response action — redefined from
    "every IOC present" (old two-stage catalogue-then-judge approach) to
    "only what a responder would need to act on right now". Not a full
    inventory: an alert with no actionable observable produces an empty
    list, a valid and expected answer, not a failure.

    `observable_type` is a flat 7-value enum (`process-id` added alongside
    the original 6 — a specific running process instance a responder could
    kill, distinct from `process-path`, the executable path itself worth
    blocking/quarantining system-wide). `recommended_disposition` names the
    concrete response action rather than a generic block/quarantine/monitor
    triad — `kill`/`block`/`collect`/`delete` map to what a responder would
    actually do; `monitor` remains the catch-all for a weak or uncertain
    signal that still needs recording, never silently dropped for being
    low-confidence.

    `confidence` is required, set by the LLM for every item — this is the
    core judgment TASK 4 exists to make, not an optional field a fallback
    might reasonably omit. `observable_id` is the opposite: NEVER set by the
    LLM (absent from the schema sent to the model, see
    `prompts/triage_agent.py::_BASE_SCHEMA`) — filled in post-hoc by
    `nodes/case_action.py` once the real TheHive write (or id lookup for an
    already-existing observable) completes, same "set after the LLM call
    returns" pattern `stage_duration_ms` below already uses."""

    observable_type: Literal[
        "process-id", "process-path", "ip", "file-path", "domain", "url", "hash"
    ]
    value: str
    recommended_disposition: Literal["kill", "block", "collect", "delete", "monitor"]
    confidence: Literal["high", "medium", "low"]
    reasoning: str
    observable_id: str | None = None


class TriageVerdict(BaseModel):
    """v6's single output contract — the union of the old `ContextualAssessment`
    (Stage 3) and `TriageVerdict` (Stage 4) fields. Produced by
    `nodes/triage.py`'s one LLM call, or by `_stage_fallback` on any
    failure — both paths share this exact schema so nothing downstream can
    tell which one ran except by reading `evidence_situation`."""

    # from old ContextualAssessment
    refined_mitre_mapping: list[MitreMapping] = Field(default_factory=list)
    correlation_decision: CorrelationDecision
    evidence_situation: EvidenceSituation

    # from old TriageVerdict
    likelihood: Literal["unlikely", "possible", "likely", "near_certain"]
    impact_if_true: Literal["minor", "moderate", "significant", "severe"]
    verdict: Literal["true_positive", "false_positive", "needs_review"]
    reasoning: str
    summary: str
    recommended_action: Literal[
        "create_case", "close_fp", "merge_quiet", "merge_and_retier", "needs_review"
    ]
    evidence_citations: list[str] = Field(default_factory=list)
    actionable_observables: list[ActionableObservable] = Field(default_factory=list)
    priority_band: Literal["P1", "P2", "P3", "P4", "P5"]
    priority_reasoning: str

    # merged (v6) — see module docstring
    investigation_gaps: list[str] = Field(default_factory=list)
    stage_duration_ms: int = 0

    # Set post-hoc by nodes/triage.py::_apply_safety_backstop (or forced True
    # by _stage_fallback), same pattern as stage_duration_ms above — not
    # LLM-facing (absent from prompts/triage_agent.py's _BASE_SCHEMA).
    safety_gate_applied: bool = False
