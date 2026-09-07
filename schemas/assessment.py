"""Shared building-block models for the unified triage output —
`schemas/verdict.py::TriageVerdict` (v6, single-call redesign, 2026-09-06).

`MitreMapping`, `CorrelationDecision`, `EvidenceSource`, `EvidenceSituation`
were originally Stage 3's own output contract (`ContextualAssessment`, now
DELETED — the two-call Stage 3/Stage 4 split it belonged to is gone, see
`nodes/triage.py`'s module docstring). They're kept here, unchanged in
shape, as the building blocks the new single-call `TriageVerdict` composes
directly.

`ExtractedObservable`/`ExtractedObservables` (the old 6-bucket raw-extraction
step, Stage 3's TASK 4) are ALSO DELETED, not kept — v6 redefines observable
extraction to directly produce `TriageVerdict.actionable_observables`
(`schemas/verdict.py::ActionableObservable`), replacing both the old
raw-extraction step and old Stage 4's separate disposition judgment in one
pass. Nothing in the new design constructs the old bucketed shape any more.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel


class MitreMapping(BaseModel):
    technique_id: str
    technique_name: str = ""
    tactic: str = ""
    confidence: Literal["high", "medium", "low"]
    basis: str = ""


class CorrelationDecision(BaseModel):
    action: Literal["new", "merge"]
    merge_into_case_id: str | None = None
    kill_chain_progression_detected: bool = False
    reasoning: str = ""


class EvidenceSource(BaseModel):
    """One Stage 1 evidence source's status, per the v5/v6 evidence-quality
    TASK. `"present"`/`"empty"` vs `"missing"` is the load-bearing
    distinction: "checked and found nothing" (real, exculpatory-or-neutral
    signal) is never the same thing as "could not check" (a reliability
    gap) — see `EvidenceSituation`'s docstring."""

    source_name: str
    status: Literal["present", "empty", "missing"]
    impact_on_triage: str


class EvidenceSituation(BaseModel):
    """`sources` covers 6 Stage 1 evidence sources: `fp_signal`,
    `rule_context`, `open_cases`, `asset_context`, `related_alerts_1h`,
    `opencti_enrichment` (`cortex_results`, a property on `canonical_alert`
    rather than a Stage 1 tool, is assessed too per the prompt's special-case
    instructions but has no dedicated `EvidenceSource` slot of its own the
    way the 6 named tools do).

    `overall_evidence_reliability` drives the priority floor ("low" forbids
    P4/P5, enforced first by prompt instruction and then by
    `nodes/triage.py::_apply_safety_backstop` as a deterministic backstop).
    `analyst_must_verify` is the model's own list of concrete
    manual-verification tasks — every item must reappear verbatim in
    `TriageVerdict.investigation_gaps`."""

    sources: list[EvidenceSource]
    overall_evidence_reliability: Literal["high", "medium", "low"]
    analyst_must_verify: list[str]
