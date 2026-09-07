"""Typed stage-boundary contracts.

Architecture §12: every stage boundary is a strict Pydantic model. A field
renamed in one stage and misread in the next must fail loudly at validation
time, never silently produce an empty value downstream.

`alert.py` (Stage 0), `evidence.py` (Stages 1-2), and `result.py` (the
top-level triage result) exist. `result.py` no longer represents a distinct
Stage 5 — v5 (`newdesign.md`) deleted the numeric scoring stage; priority
now comes from `verdict.py`. `assessment.py` (2026-09-06, v6 redesign) no
longer represents a distinct Stage 3 either — `ContextualAssessment` is
deleted, and the module now holds shared building-block models
(`MitreMapping`/`CorrelationDecision`/`EvidenceSource`/`EvidenceSituation`)
composed directly by `verdict.py::TriageVerdict`, the single-call output
contract that replaced the old Stage 3 + Stage 4 split. See
`schemas/verdict.py`'s module docstring for the full v6 rationale.
"""

from schemas.alert import (
    AlertWebhookPayload,
    CanonicalAlert,
    CortexResult,
    HashBundle,
    Host,
    InvestigationProfile,
    Network,
    OSInfo,
    Observables,
    Process,
    Rule,
    User,
)
from schemas.assessment import (
    CorrelationDecision,
    EvidenceSituation,
    EvidenceSource,
    MitreMapping,
)
from schemas.evidence import (
    AlertSummary,
    AssetContext,
    EnrichedEvidence,
    FPSignal,
    Gap,
    LogSource,
    MitreCandidate,
    OpenCTIEnrichment,
    OpenCTIRelation,
    PlaybookMatch,
    RawEvidence,
    RuleContext,
    ShallowCase,
    has_known_falsepositives,
    has_reliable_status,
)
from schemas.case_action import CaseActionResult
from schemas.result import TriageResponse, TriageResult
from schemas.verdict import ActionableObservable, TriageVerdict

__all__ = [
    "ActionableObservable",
    "AlertSummary",
    "AlertWebhookPayload",
    "AssetContext",
    "CanonicalAlert",
    "CaseActionResult",
    "CorrelationDecision",
    "CortexResult",
    "EnrichedEvidence",
    "EvidenceSituation",
    "EvidenceSource",
    "FPSignal",
    "Gap",
    "HashBundle",
    "Host",
    "InvestigationProfile",
    "LogSource",
    "MitreCandidate",
    "MitreMapping",
    "Network",
    "OSInfo",
    "Observables",
    "OpenCTIEnrichment",
    "OpenCTIRelation",
    "PlaybookMatch",
    "Process",
    "RawEvidence",
    "Rule",
    "RuleContext",
    "ShallowCase",
    "TriageResponse",
    "TriageResult",
    "TriageVerdict",
    "User",
    "has_known_falsepositives",
    "has_reliable_status",
]
