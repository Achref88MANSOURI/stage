"""Typed stage-boundary contracts.

Every stage boundary is a strict Pydantic model, so a field renamed in one
stage and misread in the next fails loudly at validation time, never
silently produces an empty value downstream.

`alert.py` holds the canonical alert shape. `evidence.py` holds the gathered
and RAG-enriched evidence passed into the LLM call. `assessment.py` holds
shared building-block models (`MitreMapping`/`CorrelationDecision`/
`EvidenceSource`/`EvidenceSituation`) composed by `verdict.py::TriageVerdict`,
the LLM call's output contract. `result.py` holds the top-level triage
result assembled from `TriageVerdict` plus `EnrichedEvidence`; priority comes
directly from the verdict, with no separate numeric-scoring stage.
"""

from schemas.alert import (
    AlertWebhookPayload,
    CanonicalAlert,
    CortexResult,
    HashBundle,
    Host,
    InvestigationProfile,
    OSInfo,
    Observables,
    Rule,
)
from schemas.assessment import (
    CorrelationDecision,
    EvidenceSituation,
    EvidenceSource,
    MitreMapping,
)
from schemas.evidence import (
    AssetContext,
    EnrichedEvidence,
    FPSignal,
    Gap,
    LogSource,
    MitreCandidate,
    OpenCTIEnrichment,
    OpenCTIRelation,
    RawEvidence,
    RuleContext,
    ShallowCase,
    has_known_falsepositives,
    has_reliable_status,
)
from schemas.case_action import CaseActionResult
from schemas.result import IocObservable, TriageResponse, TriageResult
from schemas.verdict import ActionableObservable, TriageVerdict

__all__ = [
    "ActionableObservable",
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
    "IocObservable",
    "LogSource",
    "MitreCandidate",
    "MitreMapping",
    "OSInfo",
    "Observables",
    "OpenCTIEnrichment",
    "OpenCTIRelation",
    "RawEvidence",
    "Rule",
    "RuleContext",
    "ShallowCase",
    "TriageResponse",
    "TriageResult",
    "TriageVerdict",
    "has_known_falsepositives",
    "has_reliable_status",
]
