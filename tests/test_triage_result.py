"""`TriageResult` — v5 redesign (`newdesign.md` §6). No more `PriorityScore`;
priority fields now come straight from `TriageVerdict` via
`main.py::_build_triage_result`, a thin, math-free assembly function that
replaces the deleted `nodes/score.py::priority_scoring` Stage 5 node.

**v6 redesign (2026-09-06)**: `_build_triage_result(verdict, evidence)` takes
ONE object now, not a `verdict`+`context` pair — the old `ContextualAssessment`
(`make_context()` helper) is gone, folded into `make_verdict()` below.
`stage_3_reasoning` is renamed `correlation_reasoning`.
"""

from __future__ import annotations

from datetime import datetime, timezone

from schemas import (
    CanonicalAlert,
    CorrelationDecision,
    EnrichedEvidence,
    EvidenceSituation,
    EvidenceSource,
    Host,
    RawEvidence,
    Rule,
    TriageResult,
    TriageVerdict,
    User,
)

import main


def make_alert() -> CanonicalAlert:
    return CanonicalAlert(
        alert_id="~1",
        timestamp=datetime.now(timezone.utc),
        rule=Rule(name="Test Rule", uuid="x"),
        host=Host(hostname="win-test"),
        user=User(name="tester"),
    )


def make_evidence() -> EnrichedEvidence:
    raw = RawEvidence(canonical_alert=make_alert())
    return EnrichedEvidence(**raw.model_dump())


def make_verdict(**overrides) -> TriageVerdict:
    """v6 (2026-09-06): correlation_decision/evidence_situation are required
    fields directly on TriageVerdict now — the old separate make_context()
    helper is folded in here."""
    defaults = dict(
        correlation_decision=CorrelationDecision(action="new", reasoning="correlation reasoning"),
        evidence_situation=EvidenceSituation(
            sources=[
                EvidenceSource(
                    source_name="rule_context", status="present", impact_on_triage="fine"
                )
            ],
            overall_evidence_reliability="medium",
            analyst_must_verify=["Verify asset criticality manually"],
        ),
        likelihood="likely",
        impact_if_true="significant",
        verdict="true_positive",
        reasoning="verdict reasoning",
        summary="verdict summary",
        recommended_action="create_case",
        priority_band="P2",
        priority_reasoning="P2 because confirmed malicious, no active spread",
        investigation_gaps=["Verify asset criticality manually"],
        safety_gate_applied=False,
    )
    defaults.update(overrides)
    return TriageVerdict(**defaults)


class TestTriageResultHasNoPriorityScore:
    def test_priority_field_does_not_exist(self):
        assert "priority" not in TriageResult.model_fields

    def test_priority_score_class_is_gone(self):
        import schemas

        assert not hasattr(schemas, "PriorityScore")


class TestTriageResultPriorityFieldsComeFromVerdict:
    def test_priority_band_and_reasoning(self):
        result = main._build_triage_result(make_verdict(), make_evidence())
        assert result.priority_band == "P2"
        assert result.priority_reasoning == "P2 because confirmed malicious, no active spread"

    def test_investigation_gaps_comes_from_verdict(self):
        """v5 (newdesign.md §9): investigation_gaps sources from
        TriageVerdict.investigation_gaps. v6 (2026-09-06): there's no
        separate ContextualAssessment.additional_investigation_gaps to leak
        from any more — the old two-source distinction this test used to
        guard against no longer applies, since there's only one
        investigation_gaps field anywhere in the pipeline now."""
        verdict = make_verdict(investigation_gaps=["the real consolidated gap"])

        result = main._build_triage_result(verdict, make_evidence())

        assert result.investigation_gaps == ["the real consolidated gap"]

    def test_safety_gate_applied_is_copied_through(self):
        result = main._build_triage_result(
            make_verdict(safety_gate_applied=True), make_evidence()
        )
        assert result.safety_gate_applied is True

    def test_evidence_situation_comes_from_verdict(self):
        result = main._build_triage_result(make_verdict(), make_evidence())
        assert result.evidence_situation.overall_evidence_reliability == "medium"
        assert result.evidence_situation.analyst_must_verify == ["Verify asset criticality manually"]


class TestTriageResultBuilderIsPureNoMath:
    """The whole point of the v5 redesign — no scoring formula anywhere.
    Mutation guard: if a future change reintroduces a numeric priority
    field, this test's field-set assertion should be revisited deliberately,
    not silently pass."""

    def test_result_fields_are_all_traceable_to_verdict(self):
        verdict = make_verdict()
        result = main._build_triage_result(verdict, make_evidence())

        assert result.verdict == verdict.verdict
        assert result.recommended_action == verdict.recommended_action
        assert result.summary == verdict.summary
        assert result.reasoning == verdict.reasoning
        assert result.likelihood == verdict.likelihood
        assert result.impact_if_true == verdict.impact_if_true
        assert result.correlation_reasoning == verdict.correlation_decision.reasoning
        assert result.refined_mitre_mapping == verdict.refined_mitre_mapping
        assert result.triage_assessment == verdict
