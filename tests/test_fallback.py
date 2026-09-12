"""Tests for `stages/triage.py::_stage_fallback`, the deterministic fallback
used when the triage LLM call fails. It never fabricates a verdict and
always escalates to human review.

`evidence_situation` coverage lives separately in
`tests/test_evidence_situation.py`; this file covers the rest of the
fallback's fixed output.
"""

from __future__ import annotations

from datetime import datetime, timezone

from stages import triage as triage_mod
from schemas import CanonicalAlert, RawEvidence, RuleContext, Rule, ShallowCase


def make_alert(**overrides) -> CanonicalAlert:
    defaults = dict(
        alert_id="~1",
        timestamp=datetime.now(timezone.utc),
        rule=Rule(name="Test Rule", uuid="test-uuid"),
    )
    defaults.update(overrides)
    return CanonicalAlert(**defaults)


def make_evidence(**overrides) -> RawEvidence:
    defaults = dict(canonical_alert=make_alert())
    defaults.update(overrides)
    return RawEvidence(**defaults)


class TestFallbackNeverFabricatesAVerdict:
    def test_verdict_is_always_needs_review(self):
        result = triage_mod._stage_fallback(make_evidence())
        assert result.verdict == "needs_review"

    def test_recommended_action_is_always_needs_review(self):
        result = triage_mod._stage_fallback(make_evidence())
        assert result.recommended_action == "needs_review"

    def test_actionable_observables_is_always_empty(self):
        """A downed LLM must never fabricate an IOC or a response action."""
        result = triage_mod._stage_fallback(make_evidence())
        assert result.actionable_observables == []


class TestFallbackPriorityIsP2NotP3:
    """A failed pipeline cannot safely be treated as low-risk, so P2
    guarantees the alert reaches an analyst this shift — a stricter floor
    than the "low reliability -> minimum P3" rule the LLM path itself
    follows, because here there's no verdict at all, not just a
    low-confidence one."""

    def test_priority_band_is_p2(self):
        result = triage_mod._stage_fallback(make_evidence())
        assert result.priority_band == "P2"

    def test_priority_reasoning_explains_why(self):
        result = triage_mod._stage_fallback(make_evidence())
        assert "P2" in result.priority_reasoning
        assert "fail" in result.priority_reasoning.lower()


class TestFallbackSafetyGateAlwaysApplied:
    def test_safety_gate_applied_is_true(self):
        """A downed LLM is itself the reliability failure the safety gate
        exists to catch — this path always reports the gate as fired."""
        result = triage_mod._stage_fallback(make_evidence())
        assert result.safety_gate_applied is True


class TestFallbackPreservesMitreMapping:
    """Does NOT return an empty list — a downed LLM must not silently drop
    MITRE grounding the rule context already established."""

    def test_mitre_attack_from_rule_context_is_preserved(self):
        evidence = make_evidence(
            rule_context=RuleContext(found=True, mitre_attack=["T1105", "T1059.001"])
        )
        result = triage_mod._stage_fallback(evidence)
        technique_ids = {m.technique_id for m in result.refined_mitre_mapping}
        assert technique_ids == {"T1105", "T1059.001"}

    def test_no_rule_context_produces_empty_mapping_not_a_crash(self):
        result = triage_mod._stage_fallback(make_evidence(rule_context=None))
        assert result.refined_mitre_mapping == []


class TestFallbackCorrelationDecision:
    def test_merges_into_first_open_case_when_any_exist(self):
        evidence = make_evidence(open_cases=[ShallowCase(case_id="~111"), ShallowCase(case_id="~222")])
        result = triage_mod._stage_fallback(evidence)
        assert result.correlation_decision.action == "merge"
        assert result.correlation_decision.merge_into_case_id == "~111"

    def test_creates_new_when_no_open_cases(self):
        result = triage_mod._stage_fallback(make_evidence(open_cases=[]))
        assert result.correlation_decision.action == "new"
        assert result.correlation_decision.merge_into_case_id is None

    def test_kill_chain_progression_is_always_false(self):
        """A downed LLM has no basis to claim active progression."""
        result = triage_mod._stage_fallback(make_evidence())
        assert result.correlation_decision.kill_chain_progression_detected is False


class TestFallbackInvestigationGaps:
    def test_non_empty_and_explains_the_failure(self):
        result = triage_mod._stage_fallback(make_evidence())
        assert len(result.investigation_gaps) >= 1
        assert "LLM" in result.investigation_gaps[0] or "llm" in result.investigation_gaps[0].lower()
