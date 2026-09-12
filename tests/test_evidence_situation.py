"""Tests for the `EvidenceSituation` / `EvidenceSource` models and for
`stages/triage.py::_stage_fallback`'s deterministic construction of
`evidence_situation` when the LLM call fails. The fallback path builds the
same missing/present distinction directly from `investigation_gaps`,
without an LLM in the loop.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import httpx
import pytest

from stages import triage as triage_mod
from schemas import (
    CanonicalAlert,
    EnrichedEvidence,
    EvidenceSituation,
    EvidenceSource,
    Gap,
    RawEvidence,
    Rule,
)


def run(coro):
    return asyncio.run(coro)


def make_alert(**overrides) -> CanonicalAlert:
    defaults = dict(
        alert_id="~1",
        timestamp=datetime.now(timezone.utc),
        rule=Rule(name="Test Rule", uuid="test-uuid"),
    )
    defaults.update(overrides)
    return CanonicalAlert(**defaults)


def make_evidence(*, investigation_gaps=None) -> EnrichedEvidence:
    raw = RawEvidence(canonical_alert=make_alert(), investigation_gaps=investigation_gaps or [])
    return EnrichedEvidence(**raw.model_dump())


class TestEvidenceSourceConstruction:
    def test_valid_statuses(self):
        for status in ("present", "empty", "missing"):
            source = EvidenceSource(source_name="rule_context", status=status, impact_on_triage="x")
            assert source.status == status

    def test_invalid_status_is_rejected(self):
        with pytest.raises(Exception):
            EvidenceSource(source_name="rule_context", status="unknown", impact_on_triage="x")


class TestEvidenceSituationConstruction:
    def test_valid_reliability_levels(self):
        for level in ("high", "medium", "low"):
            situation = EvidenceSituation(
                sources=[], overall_evidence_reliability=level, analyst_must_verify=[]
            )
            assert situation.overall_evidence_reliability == level

    def test_invalid_reliability_is_rejected(self):
        with pytest.raises(Exception):
            EvidenceSituation(sources=[], overall_evidence_reliability="critical", analyst_must_verify=[])

    def test_evidence_situation_is_required_on_triage_verdict(self):
        """No default — a TriageVerdict missing evidence_situation entirely
        must fail validation, the same way correlation_decision (also
        required, no default) already does."""
        from schemas import CorrelationDecision, TriageVerdict

        with pytest.raises(Exception):
            TriageVerdict(
                correlation_decision=CorrelationDecision(action="new"),
                likelihood="possible",
                impact_if_true="moderate",
                verdict="needs_review",
                reasoning="x",
                summary="x",
                recommended_action="needs_review",
                priority_band="P3",
                priority_reasoning="x",
                # evidence_situation deliberately omitted
            )


class TestStageFallbackBuildsEvidenceSituation:
    """`_stage_fallback` builds `evidence_situation` deterministically from
    `investigation_gaps` when the triage LLM call fails, using the same
    missing/present distinction the LLM path applies."""

    def test_reliability_is_always_low(self, monkeypatch):
        async def raising_call_llm(evidence):
            raise httpx.ConnectError("simulated")

        monkeypatch.setattr(triage_mod, "_call_llm", raising_call_llm)
        verdict = run(triage_mod.single_stage_triage(make_evidence()))

        assert verdict.evidence_situation.overall_evidence_reliability == "low"

    def test_analyst_must_verify_is_non_empty(self, monkeypatch):
        async def raising_call_llm(evidence):
            raise httpx.ConnectError("simulated")

        monkeypatch.setattr(triage_mod, "_call_llm", raising_call_llm)
        verdict = run(triage_mod.single_stage_triage(make_evidence()))

        assert len(verdict.evidence_situation.analyst_must_verify) >= 1
        assert "Triage LLM call failed" in verdict.evidence_situation.analyst_must_verify[0]

    def test_all_five_sources_are_covered(self, monkeypatch):
        async def raising_call_llm(evidence):
            raise httpx.ConnectError("simulated")

        monkeypatch.setattr(triage_mod, "_call_llm", raising_call_llm)
        verdict = run(triage_mod.single_stage_triage(make_evidence()))

        names = {s.source_name for s in verdict.evidence_situation.sources}
        assert names == {
            "fp_signal",
            "rule_context",
            "open_cases",
            "asset_context",
            "opencti_enrichment",
        }

    def test_source_named_in_a_real_gap_is_missing(self, monkeypatch):
        async def raising_call_llm(evidence):
            raise httpx.ConnectError("simulated")

        monkeypatch.setattr(triage_mod, "_call_llm", raising_call_llm)
        gap = Gap(source="itop", reason="timeout after 5s", tool="asset_context")
        verdict = run(triage_mod.single_stage_triage(make_evidence(investigation_gaps=[gap])))

        by_name = {s.source_name: s for s in verdict.evidence_situation.sources}
        assert by_name["asset_context"].status == "missing"

    def test_source_not_named_in_any_gap_is_present(self, monkeypatch):
        async def raising_call_llm(evidence):
            raise httpx.ConnectError("simulated")

        monkeypatch.setattr(triage_mod, "_call_llm", raising_call_llm)
        gap = Gap(source="itop", reason="timeout after 5s", tool="asset_context")
        verdict = run(triage_mod.single_stage_triage(make_evidence(investigation_gaps=[gap])))

        by_name = {s.source_name: s for s in verdict.evidence_situation.sources}
        assert by_name["rule_context"].status == "present"

    def test_mutation_guard_gap_source_detection_actually_matters(self, monkeypatch):
        """The missing/present split must be driven by actual Gap data, not
        a fixed value — two different gap sets should produce two different
        missing sets."""

        async def raising_call_llm(evidence):
            raise httpx.ConnectError("simulated")

        monkeypatch.setattr(triage_mod, "_call_llm", raising_call_llm)

        no_gaps = run(triage_mod.single_stage_triage(make_evidence(investigation_gaps=[])))
        with_gap = run(
            triage_mod.single_stage_triage(
                make_evidence(
                    investigation_gaps=[
                        Gap(source="thehive", reason="500 error", tool="open_cases")
                    ]
                )
            )
        )

        no_gaps_missing = {
            s.source_name for s in no_gaps.evidence_situation.sources if s.status == "missing"
        }
        with_gap_missing = {
            s.source_name for s in with_gap.evidence_situation.sources if s.status == "missing"
        }
        assert no_gaps_missing == set()
        assert with_gap_missing == {"open_cases"}
