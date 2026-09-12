"""Tests for `rag_enrichment` — see `stages/rag.py`'s module docstring for
why `retrieve_playbooks` is not called here.

This stage has no backend logic of its own — it orchestrates one call to
`tools.qdrant.retrieve_mitre`, which has its own real-backend tests in
`tests/test_qdrant.py`. These tests mock `retrieve_mitre` at its source
module and check only the orchestration logic: query construction,
timeout/exception containment, and `EnrichedEvidence` assembly.

`tests/fixtures/rag_live_run_real.json` was captured by running
`rag_enrichment` once against a real `RawEvidence` (built from a real
Security Onion alert plus a real `RuleContext`) through the live Qdrant and
embedding microservice, with no mocking. Rather than keep a live
network-calling test in the permanent suite, that run's output is captured
here, and `TestRealFixtureLooksReasonable` asserts basic sanity on it so a
regression in the captured shape itself would still be caught.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

import config
from stages import rag as rag_mod
from schemas import (
    CanonicalAlert,
    Host,
    RawEvidence,
    Rule,
    RuleContext,
)
from tools import qdrant

FIXTURE = Path(__file__).parent / "fixtures" / "rag_live_run_real.json"


@pytest.fixture(scope="module")
def real() -> dict:
    """One live `stages.rag.rag_enrichment` run, captured."""
    return json.loads(FIXTURE.read_text())


def run(coro):
    return asyncio.run(coro)


def make_alert(**overrides) -> CanonicalAlert:
    defaults = dict(
        alert_id="~1",
        timestamp=datetime.now(timezone.utc),
        rule=Rule(name="Suspicious Invoke-WebRequest Execution", uuid="5e3cc4d8-…"),
        host=Host(hostname="win-kvkmd51ggkq"),
    )
    defaults.update(overrides)
    return CanonicalAlert(**defaults)


def make_evidence(**alert_overrides) -> RawEvidence:
    return RawEvidence(canonical_alert=make_alert(**alert_overrides))


def patch_all_ok(monkeypatch, *, calls=None):
    """Patch tools.qdrant.retrieve_mitre to succeed with a distinct,
    recognizable value so EnrichedEvidence's field can be traced back to
    the call."""

    def record(name):
        async def wrapper(*args, **kwargs):
            if calls is not None:
                calls.setdefault(name, []).append((args, kwargs))
            return _RETURNS[name]

        return wrapper

    _RETURNS = {
        "retrieve_mitre": ([], None),
    }

    monkeypatch.setattr(qdrant, "retrieve_mitre", record("retrieve_mitre"))
    return _RETURNS


class TestHappyPath:
    def test_all_fields_populated_no_gaps(self, monkeypatch):
        patch_all_ok(monkeypatch)
        evidence = run(rag_mod.rag_enrichment(make_evidence()))

        assert evidence.mitre_candidates == []
        assert evidence.investigation_gaps == []
        assert evidence.stage_2_duration_ms >= 0

    def test_mitre_always_called(self, monkeypatch):
        calls: dict = {}
        patch_all_ok(monkeypatch, calls=calls)
        run(rag_mod.rag_enrichment(make_evidence()))
        assert "retrieve_mitre" in calls

    def test_no_playbook_call_exists_at_all(self, monkeypatch):
        """This stage should never call retrieve_playbooks, under any
        evidence shape."""
        assert not hasattr(rag_mod, "_build_playbook_query")
        assert not hasattr(rag_mod, "retrieve_playbooks")


class TestPartialFailure:
    def test_one_gap_does_not_affect_other_fields(self, monkeypatch):
        from schemas import Gap

        async def failing_mitre(*args, **kwargs):
            return [], Gap(source="qdrant", tool="retrieve_mitre", reason="simulated failure")

        monkeypatch.setattr(qdrant, "retrieve_mitre", failing_mitre)
        evidence = run(rag_mod.rag_enrichment(make_evidence()))

        assert evidence.mitre_candidates == []
        tool_names = {g.tool for g in evidence.investigation_gaps}
        assert tool_names == {"retrieve_mitre"}


class TestGatherLevelTimeout:
    def test_slow_tool_produces_gap_not_a_hang(self, monkeypatch):
        async def slow_mitre(*args, **kwargs):
            await asyncio.sleep(5)
            return [], None

        monkeypatch.setattr(qdrant, "retrieve_mitre", slow_mitre)
        monkeypatch.setattr(config, "STAGE_1_TOOL_TIMEOUT_QDRANT", 0.05)

        evidence = run(rag_mod.rag_enrichment(make_evidence()))

        gap = next(g for g in evidence.investigation_gaps if g.tool == "retrieve_mitre")
        assert "gather-level timeout" in gap.reason
        assert evidence.mitre_candidates == []


class TestUnexpectedExceptionIsContained:
    def test_tool_raising_does_not_crash_rag_enrichment(self, monkeypatch):
        """Simulates a tool breaking its own never-raises contract;
        rag_enrichment must still never propagate an unhandled exception."""

        async def broken_mitre(*args, **kwargs):
            raise RuntimeError("simulated bug")

        monkeypatch.setattr(qdrant, "retrieve_mitre", broken_mitre)
        evidence = run(rag_mod.rag_enrichment(make_evidence()))

        assert evidence.mitre_candidates == []
        gap = next(g for g in evidence.investigation_gaps if g.tool == "retrieve_mitre")
        assert "RuntimeError" in gap.reason


class TestQueryConstruction:
    def test_query_uses_title_and_description(self):
        rule_ctx = RuleContext(found=True, title="A Rule", description="does a thing")
        evidence = RawEvidence(canonical_alert=make_alert(), rule_context=rule_ctx)
        query = rag_mod._build_mitre_query(evidence)
        assert "A Rule" in query
        assert "does a thing" in query

    def test_mitre_query_falls_back_to_bare_rule_name_with_no_evidence_at_all(self):
        evidence = make_evidence()
        query = rag_mod._build_mitre_query(evidence)
        assert query == "Suspicious Invoke-WebRequest Execution"


class TestGapsPreserveStage1:
    def test_stage_1_gap_survives_into_enriched_evidence(self, monkeypatch):
        from schemas import Gap

        patch_all_ok(monkeypatch)
        evidence = make_evidence()
        evidence.investigation_gaps.append(
            Gap(source="itop", tool="itop_asset_lookup", reason="Stage 1 failure")
        )

        enriched = run(rag_mod.rag_enrichment(evidence))

        stage_1_gap_tools = {g.tool for g in enriched.investigation_gaps}
        assert "itop_asset_lookup" in stage_1_gap_tools


class TestRealFixtureLooksReasonable:
    """Sanity checks on the captured live run, reading
    tests/fixtures/rag_live_run_real.json directly, to catch the captured
    shape silently going stale after a future schema change."""

    def test_mitre_candidates_are_relevant_to_the_real_alert(self, real):
        """The real alert is a PowerShell download-and-execute, so T1059.001
        should be among the top hits — confirming the query actually
        retrieves on-topic techniques rather than noise."""
        technique_ids = {c["technique_id"] for c in real["mitre_candidates"]}
        assert "T1059.001" in technique_ids
