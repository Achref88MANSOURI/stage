"""Tests for `gather_evidence`.

This stage has no backend logic of its own — it orchestrates several tools
that each have their own dedicated test file with real captured fixtures.
These tests mock every tool at its source module and check only the
orchestration logic: call routing, timeout/exception containment, and
`RawEvidence` assembly.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

from stages import gather as gather_mod
from schemas import (
    AssetContext,
    CanonicalAlert,
    FPSignal,
    Host,
    Rule,
    RuleContext,
)
from tools import detection_rules, fp_tracking, itop, opencti, thehive


def run(coro):
    return asyncio.run(coro)


def make_alert(**overrides) -> CanonicalAlert:
    defaults = dict(
        alert_id="~1",
        timestamp=datetime.now(timezone.utc),
        rule=Rule(name="Suspicious Invoke-WebRequest Execution", uuid="5e3cc4d8-3e68-43db-8656-eaaeefdec9cc"),
        host=Host(hostname="win-kvkmd51ggkq", host_id="c8fc26bf-dc76-4dba-adbb-bf31640d9c9f"),
        event_dataset="endpoint.events.process",
    )
    defaults.update(overrides)
    return CanonicalAlert(**defaults)


def patch_all_ok(monkeypatch, *, calls=None):
    """Patch every tool to succeed with a distinct, recognizable value so
    each RawEvidence field can be traced back to the right call."""

    def record(name):
        async def wrapper(*args, **kwargs):
            if calls is not None:
                calls.setdefault(name, []).append((args, kwargs))
            return _RETURNS[name]

        return wrapper

    _RETURNS = {
        "get_fp_signal": (FPSignal(rule_fp_count_24h=1), None),
        "detection_rule_lookup": (RuleContext(found=True, rule_uuid="x"), None),
        "search_open_cases_by_entities": ([], None),
        "itop_asset_lookup": (AssetContext(found=True, hostname="win-kvkmd51ggkq"), None),
        "opencti_observable_enrichment": ([], None),
    }

    monkeypatch.setattr(fp_tracking, "get_fp_signal", record("get_fp_signal"))
    monkeypatch.setattr(detection_rules, "detection_rule_lookup", record("detection_rule_lookup"))
    monkeypatch.setattr(
        thehive, "search_open_cases_by_entities", record("search_open_cases_by_entities")
    )
    monkeypatch.setattr(itop, "itop_asset_lookup", record("itop_asset_lookup"))
    monkeypatch.setattr(
        opencti, "opencti_observable_enrichment", record("opencti_observable_enrichment")
    )
    return _RETURNS


class TestHappyPath:
    def test_all_fields_populated_no_gaps(self, monkeypatch):
        returns = patch_all_ok(monkeypatch)
        evidence = run(gather_mod.gather_evidence(make_alert()))

        assert evidence.investigation_gaps == []
        assert evidence.fp_signal == returns["get_fp_signal"][0]
        assert evidence.rule_context == returns["detection_rule_lookup"][0]
        assert evidence.asset_context == returns["itop_asset_lookup"][0]
        assert evidence.stage_1_duration_ms >= 0


class TestPartialFailure:
    def test_one_gap_does_not_affect_other_fields(self, monkeypatch):
        patch_all_ok(monkeypatch)

        async def failing_itop(*args, **kwargs):
            return AssetContext(found=False), gather_mod.Gap(
                source="itop", tool="itop_asset_lookup", reason="simulated failure"
            )

        monkeypatch.setattr(itop, "itop_asset_lookup", failing_itop)
        evidence = run(gather_mod.gather_evidence(make_alert()))

        assert evidence.asset_context.found is False
        assert any(g.tool == "itop_asset_lookup" for g in evidence.investigation_gaps)
        # everything else still fully populated
        assert evidence.rule_context.found is True
        assert evidence.investigation_gaps == [
            g for g in evidence.investigation_gaps if g.tool == "itop_asset_lookup"
        ]


class TestGatherLevelTimeout:
    def test_slow_tool_produces_gap_not_a_hang(self, monkeypatch):
        patch_all_ok(monkeypatch)

        async def slow_fp_signal(*args, **kwargs):
            await asyncio.sleep(5)
            return FPSignal(), None

        monkeypatch.setattr(fp_tracking, "get_fp_signal", slow_fp_signal)

        import config

        monkeypatch.setattr(config, "STAGE_1_TOOL_TIMEOUT_FP", 0.05)
        evidence = run(gather_mod.gather_evidence(make_alert()))

        gap = next(g for g in evidence.investigation_gaps if g.tool == "get_fp_signal")
        assert "gather-level timeout" in gap.reason
        assert evidence.fp_signal == FPSignal()


class TestUnexpectedExceptionIsContained:
    def test_tool_raising_does_not_crash_gather_evidence(self, monkeypatch):
        """Simulates a tool breaking its own "never raises" contract.
        gather_evidence must still never propagate an unhandled exception
        to its caller."""
        patch_all_ok(monkeypatch)

        async def broken_detection_rule_lookup(*args, **kwargs):
            raise RuntimeError("simulated bug")

        monkeypatch.setattr(
            detection_rules, "detection_rule_lookup", broken_detection_rule_lookup
        )
        evidence = run(gather_mod.gather_evidence(make_alert()))

        assert evidence.rule_context.found is False
        gap = next(g for g in evidence.investigation_gaps if g.tool == "detection_rule_lookup")
        assert "RuntimeError" in gap.reason


class TestMissingHostOrUser:
    def test_no_host_no_user_does_not_raise(self, monkeypatch):
        patch_all_ok(monkeypatch)
        alert = make_alert(host=None, user=None)
        # Must not raise AttributeError from e.g. alert.host.hostname on None.
        evidence = run(gather_mod.gather_evidence(alert))
        assert evidence is not None

    def test_no_host_no_user_passes_none_downstream(self, monkeypatch):
        calls: dict = {}
        patch_all_ok(monkeypatch, calls=calls)
        run(gather_mod.gather_evidence(make_alert(host=None, user=None)))

        itop_args = calls["itop_asset_lookup"][0][0]
        assert itop_args[0] is None  # hostname
        assert itop_args[1] is None  # host_id


class TestTheHiveAlertIdThreadedThrough:
    """thehive_alert_id must reach thehive.py's open-case search, since
    that call needs it to look up similar cases."""

    def test_thehive_alert_id_passed_to_open_case_search(self, monkeypatch):
        calls: dict = {}
        patch_all_ok(monkeypatch, calls=calls)
        run(gather_mod.gather_evidence(make_alert(thehive_alert_id="~4661456")))

        open_args = calls["search_open_cases_by_entities"][0][0]
        assert open_args[0] == "~4661456"
