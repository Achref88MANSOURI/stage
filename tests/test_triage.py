"""`stages/triage.py::single_stage_triage` tests: schema/model sync, the
merge-target and recommended_action consistency validators, the
JSON-escaping-safe hallucination guard, `_capped_max_tokens`, and the
deterministic fallback.

Fallback-specific coverage (P2 default, empty observables, needs_review
verdict, safety_gate_applied=True) lives in `tests/test_fallback.py`.
`_apply_safety_backstop` coverage lives in `tests/test_priority_backstop.py`.
`evidence_situation` construction on the fallback path lives in
`tests/test_evidence_situation.py`.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

import httpx
import pytest

import config
from stages import triage as triage_mod
from schemas import (
    ActionableObservable,
    CanonicalAlert,
    CorrelationDecision,
    EnrichedEvidence,
    EvidenceSituation,
    Host,
    RawEvidence,
    Rule,
    ShallowCase,
    TriageVerdict,
)


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


def make_evidence(*, open_cases=None, **alert_overrides) -> EnrichedEvidence:
    raw = RawEvidence(canonical_alert=make_alert(**alert_overrides), open_cases=open_cases or [])
    return EnrichedEvidence(**raw.model_dump())


def make_evidence_situation(**overrides) -> EvidenceSituation:
    defaults = dict(sources=[], overall_evidence_reliability="high", analyst_must_verify=[])
    defaults.update(overrides)
    return EvidenceSituation(**defaults)


def make_verdict(**overrides) -> TriageVerdict:
    defaults = dict(
        correlation_decision=CorrelationDecision(action="new", reasoning="x"),
        evidence_situation=make_evidence_situation(),
        likelihood="possible",
        impact_if_true="moderate",
        verdict="needs_review",
        reasoning="x",
        summary="x",
        recommended_action="needs_review",
        priority_band="P3",
        priority_reasoning="x",
    )
    defaults.update(overrides)
    return TriageVerdict(**defaults)


def make_actionable_observable(value, **overrides) -> ActionableObservable:
    defaults = dict(
        observable_type="hash",
        value=value,
        recommended_disposition="monitor",
        confidence="low",
        reasoning="x",
    )
    defaults.update(overrides)
    return ActionableObservable(**defaults)


def fake_response(content: str, status_code: int = 200) -> httpx.Response:
    request = httpx.Request("POST", "http://fake-llm/chat/completions")
    return httpx.Response(
        status_code,
        json={"choices": [{"message": {"content": content}}]},
        request=request,
    )


# ===========================================================================
# Schema stays in sync with TriageVerdict
# ===========================================================================


class TestSchemaStaysInSync:
    """Regression guard for the hand-inlined JSON schema and `TriageVerdict`
    silently drifting apart on a future field change."""

    def test_every_required_triage_verdict_field_is_in_the_schema(self):
        import prompts.triage_agent as prompts

        schema = prompts.build_triage_verdict_schema(make_evidence())
        schema_props = set(schema["properties"].keys())
        model_fields = set(TriageVerdict.model_fields.keys())
        # stage_duration_ms and safety_gate_applied are set post-hoc, never
        # sent to the LLM — see stages/triage.py's module docstring.
        expected_absent = {"stage_duration_ms", "safety_gate_applied"}
        assert model_fields - expected_absent <= schema_props

    def test_schema_has_zero_defs_or_refs(self):
        """See prompts/triage_agent.py's module docstring for why a
        `$defs`/`$ref`-based schema can hang the grammar-constrained
        decoder."""
        import prompts.triage_agent as prompts

        schema_text = json.dumps(prompts.build_triage_verdict_schema(make_evidence()))
        assert "$defs" not in schema_text
        assert "$ref" not in schema_text


# ===========================================================================
# Dynamic schema — merge_into_case_id / action / recommended_action
# ===========================================================================


class TestDynamicMergeSchema:
    def test_no_open_cases_forces_null_only_and_new_only(self):
        import prompts.triage_agent as prompts

        schema = prompts.build_triage_verdict_schema(make_evidence(open_cases=[]))
        correlation = schema["properties"]["correlation_decision"]["properties"]
        assert correlation["merge_into_case_id"]["enum"] == [None]
        assert correlation["action"]["enum"] == ["new"]
        assert schema["properties"]["recommended_action"]["enum"] == [
            "create_case",
            "close_fp",
            "needs_review",
        ]

    def test_open_cases_present_constrains_enum_to_real_ids(self):
        import prompts.triage_agent as prompts

        cases = [ShallowCase(case_id="~1"), ShallowCase(case_id="~2")]
        schema = prompts.build_triage_verdict_schema(make_evidence(open_cases=cases))
        correlation = schema["properties"]["correlation_decision"]["properties"]

        assert correlation["merge_into_case_id"]["enum"] == ["~1", "~2", None]
        assert correlation["action"]["enum"] == ["new", "merge"]
        # recommended_action can't be narrowed to one branch ahead of
        # generation (both fields come from the same response) — see
        # prompts/triage_agent.py's module docstring. All 5 stay legal.
        assert schema["properties"]["recommended_action"]["enum"] == [
            "create_case",
            "close_fp",
            "merge_quiet",
            "merge_and_retier",
            "needs_review",
        ]


# ===========================================================================
# _validate_merge_target — defense-in-depth behind the schema enum
# ===========================================================================


class TestMergeTargetValidation:
    def test_merge_id_not_in_open_cases_is_discarded(self):
        evidence = make_evidence(open_cases=[ShallowCase(case_id="~999")])
        verdict = make_verdict(
            correlation_decision=CorrelationDecision(action="merge", merge_into_case_id="~8613944")
        )
        result = triage_mod._validate_merge_target(verdict, evidence)
        assert result.correlation_decision.merge_into_case_id is None
        assert any("~8613944" in gap for gap in result.investigation_gaps)

    def test_merge_id_matching_a_real_open_case_is_kept(self):
        evidence = make_evidence(open_cases=[ShallowCase(case_id="~999")])
        verdict = make_verdict(
            correlation_decision=CorrelationDecision(action="merge", merge_into_case_id="~999")
        )
        result = triage_mod._validate_merge_target(verdict, evidence)
        assert result.correlation_decision.merge_into_case_id == "~999"

    def test_null_merge_id_is_a_no_op(self):
        evidence = make_evidence(open_cases=[])
        verdict = make_verdict(correlation_decision=CorrelationDecision(action="new"))
        result = triage_mod._validate_merge_target(verdict, evidence)
        assert result.correlation_decision.merge_into_case_id is None
        assert result.investigation_gaps == []


# ===========================================================================
# _validate_recommended_action — consistency check between
# correlation_decision.action and recommended_action
# ===========================================================================


class TestRecommendedActionValidation:
    def test_create_case_with_merge_action_falls_back_to_needs_review(self):
        verdict = make_verdict(
            correlation_decision=CorrelationDecision(action="merge", merge_into_case_id="~1"),
            recommended_action="create_case",
        )
        result = triage_mod._validate_recommended_action(verdict)
        assert result.recommended_action == "needs_review"

    def test_merge_quiet_with_new_action_falls_back_to_needs_review(self):
        verdict = make_verdict(
            correlation_decision=CorrelationDecision(action="new"),
            recommended_action="merge_quiet",
        )
        result = triage_mod._validate_recommended_action(verdict)
        assert result.recommended_action == "needs_review"

    def test_consistent_pair_is_untouched(self):
        verdict = make_verdict(
            correlation_decision=CorrelationDecision(action="new"),
            recommended_action="create_case",
        )
        result = triage_mod._validate_recommended_action(verdict)
        assert result.recommended_action == "create_case"


# ===========================================================================
# _validate_actionable_observables — JSON-escaping-safe hallucination guard
# ===========================================================================


class TestActionableObservablesValidation:
    def test_value_present_in_evidence_is_kept(self):
        evidence = make_evidence(raw_alert={"note": "cmd.exe /c whoami"})
        verdict = make_verdict(
            actionable_observables=[make_actionable_observable("cmd.exe /c whoami")]
        )
        result = triage_mod._validate_actionable_observables(verdict, evidence)
        assert len(result.actionable_observables) == 1

    def test_fabricated_value_is_discarded(self):
        evidence = make_evidence()
        verdict = make_verdict(
            actionable_observables=[make_actionable_observable("totally-fabricated-value.example")]
        )
        result = triage_mod._validate_actionable_observables(verdict, evidence)
        assert result.actionable_observables == []
        assert any("totally-fabricated-value.example" in g for g in result.investigation_gaps)

    def test_backslash_bearing_windows_path_is_not_falsely_discarded(self):
        """Regression guard: a genuine Windows path must not be discarded
        because evidence.model_dump_json() JSON-escapes backslashes while
        the raw LLM value doesn't carry that escaping — comparing them
        directly would always miss a real match."""
        evidence = make_evidence(
            raw_alert={"note": r"powershell -OutFile C:\Windows\Temp\xordump.exe"}
        )
        verdict = make_verdict(
            actionable_observables=[
                make_actionable_observable(
                    r"C:\Windows\Temp\xordump.exe", observable_type="process-path"
                )
            ]
        )
        result = triage_mod._validate_actionable_observables(verdict, evidence)
        assert len(result.actionable_observables) == 1


# ===========================================================================
# _capped_max_tokens
# ===========================================================================


class TestCappedMaxTokens:
    def test_small_prompt_gets_the_full_desired_budget(self, monkeypatch):
        monkeypatch.setattr(config, "LLM_MAX_CONTEXT_TOKENS", 8192)
        result = triage_mod._capped_max_tokens("system", "user", desired=4000)
        assert result == 4000

    def test_large_prompt_is_capped_below_desired(self, monkeypatch):
        monkeypatch.setattr(config, "LLM_MAX_CONTEXT_TOKENS", 8192)
        huge_prompt = "x" * 40000  # far more than fits alongside a 16000-token completion
        result = triage_mod._capped_max_tokens("system", huge_prompt, desired=16000)
        assert result < 16000
        assert result >= config.LLM_MIN_COMPLETION_TOKENS

    def test_call_llm_uses_configured_desired_value_not_a_hardcoded_literal(self, monkeypatch):
        monkeypatch.setattr(config, "STAGE_TRIAGE_DESIRED_MAX_TOKENS", 12345)
        monkeypatch.setattr(config, "LLM_MAX_CONTEXT_TOKENS", 1_000_000)

        captured = {}

        async def fake_post(self, url, *, headers, json, timeout):
            captured["max_tokens"] = json["max_tokens"]
            return fake_response('{"invalid": true}')  # parse will fail, irrelevant here

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
        try:
            run(triage_mod._call_llm(make_evidence()))
        except Exception:
            pass
        assert captured["max_tokens"] == 12345


# ===========================================================================
# Full node — parse/validate happy path and fallback dispatch
# ===========================================================================


class TestSingleStageTriage:
    def test_malformed_json_falls_back(self, monkeypatch):
        async def fake_post(self, url, *, headers, json, timeout):
            return fake_response("not valid json at all")

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
        verdict = run(triage_mod.single_stage_triage(make_evidence()))
        assert verdict.verdict == "needs_review"
        assert verdict.safety_gate_applied is True

    def test_connection_error_falls_back(self, monkeypatch):
        async def fake_post(self, url, *, headers, json, timeout):
            raise httpx.ConnectError("refused")

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
        verdict = run(triage_mod.single_stage_triage(make_evidence()))
        assert verdict.verdict == "needs_review"
        assert verdict.priority_band == "P2"

    def test_stage_duration_ms_is_always_set(self, monkeypatch):
        async def fake_post(self, url, *, headers, json, timeout):
            raise httpx.ConnectError("refused")

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
        verdict = run(triage_mod.single_stage_triage(make_evidence()))
        assert verdict.stage_duration_ms >= 0
