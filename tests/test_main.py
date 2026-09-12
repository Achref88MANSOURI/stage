"""`main.py` — the `/triage` HTTP entrypoint.
No node/tool internals are re-tested here (each already has its own test
file) — this file only exercises `main.py`'s own orchestration logic: the
gather -> rag -> triage -> case_action call sequence, `TriageResult`
assembly, and the "HTTP 200 always, success=False + failed_stage on any
unexpected failure" posture. Every node function is monkeypatched at its
`main.py` import site (`main.gather_mod`, `main.rag_mod`, etc. — `main.py`
does `from stages import gather as gather_mod` etc., the same
patch-at-the-module-object convention `tests/test_gather.py` uses), never
the real backends.

`main.triage_mod.single_stage_triage` produces one `TriageVerdict` from
`EnrichedEvidence` directly. `case_action_mod.case_action` takes
`(verdict, evidence)`.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import main

FIXTURES = Path(__file__).parent / "fixtures"
from schemas import (
    CanonicalAlert,
    CaseActionResult,
    CorrelationDecision,
    CortexResult,
    EnrichedEvidence,
    EvidenceSituation,
    Gap,
    Host,
    RawEvidence,
    Rule,
    TriageVerdict,
)

client = TestClient(main.app)

PAYLOAD = {
    "thehive_alert_id": "~1",
    "raw_alert": {"event": {"dataset": "sigma.alert"}},
}


def make_alert() -> CanonicalAlert:
    return CanonicalAlert(
        alert_id="~1",
        timestamp=datetime.now(timezone.utc),
        rule=Rule(name="test rule", uuid="x"),
        host=Host(hostname="win-test"),
    )


def make_evidence() -> EnrichedEvidence:
    raw = RawEvidence(canonical_alert=make_alert())
    return EnrichedEvidence(**raw.model_dump())


def make_verdict(**overrides) -> TriageVerdict:
    """`correlation_decision`/`evidence_situation` are required fields
    directly on `TriageVerdict`."""
    defaults = dict(
        correlation_decision=CorrelationDecision(action="new", reasoning="x"),
        evidence_situation=EvidenceSituation(
            sources=[], overall_evidence_reliability="high", analyst_must_verify=[]
        ),
        likelihood="likely",
        impact_if_true="significant",
        verdict="true_positive",
        reasoning="x",
        summary="x",
        recommended_action="create_case",
        priority_band="P2",
        priority_reasoning="test priority reasoning",
    )
    defaults.update(overrides)
    return TriageVerdict(**defaults)


@pytest.fixture(autouse=True)
def patch_ingestion(monkeypatch):
    """Every test needs the alert-detail fetch + canonical alert build to
    succeed with something plausible — patched once here, individual tests
    override further downstream stages as needed."""

    async def fake_get_full_alert(thehive_alert_id, timeout=None):
        return {"title": "t"}, None

    monkeypatch.setattr(main.thehive, "get_full_alert_with_analysis", fake_get_full_alert)
    monkeypatch.setattr(main.alert_builder, "build_canonical_alert", lambda *a, **kw: make_alert())


class TestHappyPath:
    def test_full_pipeline_success(self, monkeypatch):
        async def fake_gather(alert):
            return RawEvidence(canonical_alert=alert)

        async def fake_rag(raw_evidence):
            return EnrichedEvidence(**raw_evidence.model_dump())

        async def fake_triage(evidence):
            return make_verdict()

        async def fake_case_action(verdict, evidence):
            return CaseActionResult(success=True, case_id="~999", is_new_case=True)

        monkeypatch.setattr(main.gather_mod, "gather_evidence", fake_gather)
        monkeypatch.setattr(main.rag_mod, "rag_enrichment", fake_rag)
        monkeypatch.setattr(main.triage_mod, "single_stage_triage", fake_triage)
        # _build_triage_result is a pure, math-free function in main.py
        # itself, run for real here (no I/O, deterministic from the
        # already-mocked verdict).
        monkeypatch.setattr(main.case_action_mod, "case_action", fake_case_action)

        resp = client.post("/triage", json=PAYLOAD)

        assert resp.status_code == 200
        body = resp.json()
        assert body["success"] is True
        assert body["error"] is None
        assert body["failed_stage"] is None
        assert body["result"]["alert_id"] == "~1"
        assert body["result"]["case_action"]["case_id"] == "~999"
        # case identity hoisted to the top level, next to alert_id
        assert body["result"]["case_id"] == "~999"
        assert body["result"]["is_new_case"] is True

    def test_response_shape_v7_trim(self, monkeypatch):
        """No raw evidence / flat cortex list in the response; `ioc:true`
        observables carry their analyzer results, and the case narrative
        comes back on `case_action`."""

        alert = make_alert()
        alert.cortex_results = [
            CortexResult(observable="deadbeef", analyzer="VirusTotal", verdict=["malicious"])
        ]

        async def fake_get_full_alert(thehive_alert_id, timeout=None):
            return {
                "title": "t",
                "observables": [
                    {"_id": "~o1", "dataType": "hash", "data": "deadbeef",
                     "tags": ["sha256"], "ioc": True},
                    {"_id": "~o2", "dataType": "hostname", "data": "win-test",
                     "tags": [], "ioc": False},
                ],
            }, None

        async def fake_gather(a):
            return RawEvidence(canonical_alert=alert)

        async def fake_rag(raw):
            return EnrichedEvidence(**raw.model_dump())

        async def fake_case_action(verdict, evidence):
            return CaseActionResult(
                success=True, case_id="~999", case_number=12, is_new_case=True,
                case_narrative="## Triage Summary — Alert `~1`",
            )

        monkeypatch.setattr(main.thehive, "get_full_alert_with_analysis", fake_get_full_alert)
        monkeypatch.setattr(main.alert_builder, "build_canonical_alert", lambda *a, **kw: alert)
        monkeypatch.setattr(main.gather_mod, "gather_evidence", fake_gather)
        monkeypatch.setattr(main.rag_mod, "rag_enrichment", fake_rag)
        monkeypatch.setattr(main.triage_mod, "single_stage_triage", lambda e: _async(make_verdict()))
        monkeypatch.setattr(main.case_action_mod, "case_action", fake_case_action)

        result = client.post("/triage", json=PAYLOAD).json()["result"]

        assert "gathered_evidence" not in result
        assert "threat_intel" not in result
        assert [o["observable_id"] for o in result["ioc_observables"]] == ["~o1"]
        assert result["ioc_observables"][0]["analyzer_results"][0]["analyzer"] == "VirusTotal"
        assert result["case_action"]["case_narrative"] == "## Triage Summary — Alert `~1`"

    def test_degraded_hive_alert_fetch_does_not_block_success(self, monkeypatch):
        """A Gap from get_full_alert_with_analysis should be logged, not
        treated as fatal — that function never raises to its caller."""

        async def fake_get_full_alert(thehive_alert_id, timeout=None):
            return None, Gap(source="thehive", tool="get_full_alert_with_analysis", reason="down")

        monkeypatch.setattr(main.thehive, "get_full_alert_with_analysis", fake_get_full_alert)

        async def fake_gather(alert):
            return RawEvidence(canonical_alert=alert)

        async def fake_rag(raw_evidence):
            return EnrichedEvidence(**raw_evidence.model_dump())

        monkeypatch.setattr(main.gather_mod, "gather_evidence", fake_gather)
        monkeypatch.setattr(main.rag_mod, "rag_enrichment", fake_rag)
        monkeypatch.setattr(main.triage_mod, "single_stage_triage", lambda e: _async(make_verdict()))
        monkeypatch.setattr(
            main.case_action_mod,
            "case_action",
            lambda v, e: _async(CaseActionResult(success=True, case_id="~1")),
        )

        resp = client.post("/triage", json=PAYLOAD)
        assert resp.status_code == 200
        assert resp.json()["success"] is True


async def _async(value):
    return value


class TestFailurePosture:
    """HTTP 200 always, success=False + failed_stage on an unexpected
    failure — the user-directed posture this repo now follows."""

    def test_stage_failure_returns_200_with_error_and_failed_stage(self, monkeypatch):
        async def fake_gather(alert):
            return RawEvidence(canonical_alert=alert)

        async def raises(*args, **kwargs):
            raise RuntimeError("rag backend exploded")

        monkeypatch.setattr(main.gather_mod, "gather_evidence", fake_gather)
        monkeypatch.setattr(main.rag_mod, "rag_enrichment", raises)

        resp = client.post("/triage", json=PAYLOAD)

        assert resp.status_code == 200
        body = resp.json()
        assert body["success"] is False
        assert body["failed_stage"] == "rag"
        assert "rag backend exploded" in body["error"]
        assert body["result"] is None

    def test_failure_after_score_preserves_partial_result(self, monkeypatch):
        """A failure in case_action must not discard the TriageResult already
        built — n8n still gets the verdict."""

        async def fake_gather(alert):
            return RawEvidence(canonical_alert=alert)

        async def fake_rag(raw_evidence):
            return EnrichedEvidence(**raw_evidence.model_dump())

        async def raises(*args, **kwargs):
            raise RuntimeError("thehive down")

        monkeypatch.setattr(main.gather_mod, "gather_evidence", fake_gather)
        monkeypatch.setattr(main.rag_mod, "rag_enrichment", fake_rag)
        monkeypatch.setattr(main.triage_mod, "single_stage_triage", lambda e: _async(make_verdict()))
        monkeypatch.setattr(main.case_action_mod, "case_action", raises)

        resp = client.post("/triage", json=PAYLOAD)

        assert resp.status_code == 200
        body = resp.json()
        assert body["success"] is False
        assert body["failed_stage"] == "case_action"
        assert body["result"] is not None
        assert body["result"]["alert_id"] == "~1"
        assert body["result"]["case_action"] is None


class TestV7ResponseAgainstRealCapturedResponse:
    """Uses the full `POST /triage` JSON response for a real TheHive alert
    ([MEDIUM] Suspicious Schtasks Schedule Type With High Privileges),
    captured against real ES/TheHive/iTop/OpenCTI/Qdrant backends.

    The triage LLM call hit a rate limit at capture time, so `verdict` and
    `triage_assessment` are the deterministic fallback values — that doesn't
    matter here, since this fixture is only checking the response shape,
    which is entirely code-driven. `case_action` reflects a real
    `400 "Alert is already imported"` response, since this alert was already
    merged into case `~45391936`."""

    def test_v7_shape_contract(self):
        body = json.loads((FIXTURES / "main_triage_response_v7_real.json").read_text())
        result = body["result"]

        # the two removed fields are genuinely absent
        assert "gathered_evidence" not in result
        assert "threat_intel" not in result

        # only ioc:true observables — all 4 real ones here are process-hash
        # observables; the real alert also has a hostname + 3 endpoint-ip
        # rows (ioc:false) that must NOT appear
        obs = result["ioc_observables"]
        assert len(obs) == 4
        assert all(o["data_type"] == "hash" for o in obs)
        assert all(o["observable_id"].startswith("~") for o in obs)

        # analyzer rows are joined to the observable by value
        for o in obs:
            for a in o["analyzer_results"]:
                assert a["observable"] == o["value"]
        # 3 of the 4 had a VirusTotal report, the imphash-only one did not
        assert sum(bool(o["analyzer_results"]) for o in obs) == 3

        assert "case_narrative" in result["case_action"]

    def test_case_identity_is_at_the_top_level(self):
        """Case id + number sit next to `alert_id`. This real capture is a
        merge into case `~45391936` (#58) — surfaced even though the merge
        itself failed (already-imported), because the id/number come from
        `evidence.open_cases`, resolved before the call."""
        result = json.loads(
            (FIXTURES / "main_triage_response_v7_real.json").read_text()
        )["result"]
        assert result["case_id"] == "~45391936"
        assert result["case_number"] == 58
        assert result["is_new_case"] is False
        assert result["case_id"] == result["case_action"]["case_id"]
        assert result["case_number"] == result["case_action"]["case_number"]


def _patch_happy_stages(monkeypatch, verdict: TriageVerdict, *, alert: CanonicalAlert | None = None):
    async def fake_gather(a):
        return RawEvidence(canonical_alert=a)

    async def fake_rag(raw_evidence):
        return EnrichedEvidence(**raw_evidence.model_dump())

    async def fake_case_action(v, e):
        return CaseActionResult(success=True, case_id="~999", is_new_case=True)

    if alert is not None:
        monkeypatch.setattr(main.alert_builder, "build_canonical_alert", lambda *a, **kw: alert)
    monkeypatch.setattr(main.gather_mod, "gather_evidence", fake_gather)
    monkeypatch.setattr(main.rag_mod, "rag_enrichment", fake_rag)
    monkeypatch.setattr(main.triage_mod, "single_stage_triage", lambda e: _async(verdict))
    monkeypatch.setattr(main.case_action_mod, "case_action", fake_case_action)


class TestFPFeedbackLoop:
    """`_record_fp_feedback` verifies run_pipeline calls
    `tools.fp_tracking.record_triage_outcome` exactly when the verdict is
    `false_positive`, keyed on `rule.uuid`, and that neither a skip nor a
    write failure ever flips the response's own `success` to False."""

    def test_false_positive_verdict_records_fp_feedback(self, monkeypatch):
        calls = []

        async def fake_record(rule_uuid, analyst_reason=None, timeout=None, **kw):
            calls.append((rule_uuid, analyst_reason))
            return True, None

        monkeypatch.setattr(main.fp_tracking, "record_triage_outcome", fake_record)
        _patch_happy_stages(monkeypatch, make_verdict(verdict="false_positive", reasoning="benign scan"))

        resp = client.post("/triage", json=PAYLOAD)

        assert resp.status_code == 200
        assert resp.json()["success"] is True
        assert calls == [("x", "benign scan")]

    def test_true_positive_verdict_does_not_record_fp_feedback(self, monkeypatch):
        async def fake_record(*args, **kwargs):
            raise AssertionError("record_triage_outcome must not be called for a true_positive verdict")

        monkeypatch.setattr(main.fp_tracking, "record_triage_outcome", fake_record)
        _patch_happy_stages(monkeypatch, make_verdict(verdict="true_positive"))

        resp = client.post("/triage", json=PAYLOAD)

        assert resp.status_code == 200
        assert resp.json()["success"] is True

    def test_needs_review_verdict_does_not_record_fp_feedback(self, monkeypatch):
        async def fake_record(*args, **kwargs):
            raise AssertionError("record_triage_outcome must not be called for needs_review")

        monkeypatch.setattr(main.fp_tracking, "record_triage_outcome", fake_record)
        _patch_happy_stages(
            monkeypatch,
            make_verdict(verdict="needs_review", recommended_action="needs_review"),
        )

        resp = client.post("/triage", json=PAYLOAD)

        assert resp.status_code == 200
        assert resp.json()["success"] is True

    def test_missing_rule_uuid_skips_the_write_without_failing(self, monkeypatch):
        """A rule that never resolved a uuid carries `rule.uuid == ""` — the
        write must be skipped, logged, not attempted, and must not fail the
        response."""
        async def fake_record(*args, **kwargs):
            raise AssertionError("record_triage_outcome must not be called with no rule_uuid")

        monkeypatch.setattr(main.fp_tracking, "record_triage_outcome", fake_record)
        ruleless_alert = CanonicalAlert(
            alert_id="~1",
            timestamp=datetime.now(timezone.utc),
            rule=Rule(name="test rule", uuid=""),
        )
        _patch_happy_stages(
            monkeypatch, make_verdict(verdict="false_positive"), alert=ruleless_alert
        )

        resp = client.post("/triage", json=PAYLOAD)

        assert resp.status_code == 200
        assert resp.json()["success"] is True

    def test_write_failure_does_not_fail_the_response(self, monkeypatch):
        """A Gap from record_triage_outcome (e.g. a locked/corrupt SQLite
        file) should be logged, not treated as fatal — this write is
        best-effort."""
        async def fake_record(rule_uuid, analyst_reason=None, timeout=None, **kw):
            return False, Gap(source="fp_tracking", tool="record_triage_outcome", reason="db locked")

        monkeypatch.setattr(main.fp_tracking, "record_triage_outcome", fake_record)
        _patch_happy_stages(monkeypatch, make_verdict(verdict="false_positive"))

        resp = client.post("/triage", json=PAYLOAD)

        assert resp.status_code == 200
        assert resp.json()["success"] is True

    def test_write_raising_unexpectedly_does_not_fail_the_response(self, monkeypatch):
        """Even if record_triage_outcome unexpectedly raised,
        _record_fp_feedback's own try/except should keep the pipeline's
        success outcome intact."""
        async def fake_record(*args, **kwargs):
            raise RuntimeError("simulated bug")

        monkeypatch.setattr(main.fp_tracking, "record_triage_outcome", fake_record)
        _patch_happy_stages(monkeypatch, make_verdict(verdict="false_positive"))

        resp = client.post("/triage", json=PAYLOAD)

        assert resp.status_code == 200
        assert resp.json()["success"] is True


class TestFalsePositiveEndToEnd:
    """`/triage` with a false_positive verdict runs the REAL case_action
    node (thehive tools mocked) — no case, alert annotated, fields hoisted."""

    def test_fp_verdict_annotates_alert_no_case(self, monkeypatch):
        from tools import thehive as th_mod

        calls = {}

        async def fake_record(*a, **kw):
            calls["fp_feedback"] = True
            return True, None

        async def no_case(*a, **kw):
            raise AssertionError("no case create/merge for a false positive")

        async def fake_alert_comment(alert_id, message, timeout=None):
            calls["comment"] = alert_id
            return True, None

        async def fake_update_alert(
            alert_id, *, severity=None, tlp=None, status=None, summary=None, timeout=None
        ):
            calls["update"] = (alert_id, severity, tlp, status)
            return True, None

        monkeypatch.setattr(main.fp_tracking, "record_triage_outcome", fake_record)
        monkeypatch.setattr(th_mod, "create_case_from_alert", no_case)
        monkeypatch.setattr(th_mod, "merge_alert_into_case", no_case)
        monkeypatch.setattr(th_mod, "add_alert_comment", fake_alert_comment)
        monkeypatch.setattr(th_mod, "update_alert", fake_update_alert)

        alert = make_alert()
        alert.thehive_alert_id = "~alertFP"

        async def fake_gather(a):
            return RawEvidence(canonical_alert=alert)

        async def fake_rag(raw):
            return EnrichedEvidence(**raw.model_dump())

        monkeypatch.setattr(main.alert_builder, "build_canonical_alert", lambda *a, **kw: alert)
        monkeypatch.setattr(main.gather_mod, "gather_evidence", fake_gather)
        monkeypatch.setattr(main.rag_mod, "rag_enrichment", fake_rag)
        monkeypatch.setattr(
            main.triage_mod, "single_stage_triage",
            lambda e: _async(make_verdict(verdict="false_positive", priority_band="P1")),
        )
        # case_action is NOT patched — the real node runs.

        result = client.post("/triage", json=PAYLOAD).json()["result"]

        assert calls["fp_feedback"] is True
        assert calls["comment"] == "~alertFP"
        # forced low / clear AND closed as a false positive
        assert calls["update"] == ("~alertFP", 1, 0, "FalsePositive")
        assert result["verdict"] == "false_positive"
        assert result["case_id"] == ""
        assert result["is_new_case"] is False
        assert result["case_action"]["action_taken"] == "fp_alert"
        assert result["case_action"]["severity"] == 1
        assert result["case_action"]["tlp"] == 0
        assert result["case_action"]["status"] == "FalsePositive"


class TestHealth:
    def test_health_ok(self, monkeypatch):
        class FakeResponse:
            def raise_for_status(self):
                pass

        class FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def get(self, *a, **kw):
                return FakeResponse()

        monkeypatch.setattr(main.httpx, "AsyncClient", lambda: FakeClient())

        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_health_degraded_on_unreachable_backend(self, monkeypatch):
        class FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def get(self, *a, **kw):
                raise ConnectionError("refused")

        monkeypatch.setattr(main.httpx, "AsyncClient", lambda: FakeClient())

        resp = client.get("/health")
        assert resp.status_code == 503
        assert resp.json()["status"] == "degraded"
