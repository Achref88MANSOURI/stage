"""Tests for TheHive case correlation.

`tests/fixtures/thehive_real.json` was captured from a live TheHive 5.7.5-1
instance: the `/api/v1/describe/*` enum vocabularies, real query results,
case observables, and the stock two-call shape `get_full_alert_with_analysis`
uses. Three real cases exist in the capture: `~8609848` (New/New, a
manually-created test case with no observables of its own, which shows an
open-case entity match can legitimately come back empty without a broken
query), `~4653208` (Closed/FalsePositive), and `~8613944` (Closed/TruePositive).

The remaining `SYNTHETIC_*` rows cover resolution statuses the live instance
has no example of (Indeterminate, duplicate handling), with every enum value
still drawn from the captured vocabulary.

`test_real_schema_enums_are_what_the_code_assumes` matters most here: it pins
the synthetic rows to the captured vocabulary, so a change to TheHive's model
would fail this test first rather than leaving the synthetic fixtures
silently testing a model that no longer exists.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest

from tools import thehive as th
from tools.thehive import (
    fetch_case_observables_with_type,
    search_open_cases_by_entities,
)

FIXTURE = Path(__file__).parent / "fixtures" / "thehive_real.json"
SIMILAR_CASES_FIXTURE = Path(__file__).parent / "fixtures" / "thehive_similar_cases_real.json"
RULE_NAME = "Suspicious Invoke-WebRequest Execution"
RULE_UUID = "5e3cc4d8-3e68-43db-8656-eaaeefdec9cc"
SHA256 = "1c84c8632c5269f24876ed9f49fa810b49f77e1e92e8918fc164c34b020f9a94"


@pytest.fixture(scope="module")
def real() -> dict:
    """Captured live from TheHive."""
    return json.loads(FIXTURE.read_text())


@pytest.fixture(scope="module")
def real_similar_cases() -> list:
    """`getAlert(~4661456) -> similarCases`, the same alert
    TestGetFullAlertWithAnalysis uses. Both real cases here are
    stage=="Closed" (~8613944 TruePositive, ~4653208 FalsePositive), which
    covers the exclusion side of the open-case stage filter;
    SYNTHETIC_SIMILAR_OPEN_ROW below covers the inclusion side."""
    return json.loads(SIMILAR_CASES_FIXTURE.read_text())


def patch_query(monkeypatch, results=None, exc=None, capture=None):
    """Replace TheHive's query transport. `results` may be a list consumed in
    call order, or a single value reused."""
    state = {"i": 0}

    async def fake_query(body, timeout, name="soc3s"):
        if capture is not None:
            capture.setdefault("bodies", []).append(body)
            capture.setdefault("names", []).append(name)
        if exc is not None:
            raise exc
        if isinstance(results, list) and results and isinstance(results[0], (list, dict)):
            out = results[min(state["i"], len(results) - 1)]
            state["i"] += 1
            return out
        return results if results is not None else []

    monkeypatch.setattr(th, "_query", fake_query)


def patch_query_by_name(monkeypatch, by_name: dict, capture=None):
    """Like `patch_query`, but keyed by the `name=` query-tag rather than call
    order. `get_full_alert_with_analysis` fires its two queries concurrently
    via `asyncio.gather`, so pinning behaviour to argument order would be
    testing asyncio scheduling, not the tool."""

    async def fake_query(body, timeout, name="soc3s"):
        if capture is not None:
            capture.setdefault("bodies", []).append(body)
            capture.setdefault("names", []).append(name)
        result = by_name.get(name, [])
        if isinstance(result, BaseException):
            raise result
        return result

    monkeypatch.setattr(th, "_query", fake_query)


def run(coro):
    return asyncio.run(coro)


def _enum_values(describe_doc: dict, field: str) -> list:
    """`/api/v1/describe/<entity>` wraps its enum values as
    `{label, path, initialQuery, attributes: [{name, values, ...}, ...]}`.
    This is a dev-time-only endpoint (see tools/thehive.py's
    `_describe_error` docstring) — nothing at runtime reads this shape,
    only these tests."""
    for attr in describe_doc.get("attributes", []):
        if attr.get("name") == field:
            return attr.get("values", [])
    raise KeyError(field)


# SYNTHETIC case rows — every enum value drawn from the captured live schema.
SYNTHETIC_OPEN_CASE = {
    "_id": "~100",
    "number": 7,
    "title": "PowerShell download cradle on win-kvkmd51ggkq",
    "severity": 3,
    "stage": "InProgress",
    "status": "InProgress",
    "tags": [f"rule:{RULE_NAME}", "win-kvkmd51ggkq"],
    "_createdAt": 1785971216169,
}
# SYNTHETIC similarCases row — proves the OPEN/inclusion side of the stage
# filter, since the one real fixture only has closed examples. Wraps the
# already-real-schema-vocabulary SYNTHETIC_OPEN_CASE.
SYNTHETIC_SIMILAR_OPEN_ROW = {
    "case": SYNTHETIC_OPEN_CASE,
    "similarObservableCount": 3,
    "observableCount": 3,
    "linkedWith": [{"dataType": "hash", "data": SHA256}, {"dataType": "domain", "data": "evil.test"}],
}


class TestAgainstRealCapturedCases:
    def test_real_schema_enums_are_what_the_code_assumes(self, real):
        """The anchor test: every synthetic case row below uses these
        values, so a change to TheHive's vocabulary fails here first
        instead of leaving the synthetic fixtures silently stale."""
        case = real["describe_case_enums"]
        assert _enum_values(case, "stage") == ["New", "InProgress", "Closed"]
        assert set(_enum_values(case, "status")) == {
            "Duplicated", "FalsePositive", "InProgress",
            "Indeterminate", "New", "Other", "TruePositive",
        }
        assert _enum_values(case, "severity") == [1, 2, 3, 4]
        # "Closed" is a STAGE, never a STATUS. Filtering status for openness
        # would silently match everything.
        assert "Closed" not in _enum_values(case, "status")

    def test_stage_and_status_are_different_vocabularies(self, real):
        case = real["describe_case_enums"]
        assert set(_enum_values(case, "stage")) != set(_enum_values(case, "status"))
        assert "TruePositive" not in _enum_values(case, "stage")

class TestFailuresProduceGapsNotExceptions:
    """search_open_cases_by_entities is backed entirely by the similarCases
    query, so every failure mode below is triggered against that one query,
    tagged `name="similar-cases"`."""

    def test_connection_error(self, monkeypatch):
        patch_query_by_name(monkeypatch, {"similar-cases": httpx.ConnectError("refused")})
        cases, gap = run(search_open_cases_by_entities(thehive_alert_id="~4661456"))
        assert cases == []
        assert "Cannot connect to TheHive" in gap.reason

    def test_http_error_includes_status_and_body(self, monkeypatch):
        response = httpx.Response(
            401, text="unauthorized", request=httpx.Request("POST", "http://th/api/v1/query")
        )
        patch_query_by_name(
            monkeypatch,
            {"similar-cases": httpx.HTTPStatusError("x", request=response.request, response=response)},
        )
        _, gap = run(search_open_cases_by_entities(thehive_alert_id="~4661456"))
        assert "HTTP 401 from TheHive" in gap.reason
        assert "unauthorized" in gap.reason

    def test_timeout(self, monkeypatch):
        async def slow(body, timeout, name="soc3s"):
            await asyncio.sleep(5)

        monkeypatch.setattr(th, "_query", slow)
        cases, gap = run(
            search_open_cases_by_entities(thehive_alert_id="~4661456", timeout=0.05)
        )
        assert cases == []
        assert "Timeout after 0.05s" in gap.reason

    def test_missing_alert_id_gaps_without_calling_out(self, monkeypatch):
        """No alert id to look up shouldn't look like "looked up and found
        nothing"; the query must never fire."""
        capture: dict = {}
        patch_query(monkeypatch, results=[], capture=capture)
        cases, gap = run(search_open_cases_by_entities(None))
        assert cases == []
        assert "No thehive_alert_id" in gap.reason
        assert capture.get("bodies") is None


class TestSimilarCasesOpenPath:
    """search_open_cases_by_entities is backed entirely by TheHive's native
    similarCases query, with no fallback of any kind. thehive_alert_id is
    the only input; a missing one produces a Gap rather than a different
    query."""

    def test_real_closed_rows_correctly_excluded(self, monkeypatch, real_similar_cases):
        """Both real similarCases rows for this alert are stage=='Closed',
        so the open-cases result should be empty — the exclusion side of
        the stage filter, against real data."""
        patch_query_by_name(monkeypatch, {"similar-cases": real_similar_cases})
        cases, gap = run(search_open_cases_by_entities(thehive_alert_id="~4661456"))
        assert gap is None
        assert cases == []

    def test_synthetic_open_row_included_with_similarity_signal(self, monkeypatch):
        """Covers the inclusion side of the same filter, and confirms
        similar_observable_count, the linkedWith-derived observables list,
        and every other ShallowCase field map correctly. The real fixture
        has no open example to test this against."""
        patch_query_by_name(
            monkeypatch, {"similar-cases": [SYNTHETIC_SIMILAR_OPEN_ROW]}
        )
        cases, gap = run(search_open_cases_by_entities(thehive_alert_id="~4661456"))
        assert gap is None
        assert len(cases) == 1
        case = cases[0]
        assert case.case_id == "~100"
        assert case.case_number == 7
        assert case.severity == 3
        assert case.stage == "InProgress"
        assert case.status == "InProgress"
        assert f"rule:{RULE_NAME}" in case.tags
        assert case.similar_observable_count == 3
        assert case.observables == [SHA256, "evil.test"]

    def test_epoch_millis_are_not_read_as_seconds(self, monkeypatch):
        """TheHive returns epoch milliseconds, but Pydantic parses a bare
        int as seconds by default, which would date every case to 1970 and
        break any recency reasoning downstream."""
        patch_query_by_name(
            monkeypatch, {"similar-cases": [SYNTHETIC_SIMILAR_OPEN_ROW]}
        )
        cases, _ = run(search_open_cases_by_entities(thehive_alert_id="~4661456"))
        assert cases[0].created_at.year == 2026

    def test_similar_cases_query_shape(self, monkeypatch):
        capture: dict = {}
        patch_query_by_name(monkeypatch, {"similar-cases": []}, capture=capture)
        run(search_open_cases_by_entities(thehive_alert_id="~4661456"))
        body = capture["bodies"][capture["names"].index("similar-cases")]
        assert body == {
            "query": [
                {"_name": "getAlert", "idOrName": "~4661456"},
                {"_name": "similarCases"},
            ]
        }


class TestGetFullAlertWithAnalysis:
    """Uses payloads from a real TheHive alert that's richer than the one
    used elsewhere in this fixture, since it carries VirusTotal reports
    alongside OpenCTI's rather than only OpenCTI's "Not found".

    The stock `getAlert` -> `observables` -> `page` projection returns
    `reports[analyzer].taxonomies` directly with no extra parameters needed:
    two concurrent stock queries, no custom server-side function required.
    See the function's own docstring in tools/thehive.py.
    """

    def test_real_payload_yields_alert_and_observables(self, monkeypatch, real):
        patch_query_by_name(
            monkeypatch,
            {"alert-detail": real["alert_detail"], "alert-observables": real["alert_observables"]},
        )
        hive_alert, gap = run(th.get_full_alert_with_analysis("~4661456"))
        assert gap is None
        assert hive_alert["title"].startswith("[HIGH]")
        assert len(hive_alert["observables"]) == 4

    def test_taxonomies_survive_into_the_hive_alert(self, monkeypatch, real):
        """reports[analyzer].taxonomies must reach alert_builder unchanged
        via the stock query."""
        patch_query_by_name(
            monkeypatch,
            {"alert-detail": real["alert_detail"], "alert-observables": real["alert_observables"]},
        )
        hive_alert, _ = run(th.get_full_alert_with_analysis("~4661456"))
        with_reports = [o for o in hive_alert["observables"] if o.get("reports")]
        assert len(with_reports) == 3
        vt = [o for o in with_reports if "VirusTotal_GetReport_3_1" in o["reports"]][0]
        taxonomies = vt["reports"]["VirusTotal_GetReport_3_1"]["taxonomies"]
        assert taxonomies and "value" in taxonomies[0]

    def test_calls_getalert_then_the_observables_projection(self, monkeypatch, real):
        capture: dict = {}
        patch_query_by_name(
            monkeypatch,
            {"alert-detail": real["alert_detail"], "alert-observables": real["alert_observables"]},
            capture=capture,
        )
        run(th.get_full_alert_with_analysis("~4661456"))
        assert set(capture["names"]) == {"alert-detail", "alert-observables"}
        step_names = {n: [s.get("_name") for s in b["query"]] for n, b in zip(capture["names"], capture["bodies"])}
        assert step_names["alert-detail"] == ["getAlert"]
        assert step_names["alert-observables"] == ["getAlert", "observables", "page"]

    def test_alert_not_found_is_a_gap(self, monkeypatch):
        patch_query_by_name(monkeypatch, {"alert-detail": [], "alert-observables": []})
        hive_alert, gap = run(th.get_full_alert_with_analysis("~doesnotexist"))
        assert hive_alert is None
        assert "no alert" in gap.reason.lower()

    def test_observables_fetch_failure_still_returns_the_alert(self, monkeypatch):
        """A partial failure (alert fetched fine, observables query broke)
        shouldn't discard the alert too."""
        patch_query_by_name(
            monkeypatch,
            {
                "alert-detail": [{"_id": "~1", "title": "t"}],
                "alert-observables": httpx.ReadTimeout("slow"),
            },
        )
        hive_alert, gap = run(th.get_full_alert_with_analysis("~1"))
        assert hive_alert["title"] == "t"
        assert hive_alert["observables"] == []
        assert "observables query failed" in gap.reason

    def test_alert_without_observables_gaps_but_still_returns_the_alert(self, monkeypatch):
        patch_query_by_name(
            monkeypatch, {"alert-detail": [{"_id": "~1", "title": "t"}], "alert-observables": []}
        )
        hive_alert, gap = run(th.get_full_alert_with_analysis("~1"))
        assert hive_alert["title"] == "t"
        assert "no observables" in gap.reason

    def test_no_alert_id(self, monkeypatch):
        capture: dict = {}
        patch_query_by_name(monkeypatch, {}, capture=capture)
        hive_alert, gap = run(th.get_full_alert_with_analysis(""))
        assert hive_alert is None
        assert "No thehive_alert_id" in gap.reason
        assert capture == {}

    def test_connection_error(self, monkeypatch):
        exc = httpx.ConnectError("refused")
        patch_query_by_name(monkeypatch, {"alert-detail": exc, "alert-observables": exc})
        hive_alert, gap = run(th.get_full_alert_with_analysis("~4661456"))
        assert hive_alert is None
        assert "Cannot connect to TheHive" in gap.reason


class TestFetchCaseObservablesWithType:
    """The read-side fetch of a merge target case's existing observables,
    used before writing actionable observables. Uses the same
    getCase -> observables -> page query as `_fetch_case_observables`, but
    keeps dataType/tags instead of collapsing to bare value strings, and
    follows the same never-raises-plus-Gap contract as every other public
    function in this file."""

    def test_maps_datatype_value_and_tags(self, monkeypatch):
        patch_query(
            monkeypatch,
            results=[
                [
                    {"_id": "~111", "dataType": "ip", "data": "1.2.3.4", "tags": ["malicious"]},
                    {"_id": "~222", "dataType": "hash", "data": "deadbeef", "tags": []},
                ]
            ],
        )
        rows, gap = run(fetch_case_observables_with_type("~123"))
        assert gap is None
        assert rows == [
            {"observable_id": "~111", "data_type": "ip", "value": "1.2.3.4", "tags": ["malicious"]},
            {"observable_id": "~222", "data_type": "hash", "value": "deadbeef", "tags": []},
        ]

    def test_row_without_id_gets_empty_string_not_a_crash(self, monkeypatch):
        patch_query(
            monkeypatch, results=[[{"dataType": "ip", "data": "1.2.3.4", "tags": []}]]
        )
        rows, gap = run(fetch_case_observables_with_type("~123"))
        assert gap is None
        assert rows[0]["observable_id"] == ""

    def test_rows_without_data_are_skipped(self, monkeypatch):
        patch_query(
            monkeypatch, results=[[{"dataType": "ip", "data": ""}, "not-a-dict"]]
        )
        rows, gap = run(fetch_case_observables_with_type("~123"))
        assert gap is None
        assert rows == []

    def test_no_case_id(self, monkeypatch):
        capture: dict = {}
        patch_query(monkeypatch, results=[], capture=capture)
        rows, gap = run(fetch_case_observables_with_type(""))
        assert rows == []
        assert "No case_id" in gap.reason
        assert capture == {}

    def test_connection_error_never_raises(self, monkeypatch):
        patch_query(monkeypatch, exc=httpx.ConnectError("refused"))
        rows, gap = run(fetch_case_observables_with_type("~123"))
        assert rows == []
        assert "Cannot connect to TheHive" in gap.reason

    def test_timeout_never_raises(self, monkeypatch):
        async def hangs(body, timeout, name="soc3s"):
            await asyncio.sleep(10)

        monkeypatch.setattr(th, "_query", hangs)
        rows, gap = run(fetch_case_observables_with_type("~123", timeout=0.01))
        assert rows == []
        assert "Timed out" in gap.reason
