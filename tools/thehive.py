"""TheHive integration: case correlation and case-action writes.

Read functions: `get_full_alert_with_analysis` fetches the alert, its
observables, and their Cortex taxonomies in one call — the sole source of
IOCs and threat-intel verdicts. `search_open_cases_by_entities` answers
whether an open case is similar to this alert, feeding the triage LLM's
merge/new decision; it's backed entirely by TheHive's native `similarCases`
engine.

Write functions, all used from `stages/case_action.py`: `create_case_from_alert`
promotes an alert to a new case and then overwrites its title, description,
severity, and tags with this pipeline's own computed content.
`merge_alert_into_case` merges an alert into an existing case.
`update_case` does a partial case update (severity/tlp/tags), used for a
`merge_and_retier` outcome, since the merge endpoint itself doesn't accept
field overrides. `add_case_comment` attaches the evidence/verdict summary to
a case on every merge. `update_alert` and `add_alert_comment` handle the
false-positive path: the alert is annotated with the triage narrative,
de-prioritised, and closed in place, without ever becoming a case.

All ten functions never raise — failures come back as a `Gap` (read
functions) or `False` plus a `Gap` (write functions), same as every other
tool in this package.

The write endpoints below aren't documented in TheHive's public docs and
were found by testing: `POST /api/v1/alert/{id}/case` creates a case (not
`/promote`, which 404s); `POST /api/v1/alert/{id}/merge/{caseId}` merges;
`PATCH /api/v1/case/{id}` and `PATCH /api/v1/alert/{id}` update; comments go
to `POST /api/v1/case/{id}/comment` and `POST /api/v1/alert/{id}/comment`
(not `/api/v1/comment/case/{id}`, which also 404s). The base path is
`/api/v1` directly, not `/thehive` — that prefix returns the SPA's HTML with
a 200 rather than a 404, which makes it a poor health-check target.

A few schema quirks worth knowing, confirmed against this instance's
`/api/v1/describe/*`: `stage` (`New`/`InProgress`/`Closed`) and `status`
(`New`/`InProgress`/`TruePositive`/`FalsePositive`/`Duplicated`/
`Indeterminate`/`Other`) are separate enumerations — "open" means
`stage != "Closed"`, since there is no "Closed" status value to filter on
instead. Rule identity isn't a searchable field on Case or Alert; the only
trace of it is the `rule:<name>` tag stamped onto the alert and the
description text. Case severity is `1..4` and TLP is `0..4` — small integer
scales, not the 0-100 range used elsewhere in this pipeline, and no
conversion happens on the way in.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import httpx

import config
from schemas import (
    Gap,
    ShallowCase,
)

logger = logging.getLogger(__name__)

SOURCE = "thehive"

# Bounds. Open cases are capped because the triage LLM reads them all and a
# merge decision across dozens of cases is not a decision the prompt can make well.
MAX_OPEN_CASES = 20
MAX_OBSERVABLES_PER_CASE = 50


async def _query(body: dict, timeout: float, name: str = "soc3s") -> Any:
    """POST to TheHive's query API. Raises on transport or HTTP error.

    Unlike iTop, TheHive uses HTTP status codes for errors, so
    `raise_for_status` is meaningful here. A malformed query returns 400 with
    a body naming the offending path.
    """
    headers = {
        "Authorization": f"Bearer {config.THEHIVE_API_KEY}",
        "Content-Type": "application/json",
    }
    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.post(
            f"{config.THEHIVE_URL}/api/v1/query",
            params={"name": name},
            headers=headers,
            json=body,
        )
        response.raise_for_status()
        return response.json()


def _describe_error(exc: Exception) -> str:
    if isinstance(exc, httpx.HTTPStatusError):
        body = (exc.response.text or "")[:250].replace("\n", " ")
        return f"HTTP {exc.response.status_code} from TheHive: {body}"
    if isinstance(exc, httpx.ConnectError):
        return f"Cannot connect to TheHive at {config.THEHIVE_URL}: {exc}"
    if isinstance(exc, httpx.ReadTimeout):
        return f"TheHive read timeout: {exc}"
    return f"{type(exc).__name__}: {exc}"


async def get_full_alert_with_analysis(
    thehive_alert_id: str, timeout: float | None = None
) -> tuple[dict | None, Gap | None]:
    """Fetches the alert plus its observables and their Cortex taxonomies —
    the single source of both the IOC list and the pre-computed threat-intel
    verdicts. The return value is passed straight to
    `alert_builder.build_canonical_alert(..., hive_alert=<this>)`.

    Two stock `/api/v1/query` calls run concurrently, no custom server-side
    function required: one fetches the alert, the other fetches the alert's
    observables with the standard paging projection. That projection returns
    `reports[analyzer].taxonomies` directly for each observable, with no
    extra parameters needed.

    Never raises. Returns `(hive_alert | None, Gap | None)`; if either call
    fails — TheHive down, wrong alert id, timeout — the result carries a Gap
    and the pipeline continues with reduced or no threat intel instead of
    failing outright.
    """
    timeout = timeout if timeout is not None else config.STAGE_1_TOOL_TIMEOUT_THEHIVE
    started = time.monotonic()

    def gap(reason: str) -> Gap:
        return Gap(
            source=SOURCE,
            tool="get_full_alert_with_analysis",
            reason=reason,
            duration_ms=int((time.monotonic() - started) * 1000),
        )

    if not thehive_alert_id:
        return None, gap("No thehive_alert_id supplied — cannot fetch alert/observables")

    alert_query = {"query": [{"_name": "getAlert", "idOrName": thehive_alert_id}]}
    observables_query = {
        "query": [
            {"_name": "getAlert", "idOrName": thehive_alert_id},
            {"_name": "observables"},
            {"_name": "page", "from": 0, "to": MAX_OBSERVABLES_PER_CASE},
        ]
    }

    try:
        alert_result, observables_result = await asyncio.wait_for(
            asyncio.gather(
                _query(alert_query, timeout, name="alert-detail"),
                _query(observables_query, timeout, name="alert-observables"),
                return_exceptions=True,
            ),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        return None, gap(f"Timeout after {timeout}s fetching alert {thehive_alert_id}")

    if isinstance(alert_result, BaseException):
        logger.warning("get_full_alert_with_analysis: alert fetch failed: %s", alert_result)
        return None, gap(_describe_error(alert_result))

    # getAlert without a subsequent projection returns a single-element list.
    alert = alert_result[0] if isinstance(alert_result, list) and alert_result else None
    if not isinstance(alert, dict):
        return None, gap(f"TheHive returned no alert for {thehive_alert_id}")

    if isinstance(observables_result, BaseException):
        logger.warning(
            "get_full_alert_with_analysis: observables fetch failed: %s", observables_result
        )
        hive_alert = {**alert, "observables": []}
        return hive_alert, gap(
            f"Alert fetched but observables query failed: "
            f"{_describe_error(observables_result)}"
        )

    observables = observables_result if isinstance(observables_result, list) else []
    hive_alert = {**alert, "observables": observables}

    if not observables:
        return hive_alert, gap(
            f"Alert {thehive_alert_id} has no observables — no IOCs and no threat intel"
        )
    return hive_alert, None


async def _fetch_similar_cases(thehive_alert_id: str, timeout: float) -> list[dict]:
    """`getAlert -> similarCases` — TheHive's native, server-side case-
    similarity engine. Response shape:

        [{"case": {"_id": ..., "stage": ..., "status": ..., ...},
          "similarObservableCount": 4, "observableCount": 4,
          "linkedWith": [{"dataType": "hash", "data": "...", ...}, ...],
          ...}, ...]

    One round trip covers both the case match and its overlapping-observable
    detail — `linkedWith` already carries the overlapping observable values,
    no separate per-case enrichment call needed.

    Raises on failure, unlike the public `search_*` functions — this helper
    doesn't swallow errors itself. Its one caller,
    `search_open_cases_by_entities`, is where the never-raises contract and
    the Gap conversion live, the same layering `_query` follows for the same
    reason."""
    body = {
        "query": [
            {"_name": "getAlert", "idOrName": thehive_alert_id},
            {"_name": "similarCases"},
        ]
    }
    rows = await _query(body, timeout, name="similar-cases")
    return rows if isinstance(rows, list) else []


def _shallow_case_from_similar_row(row: dict) -> ShallowCase | None:
    """One `similarCases` row -> ShallowCase, with the overlap-strength
    signal and observable list this native query gives for free."""
    case = row.get("case")
    if not isinstance(case, dict):
        return None
    shallow = _to_shallow_case(case)
    shallow.similar_observable_count = row.get("similarObservableCount")
    shallow.observables = [
        str(o["data"])
        for o in (row.get("linkedWith") or [])
        if isinstance(o, dict) and o.get("data")
    ]
    return shallow


def _to_shallow_case(raw: dict) -> ShallowCase:
    created = raw.get("_createdAt") or raw.get("startDate")
    return ShallowCase(
        case_id=str(raw.get("_id") or ""),
        case_number=raw.get("number"),
        title=raw.get("title") or "",
        severity=raw.get("severity"),
        stage=raw.get("stage"),
        status=raw.get("status"),
        tags=[t for t in (raw.get("tags") or []) if isinstance(t, str)],
        # TheHive returns epoch milliseconds, but Pydantic parses a bare int
        # timestamp as seconds, which would date every case to 1970. Convert
        # explicitly instead of relying on that default.
        created_at=_epoch_ms_to_datetime(created),
    )


def _epoch_ms_to_datetime(value):
    from datetime import datetime, timezone

    if isinstance(value, (int, float)) and value > 0:
        return datetime.fromtimestamp(value / 1000, tz=timezone.utc)
    return None


async def fetch_case_observables_with_type(
    case_id: str, timeout: float | None = None
) -> tuple[list[dict], Gap | None]:
    """A case's full observable rows (dataType + value + tags + id).

    Called from `stages/case_action.py::_write_actionable_observables`, to
    dedup against a case's already-recorded observables before writing new
    ones.

    Distinct from `_fetch_case_observables` above: that function collapses
    each row to a bare value string (sufficient for its one caller, dedup
    inside `search_open_cases_by_entities`'s enrichment loop) and never
    raises but also never returns a `Gap`, since a missing observable list
    there is silently non-fatal. This function keeps `dataType`/`tags`
    (the caller needs to tell an IP from a hash from a process path) and
    follows the standard never-raises, `Gap`-returning contract every other
    public function in this file uses.

    Never raises. Returns `(rows, Gap | None)` where each row is
    `{"observable_id": str, "data_type": str, "value": str, "tags": list[str]}`
    — `observable_id` is TheHive's own `_id`, needed so a caller can tell
    whether an observable already exists on the case (reuse this id) or
    needs to be created (get a new one back from `create_case_observable`).
    """
    timeout = timeout if timeout is not None else config.STAGE_6_TOOL_TIMEOUT_THEHIVE
    started = time.monotonic()

    def gap(reason: str) -> Gap:
        return Gap(
            source=SOURCE,
            tool="fetch_case_observables_with_type",
            reason=reason,
            duration_ms=int((time.monotonic() - started) * 1000),
        )

    if not case_id:
        return [], gap("No case_id supplied — cannot fetch case observables")

    body = {
        "query": [
            {"_name": "getCase", "idOrName": case_id},
            {"_name": "observables"},
            {"_name": "page", "from": 0, "to": MAX_OBSERVABLES_PER_CASE},
        ]
    }
    try:
        rows = await asyncio.wait_for(
            _query(body, timeout, name="case-observables-typed"), timeout=timeout
        )
    except asyncio.TimeoutError:
        return [], gap(f"Timed out after {timeout}s fetching observables for case {case_id}")
    except Exception as exc:  # noqa: BLE001 — never raise to caller
        return [], gap(_describe_error(exc))

    return [
        {
            "observable_id": str(r.get("_id") or ""),
            "data_type": str(r.get("dataType", "")),
            "value": str(r.get("data", "")),
            "tags": list(r.get("tags") or []),
        }
        for r in (rows or [])
        if isinstance(r, dict) and r.get("data")
    ], None


async def search_open_cases_by_entities(
    thehive_alert_id: str | None,
    timeout: float | None = None,
) -> tuple[list[ShallowCase], Gap | None]:
    """Open cases similar to this alert, via TheHive's native `similarCases`
    engine (`_fetch_similar_cases`) — `getAlert -> similarCases`, filtered to
    `stage != "Closed"`, sorted newest first, capped at `MAX_OPEN_CASES`. One
    round trip; `similarObservableCount`/`linkedWith` give the overlap
    strength and matched observables for free, no separate per-case
    enrichment call needed.

    Never raises. Returns `(cases, Gap | None)`.

    An empty list with no Gap means "no similar open case", which is a real
    answer and sets the correlation decision to "new". A Gap means we could
    not find out — including when `thehive_alert_id` itself is missing, since
    this lookup has no other way to identify the alert.
    """
    timeout = timeout if timeout is not None else config.STAGE_1_TOOL_TIMEOUT_THEHIVE
    started = time.monotonic()

    def gap(reason: str) -> Gap:
        return Gap(
            source=SOURCE,
            tool="search_open_cases_by_entities",
            reason=reason,
            duration_ms=int((time.monotonic() - started) * 1000),
        )

    if not thehive_alert_id:
        return [], gap("No thehive_alert_id — cannot look up similar cases")

    try:
        from datetime import datetime, timezone

        rows = await asyncio.wait_for(
            _fetch_similar_cases(thehive_alert_id, timeout), timeout=timeout
        )
    except asyncio.TimeoutError:
        return [], gap(f"Timeout after {timeout}s querying TheHive for similar cases")
    except Exception as exc:  # noqa: BLE001 — a tool must never raise into gather
        logger.warning("search_open_cases_by_entities failed: %s", exc)
        return [], gap(_describe_error(exc))

    cases = [
        c
        for c in (_shallow_case_from_similar_row(r) for r in rows)
        if c is not None and c.stage != "Closed"
    ]
    epoch = datetime.min.replace(tzinfo=timezone.utc)
    cases.sort(key=lambda c: c.created_at or epoch, reverse=True)
    return cases[:MAX_OPEN_CASES], None


# ===========================================================================
# WRITE operations — see module docstring for the endpoints, how they were
# discovered, and why this file has a write section at all.
# ===========================================================================


async def _write(
    method: str, path: str, timeout: float, json_body: dict | None = None
) -> httpx.Response:
    """Shared transport for the four write calls below. Deliberately separate
    from `_query` (which always POSTs to the query API) — these hit distinct
    REST paths and verbs (PATCH included), not the query DSL."""
    headers = {
        "Authorization": f"Bearer {config.THEHIVE_API_KEY}",
        "Content-Type": "application/json",
    }
    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.request(
            method, f"{config.THEHIVE_URL}{path}", headers=headers, json=json_body
        )
        response.raise_for_status()
        return response


async def create_case_from_alert(
    thehive_alert_id: str,
    *,
    title: str,
    description: str,
    severity: int,
    tags: list[str] | None = None,
    tlp: int = 2,
    timeout: float | None = None,
) -> tuple[ShallowCase | None, Gap | None]:
    """Promote an alert to a new case, then immediately overwrite it with
    this pipeline's own computed content — see module docstring for why this
    is two calls, not one. Never raises."""
    timeout = timeout if timeout is not None else config.STAGE_1_TOOL_TIMEOUT_THEHIVE
    started = time.monotonic()

    def gap(reason: str) -> Gap:
        return Gap(
            source=SOURCE,
            tool="create_case_from_alert",
            reason=reason,
            duration_ms=int((time.monotonic() - started) * 1000),
        )

    if not thehive_alert_id:
        return None, gap("No thehive_alert_id supplied — cannot create a case")

    try:
        response = await asyncio.wait_for(
            _write("POST", f"/api/v1/alert/{thehive_alert_id}/case", timeout, {}),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        return None, gap(f"Timeout after {timeout}s promoting alert {thehive_alert_id}")
    except Exception as exc:  # noqa: BLE001 — a tool must never raise into its caller
        logger.warning("create_case_from_alert: promote failed: %s", exc)
        return None, gap(_describe_error(exc))

    case = response.json()
    case_id = str(case.get("_id") or "")
    if not case_id:
        return None, gap(f"TheHive promote returned no case id: {case!r}"[:250])

    update_body = {"title": title, "description": description, "severity": severity, "tlp": tlp}
    if tags:
        update_body["tags"] = tags
    try:
        await asyncio.wait_for(
            _write("PATCH", f"/api/v1/case/{case_id}", timeout, update_body), timeout=timeout
        )
    except Exception as exc:  # noqa: BLE001 — the case exists even if this content push failed
        logger.warning("create_case_from_alert: content update failed for %s: %s", case_id, exc)
        # The case was created — return it with the ALERT's own default content
        # (what promote actually set) rather than losing the case id entirely.
        shallow = _to_shallow_case(case)
        return shallow, gap(f"Case {case_id} created but content update failed: {_describe_error(exc)}")

    shallow = ShallowCase(
        case_id=case_id,
        case_number=case.get("number"),
        title=title,
        severity=severity,
        stage=case.get("stage"),
        status=case.get("status"),
        tags=tags or [],
    )
    return shallow, None


async def merge_alert_into_case(
    thehive_alert_id: str, case_id: str, timeout: float | None = None
) -> tuple[bool, Gap | None]:
    """Merge an alert into an existing case. Never raises."""
    timeout = timeout if timeout is not None else config.STAGE_1_TOOL_TIMEOUT_THEHIVE
    started = time.monotonic()

    def gap(reason: str) -> Gap:
        return Gap(
            source=SOURCE,
            tool="merge_alert_into_case",
            reason=reason,
            duration_ms=int((time.monotonic() - started) * 1000),
        )

    if not thehive_alert_id or not case_id:
        return False, gap(
            f"Missing id(s) — thehive_alert_id={thehive_alert_id!r} case_id={case_id!r}"
        )

    try:
        await asyncio.wait_for(
            _write("POST", f"/api/v1/alert/{thehive_alert_id}/merge/{case_id}", timeout, {}),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        return False, gap(f"Timeout after {timeout}s merging alert {thehive_alert_id} into {case_id}")
    except Exception as exc:  # noqa: BLE001
        logger.warning("merge_alert_into_case failed: %s", exc)
        return False, gap(_describe_error(exc))
    return True, None


async def update_case(
    case_id: str,
    *,
    severity: int | None = None,
    tlp: int | None = None,
    add_tags: list[str] | None = None,
    timeout: float | None = None,
) -> tuple[bool, Gap | None]:
    """Partial case update — only the fields passed are touched (TheHive's
    own PATCH semantics). `severity` is 1..4, `tlp` is 0..4 (0 clear / 1
    green / 2 amber / 3 amber+strict / 4 red). Never raises."""
    timeout = timeout if timeout is not None else config.STAGE_1_TOOL_TIMEOUT_THEHIVE
    started = time.monotonic()

    def gap(reason: str) -> Gap:
        return Gap(
            source=SOURCE, tool="update_case", reason=reason,
            duration_ms=int((time.monotonic() - started) * 1000),
        )

    if not case_id:
        return False, gap("No case_id supplied — nothing to update")

    body: dict[str, Any] = {}
    if severity is not None:
        body["severity"] = severity
    if tlp is not None:
        body["tlp"] = tlp
    if add_tags:
        body["addTags"] = add_tags
    if not body:
        return False, gap("No fields to update were supplied")

    try:
        await asyncio.wait_for(
            _write("PATCH", f"/api/v1/case/{case_id}", timeout, body), timeout=timeout
        )
    except asyncio.TimeoutError:
        return False, gap(f"Timeout after {timeout}s updating case {case_id}")
    except Exception as exc:  # noqa: BLE001
        logger.warning("update_case failed for %s: %s", case_id, exc)
        return False, gap(_describe_error(exc))
    return True, None


async def update_alert(
    thehive_alert_id: str,
    *,
    severity: int | None = None,
    tlp: int | None = None,
    status: str | None = None,
    summary: str | None = None,
    timeout: float | None = None,
) -> tuple[bool, Gap | None]:
    """Partial alert update — `PATCH /api/v1/alert/{id}`, returns 204 no
    body. Used on a `false_positive` verdict to drop the alert to low
    severity / clear TLP without promoting it to a case. Same `severity`
    1..4 / `tlp` 0..4 vocabulary as `update_case`.

    `status` and `summary` let a `false_positive` verdict CLOSE the alert as
    such. This TheHive instance's `alert.status` enum includes
    `"FalsePositive"` directly — `Duplicate`, `FalsePositive`, `Ignored`,
    `Imported`, `InProgress`, `New`, `Pending`. Setting
    `status="FalsePositive"` moves the alert to the `Closed` stage.
    `summary` is TheHive's own free-text triage-notes field, used to record
    the dismissal rationale. Never raises."""
    timeout = timeout if timeout is not None else config.STAGE_6_TOOL_TIMEOUT_THEHIVE
    started = time.monotonic()

    def gap(reason: str) -> Gap:
        return Gap(
            source=SOURCE, tool="update_alert", reason=reason,
            duration_ms=int((time.monotonic() - started) * 1000),
        )

    if not thehive_alert_id:
        return False, gap("No thehive_alert_id supplied — nothing to update")

    body: dict[str, Any] = {}
    if severity is not None:
        body["severity"] = severity
    if tlp is not None:
        body["tlp"] = tlp
    if status is not None:
        body["status"] = status
    if summary is not None:
        body["summary"] = summary
    if not body:
        return False, gap("No fields to update were supplied")

    try:
        await asyncio.wait_for(
            _write("PATCH", f"/api/v1/alert/{thehive_alert_id}", timeout, body),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        return False, gap(f"Timeout after {timeout}s updating alert {thehive_alert_id}")
    except Exception as exc:  # noqa: BLE001
        logger.warning("update_alert failed for %s: %s", thehive_alert_id, exc)
        return False, gap(_describe_error(exc))
    return True, None


async def add_case_comment(
    case_id: str, comment: str, timeout: float | None = None
) -> tuple[bool, Gap | None]:
    """Append a comment to a case. Never raises."""
    timeout = timeout if timeout is not None else config.STAGE_1_TOOL_TIMEOUT_THEHIVE
    started = time.monotonic()

    def gap(reason: str) -> Gap:
        return Gap(
            source=SOURCE, tool="add_case_comment", reason=reason,
            duration_ms=int((time.monotonic() - started) * 1000),
        )

    if not case_id or not comment:
        return False, gap(f"Missing case_id or empty comment (case_id={case_id!r})")

    try:
        await asyncio.wait_for(
            _write("POST", f"/api/v1/case/{case_id}/comment", timeout, {"message": comment}),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        return False, gap(f"Timeout after {timeout}s commenting on case {case_id}")
    except Exception as exc:  # noqa: BLE001
        logger.warning("add_case_comment failed for %s: %s", case_id, exc)
        return False, gap(_describe_error(exc))
    return True, None


async def add_alert_comment(
    thehive_alert_id: str, comment: str, timeout: float | None = None
) -> tuple[bool, Gap | None]:
    """Append a comment to an ALERT (not a case) — `POST /api/v1/alert/{id}/
    comment`, returns 201 with the created comment (`{_id, _type: "Comment",
    message, ...}`). Used on a `false_positive` verdict to record the triage
    narrative on the alert itself, since no case is created. Never raises."""
    timeout = timeout if timeout is not None else config.STAGE_6_TOOL_TIMEOUT_THEHIVE
    started = time.monotonic()

    def gap(reason: str) -> Gap:
        return Gap(
            source=SOURCE, tool="add_alert_comment", reason=reason,
            duration_ms=int((time.monotonic() - started) * 1000),
        )

    if not thehive_alert_id or not comment:
        return False, gap(
            f"Missing thehive_alert_id or empty comment (id={thehive_alert_id!r})"
        )

    try:
        await asyncio.wait_for(
            _write(
                "POST",
                f"/api/v1/alert/{thehive_alert_id}/comment",
                timeout,
                {"message": comment},
            ),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        return False, gap(f"Timeout after {timeout}s commenting on alert {thehive_alert_id}")
    except Exception as exc:  # noqa: BLE001
        logger.warning("add_alert_comment failed for %s: %s", thehive_alert_id, exc)
        return False, gap(_describe_error(exc))
    return True, None


# "filename" is the correct dataType for process-path and file values (e.g.
# a Windows executable path); ip/domain/url/hash use their own literal
# dataType names. The bucket->dataType mapping lives in
# stages/case_action.py (_OBSERVABLE_TYPE_TO_DATATYPE), the sole caller of
# create_case_observable.


async def create_case_observable(
    case_id: str,
    *,
    data_type: str,
    data: str,
    tags: list[str] | None = None,
    message: str = "",
    ioc: bool = True,
    timeout: float | None = None,
) -> tuple[str | None, Gap | None]:
    """Create one observable on an existing case. Never raises.

    Endpoint: `POST /api/v1/case/{id}/observable`. Payload: {dataType, data,
    tags, message, ioc}. Response: 201 with a list containing the created
    observable object(s).

    Returns `(observable_id, Gap | None)` — `observable_id` is TheHive's own
    assigned `_id` from that response, same `response.json()...get("_id")`
    pattern `create_case_from_alert` above uses. `None` on any failure
    (including a 201 whose body doesn't contain the expected list/`_id`
    shape).
    """
    timeout = timeout if timeout is not None else config.STAGE_1_TOOL_TIMEOUT_THEHIVE
    started = time.monotonic()

    def gap(reason: str) -> Gap:
        return Gap(
            source=SOURCE, tool="create_case_observable", reason=reason,
            duration_ms=int((time.monotonic() - started) * 1000),
        )

    if not case_id or not data:
        return None, gap(f"Missing case_id or data (case_id={case_id!r}, data={data!r})")

    body: dict[str, Any] = {"dataType": data_type, "data": data, "ioc": ioc}
    if message:
        body["message"] = message
    if tags:
        body["tags"] = tags

    try:
        response = await asyncio.wait_for(
            _write("POST", f"/api/v1/case/{case_id}/observable", timeout, body),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        return None, gap(f"Timeout after {timeout}s creating observable on case {case_id}")
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "create_case_observable failed for case %s, dataType=%s, data=%s: %s",
            case_id,
            data_type,
            data[:50] if len(data) > 50 else data,
            exc,
        )
        return None, gap(_describe_error(exc))

    created = response.json()
    if not isinstance(created, list) or not created:
        return None, gap(f"TheHive create-observable returned no object: {created!r}"[:250])
    observable_id = str(created[0].get("_id") or "")
    if not observable_id:
        return None, gap(f"TheHive create-observable response had no _id: {created[0]!r}"[:250])
    return observable_id, None
