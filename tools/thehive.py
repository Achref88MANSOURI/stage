"""TheHive case-correlation tools — architecture §6 tools 3 and 4, §13.

    get_full_alert_with_analysis    The alert + observables + Cortex taxonomies,
                                    in one call. Sole source of IOCs (§0.2) and
                                    of threat-intel verdicts (§6).
    search_open_cases_by_entities   Is there an open case sharing entities with
                                    this alert? Feeds Stage 3's merge/new call.

    2026-09-06: `search_closed_cases_by_rule` (TheHive closed-case historical
    lookup) is REMOVED — user-directed decision to rely solely on Qdrant's
    `incident_history` collection (`tools/qdrant.py::retrieve_incidents`,
    `IncidentMatch` in `schemas/evidence.py`) for historical TP/FP context,
    surfaced to Stage 4 as `historical_context` in
    `prompts/analyst_agent.py::_summarize_evidence`. That collection is itself
    sourced from TheHive closed cases (see `IncidentMatch`'s docstring), so no
    historical signal is lost — it now arrives via semantic similarity instead
    of an exact rule_uuid/tag match.

    create_case_from_alert          WRITE. Promotes an alert to a new case,
                                    then overwrites title/description/severity/
                                    tags with this pipeline's own computed
                                    content. `nodes/case_action.py`, not in
                                    architecture v4 — see that module's
                                    docstring and CLAUDE.md's "Case action"
                                    entry for why this file has a write
                                    section at all (2026-08-21, deliberate
                                    deviation from §1/§3's read-only design,
                                    user-directed).
    merge_alert_into_case           WRITE. Merges an alert into an existing
                                    case (`correlation_decision.merge_into_
                                    case_id`).
    update_case                     WRITE. Partial case update — severity,
                                    tlp and/or tags. Used for
                                    `merge_and_retier`.
    add_case_comment                WRITE. Appends a comment to a case —
                                    used to attach the full evidence/LLM
                                    summary on every merge (title/description
                                    overrides aren't accepted by the merge
                                    endpoint itself, unlike create).
    update_alert                    WRITE. Partial ALERT update — severity /
                                    tlp. Used on a `false_positive` verdict
                                    (2026-09-07): the alert is annotated and
                                    de-prioritised in place, never promoted.
    add_alert_comment               WRITE. Appends a comment to an ALERT —
                                    the triage narrative on a `false_positive`
                                    verdict, since no case exists to carry it.

    All NEVER RAISE, same contract as every read function above, and are
    LIVE-VERIFIED against the real instance — endpoints below were discovered
    empirically, not from any TheHive doc, because none of the guessed
    conventional paths were right on the first try:

        POST /api/v1/alert/{id}/case            create (NOT /promote — 404)
        POST /api/v1/alert/{id}/merge/{caseId}   merge  (confirmed via a real
                                                  400 "Alert is already
                                                  imported" on an already-
                                                  merged alert — a business-
                                                  logic error proves the path
                                                  is right; a 404 would have
                                                  meant it was wrong)
        PATCH /api/v1/case/{id}                  update (204, no body)
        POST /api/v1/case/{id}/comment           comment (201, returns the
                                                  created Comment object) —
                                                  NOT /api/v1/comment/case/{id}
                                                  (404)
        PATCH /api/v1/alert/{id}                 alert update (204, no body)
                                                  — verified 2026-09-07
        POST /api/v1/alert/{id}/comment          alert comment (201, returns
                                                  the created Comment) —
                                                  verified 2026-09-07

    `create_case_from_alert`'s empty-body `POST .../case` call creates a case
    from the ALERT's own title/severity/tags (confirmed live: case ~4464672,
    created from real alert ~4636880) — there was no second real alert left
    in this deployment to verify whether that same endpoint also accepts
    title/description/severity/tags overrides directly in the body, so this
    function does NOT assume it does. It always follows up with the already-
    independently-verified `PATCH` (`update_case`) to set this pipeline's own
    computed content — two confirmed calls composed, rather than one
    unverified one.

VERIFIED AGAINST THE LIVE BACKEND 2026-08-08 — TheHive 5.6.1 at
`http://172.20.24.221:9000`. Inventory at that time: **0 cases**, 3,640 alerts,
533,373 observables.

RE-VERIFIED 2026-08-13 after TheHive moved again — `http://172.20.24.228:9000`,
version 5.7.5-1, base path is `/api/v1` directly (NOT `/thehive`; that old
prefix now 200s with the SPA's HTML, a trap for a naive health check).
`get_full_alert_with_analysis` was rewritten this date: the custom
`getAlertWithObservables` Function it depended on is gone (`404 Function ... not
found`), but the stock `/api/v1/query` `getAlert` -> `observables` -> `page`
pipeline now returns `reports[analyzer].taxonomies` directly with no
`extraData` needed — confirmed live, so the custom Function is retired outright
rather than re-registered. See the function's own docstring for detail and
`thehive-reference/CONTEXT.md` for the (now historical) dependency it replaces.

Zero cases means both functions correctly return empty today, and per
implementation guide §2's table that IS the correct real result to verify at
this stage of deployment. To prove the queries are genuinely right rather than
silently matching nothing, the identical query shapes were run against the
Alert graph, which does have data:

    observable -> alert -> dedup -> count   ->  99   (same shape as Q1)
    listAlert filter tags=rule:<name>       ->  12   (same shape as Q2)

So the traversal, the `_in` filter, `dedup` and tag filtering are all confirmed
working. When cases exist, these shapes work unchanged.

THREE THINGS THE REAL SCHEMA FORCES, all confirmed via `/api/v1/describe/*`:

1. `stage` and `status` are DIFFERENT enumerations.
       stage  = New | InProgress | Closed
       status = New | InProgress | TruePositive | FalsePositive |
                Duplicated | Indeterminate | Other
   "Open" is `stage != "Closed"`. There is no "Closed" status value, so
   filtering status for openness silently matches everything.

2. **Rule uuid is not searchable.** Neither Case nor Alert has a rule-uuid
   attribute, and there are no customFields. `Alert.sourceRef` holds the
   Security Onion document id, not the rule id. The only rule identity TheHive
   carries is the `rule:<rule name>` tag that n8n stamps on the alert, plus the
   description text.

3. Case severity is `1..4` and TLP `0..4` — small ints, not the 0-100 scale
   used elsewhere in this pipeline. No conversion happens here.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Iterable

import httpx

import config
from schemas import (
    Gap,
    Observables,
    ShallowCase,
)

logger = logging.getLogger(__name__)

SOURCE = "thehive"

# Bounds. Open cases are capped because Stage 3 reads them all and a merge
# decision across dozens of cases is not a decision the prompt can make well.
MAX_OPEN_CASES = 20
# Per-case observable fetch is a second round trip each, so it is bounded
# separately and runs concurrently.
MAX_CASES_TO_ENRICH = 10
MAX_OBSERVABLES_PER_CASE = 50

# TheHive rejects an over-long `_values` array and the query gets slower with
# every entity added. Entity lists are truncated rather than dropped.
MAX_ENTITY_VALUES = 50


async def _query(body: dict, timeout: float, name: str = "soc3s") -> Any:
    """POST to TheHive's query API. Raises on transport or HTTP error.

    Unlike iTop, TheHive DOES use HTTP status codes for errors, so
    `raise_for_status` is meaningful here. A malformed query returns 400 with a
    body naming the offending path.
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
    """The alert plus its observables plus their Cortex taxonomies.

    Architecture §6 and implementation guide §0.2 name this function as the
    single source of BOTH the IOC list and the pre-computed threat-intel
    verdicts. Its return value is passed straight to
    `alert_builder.build_canonical_alert(..., hive_alert=<this>)`.

    TWO STOCK `/api/v1/query` CALLS, run concurrently — NOT a custom Function.

        {"query": [{"_name": "getAlert", "idOrName": alert_id}]}
        {"query": [{"_name": "getAlert", "idOrName": alert_id},
                    {"_name": "observables"},
                    {"_name": "page", "from": 0, "to": MAX_OBSERVABLES_PER_CASE}]}

    HISTORY, kept because it explains why this looks more roundabout than "just
    call the API": guide §0.2's documented approach — `extraData: ["reports"]`
    on observables — did not work on TheHive 5.7.3 (verified 2026-08-09, three
    ways, all yielding `['artifacts','full','success']` with no `summary`). The
    fix at the time was a custom server-side Function
    (`thehive-reference/getAlertWithObservables.json`), because its *internal*
    query engine's observable serialiser included `reports[analyzer].taxonomies`
    where the external API's didn't.

    RE-VERIFIED 2026-08-13 on the moved instance (172.20.24.228, 5.7.5-1): the
    custom Function is gone (`404 Function getAlertWithObservables not found`)
    — but so is the reason it was needed. The STOCK observables projection now
    returns `reports[analyzer].taxonomies` directly, no `extraData` required,
    confirmed against a real alert (`~4636880`, 4 observables, 3 carrying
    `reports`, e.g. `{"OpenCTI_v6_...": {"taxonomies": [...]}}`). The custom
    Function is retired outright rather than re-registered.

    NEVER RAISES. Returns `(hive_alert | None, Gap | None)`. Either call
    failing — TheHive down, alert id wrong, timeout — produces a Gap; the
    pipeline continues with reduced or no threat intel rather than failing.
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


def _entity_values(
    observables: Observables | None, host: str | None, user: str | None
) -> list[str]:
    """Flatten the alert's entities into the value list to match against.

    Hostname and username are included because n8n stamps them onto the alert as
    bare tags (confirmed on a real alert: `win-kvkmd51ggkq`, `172.20.24.99`
    alongside `host-ip:172.20.24.99`), and TheHive observables are frequently
    created for them too. Matching on them is what catches a second alert on the
    same host that shares no IOC.

    De-duplicated, order-preserving, and capped — a very long list makes the
    query slow and can be rejected outright.
    """
    values: list[str] = []

    def add(items: Iterable[str] | None) -> None:
        for item in items or []:
            if isinstance(item, str) and item.strip():
                values.append(item.strip())

    if observables is not None:
        add(observables.external_ips)
        add(observables.domains)
        add(observables.urls)
        hashes = observables.hashes
        add(hashes.md5)
        add(hashes.sha1)
        add(hashes.sha256)
        add(hashes.sha512)
        add(hashes.imphash)
    add([host] if host else None)
    add([user] if user else None)

    seen: set[str] = set()
    unique = [v for v in values if not (v in seen or seen.add(v))]
    if len(unique) > MAX_ENTITY_VALUES:
        logger.debug(
            "search_open_cases_by_entities: truncating %d entity values to %d",
            len(unique),
            MAX_ENTITY_VALUES,
        )
    return unique[:MAX_ENTITY_VALUES]


async def _fetch_similar_cases(thehive_alert_id: str, timeout: float) -> list[dict]:
    """`getAlert -> similarCases` — TheHive's native, server-side case-
    similarity engine, added 2026-08-19 (gap #12). Live-verified response
    shape (`tests/fixtures/thehive_similar_cases_real.json`, real alert
    `~4661456`, 2 real closed cases):

        [{"case": {"_id": ..., "stage": ..., "status": ..., ...},
          "similarObservableCount": 4, "observableCount": 4,
          "linkedWith": [{"dataType": "hash", "data": "...", ...}, ...],
          ...}, ...]

    One round trip replaces both the old `listObservable -> case` traversal
    AND the separate per-case `_fetch_case_observables` enrichment call —
    `linkedWith` already carries the overlapping observable values.

    RAISES on failure — unlike the public `search_*` functions, this helper
    does not swallow errors itself. Callers decide whether to fall back to
    the older hand-rolled query or surface a Gap; matches this file's
    existing layering (`_query` also raises, `search_*` functions are where
    the never-raises contract lives)."""
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
        # TheHive returns epoch milliseconds; Pydantic parses int timestamps as
        # SECONDS, which would place every case in 1970. Convert explicitly.
        created_at=_epoch_ms_to_datetime(created),
    )


def _epoch_ms_to_datetime(value):
    from datetime import datetime, timezone

    if isinstance(value, (int, float)) and value > 0:
        return datetime.fromtimestamp(value / 1000, tz=timezone.utc)
    return None


async def _fetch_case_observables(
    case_id: str, timeout: float
) -> tuple[str, list[str]]:
    """One case's observable values, for ShallowCase.observables.

    A separate round trip per case, which is why it is bounded by
    MAX_CASES_TO_ENRICH and run concurrently. Failure is non-fatal: a case
    without its observable list is still useful to Stage 3.
    """
    body = {
        "query": [
            {"_name": "getCase", "idOrName": case_id},
            {"_name": "observables"},
            {"_name": "page", "from": 0, "to": MAX_OBSERVABLES_PER_CASE},
        ]
    }
    try:
        rows = await _query(body, timeout, name="case-observables")
    except Exception as exc:  # noqa: BLE001 — partial data beats none
        logger.debug("Could not fetch observables for %s: %s", case_id, exc)
        return case_id, []
    values = [
        str(r.get("data"))
        for r in (rows or [])
        if isinstance(r, dict) and r.get("data")
    ]
    return case_id, values


async def fetch_case_observables_with_type(
    case_id: str, timeout: float | None = None
) -> tuple[list[dict], Gap | None]:
    """A case's full observable rows (dataType + value + tags).

    v6 redesign (2026-09-06): this used to have two callers — the old Stage
    4's pre-call fetch (for the LLM's judgment against a merge target's
    existing observables, DELETED along with the rest of the two-call
    design, see `nodes/triage.py`'s module docstring) and
    `nodes/case_action.py::_write_actionable_observables` (Stage 6, still
    live — dedup against a case's already-recorded observables before
    writing new ones). Only the first caller is gone; this function itself
    stays, now solely for the second.

    Distinct from `_fetch_case_observables` above: that function collapses
    each row to a bare value string (sufficient for its one caller, dedup
    inside `search_open_cases_by_entities`'s enrichment loop) and never
    raises but also never returns a `Gap`, since a missing observable list
    there is silently non-fatal. This function keeps `dataType`/`tags`
    (Stage 6 needs to tell an IP from a hash from a process path) and
    follows the standard NEVER RAISES + `Gap`-returning contract every other
    public function in this file uses.

    Same `getCase -> observables -> page` query `_fetch_case_observables`
    already proves live — this is additive, not a change to that function or
    its caller.

    NEVER RAISES. Returns `(rows, Gap | None)` where each row is
    `{"observable_id": str, "data_type": str, "value": str, "tags": list[str]}`.

    2026-08-23 fix: `observable_id` (TheHive's own `_id`) is now kept — the
    query response already carries it on every row (same `_id` field every
    other TheHive row in this file reads, e.g. `_to_shallow_case`), it just
    wasn't being copied into the returned dict before. Needed so
    `nodes/case_action.py` can tell whether an observable was judged
    already-existing on the case (reuse this id) or needs to be created (get
    a new one back from `create_case_observable`).
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
    observables: Observables | None,
    host: str | None = None,
    user: str | None = None,
    timeout: float | None = None,
    thehive_alert_id: str | None = None,
) -> tuple[list[ShallowCase], Gap | None]:
    """Open cases sharing any entity with this alert — architecture §6 tool 3.

    NEVER RAISES. Returns `(cases, Gap | None)`.

    An empty list with no Gap means "no open case shares an entity", which is a
    real answer and sets `correlation_mode = "new"`. A Gap means we could not
    find out. Those must stay distinguishable — architecture §2 requirement 4.

    Primary path (added 2026-08-19, gap #12): when `thehive_alert_id` is
    given, use TheHive's native `similarCases` query
    (`_fetch_similar_cases`), filtered to `stage != "Closed"` — one round
    trip, richer result (`ShallowCase.similar_observable_count`), no
    separate per-case observable enrichment needed. Falls through to the
    fallback path below on any failure (missing id, exception, timeout) —
    purely additive, never a new failure mode.

    Fallback path (original, unchanged): observable-first traversal
    (`listObservable -> filter -> case`) rather than case-first, because the
    observable index is what makes the entity match cheap; walking every
    case and inspecting its observables would not scale once cases exist.
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

    if thehive_alert_id:
        try:
            from datetime import datetime, timezone

            rows = await asyncio.wait_for(
                _fetch_similar_cases(thehive_alert_id, timeout), timeout=timeout
            )
            cases = [
                c
                for c in (_shallow_case_from_similar_row(r) for r in rows)
                if c is not None and c.stage != "Closed"
            ]
            epoch = datetime.min.replace(tzinfo=timezone.utc)
            cases.sort(key=lambda c: c.created_at or epoch, reverse=True)
            return cases[:MAX_OPEN_CASES], None
        except Exception as exc:  # noqa: BLE001 — fall through to the old path below
            logger.debug(
                "search_open_cases_by_entities: similarCases path failed (%s), "
                "falling back to entity-value query",
                exc,
            )

    values = _entity_values(observables, host, user)
    if not values:
        return [], gap(
            "Alert carried no observables, hostname or username — no entity to correlate on"
        )

    body = {
        "query": [
            {"_name": "listObservable"},
            {"_name": "filter", "_in": {"_field": "data", "_values": values}},
            {"_name": "case"},
            # stage, NOT status — see module docstring.
            {"_name": "filter", "_ne": {"_field": "stage", "_value": "Closed"}},
            {"_name": "dedup"},
            {"_name": "sort", "_fields": [{"_createdAt": "desc"}]},
            {"_name": "page", "from": 0, "to": MAX_OPEN_CASES},
        ]
    }

    try:
        rows = await asyncio.wait_for(
            _query(body, timeout, name="open-cases-by-entity"), timeout=timeout
        )
    except asyncio.TimeoutError:
        return [], gap(f"Timeout after {timeout}s querying TheHive for open cases")
    except Exception as exc:  # noqa: BLE001 — a tool must never raise into gather
        logger.warning("search_open_cases_by_entities failed: %s", exc)
        return [], gap(_describe_error(exc))

    if not isinstance(rows, list):
        return [], gap(f"Unexpected response shape from TheHive: {type(rows).__name__}")

    cases = [_to_shallow_case(r) for r in rows if isinstance(r, dict)]
    if not cases:
        return [], None

    # Enrich a bounded subset with their observables, concurrently.
    to_enrich = [c for c in cases[:MAX_CASES_TO_ENRICH] if c.case_id]
    if to_enrich:
        try:
            results = await asyncio.wait_for(
                asyncio.gather(
                    *(_fetch_case_observables(c.case_id, timeout) for c in to_enrich),
                    return_exceptions=True,
                ),
                timeout=timeout,
            )
            by_id = {
                case_id: obs
                for result in results
                if isinstance(result, tuple)
                for case_id, obs in [result]
            }
            for case in cases:
                case.observables = by_id.get(case.case_id, [])
        except asyncio.TimeoutError:
            logger.debug("Observable enrichment timed out; returning cases without it")

    return cases, None


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
    is two calls, not one. NEVER RAISES."""
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
    """Merge an alert into an existing case. NEVER RAISES."""
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
    own PATCH semantics, confirmed live). `severity` is 1..4, `tlp` is 0..4
    (0 clear / 1 green / 2 amber / 3 amber+strict / 4 red — verified against
    `/api/v1/describe/case` 2026-09-07). NEVER RAISES."""
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
    timeout: float | None = None,
) -> tuple[bool, Gap | None]:
    """Partial alert update — `PATCH /api/v1/alert/{id}`, returns 204 no
    body. Used on a `false_positive` verdict to drop the alert to low
    severity / clear TLP without promoting it to a case (2026-09-07,
    user-directed). Same `severity` 1..4 / `tlp` 0..4 vocabulary as
    `update_case` — verified against `/api/v1/describe/alert` and a real
    `PATCH` (204) 2026-09-07. NEVER RAISES."""
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
    """Append a comment to a case. NEVER RAISES."""
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
    comment`, returns 201 with the created comment. Used on a
    `false_positive` verdict to record the triage narrative on the alert
    itself, since no case is created (2026-09-07, user-directed).
    Live-verified: 201 + `{_id, _type: "Comment", message, ...}` against a
    real alert 2026-09-07. NEVER RAISES."""
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


# "filename" for process/file dataType is LIVE-VERIFIED (2026-08-21):
# confirmed working for process-path values (e.g. "C:\Windows\Temp\malware.exe").
# Other types (ip/domain/url/hash) are tier-1/2 confirmed via
# tests/fixtures/thehive_real.json (real captured observables) and
# tests/fixtures/thehive_create_observable_real.json (live creation probes).
# The bucket->dataType mapping itself now lives in nodes/case_action.py
# (_OBSERVABLE_TYPE_TO_DATATYPE) — that's the only caller of
# create_case_observable left after add_extracted_observables was retired
# 2026-08-23 (see that module's docstring for why).


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
    """Create one observable on an existing case. NEVER RAISES.

    LIVE-VERIFIED endpoint (2026-08-21): POST /api/v1/case/{id}/observable
    — confirmed against http://172.20.24.228:9000 (TheHive v5.7.5-1).
    See tests/fixtures/thehive_create_observable_real.json for the real
    request/response shape and provenance.

    Payload: {dataType, data, tags, message, ioc}. Response: 201 with a
    list containing the created observable object(s).

    Returns `(observable_id, Gap | None)` — `observable_id` is TheHive's own
    assigned `_id` from that response, same `response.json()...get("_id")`
    pattern `create_case_from_alert` above already uses. 2026-08-23 fix: this
    previously discarded the response entirely and returned a bare
    `(bool, Gap | None)` — the id TheHive handed back was fetched and thrown
    away on every single call. `None` on any failure (including a 201 whose
    body doesn't contain the expected list/`_id` shape).
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
