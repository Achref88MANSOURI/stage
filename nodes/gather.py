"""`gather_evidence` — Stage 1, architecture §6.

Runs all six remaining Stage 1 tool calls in parallel (of the original
architecture §6 seven, two are gone — `search_closed_cases_by_rule` and
`elasticsearch_process_history`, both removed 2026-09-06, user-directed, see
below — plus `opencti_observable_enrichment`, a deployment addition — see
`tools/opencti.py`'s module docstring and CLAUDE.md) and assembles a
`RawEvidence`. Never raises: every call is wrapped twice —

1. Each tool already wraps its own backend call in an internal
   `asyncio.wait_for(..., config.STAGE_1_TOOL_TIMEOUT_*)` and never raises on
   its own (documented on every tool, e.g. `detection_rules.py`).
2. `_guarded` here adds an OUTER `asyncio.wait_for` around each already-safe
   call — the tool's own timeout bounds the backend call itself; this one
   bounds total wall time including event-loop scheduling, and is the last
   line of defense if a tool's internal safety net has a bug and raises
   anyway.

All `_guarded`/`_skip` coroutines still go through one
`asyncio.gather(..., return_exceptions=True)` on top of that (CLAUDE.md's
literal hard constraint), even though nothing should ever reach it as a raw
exception given the two layers above.

`elasticsearch_process_history` (formerly call 7, "what other processes ran
on this host") is REMOVED (2026-09-06, user-directed) — it queried the host
with no suspiciousness filter (a 24h window, up to 50 hits, legitimate
processes included by design), and the raw ancestry context wasn't judged
worth its prompt-size cost. `PROCESS_DATASET`'s dataset-gating logic, the
`process_history_call`/`_skip` branch, and `RawEvidence.process_history_24h`
are all gone with it. See `tools/elasticsearch.py`'s module docstring for
the full rationale.

`elasticsearch_related_alerts` (call 6) is passed `alert.network` and
`alert.investigation_profile` — as of 2026-08-21 (gap #17) that tool
branches internally on the profile to query the right index with the right
field set for Sigma vs. Suricata alerts (see `tools/elasticsearch.py`'s
module docstring for why one query can't serve both). This is the one
concrete use of `InvestigationProfile`'s originally-documented purpose
("nodes/gather.py and nodes/rag.py switch on these for deterministic
tool/retrieval selection", `schemas/alert.py`) — everything else in this
file still runs the identical fixed tool set regardless of engine (gap #19,
still open). It is also passed `hours=RELATED_ALERTS_WINDOW_HOURS` (1, was
the tool's own default of 24) — user-directed 2026-09-06, to keep this
signal tight to genuinely concurrent activity and reduce Stage 3's prompt
size (`related_alerts_1h` on `RawEvidence`, renamed from `related_alerts_24h`
to match).

`search_closed_cases_by_rule` (formerly call 4, TheHive's exact rule_uuid/tag
closed-case lookup) is REMOVED (2026-09-06, user-directed). Its brief
replacement, Qdrant's `incident_history`-based `EnrichedEvidence.
incident_matches` (Stage 2), was ALSO REMOVED the same day, user-directed.
There is no historical-TP/FP-context source anywhere in this pipeline any
more. See `tools/qdrant.py`'s module docstring for the full removal chain.

Every optional `RawEvidence` field this node sets is always a real,
zero-value model (`FPSignal()`, `RuleContext(found=False)`, ...), never a
bare `None` — matching how every individual tool already behaves on its own
failure path. A `None` here would just mean "go look up the Gap by hand";
a populated zero-value object plus the Gap is strictly more useful.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import config
from logging_config import alert_context
from nodes._guard import _guarded, _unpack
from schemas import (
    AssetContext,
    CanonicalAlert,
    FPSignal,
    RawEvidence,
    RuleContext,
)
from tools import detection_rules, elasticsearch, fp_tracking, itop, opencti, thehive

logger = logging.getLogger(__name__)

# Narrowed from the tool's own 24h default — user-directed 2026-09-06 — see
# module docstring.
RELATED_ALERTS_WINDOW_HOURS = 1


async def gather_evidence(alert: CanonicalAlert) -> RawEvidence:
    with alert_context(alert.alert_id):
        return await _gather_evidence(alert)


async def _gather_evidence(alert: CanonicalAlert) -> RawEvidence:
    started = time.monotonic()
    logger.info(
        "Stage 1 started: rule=%r host=%r dataset=%r",
        alert.rule.name,
        alert.host.hostname if alert.host else None,
        alert.event_dataset,
    )

    host = alert.host
    user = alert.user
    hostname = host.hostname if host else None
    host_id = host.host_id if host else None
    username = user.name if user else None

    calls = [
        _guarded(
            fp_tracking.get_fp_signal(alert.rule.uuid, hostname),
            seconds=config.STAGE_1_TOOL_TIMEOUT_FP,
            default=FPSignal(),
            source=fp_tracking.SOURCE,
            tool=fp_tracking.TOOL_NAME_GET,
        ),
        _guarded(
            detection_rules.detection_rule_lookup(alert.rule.uuid),
            seconds=config.STAGE_1_TOOL_TIMEOUT_ES,
            default=RuleContext(found=False),
            source=detection_rules.SOURCE,
            tool=detection_rules.TOOL_NAME,
        ),
        _guarded(
            thehive.search_open_cases_by_entities(
                alert.observables, hostname, username, thehive_alert_id=alert.thehive_alert_id
            ),
            seconds=config.STAGE_1_TOOL_TIMEOUT_THEHIVE,
            default=[],
            source=thehive.SOURCE,
            tool="search_open_cases_by_entities",
        ),
        _guarded(
            itop.itop_asset_lookup(hostname, host_id),
            seconds=config.STAGE_1_TOOL_TIMEOUT_ITOP,
            default=AssetContext(found=False),
            source=itop.SOURCE,
            tool=itop.TOOL_NAME,
        ),
        _guarded(
            elasticsearch.elasticsearch_related_alerts(
                host,
                user,
                alert.observables,
                network=alert.network,
                investigation_profile=alert.investigation_profile,
                hours=RELATED_ALERTS_WINDOW_HOURS,
            ),
            seconds=config.STAGE_1_TOOL_TIMEOUT_ES,
            default=[],
            source=elasticsearch.SOURCE,
            tool=elasticsearch.TOOL_NAME_RELATED,
        ),
        _guarded(
            opencti.opencti_observable_enrichment(alert.observables),
            seconds=config.STAGE_1_TOOL_TIMEOUT_OPENCTI,
            default=[],
            source=opencti.SOURCE,
            tool=opencti.TOOL_NAME,
        ),
    ]

    results = await asyncio.gather(*calls, return_exceptions=True)
    evidence = _build_raw_evidence(alert, results, started)
    logger.info(
        "Stage 1 completed in %dms: %d gaps",
        evidence.stage_1_duration_ms,
        len(evidence.investigation_gaps),
    )
    return evidence


def _build_raw_evidence(alert: CanonicalAlert, results: list[Any], started: float) -> RawEvidence:
    fp_signal, gap_fp = _unpack(results[0], FPSignal())
    rule_context, gap_rule = _unpack(results[1], RuleContext(found=False))
    open_cases, gap_open = _unpack(results[2], [])
    asset_context, gap_asset = _unpack(results[3], AssetContext(found=False))
    related_alerts, gap_related = _unpack(results[4], [])
    opencti_enrichment, gap_opencti = _unpack(results[5], [])

    gaps = [
        g
        for g in (
            gap_fp,
            gap_rule,
            gap_open,
            gap_asset,
            gap_related,
            gap_opencti,
        )
        if g is not None
    ]

    return RawEvidence(
        canonical_alert=alert,
        fp_signal=fp_signal,
        rule_context=rule_context,
        open_cases=open_cases,
        asset_context=asset_context,
        related_alerts_1h=related_alerts,
        opencti_enrichment=opencti_enrichment,
        investigation_gaps=gaps,
        stage_1_duration_ms=int((time.monotonic() - started) * 1000),
    )
