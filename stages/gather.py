"""`gather_evidence` — runs every backend tool call for Stage 1 concurrently
and assembles the results into a `RawEvidence`.

Every call is guarded twice: each tool already wraps its own backend call
in an internal timeout and never raises on its own, and `_guarded` here
adds a second, outer timeout as a last line of defense in case a tool's
internal handling has a bug. All calls run through
`asyncio.gather(return_exceptions=True)` on top of both layers.

There's no historical-context lookup in this pipeline beyond
`fp_tracking`'s own per-rule false-positive count — no related-alerts
search, no closed-case lookup, no incident history.

Every optional field this stage sets is a real zero-value model
(`FPSignal()`, `RuleContext(found=False)`, etc.) rather than `None`,
matching how each tool already behaves on failure — a populated zero-value
object paired with a Gap carries more information than a bare `None` would.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import config
from logging_config import alert_context
from stages._guard import _guarded, _unpack
from schemas import (
    AssetContext,
    CanonicalAlert,
    FPSignal,
    RawEvidence,
    RuleContext,
)
from tools import detection_rules, fp_tracking, itop, opencti, thehive

logger = logging.getLogger(__name__)


async def gather_evidence(alert: CanonicalAlert) -> RawEvidence:
    with alert_context(alert.alert_id):
        return await _gather_evidence(alert)


async def _gather_evidence(alert: CanonicalAlert) -> RawEvidence:
    started = time.monotonic()
    logger.info(
        "Gather started: rule=%r host=%r dataset=%r",
        alert.rule.name,
        alert.host.hostname if alert.host else None,
        alert.event_dataset,
    )

    hostname = alert.host.hostname if alert.host else None
    host_id = alert.host.host_id if alert.host else None

    calls = [
        _guarded(
            fp_tracking.get_fp_signal(alert.rule.uuid),
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
            thehive.search_open_cases_by_entities(alert.thehive_alert_id),
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
        "Gather completed in %dms: %d gaps",
        evidence.stage_1_duration_ms,
        len(evidence.investigation_gaps),
    )
    return evidence


def _build_raw_evidence(alert: CanonicalAlert, results: list[Any], started: float) -> RawEvidence:
    fp_signal, gap_fp = _unpack(results[0], FPSignal())
    rule_context, gap_rule = _unpack(results[1], RuleContext(found=False))
    open_cases, gap_open = _unpack(results[2], [])
    asset_context, gap_asset = _unpack(results[3], AssetContext(found=False))
    opencti_enrichment, gap_opencti = _unpack(results[4], [])

    gaps = [
        g
        for g in (
            gap_fp,
            gap_rule,
            gap_open,
            gap_asset,
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
        opencti_enrichment=opencti_enrichment,
        investigation_gaps=gaps,
        stage_1_duration_ms=int((time.monotonic() - started) * 1000),
    )
