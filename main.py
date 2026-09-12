"""FastAPI HTTP entrypoint: POST /triage, GET /health.

Runs the full pipeline synchronously for one alert. The incoming payload
only carries thehive_alert_id and raw_alert, so this module fetches the full
TheHive alert record itself before building the canonical alert.

Every failure returns HTTP 200 with success=False and a failed_stage marker
rather than an error status, so the caller inspects the response body
instead of relying on status codes. Each pipeline stage already degrades
gracefully on its own, so the top-level try/except here mainly covers
ingestion failures and unexpected bugs. The current stage is tracked
explicitly rather than inferred from the exception, and any partial result
already built is returned rather than discarded.

Result assembly copies the LLM verdict's fields onto the response with no
scoring math of its own. False-positive verdicts are recorded to the local
FP-tracking store, keyed on the rule's uuid, before the case-action write
runs.
"""

from __future__ import annotations

import logging
import time

import httpx
from fastapi import FastAPI
from fastapi.responses import JSONResponse

import alert_builder
import config
from logging_config import alert_context
from stages import case_action as case_action_mod
from stages import gather as gather_mod
from stages import rag as rag_mod
from stages import triage as triage_mod
from schemas import (
    AlertWebhookPayload,
    CanonicalAlert,
    EnrichedEvidence,
    IocObservable,
    TriageResponse,
    TriageResult,
    TriageVerdict,
)
from tools import fp_tracking, thehive

logger = logging.getLogger(__name__)

app = FastAPI(title="SOC-3s triage")


def _build_ioc_observables(
    hive_alert: dict | None, evidence: EnrichedEvidence
) -> list[IocObservable]:
    """Builds the alert's ioc=true observables, each paired with the Cortex
    analyzer output that ran against it (joined by observable value).
    Non-IOC observables (hostname, endpoint IP, ...) are left out.

    Reads hive_alert.observables directly for fields alert_builder collapses
    away (_id, dataType, tags, ioc), and joins against
    evidence.canonical_alert.cortex_results by observable value."""
    cortex_by_value: dict[str, list] = {}
    for cr in evidence.canonical_alert.cortex_results:
        cortex_by_value.setdefault(cr.observable, []).append(cr)

    out: list[IocObservable] = []
    for obs in (hive_alert or {}).get("observables", []) or []:
        if obs.get("ioc") is not True:
            continue
        value = str(obs.get("data") or "")
        if not value:
            continue
        out.append(
            IocObservable(
                observable_id=str(obs.get("_id") or ""),
                data_type=str(obs.get("dataType") or ""),
                value=value,
                tags=list(obs.get("tags") or []),
                analyzer_results=cortex_by_value.get(value, []),
            )
        )
    return out


def _build_triage_result(
    verdict: TriageVerdict, evidence: EnrichedEvidence, hive_alert: dict | None
) -> TriageResult:
    """Assembles the final TriageResult from the LLM verdict and the
    gathered evidence. Priority, reasoning, and gaps are already on the
    verdict; this just copies them across and attaches the IOC observable
    list."""
    started = time.monotonic()
    alert_id = evidence.canonical_alert.alert_id

    result = TriageResult(
        alert_id=alert_id,
        verdict=verdict.verdict,
        recommended_action=verdict.recommended_action,
        summary=verdict.summary,
        reasoning=verdict.reasoning,
        likelihood=verdict.likelihood,
        impact_if_true=verdict.impact_if_true,
        ioc_observables=_build_ioc_observables(hive_alert, evidence),
        actionable_observables=verdict.actionable_observables,
        correlation_reasoning=verdict.correlation_decision.reasoning,
        refined_mitre_mapping=verdict.refined_mitre_mapping,
        investigation_gaps=verdict.investigation_gaps,
        triage_assessment=verdict,
        priority_band=verdict.priority_band,
        priority_reasoning=verdict.priority_reasoning,
        safety_gate_applied=verdict.safety_gate_applied,
        evidence_situation=verdict.evidence_situation,
        stage_5_duration_ms=int((time.monotonic() - started) * 1000),
    )
    logger.info(
        "Result assembled: priority_band=%s safety_gate_applied=%s",
        result.priority_band,
        result.safety_gate_applied,
    )
    return result


async def _record_fp_feedback(alert: CanonicalAlert, verdict: TriageVerdict) -> None:
    """Records a false-positive outcome to the FP tracking store.

    Called only when the verdict is false_positive, since the store tracks
    counts rather than a rate and a true-positive write would corrupt the
    signal. Best-effort: never raises, and skips silently (just a log line)
    if the rule has no uuid to key on."""
    rule_uuid = alert.rule.uuid if alert.rule else ""
    if not rule_uuid:
        logger.info("Skipping FP feedback write: rule_uuid is empty")
        return
    try:
        ok, gap = await fp_tracking.record_triage_outcome(
            rule_uuid, analyst_reason=verdict.reasoning
        )
        if not ok:
            logger.warning(
                "FP feedback write failed: %s", gap.reason if gap else "unknown reason"
            )
    except Exception as exc:  # noqa: BLE001 — this write must never fail the pipeline
        logger.warning("FP feedback write raised unexpectedly: %s", exc)


@app.post("/triage", response_model=TriageResponse)
async def triage(payload: AlertWebhookPayload) -> TriageResponse:
    return await run_pipeline(payload)


async def run_pipeline(payload: AlertWebhookPayload) -> TriageResponse:
    stage = "ingest"
    result: TriageResult | None = None

    with alert_context(payload.thehive_alert_id):
        try:
            hive_alert, gap = await thehive.get_full_alert_with_analysis(
                payload.thehive_alert_id
            )
            if gap:
                logger.warning("main: hive_alert fetch degraded: %s", gap.reason)
            alert = alert_builder.build_canonical_alert(
                payload.raw_alert,
                hive_alert,
                payload.thehive_alert_id,
            )

            stage = "gather"
            raw_evidence = await gather_mod.gather_evidence(alert)

            stage = "rag"
            evidence = await rag_mod.rag_enrichment(raw_evidence)

            stage = "triage"
            verdict = await triage_mod.single_stage_triage(evidence)

            if verdict.verdict == "false_positive":
                await _record_fp_feedback(alert, verdict)

            stage = "build_result"
            result = _build_triage_result(verdict, evidence, hive_alert)

            stage = "case_action"
            result.case_action = await case_action_mod.case_action(verdict, evidence)
            # case_action is the only place a real TheHive observable id gets
            # resolved or created, so replace both copies with the enriched
            # version to keep the response internally consistent.
            result.actionable_observables = result.case_action.actionable_observables_written
            verdict.actionable_observables = result.case_action.actionable_observables_written
            result.case_id = result.case_action.case_id
            result.case_number = result.case_action.case_number
            result.is_new_case = result.case_action.is_new_case

            logger.info(
                "triage completed: alert_id=%s priority_band=%s case_action.success=%s",
                result.alert_id,
                result.priority_band,
                result.case_action.success if result.case_action else None,
            )
            return TriageResponse(success=True, result=result)

        except Exception as exc:  # noqa: BLE001 — always return 200, see module docstring
            logger.exception(
                "triage pipeline failed at stage=%s for thehive_alert_id=%s",
                stage,
                payload.thehive_alert_id,
            )
            return TriageResponse(
                success=False,
                result=result,
                error=f"{type(exc).__name__}: {exc}",
                failed_stage=stage,
            )


@app.get("/health")
async def health() -> JSONResponse:
    """Checks that the LLM backend is reachable. Doesn't probe the other
    dependencies (Elasticsearch, TheHive, iTop, Qdrant) — this is meant as a
    cheap, fast check that would still catch a dead endpoint or expired
    credential before it fails a real alert."""
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{config.LLM_BASE_URL}/models",
                headers={"Authorization": f"Bearer {config.LLM_API_KEY}"},
                timeout=10.0,
            )
        resp.raise_for_status()
        return JSONResponse({"status": "ok", "llm_base_url": config.LLM_BASE_URL})
    except Exception as exc:  # noqa: BLE001 — health check must never itself crash
        return JSONResponse(
            {"status": "degraded", "llm_base_url": config.LLM_BASE_URL, "error": str(exc)},
            status_code=503,
        )
