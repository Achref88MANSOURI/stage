"""`single_stage_triage` — v6 single-call redesign (SOC-3s v6 spec,
2026-09-06). Collapses the old Stage 3 (`context_analysis`, `nodes/
context.py`, deleted) + Stage 4 (`analyst_verdict`, `nodes/analyze.py`,
deleted) two-LLM-call design into ONE call. This is now the pipeline's
entire LLM budget — CLAUDE.md's old "exactly 2 LLM calls" hard constraint is
superseded by this redesign; there is exactly ONE now, made here and
nowhere else.

Single-shot, no tools: builds a prompt from the full `EnrichedEvidence` (no
firewall — see `schemas/verdict.py`'s module docstring for the accepted
tradeoff this is), calls the LLM once, parses/validates its response, and
never raises to its caller — any failure (connection error, timeout,
non-2xx status, malformed JSON, a response that fails Pydantic validation)
produces the same kind of deterministic `TriageVerdict` fallback instead
(`_stage_fallback`).

Not built on `nodes/_guard.py`, for the same reason the deleted
`nodes/context.py` never was: `_guarded`'s `default` parameter is a static
value, this node's fallback is a function of the input `evidence`, which
`_guarded`'s signature can't express cleanly; exactly one sequential call,
so the "outer wait_for + inner tool timeout" two-layer parallel-tool defense
doesn't apply — `httpx`'s own `timeout=` on the request is the only layer
needed.

**No pre-call `case_observables` fetch.** The old Stage 4 fetched the merge
target's existing TheHive observables before building its prompt, so it
could judge disposition against what the case already held. That fetch is
deleted outright here, not replaced by a lighter version — this call has no
visibility into the merge target's existing observables and cannot
deduplicate against them. Accepted risk (duplicate observable writes on
repeated merges), not solved here; see `nodes/case_action.py`'s module
docstring for where that fix would belong if it becomes a real problem.

**No `retrieve_playbooks` call.** Runbook retrieval depended on the old
Stage 3's *refined* MITRE mapping as a separate pre-call artifact between
the two old stages; that artifact doesn't exist any more in a one-call
design. Dropped entirely, not replaced — two live options to revisit this
later: move the Qdrant query into Stage 2 off Stage 1's raw MITRE
candidates (lower precision, but keeps it available as input context), or
query post-call in assembly using this call's own `refined_mitre_mapping`,
surfaced for the analyst but never fed back into a second LLM call.

`config.STAGE_TRIAGE_LLM_TIMEOUT` / `config.STAGE_TRIAGE_DESIRED_MAX_TOKENS`
consolidate the old per-stage `STAGE_3_*`/`STAGE_4_*` config (removed) — one
call, one budget. `_capped_max_tokens` is unchanged in mechanism from the
old Stage 3/4's identical (duplicated) function — still caps the requested
completion size against the real prompt so the two can never together
exceed the model's context window — but the single prompt here is now
old-Stage-3-sized (full evidence dump) while the response must be
old-Stage-4-sized (a verdict, not just a refinement), which is the single
most likely place this redesign fails first in practice.
`STAGE_TRIAGE_DESIRED_MAX_TOKENS` defaults to 16000 (the larger of the two
old per-stage defaults) precisely because of this.
"""

from __future__ import annotations

import json
import logging
import time

import httpx

import config
import prompts.triage_agent as prompts
from logging_config import alert_context
from schemas import (
    CorrelationDecision,
    EnrichedEvidence,
    EvidenceSituation,
    EvidenceSource,
    MitreMapping,
    RawEvidence,
    TriageVerdict,
)

logger = logging.getLogger(__name__)


async def single_stage_triage(evidence: EnrichedEvidence) -> TriageVerdict:
    with alert_context(evidence.canonical_alert.alert_id):
        return await _single_stage_triage(evidence)


async def _single_stage_triage(evidence: EnrichedEvidence) -> TriageVerdict:
    started = time.monotonic()
    logger.info("Triage stage started")
    try:
        raw_content = await _call_llm(evidence)
        parsed = _extract_first_json_object(raw_content)
        verdict = TriageVerdict.model_validate(parsed)
        verdict = _validate_merge_target(verdict, evidence)
        verdict = _validate_recommended_action(verdict)
        verdict = _validate_actionable_observables(verdict, evidence)
        verdict, gate_fired = _apply_safety_backstop(verdict)
        verdict.safety_gate_applied = gate_fired
    except Exception as exc:  # noqa: BLE001 — see module docstring, every failure falls back
        logger.warning("Triage LLM call/parse failed, using deterministic fallback: %s", exc)
        verdict = _stage_fallback(evidence)

    verdict.stage_duration_ms = int((time.monotonic() - started) * 1000)
    logger.info(
        "Triage stage completed in %dms: verdict=%s action=%s priority_band=%s "
        "evidence_reliability=%s safety_gate_applied=%s",
        verdict.stage_duration_ms,
        verdict.verdict,
        verdict.correlation_decision.action,
        verdict.priority_band,
        verdict.evidence_situation.overall_evidence_reliability,
        verdict.safety_gate_applied,
    )
    return verdict


def _capped_max_tokens(system_prompt: str, user_prompt: str, desired: int) -> int:
    """Caps the requested completion max_tokens so prompt + completion stays
    under the model's real context window — see config.py's
    LLM_MAX_CONTEXT_TOKENS/LLM_TOKEN_ESTIMATE_CHARS_PER_TOKEN/
    LLM_CONTEXT_SAFETY_MARGIN_TOKENS docstrings for the live-caught bug this
    closes and why the estimate is character-based and deliberately
    conservative. Unchanged in mechanism from the old (deleted) Stage 3/4's
    identical duplicated functions."""
    estimated_prompt_tokens = len(system_prompt + user_prompt) / config.LLM_TOKEN_ESTIMATE_CHARS_PER_TOKEN
    available = (
        config.LLM_MAX_CONTEXT_TOKENS - estimated_prompt_tokens - config.LLM_CONTEXT_SAFETY_MARGIN_TOKENS
    )
    return max(config.LLM_MIN_COMPLETION_TOKENS, min(desired, int(available)))


async def _call_llm(evidence: EnrichedEvidence) -> str:
    user_prompt = prompts.build_user_prompt(evidence)
    max_tokens = _capped_max_tokens(
        prompts.SYSTEM_PROMPT, user_prompt, config.STAGE_TRIAGE_DESIRED_MAX_TOKENS
    )
    payload = {
        "model": config.LLM_MODEL,
        "messages": [
            {"role": "system", "content": prompts.SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "TriageVerdict",
                "schema": prompts.build_triage_verdict_schema(evidence),
            },
        },
        "temperature": 0.1,
        "max_tokens": max_tokens,
        "stream": False,
    }
    logger.info(
        "Triage LLM call started (model=%s, timeout=%ss, max_tokens=%d)",
        config.LLM_MODEL,
        config.STAGE_TRIAGE_LLM_TIMEOUT,
        max_tokens,
    )
    llm_started = time.monotonic()
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{config.LLM_BASE_URL}/chat/completions",
            headers={"Authorization": f"Bearer {config.LLM_API_KEY}"},
            json=payload,
            timeout=config.STAGE_TRIAGE_LLM_TIMEOUT,
        )
        resp.raise_for_status()
        logger.info("Triage LLM call completed in %.1fs", time.monotonic() - llm_started)
        return resp.json()["choices"][0]["message"]["content"]


def _extract_first_json_object(content: str) -> dict:
    """Only the first JSON value in the string is trustworthy. Live-testing
    under plain `json_object` mode (the old Ollama/vLLM deployments) showed
    the model emitting a valid JSON object followed by hallucinated extra
    prose/JSON turns — `json.loads()` on the whole string fails or (worse)
    succeeds on the wrong thing. `json_schema` mode didn't reproduce that in
    testing, but nothing guarantees it can't with a different prompt shape,
    so this stays defensive rather than assuming the stricter mode never
    regresses."""
    return json.JSONDecoder().raw_decode(content.strip())[0]


def _validate_merge_target(verdict: TriageVerdict, evidence: RawEvidence) -> TriageVerdict:
    """Defense-in-depth behind the schema-level enum constraint in
    prompts.triage_agent.build_triage_verdict_schema — belt and suspenders
    for the case the backend's schema enforcement doesn't hold. Never called
    on the fallback path, which sources merge_into_case_id directly from
    evidence.open_cases and is correct by construction."""
    merge_id = verdict.correlation_decision.merge_into_case_id
    if merge_id is None:
        return verdict

    real_ids = {case.case_id for case in evidence.open_cases}
    if merge_id not in real_ids:
        logger.warning(
            "Triage stage proposed merge_into_case_id=%r not in open_cases, discarding", merge_id
        )
        verdict.correlation_decision.merge_into_case_id = None
        verdict.investigation_gaps.append(
            f"LLM proposed merge target {merge_id!r} not present in open_cases — "
            "discarded, treated as new"
        )
    return verdict


def _validate_recommended_action(verdict: TriageVerdict) -> TriageVerdict:
    """Defense-in-depth for the structural gap the single-call design
    introduces (see schemas/verdict.py and prompts/triage_agent.py module
    docstrings): `recommended_action`'s schema enum can no longer be
    narrowed to just the branch matching `correlation_decision.action`
    ahead of generation, because both fields come from the SAME response.
    This checks self-consistency post-parse instead — mirrors the old
    (deleted) Stage 4 validator's exact role, just checking against this
    response's own correlation_decision instead of a separate prior stage's
    already-decided output."""
    action = verdict.correlation_decision.action
    invalid = (action == "merge" and verdict.recommended_action == "create_case") or (
        action == "new" and verdict.recommended_action in ("merge_quiet", "merge_and_retier")
    )
    if invalid:
        logger.warning(
            "Triage stage recommended_action=%r incompatible with its own "
            "correlation_decision.action=%r, falling back to needs_review",
            verdict.recommended_action,
            action,
        )
        verdict.recommended_action = "needs_review"
    return verdict


def _validate_actionable_observables(verdict: TriageVerdict, evidence: RawEvidence) -> TriageVerdict:
    """Defense-in-depth for the same live-observed failure mode the old
    (deleted) Stage 3/4 validators guarded against: fabricated values with
    no basis anywhere in the evidence. No firewall boundary exists any more
    (see schemas/verdict.py's module docstring) — this single call sees the
    FULL evidence dump, so validation checks against the whole
    evidence.model_dump_json(), not a restricted known/extracted/
    case-observables union the way the old Stage 4 validator did.

    Uses the JSON-escaping-safe comparison from the 2026-08-23 fix
    (CLAUDE.md): json.dumps(value, ensure_ascii=False)[1:-1] against a
    haystack built the same way — a value containing a backslash, quote, or
    non-ASCII character must not be wrongly discarded (a real Windows path
    was, before that fix)."""
    evidence_json = evidence.model_dump_json()
    kept = []
    for item in verdict.actionable_observables:
        needle = json.dumps(item.value, ensure_ascii=False)[1:-1]
        if needle not in evidence_json:
            logger.warning(
                "Triage stage actionable_observables value %r not traceable to evidence, "
                "discarding as a likely hallucination",
                item.value,
            )
            verdict.investigation_gaps.append(
                f"LLM proposed actionable observable {item.value!r} not traceable to any "
                "evidence field — discarded as a likely hallucination"
            )
            continue
        kept.append(item)
    verdict.actionable_observables = kept
    return verdict


def _apply_safety_backstop(verdict: TriageVerdict) -> tuple[TriageVerdict, bool]:
    """Deterministic safety gate applied after LLM output is parsed
    (unchanged from the old (deleted) Stage 4's identical function, now
    reading evidence_situation directly off the single verdict object
    instead of a separate `context` argument).

    If evidence reliability is low AND the LLM assigned P4 or P5, escalate
    by one band. This catches cases where the LLM ignored the evidence
    situation instructions in the prompt.

    Returns the (possibly modified) verdict and a boolean indicating
    whether the gate fired."""
    if verdict.evidence_situation.overall_evidence_reliability != "low":
        return verdict, False

    escalation_map = {"P5": "P4", "P4": "P3"}
    if verdict.priority_band not in escalation_map:
        return verdict, False

    new_band = escalation_map[verdict.priority_band]
    new_reasoning = (
        verdict.priority_reasoning
        + f"\n\n[SAFETY GATE APPLIED]: Priority escalated from "
        f"{verdict.priority_band} to {new_band}. Evidence reliability was "
        f"'low' — automated triage cannot safely close or defer this alert. "
        f"A human analyst must review."
    )

    updated = verdict.model_copy(update={
        "priority_band": new_band,
        "priority_reasoning": new_reasoning,
    })
    return updated, True


_FALLBACK_EVIDENCE_SOURCE_NAMES = (
    "fp_signal",
    "rule_context",
    "open_cases",
    "asset_context",
    "related_alerts_1h",
    "opencti_enrichment",
)


def _stage_fallback(evidence: RawEvidence) -> TriageVerdict:
    """Merged fallback, replacing both the old (deleted) `_stage_3_fallback`
    and `_stage_4_fallback`. Never fabricates a verdict; always escalates to
    human review on failure.

    `priority_band` defaults to P2, not P3 — carried over from the old Stage
    4 fallback's stated rationale (`newdesign.md` §4): a failed pipeline
    cannot safely be treated as low-risk, and P2 guarantees the alert
    reaches an analyst this shift. `safety_gate_applied=True` unconditionally
    — a downed LLM is itself the reliability failure the safety gate exists
    to catch, so this path always reports the gate as fired, the same way
    the LLM path's `_apply_safety_backstop` would if it had run against
    `overall_evidence_reliability="low"` (which this fallback always sets).
    `refined_mitre_mapping` is preserved from `rule_context.mitre_attack` —
    does NOT return an empty list (the v3 "silent severity cap" bug,
    architecture §8's own named warning). `actionable_observables` stays
    empty — a downed LLM must never fabricate an IOC or a response action."""
    rule_context = evidence.rule_context
    mitre_attack = rule_context.mitre_attack if rule_context else []

    gap_sources = {g.tool for g in evidence.investigation_gaps}
    sources = []
    for name in _FALLBACK_EVIDENCE_SOURCE_NAMES:
        if name in gap_sources:
            status = "missing"
            impact = f"{name} unavailable — triage LLM also failed; cannot assess impact."
        else:
            status = "present"
            impact = f"{name} data available but triage LLM failed — assessment not performed."
        sources.append(EvidenceSource(source_name=name, status=status, impact_on_triage=impact))

    evidence_situation = EvidenceSituation(
        sources=sources,
        overall_evidence_reliability="low",
        analyst_must_verify=[
            "Triage LLM call failed — complete manual review required. "
            "All automated evidence interpretation is unavailable."
        ],
    )

    return TriageVerdict(
        refined_mitre_mapping=[
            MitreMapping(
                technique_id=technique_id,
                confidence="medium",
                basis="deterministic fallback from rule_context",
            )
            for technique_id in mitre_attack
        ],
        correlation_decision=CorrelationDecision(
            action="merge" if evidence.open_cases else "new",
            merge_into_case_id=evidence.open_cases[0].case_id if evidence.open_cases else None,
            kill_chain_progression_detected=False,
            reasoning="Deterministic fallback: LLM unavailable",
        ),
        evidence_situation=evidence_situation,
        likelihood="possible",
        impact_if_true="moderate",
        verdict="needs_review",
        reasoning="Triage LLM unavailable, defaulting to human review",
        summary="Automated triage failed, analyst review required",
        recommended_action="needs_review",
        evidence_citations=[],
        actionable_observables=[],
        priority_band="P2",
        priority_reasoning=(
            "Triage LLM call failed — priority defaulted to P2 to ensure human review. "
            "A failed pipeline cannot safely be treated as low-risk."
        ),
        investigation_gaps=[
            "Triage LLM call failed — complete manual triage required. "
            "No automated assessment was produced."
        ],
        safety_gate_applied=True,
    )
