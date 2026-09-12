"""`single_stage_triage` — the pipeline's one and only LLM call.

Builds a prompt from the full `EnrichedEvidence`, calls the LLM once, and
parses and validates the response. Any failure along the way — connection
error, timeout, a non-2xx response, malformed JSON, or a response that
fails schema validation — falls back to a deterministic `TriageVerdict`
instead of raising (`_stage_fallback`).

This doesn't use `stages/_guard.py`: `_guarded`'s fallback value has to be
static, but this stage's fallback depends on the input evidence, which
doesn't fit that signature. There's also only one sequential call here, so
the outer-timeout pattern used for concurrent tool calls isn't needed —
`httpx`'s own request timeout is the only layer required.

Two things this call deliberately doesn't do: it never fetches the merge
target's existing TheHive observables before generating
`actionable_observables`, so a duplicate observable can be written on a
repeated merge (an accepted risk — see `stages/case_action.py`); and it
never queries for playbooks, since that would need a refined MITRE mapping
that doesn't exist as a separate artifact in a single-call design.

`_capped_max_tokens` caps the requested completion size so the prompt and
completion together can't exceed the model's context window. The prompt
here carries the full evidence dump and the response must carry a full
verdict, so `config.STAGE_TRIAGE_DESIRED_MAX_TOKENS` is set generously
(16000) to leave enough room.
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
    except Exception as exc:  # noqa: BLE001 — any failure here falls back to a deterministic verdict
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
    """Caps the requested completion size so prompt and completion together
    stay under the model's context window. Prompt size is estimated from
    character count, since not every backend model has a matching local
    tokenizer available — see config.py for the conversion constants."""
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
    """Parses only the first JSON value in the response. Under plain
    json_object mode, a model can keep generating after a complete object,
    which would break a plain json.loads() call. json_schema mode is less
    prone to this but not guaranteed immune, so this stays defensive
    either way."""
    return json.JSONDecoder().raw_decode(content.strip())[0]


def _validate_merge_target(verdict: TriageVerdict, evidence: RawEvidence) -> TriageVerdict:
    """Backstops the schema-level enum constraint in
    `build_triage_verdict_schema`, in case the backend doesn't enforce it.
    Discards `merge_into_case_id` if it isn't one of the alert's real open
    cases. Not used on the fallback path, which sources the id directly
    from evidence and is correct by construction."""
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
    """`recommended_action` and `correlation_decision.action` come from the
    same LLM response, so the schema can't always constrain
    `recommended_action` to match whichever branch of `action` the model
    picks. Checks the two are consistent after parsing and falls back to
    `needs_review` if not."""
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
    """Discards any actionable observable whose value doesn't appear
    anywhere in the evidence, since this call sees the full evidence dump
    with nothing filtered out first.

    The comparison escapes the value the same way
    `evidence.model_dump_json()` does (`json.dumps(value,
    ensure_ascii=False)[1:-1]`) before searching for it, so a value
    containing a backslash, quote, or non-ASCII character isn't wrongly
    flagged just because JSON serialization escapes it differently than
    the raw string looks."""
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
    """Deterministic safety gate applied after LLM output is parsed.

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
    "opencti_enrichment",
)


def _stage_fallback(evidence: RawEvidence) -> TriageVerdict:
    """Deterministic fallback used when the LLM call or parsing fails.
    Always escalates to human review rather than guessing a verdict.

    Defaults to priority P2 rather than P3, since a failed pipeline
    shouldn't be treated as low-risk, and P2 ensures an analyst sees the
    alert this shift. `safety_gate_applied` is always True here, consistent
    with `overall_evidence_reliability` being set to "low". The MITRE
    mapping is carried over from the rule's own tags rather than left
    empty, so severity isn't understated, and `actionable_observables`
    stays empty since a downed LLM must not fabricate an IOC or a response
    action."""
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
        evidence_analysis=(
            "Triage LLM unavailable — no evidence analysis was produced. "
            "The analyst must review the raw evidence manually."
        ),
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
