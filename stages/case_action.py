"""`case_action` — creates a case, merges into one, or annotates the alert
in place for a false positive. This is the pipeline's only stage with
real, externally visible side effects.

A `false_positive` verdict never creates or merges a case. Instead, the
triage narrative is posted as a comment on the alert, the alert is closed
(`status="FalsePositive"`, the dismissal reason written to its `summary`),
and severity/TLP are forced to the floor. FP feedback into the tracking DB
is handled separately, upstream, in `main.py::_record_fp_feedback`; this
stage just handles the TheHive side (`_false_positive_alert_action`).

Every other verdict results in either a new case or a merge, driven only
by `verdict.correlation_decision.action` — there's no `needs_review`
hold-off. The verdict's other fields (`recommended_action`, `reasoning`,
`summary`) become case content rather than a gate on whether to act, with
one exception: `recommended_action == "merge_and_retier"` triggers an
extra severity/TLP update on top of the merge, since TheHive's merge
endpoint doesn't accept field overrides in the same call.

Case severity (1-4) and TLP (0-4) both derive from `verdict.priority_band`.
Severity can't distinguish P4 from P5 (both map to 1/low); TLP covers the
full 5-band spread.

This stage makes 1-3 real HTTP calls to TheHive and never raises to its
caller — a write failure becomes `CaseActionResult(success=False,
error=...)` instead. `TriageResult.case_action` stays `None` until this
stage runs and assigns it.

Observable writes reflect the LLM's judgment on every observable it was
shown, not a filtered subset, and only happen after
`create_case_from_alert`/`merge_alert_into_case` succeeds — a new case has
no id to write against until the create call returns one.
"""

from __future__ import annotations

import logging

from logging_config import alert_context
from schemas import (
    ActionableObservable,
    CaseActionResult,
    EnrichedEvidence,
    TriageVerdict,
)
from tools import thehive

logger = logging.getLogger(__name__)

# TheHive severity is 1..4 only, so P4 and P5 both collapse to 1 (low) — the
# two are kept distinct by TLP below instead.
PRIORITY_TO_HIVE_SEVERITY: dict[str, int] = {"P1": 4, "P2": 3, "P3": 2, "P4": 1, "P5": 1}

# priority_band -> TheHive TLP (0..4 = clear / green / amber / amber+strict /
# red). Spreads all 5 bands across all 5 TLP values so the priority survives
# even where severity can't distinguish P4 from P5. Applied to the case on
# create (and on a merge_and_retier bump); the FP branch below forces the
# alert to CLEAR regardless.
PRIORITY_TO_HIVE_TLP: dict[str, int] = {"P1": 4, "P2": 3, "P3": 2, "P4": 1, "P5": 0}
_DEFAULT_TLP = 2  # amber — used only if an unknown band string ever appears

# A `false_positive` verdict never opens a case. The alert is annotated in
# place and dropped to the floor: low severity, clear TLP, regardless of the
# band the LLM assigned.
FP_ALERT_SEVERITY = 1  # low
FP_ALERT_TLP = 0  # clear
# A false_positive verdict CLOSES the alert as such. `"FalsePositive"` is a
# real value in this TheHive instance's alert.status enum (Duplicate /
# FalsePositive / Ignored / Imported / InProgress / New / Pending) — setting
# it moves the alert to the Closed stage.
FP_ALERT_STATUS = "FalsePositive"

# ActionableObservable.observable_type -> TheHive dataType. TheHive has no
# native process/PID observable type, so "process-id" maps to "other", its
# generic catch-all bucket.
_OBSERVABLE_TYPE_TO_DATATYPE: dict[str, str] = {
    "process-id": "other",
    "process-path": "filename",
    "file-path": "filename",
    "domain": "domain",
    "url": "url",
    "ip": "ip",
    "hash": "hash",
}


async def _write_actionable_observables(
    case_id: str, actionable_observables: list[ActionableObservable]
) -> tuple[list[ActionableObservable], int, int]:
    """Writes the LLM's judged observables onto the case, reusing an
    existing observable's id if its value is already there and creating a
    new one otherwise. Returns `(enriched_list, written_count,
    failed_count)`, where `enriched_list` is the same items with
    `observable_id` filled in (or left `None` on a genuine failure, so the
    LLM's judgment still comes through even if the TheHive write didn't).

    Each observable's tags reflect the LLM's own judgment
    (`disposition:<value>`, `confidence:<value>`) regardless of confidence
    level, and `ioc` is only set for block/quarantine dispositions. The
    TheHive `message` leads with the recommendation, then the LLM's
    reasoning.

    Creating a new case triggers TheHive's own background import of the
    alert's observables onto it, which isn't guaranteed to finish before
    the existence check above runs — so a create call can still hit
    TheHive's "Observable already exists" error for a value the check
    missed. When that happens, this re-fetches once and reuses the real
    id instead of reporting a failure. It doesn't re-apply the LLM's
    tags/message onto that already-imported row (no update endpoint
    exists for it), and it doesn't cover the rarer case where TheHive
    accepts a duplicate outright instead of rejecting it.
    """
    if not actionable_observables:
        return [], 0, 0

    existing, fetch_gap = await thehive.fetch_case_observables_with_type(case_id)
    if fetch_gap:
        logger.warning(
            "case_action: could not fetch existing observables for case %s before "
            "writing actionable_observables: %s",
            case_id,
            fetch_gap.reason,
        )
    existing_by_value = {
        row["value"]: row["observable_id"] for row in existing if row.get("observable_id")
    }

    enriched: list[ActionableObservable] = []
    written = 0
    failed = 0
    # Lazily populated on the first "already exists" conflict, then reused —
    # avoids one extra fetch per conflicting item.
    conflict_refetch_by_value: dict[str, str] | None = None

    for item in actionable_observables:
        if item.value in existing_by_value:
            item.observable_id = existing_by_value[item.value]
            enriched.append(item)
            written += 1
            continue

        observable_id, gap = await thehive.create_case_observable(
            case_id,
            data_type=_OBSERVABLE_TYPE_TO_DATATYPE[item.observable_type],
            data=item.value,
            tags=[f"disposition:{item.recommended_disposition}", f"confidence:{item.confidence}"],
            message=f"Recommendation: {item.recommended_disposition}. {item.reasoning}",
            ioc=item.recommended_disposition in ("block", "quarantine"),
        )
        if observable_id:
            item.observable_id = observable_id
            enriched.append(item)
            written += 1
            continue

        if gap and _is_already_exists_conflict(gap.reason):
            if conflict_refetch_by_value is None:
                refetched, refetch_gap = await thehive.fetch_case_observables_with_type(case_id)
                conflict_refetch_by_value = (
                    {}
                    if refetch_gap
                    else {
                        row["value"]: row["observable_id"]
                        for row in refetched
                        if row.get("observable_id")
                    }
                )
            reused_id = conflict_refetch_by_value.get(item.value)
            if reused_id:
                item.observable_id = reused_id
                enriched.append(item)
                written += 1
                continue

        logger.warning(
            "case_action: could not write actionable observable %r to case %s: %s",
            item.value,
            case_id,
            gap.reason if gap else "unknown",
        )
        enriched.append(item)
        failed += 1

    return enriched, written, failed


def _is_already_exists_conflict(reason: str | None) -> bool:
    """Detects TheHive's duplicate-observable error. `create_case_observable`
    folds the raw error response into `Gap.reason` as text rather than a
    structured field, so this matches on the substring in the message
    (`"Observable already exists"`)."""
    return "already exists" in (reason or "").lower()


def _build_case_title(verdict: TriageVerdict, evidence: EnrichedEvidence) -> str:
    """Builds the case title as `[{priority_band}] {rule} — {host}`. The
    alert id isn't in the title — it's in `_build_case_description`'s
    heading instead, and in `TriageResult.alert_id` in the response."""
    alert = evidence.canonical_alert
    host = alert.host.hostname if alert.host else "unknown-host"
    return f"[{verdict.priority_band}] {alert.rule.name} — {host}"


def _build_case_tags(verdict: TriageVerdict, evidence: EnrichedEvidence) -> list[str]:
    """Builds the case tags from the verdict's priority band, verdict label,
    and the rule's MITRE techniques."""
    rc = evidence.rule_context
    mitre = list(rc.mitre_attack) if rc else []
    tags = [
        "soc3s-triage",
        f"priority:{verdict.priority_band}",
        f"verdict:{verdict.verdict}",
        *mitre,
    ]
    # TheHive caps tags at 128 chars each; this is a defensive truncation,
    # not expected to actually trigger.
    return [t[:128] for t in tags]


def _build_case_description(
    verdict: TriageVerdict,
    evidence: EnrichedEvidence,
) -> str:
    """Builds the case/alert narrative as Markdown, from the verdict and
    evidence already computed — no LLM call of its own.

    This same string serves as both the new case's `description` and the
    comment body posted on a merge, which is why it opens with a
    deterministic alert-identity heading (id and rule name, not
    LLM-sourced): the case title only reflects whichever alert created it,
    so without that heading a case with several merged alerts would give
    no way to tell which comment came from which alert."""
    alert = evidence.canonical_alert
    rc = evidence.rule_context
    ac = evidence.asset_context
    lines = [
        f"## Triage Summary — Alert `{alert.alert_id}` — {alert.rule.name}",
        f"**Verdict:** {verdict.verdict} | **Recommended action:** "
        f"{verdict.recommended_action} | **Priority:** {verdict.priority_band}",
        # An analyst reading the case/comment shouldn't have to open the
        # alert to see when it fired.
        f"**Alert timestamp:** {alert.timestamp.isoformat()}"
        + (
            f" (source event: {alert.event_timestamp.isoformat()})"
            if alert.event_timestamp and alert.event_timestamp != alert.timestamp
            else ""
        ),
        "",
        verdict.summary,
        "",
        "### Reasoning",
        verdict.reasoning,
        "",
        "### Rule",
        f"- Name: {alert.rule.name}",
        f"- Severity: {rc.level if rc else 'unknown'}",
        f"- MITRE: {', '.join(rc.mitre_attack) if rc and rc.mitre_attack else 'none'}",
    ]
    if ac and ac.found:
        lines += [
            "",
            "### Asset",
            f"- Host: {ac.hostname or 'unknown'}",
            f"- Criticality: {ac.criticality or 'unknown'}",
        ]
    if verdict.evidence_analysis:
        lines += ["", "### Evidence analysis", verdict.evidence_analysis]
    if verdict.correlation_decision.reasoning:
        lines += ["", "### Correlation reasoning", verdict.correlation_decision.reasoning]
    if evidence.investigation_gaps:
        lines += ["", "### Gather tool gaps"]
        lines += [f"- {g.tool}: {g.reason}" for g in evidence.investigation_gaps]
    # There is no per-source reliability table in this narrative — the
    # LLM's own "Evidence analysis" section above is what an analyst reads.
    # The structured `verdict.evidence_situation` is still produced and
    # still surfaced in the `/triage` JSON response; it just isn't written
    # into the TheHive case/alert body.
    lines += [
        "",
        "### Priority assessment",
        f"- Band: **{verdict.priority_band}**"
        + (" (safety gate applied)" if verdict.safety_gate_applied else ""),
        verdict.priority_reasoning,
    ]
    if verdict.investigation_gaps:
        lines += ["", "### Analyst must verify"]
        lines += [f"- {g}" for g in verdict.investigation_gaps]
    return "\n".join(lines)


async def case_action(
    verdict: TriageVerdict,
    evidence: EnrichedEvidence,
) -> CaseActionResult:
    with alert_context(evidence.canonical_alert.alert_id):
        return await _case_action(verdict, evidence)


async def _case_action(
    verdict: TriageVerdict,
    evidence: EnrichedEvidence,
) -> CaseActionResult:
    alert = evidence.canonical_alert
    thehive_alert_id = alert.thehive_alert_id

    # A false_positive verdict never opens a case — the narrative goes on
    # the alert as a comment instead, and the alert drops to low/clear in
    # place. FP feedback is recorded separately, before this stage runs
    # (main.py::_record_fp_feedback).
    if verdict.verdict == "false_positive":
        return await _false_positive_alert_action(verdict, evidence)

    logger.info(
        "Case action started: correlation_action=%s merge_target=%s",
        verdict.correlation_decision.action,
        verdict.correlation_decision.merge_into_case_id,
    )
    severity = PRIORITY_TO_HIVE_SEVERITY.get(verdict.priority_band, 2)
    tlp = PRIORITY_TO_HIVE_TLP.get(verdict.priority_band, _DEFAULT_TLP)
    title = _build_case_title(verdict, evidence)
    description = _build_case_description(verdict, evidence)
    tags = _build_case_tags(verdict, evidence)

    action = verdict.correlation_decision.action
    merge_into_case_id = verdict.correlation_decision.merge_into_case_id

    if action == "merge" and not merge_into_case_id:
        logger.warning(
            "case_action: correlation_decision.action=='merge' but merge_into_case_id "
            "is None for alert %s — falling back to creating a new case",
            thehive_alert_id,
        )
        action = "new"

    if action == "new":
        shallow, gap = await thehive.create_case_from_alert(
            thehive_alert_id,
            title=title,
            description=description,
            severity=severity,
            tags=tags,
            tlp=tlp,
        )
        if shallow is None:
            logger.warning("Case action failed: could not create case: %s", gap.reason if gap else "unknown")
            return CaseActionResult(
                success=False, action_taken="new_case", is_new_case=True,
                error=gap.reason if gap else "unknown error",
            )

        # Write the verdict's actionable_observables to the new case.
        enriched_obs, obs_written, obs_failed = await _write_actionable_observables(
            shallow.case_id, verdict.actionable_observables
        )

        error_msg = gap.reason if gap else None
        if obs_failed:
            gap_summary = f"{obs_failed} observable write(s) failed"
            error_msg = f"{error_msg}; {gap_summary}" if error_msg else gap_summary

        new_result = CaseActionResult(
            success=True,
            action_taken="new_case",
            case_id=shallow.case_id,
            case_number=shallow.case_number,
            is_new_case=True,
            severity=shallow.severity,
            # tlp as requested from priority_band — ShallowCase doesn't carry
            # it back, but create_case_from_alert's PATCH set it.
            tlp=tlp,
            stage=shallow.stage,
            status=shallow.status,
            tags=shallow.tags,
            observables_written=obs_written,
            observables_failed=obs_failed,
            actionable_observables_written=enriched_obs,
            # The exact Markdown written as this new case's description —
            # surfaced back in TriageResult so the /triage caller sees what
            # landed in TheHive without a second round trip.
            case_narrative=description,
            error=error_msg,  # partial-success case: created but content push or observable writes failed
        )
        logger.info(
            "Case action completed: created case_id=%s severity=%s observables=%d/%d",
            new_result.case_id,
            new_result.severity,
            obs_written,
            obs_written + obs_failed,
        )
        return new_result

    # action == "merge", merge_into_case_id is a real id
    merged, gap = await thehive.merge_alert_into_case(thehive_alert_id, merge_into_case_id)
    merge_target_number = next(
        (c.case_number for c in evidence.open_cases if c.case_id == merge_into_case_id),
        None,
    )
    if not merged:
        logger.warning("Case action failed: could not merge into %s: %s", merge_into_case_id, gap.reason if gap else "unknown")
        return CaseActionResult(
            success=False, action_taken="merge", case_id=merge_into_case_id,
            case_number=merge_target_number, is_new_case=False,
            error=gap.reason if gap else "unknown error",
        )

    # Write the verdict's actionable_observables to the merged case.
    enriched_obs, obs_written, obs_failed = await _write_actionable_observables(
        merge_into_case_id, verdict.actionable_observables
    )

    result = CaseActionResult(
        success=True,
        action_taken="merge",
        case_id=merge_into_case_id,
        # TheHive's merge endpoint doesn't return the case body, but the
        # merge target is always one of `evidence.open_cases` (enforced by
        # `_validate_merge_target` in stages/triage.py), so its number is
        # already in hand — no extra round trip.
        case_number=merge_target_number,
        is_new_case=False,
        severity=severity,
        tags=tags,
        observables_written=obs_written,
        observables_failed=obs_failed,
        actionable_observables_written=enriched_obs,
        # Same Markdown that gets posted as the merge comment below — see
        # the new-case path's note.
        case_narrative=description,
    )
    if obs_failed:
        gap_summary = f"{obs_failed} observable write(s) failed"
        result.error = gap_summary

    if verdict.recommended_action == "merge_and_retier":
        updated, update_gap = await thehive.update_case(
            merge_into_case_id, severity=severity, tlp=tlp, add_tags=tags
        )
        if updated:
            result.tlp = tlp
        else:
            logger.warning(
                "case_action: merge_and_retier severity/tlp update failed for case %s: %s",
                merge_into_case_id,
                update_gap.reason if update_gap else "unknown",
            )
            if result.error:
                result.error += f"; retier update failed: {update_gap.reason if update_gap else 'unknown'}"
            else:
                result.error = f"Merged, but retier update failed: {update_gap.reason if update_gap else 'unknown'}"

    commented, comment_gap = await thehive.add_case_comment(merge_into_case_id, description)
    result.comment_added = commented
    if not commented and not result.error:
        result.error = f"Merged, but comment failed: {comment_gap.reason if comment_gap else 'unknown'}"
    elif not commented and result.error:
        result.error += f"; comment failed: {comment_gap.reason if comment_gap else 'unknown'}"

    logger.info(
        "Case action completed: merged into case_id=%s comment_added=%s observables=%d/%d",
        result.case_id,
        result.comment_added,
        obs_written,
        obs_written + obs_failed,
    )
    return result


async def _false_positive_alert_action(
    verdict: TriageVerdict, evidence: EnrichedEvidence
) -> CaseActionResult:
    """Handles a `false_positive` verdict — no case is ever created. Two
    writes to the alert: the triage narrative as a comment, and an
    `update_alert` call that closes the alert (`status="FalsePositive"`),
    records the dismissal reason in its `summary`, and floors
    severity/TLP. `success` tracks the comment, since that's the write
    that matters most; a failed `update_alert` is appended to `error`
    without flipping `success`, the same posture used on the merge path's
    comment step."""
    alert = evidence.canonical_alert
    thehive_alert_id = alert.thehive_alert_id
    logger.info("Case action started: verdict=false_positive — annotating alert, no case")

    description = _build_case_description(verdict, evidence)

    result = CaseActionResult(
        success=False,
        action_taken="fp_alert",
        is_new_case=False,
        severity=FP_ALERT_SEVERITY,
        tlp=FP_ALERT_TLP,
        case_narrative=description,
    )

    if not thehive_alert_id:
        result.error = "No thehive_alert_id — cannot annotate the alert for a false positive"
        logger.warning("Case action failed: %s", result.error)
        return result

    commented, comment_gap = await thehive.add_alert_comment(thehive_alert_id, description)
    result.comment_added = commented
    result.success = commented
    if not commented:
        result.error = (
            f"FP alert comment failed: {comment_gap.reason if comment_gap else 'unknown'}"
        )

    updated, update_gap = await thehive.update_alert(
        thehive_alert_id,
        severity=FP_ALERT_SEVERITY,
        tlp=FP_ALERT_TLP,
        status=FP_ALERT_STATUS,
        summary=f"Triage verdict: false positive. {verdict.summary}",
    )
    if updated:
        result.status = FP_ALERT_STATUS
    else:
        reason = update_gap.reason if update_gap else "unknown"
        result.error = (
            f"{result.error}; FP alert close/update failed: {reason}"
            if result.error
            else f"FP alert close/update failed: {reason}"
        )

    logger.info(
        "Case action completed: false_positive — alert comment_added=%s status=%s "
        "severity=%s tlp=%s",
        result.comment_added,
        result.status,
        FP_ALERT_SEVERITY,
        FP_ALERT_TLP,
    )
    return result
