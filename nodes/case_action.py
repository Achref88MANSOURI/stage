"""`case_action` — creates a case, merges into one, or (on a false positive)
annotates the alert in place.

NOT part of architecture v4's six stages. A deliberate deviation from §1/§3's
"read-only, n8n owns case mutation" design, user-directed 2026-08-21 — see
CLAUDE.md's "Case action" entry for the full record of that decision. This is
the first node in the pipeline with real, externally-visible side effects.

**Three branches:**

- `verdict.verdict == "false_positive"` (2026-09-07, user-directed — a
  scoped reversal of the "every alert -> case action, unconditionally"
  directive below, for FP only): NO case is created or merged. The triage
  narrative is posted as a comment on the ALERT, and the alert's severity /
  TLP are forced to the floor (low / clear). FP feedback into the tracking
  DB is wired separately, upstream, in `main.py::_record_fp_feedback`.
  Handled by `_false_positive_alert_action`.

- otherwise, driven ONLY by `verdict.correlation_decision.action` — every
  non-FP alert results in either a new case or a merge, unconditionally.
  There is no `needs_review` hold-off: `TriageVerdict`'s richer fields
  (recommended_action, reasoning, summary, citations) become CONTENT written
  into the case, never a gate on whether to act. `recommended_action ==
  "merge_and_retier"` is the one place those richer fields DO change
  behavior — it triggers an extra severity/TLP-bump call on top of the
  merge, since TheHive's merge endpoint doesn't accept field overrides in
  the same call (see `tools/thehive.py`'s module docstring).

Case severity (1..4) and TLP (0..4) are both derived from
`verdict.priority_band` — `PRIORITY_TO_HIVE_SEVERITY` / `PRIORITY_TO_HIVE_TLP`.
Severity can't distinguish P4 from P5 (both `1`/low); TLP carries the full
5-band spread (P1 red .. P5 clear).

This node makes 1-3 real HTTP calls to a live TheHive instance and needs its
own timeout/Gap handling. `TriageResult.case_action` is `None` until a caller
runs this node and assigns it.

**v6 redesign (2026-09-06)**: `case_action(verdict, evidence)` takes ONE
object now, not two — `correlation_decision`/`evidence_situation` live
directly on `TriageVerdict` (schemas/verdict.py) since the old Stage 3
(`ContextualAssessment`, deleted) / Stage 4 split is gone. Every
`context.X` read in this file becomes `verdict.X`; nothing else about the
write logic changes.

**v5 redesign (`newdesign.md` §5, §8) — no more `PriorityScore` parameter.**
The numeric/matrix scoring stage this node used to receive a `priority:
PriorityScore` from is deleted entirely; `priority_band`/`priority_reasoning`
now come straight from `verdict` (`TriageVerdict.priority_band`/
`.priority_reasoning`, assigned directly by Stage 4's LLM). `PRIORITY_TO_
HIVE_SEVERITY` moves here from the deleted `scoring_config.py` as a
module-level constant — same mapping, unchanged.

NEVER RAISES to its caller — every TheHive write failure becomes
`CaseActionResult(success=False, error=...)`, same contract as every other
node/tool in this repo.

**2026-08-23 correction — observable writes now come from Stage 4, not
Stage 3 directly.** Previously this node called `thehive.
add_extracted_observables(case_id, context.extracted_observables)` — Stage
3's raw extraction, written straight to TheHive without Stage 4 ever
weighing in. That skipped the whole point of TASK 5 (`prompts/analyst_agent.py`):
Stage 4 was supposed to be the one deciding what's serious. Fixed: this node
now writes `verdict.actionable_observables` instead — Stage 4's judgment on
EVERY observable it was shown (not a filtered subset, see that prompt's
module docstring), each carrying a `confidence`. `add_extracted_observables`
is retired from `tools/thehive.py` along with this change — its "write
everything, don't check what's already there" approach is exactly what a
call site keyed on Stage 4's per-item confidence + potential duplicates
against already-known observables shouldn't do blindly; `_write_actionable_
observables` below replaces it.

This can only run AFTER `create_case_from_alert`/`merge_alert_into_case`
succeeds — a "new" case has no `case_id` until the create call returns one,
so the write (and the existing-observable lookup that avoids duplicating
one already on the case) happens here, in Stage 6, never earlier.
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

# Moved from the deleted scoring_config.py (v5 redesign, `newdesign.md` §7) —
# same mapping, unchanged. Keyed on TriageVerdict.priority_band now, not the
# old PriorityScore.final_priority. TheHive severity is 1..4 only, so P4 and
# P5 both collapse to 1 (low) — the two are kept distinct by TLP below
# (user-directed 2026-09-07: "P5 and P4 both to 1, but with different color").
PRIORITY_TO_HIVE_SEVERITY: dict[str, int] = {"P1": 4, "P2": 3, "P3": 2, "P4": 1, "P5": 1}

# priority_band -> TheHive TLP (0..4 = clear / green / amber / amber+strict /
# red — verified live against /api/v1/describe/{case,alert} 2026-09-07).
# User-directed 2026-09-07: spread all 5 bands across all 5 TLP values so the
# priority survives even where severity can't distinguish P4 from P5.
# Applied to the case on create (and on a merge_and_retier bump); the FP
# branch below forces the alert to CLEAR regardless.
PRIORITY_TO_HIVE_TLP: dict[str, int] = {"P1": 4, "P2": 3, "P3": 2, "P4": 1, "P5": 0}
_DEFAULT_TLP = 2  # amber — used only if an unknown band string ever appears

# A `false_positive` verdict never opens a case (user-directed 2026-09-07,
# a deliberate scoped reversal of the 2026-08-21 "every alert -> case action
# unconditionally" directive — see CLAUDE.md). The alert is annotated in
# place and dropped to the floor: low severity, clear TLP, regardless of the
# band the LLM assigned.
FP_ALERT_SEVERITY = 1  # low
FP_ALERT_TLP = 0  # clear

# ActionableObservable.observable_type -> TheHive dataType. Distinct from
# tools/thehive.py's old (now-retired) _BUCKET_TO_DATATYPE: these are the
# singular type labels the LLM actually outputs ("domain"/"ip"/"url"), not
# n8n's plural bucket names ("domains"/"external_ips"/"urls").
#
# v6 redesign (2026-09-06): "file" renamed "file-path" (no behavior change,
# same TheHive dataType) and "process-id" added — TheHive has no native
# process/PID observable dataType (confirmed against the same live
# /api/v1/describe/observable enum the rest of this mapping was built from,
# see tools/thehive.py's module docstring); "other" is TheHive's own
# documented generic catch-all bucket. NOT yet live-verified end-to-end for
# a real process-id write the way every other row in this mapping was —
# flagged as a real gap to close on the first live merge/create run that
# actually produces a process-id item.
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
    """For each of Stage 4's judged observables: reuse its id if a matching
    value is already on the case, otherwise create it and capture the new
    id TheHive assigns. Returns `(enriched_list, written_count,
    failed_count)` — `enriched_list` is the SAME items with `observable_id`
    filled in (or left `None` on a genuine create failure — still returned,
    never dropped, so the LLM's judgment survives in the output even when
    the TheHive write itself didn't). `written_count` covers both reused and
    newly-created items — either way the case now has that observable.

    Tags written reflect Stage 4's own judgment (`disposition:<value>`,
    `confidence:<value>`) rather than the old blanket `["react",
    "malicious"]` every process-path observable used to get regardless of
    how confident that judgment actually was — that convention doesn't carry
    over cleanly now that low-confidence/"monitor" items are written too.
    `ioc=True` only for block/quarantine; a "monitor" item is worth watching,
    not necessarily an indicator of compromise.

    2026-08-23, user-directed: the observable's TheHive `message` (its
    description in the UI) now states the recommendation up front, followed
    by Stage 4's reasoning, rather than reasoning alone — so an analyst
    reading the observable in TheHive sees the recommended action without
    having to cross-reference the tags.

    2026-08-23 fix — race with TheHive's own alert-to-case observable import.
    Live-caught: on the "new case" path, `create_case_from_alert` triggers
    TheHive's own background import of the ALERT's observables into the just
    -created case (visible as TheHive's own `re&ct:*`/`field:*` tags on those
    rows) — an async process not guaranteed complete by the time the
    existence pre-check above runs a moment later. Result observed on a real
    case: 4 of 6 items the pre-check missed hit TheHive's own uniqueness
    constraint at create time (`"Observable already exists"`), and the real
    ID for each was silently lost (marked failed, Stage 4's judgment
    attached to nothing). On a create failure matching that specific TheHive
    error, re-fetch and reuse the real existing ID instead of discarding it
    — same "recovered, not lost" contract this function already gives a
    value that was visible in the pre-check. This does NOT re-apply Stage
    4's tags/message onto that pre-existing (TheHive-auto-imported) row —
    no update-observable endpoint exists in this codebase yet; recovering
    the ID (so the value is at least correctly represented in the output)
    is this fix's scope. Also does not address the rarer case observed in
    the same live run where TheHive did NOT reject a colliding create
    outright (a duplicate `ip` observable resulted) — that failure mode
    produces no error to catch here and needs a different fix if it recurs.
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
    """TheHive's own duplicate-observable error, live-observed verbatim:
    {'success': [], 'failure': [{'type': 'CreateError',
    'message': 'Observable already exists', ...}]} — create_case_observable
    folds this into its Gap.reason as an unparsed repr (it isn't the plain
    list shape a successful create returns), so this matches on the
    substring rather than a structured field."""
    return "already exists" in (reason or "").lower()


def _build_case_title(verdict: TriageVerdict, evidence: EnrichedEvidence) -> str:
    """v5 (`newdesign.md` §8): title now leads with `[{priority_band}]`,
    replacing the old score-bearing title (`priority_score.priority` /
    `.score`, both gone with `PriorityScore`).

    2026-09-07, user-directed: the alert_id is NOT in the title. It appears
    only in `_build_case_description`'s alert-identity heading (which is
    written both as the new case's description AND as every merge comment,
    so each merged alert's id/rule stays visible there) and in
    `TriageResult.alert_id` in the HTTP response. An earlier revision the
    same day appended `(alert {alert_id})` here; that was reverted on the
    user's instruction — the title carries priority/rule/host only."""
    alert = evidence.canonical_alert
    host = alert.host.hostname if alert.host else "unknown-host"
    return f"[{verdict.priority_band}] {alert.rule.name} — {host}"


def _build_case_tags(verdict: TriageVerdict, evidence: EnrichedEvidence) -> list[str]:
    """v5 (`newdesign.md` §7-§8): tag source moves from the deleted
    `PriorityScore.final_priority`/`.deployment_mode` to `TriageVerdict.
    priority_band` directly. The `scoring-mode` tag is gone — it named the
    v3 matrix scorer's shadow/live calibration status, which no longer
    exists; there is no equivalent concept for an LLM-direct priority_band."""
    rc = evidence.rule_context
    mitre = list(rc.mitre_attack) if rc else []
    tags = [
        "soc3s-triage",
        f"priority:{verdict.priority_band}",
        f"verdict:{verdict.verdict}",
        *mitre,
    ]
    # TheHive tags are capped at 128 chars each (hive://schema/case/create,
    # live-verified) — defensive truncation, not expected to bite in practice.
    return [t[:128] for t in tags]


def _build_case_description(
    verdict: TriageVerdict,
    evidence: EnrichedEvidence,
) -> str:
    """Deterministic Markdown assembly from already-computed Stage 1-4
    output. NO new LLM call — CLAUDE.md's hard constraint caps this pipeline
    at exactly 2, both already spent (Stage 3, Stage 4). Every section here
    is either a pass-through of Stage 3/4's own free text, or Stage 4's own
    priority_band/priority_reasoning/investigation_gaps (v5, `newdesign.md`
    §8-§9) — there is no scoring-formula breakdown any more.

    2026-09-07, user-directed: this same string is used for TWO things —
    `create_case_from_alert`'s `description` on a "new" case, AND
    `add_case_comment`'s comment body on every "merge" (see `_case_action`
    below). The case's own title (`_build_case_title`) only ever reflects
    the FIRST alert that created it — a case with 5 merged alerts otherwise
    has no way to tell, from the comment thread alone, which alert each
    later comment came from. The alert-identity heading below fixes that:
    it is deterministic (`CanonicalAlert.alert_id`/`.rule.name`), never
    LLM-sourced."""
    alert = evidence.canonical_alert
    rc = evidence.rule_context
    ac = evidence.asset_context
    lines = [
        f"## Triage Summary — Alert `{alert.alert_id}` — {alert.rule.name}",
        f"**Verdict:** {verdict.verdict} | **Recommended action:** "
        f"{verdict.recommended_action} | **Priority:** {verdict.priority_band}",
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
    if verdict.correlation_decision.reasoning:
        lines += ["", "### Correlation reasoning", verdict.correlation_decision.reasoning]
    if verdict.evidence_citations:
        lines += ["", "### Evidence citations"]
        lines += [f"- {c}" for c in verdict.evidence_citations]
    if evidence.investigation_gaps:
        lines += ["", "### Stage 1 tool gaps"]
        lines += [f"- {g.tool}: {g.reason}" for g in evidence.investigation_gaps]
    # v5 (`newdesign.md` §3-§4, §9), field source updated for v6 (2026-09-06):
    # what an analyst needs is the evidence reliability report and the
    # rubric-driven priority band, both now on the single `verdict` object
    # (there's no separate Stage 3 `context` any more).
    es = verdict.evidence_situation
    lines += [
        "",
        "### Evidence situation",
        f"- Overall reliability: **{es.overall_evidence_reliability}**",
    ]
    lines += [f"- {s.source_name}: **{s.status}** — {s.impact_on_triage}" for s in es.sources]
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

    # 2026-09-07, user-directed: a false_positive verdict never opens a case.
    # The triage narrative goes on the ALERT as a comment and the alert is
    # dropped to low/clear in place. FP feedback is wired separately, before
    # this node runs (main.py::_record_fp_feedback). See CLAUDE.md.
    if verdict.verdict == "false_positive":
        return await _false_positive_alert_action(verdict, evidence)

    logger.info(
        "Case action started: correlation_action=%s merge_target=%s",
        verdict.correlation_decision.action,
        verdict.correlation_decision.merge_into_case_id,
    )
    # v5 (`newdesign.md` §7-§8): severity now keys off TriageVerdict.
    # priority_band directly — the deleted PriorityScore/deployment_mode
    # shadow-vs-live distinction no longer exists. tlp too (2026-09-07).
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

        # Write Stage 4's actionable_observables to the new case.
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

    # Write Stage 4's actionable_observables to the merged case.
    enriched_obs, obs_written, obs_failed = await _write_actionable_observables(
        merge_into_case_id, verdict.actionable_observables
    )

    result = CaseActionResult(
        success=True,
        action_taken="merge",
        case_id=merge_into_case_id,
        # TheHive's merge endpoint doesn't return the case body, but the
        # merge target is always one of `evidence.open_cases` (enforced by
        # the Stage-3 `_validate_merge_target` check), so its number is
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
    """`verdict.verdict == "false_positive"` — no case, ever. Two writes to
    the alert itself: the triage narrative as a comment, and severity/TLP
    forced to the floor (low / clear). Neither raises. `success` tracks the
    comment (the narrative landing on the alert is the point); a failed
    severity/TLP patch is appended to `error` but doesn't flip `success`,
    same posture as the merge path's comment handling."""
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
        thehive_alert_id, severity=FP_ALERT_SEVERITY, tlp=FP_ALERT_TLP
    )
    if not updated:
        reason = update_gap.reason if update_gap else "unknown"
        result.error = (
            f"{result.error}; FP alert severity/tlp update failed: {reason}"
            if result.error
            else f"FP alert severity/tlp update failed: {reason}"
        )

    logger.info(
        "Case action completed: false_positive — alert comment_added=%s severity=%s tlp=%s",
        result.comment_added,
        FP_ALERT_SEVERITY,
        FP_ALERT_TLP,
    )
    return result
