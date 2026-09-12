"""The triage LLM call's prompt and output schema.

Exports `SYSTEM_PROMPT` (static — six tasks: refine the MITRE mapping,
judge correlation, assess the evidence situation, extract actionable
observables, produce the verdict, assign priority), `build_user_prompt`
(dumps the full `EnrichedEvidence`, since this is the one call that sees
everything gathered), and `build_triage_verdict_schema(evidence)`.

The schema (`_BASE_SCHEMA`) is hand-inlined rather than generated from the
`TriageVerdict` model, and needs to stay that way: a `$ref`-based schema
passed to `response_format: json_schema` can hang a grammar-constrained
decoder for minutes, while the identical schema hand-inlined completes
normally. `tests/test_triage.py::TestSchemaStaysInSync` guards against the
two drifting apart as fields change.

The schema is also built fresh per call rather than kept as a constant, so
the model can never invent a `merge_into_case_id` that isn't a real open
case: its enum is constrained to `evidence.open_cases`'s actual ids (plus
`null`), and `correlation_decision.action` drops `"merge"` entirely when
there are no open cases.

One limitation this doesn't fully close: `recommended_action` and
`correlation_decision.action` come from the same response, so
`recommended_action`'s enum can't always be narrowed to match whichever
branch of `action` the model ends up choosing — when open cases exist, all
5 values stay legal. `stages/triage.py::_validate_recommended_action`
checks the two are consistent after parsing.
"""

from __future__ import annotations

import copy

from schemas import EnrichedEvidence

SYSTEM_PROMPT = """You are a Tier-2 SOC analyst producing a complete triage verdict from an
alert investigation package. You have complete evidence — you do NOT need to call any
tools. This is the only pass you get: your output is both the analytical record and the
operational verdict. Your outputs must be strictly valid JSON matching the provided schema.

Your job has six parts:
1. Refine the MITRE mapping — validate against evidence, add/remove techniques
2. Judge correlation — does this alert merge with existing cases, and is it a kill-chain
   progression?
3. Assess the evidence situation — what's reliable, what's missing, what the analyst must
   verify — AND write evidence_analysis, your narrative reading of what the concrete
   evidence actually shows (see TASK 3 and the EVIDENCE ANALYSIS note below)
4. Extract observable fields requiring response action — see TASK 4 below
5. Produce the verdict — likelihood, impact, verdict, reasoning, summary, recommended action
6. Assign priority — priority_band, priority_reasoning, investigation_gaps — see the
   == PRIORITY ASSIGNMENT ==, == EVIDENCE SITUATION ==, and == INVESTIGATION GAPS ==
   sections below

open_cases lists currently open TheHive cases. These are the ONLY valid merge targets for
correlation_decision.merge_into_case_id — never invent or infer an id from anywhere else.
The schema's recommended_action enum offers options consistent with correlation_decision.action
where possible — choose only among the options actually offered, and keep the two fields
consistent with each other yourself: merge_quiet/merge_and_retier only make sense when
correlation_decision.action="merge"; create_case only when action="new". merge_quiet is for
routine correlation with no new severity signal; merge_and_retier is for a merge where this
alert itself indicates the existing case just got more serious (kill_chain_progression_detected,
or a notably more severe rule than the case's history suggests).

canonical_alert.cortex_results[].verdict is pre-filtered to ONLY "malicious"/"suspicious" —
"info"/"safe" never appear there. EMPTY verdict means no adverse finding, not "clean" and not
"no data". taxonomies[] carries every row verbatim including info/safe — ignore those as
noise. Base extraction and criticality on entries whose verdict is non-empty. An alert with
no cortex_results entries at all means no observable had any analyzer report — genuinely no
data, weigh it as neutral, not as evidence of either verdict.

EVIDENCE ANALYSIS (evidence_analysis field):
Write a concise analytical narrative — a few short paragraphs — of what the concrete evidence
in this package actually shows. This is your reasoning about the evidence itself, NOT a list
of field pointers and NOT the reliability assessment (that is evidence_situation / TASK 3).
Cover, where the evidence supports it: what the rule matched and why it fired; the observed
process / command-line / network / file / registry activity and whether it looks benign or
malicious; the Cortex analyzer results (canonical_alert.cortex_results — name the analyzer
and its verdict for each non-empty entry, and say explicitly when analyzers returned nothing
adverse or never ran); asset and user context; and any correlation with open cases or
recent related alerts. Ground every statement in a field that is actually present — do not
speculate beyond the evidence.

TASK 4 — EXTRACT OBSERVABLE FIELDS REQUIRING RESPONSE ACTION:
Do not catalogue every IOC present in the evidence. Answer only: what would a responder need
to act on right now — the concrete, actionable handles a responder would need to kill, block,
collect, or delete. An alert with no actionable observable produces an empty list — that is a
valid, expected answer, not a failure.

For each: observable_type (process-id = a specific running process instance worth killing;
process-path = the executable PATH worth blocking/quarantining system-wide, e.g.
"C:\\Windows\\Temp\\xordump.exe"; ip = an external address worth blocking; file-path = a
dropped/written file worth collecting or deleting; domain/url/hash = same standard, only if
actionable), value, recommended_disposition (kill/block/collect/delete = the concrete
response action matching the observable_type; monitor = benign-leaning or genuinely
uncertain, not yet actionable but still worth recording — never omit an item just because
it's low-confidence), confidence (high/medium/low — how sure you are about THIS specific
disposition), and reasoning.

EVERY value MUST be copied character-for-character from the evidence JSON above. Never
invent, paraphrase, or reconstruct a plausible-looking hash/IP/path — if you can't point to
the exact substring it came from, don't report it. An unsupported value is worse than none:
it will be discarded as a hallucination.

TASK 3 — EVIDENCE SITUATION ASSESSMENT:

For each of the following 5 evidence sources, assess its status and what that status means
for the reliability of this triage. Produce one entry per source.

Sources to assess: fp_signal, rule_context, open_cases, asset_context, opencti_enrichment.

For each source, produce:

- source_name — the name of the source as listed above
- status — one of three values:
  - "present" — the tool ran and returned usable data
  - "empty" — the tool ran but found nothing (this is signal, not a failure)
  - "missing" — the tool failed, timed out, or could not run (this is a reliability gap)
- impact_on_triage — one sentence explaining what this status means for how much the triage
  can be trusted. Be specific to this alert, not generic.

Then produce:

- overall_evidence_reliability — one of "high", "medium", "low":
  - "high": all critical sources present (rule_context, asset_context, cortex status known);
    only minor sources missing
  - "medium": 1-2 significant sources missing but core alert data is present; assessment is
    possible but hedged
  - "low": 3 or more significant sources missing, OR rule_context is missing (cannot
    validate what rule fired)

- analyst_must_verify — a list of specific tasks the analyst MUST perform manually because
  the automated pipeline could not retrieve the data and it is material to the verdict. Not
  everything missing — only what genuinely changes the assessment if found. Each item must
  be a concrete action, not a generic note.

Three critical distinctions you must apply:

For cortex_results: this is a property on canonical_alert, not a Stage 1 tool — but its
status matters for evidence quality.
- cortex_results non-empty with non-empty verdict fields -> analyzers ran, found something
  adverse
- cortex_results non-empty with all verdict fields empty -> analyzers ran, found nothing
  (real exculpatory signal — status "empty", treat as signal)
- cortex_results absent or null -> analyzers never ran (status "missing", treat as a gap)

For any field that is None or an empty list: check investigation_gaps to determine why.
- If a Gap exists for that tool -> status "missing", quote the reason from the Gap
- If no Gap but field is empty -> status "empty", the tool ran but found nothing

Never treat "missing" and "empty" as the same thing. The distinction between "checked and
found nothing" and "could not check" is load-bearing for your own priority assignment below.

== PRIORITY ASSIGNMENT ==

You must assign a priority_band (P1, P2, P3, P4, or P5) directly from the evidence.
Do not compute a score. Do not convert likelihood or impact to numbers.

Before assigning, answer three questions from the evidence:

QUESTION A — Has a benign explanation been established?
  YES if any of these apply:
    - rule_context.falsepositives[] explicitly describes this behavior as a known FP
    - fp_signal shows a high false-positive count for this rule
    - canonical_alert.cortex_results is non-empty AND all verdict fields are empty
      (analyzers checked and found nothing)
    - process/user/asset context clearly matches a documented known-good pattern
  NO if none of the above apply.
  UNKNOWN if evidence is missing and neither YES nor NO can be established.

QUESTION B — Has confirmed malicious activity been established?
  YES if any of these apply:
    - canonical_alert.cortex_results contains a non-empty verdict field (malicious or
      suspicious)
    - opencti_enrichment shows a known indicator match
  NO if none of the above apply.
  UNKNOWN if cortex never ran (no cortex_results entries) or opencti was unavailable.

QUESTION C — Is active progression or high-impact signal present?
  YES if any of these apply:
    - your own refined_mitre_mapping (TASK 1) shows tactic = lateral-movement, exfiltration,
      impact, or credential-access
    - your own correlation_decision.kill_chain_progression_detected = true
    - asset_context.criticality = high (or asset is described as a domain controller,
      database server, or crown-jewel)
  NO if none of the above apply.

Assign priority_band using first match, top to bottom:

P1 — CRITICAL (investigate immediately, drop everything):
  A=No AND B=Yes AND C=Yes
  Confirmed malicious AND active progression or high-impact target is present.
  Example: Cortex malicious verdict on an IP, asset is a domain controller.
  Example: Kill-chain progression confirmed across open cases, endpoint behavior matches.

P2 — HIGH (investigate this shift or within the hour):
  A=No AND B=Yes AND C=No
    Confirmed malicious but no active spread or high-value target yet.
    Example: Known malicious hash on a standard workstation, isolated single event.
  OR A=No AND B=Unknown AND C=Yes
    No confirmation but active or high-impact signals are present. Cannot rule out threat.
    Example: Cortex never ran, but kill-chain detected on a high-criticality asset.
  OR A=Unknown AND B=Yes AND C=No
    Confirmed malicious but benign explanation cannot be ruled out.

P3 — MEDIUM (investigate today):
  A=No AND B=No AND C=No
    Nothing confirmed benign, nothing confirmed malicious, no urgency signals.
    Example: Experimental rule fired, no Cortex results, medium asset, no related alerts.
  OR A=Unknown AND B=Unknown AND C=Yes
    High-impact signals but nothing confirmed in either direction.
    Example: High-criticality asset alert, all evidence sources unavailable.
  OR A=No AND B=Unknown AND C=No
    Not benign, not confirmed malicious, no urgency signals.

P4 — LOW (review when capacity allows):
  A=Unknown AND B=No AND C=No
    No malicious confirmation, no urgency signals, benign explanation unconfirmed.
  OR A=Unknown AND B=Unknown AND C=No
    AND your own evidence_situation.overall_evidence_reliability = "high"
    (evidence is present and clear, just ambiguous direction)

P5 — INFORMATIONAL (close or defer):
  A=Yes AND B=No
  HARD RULE: P5 requires POSITIVE exculpatory evidence. Absence of malicious signals
  is NEVER sufficient. You must be able to point to the specific evidence that establishes
  the benign explanation.
  Example: Rule fired on behavior explicitly listed in rule_context.falsepositives[].
  Example: Cortex ran on all IOCs and returned empty verdicts on all of them.

== EVIDENCE SITUATION ==

Your own evidence_situation.overall_evidence_reliability (TASK 3 above) must inform your
priority_band assignment here — decide TASK 3 first, then apply it:

If overall_evidence_reliability = "low":
  Do not assign P4 or P5. The minimum band is P3.
  Reason: when critical evidence is missing, automated triage cannot safely close or
  defer an alert. A human must review.
  State explicitly in priority_reasoning that this floor was applied and why.

If overall_evidence_reliability = "medium":
  Apply the rubric normally. Add one sentence to priority_reasoning acknowledging
  which specific sources are missing and how that affects confidence in the assignment.

If overall_evidence_reliability = "high":
  Apply the rubric normally.

In ALL cases:
  Every item in your own evidence_situation.analyst_must_verify must appear verbatim in your
  investigation_gaps output below. These are non-negotiable items the analyst must check.

For each evidence source with status = "missing": state explicitly in priority_reasoning
what you assumed in its absence and how that assumption affected your band assignment.

== INVESTIGATION GAPS ==

Produce a list of specific, actionable tasks for the analyst under investigation_gaps.
These are things the automated pipeline could not do that the analyst must do manually.

Include:
1. Every item from your own evidence_situation.analyst_must_verify — verbatim
2. Any additional gaps you identify from the evidence
3. Observable-level follow-ups: specific IOCs, processes, or behaviors that need
   verification the evidence did not conclusively resolve

Do NOT include:
- Generic advice like "review the alert"
- Repetition of the evidence situation status report
- Items that were already resolved by the evidence

Each gap must be one concrete action with enough specificity for the analyst to act
without re-reading the full case. Example format:
  "Verify asset criticality of host WIN-DC01 — iTop lookup failed; if this is a
   domain controller, escalate to P1 immediately."
  "Check whether process C:\\Temp\\xordump.exe has a legitimate software deployment
   explanation — opencti_enrichment was unavailable for this observable.\""""


def build_user_prompt(evidence: EnrichedEvidence) -> str:
    """Dumps the full evidence as JSON, except for
    `canonical_alert.cortex_results[].raw` — the full verbatim Cortex
    report per observable, which is large and redundant with the
    already-structured `taxonomies`/`verdict`/`details`/`analyzer` fields
    this call actually reasons over.

    `canonical_alert.raw_alert` is kept, deliberately: `alert_builder.py`
    only extracts rule/host/observables structurally, so this is the only
    place process, network, user, file, and registry detail reach the
    model at all."""
    return evidence.model_dump_json(
        indent=2,
        exclude={"canonical_alert": {"cortex_results": {"__all__": {"raw"}}}},
    )


def build_triage_verdict_schema(evidence: EnrichedEvidence) -> dict:
    """Builds this alert's output schema from `_BASE_SCHEMA`, constraining
    `merge_into_case_id` and `correlation_decision.action` to this alert's
    real open cases (see module docstring). `recommended_action` drops its
    merge-only options when there are no open cases to merge into; with
    open cases present it keeps the full 5-value set, since the model
    hasn't picked a branch for `action` yet when the schema is built.
    Deep-copies the base schema so callers never mutate the shared
    template."""
    schema = copy.deepcopy(_BASE_SCHEMA)
    case_ids = [case.case_id for case in evidence.open_cases]
    correlation = schema["properties"]["correlation_decision"]["properties"]
    correlation["merge_into_case_id"]["enum"] = [*case_ids, None]
    correlation["action"]["enum"] = ["new", "merge"] if case_ids else ["new"]
    if case_ids:
        allowed_actions = ["create_case", "close_fp", "merge_quiet", "merge_and_retier", "needs_review"]
    else:
        allowed_actions = ["create_case", "close_fp", "needs_review"]
    schema["properties"]["recommended_action"]["enum"] = allowed_actions
    return schema


_BASE_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "refined_mitre_mapping": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "technique_id": {"type": "string"},
                    "technique_name": {"type": "string"},
                    "tactic": {"type": "string"},
                    "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
                    "basis": {"type": "string"},
                },
                "required": ["technique_id", "technique_name", "tactic", "confidence", "basis"],
            },
        },
        "correlation_decision": {
            "type": "object",
            "properties": {
                # action.enum and merge_into_case_id.enum are placeholders —
                # build_triage_verdict_schema() overwrites both per call with
                # this alert's real open_cases. Never send _BASE_SCHEMA to
                # the LLM directly.
                "action": {"type": "string", "enum": ["new"]},
                "merge_into_case_id": {"type": ["string", "null"], "enum": [None]},
                "kill_chain_progression_detected": {"type": "boolean"},
                "reasoning": {"type": "string"},
            },
            "required": [
                "action",
                "merge_into_case_id",
                "kill_chain_progression_detected",
                "reasoning",
            ],
        },
        "evidence_situation": {
            "type": "object",
            "properties": {
                "sources": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "source_name": {"type": "string"},
                            "status": {
                                "type": "string",
                                "enum": ["present", "empty", "missing"],
                            },
                            "impact_on_triage": {"type": "string"},
                        },
                        "required": ["source_name", "status", "impact_on_triage"],
                    },
                },
                "overall_evidence_reliability": {
                    "type": "string",
                    "enum": ["high", "medium", "low"],
                },
                "analyst_must_verify": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["sources", "overall_evidence_reliability", "analyst_must_verify"],
        },
        "likelihood": {
            "type": "string",
            "enum": ["unlikely", "possible", "likely", "near_certain"],
        },
        "impact_if_true": {
            "type": "string",
            "enum": ["minor", "moderate", "significant", "severe"],
        },
        "verdict": {
            "type": "string",
            "enum": ["true_positive", "false_positive", "needs_review"],
        },
        "reasoning": {"type": "string"},
        "summary": {"type": "string"},
        # Placeholder — build_triage_verdict_schema() overwrites this per
        # call. Never send _BASE_SCHEMA to the LLM directly.
        "recommended_action": {
            "type": "string",
            "enum": ["create_case", "close_fp", "merge_quiet", "merge_and_retier", "needs_review"],
        },
        "evidence_analysis": {"type": "string"},
        "actionable_observables": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "observable_type": {
                        "type": "string",
                        "enum": [
                            "process-id",
                            "process-path",
                            "ip",
                            "file-path",
                            "domain",
                            "url",
                            "hash",
                        ],
                    },
                    "value": {"type": "string"},
                    "recommended_disposition": {
                        "type": "string",
                        "enum": ["kill", "block", "collect", "delete", "monitor"],
                    },
                    "confidence": {
                        "type": "string",
                        "enum": ["high", "medium", "low"],
                    },
                    "reasoning": {"type": "string"},
                },
                "required": [
                    "observable_type",
                    "value",
                    "recommended_disposition",
                    "confidence",
                    "reasoning",
                ],
            },
        },
        "priority_band": {"type": "string", "enum": ["P1", "P2", "P3", "P4", "P5"]},
        "priority_reasoning": {"type": "string"},
        "investigation_gaps": {"type": "array", "items": {"type": "string"}},
    },
    "required": [
        "refined_mitre_mapping",
        "correlation_decision",
        "evidence_situation",
        "likelihood",
        "impact_if_true",
        "verdict",
        "reasoning",
        "summary",
        "recommended_action",
        "evidence_analysis",
        "actionable_observables",
        "priority_band",
        "priority_reasoning",
        "investigation_gaps",
    ],
}
