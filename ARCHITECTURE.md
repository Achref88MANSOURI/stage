# SOC-3s — Codebase Documentation

An automated triage service for Security Onion alerts. It receives an alert (via n8n),
gathers evidence from every relevant security backend, asks one LLM to produce a complete
triage verdict, and writes the outcome back to TheHive — either a new case, a merge into
an existing one, or a closed false positive. Everything except that one LLM call is
deterministic Python: no agent loop, no tool-calling model, no second-guessing.

This document explains what the system does, how the pipeline works end to end, and what
every file's job is — in enough detail to read the code with a map in hand.

---

## Table of contents

1. [What the system is, and isn't](#1-what-the-system-is-and-isnt)
2. [Architecture: the four layers](#2-architecture-the-four-layers)
3. [The pipeline, end to end](#3-the-pipeline-end-to-end)
4. [Data contracts (`schemas/`)](#4-data-contracts-schemas)
5. [Backend tools (`tools/`)](#5-backend-tools-tools)
6. [Pipeline stages (`stages/`)](#6-pipeline-stages-stages)
7. [The LLM call in detail (`prompts/`)](#7-the-llm-call-in-detail-prompts)
8. [Case action — writing the outcome to TheHive](#8-case-action--writing-the-outcome-to-thehive)
9. [The HTTP API (`main.py`)](#9-the-http-api-mainpy)
10. [Alert building (`alert_builder.py`)](#10-alert-building-alert_builderpy)
11. [Configuration](#11-configuration)
12. [Error handling philosophy](#12-error-handling-philosophy)
13. [Testing](#13-testing)
14. [Known limitations](#14-known-limitations)

---

## 1. What the system is, and isn't

**What it is:** a machine that turns a raw Security Onion alert into a fully-actioned
triage outcome — evidence gathered, a verdict produced, a TheHive case created or merged
(or the alert closed as a false positive), and any actionable observables (IPs, hashes,
processes) written onto that case with a recommended disposition.

**What it isn't:**
- **Not an agent.** There is no ReAct loop, no tool-calling LLM, no multi-turn reasoning.
  Evidence gathering is a fixed, deterministic sequence of backend calls — the tools
  needed for a given alert are always the same, so there's nothing for an LLM to decide
  there. The one LLM call in the whole pipeline has zero tool access; it's a single-shot
  completion.
- **Not a scoring engine.** There is no numeric formula anywhere. The LLM outputs a
  priority band (`P1`–`P5`) and qualitative labels directly; a single deterministic
  safety check can escalate the band by one step, and that's the only math in the system.
- **Not read-only.** Unlike a purely advisory design, this service writes directly to
  TheHive — creating cases, merging alerts, closing false positives, and writing
  observables. It is a deliberate deployment decision, not an oversight.

## 2. Architecture: the four layers

```
schemas/   →  data contracts (Pydantic models). No logic, no I/O, no dependencies
              on anything else in this repo.
tools/     →  one function per external system call (TheHive, Elasticsearch, iTop,
              OpenCTI, Qdrant, local SQLite). Pure I/O — never decides *when* to run.
prompts/   →  what's sent to the LLM: the system prompt text and the per-call JSON
              schema that constrains its output. No I/O, no orchestration.
stages/    →  the pipeline stages. Orchestration only — call tools/prompts, produce
              the next typed object, handle concurrency/timeouts/fallbacks.
```

The dependency graph is strictly one-directional:

```
schemas/  ← nothing (the foundation)
tools/    ← schemas, config
prompts/  ← schemas
stages/   ← schemas, tools, prompts, config, logging_config
main.py   ← stages, schemas, alert_builder, config
```

`schemas/` never imports from `tools/`, `stages/`, or `prompts/` — the data contracts
can never depend on how they're produced. This is what makes every stage boundary a
strict, checkable Pydantic model instead of a raw dict: a field renamed in one place and
misread in another fails loudly at validation time, not silently downstream.

## 3. The pipeline, end to end

`POST /triage` (`main.py::run_pipeline`) runs, in order, for one alert:

```
                     ┌─────────────────────────────────────────────┐
  n8n webhook        │  1. alert_builder.build_canonical_alert       │
  {thehive_alert_id, │     raw alert + fetched TheHive record         │
   raw_alert}    ───▶│     → CanonicalAlert                          │
                     └───────────────────┬───────────────────────────┘
                                          ▼
                     ┌─────────────────────────────────────────────┐
                     │  2. stages/gather.py::gather_evidence         │
                     │     5 backend calls, concurrent               │
                     │     → RawEvidence                              │
                     └───────────────────┬───────────────────────────┘
                                          ▼
                     ┌─────────────────────────────────────────────┐
                     │  3. stages/rag.py::rag_enrichment              │
                     │     1 Qdrant call (MITRE grounding)            │
                     │     → EnrichedEvidence                         │
                     └───────────────────┬───────────────────────────┘
                                          ▼
                     ┌─────────────────────────────────────────────┐
                     │  4. stages/triage.py::single_stage_triage      │
                     │     THE ONE LLM CALL                           │
                     │     → TriageVerdict                            │
                     └───────────────────┬───────────────────────────┘
                                          ▼
                     ┌─────────────────────────────────────────────┐
                     │  5. stages/case_action.py::case_action         │
                     │     writes to TheHive: new case / merge /      │
                     │     closed FP + actionable observables         │
                     │     → CaseActionResult                         │
                     └───────────────────┬───────────────────────────┘
                                          ▼
                          main.py assembles TriageResult / TriageResponse
                                          ▼
                                  HTTP 200 response to n8n
```

Every stage takes a typed input and returns a typed output. Nothing passes a raw `dict`
between stages. Every stage has a documented "never raises to its caller" contract — a
failure degrades gracefully (a logged `Gap`, a deterministic fallback verdict, or a
`success=False` result) rather than crashing the pipeline.

## 4. Data contracts (`schemas/`)

Seven files, pure Pydantic models, zero logic.

### `schemas/alert.py` — the canonical alert shape

- **`InvestigationProfile`** — `Literal["network_threat", "endpoint_behavior",
  "malicious_file", "generic"]`, set by `alert_builder.py` from which detection engine
  fired (Suricata / Sigma / YARA-Strelka / unknown).
- **`HashBundle`** — `md5`/`sha1`/`sha256`/`sha512`/`imphash`/`ssdeep`, each a list (an
  alert can carry more than one hash per algorithm — process hash + file hash + DLL
  hash).
- **`Observables`** — `external_ips`, `domains`, `urls`, `hashes: HashBundle`. Sourced
  from `hive_alert.observables` (n8n extracts them, Cortex scores them, before
  `/triage` is ever called) — never regexed out of raw alert text.
- **`OSInfo`**, **`Rule`** (`name`, `uuid`, `native_severity`, `level`, `product`,
  `category`, `service`), **`Host`**. There is no typed `Process`, `Network`, or `User`
  model — none of that detail is structurally extracted at all; it reaches the LLM
  through `raw_alert` directly instead, the same as file/registry/related-entity detail.
- **`CortexResult`** — one analyzer's output for one observable. Carries **no number** —
  scoring is left entirely to the LLM. `verdict` is a list of only the adverse taxonomy
  levels (`malicious`/`suspicious`); an empty list means "nothing adverse reported," not
  "clean" and not "unknown."
- **`CanonicalAlert`** — the alert-builder's output, read by every later stage. Carries
  `timestamp` (the alert's own time) and `event_timestamp` (the underlying event's time)
  as two separate fields since they can differ by days. `raw_alert: dict` carries the
  original webhook body verbatim — this is deliberate, not a compatibility shim: the LLM
  reads file/registry/parent-process/etc. detail directly from here rather than through
  a typed intermediate only it would ever consume.
- **`AlertWebhookPayload`** — what n8n actually POSTs: `{thehive_alert_id, raw_alert}`.
  No asset context, no pre-fetched TheHive record — `main.py` fetches that itself.

### `schemas/evidence.py` — gathered and enriched evidence

- **`Gap`** — `{source, reason, tool, duration_ms}`. The explicit "couldn't gather this,
  and here's why" record used everywhere in the pipeline.
- **`LogSource`**, **`RuleContext`** — `detection_rule_lookup`'s output: rule metadata,
  `mitre_attack`/`mitre_tactics`/`mitre_groups`/`mitre_software` (parsed from the rule's
  own content), `falsepositives`, `has_known_falsepositives`, `status`,
  `has_reliable_status` (only `"stable"` counts as reliably vetted).
- **`FPSignal`** — `rule_fp_count_24h`, `rule_fp_count_30d`. Rule-scoped only (the host
  dimension was deliberately removed). Counts, not a rate — there's no valid denominator
  since only FP closures are ever logged.
- **`OpenCTIRelation`**, **`OpenCTIEnrichment`** — OpenCTI's threat-graph answer for one
  observable: is it known, and what's it related to.
- **`ShallowCase`** — a TheHive case summary (deliberately shallow — the LLM never needs
  the full case body): `case_id`, `case_number`, `title`, `severity`, `stage`, `status`,
  `tags`, `created_at`, `observables` (the matched overlap values), and
  `similar_observable_count` (TheHive's own similarity-engine overlap score).
- **`AssetContext`** — `itop_asset_lookup`'s output: `found`, `hostname`, `criticality`,
  `owner`, `organization`, `ip_addresses`, `asset_number`, `os_family`, etc. Several
  fields may be legitimately unpopulated depending on what's configured in the CMDB —
  `found=True` with `criticality=None` is a real, meaningful state ("asset exists, no
  criticality assigned"), distinct from `found=False`.
- **`MitreCandidate`** — one `mitre_techniques` Qdrant hit (technique id/name, tactic
  list, platforms, sub-technique flag, similarity score).
- **`RawEvidence`** — Stage 1's output: `canonical_alert`, `fp_signal`, `rule_context`,
  `open_cases: list[ShallowCase]`, `asset_context`, `opencti_enrichment`,
  `investigation_gaps: list[Gap]`, `stage_1_duration_ms`. A `cortex_results` property
  re-exposes `canonical_alert.cortex_results` so downstream code reads one object.
- **`EnrichedEvidence(RawEvidence)`** — subclasses `RawEvidence` (never re-declares its
  fields, so nothing added upstream can silently go missing) and adds
  `mitre_candidates: list[MitreCandidate]` plus `stage_2_duration_ms`.

### `schemas/assessment.py` — shared building blocks for the verdict

- **`MitreMapping`** — `technique_id`, `technique_name`, `tactic`, `confidence`, `basis`.
- **`CorrelationDecision`** — `action: Literal["new", "merge"]`, `merge_into_case_id`,
  `kill_chain_progression_detected`, `reasoning`.
- **`EvidenceSource`** — one gathered source's status: `present`/`empty`/`missing`, plus
  `impact_on_triage`. `"empty"` (checked, found nothing) and `"missing"` (couldn't check)
  are never conflated.
- **`EvidenceSituation`** — `sources: list[EvidenceSource]` (covering the 5 gathered
  sources — `fp_signal`, `rule_context`, `open_cases`, `asset_context`,
  `opencti_enrichment`), `overall_evidence_reliability: Literal["high","medium","low"]`,
  `analyst_must_verify: list[str]`.

### `schemas/verdict.py` — the LLM call's entire output contract

- **`ActionableObservable`** — `observable_type` (7-value enum: `process-id`,
  `process-path`, `ip`, `file-path`, `domain`, `url`, `hash`), `value`,
  `recommended_disposition` (`kill`/`block`/`collect`/`delete`/`monitor`), `confidence`
  (required — the core judgment), `reasoning`, `observable_id` (never set by the LLM;
  filled in post-hoc by `case_action.py` once the real TheHive write completes).
- **`TriageVerdict`** — `refined_mitre_mapping`, `correlation_decision`,
  `evidence_situation`, `likelihood` (`unlikely`/`possible`/`likely`/`near_certain`),
  `impact_if_true` (`minor`/`moderate`/`significant`/`severe`), `verdict`
  (`true_positive`/`false_positive`/`needs_review`), `reasoning`, `summary`,
  `recommended_action` (`create_case`/`close_fp`/`merge_quiet`/`merge_and_retier`/
  `needs_review`), `evidence_analysis` (free-text narrative of what the evidence shows),
  `actionable_observables`, `priority_band` (`P1`–`P5`), `priority_reasoning`,
  `investigation_gaps`, `stage_duration_ms` (set post-hoc), `safety_gate_applied` (set
  post-hoc). Produced either by the real LLM call or by the deterministic fallback —
  both paths share this exact schema.

### `schemas/case_action.py`

- **`CaseActionResult`** — `success`, `action_taken` (`"new_case"`/`"merge"`/
  `"fp_alert"`), `case_id`, `case_number`, `is_new_case`, `severity` (TheHive's 1–4),
  `tlp` (TheHive's 0–4), `stage`, `status`, `tags`, `comment_added`,
  `observables_written`/`observables_failed`, `case_narrative` (the exact Markdown
  written to TheHive), `actionable_observables_written` (the verdict's list, enriched
  with real TheHive ids), `error`.

### `schemas/result.py` — the final `/triage` response

- **`IocObservable`** — one `ioc: true` observable from the alert paired with its Cortex
  analyzer results.
- **`TriageResult`** — the full `/triage` payload: flattened verdict fields
  (`verdict`, `recommended_action`, `summary`, `reasoning`, `likelihood`,
  `impact_if_true`, `priority_band`, `priority_reasoning`, `safety_gate_applied`,
  `investigation_gaps`, `correlation_reasoning`, `refined_mitre_mapping`), the alert's
  `ioc_observables`, `actionable_observables` (the enriched, TheHive-id-bearing version),
  `evidence_situation`, the complete `triage_assessment: TriageVerdict` object (deliberate
  redundancy — quick-glance fields plus full audit detail), case identity (`case_id`,
  `case_number`, `is_new_case`), and `case_action: CaseActionResult | None`.
- **`TriageResponse`** — `{success, result, error, failed_stage}`. This is what `/triage`
  actually returns over HTTP, always as a `200`.

## 5. Backend tools (`tools/`)

Every tool follows the same contract: **async, typed input, returns
`(result, Gap | None)`, never raises.**

| File | Backend | Function(s) | What it does |
|---|---|---|---|
| `thehive.py` | TheHive | `get_full_alert_with_analysis` | Fetches the alert plus its observables and Cortex/VirusTotal/OpenCTI taxonomy rows, via two concurrent stock query-API calls (no custom server-side function). Sole source of IOCs and threat-intel verdicts. |
| | | `search_open_cases_by_entities` | Finds cases similar to this alert, entirely via TheHive's native `getAlert -> similarCases` engine, filtered to `stage != "Closed"`, sorted newest-first, capped at 20. One round trip; no fallback query. |
| | | `create_case_from_alert` | **Write.** Promotes an alert to a new case (two calls: create, then `PATCH` to set this pipeline's own title/description/severity/tags/tlp, since the create endpoint's own override-acceptance is never assumed). |
| | | `merge_alert_into_case` | **Write.** Merges an alert into an existing case. |
| | | `update_case` | **Write.** Partial update (severity/tlp/tags) — used for `merge_and_retier`. |
| | | `add_case_comment` / `add_alert_comment` | **Write.** Attaches the triage narrative to a case (on merge) or an alert (on false positive). |
| | | `update_alert` | **Write.** Partial alert update (severity/tlp/status/summary) — closes an alert as `FalsePositive`. |
| | | `create_case_observable` / `fetch_case_observables_with_type` | **Write / read.** Creates an observable on a case (returns its real TheHive id) and fetches a case's existing observables (for dedup before writing). |
| `detection_rules.py` | Elasticsearch (`so-detection`) | `detection_rule_lookup` | Fetches the fired rule's metadata and parses its original content — Sigma YAML `tags:`, or Suricata's inline `metadata:key val,...;` clause — for MITRE technique/tactic/group/software ids. YARA content isn't parsed (no ATT&CK data exists in this deployment's YARA rules). |
| `es_client.py` | (shared transport) | — | Not a tool itself — the `httpx` wrapper `detection_rules.py` uses for auth/TLS/timeout handling against Elasticsearch. |
| `itop.py` | iTop (CMDB) | `itop_asset_lookup` | Resolves a hostname (or asset number, tried first when populated) to a CMDB asset and returns criticality/owner/org/OS for the impact side of triage. No IP-based lookup exists on this instance. |
| `opencti.py` | OpenCTI (GraphQL) | `opencti_observable_enrichment` | Batches every IOC on the alert into one GraphQL query against OpenCTI's threat graph: is each a known indicator, and what's it related to (malware/actor/campaign). Distinct from the OpenCTI *Cortex analyzer* results, which arrive through `thehive.py` instead. |
| `qdrant.py` | Qdrant (vector DB) | `retrieve_mitre` | The only RAG call in the pipeline. Embeds the alert's most specific behavioral signal (command line, or a network-connection description) and retrieves matching MITRE ATT&CK techniques from the `mitre_techniques` collection, to ground the LLM's own MITRE reasoning against a real technique corpus. |
| `fp_tracking.py` | local SQLite | `get_fp_signal` / `record_triage_outcome` | Per-rule false-positive history: how many times this specific rule has closed as a false positive in the last 24h/30d. Backed by a timestamped event-log table (`fp_events`), not raw counters, so the time windows are computed as real `COUNT(*) ... WHERE` queries. `record_triage_outcome` is called only on an FP close. |

## 6. Pipeline stages (`stages/`)

### `stages/_guard.py` — shared plumbing

Two helpers every multi-call stage uses:
- **`_guarded(coro, seconds, default, source, tool)`** — wraps a tool call in an outer
  `asyncio.wait_for`. Every tool already guards its own backend call internally; this is
  the last line of defense if a tool's own safety net has a bug and raises anyway. Also
  the single injection point for per-tool DEBUG-level entry/exit/duration logging —
  covering every tool call with zero edits to any individual `tools/*.py` file.
- **`_unpack(result, default)`** — defensively unpacks an `asyncio.gather(...,
  return_exceptions=True)` result back into `(value, Gap)`, converting a stray raw
  exception into a Gap rather than letting it propagate.

### `stages/gather.py::gather_evidence` — Stage 1

Fires 5 tool calls concurrently via `asyncio.gather`:
`fp_tracking.get_fp_signal`, `detection_rules.detection_rule_lookup`,
`thehive.search_open_cases_by_entities`, `itop.itop_asset_lookup`,
`opencti.opencti_observable_enrichment` — each `_guarded` with its own
`config.STAGE_1_TOOL_TIMEOUT_*` budget and a zero-value default
(`FPSignal()`, `RuleContext(found=False)`, `[]`, `AssetContext(found=False)`, `[]`).
Assembles the results, plus any Gaps, into `RawEvidence`. Never raises.

### `stages/rag.py::rag_enrichment` — Stage 2

Builds a MITRE query from the rule's own title (or `rule.name` if no title) plus its
description only (`_build_mitre_query`) — never anything from the alert itself
(`process.command_line`, network context, etc. are deliberately excluded). Calls
`qdrant.retrieve_mitre` once (guarded the same way as Stage 1), producing
`EnrichedEvidence`. There is no historical-context retrieval, no CVE lookup, and no
playbook/runbook retrieval anywhere in this pipeline.

### `stages/triage.py::single_stage_triage` — Stage 3, the one LLM call

1. Builds the prompt (`prompts.build_user_prompt`) and the per-call output schema
   (`prompts.build_triage_verdict_schema`).
2. Caps the requested completion size (`_capped_max_tokens`) so `prompt + completion`
   never exceeds the model's real context window — prompt size is estimated from
   character count (no universal tokenizer available across backends), with a safety
   margin and a floor.
3. Sends one `chat/completions` request with `response_format: json_schema` and
   `temperature=0.1`.
4. Parses only the *first* JSON value in the response (`_extract_first_json_object`) —
   defensive against a model that keeps generating after a complete object.
5. Validates into `TriageVerdict`, then runs three post-parse defense-in-depth checks:
   - `_validate_merge_target` — discards `merge_into_case_id` if it isn't actually one
     of `evidence.open_cases`'s real ids.
   - `_validate_recommended_action` — falls back to `needs_review` if
     `recommended_action` is inconsistent with `correlation_decision.action` (both come
     from the same response, so the schema can't always narrow one against the other
     ahead of generation).
   - `_validate_actionable_observables` — discards any observable value not traceable,
     byte-for-byte, to the evidence JSON (a JSON-escaping-safe comparison, so a Windows
     path or non-ASCII value isn't wrongly flagged as a hallucination).
6. Applies `_apply_safety_backstop`: if `overall_evidence_reliability == "low"` and the
   LLM assigned `P4`/`P5` anyway, escalates one band and appends an explanation.
7. **On any failure at any step** (connection error, timeout, non-2xx, malformed JSON,
   failed validation) — `_stage_fallback` produces a deterministic `TriageVerdict`
   instead: `verdict="needs_review"`, `priority_band="P2"`,
   `overall_evidence_reliability="low"`, `safety_gate_applied=True`,
   `correlation_decision.action` set to `"merge"` into the first open case if any exist
   (otherwise `"new"`), `refined_mitre_mapping` preserved from the rule's own MITRE
   tags, `actionable_observables` empty (a downed LLM must never fabricate an IOC).

## 7. The LLM call in detail (`prompts/`)

`prompts/triage_agent.py` is the entire LLM interface — nothing about what's asked of
the model lives anywhere else.

### The prompt (`build_user_prompt`)

Dumps the **entire** `EnrichedEvidence` object as JSON, minus one thing: each Cortex
result's raw `.raw` field (a large, redundant duplicate of the already-structured
`taxonomies`/`verdict`/`details`/`analyzer` fields). `canonical_alert.raw_alert` is
**not** excluded — it's included verbatim, since it's the LLM's only source for
file/registry/parent-process/target-process detail that `alert_builder.py` deliberately
doesn't extract into a typed field.

There is **no prompt-injection firewall** — this is a deliberate, documented trade-off.
The LLM reasons over the full evidence dump for both the analytical read and the
operational verdict in one pass, so attacker-controlled fields (command lines, file
paths, rule descriptions) reach it unfiltered. The compensating control is the
hallucination guard described above (§6) — it catches fabricated *values*, not
manipulated *reasoning* elsewhere in the response.

### The six tasks (`SYSTEM_PROMPT`)

1. **Refine the MITRE mapping** — validate the RAG-retrieved candidates against the
   actual evidence, add or remove techniques.
2. **Judge correlation** — decide `new` vs. `merge` (only against real `open_cases`
   ids — "never invent or infer an id from anywhere else"), and whether this alert
   represents kill-chain progression.
3. **Assess the evidence situation** — one entry per gathered source
   (`present`/`empty`/`missing` + impact), `overall_evidence_reliability`, and
   `analyst_must_verify`; plus write `evidence_analysis`, a narrative reading of what
   the rule match, process/network/file activity, and Cortex results actually show.
4. **Extract actionable observables** — not every IOC, only what a responder would need
   to act on right now, each copied character-for-character from the evidence (an
   unsupported value is discarded as a hallucination).
5. **Produce the verdict** — `likelihood`, `impact_if_true`, `verdict`, `reasoning`,
   `summary`, `recommended_action`.
6. **Assign priority** — a `P1`–`P5` band via an explicit three-question rubric (see
   below), never a computed score.

### The priority rubric

The model answers three yes/no/unknown questions from the evidence — **A**: has a
benign explanation been established (rule's own documented false positives, high FP
count for this rule, Cortex ran and found nothing, known-good pattern)? **B**: has
confirmed malicious activity been established (adverse Cortex verdict, OpenCTI known
indicator)? **C**: is active progression or high-impact signal present (a
lateral-movement/exfiltration/impact/credential-access MITRE tactic, kill-chain
progression detected, or a high-criticality/crown-jewel asset)? — then maps the
`(A, B, C)` combination to a band via a fixed decision table (e.g. `A=No, B=Yes, C=Yes`
→ **P1**; `A=Yes, B=No` with positive exculpatory evidence → **P5**). If
`overall_evidence_reliability == "low"`, the prompt itself instructs a **P3 floor**
before the model even answers — the same rule `_apply_safety_backstop` enforces
deterministically afterward as a backstop.

### The dynamic schema (`build_triage_verdict_schema`)

Built fresh **per call**, not a static constant — this is how the model is made
structurally incapable of inventing a case to merge into:
- `correlation_decision.merge_into_case_id`'s enum is set to this alert's real
  `open_cases` ids, plus `null`.
- `correlation_decision.action`'s enum drops `"merge"` entirely when there are no open
  cases — the option doesn't exist in the schema, not just discouraged in the prompt.
- `recommended_action`'s enum excludes `merge_quiet`/`merge_and_retier` when there are
  no open cases to merge into.

The schema itself is **hand-inlined** (`_BASE_SCHEMA`), never generated from
`TriageVerdict.model_json_schema()` — a `$ref`/`$defs`-based schema sent to
`response_format: json_schema` can hang a grammar-constrained decoder for minutes on
some backends; the identical schema hand-inlined completes normally.
`tests/test_triage.py::TestSchemaStaysInSync` guards against the hand-inlined schema and
the real `TriageVerdict` model drifting apart on a future field change.

## 8. Case action — writing the outcome to TheHive

`stages/case_action.py::case_action` is the **only** node with real, externally-visible
side effects. It dispatches on `TriageVerdict.verdict` into three branches:

**Branch 1 — `verdict == "false_positive"`.** No case is ever created or merged. The
triage narrative is posted as a **comment on the alert**, and the alert itself is
**closed** via `update_alert(status="FalsePositive", ...)` — a real, first-class value
in this TheHive instance's alert-status enum. Severity and TLP are forced to the floor
(`1`/low, `0`/clear) regardless of what band the LLM assigned. FP feedback into the
local SQLite tracker is wired separately, upstream, in `main.py`.

**Branch 2 & 3 — everything else, driven only by `correlation_decision.action`.** Every
non-FP alert results in either a new case or a merge, **unconditionally** — there is no
`needs_review`/hold-off state. The verdict's richer fields (`recommended_action`,
`reasoning`, `summary`) become case *content*, never a gate on whether to act.
- **`action == "new"`** → `create_case_from_alert` (title = `[{priority_band}] {rule
  name} — {host}`; description = the full Markdown narrative below; severity/TLP from
  `priority_band`).
- **`action == "merge"`** → `merge_alert_into_case`, then `add_case_comment` with the
  same narrative (so each merged alert's identity stays visible in the comment thread —
  the case's own title only ever reflects whichever alert *created* it).
  `recommended_action == "merge_and_retier"` additionally triggers `update_case` to bump
  severity/TLP, since TheHive's merge endpoint doesn't accept field overrides in the
  same call.

**Severity and TLP mapping** — both derive from `priority_band`:

| Band | TheHive severity (1–4) | TheHive TLP (0–4) |
|---|---|---|
| P1 | 4 | 4 (red) |
| P2 | 3 | 3 |
| P3 | 2 | 2 |
| P4 | 1 | 1 |
| P5 | 1 | 0 (clear) |

Severity can't distinguish P4 from P5 (TheHive's scale tops out at 4 values); TLP
carries the full 5-band spread instead.

**The case narrative** (`_build_case_description`) is deterministic Markdown assembly —
no LLM call of its own. It always includes an alert-identity heading (`alert_id`, rule
name, timestamp), the verdict/action/priority summary, the LLM's `reasoning` and
`evidence_analysis`, rule/asset detail, correlation reasoning, any Stage-1 tool gaps, the
priority band and reasoning, and the analyst-must-verify list.

**Actionable observables** are written only *after* a case genuinely exists (post
create/merge success): `_write_actionable_observables` fetches the case's current
observables, reuses an existing id when a value already matches, and otherwise creates
a new one — tagged `disposition:<value>` and `confidence:<value>`, with `ioc=True` only
for `block`/`quarantine` dispositions. It specifically handles the race where TheHive's
own background alert-to-case observable import collides with this write (a
`"Observable already exists"` error triggers a re-fetch-and-reuse rather than a
reported failure).

## 9. The HTTP API (`main.py`)

- **`POST /triage`** — synchronous, one blocking request/response per alert. Runs
  ingestion (fetches the full TheHive alert record via
  `thehive.get_full_alert_with_analysis`, then `alert_builder.build_canonical_alert`),
  then the five pipeline stages in sequence, then assembles `TriageResult`.
- **Failure posture: HTTP 200, always.** A failure at any point produces
  `TriageResponse(success=False, result=<whatever was built so far>, error=...,
  failed_stage=...)` rather than an HTTP error status — the caller's workflow inspects
  `success` instead of relying on status codes. `stage` is tracked explicitly (not
  inferred from a traceback) so `failed_stage` is always accurate, and a partially-built
  `result` is returned rather than discarded if a later stage fails.
- **FP feedback** (`_record_fp_feedback`) — writes to the local SQLite tracker whenever
  `verdict.verdict == "false_positive"`, keyed on `rule.uuid` alone. Best-effort, never
  raises, skipped (logged) when `rule.uuid` is empty.
- **`GET /health`** — checks LLM reachability only, deliberately minimal (not a full
  dependency check across TheHive/Elasticsearch/iTop/Qdrant) — the cheapest check that
  catches a dead or misconfigured LLM backend immediately.

## 10. Alert building (`alert_builder.py`)

`build_canonical_alert(raw_alert, hive_alert, thehive_alert_id)` is pure Python, no LLM,
no I/O — the translation layer between "whatever Security Onion actually sent" and the
typed `CanonicalAlert` every stage reads.

- **Engine detection** (`_source_engine`) — `event.module` first, then the
  `event.dataset` prefix.
- **Two structurally different shapes handled explicitly**: Sigma/Sysmon alerts nest
  their event fields under `event_data`; Suricata alerts carry the equivalent fields one
  level up, at the top level — there is no `event_data` wrapper on a Suricata document
  at all. Host identity is the only structured extraction that spans both shapes
  (`_extract_host_from_event_data`, falling back to `_extract_winlog_host`) — process,
  network, and user detail are not structurally extracted for either shape at all; both
  reach the LLM only through `raw_alert`.
- **Rule parsing** (`_parse_rule`) — a real, guarded-against collision: Sysmon's own
  internal `event_data.rule` (a config `RuleName` tag) is never confused with the
  actually-fired rule at the top-level `rule.name`.
- **Observable building** (`_build_observables`) — merges hashes/IOCs from
  `hive_alert.observables`; a value starting with `http(s)://` is always classified as a
  URL regardless of what the ingest pipeline's own `dataType` label claims (a known
  mis-classification source in the raw data).
- **Cortex taxonomy summarization** (`_summarize_taxonomies`, `_build_cortex_results`) —
  reads `hive_alert.observables[].reports`, keeps only adverse (`malicious`/`suspicious`)
  verdict levels, preserves every raw taxonomy row for the LLM to reason over directly.

## 11. Configuration

`config.py` loads and validates every environment variable at import time — a missing
required variable raises immediately, so no module can ever import a partially
configured client. `.env` is parsed with a small stdlib loader (not `python-dotenv`,
which isn't installed); real process environment variables always win over the file.

Key groups (see `.env.example` for the full list with defaults):

- **LLM** — `LLM_BASE_URL`/`LLM_MODEL`/`LLM_API_KEY` (one endpoint, no per-stage split).
  `LLM_MAX_CONTEXT_TOKENS` (default 8192), `LLM_TOKEN_ESTIMATE_CHARS_PER_TOKEN` (default
  3.2 — conservative, since dense low-entropy text like GUIDs/hashes tokenizes less
  efficiently than prose), `LLM_CONTEXT_SAFETY_MARGIN_TOKENS`,
  `LLM_MIN_COMPLETION_TOKENS`, `STAGE_TRIAGE_DESIRED_MAX_TOKENS` (default 16000).
- **Backends** — `THEHIVE_URL`/`THEHIVE_API_KEY`, `ITOP_URL`/`ITOP_USER`/`ITOP_PWD`
  (username+password, not an API key), `ES_URL` (must carry `:9200` explicitly — the
  bare host redirects to the Security Onion web UI), `QDRANT_URL`/`EMBEDDING_API_URL`,
  `OPENCTI_URL`/`OPENCTI_TOKEN`.
- **Indexes** — `ES_DETECTION_INDEX` (default `so-detection`, must never be wildcarded),
  `ES_AUDIT_INDEX`.
- **Storage** — `FP_TRACKING_DB_PATH` (local SQLite file).
- **Timeouts** — one `STAGE_1_TOOL_TIMEOUT_*` per Stage-1 tool (ITOP/THEHIVE/ES/QDRANT/
  FP/OPENCTI), `STAGE_TRIAGE_LLM_TIMEOUT`, `STAGE_6_TOOL_TIMEOUT_THEHIVE` (used by
  `case_action.py`'s pre-write observable dedup fetch).
- **Logging** — `LOG_LEVEL` (default INFO), `LOG_FILE` (default `./logs/soc3s.log`,
  empty disables file output).
- **Redis is deliberately absent.** `REDIS_URL` is unset in this deployment; dedup
  simply doesn't run — a duplicate alert within a dedup window would just be processed
  twice, a documented and accepted failure mode.

`logging_config.py` uses a `ContextVar` (not a thread-local — this is an asyncio
codebase) to tag every log line across every stage with the current alert's id, via
`alert_context(alert_id)`, which every stage function wraps its body in.

## 12. Error handling philosophy

Three rules hold everywhere in this codebase:

1. **A tool never raises.** Every `tools/*.py` function catches its own timeouts,
   connection errors, and unexpected exceptions, converting them into `(default_value,
   Gap)`. A `Gap` always carries a concrete reason — never `"unknown"`.
2. **`{found: false}` never means two different things.** "Checked, genuinely absent"
   (a real, exculpatory-or-neutral signal) and "could not check" (a reliability gap) are
   always kept distinguishable — usually via a `Gap` accompanying the zero-value result
   in the second case and no `Gap` in the first.
3. **Every stage degrades, never crashes.** `gather_evidence`/`rag_enrichment` degrade
   per-tool via Gaps; `single_stage_triage` falls back to a deterministic verdict on any
   LLM failure; `case_action` returns `CaseActionResult(success=False, error=...)`
   rather than raising; `main.py`'s top-level `try/except` is a last-resort safety net
   for ingestion and genuine unexpected defects, not a path expected to fire often.

Stage 1's `_guarded` wrapper is the concrete mechanism: each tool call is wrapped twice
— its own internal timeout, plus an outer `asyncio.wait_for` in `_guarded` — and the
whole set still goes through `asyncio.gather(..., return_exceptions=True)` on top, even
though nothing should ever reach that outer layer as a raw exception given the two
layers underneath.

## 13. Testing

Every module has a corresponding `tests/test_*.py`. The project's fixture discipline is
explicit: **a tool is not considered done when it passes a mocked test** — it's done
once it's been called against the real, live backend at least once and the actual
response shape inspected field-by-field against its Pydantic model. Mocked tests are
then written *from* that captured real response, never from an imagined shape.
Fixtures under `tests/fixtures/` are labeled REAL (verbatim captured data) or SYNTHETIC
(built from a field-mapping reference, with no live example confirmed yet) — a real
fixture is never sanitized, since the quirks it carries are exactly what makes it a
useful regression guard.

## 14. Known limitations

Documented, deliberate gaps — not oversights:

- **iTop asset lookup is hostname/asset-number keyed only.** No IP-based lookup exists
  on this instance, so a Suricata alert (which has no hostname, only IPs) gets zero
  asset-criticality context from iTop.
- **YARA rule content is not parsed for MITRE data** — this deployment's real YARA rules
  carry no ATT&CK references at all, so there's nothing to extract.
- **A Suricata alert's route into this service depends on an upstream (n8n-side)
  ingestion path** that is separate from this codebase entirely — not something fixable
  here if it's missing for a given deployment.
- **No historical-incident or closed-case retrieval** exists anywhere in the pipeline —
  the only backward-looking signal is `fp_tracking`'s own rule-scoped FP count.
- **No prompt-injection firewall** on the single LLM call (§7) — a deliberate trade-off,
  compensated for by the post-parse hallucination guard on actionable observables only.
