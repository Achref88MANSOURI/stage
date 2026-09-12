# SOC-3s — Agent Operating Instructions

An alert-triage service for Security Onion alerts. It gathers evidence from every
relevant backend, asks one LLM to produce a complete triage verdict, and writes the
outcome (a new TheHive case, a merge into an existing one, or a closed false positive)
back to TheHive. Everything except that one LLM call is deterministic Python.

## Pipeline

`POST /triage` (`main.py`) runs, in order, for one alert:

1. **`alert_builder.build_canonical_alert`** — turns the raw Security Onion alert plus
   the fetched TheHive alert record into one typed `CanonicalAlert`.
2. **`stages/gather.py::gather_evidence`** — every backend tool call, concurrently, into
   a `RawEvidence`.
3. **`stages/rag.py::rag_enrichment`** — one Qdrant retrieval (`retrieve_mitre`) on top of
   that, producing `EnrichedEvidence`.
4. **`stages/triage.py::single_stage_triage`** — the one LLM call. Produces a
   `TriageVerdict`.
5. **`stages/case_action.py::case_action`** — writes the outcome to TheHive (new case,
   merge, or a closed false-positive alert) and writes the LLM's judged
   `actionable_observables` onto the resulting case.

`main.py::_build_triage_result` assembles the final `TriageResult` from `TriageVerdict`
plus `EnrichedEvidence` — a thin, math-free copy, not a computation.

## Hard constraints

- Exactly one LLM call per alert, in `stages/triage.py::single_stage_triage`. No tool
  access, single-shot completion, no ReAct loop, no recursion-limit math. If you're
  about to add a second call or a tool-calling loop, stop and reconsider — this
  pipeline is deliberately not an agent.
- Every stage input/output is a typed Pydantic model from `schemas/`. Never pass a raw
  dict between `nodes/*.py` files.
- Every backend call in `stages/gather.py` and `stages/rag.py` runs inside
  `asyncio.gather(..., return_exceptions=True)`, wrapped twice: each tool already
  guards its own backend call with an internal timeout and never raises on its own;
  `stages/_guard.py::_guarded` adds an outer timeout as the last line of defense. A
  failed or slow backend produces a logged `Gap`, never an unhandled exception reaching
  the caller.
- The triage LLM outputs `priority_band` (P1-P5) and `likelihood`/`impact_if_true`
  labels directly — there is no separate numeric-scoring stage and no formula anywhere
  in this pipeline. `stages/triage.py::_apply_safety_backstop` is the one deterministic
  adjustment: it escalates one band when `evidence_situation.overall_evidence_reliability`
  is `"low"` and the LLM assigned P4/P5 anyway.
- `stages/case_action.py` is the only node with real, externally-visible side effects
  (TheHive writes). Every other node is pure with respect to the outside world.
- Build one node at a time. Write tests for each node — happy path and at least one
  failure/timeout path — before moving to the next.

## What "done" means for a node (`nodes/*.py`)

Typed Pydantic input and output; unit tests covering the happy path and at least one
failure/timeout path; never raises an unhandled exception to its caller. `gather_evidence`
and `rag_enrichment` degrade per-tool via `Gap`s; `single_stage_triage` falls back to a
deterministic `TriageVerdict` on any failure; `case_action` returns
`CaseActionResult(success=False, error=...)` rather than raising.

## What "done" means for a tool (`tools/*.py`)

A tool is not done when it type-checks or passes a mocked test. It is done when it has
been called against the real, live backend at least once and the actual response shape
inspected field-by-field against its Pydantic model. Mocked tests are written *after*
that, from the captured real response — never instead of it, never from an imagined
shape.

## Fixture discipline

Real before mocked, always. Every fixture states whether it's real or synthetic, and if
real, which backend/document shape it covers — a fixture labeled REAL is verbatim data
from a live call; a fixture labeled SYNTHETIC says what it was built from (a field-mapping
reference, an illustrative shape) and that no real example has been captured yet. Never
sanitize a real fixture — quirks a real document carries (fields that look like they
shouldn't be trusted, placeholder values, unexpected nesting) are exactly what makes it
useful; a cleaned-up fixture tests a world that doesn't exist. One real fixture proves one
document shape, nothing else — don't report coverage a fixture doesn't actually back.
After writing a fixture-backed test, break the mapping deliberately and confirm the test
goes red; a test asserting against a field the code never populates passes for the wrong
reason.

## Ground truth hierarchy

When two sources disagree about what a field is called or what it contains, prefer the
more direct one:

1. A live call to the real backend, made during development — proves what the system
   returns today, not that it's returned for every alert shape.
2. A real captured document — proves that shape exists in production, not that other
   shapes resemble it.
3. A live index/schema mapping (field names and types, no values) — proves a field can
   exist, not that any document populates it.
4. Reference material for the upstream system (its own pipelines, templates, docs) —
   proves what a field *can* be called or produced, not that this deployment does.
5. General domain knowledge, inference, or an external spec's illustrative example —
   never sufficient on its own; treat as a hypothesis to verify, not a fact.

## Scope discipline

On multi-part work: never skip, silently simplify, or drop part of a task because it is
large or tedious. If it is too big for one pass, break it into explicit sub-steps, say
so, and do all of them in sequence. If a part genuinely isn't worth doing, say so and ask
before dropping it.

---

## Deployment reference

Operational facts about the real backends this service talks to — not a log of how they
were discovered, just what's true now.

### LLM call (`stages/triage.py`, `prompts/triage_agent.py`)

- One `LLM_BASE_URL` / `LLM_MODEL` / `LLM_API_KEY` — no per-stage split.
- `response_format: {"type": "json_schema", ...}` requires a fully hand-inlined schema
  (no `$defs`/`$ref`) — a `$ref`-based schema can hang a grammar-constrained decoder for
  minutes; the identical schema hand-inlined completes normally.
  `prompts/triage_agent.py::_BASE_SCHEMA` is hand-inlined for exactly this reason, and
  `tests/test_triage.py::TestSchemaStaysInSync` guards it against drifting from
  `TriageVerdict`.
- Plain `json_object` mode alone is not safe: a model can emit one valid JSON object and
  then keep generating hallucinated extra prose/JSON. `_extract_first_json_object` always
  parses only the first JSON value in the response (`json.JSONDecoder().raw_decode`),
  regardless of mode.
- The verdict schema is built per call, not a static constant: `merge_into_case_id`'s
  enum is constrained to the alert's real `open_cases` ids (plus `null`), and
  `correlation_decision.action` drops `"merge"` entirely when there are no open cases —
  the model must never be free to invent a case id to merge into.
  `stages/triage.py::_validate_merge_target` and `_validate_recommended_action` are the
  post-parse defense-in-depth backstops for the same constraint.
- `max_tokens` is capped so `prompt + completion` stays under the model's real context
  window (`LLM_MAX_CONTEXT_TOKENS`, default 8192) — `_capped_max_tokens` estimates prompt
  size from character count (`LLM_TOKEN_ESTIMATE_CHARS_PER_TOKEN`, default 3.2, kept low
  because dense low-entropy text like GUIDs and hashes tokenizes less efficiently than
  prose) plus a safety margin (`LLM_CONTEXT_SAFETY_MARGIN_TOKENS`), floored at
  `LLM_MIN_COMPLETION_TOKENS` so an oversized prompt still gets some completion room.
  `STAGE_TRIAGE_DESIRED_MAX_TOKENS` (default 16000) budgets generously because some
  backend models spend a variable, invisible slice of the same budget on internal
  reasoning that never shows up in the response's own token count.
- There is no prompt-injection firewall — the LLM reasons over the full evidence dump for
  both the analytical read and the operational verdict in one pass, so
  attacker-controlled fields (command lines, file paths, rule descriptions) reach it
  unfiltered. The compensating control is `stages/triage.py::_validate_actionable_observables`,
  which checks every `actionable_observables[].value` is traceable to real evidence —
  catching fabricated *values*, not manipulated *reasoning* elsewhere in the response.
  When checking traceability, the needle must be escaped the same way the evidence was
  serialized (`json.dumps(value, ensure_ascii=False)[1:-1]`) before a substring check
  against the JSON-serialized evidence — an unescaped comparison wrongly discards genuine
  values containing a backslash, quote, or non-ASCII character (e.g. any Windows path) as
  hallucinations.

### TheHive (`tools/thehive.py`)

- Base path is `/api/v1` directly — not `/thehive`; that prefix returns HTTP 200 with the
  SPA's own HTML, a trap for a naive reachability check.
- Open-case correlation (`search_open_cases_by_entities`) is backed entirely by TheHive's
  own native `getAlert -> similarCases` engine — one round trip, filtered to
  `stage != "Closed"`, giving `similar_observable_count` and the matched observables for
  free. There is no other lookup path; a missing `thehive_alert_id` is a `Gap`, not a
  different query.
- `stage` and `status` are different enumerations. `stage` is `New | InProgress | Closed`.
  `status` (on an alert) includes `FalsePositive` as a real, first-class value — setting
  it moves the alert to the closed stage.
- Write endpoints, none of them the conventionally-guessable path:
  - `POST /api/v1/alert/{id}/case` — create a case from an alert (not `/promote`)
  - `POST /api/v1/alert/{id}/merge/{caseId}` — merge an alert into a case
  - `PATCH /api/v1/case/{id}` — partial case update (204, no body)
  - `POST /api/v1/case/{id}/comment` — case comment (not `/api/v1/comment/case/{id}`)
  - `PATCH /api/v1/alert/{id}` — partial alert update (severity/tlp/status/summary)
  - `POST /api/v1/alert/{id}/comment` — alert comment
- Creating a case from an alert is two calls: the create endpoint uses the alert's own
  title/severity/tags as defaults, so `create_case_from_alert` always follows up with a
  `PATCH` to set this pipeline's own computed content rather than assuming the create
  endpoint accepts overrides directly.
- TheHive returns tags in a different order than they were sent — compare as a set or
  sorted list, never positionally.
- Case severity (`1`-`4`) and TLP (`0`-`4`) both derive from `priority_band`. Severity
  can't distinguish P4 from P5 (both map to `1`/low); TLP carries the full 5-band spread.

### Elasticsearch (`tools/detection_rules.py`)

- `so-detection` must be queried EXACTLY, never as a wildcard — `so-detection*` also
  matches `so-detectionhistory` (hundreds of thousands of rule-revision documents), which
  can return a stale rule version.
- `ES_URL` needs an explicit `:9200` — the bare host redirects to the Security Onion web
  UI on 443.
- `raw_alert.ioc.*` is never read anywhere in this codebase. It's produced by a custom
  ingest add-on layered on top of Security Onion (derived from `event.module`), not a
  native SO field, and can never independently corroborate the field it looks like it
  confirms. Engine detection uses `event.module` first, then the `event.dataset` prefix.
- Detection-rule content: `source_engine` comes from `so_detection.language`
  ("sigma"/"suricata"/"yara"), never `so_detection.engine` (the *execution* engine, e.g.
  "elastalert") — reading the wrong one sends every rule down the wrong parse branch.
  MITRE data lives only inside `so_detection.content` (the original pre-compilation rule
  text); doc-level `tags` is always `null`. Sigma content parses as YAML `tags:`; Suricata
  content parses an inline `metadata:key val, key2 val2, ...;` clause (present on roughly
  half of real Suricata rules — its absence is a legitimate, common shape, not a parse
  failure); YARA content is not parsed for MITRE, since YARA `meta:` blocks in this
  deployment never carry an ATT&CK reference. `falsepositives` is commonly the literal
  `["Unknown"]` — Sigma's placeholder for "none documented", not real guidance.

### iTop (`tools/itop.py`)

- Auth is username + password (`ITOP_USER`/`ITOP_PWD`), not an API key.
- No IP-based asset lookup exists at all — `managementip` is blank on every object, and
  no `IPv4Address`/`IPv4Subnet` class exists in this instance. Hostname and
  `asset_number` are the only lookup keys; `asset_number` itself is blank on every
  object currently populated too, so hostname is the only key that actually resolves
  today. A host with no matching asset record returns `found=False` — an unpopulated
  CMDB, not a bug.

### OpenCTI (`tools/opencti.py`)

- `opencti_observable_enrichment` is direct GraphQL threat-graph enrichment ("what does
  OpenCTI's graph say this observable relates to"), distinct from and additional to the
  OpenCTI Cortex analyzer's taxonomy rows (which arrive through
  `tools/thehive.py::get_full_alert_with_analysis`, "did the SOC's own Cortex pipeline
  flag this"). Neither replaces the other.
- The exact-match filter batches every observable value into one query; a value with no
  OpenCTI record simply doesn't appear in the response (`found=False`), not an error.
- `stixCoreRelationships.to` is a STIX-core union type, queried via inline fragments; an
  unmatched fragment resolves to `{}`, treated as "no attributable entity", not a `Gap`.

### False-positive tracking (`tools/fp_tracking.py`)

- Local SQLite (`FP_TRACKING_DB_PATH`), no server dependency.
- One signal, rule-scoped only — how often this specific rule has closed as a false
  positive, in the last 24h and 30d.
- Counts, not a fraction: `record_triage_outcome` only ever writes a row on an FP close,
  never a true-positive close, so there's no valid denominator for a rate.
- The tightest timeout budget in the pipeline (100ms) — a fast local query.

### Redis / dedup

Not deployed. Its absence disables the dedup check entirely and never blocks the
pipeline — a duplicate alert within the dedup window is simply processed twice. A
documented, accepted failure mode.

### Qdrant / RAG (`tools/qdrant.py`, `stages/rag.py`)

Only `retrieve_mitre` runs — MITRE technique retrieval against the `mitre_techniques`
collection. No CVE retrieval, no historical-incident retrieval, and no playbook/runbook
retrieval exist anywhere in this pipeline. The embedding model runs behind its own HTTP
microservice colocated with Qdrant, not loaded in-process.

### Alert building (`alert_builder.py`)

- Sigma alerts nest their event fields under `event_data`; Suricata alerts carry the
  equivalent fields one level up, at the top level — there is no `event_data` wrapper on
  a Suricata document at all.
- A value starting with `http(s)://` is always classified as a URL regardless of what the
  ingest pipeline's own `dataType` label says — a known mis-classification source in the
  raw data.
- YARA/Strelka fields exist in the schema but have only synthetic test coverage — no real
  Strelka/YARA alert has been observed in this deployment to validate against.
- A Suricata alert's route into this service depends on an upstream (n8n-side) ingestion
  path that is separate from this codebase — not something to fix here if it's missing
  for a given deployment.

### HTTP entrypoint (`main.py`)

- `POST /triage` is synchronous — one blocking request/response per alert.
- Every response is HTTP 200. Failure is signaled via `TriageResponse.success=False` plus
  `error`/`failed_stage`, never an HTTP error status, so the caller's workflow never
  breaks on a triage failure — it inspects `success` instead.
- `GET /health` checks LLM reachability only — the cheapest check that catches a dead or
  misconfigured LLM backend immediately — not a full dependency check across every
  backend.

### Case action (`stages/case_action.py`)

- Two-way dispatch on `TriageVerdict.verdict`: a `false_positive` verdict never opens or
  merges a case — the triage narrative is posted as a comment on the alert, and the alert
  is closed (`status="FalsePositive"`) with severity/TLP forced to the floor (low/clear)
  regardless of the LLM's assigned band. Every other verdict results in either a new case
  or a merge, unconditionally — there is no "needs review, do nothing" hold-off; the
  richer verdict fields (`recommended_action`, `reasoning`, `summary`) become case
  content, never a gate on whether to act.
- Actionable-observable writes happen only after a case genuinely exists (after a
  successful create or merge), deduplicated by value against the case's existing
  observables before writing a new one.
