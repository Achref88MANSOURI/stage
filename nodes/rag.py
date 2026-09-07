"""`rag_enrichment` — Stage 2, architecture §7 (trimmed to this deployment's
scope — see module docstring notes below).

Runs one Qdrant retrieval: `retrieve_mitre` (always). Turns Stage 1's
`RawEvidence` into Stage 3's input, `EnrichedEvidence`.

`retrieve_cve` (gated on `_has_cve_indicators`/`_extract_product_hint`) was
REMOVED 2026-09-06, user-directed, along with `CveMatch`
(`schemas/evidence.py`) and `EnrichedEvidence.cve_matches`.
`retrieve_incidents` (the deployment-added `incident_history` collection,
always called) was ALSO REMOVED 2026-09-06, user-directed, along with
`IncidentMatch` and `EnrichedEvidence.incident_matches` — this had itself
only just replaced TheHive's `search_closed_cases_by_rule` (removed earlier
the same day) as the historical-TP/FP-context source. There is now no
historical-context source anywhere in this pipeline; `_build_incident_query`
and `prompts/analyst_agent.py`'s `historical_context` field are gone with it,
not replaced. See `tools/qdrant.py`'s module docstring for the tool-level
side of both removals.

**`retrieve_playbooks` is deliberately NOT called here.** It isn't called
anywhere in the pipeline any more (v6, 2026-09-06) — see
`nodes/triage.py`'s module docstring for the accepted tradeoff. Historically
(pre-v6), playbook/runbook retrieval's natural query input was the refined
MITRE mapping produced by the old Stage 3 LLM call (`refined_mitre_mapping`,
populated for every alert regardless of source engine — Sigma, Suricata, or
YARA), not anything Stage 1/2 has. `rule_context.mitre_tactics` — the only MITRE-tactic field
Stage 2 has access to — is Sigma-`attack.*`-tag-only: Suricata and YARA
alerts never populate it, and plenty of Sigma rules don't either. Querying
playbooks from it here would silently zero out playbook retrieval for a
large share of alerts, forever. Playbook lookup is out of scope for this
node; it is not designed or implemented anywhere in this repo yet.

Same two-layer never-raises pattern as `nodes/gather.py`: each
`tools.qdrant.retrieve_*` call is already internally `NEVER RAISES`
(`tools/qdrant.py`'s own contract), `_guarded` (now shared, see
`nodes/_guard.py`) adds an outer `asyncio.wait_for` as the last line of
defense, and one `asyncio.gather(..., return_exceptions=True)` sits on top
per CLAUDE.md's hard constraint.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import config
from logging_config import alert_context
from nodes._guard import _guarded, _unpack
from schemas import CanonicalAlert, EnrichedEvidence, RawEvidence
from tools import qdrant

logger = logging.getLogger(__name__)

MAX_MITRE_QUERY_CHARS = 500
MAX_DESCRIPTION_CHARS = 200
MAX_COMMAND_LINE_CHARS = 300


def _truncate(text: str, max_len: int) -> str:
    text = text.strip()
    return text if len(text) <= max_len else text[:max_len].rstrip()


def _most_specific_behavior_keyword(alert: CanonicalAlert) -> str | None:
    """Exactly one priority-selected behavioral phrase — never a
    concatenation of everything available. See module docstring / the
    approved plan for why a multi-behavior blob collapses MITRE recall.

    Trimmed 2026-09-07, user-directed (alert_builder.py simplification):
    the api-call/target-process and file/library branches this function used
    to have are gone along with `CanonicalAlert.process.api`/`.target_process`
    /`.file`/`.library` themselves — those fields no longer exist (see
    `schemas/alert.py::Process`'s docstring). `command_line` and network
    context are the only structured behavioral signals left; anything else
    those removed branches used to surface now reaches the single LLM call
    through `CanonicalAlert.raw_alert` directly instead, which this Stage 2
    query builder has no access to (nor needs — a Qdrant query built from raw
    JSON text would be noise, not signal)."""
    if alert.process and alert.process.command_line:
        collapsed = " ".join(alert.process.command_line.split())
        return _truncate(collapsed, MAX_COMMAND_LINE_CHARS)

    if alert.network and (alert.network.dst_ip or alert.network.dst_ipv6):
        dst = alert.network.dst_ip or alert.network.dst_ipv6
        protocol = alert.network.protocol or "unknown protocol"
        if alert.network.dst_port:
            return f"network connection to {dst}:{alert.network.dst_port} over {protocol}"
        return f"network connection to {dst} over {protocol}"

    return None


def _build_mitre_query(evidence: RawEvidence) -> str:
    alert = evidence.canonical_alert
    rule_ctx = evidence.rule_context

    title = (rule_ctx.title if rule_ctx and rule_ctx.title else None) or alert.rule.name
    parts = [title] if title else []

    if rule_ctx and rule_ctx.description:
        parts.append(_truncate(rule_ctx.description, MAX_DESCRIPTION_CHARS))

    keyword = _most_specific_behavior_keyword(alert)
    if keyword:
        parts.append(keyword)

    return " — ".join(p.strip() for p in parts if p and p.strip())[:MAX_MITRE_QUERY_CHARS]


async def rag_enrichment(evidence: RawEvidence) -> EnrichedEvidence:
    with alert_context(evidence.canonical_alert.alert_id):
        return await _rag_enrichment(evidence)


async def _rag_enrichment(evidence: RawEvidence) -> EnrichedEvidence:
    started = time.monotonic()
    logger.info("Stage 2 started")

    calls = [
        _guarded(
            qdrant.retrieve_mitre(_build_mitre_query(evidence)),
            seconds=config.STAGE_1_TOOL_TIMEOUT_QDRANT,
            default=[],
            source=qdrant.SOURCE,
            tool=qdrant.TOOL_NAME_MITRE,
        ),
    ]

    results = await asyncio.gather(*calls, return_exceptions=True)
    enriched = _build_enriched_evidence(evidence, results, started)
    logger.info(
        "Stage 2 completed in %dms: %d mitre matches",
        enriched.stage_2_duration_ms,
        len(enriched.mitre_candidates),
    )
    return enriched


def _build_enriched_evidence(
    evidence: RawEvidence, results: list[Any], started: float
) -> EnrichedEvidence:
    mitre_candidates, gap_mitre = _unpack(results[0], [])

    new_gaps = [g for g in (gap_mitre,) if g is not None]

    return EnrichedEvidence(
        **evidence.model_dump(exclude={"investigation_gaps"}),
        investigation_gaps=list(evidence.investigation_gaps) + new_gaps,
        mitre_candidates=mitre_candidates,
        stage_2_duration_ms=int((time.monotonic() - started) * 1000),
    )
