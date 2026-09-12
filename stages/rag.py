"""`rag_enrichment` — runs one Qdrant retrieval (`retrieve_mitre`) and turns
`RawEvidence` into `EnrichedEvidence` for the triage LLM call.

There's no historical-context or playbook/runbook retrieval here. Playbook
lookup would need a refined MITRE mapping that isn't available at this
point in the pipeline — only the raw `rule_context.mitre_tactics` is, and
that's populated from Sigma `attack.*` tags only, so Suricata and YARA
alerts (and many Sigma rules) never have it. Querying playbooks from that
field would silently return nothing for a large share of alerts, so it's
left out.

Same never-raises pattern as `stages/gather.py`: `tools.qdrant.retrieve_mitre`
already guards its own call, `_guarded` adds an outer timeout as a second
layer, and `asyncio.gather(return_exceptions=True)` wraps both.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import config
from logging_config import alert_context
from stages._guard import _guarded, _unpack
from schemas import EnrichedEvidence, RawEvidence
from tools import qdrant

logger = logging.getLogger(__name__)

MAX_MITRE_QUERY_CHARS = 500
MAX_DESCRIPTION_CHARS = 200


def _truncate(text: str, max_len: int) -> str:
    text = text.strip()
    return text if len(text) <= max_len else text[:max_len].rstrip()


def _build_mitre_query(evidence: RawEvidence) -> str:
    """Rule title/name plus rule description only — no process command line,
    no network context. Everything else about the alert reaches the LLM call
    directly through `CanonicalAlert.raw_alert` instead."""
    alert = evidence.canonical_alert
    rule_ctx = evidence.rule_context

    title = (rule_ctx.title if rule_ctx and rule_ctx.title else None) or alert.rule.name
    parts = [title] if title else []

    if rule_ctx and rule_ctx.description:
        parts.append(_truncate(rule_ctx.description, MAX_DESCRIPTION_CHARS))

    return " — ".join(p.strip() for p in parts if p and p.strip())[:MAX_MITRE_QUERY_CHARS]


async def rag_enrichment(evidence: RawEvidence) -> EnrichedEvidence:
    with alert_context(evidence.canonical_alert.alert_id):
        return await _rag_enrichment(evidence)


async def _rag_enrichment(evidence: RawEvidence) -> EnrichedEvidence:
    started = time.monotonic()
    logger.info("RAG enrichment started")

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
        "RAG enrichment completed in %dms: %d mitre matches",
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
