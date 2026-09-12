"""`retrieve_mitre` — RAG retrieval against Qdrant, grounding the triage LLM's
MITRE ATT&CK technique output in a real corpus instead of letting it invent
technique IDs cold.

Deterministic Python, not an LLM-callable tool — no tool schema is exposed
anywhere in this module. The evidence-gathering node calls this function
before the LLM runs and folds the result into `EnrichedEvidence`, which the
single-shot LLM call then reads as plain data. This matches every other
`tools/*.py` module in this repo: neither LLM call in this pipeline has tool
access.

Qdrant lives at `config.QDRANT_URL`; embeddings come from
`config.EMBEDDING_API_URL`, a separate HTTP microservice colocated on the
same host (`POST {"text": ...} -> {"embedding": [float x 1024]}`,
BAAI/bge-m3, 1024-dim Cosine) — the model is not loaded in-process, so there
is nothing to initialize once on this side; every call below is a fresh,
cheap HTTP round trip, matching every other `tools/*.py`'s fresh-client-per-
call convention.

Queries the `mitre_techniques` collection (697 points). Real point payloads
have no `description`, `detection_guidance`, `mitigations` or
`priority_score_0_5` field, and `tactic` is a list, not a single string (a
technique can belong to more than one tactic) — see the `MitreCandidate`
docstring in `schemas/evidence.py` for the full mapped shape.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Callable, TypeVar

import httpx

import config
from schemas import Gap, MitreCandidate

logger = logging.getLogger(__name__)

SOURCE = "qdrant"
TOOL_NAME_MITRE = "retrieve_mitre"

MITRE_COLLECTION = "mitre_techniques"

# A lower threshold favors broader recall for MITRE technique matching.
MITRE_MIN_SIMILARITY = 0.5

T = TypeVar("T")


def _describe_error(exc: Exception, url: str) -> str:
    if isinstance(exc, httpx.HTTPStatusError):
        body = (exc.response.text or "")[:200].replace("\n", " ")
        return f"HTTP {exc.response.status_code} from {url}: {body}"
    if isinstance(exc, httpx.ConnectError):
        return f"Cannot connect to {url}: {exc}"
    if isinstance(exc, httpx.ReadTimeout):
        return f"Read timeout from {url}: {exc}"
    return f"{type(exc).__name__}: {exc}"


async def _embed(text: str, client: httpx.AsyncClient) -> list[float]:
    """POST config.EMBEDDING_API_URL/embed. Raises on transport/HTTP error or
    an unusable response — the caller converts that into a Gap."""
    response = await client.post(f"{config.EMBEDDING_API_URL}/embed", json={"text": text})
    response.raise_for_status()
    data = response.json()
    embedding = data.get("embedding")
    if not isinstance(embedding, list) or not embedding:
        raise ValueError(f"Embedding API returned no usable 'embedding' field: {str(data)[:200]}")
    return embedding


async def _search(
    collection: str,
    vector: list[float],
    *,
    top_k: int,
    score_threshold: float,
    client: httpx.AsyncClient,
) -> list[dict[str, Any]]:
    """POST config.QDRANT_URL/collections/{collection}/points/search. Raises
    on transport/HTTP error — the caller converts that into a Gap.
    `score_threshold` excludes low-similarity hits entirely — they are not
    returned with a low score, they are absent from the response."""
    body = {
        "vector": vector,
        "limit": top_k,
        "with_payload": True,
        "score_threshold": score_threshold,
    }
    response = await client.post(
        f"{config.QDRANT_URL}/collections/{collection}/points/search", json=body
    )
    response.raise_for_status()
    data = response.json()
    return data.get("result") or []


async def _fetch_hits(
    collection: str, query_text: str, top_k: int, score_threshold: float, timeout: float
) -> list[dict[str, Any]]:
    async with httpx.AsyncClient(timeout=timeout) as client:
        vector = await _embed(query_text, client)
        return await _search(
            collection, vector, top_k=top_k, score_threshold=score_threshold, client=client
        )


def _mitre_from_hit(hit: dict[str, Any]) -> MitreCandidate:
    payload = hit.get("payload") or {}
    return MitreCandidate(
        technique_id=payload.get("technique_id", ""),
        technique_name=payload.get("name", ""),
        tactic=payload.get("tactic") or [],
        platforms=payload.get("platforms") or [],
        is_sub_technique=bool(payload.get("is_sub_technique", False)),
        parent_technique_id=payload.get("parent_technique_id"),
        x_mitre_version=payload.get("x_mitre_version"),
        detection_strategy_id=payload.get("detection_strategy_id"),
        analytic_ids=payload.get("analytic_ids") or [],
        log_sources=payload.get("log_sources") or [],
        score=float(hit.get("score", 0.0)),
    )


async def _retrieve(
    *,
    collection: str,
    query_text: str,
    top_k: int,
    score_threshold: float,
    map_hit: Callable[[dict[str, Any]], T],
    tool: str,
    timeout: float | None,
) -> tuple[list[T], Gap | None]:
    """Shared NEVER-RAISES retrieval body. Returns `(hits, Gap | None)`:

    - hits found or genuinely none clear score_threshold -> `(list, None)` —
      an empty list with no Gap is a real, fully successful result, same
      convention as every other tool in this repo.
    - nothing to embed        -> `([], Gap)`, network never touched
    - embed/search/timeout failure -> `([], Gap)` with the transport reason
    """
    timeout = timeout if timeout is not None else config.STAGE_1_TOOL_TIMEOUT_QDRANT
    started = time.monotonic()

    def elapsed_ms() -> int:
        return int((time.monotonic() - started) * 1000)

    if not query_text or not query_text.strip():
        return [], Gap(
            source=SOURCE,
            tool=tool,
            reason="Empty query_text — nothing to embed or search",
            duration_ms=elapsed_ms(),
        )

    try:
        hits = await asyncio.wait_for(
            _fetch_hits(collection, query_text, top_k, score_threshold, timeout),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        logger.warning("%s timed out after %.1fs", tool, timeout)
        return [], Gap(
            source=SOURCE,
            tool=tool,
            reason=f"Timeout after {timeout}s embedding/searching {collection}",
            duration_ms=elapsed_ms(),
        )
    except Exception as exc:  # noqa: BLE001 — a tool must never raise into gather
        logger.warning("%s failed for %s: %s", tool, collection, exc)
        return [], Gap(
            source=SOURCE,
            tool=tool,
            reason=_describe_error(exc, config.QDRANT_URL),
            duration_ms=elapsed_ms(),
        )

    try:
        return [map_hit(h) for h in hits], None
    except Exception as exc:  # noqa: BLE001
        logger.warning("%s could not map hits for %s: %s", tool, collection, exc)
        return [], Gap(
            source=SOURCE,
            tool=tool,
            reason=f"Hit mapping failed: {type(exc).__name__}: {exc}",
            duration_ms=elapsed_ms(),
        )


async def retrieve_mitre(
    query_text: str, top_k: int = 5, timeout: float | None = None
) -> tuple[list[MitreCandidate], Gap | None]:
    """Always called. `query_text` should be the single most behaviorally
    specific observation from the evidence, NOT the full evidence package
    concatenated — a multi-behavior blob collapses recall on the technique
    that actually matters (see `stages/rag.py` for query construction).

    Never raises; see `_retrieve` for the `(result, Gap | None)` contract.
    """
    return await _retrieve(
        collection=MITRE_COLLECTION,
        query_text=query_text,
        top_k=top_k,
        score_threshold=MITRE_MIN_SIMILARITY,
        map_hit=_mitre_from_hit,
        tool=TOOL_NAME_MITRE,
        timeout=timeout,
    )
