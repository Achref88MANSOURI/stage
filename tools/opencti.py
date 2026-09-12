"""Queries OpenCTI's GraphQL API directly for an observable's threat-graph
context: is it a known indicator, and what is it related to (malware,
intrusion-set, threat-actor, campaign, via `stixCoreRelationships`).

This is separate from the OpenCTI Cortex analyzer, whose taxonomy rows
already arrive through `tools/thehive.py::get_full_alert_with_analysis` and
are structured into `CortexResult` alongside VirusTotal's — that path
answers "did the SOC's Cortex pipeline flag this" from a pre-run analyzer
job. This tool answers a different question, "what does OpenCTI's graph say
this observable relates to", via a live query, and the two are complementary
rather than redundant.

The GraphQL filter batches every observable value into one `stixCyberObservables`
query with an `OR` filter group; values with no record in OpenCTI simply
don't appear in the response and are reported as `found=False` rather than
as an error.

`stixCoreRelationships.to` uses inline fragments (`... on Malware { ... }`)
since `to` is a STIX-core union type. When the relationship target doesn't
match any of the fragments here (e.g. it's another Indicator, not a
Malware/IntrusionSet/ThreatActor/Campaign), it resolves to `{}`, which is
treated as "no attributable entity" rather than an error.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import httpx

import config
from schemas import Gap, Observables, OpenCTIEnrichment, OpenCTIRelation

logger = logging.getLogger(__name__)

SOURCE = "opencti"
TOOL_NAME = "opencti_observable_enrichment"

# A very long value list makes the query slower and risks a request-size
# rejection.
MAX_ENTITY_VALUES = 50
MAX_RELATIONS_PER_OBSERVABLE = 10


def _flatten_observable_values(observables: Observables | None) -> list[str]:
    """Flatten the alert's IOCs (external IPs, domains, URLs, every hash
    algorithm) into one de-duplicated, order-preserving, capped list of
    match values for the GraphQL filter below."""
    values: list[str] = []
    if observables is not None:
        values.extend(observables.external_ips)
        values.extend(observables.domains)
        values.extend(observables.urls)
        hashes = observables.hashes
        values.extend(hashes.md5)
        values.extend(hashes.sha1)
        values.extend(hashes.sha256)
        values.extend(hashes.sha512)
        values.extend(hashes.imphash)

    seen: set[str] = set()
    unique = [v for v in values if v and not (v in seen or seen.add(v))]
    return unique[:MAX_ENTITY_VALUES]

_QUERY = """
query Enrich($filters: FilterGroup) {
  stixCyberObservables(filters: $filters, first: %d) {
    edges { node {
      observable_value
      entity_type
      x_opencti_score
      objectLabel { value }
      objectMarking { definition }
      indicators { edges { node { name } } }
      stixCoreRelationships(first: %d) { edges { node {
        relationship_type
        to {
          ... on Malware { name entity_type }
          ... on IntrusionSet { name entity_type }
          ... on ThreatActor { name entity_type }
          ... on Campaign { name entity_type }
        }
      } } }
    } }
  }
}
""" % (MAX_ENTITY_VALUES, MAX_RELATIONS_PER_OBSERVABLE)


def _describe_error(exc: Exception) -> str:
    if isinstance(exc, httpx.HTTPStatusError):
        body = (exc.response.text or "")[:250].replace("\n", " ")
        return f"HTTP {exc.response.status_code} from OpenCTI: {body}"
    if isinstance(exc, httpx.ConnectError):
        return f"Cannot connect to OpenCTI at {config.OPENCTI_URL}: {exc}"
    if isinstance(exc, httpx.ReadTimeout):
        return f"OpenCTI read timeout: {exc}"
    return f"{type(exc).__name__}: {exc}"


def _node_to_enrichment(node: dict) -> OpenCTIEnrichment:
    relations = []
    for edge in (node.get("stixCoreRelationships") or {}).get("edges", []) or []:
        rel = edge.get("node") or {}
        to = rel.get("to") or {}
        if not to:
            # An empty `to` means the relationship target didn't match any of
            # the inline fragments above (e.g. it's another Indicator) — real
            # data, not a Gap; the relationship exists, just not to an
            # attributable entity this tool cares about.
            continue
        relations.append(OpenCTIRelation(
            relationship_type=rel.get("relationship_type") or "",
            related_entity_type=to.get("entity_type"),
            related_entity_name=to.get("name"),
        ))
    return OpenCTIEnrichment(
        observable=node.get("observable_value") or "",
        found=True,
        entity_type=node.get("entity_type"),
        indicator_names=[
            e["node"]["name"]
            for e in (node.get("indicators") or {}).get("edges", []) or []
            if e.get("node", {}).get("name")
        ],
        opencti_score=node.get("x_opencti_score"),
        labels=[
            e["value"] for e in node.get("objectLabel") or [] if e.get("value")
        ],
        marking=[
            e["definition"] for e in node.get("objectMarking") or [] if e.get("definition")
        ],
        relations=relations,
    )


async def _query(filters: dict, timeout: float) -> Any:
    """POST to OpenCTI's GraphQL endpoint. Raises on transport or HTTP error,
    or on a GraphQL-level error (200 status, `errors` key set — e.g. the
    AUTH_REQUIRED shape a bad token returns)."""
    headers = {
        "Authorization": f"Bearer {config.OPENCTI_TOKEN}",
        "Content-Type": "application/json",
    }
    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.post(
            f"{config.OPENCTI_URL}/graphql",
            headers=headers,
            json={"query": _QUERY, "variables": {"filters": filters}},
        )
        response.raise_for_status()
        payload = response.json()
    if payload.get("errors"):
        messages = "; ".join(
            e.get("message", "unknown error") for e in payload["errors"][:3]
        )
        raise httpx.HTTPStatusError(
            f"GraphQL error: {messages}",
            request=response.request,
            response=response,
        )
    return payload.get("data", {}).get("stixCyberObservables", {}).get("edges", []) or []


async def opencti_observable_enrichment(
    observables: Observables | None, timeout: float | None = None
) -> tuple[list[OpenCTIEnrichment], Gap | None]:
    """Looks up every IOC on the alert against OpenCTI's threat graph in one
    batched query. Never raises.

    Returns `(enrichments, Gap | None)`, one entry per queried value:
    `found=True` when OpenCTI has a record of it, `found=False` when it was
    checked and doesn't — both are real answers, not gaps. A Gap means the
    query itself couldn't be run at all.
    """
    timeout = timeout if timeout is not None else config.STAGE_1_TOOL_TIMEOUT_OPENCTI
    started = time.monotonic()

    def gap(reason: str) -> Gap:
        return Gap(
            source=SOURCE,
            tool=TOOL_NAME,
            reason=reason,
            duration_ms=int((time.monotonic() - started) * 1000),
        )

    values = _flatten_observable_values(observables)
    if not values:
        return [], gap("Alert carried no observables to check against OpenCTI")

    filters = {"mode": "or", "filters": [{"key": "value", "values": values}], "filterGroups": []}

    try:
        edges = await asyncio.wait_for(_query(filters, timeout), timeout=timeout)
    except asyncio.TimeoutError:
        return [], gap(f"Timeout after {timeout}s querying OpenCTI")
    except Exception as exc:  # noqa: BLE001 — a tool must never raise into gather
        logger.warning("opencti_observable_enrichment failed: %s", exc)
        return [], gap(_describe_error(exc))

    found_by_value = {}
    for edge in edges:
        node = edge.get("node") if isinstance(edge, dict) else None
        if not isinstance(node, dict) or not node.get("observable_value"):
            continue
        found_by_value[node["observable_value"]] = _node_to_enrichment(node)

    results = [
        found_by_value.get(v) or OpenCTIEnrichment(observable=v, found=False)
        for v in values
    ]
    return results, None
