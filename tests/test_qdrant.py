"""Tests for `retrieve_mitre`, the RAG retrieval tool. See
`tools/qdrant.py`'s module docstring for the tool's own contract (payload
shape, the colocated embedding microservice).

`tests/fixtures/qdrant_real.json` was captured from a live Qdrant
`/points/search` response for the `mitre_techniques` collection.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest

from tools import qdrant as qdrant_mod
from tools.qdrant import retrieve_mitre

FIXTURE = Path(__file__).parent / "fixtures" / "qdrant_real.json"


@pytest.fixture(scope="module")
def real() -> dict:
    """Captured live from Qdrant."""
    return json.loads(FIXTURE.read_text())


def patch_fetch_hits(monkeypatch, hits=None, exc=None, capture=None):
    async def fake_fetch_hits(collection, query_text, top_k, score_threshold, timeout):
        if capture is not None:
            capture["collection"] = collection
            capture["query_text"] = query_text
            capture["top_k"] = top_k
            capture["score_threshold"] = score_threshold
        if exc is not None:
            raise exc
        return hits or []

    monkeypatch.setattr(qdrant_mod, "_fetch_hits", fake_fetch_hits)


def run(coro):
    return asyncio.run(coro)


class TestRealHits:
    """`retrieve_mitre` correctly maps the real Qdrant payload shape into
    `MitreCandidate` (`schemas/evidence.py`)."""

    def test_mitre_maps_real_payload(self, monkeypatch, real):
        patch_fetch_hits(monkeypatch, hits=real["mitre_techniques"])
        results, gap = run(retrieve_mitre("PowerShell download and execute"))
        assert gap is None
        assert len(results) == len(real["mitre_techniques"])
        top = results[0]
        assert top.technique_id == real["mitre_techniques"][0]["payload"]["technique_id"]
        assert top.technique_name == real["mitre_techniques"][0]["payload"]["name"]
        assert isinstance(top.tactic, list)
        assert top.score == real["mitre_techniques"][0]["score"]


class TestQueryConstruction:
    def test_empty_query_text_gaps_without_calling_out(self, monkeypatch):
        capture: dict = {}
        patch_fetch_hits(monkeypatch, hits=[], capture=capture)
        results, gap = run(retrieve_mitre(""))
        assert results == []
        assert "empty" in gap.reason.lower()
        assert capture == {}

    def test_whitespace_only_query_text_gaps(self, monkeypatch):
        capture: dict = {}
        patch_fetch_hits(monkeypatch, hits=[], capture=capture)
        results, gap = run(retrieve_mitre("   "))
        assert results == []
        assert capture == {}

    def test_no_results_above_threshold_is_not_a_gap(self, monkeypatch):
        """Nothing clearing score_threshold is a successful empty result,
        not a failure — the same convention every other tool follows."""
        patch_fetch_hits(monkeypatch, hits=[])
        results, gap = run(retrieve_mitre("query with no good matches"))
        assert results == []
        assert gap is None


class TestFailureModes:
    def test_timeout_is_a_gap(self, monkeypatch):
        async def slow_fetch(collection, query_text, top_k, score_threshold, timeout):
            await asyncio.sleep(10)

        monkeypatch.setattr(qdrant_mod, "_fetch_hits", slow_fetch)
        results, gap = run(retrieve_mitre("query", timeout=0.01))
        assert results == []
        assert "timeout" in gap.reason.lower()

    def test_qdrant_connection_error_is_a_gap(self, monkeypatch):
        patch_fetch_hits(monkeypatch, exc=httpx.ConnectError("refused"))
        results, gap = run(retrieve_mitre("query"))
        assert results == []
        assert "cannot connect" in gap.reason.lower()

    def test_embedding_api_bad_response_is_a_gap_not_a_crash(self, monkeypatch):
        """The real failure shape if the embedding microservice returns a
        malformed body — see tools/qdrant.py::_embed's explicit check, which
        raises exactly this ValueError."""
        patch_fetch_hits(
            monkeypatch,
            exc=ValueError("Embedding API returned no usable 'embedding' field: {}"),
        )
        results, gap = run(retrieve_mitre("query"))
        assert results == []
        assert "embedding" in gap.reason.lower()

    def test_hit_mapping_failure_is_a_gap_not_a_crash(self, monkeypatch):
        """A structurally malformed hit (payload isn't even a dict) should
        become a Gap rather than raising. A merely incomplete payload is a
        different case — every _*_from_hit getter has a safe default for
        missing keys (see TestHitMapping below)."""
        patch_fetch_hits(monkeypatch, hits=[{"score": 0.9, "payload": "not-a-dict"}])
        results, gap = run(retrieve_mitre("query"))
        assert results == []
        assert "mapping failed" in gap.reason.lower()


class TestHitMapping:
    """Direct unit test of `_mitre_from_hit` — no network, no mocking."""

    def test_mitre_from_hit_defaults_missing_optional_fields(self):
        from tools.qdrant import _mitre_from_hit

        candidate = _mitre_from_hit({"score": 0.7, "payload": {"technique_id": "T9999"}})
        assert candidate.technique_id == "T9999"
        assert candidate.technique_name == ""
        assert candidate.tactic == []
        assert candidate.is_sub_technique is False
        assert candidate.score == 0.7
