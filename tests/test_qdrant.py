"""`retrieve_mitre` / `retrieve_playbooks` — Stage 2 RAG retrieval tools.
See `tools/qdrant.py`'s module docstring for the full live-verification
writeup (payload shape corrections vs. architecture §7's illustrative
example, the colocated embedding microservice).

`retrieve_cve` and `retrieve_incidents`, and every test section specific to
either (`TestCveProductFilter`; the CVE/incident cases in
`TestRealHits`/`TestHitMapping`), were REMOVED 2026-09-06, user-directed —
see `tools/qdrant.py`'s module docstring for both removal notes.
`tests/fixtures/qdrant_real.json` is left as-is (its `cve_context`/
`incident_history` keys are simply no longer read) since the fixture still
covers the two remaining collections' real shapes.

PROVENANCE: `tests/fixtures/qdrant_real.json` is REAL, captured live from
Qdrant at `172.20.24.224:6333` (via `172.20.24.224:8001`'s embedding
microservice) on 2026-08-16 — one real `/points/search` response per
collection (`mitre_techniques`, `soc_playbooks`), verbatim, `with_payload:
true`. The tool itself was called live against the real backend, and its
output field-by-field inspected against `MitreCandidate`/`PlaybookMatch`,
before any of these tests were written (implementation guide §2).
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest

from tools import qdrant as qdrant_mod
from tools.qdrant import (
    retrieve_mitre,
    retrieve_playbooks,
)

FIXTURE = Path(__file__).parent / "fixtures" / "qdrant_real.json"


@pytest.fixture(scope="module")
def real() -> dict:
    """REAL — captured live from Qdrant on 2026-08-16, one collection each."""
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
    """Each retrieve_* function correctly maps ITS collection's real payload
    shape — proving the corrected schemas in schemas/evidence.py, not the
    architecture §7 illustrative example."""

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

    def test_playbooks_maps_real_payload_including_runbook_id_rename(self, monkeypatch, real):
        """The schema field is `playbook_id`; the real payload key is
        `runbook_id` — this is the rename the mapping function exists to do."""
        patch_fetch_hits(monkeypatch, hits=real["soc_playbooks"])
        results, gap = run(retrieve_playbooks("phishing attachment"))
        assert gap is None
        top = results[0]
        assert top.playbook_id == real["soc_playbooks"][0]["payload"]["runbook_id"]
        assert top.document_text == real["soc_playbooks"][0]["payload"]["document_text"]

    def test_multiple_sections_of_same_runbook_are_not_deduped(self, monkeypatch, real):
        """Architecture §7: multiple sections from one runbook co-occurring in
        a result set is expected behavior, not a bug to filter out."""
        hits = real["soc_playbooks"]
        patch_fetch_hits(monkeypatch, hits=hits)
        results, _ = run(retrieve_playbooks("phishing attachment", top_k=len(hits)))
        assert len(results) == len(hits)

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
        results, gap = run(retrieve_playbooks("   "))
        assert results == []
        assert capture == {}

    def test_mitre_uses_its_own_lower_similarity_threshold(self, monkeypatch):
        capture: dict = {}
        patch_fetch_hits(monkeypatch, hits=[], capture=capture)
        run(retrieve_mitre("query"))
        assert capture["score_threshold"] == qdrant_mod.MITRE_MIN_SIMILARITY
        assert capture["score_threshold"] < qdrant_mod.PLAYBOOK_MIN_SIMILARITY

    def test_no_results_above_threshold_is_not_a_gap(self, monkeypatch):
        """Architecture §7 semantics, matching every other Stage 1/2 tool:
        genuinely nothing cleared score_threshold is a real, successful
        empty result, not a failure."""
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
        results, gap = run(retrieve_playbooks("query"))
        assert results == []
        assert "embedding" in gap.reason.lower()

    def test_hit_mapping_failure_is_a_gap_not_a_crash(self, monkeypatch):
        """A structurally malformed hit (payload isn't even a dict) must not
        raise AttributeError up through gather — it becomes a Gap. A merely
        incomplete payload is NOT this case: every _*_from_hit getter has a
        safe default, so missing keys alone never raise (see TestHitMapping's
        `test_mitre_from_hit_defaults_missing_optional_fields`)."""
        patch_fetch_hits(monkeypatch, hits=[{"score": 0.9, "payload": "not-a-dict"}])
        results, gap = run(retrieve_mitre("query"))
        assert results == []
        assert "mapping failed" in gap.reason.lower()


class TestHitMapping:
    """Direct unit tests of the two _*_from_hit mapping functions — no
    network, no mocking."""

    def test_mitre_from_hit_defaults_missing_optional_fields(self):
        from tools.qdrant import _mitre_from_hit

        candidate = _mitre_from_hit({"score": 0.7, "payload": {"technique_id": "T9999"}})
        assert candidate.technique_id == "T9999"
        assert candidate.technique_name == ""
        assert candidate.tactic == []
        assert candidate.is_sub_technique is False
        assert candidate.score == 0.7

    def test_playbook_from_hit_maps_runbook_id_to_playbook_id(self):
        from tools.qdrant import _playbook_from_hit

        match = _playbook_from_hit(
            {"score": 0.6, "payload": {"runbook_id": "phishing-response", "section": "Detection"}}
        )
        assert match.playbook_id == "phishing-response"
        assert match.section == "Detection"
