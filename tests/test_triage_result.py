"""`TriageResult` — v5 redesign (`newdesign.md` §6). No more `PriorityScore`;
priority fields now come straight from `TriageVerdict` via
`main.py::_build_triage_result`, a thin, math-free assembly function that
replaces the deleted `nodes/score.py::priority_scoring` Stage 5 node.

**v6 redesign (2026-09-06)**: `_build_triage_result(verdict, evidence)` takes
ONE object now, not a `verdict`+`context` pair — the old `ContextualAssessment`
(`make_context()` helper) is gone, folded into `make_verdict()` below.
`stage_3_reasoning` is renamed `correlation_reasoning`.
"""

from __future__ import annotations

from datetime import datetime, timezone

from schemas import (
    CanonicalAlert,
    CorrelationDecision,
    CortexResult,
    EnrichedEvidence,
    EvidenceSituation,
    EvidenceSource,
    Host,
    IocObservable,
    RawEvidence,
    Rule,
    TriageResult,
    TriageVerdict,
    User,
)

import main


def make_alert() -> CanonicalAlert:
    return CanonicalAlert(
        alert_id="~1",
        timestamp=datetime.now(timezone.utc),
        rule=Rule(name="Test Rule", uuid="x"),
        host=Host(hostname="win-test"),
        user=User(name="tester"),
    )


def make_evidence() -> EnrichedEvidence:
    raw = RawEvidence(canonical_alert=make_alert())
    return EnrichedEvidence(**raw.model_dump())


def make_verdict(**overrides) -> TriageVerdict:
    """v6 (2026-09-06): correlation_decision/evidence_situation are required
    fields directly on TriageVerdict now — the old separate make_context()
    helper is folded in here."""
    defaults = dict(
        correlation_decision=CorrelationDecision(action="new", reasoning="correlation reasoning"),
        evidence_situation=EvidenceSituation(
            sources=[
                EvidenceSource(
                    source_name="rule_context", status="present", impact_on_triage="fine"
                )
            ],
            overall_evidence_reliability="medium",
            analyst_must_verify=["Verify asset criticality manually"],
        ),
        likelihood="likely",
        impact_if_true="significant",
        verdict="true_positive",
        reasoning="verdict reasoning",
        summary="verdict summary",
        recommended_action="create_case",
        priority_band="P2",
        priority_reasoning="P2 because confirmed malicious, no active spread",
        investigation_gaps=["Verify asset criticality manually"],
        safety_gate_applied=False,
    )
    defaults.update(overrides)
    return TriageVerdict(**defaults)


class TestTriageResultHasNoPriorityScore:
    def test_priority_field_does_not_exist(self):
        assert "priority" not in TriageResult.model_fields

    def test_priority_score_class_is_gone(self):
        import schemas

        assert not hasattr(schemas, "PriorityScore")


class TestTriageResultPriorityFieldsComeFromVerdict:
    def test_priority_band_and_reasoning(self):
        result = main._build_triage_result(make_verdict(), make_evidence(), None)
        assert result.priority_band == "P2"
        assert result.priority_reasoning == "P2 because confirmed malicious, no active spread"

    def test_investigation_gaps_comes_from_verdict(self):
        """v5 (newdesign.md §9): investigation_gaps sources from
        TriageVerdict.investigation_gaps. v6 (2026-09-06): there's no
        separate ContextualAssessment.additional_investigation_gaps to leak
        from any more — the old two-source distinction this test used to
        guard against no longer applies, since there's only one
        investigation_gaps field anywhere in the pipeline now."""
        verdict = make_verdict(investigation_gaps=["the real consolidated gap"])

        result = main._build_triage_result(verdict, make_evidence(), None)

        assert result.investigation_gaps == ["the real consolidated gap"]

    def test_safety_gate_applied_is_copied_through(self):
        result = main._build_triage_result(
            make_verdict(safety_gate_applied=True), make_evidence(), None
        )
        assert result.safety_gate_applied is True

    def test_evidence_situation_comes_from_verdict(self):
        result = main._build_triage_result(make_verdict(), make_evidence(), None)
        assert result.evidence_situation.overall_evidence_reliability == "medium"
        assert result.evidence_situation.analyst_must_verify == ["Verify asset criticality manually"]


class TestTriageResultBuilderIsPureNoMath:
    """The whole point of the v5 redesign — no scoring formula anywhere.
    Mutation guard: if a future change reintroduces a numeric priority
    field, this test's field-set assertion should be revisited deliberately,
    not silently pass."""

    def test_result_fields_are_all_traceable_to_verdict(self):
        verdict = make_verdict()
        result = main._build_triage_result(verdict, make_evidence(), None)

        assert result.verdict == verdict.verdict
        assert result.recommended_action == verdict.recommended_action
        assert result.summary == verdict.summary
        assert result.reasoning == verdict.reasoning
        assert result.likelihood == verdict.likelihood
        assert result.impact_if_true == verdict.impact_if_true
        assert result.correlation_reasoning == verdict.correlation_decision.reasoning
        assert result.refined_mitre_mapping == verdict.refined_mitre_mapping
        assert result.triage_assessment == verdict


class TestTriageResultV7Trim:
    """2026-09-07, user-directed: the response no longer carries the raw
    evidence dump or the flat Cortex list."""

    def test_gathered_evidence_field_is_gone(self):
        assert "gathered_evidence" not in TriageResult.model_fields

    def test_flat_threat_intel_field_is_gone(self):
        assert "threat_intel" not in TriageResult.model_fields

    def test_ioc_observables_field_exists(self):
        assert "ioc_observables" in TriageResult.model_fields

    def test_case_identity_fields_are_top_level(self):
        """2026-09-07, user-directed: the case id (new or merge target) sits
        next to alert_id, not only nested under case_action."""
        for f in ("case_id", "case_number", "is_new_case"):
            assert f in TriageResult.model_fields


def _evidence_with_cortex(*cortex: CortexResult) -> EnrichedEvidence:
    alert = make_alert()
    alert.cortex_results = list(cortex)
    raw = RawEvidence(canonical_alert=alert)
    return EnrichedEvidence(**raw.model_dump())


class TestIocObservables:
    """`main._build_ioc_observables` — only `ioc: true` observables, each
    joined to its Cortex analyzer rows by observable value. No OpenCTI."""

    HIVE_ALERT = {
        "observables": [
            {
                "_id": "~obs-hash",
                "dataType": "hash",
                "data": "8dd1ebb0deadbeef",
                "tags": ["sha256", "process:cmd.exe"],
                "ioc": True,
            },
            {
                "_id": "~obs-host",
                "dataType": "hostname",
                "data": "desktop-8f2igk2",
                "tags": [],
                "ioc": False,
            },
            {
                "_id": "~obs-ip",
                "dataType": "ip",
                "data": "203.0.113.9",
                "tags": ["field:destination.ip"],
                "ioc": True,
            },
        ]
    }

    def _build(self):
        vt = CortexResult(
            observable="8dd1ebb0deadbeef",
            type="hash",
            verdict=["malicious"],
            analyzer="VirusTotal_GetReport_3_1",
        )
        evidence = _evidence_with_cortex(vt)
        return main._build_triage_result(make_verdict(), evidence, self.HIVE_ALERT)

    def test_only_ioc_true_observables_are_surfaced(self):
        result = self._build()
        ids = {o.observable_id for o in result.ioc_observables}
        assert ids == {"~obs-hash", "~obs-ip"}  # the hostname (ioc: false) is dropped

    def test_observable_metadata_is_carried(self):
        result = self._build()
        by_id = {o.observable_id: o for o in result.ioc_observables}
        assert by_id["~obs-hash"].data_type == "hash"
        assert by_id["~obs-hash"].value == "8dd1ebb0deadbeef"
        assert by_id["~obs-hash"].tags == ["sha256", "process:cmd.exe"]

    def test_analyzer_results_joined_by_value(self):
        result = self._build()
        by_id = {o.observable_id: o for o in result.ioc_observables}
        assert [a.analyzer for a in by_id["~obs-hash"].analyzer_results] == [
            "VirusTotal_GetReport_3_1"
        ]
        # the ip is ioc: true but no analyzer ran against it
        assert by_id["~obs-ip"].analyzer_results == []

    def test_no_hive_alert_yields_empty_list(self):
        result = main._build_triage_result(make_verdict(), _evidence_with_cortex(), None)
        assert result.ioc_observables == []

    def test_mutation_ioc_filter(self):
        """If the `ioc is not True` guard were dropped, the hostname row
        would leak in — this asserts it doesn't."""
        result = self._build()
        assert all(o.data_type != "hostname" for o in result.ioc_observables)

    def test_mutation_value_join_key(self):
        """A Cortex row whose observable value matches nothing on the alert
        must not attach to an unrelated observable."""
        stray = CortexResult(observable="not-on-this-alert", analyzer="X")
        evidence = _evidence_with_cortex(stray)
        result = main._build_triage_result(make_verdict(), evidence, self.HIVE_ALERT)
        assert all(o.analyzer_results == [] for o in result.ioc_observables)
