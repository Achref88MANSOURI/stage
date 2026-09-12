"""Tests for `alert_builder.build_canonical_alert`.

`TestRealSigmaProcessAlert` runs against a real captured Security Onion
alert covering the `endpoint.events.process` dataset shape, which accounts
for most of this deployment's alert volume. Every other test class runs
against synthetic fixtures built from documented field mappings — these
confirm the extractors map the expected paths without crashing, but don't
prove what Security Onion actually emits for those shapes, since no real
example has been captured yet.

`CanonicalAlert` has no typed field for process, network, or user detail —
none of it is structurally extracted. That detail reaches the single LLM
call directly through `CanonicalAlert.raw_alert` (the webhook body carried
verbatim) instead. See `schemas/alert.py` and `TestRawAlertPassthrough`
below.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from alert_builder import build_canonical_alert
from schemas import CanonicalAlert
from tests.fixtures.synthetic_alerts import (
    SYSMON_WINLOG_ALERT,
    YARA_STRELKA_ALERT,
)


def build(raw, hive_alert=None, alert_id="") -> CanonicalAlert:
    return build_canonical_alert(
        raw_alert=raw,
        hive_alert=hive_alert,
        thehive_alert_id=alert_id,
    )


# ===========================================================================
# REAL captured alert — endpoint.events.process ONLY
# ===========================================================================
class TestRealSigmaProcessAlert:
    """Runs against a real captured Sigma alert covering
    `endpoint.events.process` (xordump.exe Invoke-WebRequest on
    win-kvkmd51ggkq), from sigma-alert-sample.json. Covers this one
    dataset shape only.
    """

    def test_identity_and_profile(self, real_sigma_process_alert):
        alert = build(real_sigma_process_alert, alert_id="~1190993992")
        assert alert.alert_id == "~1190993992"
        assert alert.source_engine == "sigma"
        assert alert.investigation_profile == "endpoint_behavior"
        assert alert.event_dataset == "endpoint.events.process"

    def test_alert_id_falls_back_to_document_id(self, real_sigma_process_alert):
        alert = build(real_sigma_process_alert)
        assert alert.alert_id == "6qS9fp8BiUkBvoTNPeON"

    def test_rule_uses_structured_top_level_dict(self, real_sigma_process_alert):
        """Sigma alerts carry a top-level `rule` dict. If this ever falls
        through to the description regex instead, uuid comes back empty and
        detection_rule_lookup and get_fp_signal both lose their join key."""
        rule = build(real_sigma_process_alert).rule
        assert rule.uuid == "5e3cc4d8-3e68-43db-8656-eaaeefdec9cc"
        assert rule.name == "Suspicious Invoke-WebRequest Execution"
        assert rule.product == "windows"
        assert rule.category == "process_creation"
        assert rule.level == "high"
        assert rule.native_severity == 4

    def test_host(self, real_sigma_process_alert):
        host = build(real_sigma_process_alert).host
        assert host.hostname == "win-kvkmd51ggkq"
        assert host.host_id == "c8fc26bf-dc76-4dba-adbb-bf31640d9c9f"
        assert host.os.type == "windows"

    def test_host_ip_recovered_from_beats_metadata(self, real_sigma_process_alert):
        """event_data.host.ip is absent on this real alert; the agent
        address is only at event_data.metadata.input.beats.host.ip. Without
        this fallback the host IP would be lost for this shape."""
        assert build(real_sigma_process_alert).host.ip == ["172.20.24.99"]

    def test_process_hashes_no_longer_reach_observables_without_thehive(
        self, real_sigma_process_alert
    ):
        """Process hashes in raw_alert (event_data.process.hash.*/pe.imphash)
        are not extracted into observables. Without a hive_alert,
        observables.hashes must be empty."""
        hashes = build(real_sigma_process_alert).observables.hashes
        assert hashes.is_empty()

    def test_no_iocs_without_thehive(self, real_sigma_process_alert):
        """The raw Sigma alert carries no IOCs of its own. IOC extraction is
        n8n's job, not this module's — the xordump URL in the command line
        is still visible to the LLM via `raw_alert`, but must never be
        promoted to a typed observable field here."""
        observables = build(real_sigma_process_alert).observables
        assert observables.urls == []
        assert observables.domains == []
        assert observables.external_ips == []

    def test_alert_and_event_timestamps_both_captured_and_differ(
        self, real_sigma_process_alert
    ):
        """The alert timestamp and the underlying event timestamp are ~2
        days apart in this sample, and are carried as separate fields
        rather than collapsed into one, so a consumer computing evidence
        age can choose which one it means."""
        alert = build(real_sigma_process_alert)
        assert alert.timestamp.isoformat().startswith("2026-07-22T08:55:59")
        assert alert.event_timestamp.isoformat().startswith("2026-07-20T08:52:32")
        assert (alert.timestamp - alert.event_timestamp).total_seconds() > 24 * 3600

    def test_thehive_observables_and_cortex_reports(self, real_sigma_process_alert):
        """The IOC path that DOES exist: hive_alert.observables, with Cortex
        reports already attached."""
        hive_alert = {
            "observables": [
                {
                    "_id": "~obs1",
                    "dataType": "url",
                    "data": "https://github.com/audibleblink/xordump/releases/download/v0.0.1/xordump.exe",
                    "reports": {
                        "VirusTotal_GetReport_3_1": {
                            "summary": {
                                "taxonomies": [
                                    {
                                        "level": "suspicious",
                                        "namespace": "VT",
                                        "predicate": "GetReport",
                                        "value": "3/70",
                                    }
                                ]
                            }
                        }
                    },
                },
                {"_id": "~obs2", "dataType": "ip", "data": "140.82.121.4", "reports": {}},
            ]
        }
        alert = build(real_sigma_process_alert, hive_alert=hive_alert)
        assert alert.observables.urls == [
            "https://github.com/audibleblink/xordump/releases/download/v0.0.1/xordump.exe"
        ]
        assert alert.observables.external_ips == ["140.82.121.4"]
        assert len(alert.cortex_results) == 1
        assert alert.cortex_results[0].verdict == ["suspicious"]
        assert alert.cortex_results[0].analyzer == "VirusTotal_GetReport_3_1"
        assert alert.thehive_observable_ids["140.82.121.4"] == "~obs2"

    def test_url_wins_over_mislabelled_datatype(self, real_sigma_process_alert):
        """n8n's Alert Builder is known to stamp URLs with the wrong dataType.
        A value starting with http(s):// is a URL regardless."""
        hive_alert = {
            "observables": [
                {"_id": "~x", "dataType": "fqdn", "data": "https://evil.example/pay.exe"}
            ]
        }
        alert = build(real_sigma_process_alert, hive_alert=hive_alert)
        assert alert.observables.urls == ["https://evil.example/pay.exe"]
        assert alert.observables.domains == []


class TestRealProductionEsDocument:
    """An untouched production Security Onion alert document, pulled
    directly from the live alerts index rather than a webhook capture.
    Same rule as the webhook sample, a different alert instance.
    """

    def test_parses_from_the_raw_index_document(self, real_es_alert_source):
        alert = build(real_es_alert_source, alert_id="~prod")
        assert alert.source_engine == "sigma"
        assert alert.investigation_profile == "endpoint_behavior"
        assert alert.event_dataset == "endpoint.events.process"
        assert alert.rule.uuid == "5e3cc4d8-3e68-43db-8656-eaaeefdec9cc"
        assert alert.host.hostname == "win-kvkmd51ggkq"

    def test_ioc_present_in_real_production_data_and_still_ignored(
        self, real_es_alert_source
    ):
        """An ingest add-on in this deployment stamps `ioc.*` onto real
        alerts, so this production document genuinely contains it.
        `ioc.source_engine` is itself derived from `event.module`, so it
        can never independently corroborate it — engine detection must
        read `event.module` directly instead.
        """
        assert "ioc" in real_es_alert_source
        assert real_es_alert_source["ioc"]["source_engine"] == "sigma"
        alert = build(real_es_alert_source)
        # Same answer, but reached from event.module — verify by contradicting
        # the ioc block and confirming the result does not move.
        contradicted = dict(real_es_alert_source)
        contradicted["ioc"] = {**contradicted["ioc"], "source_engine": "suricata"}
        assert build(contradicted).source_engine == alert.source_engine == "sigma"

    def test_no_iocs_reach_observables_from_production_document(
        self, real_es_alert_source
    ):
        """Hashes are never extracted from raw_alert into observables — with
        no hive_alert given, observables.hashes must be empty here."""
        observables = build(real_es_alert_source).observables
        assert observables.urls == []
        assert observables.domains == []
        assert observables.external_ips == []
        assert observables.hashes.is_empty()


# ===========================================================================
# SYNTHETIC — every shape below is unvalidated against real data
# ===========================================================================
class TestSyntheticWinlogShapes:
    """Synthetic fixture covering the native Windows Event Log (winlog)
    telemetry shape."""

    def test_sysmon_winlog(self):
        """Confirms host identity and event_dataset resolve correctly for
        the winlog shape (_extract_winlog_host), distinct from the
        Elastic-Defend/Sysmon-via-elastic-agent shape
        _extract_host_from_event_data handles."""
        alert = build(SYSMON_WINLOG_ALERT)
        assert alert.host.hostname == "win-kvkmd51ggkq"
        assert alert.event_dataset == "windows.sysmon_operational"


# ===========================================================================
# REAL captured Suricata alert — network_threat profile
# ===========================================================================
class TestRealSuricataPath:
    """Runs against a real captured suricata.alert document
    ("GPL ATTACK_RESPONSE id check returned root", SID 2100498, from
    tests/fixtures/suricata-alert-real.json — see conftest.py for why this
    alert has never actually reached `/triage`). Covers the network_threat
    profile only, same discipline as `TestRealSigmaProcessAlert` above.
    """

    def test_identity_and_profile(self, real_suricata_alert_source):
        alert = build(real_suricata_alert_source)
        assert alert.source_engine == "suricata"
        assert alert.investigation_profile == "network_threat"

    def test_event_dataset_from_top_level_fallback(self, real_suricata_alert_source):
        """Suricata alerts have no event_data, so event_dataset must fall
        back to the top-level raw_alert.event.dataset rather than coming
        back None just because the Sigma-shaped nested path is absent."""
        alert = build(real_suricata_alert_source)
        assert alert.event_dataset == "suricata.alert"

    def test_rule_identity(self, real_suricata_alert_source):
        alert = build(real_suricata_alert_source)
        assert alert.rule.uuid == "2100498"
        assert alert.rule.name == "GPL ATTACK_RESPONSE id check returned root"

    def test_no_endpoint_context(self, real_suricata_alert_source):
        """No host fields exist anywhere on a Suricata document."""
        alert = build(real_suricata_alert_source)
        assert alert.host is None


class TestRuleIdentityRegressionGuards:
    """`_parse_rule`'s collision guard: Sysmon's own internal RuleName config
    tag lives at the same-looking path as the real fired Sigma rule name and
    must not be confused with it."""

    def test_rule_identity_not_confused_with_sysmon_internal_rule_name(
        self, real_sysmon_registry_alert_source
    ):
        """event_data.rule.name on this alert is "T1183,IFEO" (Sysmon's own
        internal RuleName tag), completely different from the actually
        fired Sigma rule name — confirms _parse_rule picks the right one."""
        raw = real_sysmon_registry_alert_source
        assert raw["event_data"]["rule"]["name"] == "T1183,IFEO"
        alert = build(raw)
        assert alert.rule.name == "Potential Persistence Via GlobalFlags"
        assert alert.rule.uuid == "36803969-5421-41ec-b92f-8500f79c23b0"


class TestSyntheticYaraPath:
    # Tested against a synthetic fixture only; no live YARA alert has been
    # captured to validate against yet. YARA_STRELKA_ALERT's file/hash/scan
    # content reaches the LLM through raw_alert verbatim (see
    # TestRawAlertPassthrough) rather than a separately extracted field.
    def test_malicious_file_profile_and_top_level_hashes(self):
        alert = build(YARA_STRELKA_ALERT)
        # event.module is "strelka" for Security Onion's file-extraction
        # path; PROFILE_BY_ENGINE maps both "strelka" and "yara" spellings
        # to malicious_file.
        assert alert.source_engine == "strelka"
        assert alert.investigation_profile == "malicious_file"
        # No hive_alert given — process/file hashes are not extracted from
        # raw_alert into observables (see TestRealSigmaProcessAlert's
        # equivalent guard above).
        assert alert.observables.hashes.is_empty()

    def test_rule_uuid_equals_rule_name_for_yara(self):
        """Security Onion's strelka.file pipeline sets rule.uuid = rule.name —
        there is no separate YARA rule ID."""
        rule = build(YARA_STRELKA_ALERT).rule
        assert rule.uuid == rule.name == "MALWARE_Win_Generic"


# ===========================================================================
# raw_alert passthrough
# ===========================================================================
class TestRawAlertPassthrough:
    """`CanonicalAlert.raw_alert` carries the original webhook body verbatim
    so the single LLM call (`stages/triage.py`, via
    `prompts/triage_agent.py::build_user_prompt`) can read process/file/
    registry/etc. detail directly, without needing a dedicated typed field
    for each. See schemas/alert.py::CanonicalAlert's docstring."""

    def test_raw_alert_carried_verbatim_for_real_sigma_alert(
        self, real_sigma_process_alert
    ):
        alert = build(real_sigma_process_alert)
        assert alert.raw_alert == real_sigma_process_alert
        # Confirms detail not structurally extracted into a typed field (the
        # full event_data.process object, not just command_line) is still
        # reachable from raw_alert.
        assert (
            alert.raw_alert["event_data"]["process"]["pid"]
            == 8524
        )

    def test_raw_alert_carried_verbatim_for_real_suricata_alert(
        self, real_suricata_alert_source
    ):
        alert = build(real_suricata_alert_source)
        assert alert.raw_alert == real_suricata_alert_source

    def test_raw_alert_defaults_to_empty_dict_for_empty_input(self):
        alert = build({})
        assert alert.raw_alert == {}


# ===========================================================================
# Degradation — the invariant that must hold for EVERY shape, known or not
# ===========================================================================
class TestDegradesRatherThanRaises:
    """Presence-guarded extraction is the load-bearing property of this module:
    an unrecognised shape must produce a sparse CanonicalAlert, never an
    exception. Stage 0 returning 500 on an unfamiliar alert would take the
    pipeline down for a shape nobody anticipated."""

    def test_empty_alert(self):
        alert = build({})
        assert alert.rule.name == "unknown"
        assert alert.host is None
        assert alert.observables.hashes.is_empty()

    def test_alert_with_only_event_data_scaffolding(self):
        alert = build({"event_data": {}})
        assert isinstance(alert, CanonicalAlert)
        assert alert.event_dataset is None

    def test_wrong_types_do_not_raise(self):
        """n8n's envelope carries a top-level `source` STRING (the source
        system) which collides with Suricata's ECS `source` OBJECT. Every
        nested read goes through _as_dict for exactly this reason."""
        alert = build(
            {
                "source": "security-onion",
                "rule": "not-a-dict",
                "event": None,
                "event_data": {"host": "nope"},
                "ioc": "string-not-dict",
                "tags": None,
            }
        )
        assert isinstance(alert, CanonicalAlert)
        assert alert.host is None

    def test_scalar_where_array_expected(self):
        """ECS array-typed fields are routinely emitted as bare scalars when
        there is exactly one value."""
        alert = build(
            {
                "rule": {"name": "x", "uuid": "u"},
                "event_data": {
                    "host": {"name": "h", "ip": "10.0.0.1", "mac": "00:11:22:33:44:55"},
                },
            }
        )
        assert alert.host.ip == ["10.0.0.1"]
        assert alert.host.mac == ["00:11:22:33:44:55"]

    def test_unknown_engine_falls_back_to_generic_profile(self):
        alert = build({"event": {"module": "some-future-engine"}})
        assert alert.source_engine == "some-future-engine"
        assert alert.investigation_profile == "generic"

    def test_source_engine_falls_back_to_event_dataset_prefix(self):
        """event.dataset is the second confirmed path from the real alerter
        source (securityonion-es.py writes event.severity/module/dataset)."""
        alert = build({"event": {"dataset": "suricata.alert"}})
        assert alert.source_engine == "suricata"
        assert alert.investigation_profile == "network_threat"

    def test_ioc_field_is_ignored_entirely(self):
        """`ioc.*` is not a native Security Onion field — a custom ingest
        add-on sets `ioc.source_engine = ctx.event.module`, derived from
        event.module, so it can never independently corroborate it. This
        guards against reintroducing a dependency on `ioc.*`."""
        alert = build(
            {
                "ioc": {
                    "source_engine": "suricata",
                    "rule": {"severity": "critical", "uuid": "ioc-uuid", "name": "ioc-name"},
                    "indicators": [
                        {"type": "ip", "value": "1.2.3.4"},
                        {"type": "url", "value": "https://evil.example/x"},
                        {"type": "hash_sha256", "value": "c" * 64},
                    ],
                },
                "event": {"module": "sigma"},
                "rule": {"name": "real-name", "uuid": "real-uuid"},
            }
        )
        # engine comes from event.module, never from ioc.source_engine
        assert alert.source_engine == "sigma"
        assert alert.investigation_profile == "endpoint_behavior"
        # rule identity comes from the top-level rule dict, never from ioc.rule
        assert alert.rule.uuid == "real-uuid"
        assert alert.rule.name == "real-name"
        assert alert.rule.level is None
        # ioc.indicators must NOT reach observables — IOCs come from TheHive only
        assert alert.observables.external_ips == []
        assert alert.observables.urls == []
        assert alert.observables.hashes.is_empty()

    def test_missing_timestamp_defaults_to_now_but_event_timestamp_stays_none(self):
        """"Unknown" must stay distinguishable from "just happened" for the
        event timestamp, since downstream reasoning may use it to judge
        evidence age."""
        alert = build({})
        assert alert.timestamp is not None
        assert alert.event_timestamp is None

    def test_hive_alert_none_is_safe(self):
        alert = build({"rule": {"name": "x"}}, hive_alert=None)
        assert alert.cortex_results == []
        assert alert.thehive_observable_ids == {}

    def test_malformed_observables_are_skipped_not_fatal(self):
        alert = build(
            {"rule": {"name": "x"}},
            hive_alert={"observables": [{"dataType": "ip"}, {"data": ""}, {}]},
        )
        assert alert.observables.external_ips == []


# ===========================================================================
# Cortex taxonomies -> verdict.
# ===========================================================================
@pytest.fixture(scope="module")
def hive_alert() -> dict:
    """The 4 real observables of alert ~4661456, fetched via the stock
    `getAlert -> observables -> page` projection (tools/thehive.py) — the
    richest of the alerts available on this instance, with real VirusTotal
    reports on the URL observable rather than only OpenCTI's "Not
    found"."""
    payload = json.loads(
        (Path(__file__).parent / "fixtures" / "thehive_real.json").read_text()
    )
    return {"observables": payload["alert_observables"]}


class TestCortexTaxonomyVerdicts:
    """Runs against the four real observables of alert ~4661456.

    The real reports on this instance are simple — no duplicate rows or
    context-row/verdict-row split appears in this data (VT ran only on the
    URL, both its rows carry a single `level: malicious` at a low 1/92
    ratio; OpenCTI's rows are all `level: info`, "Not found"; the
    github.com domain has no reports at all). The duplicate-row and
    context-vs-verdict scenarios `_summarize_taxonomies` also needs to
    handle are covered separately below with synthetic input, since this
    real data doesn't happen to exercise them.
    """

    def results_by_observable(self, real_sigma_process_alert, hive_alert):
        alert = build(real_sigma_process_alert, hive_alert=hive_alert)
        return {(r.observable, r.analyzer): r for r in alert.cortex_results}

    def test_reports_without_a_summary_wrapper_are_read(
        self, real_sigma_process_alert, hive_alert
    ):
        """The stock projection returns `report["taxonomies"]` unwrapped (no
        `summary` key); Cortex's own API wraps it as
        `report["summary"]["taxonomies"]`. Both must work. 5 results: the URL
        carries 3 analyzer reports (VT Scan, VT GetReport, OpenCTI), each hash
        carries 1 (OpenCTI), the domain carries 0."""
        alert = build(real_sigma_process_alert, hive_alert=hive_alert)
        assert len(alert.cortex_results) == 5

    def test_low_ratio_ties_are_still_trusted_as_malicious(
        self, real_sigma_process_alert, hive_alert
    ):
        """VT's own GetReport row for the xordump URL is `1/92` labelled
        `malicious` directly — no ratio parsing happens here, the analyzer's
        own label is taken as-is, even though 1 of 92 engines looks weak
        next to the label."""
        results = self.results_by_observable(real_sigma_process_alert, hive_alert)
        url = [r for k, r in results.items() if "xordump" in k[0] and "GetReport" in k[1]][0]
        assert url.verdict == ["malicious"]
        assert "1/92 (malicious)" in url.details

    def test_opencti_not_found_is_not_a_verdict(
        self, real_sigma_process_alert, hive_alert
    ):
        """OpenCTI's "Not found" rows are all `level: info` — info is context,
        not a verdict, on every observable it ran against."""
        results = self.results_by_observable(real_sigma_process_alert, hive_alert)
        opencti_rows = [r for (obs, an), r in results.items() if "OpenCTI" in an]
        assert opencti_rows
        assert all(r.verdict == [] for r in opencti_rows)
        assert all("Not found (info)" in r.details for r in opencti_rows)

    def test_domain_with_no_reports_yields_no_result(
        self, real_sigma_process_alert, hive_alert
    ):
        """github.com (the domain observable, distinct from the xordump URL
        that references it) had no analyzer run against it at all — an empty
        `reports: {}`, not an empty-taxonomies report."""
        results = self.results_by_observable(real_sigma_process_alert, hive_alert)
        assert not any(k[0] == "github.com" for k in results)

    def test_hash_with_no_matching_analyzer_yields_no_result(
        self, real_sigma_process_alert, hive_alert
    ):
        """Sanity check on a second observable-with-no-reports shape distinct
        from the domain above: the sha256 hash (not the observable this
        instance's OpenCTI/VT jobs ran on) still gets a real OpenCTI 'Not
        found' — confirms the no-report case above isn't the only path
        exercised."""
        results = self.results_by_observable(real_sigma_process_alert, hive_alert)
        assert any(k[0].startswith("1c84c863") for k in results)

    def test_context_row_does_not_silently_win_over_the_real_verdict(self):
        """SYNTHETIC, modelled on a real observed VT taxonomy shape (this
        instance's current data doesn't have an observable with this split —
        see class docstring). VT's actual pattern: a context row
        ("56 resolution(s)") happens to be tagged `level: malicious`, while
        the real detection-ratio row ("0/91") is tagged `level: info`. Under
        the current rule both rows are taken at face value — verdict
        genuinely includes "malicious" — but `details` must keep BOTH rows
        with their own labels so that fact is visible downstream, not lost."""
        from alert_builder import _summarize_taxonomies

        verdict, details = _summarize_taxonomies([
            {"namespace": "VT", "predicate": "GetReport", "value": "56 resolution(s)", "level": "malicious"},
            {"namespace": "VT", "predicate": "GetReport", "value": "0/91", "level": "info"},
        ])
        assert verdict == ["malicious"]
        assert "56 resolution(s) (malicious)" in details
        assert "0/91 (info)" in details

    def test_duplicate_taxonomy_rows_are_collapsed(self):
        """SYNTHETIC, modelled on a real observed payload that carried
        `VT:GetReport=3/97` twice (this instance's current data has no
        duplicated row — see class docstring)."""
        from alert_builder import _summarize_taxonomies

        verdict, details = _summarize_taxonomies([
            {"namespace": "VT", "predicate": "GetReport", "value": "3/97", "level": "malicious"},
            {"namespace": "VT", "predicate": "GetReport", "value": "3/97", "level": "malicious"},
        ])
        assert verdict == ["malicious"]
        assert details.count("3/97") == 1

    def test_level_is_honoured_with_no_ratio_present(self):
        """Analyzers like MISP report `hits=2 (suspicious)` with no ratio at
        all — the level IS the verdict."""
        from alert_builder import _summarize_taxonomies

        verdict, _ = _summarize_taxonomies(
            [{"namespace": "MISP", "predicate": "hits", "value": "2", "level": "suspicious"}]
        )
        assert verdict == ["suspicious"]

    def test_ratio_count_no_longer_drives_the_verdict(self):
        """A high detection count with an explicit `info` label must NOT be
        promoted to malicious/suspicious — this function makes no scoring
        judgement of its own. The analyzer's own label wins, even when it
        looks under-cautious next to the number."""
        from alert_builder import _summarize_taxonomies

        verdict, details = _summarize_taxonomies(
            [{"namespace": "VT", "predicate": "GetReport", "value": "42/70", "level": "info"}]
        )
        assert verdict == []
        assert "42/70" in details

    def test_low_ratio_count_with_malicious_label_is_trusted(self):
        """The mirror case: a LOW detection count explicitly labelled
        malicious by the analyzer is still taken at face value — no threshold
        second-guesses it either direction."""
        from alert_builder import _summarize_taxonomies

        verdict, _ = _summarize_taxonomies(
            [{"namespace": "VT", "predicate": "GetReport", "value": "1/92", "level": "malicious"}]
        )
        assert verdict == ["malicious"]
