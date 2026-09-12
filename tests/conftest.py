"""Shared pytest fixtures for the test suite.

Fixtures are split into two categories that must not be blurred: alerts
captured verbatim from a real Security Onion deployment (this file), and
synthetic alerts built by hand from known field mappings
(tests/fixtures/synthetic_alerts.py).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))


@pytest.fixture(scope="session")
def webhook_envelope() -> dict:
    """The raw n8n webhook envelope as saved from Security Onion.

    Shape: `[{headers, params, query, body, webhookUrl, executionMode}]`.
    This is what n8n receives, not what it forwards to /triage — n8n
    unwraps it first. See schemas.AlertWebhookPayload.
    """
    return json.loads((REPO_ROOT / "sigma-alert-sample.json").read_text())[0]


@pytest.fixture(scope="session")
def real_es_alert_hit() -> dict:
    """A full Elasticsearch hit pulled unmodified from a production Security
    Onion alerts index — an untouched production document rather than a
    webhook capture. Same rule as the webhook sample (5e3cc4d8-...), a
    different alert instance.

    Includes a top-level `ioc` block: a `so-ioc-normalize` ingest pipeline
    in this deployment stamps `ioc.{schema_version, source_engine, rule,
    dataset}` onto real alerts. `ioc.*` is not a Security Onion field and
    must never be read by the parser; keeping it here lets
    `TestRealProductionEsDocument` confirm the code ignores it on real
    data, not just a synthetic case.
    """
    return json.loads((REPO_ROOT / "tests" / "fixtures" / "sigma-alert-real.json").read_text())


@pytest.fixture(scope="session")
def real_es_alert_source(real_es_alert_hit: dict) -> dict:
    """The `_source` of the verbatim ES hit — the raw alert document itself.

    Differs from the webhook body by six keys the alerter/n8n layer adds at
    webhook time and which are absent from the index (`_id`, `_index`,
    `num_hits`, `num_matches`, `severity_filter`, `source_system`); every
    other key is identical between the two.
    """
    return real_es_alert_hit["_source"]


@pytest.fixture(scope="session")
def real_suricata_alert_hit() -> dict:
    """A Suricata alert pulled from a Security Onion instance ("GPL
    ATTACK_RESPONSE id check returned root", SID 2100498), trimmed to the
    same `_id`/`_index`/`_score`/`_source` shape as `real_es_alert_hit`.

    Field shape: `rule.uuid` as a string, `event.module="suricata"`,
    `event.dataset="suricata.alert"`, no host/user/process fields — the
    live shape Suricata alerts carry in this deployment's
    `logs-suricata.alerts-so` index.

    This alert has never actually reached `/triage`: the pipeline reads
    from `logs-detections.alerts-so*`, which in this deployment is entirely
    `event.module=sigma`. Security Onion's Sigma alerter never writes to
    `logs-suricata.alerts-so`, so a Suricata alert needs a separate
    ingestion bridge before it can reach this service — `build_canonical_alert`
    handling the shape correctly is necessary but not sufficient on its own.
    """
    return json.loads((REPO_ROOT / "tests" / "fixtures" / "suricata-alert-real.json").read_text())


@pytest.fixture(scope="session")
def real_suricata_alert_source(real_suricata_alert_hit: dict) -> dict:
    """The `_source` of the verbatim Suricata ES hit above — the raw_alert
    shape `/triage` would receive in its webhook body, per the same
    `_source` == `raw_alert` relationship `real_es_alert_source` documents
    for the Sigma fixture."""
    return real_suricata_alert_hit["_source"]


@pytest.fixture(scope="session")
def real_sysmon_registry_alert_hit() -> dict:
    """A Sysmon registry-set alert pulled from `logs-detections.alerts-so*`
    ("Potential Persistence Via GlobalFlags", rule uuid
    36803969-5421-41ec-b92f-8500f79c23b0), an Atomic-Red-Team-style
    persistence technique fired by `nanodump.x64.exe`.

    A distinct Sysmon event shape from `endpoint.events.process`
    (`real_sigma_process_alert` below): `event_data.event.code == 13` (an
    int, not a string), `event_data.registry.{hive,key,path,value,
    data.{type,strings}}` populated, and no `event_data.process.pe.*`
    (that belongs to the separate code==1 ProcessCreate shape).

    Also a real example of a rule-name collision: `event_data.rule` here is
    `{"name": "T1183,IFEO"}`, Sysmon's own internal RuleName config tag,
    while the actual fired Sigma rule name is the top-level `rule.name`,
    "Potential Persistence Via GlobalFlags". This confirms the collision
    `_parse_rule` guards against is real rather than a hypothetical edge
    case.
    """
    return json.loads(
        (REPO_ROOT / "tests" / "fixtures" / "sysmon-registry-alert-real.json").read_text()
    )


@pytest.fixture(scope="session")
def real_sysmon_registry_alert_source(real_sysmon_registry_alert_hit: dict) -> dict:
    """The `_source` of the verbatim Sysmon registry ES hit above — the
    raw_alert shape `/triage` would receive in its webhook body."""
    return real_sysmon_registry_alert_hit["_source"]


@pytest.fixture(scope="session")
def real_sysmon_pe_alert_hit() -> dict:
    """A Sysmon ProcessCreate alert pulled from `logs-detections.alerts-so*`
    ("Potentially Suspicious Powershell Script Execution From Temp Folder",
    rule uuid a6a39bdb-935c-4f0a-ab77-35f4bbf44d33) — an xordump/lsass-dump
    PowerShell invocation.

    Confirms `event_data.process.pe.{company,description,file_version,
    product,imphash,original_file_name}` are all populated on real data;
    `.architecture` is not present on this particular example."""
    return json.loads(
        (REPO_ROOT / "tests" / "fixtures" / "sysmon-powershell-pe-alert-real.json").read_text()
    )


@pytest.fixture(scope="session")
def real_sysmon_pe_alert_source(real_sysmon_pe_alert_hit: dict) -> dict:
    """The `_source` of the verbatim Sysmon PE-metadata ES hit above."""
    return real_sysmon_pe_alert_hit["_source"]


@pytest.fixture(scope="session")
def real_sigma_process_alert(webhook_envelope: dict) -> dict:
    """A captured Sigma alert covering the `endpoint.events.process`
    dataset: "Suspicious Invoke-WebRequest Execution" / xordump.exe
    download on win-kvkmd51ggkq, rule uuid
    5e3cc4d8-3e68-43db-8656-eaaeefdec9cc.

    Covers this one dataset shape only; assertions against it say nothing
    about other shapes.
    """
    return webhook_envelope["body"]
