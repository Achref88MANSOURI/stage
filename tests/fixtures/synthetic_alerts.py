"""Synthetic raw-alert fixtures for dataset shapes with no captured live alert.

READ THIS BEFORE TRUSTING ANY TEST THAT USES THESE.

Every fixture in this module is SYNTHETIC. Field paths are transcribed from
`ingest-templates.txt` (the live `logs-detections.alerts-so/_mapping` dump) and
from `so-alert-reference/`'s ingest pipelines — sources that prove a field *can
exist*, never that a real alert of this shape *was observed*. No alert of any
shape below has been captured from this deployment.

A green test against these fixtures proves exactly one thing: the extractor does
not crash and maps the field paths as written. It does NOT prove the shape is
what Security Onion actually emits. Per implementation guide §0.1, that can only
be established once the relevant sensor or telemetry path is live.

The one REAL fixture lives in `sigma-alert-sample.json` at the repo root and
covers `endpoint.events.process` only. It is loaded by `conftest.py`, not here.

These are Python rather than JSON files on purpose: the provenance labelling
above and per-fixture below is the most important content in this file, and JSON
cannot carry it.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# endpoint.events.file / endpoint.events.library / cross-process-access /
# ECS related.* fixtures (ENDPOINT_FILE_ALERT, ENDPOINT_LIBRARY_ALERT,
# TARGET_PROCESS_ALERT, RELATED_ENTITIES_ALERT) REMOVED 2026-09-07,
# user-directed — alert_builder.py no longer structurally extracts
# file/registry/target_process/library/related_entities at all (see
# schemas/alert.py::CanonicalAlert's docstring); that detail now reaches the
# single LLM call through CanonicalAlert.raw_alert directly, which needs no
# dedicated fixture since it's just the raw_alert dict passed straight
# through. See tests/test_alert_builder.py::TestRawAlertPassthrough.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# SYNTHETIC — windows.sysmon_operational (native winlog channel)
# Field paths from ingest-templates.txt event_data.winlog.*.
# ---------------------------------------------------------------------------
SYSMON_WINLOG_ALERT = {
    "@timestamp": "2026-07-22T09:50:00Z",
    "sigma_level": "medium",
    "rule": {
        "name": "Sysmon Process Creation Anomaly",
        "uuid": "eeeeeeee-1111-2222-3333-444444444444",
        "product": "windows",
    },
    "event": {"severity": 3, "module": "sigma", "severity_label": "medium"},
    "event_data": {
        "@timestamp": "2026-07-22T09:49:30.000000Z",
        "event": {"dataset": "windows.sysmon_operational", "code": "1"},
        "winlog": {
            "computer_name": "win-kvkmd51ggkq",
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "event_id": 1,
            "process": {"pid": 3312},
            "user": {"name": "SYSTEM", "identifier": "S-1-5-18", "domain": "NT AUTHORITY"},
        },
    },
}

# ---------------------------------------------------------------------------
# SYNTHETIC — PowerShell engine-lifecycle (winlog sub-shape)
# ---------------------------------------------------------------------------
POWERSHELL_ENGINE_ALERT = {
    "@timestamp": "2026-07-22T10:00:00Z",
    "rule": {"name": "PowerShell Engine Started", "uuid": "ffffffff-1111-2222-3333-444444444444"},
    "event": {"severity": 2, "module": "sigma"},
    "event_data": {
        "event": {"dataset": "windows.powershell_operational"},
        "winlog": {"computer_name": "win-kvkmd51ggkq"},
        "powershell": {
            "engine": {"new_state": "Available", "previous_state": "None", "version": "5.1.19041.1"},
            "process": {"executable_version": "5.1.19041.1"},
            "runspace_id": "11111111-2222-3333-4444-555555555555",
        },
    },
}

# ---------------------------------------------------------------------------
# SYNTHETIC — system.auth (Filebeat SSH auth log)
# ---------------------------------------------------------------------------
SSH_AUTH_ALERT = {
    "@timestamp": "2026-07-22T10:10:00Z",
    "rule": {"name": "SSH Login Accepted", "uuid": "00000000-1111-2222-3333-444444444444"},
    "event": {"severity": 2, "module": "sigma"},
    "event_data": {
        "event": {"dataset": "system.auth"},
        "system": {"auth": {"ssh": {"event": "Accepted", "method": "publickey"}}},
        "source": {"ip": "10.20.30.40", "port": 51234},
        "user": {"name": "root"},
    },
}

# ---------------------------------------------------------------------------
# SYNTHETIC — windows.sysmon_operational network_connection event (gap #5).
# No real Sysmon network_connection alert has been captured in this
# deployment yet — field path (event_data.network.community_id) taken from
# so-analysis/elasticsearch templates (tier 3), not a live document.
# ---------------------------------------------------------------------------
SSH_AUTH_ALERT_WITH_COMMUNITY_ID = {
    "@timestamp": "2026-07-22T10:10:00Z",
    "rule": {"name": "SSH Login Accepted", "uuid": "00000000-1111-2222-3333-444444444444"},
    "event": {"severity": 2, "module": "sigma"},
    "event_data": {
        "event": {"dataset": "system.auth"},
        "system": {"auth": {"ssh": {"event": "Accepted", "method": "publickey"}}},
        "source": {"ip": "10.20.30.40", "port": 51234},
        "user": {"name": "root"},
        "network": {"community_id": "1:synthetic-community-id-hash="},
    },
}

# ---------------------------------------------------------------------------
# SYNTHETIC — kratos.audit (HTTP identity-provider login flow)
# ---------------------------------------------------------------------------
KRATOS_LOGIN_FLOW_ALERT = {
    "@timestamp": "2026-07-22T10:20:00Z",
    "rule": {"name": "Repeated Failed Login Flow", "uuid": "99999999-1111-2222-3333-444444444444"},
    "event": {"severity": 3, "module": "sigma"},
    "event_data": {
        "event": {"dataset": "kratos.audit"},
        "http": {
            "method": "POST",
            "uri": "/self-service/login",
            "useragent": "Mozilla/5.0",
            "request": {"remote": "203.0.113.9:44321"},
        },
        "login_flow": {"type": "browser", "state": "choose_method", "active": "password"},
    },
}

# ---------------------------------------------------------------------------
# SYNTHETIC — Suricata network alert.
# A REAL Suricata alert fixture now exists (`tests/fixtures/
# suricata-alert-real.json`, `real_suricata_alert_source` in conftest.py) —
# see TestRealSuricataPath for the parts that fixture covers. This synthetic
# fixture remains for the parts it doesn't: a different rule/uuid (breadth
# across more than one Suricata rule), an IPv6 destination, and
# `network.initiated` — a field the live index mapping (ingest-templates.txt)
# confirms CAN appear on a Suricata alert, just not one the one real sample
# happens to have populated. `transport` was corrected 2026-08-18 to match
# real data: `"TCP"` (uppercase), not `"tcp"`.
# ---------------------------------------------------------------------------
SURICATA_ALERT = {
    "@timestamp": "2026-07-22T10:30:00Z",
    "rule": {"name": "ET MALWARE Observed DNS Query", "uuid": "2027001"},
    "event": {"severity": 4, "module": "suricata", "severity_label": "high"},
    "source": {"ip": "172.20.24.99", "port": 51515},
    "destination": {"ip": "185.53.178.50", "port": 443, "ipv6": None},
    "network": {"transport": "TCP", "initiated": True},
}

# ---------------------------------------------------------------------------
# SYNTHETIC — YARA/Strelka file alert.
# NOTE: YARA path — unit-tested against synthetic fixture only, no live SO alert
# exists yet to validate against (implementation guide §0.1). Hashes sit at a
# TOP-LEVEL `hash` sibling of `file`, not nested under it — per Security Onion's
# own strelka.file ingest pipeline in so-alert-reference/.
#
# entropy/pe_image_version/pe_flags/timestamps/mode/ssdeep (added 2026-08-19,
# gap #7) are ALSO synthetic — field paths from so-analysis/elasticsearch
# templates (TEMPLATE-SCHEMA-REFERENCE.md §5), not a live document. The
# Strelka sensor isn't enabled in this deployment (gap #13), so no real
# alert of this shape can exist yet to validate against.
# ---------------------------------------------------------------------------
YARA_STRELKA_ALERT = {
    "@timestamp": "2026-07-22T10:40:00Z",
    "rule": {"name": "MALWARE_Win_Generic", "uuid": "MALWARE_Win_Generic"},
    "event": {"severity": 4, "module": "strelka", "severity_label": "high"},
    "file": {
        "name": "invoice.doc.exe",
        "path": "/nsm/strelka/extracted/invoice.doc.exe",
        "size": 245760,
        "mime_type": "application/x-dosexec",
        "created": "2026-07-22T10:39:50Z",
        "accessed": "2026-07-22T10:39:55Z",
        "mtime": "2026-06-01T08:00:00Z",
        "ctime": "2026-06-01T08:00:00Z",
        "mode": "0755",
    },
    "hash": {"md5": "0" * 32, "sha256": "f" * 64, "ssdeep": "768:abc123:xyz789"},
    "scan": {
        "entropy": {"entropy": 7.89},
        "pe": {"image_version": "6.1", "flags": "DLL, EXECUTABLE_IMAGE"},
    },
}
