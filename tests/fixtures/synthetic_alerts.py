"""Synthetic raw-alert fixtures for dataset shapes with no captured live alert.

READ THIS BEFORE TRUSTING ANY TEST THAT USES THESE.

Every fixture in this module is SYNTHETIC. Field paths are transcribed from
`ingest-templates.txt` (the live `logs-detections.alerts-so/_mapping` dump) and
from `so-alert-reference/`'s ingest pipelines — sources that prove a field *can
exist*, never that a real alert of this shape *was observed*. No alert of any
shape below has been captured from this deployment.

A green test against these fixtures proves exactly one thing: the extractor does
not crash and maps the field paths as written. It does NOT prove the shape is
what Security Onion actually emits — that can only be established once the
relevant sensor or telemetry path is live.

The one REAL fixture lives in `sigma-alert-sample.json` at the repo root and
covers `endpoint.events.process` only. It is loaded by `conftest.py`, not here.

These are Python rather than JSON files on purpose: the provenance labelling
above and per-fixture below is the most important content in this file, and JSON
cannot carry it.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# endpoint.events.file / endpoint.events.library / cross-process-access /
# ECS related.* shapes have no dedicated fixture here — alert_builder.py does
# not structurally extract file/registry/target_process/library/related_entities
# at all (see schemas/alert.py::CanonicalAlert's docstring); that detail
# reaches the LLM call through CanonicalAlert.raw_alert directly, which needs
# no dedicated fixture since it's just the raw_alert dict passed straight
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
# SYNTHETIC — YARA/Strelka file alert.
# NOTE: YARA path — unit-tested against synthetic fixture only, no live SO alert
# exists yet to validate against. Hashes sit at a TOP-LEVEL `hash` sibling of
# `file`, not nested under it — per Security Onion's own strelka.file ingest
# pipeline in so-alert-reference/.
#
# entropy/pe_image_version/pe_flags/timestamps/mode/ssdeep are ALSO synthetic
# — field paths from so-analysis/elasticsearch templates, not a live
# document. The Strelka sensor isn't enabled in this deployment, so no real
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
