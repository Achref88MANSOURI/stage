"""Tests for `get_fp_signal` / `record_triage_outcome`.

These hit an actual on-disk SQLite file with real blocking `sqlite3` calls
rather than mocking the connection. Each test points
`config.FP_TRACKING_DB_PATH` at a fresh `tmp_path` file, so tests never
share state or touch the real deployment database.
"""

from __future__ import annotations

import asyncio
import os
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

import config
from tools import fp_tracking as fp_mod
from tools.fp_tracking import get_fp_signal, record_triage_outcome

RULE = "5e3cc4d8-3e68-43db-8656-eaaeefdec9cc"
OTHER_RULE = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def fp_db(tmp_path, monkeypatch):
    """Point every test at its own fresh, real SQLite file."""
    db_path = str(tmp_path / "fp_events.db")
    monkeypatch.setattr(config, "FP_TRACKING_DB_PATH", db_path)
    return db_path


class TestGetFpSignalAgainstRealDb:
    def test_empty_db_returns_real_zero_result_no_gap(self):
        """Zero history is a successful result, not a Gap."""
        signal, gap = run(get_fp_signal(RULE))
        assert gap is None
        assert signal.rule_fp_count_24h == 0
        assert signal.rule_fp_count_30d == 0

    def test_seeded_events_produce_correct_windowed_counts(self):
        now = datetime.now(timezone.utc)
        run(record_triage_outcome(RULE, "recent", now=now - timedelta(hours=1)))
        run(record_triage_outcome(RULE, "mid", now=now - timedelta(days=5)))
        run(record_triage_outcome(RULE, "old", now=now - timedelta(days=40)))

        signal, gap = run(get_fp_signal(RULE, now=now))
        assert gap is None
        assert signal.rule_fp_count_24h == 1  # "recent" only
        assert signal.rule_fp_count_30d == 2  # "recent" + "mid", not "old"

    def test_events_outside_30d_window_are_excluded(self):
        now = datetime.now(timezone.utc)
        run(record_triage_outcome(RULE, "ancient", now=now - timedelta(days=31)))
        signal, gap = run(get_fp_signal(RULE, now=now))
        assert gap is None
        assert signal.rule_fp_count_30d == 0

    def test_rule_signal_ignores_other_rules(self):
        """A row for a different rule must not count toward this rule's
        total (the query filters on rule_uuid, not the whole table)."""
        now = datetime.now(timezone.utc)
        run(record_triage_outcome(OTHER_RULE, "unrelated", now=now))

        signal, gap = run(get_fp_signal(RULE, now=now))
        assert gap is None
        assert signal.rule_fp_count_30d == 0


class TestRecordTriageOutcome:
    def test_insert_succeeds_and_is_queryable(self, fp_db):
        ok, gap = run(record_triage_outcome(RULE, "SCCM deployment"))
        assert ok is True
        assert gap is None

        conn = sqlite3.connect(fp_db)
        try:
            row = conn.execute(
                "SELECT rule_uuid, analyst_reason FROM fp_events"
            ).fetchone()
        finally:
            conn.close()
        assert row == (RULE, "SCCM deployment")

    def test_multiple_inserts_accumulate(self, fp_db):
        for _ in range(3):
            run(record_triage_outcome(RULE))
        conn = sqlite3.connect(fp_db)
        try:
            (count,) = conn.execute("SELECT COUNT(*) FROM fp_events").fetchone()
        finally:
            conn.close()
        assert count == 3

    def test_missing_rule_uuid_produces_gap_no_db_touch(self, fp_db):
        ok, gap = run(record_triage_outcome(""))
        assert ok is False
        assert "required" in gap.reason
        assert not os.path.exists(fp_db)


class TestNoLookupKey:
    def test_no_rule_uuid_at_all(self, fp_db):
        signal, gap = run(get_fp_signal(None))
        assert gap is not None
        assert "nothing to look up" in gap.reason
        assert not os.path.exists(fp_db)


class TestFailuresProduceGapsNotExceptions:
    def test_corrupt_db_file_produces_gap(self, fp_db):
        with open(fp_db, "wb") as f:
            f.write(b"not a sqlite file, just garbage bytes")

        signal, gap = run(get_fp_signal(RULE))
        assert gap is not None
        assert "FP tracker DB error" in gap.reason
        assert signal.rule_fp_count_24h == 0

    def test_unwritable_parent_directory_produces_gap(self, tmp_path, monkeypatch):
        if os.geteuid() == 0:
            pytest.skip("permission checks don't apply as root")
        readonly_dir = tmp_path / "readonly"
        readonly_dir.mkdir(mode=0o444)
        monkeypatch.setattr(
            config, "FP_TRACKING_DB_PATH", str(readonly_dir / "nested" / "fp.db")
        )
        try:
            signal, gap = run(get_fp_signal(RULE))
            assert gap is not None
            assert "FP tracker storage error" in gap.reason
        finally:
            readonly_dir.chmod(0o755)  # let tmp_path cleanup succeed

    def test_timeout(self, monkeypatch):
        def slow_sync(db_path, rule_uuid, now):
            import time as _time

            _time.sleep(5)

        monkeypatch.setattr(fp_mod, "_get_fp_signal_sync", slow_sync)
        signal, gap = run(get_fp_signal(RULE, timeout=0.05))
        assert gap is not None
        assert "Timeout after 0.05s" in gap.reason
