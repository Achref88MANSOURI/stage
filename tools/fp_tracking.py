"""Per-rule false-positive history, backed by local SQLite
(`config.FP_TRACKING_DB_PATH`, created automatically on first run).

A local file rather than a server-backed database keeps this dependency-free.
`record_triage_outcome` is called only when an alert closes as a false
positive, never on a true positive, so there's no valid denominator for a
rate — `get_fp_signal` reports a raw count instead. Per the AACT literature
(arXiv:2505.09843), this kind of per-rule FP count is one of the strongest
signals available for automating alert closure, and unlike a case-history
search against an external system it's useful from the very first alert.

The 24h/30d windows are computed from a timestamped event-log table
(`fp_events`) rather than a mutable counter, via two `COUNT(*) ... WHERE
rule_uuid = ? AND triage_timestamp >= ?` queries. Cutoffs are computed in
Python rather than SQLite's `datetime('now', ...)` so they're deterministic
and can be injected in tests via the `now=` keyword.

Neither public function raises. `sqlite3` is synchronous, so the actual work
runs in `asyncio.to_thread`, wrapped in the same timeout pattern every other
tool in this package uses around its own I/O. Zero history for a rule is a
normal, successful result; a `Gap` is reserved for an actual backend problem
— a corrupt or locked DB file, an unwritable storage directory, a timeout.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import config
from schemas import FPSignal, Gap

logger = logging.getLogger(__name__)

TOOL_NAME_GET = "get_fp_signal"
TOOL_NAME_RECORD = "record_triage_outcome"
SOURCE = "fp_tracking"

SHORT_TERM_WINDOW = timedelta(hours=24)
LONG_TERM_WINDOW = timedelta(days=30)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS fp_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_uuid TEXT NOT NULL,
    triage_timestamp TEXT NOT NULL,
    analyst_reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_fp_events_rule ON fp_events(rule_uuid, triage_timestamp);
"""


def _connect(db_path: str) -> sqlite3.Connection:
    """Open a connection, creating the parent directory, file, and schema on
    first run. Idempotent — safe to call on every invocation, matches the
    no-persistent-connection pattern every other tool in this repo already
    uses (a fresh httpx client per call)."""
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")  # concurrent reads while a triage outcome is written
    conn.executescript(_SCHEMA)
    conn.commit()
    return conn


def _count_rule_since(conn: sqlite3.Connection, rule_uuid: str, cutoff_iso: str) -> int:
    row = conn.execute(
        "SELECT COUNT(*) FROM fp_events WHERE rule_uuid = ? AND triage_timestamp >= ?",
        (rule_uuid, cutoff_iso),
    ).fetchone()
    return row[0] if row else 0


def _get_fp_signal_sync(db_path: str, rule_uuid: str | None, now: datetime) -> FPSignal:
    conn = _connect(db_path)
    try:
        signal = FPSignal()
        if rule_uuid:
            short_cutoff = (now - SHORT_TERM_WINDOW).isoformat()
            long_cutoff = (now - LONG_TERM_WINDOW).isoformat()
            signal.rule_fp_count_24h = _count_rule_since(conn, rule_uuid, short_cutoff)
            signal.rule_fp_count_30d = _count_rule_since(conn, rule_uuid, long_cutoff)
        return signal
    finally:
        conn.close()


def _record_sync(
    db_path: str, rule_uuid: str, analyst_reason: str | None, now: datetime
) -> None:
    conn = _connect(db_path)
    try:
        conn.execute(
            "INSERT INTO fp_events (rule_uuid, triage_timestamp, analyst_reason) "
            "VALUES (?, ?, ?)",
            (rule_uuid, now.isoformat(), analyst_reason),
        )
        conn.commit()
    finally:
        conn.close()


async def get_fp_signal(
    rule_uuid: str | None,
    timeout: float | None = None,
    *,
    now: datetime | None = None,
) -> tuple[FPSignal, Gap | None]:
    """How often has this rule fired as a false positive in the last 24h/30d?

    Never raises. Returns `(FPSignal, Gap | None)`: zero counts with no Gap
    means the rule genuinely has no history yet, which is a successful
    result, not a failure. A Gap means the lookup itself couldn't run — no
    rule uuid was given, or the database couldn't be reached — and the
    counts stay at zero either way.

    `now` is keyword-only, for deterministic tests; real callers never pass it.
    """
    timeout = timeout if timeout is not None else config.STAGE_1_TOOL_TIMEOUT_FP
    started = time.monotonic()

    def elapsed_ms() -> int:
        return int((time.monotonic() - started) * 1000)

    if not rule_uuid:
        return FPSignal(), Gap(
            source=SOURCE,
            tool=TOOL_NAME_GET,
            reason="No rule uuid on the alert — nothing to look up",
            duration_ms=elapsed_ms(),
        )

    resolved_now = now or datetime.now(timezone.utc)

    try:
        signal = await asyncio.wait_for(
            asyncio.to_thread(
                _get_fp_signal_sync, config.FP_TRACKING_DB_PATH, rule_uuid, resolved_now
            ),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        logger.warning("%s timed out after %.1fs", TOOL_NAME_GET, timeout)
        return FPSignal(), Gap(
            source=SOURCE,
            tool=TOOL_NAME_GET,
            reason=f"Timeout after {timeout}s querying the local FP tracker",
            duration_ms=elapsed_ms(),
        )
    except sqlite3.Error as exc:
        logger.warning("%s DB error: %s", TOOL_NAME_GET, exc)
        return FPSignal(), Gap(
            source=SOURCE,
            tool=TOOL_NAME_GET,
            reason=f"FP tracker DB error: {type(exc).__name__}: {exc}",
            duration_ms=elapsed_ms(),
        )
    except OSError as exc:
        logger.warning("%s storage error: %s", TOOL_NAME_GET, exc)
        return FPSignal(), Gap(
            source=SOURCE,
            tool=TOOL_NAME_GET,
            reason=f"FP tracker storage error: {exc}",
            duration_ms=elapsed_ms(),
        )
    except Exception as exc:  # noqa: BLE001 — a tool must never raise into gather
        logger.warning("%s failed: %s", TOOL_NAME_GET, exc)
        return FPSignal(), Gap(
            source=SOURCE,
            tool=TOOL_NAME_GET,
            reason=f"{type(exc).__name__}: {exc}",
            duration_ms=elapsed_ms(),
        )

    return signal, None


async def record_triage_outcome(
    rule_uuid: str,
    analyst_reason: str | None = None,
    timeout: float | None = None,
    *,
    now: datetime | None = None,
) -> tuple[bool, Gap | None]:
    """Record a false-positive triage closure.

    Call this only when an alert closes as `false_positive` — never on a
    true positive, or the count above loses its meaning as a denominator-free
    signal. The caller decides the verdict; this function only writes it.

    Never raises. Returns `(True, None)` on success, `(False, Gap)` on any
    failure. Reuses `STAGE_1_TOOL_TIMEOUT_FP` as the default budget, which is
    generous for a local insert even though this write happens later in the
    pipeline than the initial evidence-gathering reads.
    """
    timeout = timeout if timeout is not None else config.STAGE_1_TOOL_TIMEOUT_FP
    started = time.monotonic()

    def elapsed_ms() -> int:
        return int((time.monotonic() - started) * 1000)

    if not rule_uuid:
        return False, Gap(
            source=SOURCE,
            tool=TOOL_NAME_RECORD,
            reason="rule_uuid is required to record a triage outcome",
            duration_ms=elapsed_ms(),
        )

    resolved_now = now or datetime.now(timezone.utc)

    try:
        await asyncio.wait_for(
            asyncio.to_thread(
                _record_sync,
                config.FP_TRACKING_DB_PATH,
                rule_uuid,
                analyst_reason,
                resolved_now,
            ),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        logger.warning("%s timed out after %.1fs", TOOL_NAME_RECORD, timeout)
        return False, Gap(
            source=SOURCE,
            tool=TOOL_NAME_RECORD,
            reason=f"Timeout after {timeout}s writing to the local FP tracker",
            duration_ms=elapsed_ms(),
        )
    except sqlite3.Error as exc:
        logger.warning("%s DB error: %s", TOOL_NAME_RECORD, exc)
        return False, Gap(
            source=SOURCE,
            tool=TOOL_NAME_RECORD,
            reason=f"FP tracker DB error: {type(exc).__name__}: {exc}",
            duration_ms=elapsed_ms(),
        )
    except OSError as exc:
        logger.warning("%s storage error: %s", TOOL_NAME_RECORD, exc)
        return False, Gap(
            source=SOURCE,
            tool=TOOL_NAME_RECORD,
            reason=f"FP tracker storage error: {exc}",
            duration_ms=elapsed_ms(),
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("%s failed: %s", TOOL_NAME_RECORD, exc)
        return False, Gap(
            source=SOURCE,
            tool=TOOL_NAME_RECORD,
            reason=f"{type(exc).__name__}: {exc}",
            duration_ms=elapsed_ms(),
        )

    return True, None
