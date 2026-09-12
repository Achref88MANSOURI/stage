"""Shared helpers for running tool calls inside a stage: bound a coroutine
with a timeout, skip one outright, and safely unpack results from
`asyncio.gather(return_exceptions=True)`.

Every stage that fires several tool calls concurrently imports from here,
so this logic lives in one place instead of being duplicated per stage. It
also centralizes per-tool timing logs — `_guarded`/`_skip` log entry, exit,
and duration for every call at DEBUG level, so individual `tools/*.py`
files don't need their own logging for this. DEBUG keeps it out of the way
of the higher-level INFO summary each stage logs for itself.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, TypeVar

from schemas import Gap

logger = logging.getLogger(__name__)

T = TypeVar("T")


async def _guarded(
    coro, *, seconds: float, default: T, source: str, tool: str
) -> tuple[T, Gap | None]:
    """Runs a tool coroutine under a timeout, converting a timeout or any
    unexpected exception into a Gap instead of letting it propagate."""
    started = time.monotonic()
    logger.debug("tool %s started (timeout=%.1fs)", tool, seconds)
    try:
        result, gap = await asyncio.wait_for(coro, timeout=seconds)
        elapsed_ms = int((time.monotonic() - started) * 1000)
        if gap is not None:
            logger.debug("tool %s completed in %dms with a Gap: %s", tool, elapsed_ms, gap.reason)
        else:
            logger.debug("tool %s completed in %dms", tool, elapsed_ms)
        return result, gap
    except asyncio.TimeoutError:
        logger.debug("tool %s hit the gather-level timeout after %.1fs", tool, seconds)
        return default, Gap(
            source=source,
            tool=tool,
            reason=f"gather-level timeout after {seconds}s",
            duration_ms=int(seconds * 1000),
        )
    except Exception as exc:  # noqa: BLE001 — last line of defense against a bug in the wrapped call
        logger.warning("gather guard caught an unexpected error from %s: %s", tool, exc)
        return default, Gap(
            source=source,
            tool=tool,
            reason=f"Unexpected error: {type(exc).__name__}: {exc}",
            duration_ms=0,
        )


async def _skip(*, default: T, source: str, tool: str, reason: str) -> tuple[T, Gap | None]:
    """No coroutine to run at all — e.g. a dataset gate or a disabled feature
    flag."""
    logger.debug("tool %s skipped: %s", tool, reason)
    return default, Gap(source=source, tool=tool, reason=reason, duration_ms=0)


def _unpack(result: Any, default: T) -> tuple[T, Gap | None]:
    """Unpacks a `_guarded`/`_skip` result. If `asyncio.gather` caught a raw
    exception instead — meaning it escaped `_guarded` itself — returns the
    default value with a synthesized Gap rather than raising a confusing
    unpacking error."""
    if isinstance(result, BaseException):
        return default, Gap(
            source="node",
            tool="unknown",
            reason=(
                "Unhandled exception escaped _guarded and reached the outer "
                f"asyncio.gather: {type(result).__name__}: {result}"
            ),
            duration_ms=0,
        )
    return result
