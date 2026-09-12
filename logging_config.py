"""Pipeline-wide logging setup: a console handler and a rotating file
handler, both tagging every log line with the alert it belongs to.

configure_logging() runs automatically on import of stages/ or tools/, so
it's set up before any real run, script, or test suite needs it.
_AlertIdFilter attaches the current alert id to every record, so a plain
logging.getLogger(__name__) call anywhere picks it up automatically.
"""

from __future__ import annotations

import contextlib
import logging
import logging.handlers
import sys
from contextvars import ContextVar
from pathlib import Path

import config

# A ContextVar rather than a thread-local, since this is an asyncio codebase
# and a thread-local wouldn't propagate correctly across await boundaries.
alert_id_var: ContextVar[str] = ContextVar("alert_id", default="-")

FORMAT = "%(asctime)s %(levelname)-8s [%(alert_id)s] %(name)s: %(message)s"

_configured = False

# Third-party libraries whose own DEBUG output would drown out this
# pipeline's per-tool lifecycle logs — forced to WARNING regardless of
# config.LOG_LEVEL. Raise these individually if transport-level tracing is
# ever needed.
_NOISY_LOGGERS = ("httpcore", "httpx", "asyncio")


class _AlertIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.alert_id = alert_id_var.get()
        return True


def configure_logging() -> None:
    """Sets up the console and file handlers. Idempotent via a module-level
    flag rather than checking for existing handlers, since pytest or another
    framework may already have attached its own before this runs."""
    global _configured
    if _configured:
        return
    _configured = True

    root = logging.getLogger()
    root.setLevel(config.LOG_LEVEL)

    for name in _NOISY_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)

    formatter = logging.Formatter(FORMAT)
    alert_filter = _AlertIdFilter()

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    console.addFilter(alert_filter)
    root.addHandler(console)

    if config.LOG_FILE:
        path = Path(config.LOG_FILE)
        path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            path, maxBytes=10_000_000, backupCount=5
        )
        file_handler.setFormatter(formatter)
        file_handler.addFilter(alert_filter)
        root.addHandler(file_handler)


@contextlib.contextmanager
def alert_context(alert_id: str):
    """Tags every log line emitted inside this block, including anything it
    awaits, with the given alert id. Resets on exit so concurrent alerts
    don't leak into each other's logs."""
    token = alert_id_var.set(alert_id or "-")
    try:
        yield
    finally:
        alert_id_var.reset(token)
