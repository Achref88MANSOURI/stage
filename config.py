"""Configuration. Loads and validates every environment variable at import
time and raises immediately on a missing required one — no module should be
able to import a partially-configured client.

`.env` is parsed with a small stdlib loader rather than python-dotenv, which is
not installed. Real process environment always wins over the file, so container
env vars override a stale `.env` on the host.

Run `python config.py` to print all resolved settings. Secrets are masked in
that output.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent
ENV_FILE = REPO_ROOT / ".env"

_SECRET_HINTS = ("KEY", "TOKEN", "PASSWORD", "SECRET", "PWD")


def _load_env_file(path: Path) -> None:
    """Minimal `.env` parser: KEY=VALUE, `#` comments, blank lines, optional
    surrounding quotes. Does NOT overwrite variables already in the real
    environment."""
    if not path.is_file():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.split(" #", 1)[0].strip().strip("'\"")
        if key and key not in os.environ:
            os.environ[key] = value


_load_env_file(ENV_FILE)


class ConfigError(RuntimeError):
    """Raised at import time when a required variable is missing or unusable."""


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ConfigError(
            f"Required environment variable {name} is missing or empty. "
            f"See .env.example for the full variable set."
        )
    return value


def _optional(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name, "").strip()
    return value or default


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc


def _float(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number, got {raw!r}") from exc


# ---------------------------------------------------------------------------
# LLM — exactly one single-shot completion call per alert (stages/triage.py),
# no tools, no multi-turn.
# ---------------------------------------------------------------------------
LLM_BASE_URL = _required("LLM_BASE_URL")
LLM_MODEL = _required("LLM_MODEL")
LLM_API_KEY = _optional("LLM_API_KEY", "sk-no-auth")

# Prompt tokens plus requested completion tokens must stay under the
# model's context window, or the backend rejects the call outright.
# stages/triage.py::_capped_max_tokens enforces this at call time. Since no
# local tokenizer covers every backend model, prompt size is estimated from
# character count (LLM_TOKEN_ESTIMATE_CHARS_PER_TOKEN is conservative, since
# GUIDs and hashes tokenize less efficiently than prose), with an added
# safety margin.
LLM_MAX_CONTEXT_TOKENS = _int("LLM_MAX_CONTEXT_TOKENS", 8192)
LLM_TOKEN_ESTIMATE_CHARS_PER_TOKEN = _float("LLM_TOKEN_ESTIMATE_CHARS_PER_TOKEN", 3.2)
LLM_CONTEXT_SAFETY_MARGIN_TOKENS = _int("LLM_CONTEXT_SAFETY_MARGIN_TOKENS", 400)
# Floor so a very large prompt still gets some completion room instead of
# being capped to near zero.
LLM_MIN_COMPLETION_TOKENS = _int("LLM_MIN_COMPLETION_TOKENS", 500)

# Desired completion size before the context-window cap above is applied.
# Set high because some models spend part of this budget on internal
# reasoning that isn't reflected in the visible output.
STAGE_TRIAGE_DESIRED_MAX_TOKENS = _int("STAGE_TRIAGE_DESIRED_MAX_TOKENS", 16000)

# ---------------------------------------------------------------------------
# Backends
# ---------------------------------------------------------------------------
THEHIVE_URL = _required("THEHIVE_URL").rstrip("/")
THEHIVE_API_KEY = _required("THEHIVE_API_KEY")

ITOP_URL = _required("ITOP_URL").rstrip("/")
ITOP_USER = _required("ITOP_USER")
# iTop REST auth is username + password (`auth_pwd`), not an API key.
ITOP_PWD = _required("ITOP_PWD")

ES_URL = _required("ES_URL").rstrip("/")
ES_API_KEY = _optional("ES_API_KEY")  # empty is valid: an ES with no auth
# The bare SO host redirects to the web UI on 443; Elasticsearch is on 9200.
if ES_URL.count(":") < 2 and not ES_URL.rsplit(":", 1)[-1].isdigit():
    raise ConfigError(
        f"ES_URL={ES_URL!r} has no explicit port. Elasticsearch is on :9200 — "
        f"the bare host redirects (302) to the Security Onion web UI on 443."
    )
# Self-signed certificate on the SO manager.
ES_VERIFY_TLS = _optional("ES_VERIFY_TLS", "false").lower() in ("1", "true", "yes")

QDRANT_URL = _required("QDRANT_URL").rstrip("/")
QDRANT_EMBEDDING_MODEL = _optional("QDRANT_EMBEDDING_MODEL", "BAAI/bge-m3")
# The embedding model above runs behind its own HTTP microservice, not
# loaded in-process — POST {"text": "..."} -> {"embedding": [float x 1024]}.
# See tools/qdrant.py.
EMBEDDING_API_URL = _required("EMBEDDING_API_URL").rstrip("/")

# OpenCTI — direct GraphQL graph enrichment (tools/opencti.py), separate
# from the OpenCTI Cortex analyzer whose taxonomy rows arrive via
# THEHIVE_URL above.
OPENCTI_URL = _required("OPENCTI_URL").rstrip("/")
OPENCTI_TOKEN = _required("OPENCTI_TOKEN")

# ---------------------------------------------------------------------------
# Elasticsearch index names.
# so-detection is pinned EXACTLY, not as a wildcard — a wildcard also
# matches the rule-revision-history index alongside current rules, which
# would return stale rule versions.
# ---------------------------------------------------------------------------
ES_DETECTION_INDEX = _optional("ES_DETECTION_INDEX", "so-detection")
ES_AUDIT_INDEX = _optional("ES_AUDIT_INDEX", "so-triage-audit")

# ---------------------------------------------------------------------------
# Storage.
# ---------------------------------------------------------------------------
FP_TRACKING_DB_PATH = (
    _optional("FP_TRACKING_DB_PATH") or _optional("FP_DB_PATH") or "./data/fp_events.db"
)
# Absent by design in this deployment — dedup no-ops and never blocks the
# pipeline when unset.
REDIS_URL = _optional("REDIS_URL")

# ---------------------------------------------------------------------------
# Timeouts (seconds) — per-tool budgets for Stage 1 gathering.
# ---------------------------------------------------------------------------
STAGE_1_TOOL_TIMEOUT_ITOP = _float("STAGE_1_TOOL_TIMEOUT_ITOP", 5.0)
STAGE_1_TOOL_TIMEOUT_THEHIVE = _float("STAGE_1_TOOL_TIMEOUT_THEHIVE", 5.0)
STAGE_1_TOOL_TIMEOUT_ES = _float("STAGE_1_TOOL_TIMEOUT_ES", 3.0)
STAGE_1_TOOL_TIMEOUT_QDRANT = _float("STAGE_1_TOOL_TIMEOUT_QDRANT", 3.0)
STAGE_1_TOOL_TIMEOUT_FP = _float("STAGE_1_TOOL_TIMEOUT_FP", 0.1)
STAGE_1_TOOL_TIMEOUT_OPENCTI = _float("STAGE_1_TOOL_TIMEOUT_OPENCTI", 5.0)
# The single triage LLM call's timeout. Set generously since CPU-bound
# inference on a full evidence dump can take several minutes; tighten this
# on a GPU-backed endpoint.
STAGE_TRIAGE_LLM_TIMEOUT = _float("STAGE_TRIAGE_LLM_TIMEOUT", 600.0)
# `tools.thehive.fetch_case_observables_with_type`'s timeout — used by
# `stages/case_action.py::_write_actionable_observables` to dedup against a
# case's already-recorded observables before writing new ones.
STAGE_6_TOOL_TIMEOUT_THEHIVE = _float("STAGE_6_TOOL_TIMEOUT_THEHIVE", 5.0)

# ---------------------------------------------------------------------------
# Logging — see logging_config.py. LOG_LEVEL governs both the console and
# file handlers (there is only one level, not one per handler — simpler to
# reason about, and nothing in this deployment has needed the split yet).
# LOG_FILE empty/unset disables file logging entirely (console only).
# ---------------------------------------------------------------------------
LOG_LEVEL = _optional("LOG_LEVEL", "INFO")
LOG_FILE = _optional("LOG_FILE", "./logs/soc3s.log")


def _mask(name: str, value: Any) -> str:
    if value is None:
        return "<unset>"
    text = str(value)
    if any(hint in name for hint in _SECRET_HINTS) and text:
        return f"{text[:4]}…{text[-2:]} ({len(text)} chars)" if len(text) > 8 else "<set>"
    return text


def resolved_settings() -> dict[str, Any]:
    return {
        name: value
        for name, value in sorted(globals().items())
        if name.isupper() and not name.startswith("_")
    }


def describe() -> str:
    lines = [f"config.py — loaded from {ENV_FILE if ENV_FILE.is_file() else '<no .env>'}"]
    for name, value in resolved_settings().items():
        lines.append(f"  {name:34s} {_mask(name, value)}")
    return "\n".join(lines)


if __name__ == "__main__":
    print(describe())
