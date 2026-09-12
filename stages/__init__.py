"""Pipeline stage modules. Each one exposes a single async function that
takes and returns typed schema models rather than raw dicts."""

import logging_config as _logging_config

_logging_config.configure_logging()
