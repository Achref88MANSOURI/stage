"""Deterministic backend tools for evidence gathering and RAG retrieval.

Every function here is a fixed, named async call. There is no dynamic tool
registry and no LLM-driven tool selection anywhere in this system.
"""

import logging_config as _logging_config

_logging_config.configure_logging()
