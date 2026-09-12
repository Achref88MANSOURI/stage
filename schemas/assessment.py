"""Shared building-block models composed by `schemas/verdict.py::TriageVerdict`,
the triage LLM call's output contract.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel


class MitreMapping(BaseModel):
    """One MITRE ATT&CK technique the LLM has confirmed against the evidence."""

    technique_id: str
    technique_name: str = ""
    tactic: str = ""
    confidence: Literal["high", "medium", "low"]
    basis: str = ""


class CorrelationDecision(BaseModel):
    """Whether this alert should open a new case or merge into an existing one."""

    action: Literal["new", "merge"]
    merge_into_case_id: str | None = None
    kill_chain_progression_detected: bool = False
    reasoning: str = ""


class EvidenceSource(BaseModel):
    """One gathered evidence source's status. "Empty" (checked, found
    nothing) and "missing" (couldn't check) are kept distinct, since only
    the latter is a reliability gap."""

    source_name: str
    status: Literal["present", "empty", "missing"]
    impact_on_triage: str


class EvidenceSituation(BaseModel):
    """The LLM's assessment of the evidence it was given. `sources` covers
    the 5 gathered evidence sources (`fp_signal`, `rule_context`,
    `open_cases`, `asset_context`, `opencti_enrichment`); Cortex results are
    assessed too but have no dedicated slot, since they arrive as a property
    on the alert rather than a separate gathered result.

    `overall_evidence_reliability` sets a floor on priority: "low" rules out
    P4/P5, enforced both by the prompt and, as a backstop, by
    `stages/triage.py::_apply_safety_backstop`. `analyst_must_verify` is the
    model's list of manual follow-ups, which must also appear in
    `TriageVerdict.investigation_gaps`."""

    sources: list[EvidenceSource]
    overall_evidence_reliability: Literal["high", "medium", "low"]
    analyst_must_verify: list[str]
