"""Case-action output contract. This service writes to TheHive directly —
creating or merging cases, and annotating false-positive alerts — rather
than leaving case mutation to an external workflow. See
`stages/case_action.py`'s module docstring for the write behavior.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from schemas.verdict import ActionableObservable


class CaseActionResult(BaseModel):
    success: bool
    # What this node actually did: "new_case" / "merge" (a case was created
    # or merged into), or "fp_alert" — a `false_positive` verdict is
    # annotated onto the alert in place (comment + severity/tlp) and no case
    # is touched. Empty on an early failure.
    action_taken: str = ""
    case_id: str = ""
    case_number: int | None = None
    is_new_case: bool = False
    severity: int | None = None  # TheHive's 1-4 scale, as actually written
    tlp: int | None = None  # TheHive's 0-4 scale, as actually written
    stage: str | None = None
    status: str | None = None
    tags: list[str] = Field(default_factory=list)
    comment_added: bool = False
    observables_written: int = 0
    observables_failed: int = 0
    # The Markdown written to TheHive — the new case's description, or the
    # merge comment body. Surfaced here so the /triage caller has it without
    # a follow-up read. Empty only on the failure paths.
    case_narrative: str = ""
    # The verdict's actionable_observables, enriched with each item's real
    # TheHive observable_id (reused if it already existed on the case,
    # created otherwise). observables_written/_failed above count against
    # this list.
    actionable_observables_written: list[ActionableObservable] = Field(default_factory=list)
    # Set only on failure — this stage never raises, so a failed write shows
    # up here rather than as an exception. The alert itself was still
    # triaged; only the case write failed.
    error: str | None = None
