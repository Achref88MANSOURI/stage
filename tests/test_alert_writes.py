"""`tools/thehive.py::add_alert_comment` + `update_alert` — the two
alert-level write primitives added 2026-09-07 for the `false_positive`
branch of `nodes/case_action.py` (annotate the alert, never a case).

PROVENANCE: `tests/fixtures/thehive_alert_writes_real.json` is REAL —
captured live 2026-09-07 against `http://172.20.24.228:9000` (TheHive
5.7.5), alert `~46149872`. It holds the real
`POST /api/v1/alert/{id}/comment` response (201, a Comment object) and the
real `PATCH /api/v1/alert/{id}` response (204, empty body). The mocked tests
below are built from those shapes, not imagined ones.
"""

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx

from tools.thehive import add_alert_comment, update_alert

FIXTURE = Path(__file__).parent / "fixtures" / "thehive_alert_writes_real.json"
REAL = json.loads(FIXTURE.read_text())


def run(coro):
    import asyncio

    return asyncio.run(coro)


class TestRealCapturedShapes:
    def test_comment_endpoint_returned_201_with_a_comment_object(self):
        assert REAL["comment_status"] == 201
        assert REAL["comment_response"]["_type"] == "Comment"
        assert "message" in REAL["comment_response"]

    def test_patch_endpoint_returned_204_no_body(self):
        assert REAL["patch_status"] == 204
        assert REAL["patch_body"] == ""


class TestAddAlertComment:
    def test_happy_path(self):
        with patch("tools.thehive._write", new_callable=AsyncMock) as mock_write:
            mock_write.return_value = MagicMock()
            ok, gap = run(add_alert_comment("~a1", "triage narrative"))
        assert ok is True and gap is None
        method, path, _timeout, body = mock_write.call_args[0]
        assert method == "POST"
        assert path == "/api/v1/alert/~a1/comment"
        assert body == {"message": "triage narrative"}

    def test_missing_id_or_empty_comment_short_circuits(self):
        with patch("tools.thehive._write", new_callable=AsyncMock) as mock_write:
            ok, gap = run(add_alert_comment("", "x"))
            assert ok is False and gap is not None
            ok, gap = run(add_alert_comment("~a1", ""))
            assert ok is False and gap is not None
            mock_write.assert_not_called()

    def test_http_error_becomes_a_gap_not_an_exception(self):
        with patch("tools.thehive._write", new_callable=AsyncMock) as mock_write:
            mock_write.side_effect = httpx.HTTPStatusError(
                "500", request=MagicMock(), response=MagicMock(status_code=500, text="boom")
            )
            ok, gap = run(add_alert_comment("~a1", "x"))
        assert ok is False
        assert gap is not None and gap.tool == "add_alert_comment"


class TestUpdateAlert:
    def test_sends_only_the_fields_given(self):
        with patch("tools.thehive._write", new_callable=AsyncMock) as mock_write:
            mock_write.return_value = MagicMock()
            ok, gap = run(update_alert("~a1", severity=1, tlp=0))
        assert ok is True and gap is None
        method, path, _timeout, body = mock_write.call_args[0]
        assert method == "PATCH"
        assert path == "/api/v1/alert/~a1"
        assert body == {"severity": 1, "tlp": 0}

    def test_partial_update(self):
        with patch("tools.thehive._write", new_callable=AsyncMock) as mock_write:
            mock_write.return_value = MagicMock()
            run(update_alert("~a1", tlp=4))
        assert mock_write.call_args[0][3] == {"tlp": 4}

    def test_no_fields_is_a_gap(self):
        with patch("tools.thehive._write", new_callable=AsyncMock) as mock_write:
            ok, gap = run(update_alert("~a1"))
            assert ok is False and gap is not None
            mock_write.assert_not_called()

    def test_missing_id_is_a_gap(self):
        ok, gap = run(update_alert("", severity=1))
        assert ok is False and gap is not None

    def test_http_error_becomes_a_gap(self):
        with patch("tools.thehive._write", new_callable=AsyncMock) as mock_write:
            mock_write.side_effect = httpx.ConnectError("refused")
            ok, gap = run(update_alert("~a1", severity=1))
        assert ok is False
        assert gap is not None and gap.tool == "update_alert"
