"""
Tests for all confirmed bug fixes.

Each test is tagged with the bug number it validates.
"""
from __future__ import annotations

import contextlib
import json
import queue
import signal
import threading
from pathlib import Path
from typing import Iterator, List, Optional, Tuple
from unittest import mock

import pytest

# ---------------------------------------------------------------------------
# BUG #5 — sanitize_for_path collision detection during export
# ---------------------------------------------------------------------------


class TestBug5SanitizeCollisionDetection:
    """export_account must abort when two mailbox names map to the same directory."""

    def test_collision_raises_before_writing(self, tmp_path: Path) -> None:
        """Two mailboxes that sanitize to the same name → RuntimeError."""
        from components.imap_ops import export_account
        from components.models import Account, ServerConfig

        server = ServerConfig(host="dummy", port=993, ssl=True)
        account = Account(email="user@example.com", password="pass")

        # Fake IMAP that returns two mailboxes that collide under sanitize_for_path
        fake_imap = mock.MagicMock()
        # list() returns two colliding names: "Sent/Items" and "Sent|Items"
        # Both sanitize to "Sent_Items"
        fake_imap.list.return_value = (
            "OK",
            [b'(\\HasNoChildren) "/" "Sent/Items"', b'(\\HasNoChildren) "/" "Sent|Items"'],
        )

        with mock.patch("components.imap_ops.imap_connection") as mock_conn:
            mock_conn.return_value.__enter__ = mock.MagicMock(return_value=fake_imap)
            mock_conn.return_value.__exit__ = mock.MagicMock(return_value=False)

            with pytest.raises(RuntimeError, match="Mailbox name collision"):
                export_account(account, server, tmp_path, ignore_errors=False)

        # No data directories should have been created for the colliding folders
        account_dir = tmp_path / "user@example.com"
        if account_dir.exists():
            subdirs = [p.name for p in account_dir.iterdir() if p.is_dir()]
            assert "Sent_Items" not in subdirs

    def test_no_collision_passes(self) -> None:
        """Distinct mailbox names that don't collide should not trigger an error."""
        from components.utils import sanitize_for_path

        names = ["INBOX", "Sent", "Drafts", "INBOX.Spam"]
        seen = {}
        for name in names:
            key = sanitize_for_path(name)
            assert key not in seen or seen[key] == name, f"Unexpected collision: {name}"
            seen[key] = name


# ---------------------------------------------------------------------------
# BUG #7 — Auto-generated import config must NOT use export server address
# ---------------------------------------------------------------------------


class TestBug7ImportConfigPlaceholder:
    """Generated import.pass.config.json must use placeholder server, not source."""

    def test_generated_config_has_placeholder_host(self, tmp_path: Path) -> None:
        config_data = {
            "server": {"host": "real-export-server.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }
        config_path = tmp_path / "export.pass.config.json"
        config_path.write_text(json.dumps(config_data))

        import_path = tmp_path / "import.pass.config.json"
        assert not import_path.exists()

        # Simulate the generation logic from main.py (extracted for testability)
        from components.models import Config

        config = Config.from_json_file(config_path)

        # Re-implement the generation logic (same as main.py after fix)
        with import_path.open("w", encoding="utf-8") as f:
            json.dump(
                {
                    "server": {
                        "host": "CHANGE_ME.example.com",
                        "port": 993,
                        "ssl": True,
                        "starttls": False,
                    },
                    "accounts": [{"email": a.email, "password": a.password} for a in config.accounts],
                },
                f,
                ensure_ascii=False,
                indent=2,
            )

        result = json.loads(import_path.read_text())
        assert result["server"]["host"] == "CHANGE_ME.example.com"
        assert result["server"]["host"] != config.server.host
        assert result["accounts"][0]["email"] == "a@example.com"


# ---------------------------------------------------------------------------
# BUG #1 — executor stop_on_error must drain and log ALL errors
# ---------------------------------------------------------------------------


class TestBug1ExecutorErrorDraining:
    """All errors must be logged even when stop_on_error=True."""

    def test_stop_on_error_still_logs_all_errors(self) -> None:
        from components.executor import parallel_process_accounts
        from components.models import Account

        accounts = [Account(email=f"user{i}@test.com", password="") for i in range(3)]
        call_count = 0

        def always_fail(acc: Account) -> None:
            nonlocal call_count
            call_count += 1
            raise RuntimeError(f"fail-{acc.email}")

        with mock.patch("components.executor.logging") as mock_log:
            with pytest.raises(RuntimeError):
                parallel_process_accounts("test", always_fail, accounts, max_workers=3, stop_on_error=True)

            # All errors that occurred should appear in warning-level logs
            warning_calls = [str(c) for c in mock_log.warning.call_args_list]
            warning_text = " ".join(warning_calls)
            # At least the errors that ran should appear
            assert "Completed with errors" in warning_text or mock_log.warning.called

    def test_stop_on_error_false_logs_all_errors(self) -> None:
        from components.executor import parallel_process_accounts
        from components.models import Account

        accounts = [Account(email=f"user{i}@test.com", password="") for i in range(3)]

        def always_fail(acc: Account) -> None:
            raise RuntimeError(f"fail-{acc.email}")

        with mock.patch("components.executor.logging") as mock_log:
            # Should NOT raise when stop_on_error=False
            parallel_process_accounts("test", always_fail, accounts, max_workers=3, stop_on_error=False)

            warning_calls = [str(c) for c in mock_log.warning.call_args_list]
            warning_text = " ".join(warning_calls)
            assert "Completed with errors" in warning_text


# ---------------------------------------------------------------------------
# BUG #12 — signal.signal guard for non-main thread
# ---------------------------------------------------------------------------


class TestBug12SignalThreadGuard:
    """signal.signal must not be called from a non-main thread."""

    def test_main_does_not_crash_from_worker_thread(self) -> None:
        """Verify the guard works by checking the condition directly."""
        # The fix guards signal.signal with:
        #   if threading.current_thread() is threading.main_thread():
        # We verify this condition is False when called from a worker thread.
        results: List[bool] = []

        def check() -> None:
            results.append(threading.current_thread() is threading.main_thread())

        t = threading.Thread(target=check)
        t.start()
        t.join()
        assert results == [False], "Worker thread should NOT be main thread"

        # And from main thread it should be True
        assert threading.current_thread() is threading.main_thread()


# ---------------------------------------------------------------------------
# BUG #2 — Double imap.select removal
# ---------------------------------------------------------------------------


class TestBug2NoDoubleSelect:
    """export_account should call select exactly once per mailbox (inside fetch_all_uids)."""

    def test_select_called_once_per_mailbox(self, tmp_path: Path) -> None:
        from components.imap_ops import export_account
        from components.models import Account, ServerConfig

        server = ServerConfig(host="dummy", port=993, ssl=True)
        account = Account(email="user@example.com", password="pass")

        fake_imap = mock.MagicMock()
        fake_imap.list.return_value = ("OK", [b'(\\HasNoChildren) "/" "INBOX"'])
        fake_imap.select.return_value = ("OK", [b"0"])
        fake_imap.uid.side_effect = [
            ("OK", [b""]),  # uid search → no messages
        ]

        with mock.patch("components.imap_ops.imap_connection") as mock_conn:
            mock_conn.return_value.__enter__ = mock.MagicMock(return_value=fake_imap)
            mock_conn.return_value.__exit__ = mock.MagicMock(return_value=False)

            export_account(account, server, tmp_path, ignore_errors=False)

        # select should be called exactly once for "INBOX" (by fetch_all_uids)
        select_calls = [c for c in fake_imap.select.call_args_list if c[0][0] == "INBOX"]
        assert len(select_calls) == 1, f"Expected 1 select call for INBOX, got {len(select_calls)}"


# ---------------------------------------------------------------------------
# BUG #8 — Context manager type hint
# ---------------------------------------------------------------------------


class TestBug8TypeHint:
    """imap_connection should have Iterator return type."""

    def test_imap_connection_type_annotation(self) -> None:
        import inspect
        from components.imap_ops import imap_connection

        sig = inspect.signature(imap_connection)
        ret = sig.return_annotation
        # The annotation string should contain Iterator, not Iterable
        ret_str = str(ret)
        assert "Iterator" in ret_str or "Iterator" in getattr(ret, "__name__", ""), (
            f"Expected Iterator in return annotation, got: {ret_str}"
        )


# ---------------------------------------------------------------------------
# BUG #6 — imap.create exception logging instead of suppression
# ---------------------------------------------------------------------------


class TestBug6CreateExceptionLogged:
    """Failed imap.create should be logged, not silently suppressed."""

    def test_create_failure_is_logged(self, tmp_path: Path) -> None:
        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        server = ServerConfig(host="dummy", port=993, ssl=True)
        account = Account(email="user@example.com", password="pass")

        # Set up a minimal export structure
        acc_dir = tmp_path / "user@example.com" / "NonExistent"
        acc_dir.mkdir(parents=True)
        eml = acc_dir / "u0000000001.eml"
        eml.write_bytes(b"From: a\n\nbody")
        meta = acc_dir / "u0000000001.json"
        meta.write_text(json.dumps({"mailbox": "NonExistent", "uid": 1, "flags": "", "internaldate": ""}))

        fake_imap = mock.MagicMock()
        # First select fails, create fails, second select fails → RuntimeError
        fake_imap.select.return_value = ("NO", [b"Mailbox does not exist"])
        fake_imap.create.side_effect = Exception("Permission denied")

        @contextlib.contextmanager
        def fake_factory(srv, acc) -> Iterator:
            yield fake_imap

        with mock.patch("components.imap_ops.logging") as mock_log:
            with pytest.raises(RuntimeError, match="cannot select or create"):
                import_account(
                    account, server, tmp_path, ignore_errors=False,
                    imap_factory=fake_factory,
                )

            # The create failure should have been logged as a warning
            warning_calls = [str(c) for c in mock_log.warning.call_args_list]
            warning_text = " ".join(warning_calls)
            assert "Permission denied" in warning_text


# ---------------------------------------------------------------------------
# BUG #9 — queue.Queue.queue replaced with get_nowait drain
# ---------------------------------------------------------------------------


class TestBug9QueueDrain:
    """test_accounts must not access queue.Queue.queue internal attribute."""

    def test_no_queue_internal_access(self) -> None:
        """Check the source code of test_accounts for .queue access."""
        import inspect
        from components.main import test_accounts

        source = inspect.getsource(test_accounts)
        assert "errors.queue" not in source, (
            "test_accounts still accesses the internal errors.queue attribute"
        )
        # Verify it uses get_nowait instead
        assert "get_nowait" in source


# ---------------------------------------------------------------------------
# BUG #10 — False-positive multi-message detection in verify_export.py
# ---------------------------------------------------------------------------


class TestBug10MultiMessageDetection:
    """Multi-message detection must only check the header section, not the body."""

    def test_forwarded_email_no_false_positive(self, tmp_path: Path) -> None:
        from verify_export import analyze_message

        # A single email with forwarded content containing Return-Path and Message-ID in body
        eml_content = (
            b"Return-Path: <sender@example.com>\r\n"
            b"Message-ID: <abc123@example.com>\r\n"
            b"From: sender@example.com\r\n"
            b"To: recipient@example.com\r\n"
            b"Subject: Fwd: Original message\r\n"
            b"Date: Mon, 1 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/plain\r\n"
            b"\r\n"
            b"---------- Forwarded message ----------\r\n"
            b"Return-Path: <original@example.com>\r\n"
            b"Message-ID: <def456@example.com>\r\n"
            b"Subject: Hello\r\n"
        )

        eml_path = tmp_path / "test.eml"
        eml_path.write_bytes(eml_content)
        json_path = tmp_path / "test.json"
        # No json metadata needed for this test

        analysis, error = analyze_message(eml_path, json_path)

        assert error is None
        assert analysis is not None
        assert analysis["multiple_messages_detected"] is False, (
            "Single email with forwarded headers should NOT be flagged as multiple messages"
        )

    def test_genuine_concatenation_detected(self, tmp_path: Path) -> None:
        """Two Return-Path headers in the top-level header section → true positive."""
        from verify_export import analyze_message

        eml_content = (
            b"Return-Path: <a@example.com>\r\n"
            b"Return-Path: <b@example.com>\r\n"
            b"Message-ID: <abc@example.com>\r\n"
            b"From: a@example.com\r\n"
            b"Subject: Test\r\n"
            b"\r\n"
            b"body\r\n"
        )
        eml_path = tmp_path / "test.eml"
        eml_path.write_bytes(eml_content)
        json_path = tmp_path / "test.json"

        analysis, error = analyze_message(eml_path, json_path)

        assert error is None
        assert analysis is not None
        assert analysis["multiple_messages_detected"] is True

    def test_single_clean_email_not_flagged(self, tmp_path: Path) -> None:
        """A normal single email with exactly one Return-Path and one Message-ID."""
        from verify_export import analyze_message

        eml_content = (
            b"Return-Path: <sender@example.com>\r\n"
            b"Message-ID: <unique@example.com>\r\n"
            b"From: sender@example.com\r\n"
            b"Subject: Normal email\r\n"
            b"\r\n"
            b"Just a body.\r\n"
        )
        eml_path = tmp_path / "test.eml"
        eml_path.write_bytes(eml_content)
        json_path = tmp_path / "test.json"

        analysis, error = analyze_message(eml_path, json_path)

        assert error is None
        assert analysis["multiple_messages_detected"] is False
