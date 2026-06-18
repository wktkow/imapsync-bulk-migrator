"""
Tests for all confirmed bug fixes.

Each test is tagged with the bug number it validates.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import queue
import signal
import subprocess
import threading
from pathlib import Path
from typing import Iterator, List, Optional, Tuple
from unittest import mock

import pytest


def _write_legacy_message_fixture(
    folder: Path,
    *,
    uid: int = 1,
    mailbox: str = "INBOX",
    data: bytes = b"From: a\r\nTo: b\r\n\r\nbody",
    source_server=None,
) -> Path:
    from components.imap_ops import legacy_server_endpoint, legacy_server_endpoint_digest
    from components.models import ServerConfig

    source_server = source_server or ServerConfig(host="imap.example.com", port=993, ssl=True, starttls=False)
    folder.mkdir(parents=True, exist_ok=True)
    eml = folder / f"u{uid:010d}.eml"
    eml.write_bytes(data)
    eml.with_suffix(".json").write_text(json.dumps({
        "mailbox": mailbox,
        "uid": uid,
        "flags": "\\Seen",
        "internaldate": "01-Jan-2024 00:00:00 +0000",
        "rfc822_size": len(data),
        "content_sha256": hashlib.sha256(data).hexdigest(),
    }))
    account_dir = folder.parent
    state_path = account_dir / "export-state.json"
    state = {
        "schema_version": 1,
        "account": account_dir.name,
        "source_server": legacy_server_endpoint(source_server),
        "source_server_sha256": legacy_server_endpoint_digest(source_server),
        "complete": True,
        "completed_at": 0,
        "mailboxes": [],
    }
    if state_path.exists():
        state = json.loads(state_path.read_text())
    state.setdefault("source_server", legacy_server_endpoint(source_server))
    state.setdefault("source_server_sha256", legacy_server_endpoint_digest(source_server))
    mailboxes = [entry for entry in state.get("mailboxes", []) if isinstance(entry, dict) and entry.get("path") != folder.name]
    mailboxes.append({
        "mailbox": mailbox,
        "path": folder.name,
        "message_count": len(list(folder.glob("*.eml"))),
    })
    state["mailboxes"] = mailboxes
    state_path.write_text(json.dumps(state))
    return eml

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

    def test_export_mode_generates_import_config_template_with_placeholder(self, tmp_path: Path) -> None:
        from components.main import main

        config_path = tmp_path / "export.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "real-export-server.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))
        import_path = tmp_path / "import.pass.config.json"

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.main.export_account"):
            rc = main([
                "--mode", "export",
                "--config", str(config_path),
                "--output-dir", str(tmp_path / "exported"),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--no-connectivity-test",
                "--no-audit-after-export",
            ])

        assert rc == 0
        result = json.loads(import_path.read_text())
        assert result["server"]["host"] == "CHANGE_ME.example.com"
        assert result["server"]["host"] != "real-export-server.example.com"
        assert result["source_server"] == {
            "host": "real-export-server.example.com",
            "port": 993,
            "ssl": True,
            "starttls": False,
        }
        assert result["accounts"][0]["email"] == "a@example.com"
        assert import_path.stat().st_mode & 0o777 == 0o600

    def test_generated_config_has_placeholder_host_and_private_permissions(self, tmp_path: Path) -> None:
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
        from components.main import _write_secure_json_file

        _write_secure_json_file(
            import_path,
            {
                "server": {
                    "host": "CHANGE_ME.example.com",
                    "port": 993,
                    "ssl": True,
                    "starttls": False,
                },
                "source_server": {
                    "host": config.server.host,
                    "port": config.server.port,
                    "ssl": config.server.ssl,
                    "starttls": config.server.starttls,
                },
                "accounts": [{"email": a.email, "password": a.password} for a in config.accounts],
            },
        )

        result = json.loads(import_path.read_text())
        assert result["server"]["host"] == "CHANGE_ME.example.com"
        assert result["server"]["host"] != config.server.host
        assert result["source_server"]["host"] == config.server.host
        assert result["accounts"][0]["email"] == "a@example.com"
        assert import_path.stat().st_mode & 0o777 == 0o600


# ---------------------------------------------------------------------------
# BUG #1 — executor stop_on_error must drain and log ALL errors
# ---------------------------------------------------------------------------


class TestBug1ExecutorErrorDraining:
    """All errors must be logged even when stop_on_error=True."""

    def test_stop_on_error_still_logs_all_errors(self) -> None:
        from components.executor import parallel_process_accounts
        from components.models import Account

        accounts = [Account(email=f"user{i}@test.com", password="") for i in range(3)]
        failed_accounts: List[str] = []
        failed_lock = threading.Lock()

        def always_fail(acc: Account) -> None:
            with failed_lock:
                failed_accounts.append(acc.email)
            raise RuntimeError(f"fail-{acc.email}")

        with mock.patch("components.executor.logging") as mock_log:
            with pytest.raises(RuntimeError):
                parallel_process_accounts("test", always_fail, accounts, max_workers=3, stop_on_error=True)

            # All errors that occurred should appear in warning-level logs
            warning_calls = [str(c) for c in mock_log.warning.call_args_list]
            warning_text = " ".join(warning_calls)
            # At least the errors that ran should appear
            assert "Completed with errors" in warning_text or mock_log.warning.called
            for email in failed_accounts:
                assert email in warning_text

    def test_stop_on_error_false_logs_all_errors(self) -> None:
        from components.executor import parallel_process_accounts
        from components.models import Account

        accounts = [Account(email=f"user{i}@test.com", password="") for i in range(3)]

        def always_fail(acc: Account) -> None:
            raise RuntimeError(f"fail-{acc.email}")

        with mock.patch("components.executor.logging") as mock_log:
            with pytest.raises(RuntimeError, match=r"test failed for 3 account\(s\)"):
                parallel_process_accounts("test", always_fail, accounts, max_workers=3, stop_on_error=False)

            warning_calls = [str(c) for c in mock_log.warning.call_args_list]
            warning_text = " ".join(warning_calls)
            assert "Completed with errors" in warning_text

    def test_stop_on_error_does_not_start_queued_accounts(self) -> None:
        from components.executor import parallel_process_accounts
        from components.models import Account

        accounts = [Account(email=f"user{i}@test.com", password="") for i in range(3)]
        started: List[str] = []

        def fail(acc: Account) -> None:
            started.append(acc.email)
            raise RuntimeError(f"fail-{acc.email}")

        with pytest.raises(RuntimeError):
            parallel_process_accounts("test", fail, accounts, max_workers=1, stop_on_error=True)

        assert started == ["user0@test.com"]


# ---------------------------------------------------------------------------
# BUG #12 — signal.signal guard for non-main thread
# ---------------------------------------------------------------------------


class TestBug12SignalThreadGuard:
    """signal.signal must not be called from a non-main thread."""

    def test_main_skips_signal_registration_from_worker_thread(self, tmp_path: Path) -> None:
        from components.main import main

        config_path = tmp_path / "export.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "source_server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))
        input_dir = tmp_path / "exported"
        input_dir.mkdir()
        results: "queue.Queue[int]" = queue.Queue()

        def guarded_signal(*_args) -> None:
            if threading.current_thread() is not threading.main_thread():
                raise AssertionError("signal.signal called from worker thread")

        def run_main() -> None:
            with mock.patch("components.main.check_environment"), \
                mock.patch("components.main.check_free_space_for_path"), \
                mock.patch("components.main.audit_export", return_value=(True, [])), \
                mock.patch("components.main.signal.signal", guarded_signal):
                results.put(main([
                    "--mode", "audit",
                    "--config", str(config_path),
                    "--input-dir", str(input_dir),
                    "--log-dir", str(tmp_path / "logs"),
                    "--min-free-gb", "0",
                    "--max-workers", "1",
                    "--audit-offline",
                ]))

        t = threading.Thread(target=run_main)
        t.start()
        t.join()
        assert results.get_nowait() == 0

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
        state = json.loads((tmp_path / "user@example.com" / "export-state.json").read_text())
        assert state["complete"] is True
        assert state["mailboxes"] == [{"mailbox": "INBOX", "message_count": 0, "path": "INBOX"}]

    def test_export_writes_private_source_bound_staging_artifacts(self, tmp_path: Path) -> None:
        from components.imap_ops import legacy_server_endpoint, legacy_server_endpoint_digest, export_account
        from components.models import Account, ServerConfig

        server = ServerConfig(host="source.example.com", port=993, ssl=True, starttls=False)
        account = Account(email="user@example.com", password="pass")
        data = b"Message-ID: <m@example.com>\r\nFrom: a@example.com\r\nTo: b@example.com\r\n\r\nbody"

        class SingleMessageExportImap:
            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"1"]

            def uid(self, command: str, *args):
                if command == "search":
                    return "OK", [b"1"]
                if command == "fetch":
                    return "OK", [(
                        b'1 (UID 1 FLAGS (\\Seen) INTERNALDATE "01-Jan-2024 00:00:00 +0000")',
                        data,
                    )]
                raise AssertionError(command)

            def logout(self):
                return "OK", []

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[SingleMessageExportImap]:
            yield SingleMessageExportImap()

        with mock.patch("components.imap_ops.imap_connection", fake_connection):
            export_account(account, server, tmp_path, ignore_errors=False)

        account_dir = tmp_path / "user@example.com"
        inbox = account_dir / "INBOX"
        state_path = account_dir / "export-state.json"
        state = json.loads(state_path.read_text())

        assert state["source_server"] == legacy_server_endpoint(server)
        assert state["source_server_sha256"] == legacy_server_endpoint_digest(server)
        assert account_dir.stat().st_mode & 0o777 == 0o700
        assert inbox.stat().st_mode & 0o777 == 0o700
        assert state_path.stat().st_mode & 0o777 == 0o600
        assert (inbox / ".mailbox.json").stat().st_mode & 0o777 == 0o600
        assert (inbox / "u0000000001.eml").stat().st_mode & 0o777 == 0o600
        assert (inbox / "u0000000001.json").stat().st_mode & 0o777 == 0o600


class TestLegacyExportCompleteness:
    """A searched UID must not disappear silently when FETCH lacks a message literal."""

    def test_export_raises_when_fetch_has_no_message_bytes(self, tmp_path: Path) -> None:
        from components.imap_ops import export_account
        from components.models import Account, ServerConfig

        server = ServerConfig(host="dummy", port=993, ssl=True)
        account = Account(email="user@example.com", password="pass")

        fake_imap = mock.MagicMock()
        fake_imap.list.return_value = ("OK", [b'(\\HasNoChildren) "/" "INBOX"'])
        fake_imap.select.return_value = ("OK", [b"1"])
        fake_imap.uid.side_effect = [
            ("OK", [b"1"]),
            ("OK", [b'1 (UID 1 FLAGS (\\Seen) INTERNALDATE "01-Jan-2024 00:00:00 +0000")']),
        ]

        with mock.patch("components.imap_ops.imap_connection") as mock_conn:
            mock_conn.return_value.__enter__ = mock.MagicMock(return_value=fake_imap)
            mock_conn.return_value.__exit__ = mock.MagicMock(return_value=False)

            with pytest.raises(RuntimeError, match="no message bytes"):
                export_account(account, server, tmp_path, ignore_errors=False)

    def test_export_ignore_errors_continues_but_raises_aggregate(self, tmp_path: Path) -> None:
        from components.imap_ops import export_account
        from components.models import Account, ServerConfig

        server = ServerConfig(host="dummy", port=993, ssl=True)
        account = Account(email="user@example.com", password="pass")

        class PartialExportImap:
            def __init__(self) -> None:
                self.selected = ""

            def list(self):
                return "OK", [
                    b'(\\HasNoChildren) "/" "INBOX"',
                    b'(\\HasNoChildren) "/" "Archive"',
                ]

            def select(self, mailbox: str, readonly: bool = False):
                self.selected = mailbox.strip('"')
                return "OK", [b"1"]

            def uid(self, command: str, *args):
                if command == "search":
                    return "OK", [b"1"]
                if command == "fetch" and self.selected == "INBOX":
                    return "NO", [b"fetch failed"]
                if command == "fetch":
                    return "OK", [(
                        b'1 (UID 1 FLAGS (\\Seen) INTERNALDATE "01-Jan-2024 00:00:00 +0000")',
                        b"Message-ID: <archive@example.com>\r\n\r\nbody",
                    )]
                raise AssertionError(command)

            def logout(self):
                return "OK", []

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[PartialExportImap]:
            yield PartialExportImap()

        with mock.patch("components.imap_ops.imap_connection", fake_connection):
            with pytest.raises(RuntimeError, match="legacy export user@example.com failed"):
                export_account(account, server, tmp_path, ignore_errors=True)

        assert (tmp_path / "user@example.com" / "Archive" / "u0000000001.eml").exists()
        state = json.loads((tmp_path / "user@example.com" / "export-state.json").read_text())
        assert state["complete"] is False

    def test_failed_reexport_invalidates_previous_complete_export_state(self, tmp_path: Path) -> None:
        from components.audit import audit_account
        from components.imap_ops import export_account
        from components.models import Account, ServerConfig

        server = ServerConfig(host="dummy", port=993, ssl=True)
        account = Account(email="user@example.com", password="pass")

        class SuccessfulExportImap:
            selected = "INBOX"

            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

            def select(self, mailbox: str, readonly: bool = False):
                self.selected = mailbox.strip('"')
                return "OK", [b"1"]

            def uid(self, command: str, *args):
                if command == "search":
                    return "OK", [b"1"]
                if command == "fetch":
                    return "OK", [(
                        b'1 (UID 1 FLAGS (\\Seen) INTERNALDATE "01-Jan-2024 00:00:00 +0000")',
                        b"Message-ID: <m@example.com>\r\n\r\nbody",
                    )]
                raise AssertionError(command)

            def logout(self):
                return "OK", []

        @contextlib.contextmanager
        def successful_connection(*_args, **_kwargs) -> Iterator[SuccessfulExportImap]:
            yield SuccessfulExportImap()

        with mock.patch("components.imap_ops.imap_connection", successful_connection):
            export_account(account, server, tmp_path, ignore_errors=False)

        state_path = tmp_path / "user@example.com" / "export-state.json"
        assert json.loads(state_path.read_text())["complete"] is True

        class FailedExportImap(SuccessfulExportImap):
            def uid(self, command: str, *args):
                if command == "search":
                    return "OK", [b"1"]
                if command == "fetch":
                    return "NO", [b"failed"]
                raise AssertionError(command)

        @contextlib.contextmanager
        def failed_connection(*_args, **_kwargs) -> Iterator[FailedExportImap]:
            yield FailedExportImap()

        with mock.patch("components.imap_ops.imap_connection", failed_connection):
            with pytest.raises(RuntimeError, match="legacy export user@example.com failed"):
                export_account(account, server, tmp_path, ignore_errors=True)

        assert json.loads(state_path.read_text())["complete"] is False
        _email, issues = audit_account(account, tmp_path, server=None, check_remote=False, require_integrity_metadata=True)
        assert any("export-state is not complete" in issue for issue in issues)


class TestLegacyListParsing:
    """Legacy mailbox discovery should handle RFC-valid literal LIST responses."""

    def test_list_all_mailboxes_accepts_literal_names(self) -> None:
        from components.imap_ops import list_all_mailboxes
        from components.utils import encode_imap_utf7

        fake_imap = mock.MagicMock()
        fake_imap.list.return_value = (
            "OK",
            [(b'(\\HasNoChildren) "/" {13}', encode_imap_utf7("Föld & Team").encode("ascii"))],
        )

        assert list_all_mailboxes(fake_imap) == ["Föld & Team"]


class TestLegacyImportJournal:
    """Legacy import should not blindly duplicate committed local messages on rerun."""

    def _make_export(self, tmp_path: Path) -> Path:
        account_dir = tmp_path / "user@example.com" / "INBOX"
        eml = _write_legacy_message_fixture(
            account_dir,
            data=b"Message-ID: <m@example.com>\r\nFrom: a@example.com\r\nTo: b@example.com\r\n\r\nbody",
        )
        return tmp_path

    def test_cli_import_refuses_source_server_mismatch_before_append(self, tmp_path: Path) -> None:
        from components.main import main

        in_root = self._make_export(tmp_path / "exported")
        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "target.example.com", "port": 993, "ssl": True, "starttls": False},
            "source_server": {"host": "wrong-source.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "user@example.com", "password": "pass"}],
        }))

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.main.import_account") as import_mock:
            rc = main([
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(in_root),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--no-connectivity-test",
            ])

        assert rc == 4
        import_mock.assert_not_called()

    def test_cli_import_requires_explicit_source_server_before_append(self, tmp_path: Path) -> None:
        from components.main import main

        in_root = self._make_export(tmp_path / "exported")
        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "user@example.com", "password": "pass"}],
        }))

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.main.import_account") as import_mock:
            rc = main([
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(in_root),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--no-connectivity-test",
            ])

        assert rc == 4
        import_mock.assert_not_called()

    def test_import_rerun_skips_committed_journal_entry(self, tmp_path: Path) -> None:
        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        in_root = self._make_export(tmp_path)
        account = Account(email="user@example.com", password="pass")
        server = ServerConfig(host="dummy", port=993, ssl=True)

        class MatchingImportImap:
            def __init__(self) -> None:
                self.append_count = 0
                self.has_message = False

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"1" if self.has_message else b"0"]

            def append(self, mailbox: str, flags: str, date_time: str, data: bytes):
                self.append_count += 1
                self.has_message = True
                return "OK", [b""]

            def search(self, charset, *criteria):
                if self.has_message:
                    return "OK", [b"1"]
                return "OK", [b""]

            def fetch(self, *_args, **_kwargs):
                return "OK", [(b"1 (RFC822.SIZE 77 BODY[] {77}", b"Message-ID: <m@example.com>\r\nFrom: a@example.com\r\nTo: b@example.com\r\n\r\nbody")]

            def logout(self):
                return "OK", []

        fake_imap = MatchingImportImap()

        @contextlib.contextmanager
        def fake_factory(*_args, **_kwargs) -> Iterator:
            yield fake_imap

        import_account(account, server, in_root, ignore_errors=False, imap_factory=fake_factory)
        import_account(account, server, in_root, ignore_errors=False, imap_factory=fake_factory)

        assert fake_imap.append_count == 1

    def test_import_rejects_empty_staged_account_directory(self, tmp_path: Path) -> None:
        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        (tmp_path / "user@example.com").mkdir()
        account = Account(email="user@example.com", password="pass")
        server = ServerConfig(host="dummy", port=993, ssl=True)

        with pytest.raises(RuntimeError, match="no mailbox folders"):
            import_account(account, server, tmp_path, ignore_errors=False)

    def test_import_accepts_completed_zero_message_export(self, tmp_path: Path) -> None:
        from components.imap_ops import legacy_server_endpoint, legacy_server_endpoint_digest, import_account
        from components.models import Account, ServerConfig

        server = ServerConfig(host="dummy", port=993, ssl=True)
        folder = tmp_path / "user@example.com" / "INBOX"
        folder.mkdir(parents=True)
        (folder / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": 0}))
        (tmp_path / "user@example.com" / "export-state.json").write_text(json.dumps({
            "schema_version": 1,
            "account": "user@example.com",
            "source_server": legacy_server_endpoint(server),
            "source_server_sha256": legacy_server_endpoint_digest(server),
            "complete": True,
            "completed_at": 0,
            "mailboxes": [{"mailbox": "INBOX", "path": "INBOX", "message_count": 0}],
        }))
        account = Account(email="user@example.com", password="pass")

        class EmptyTarget:
            def __init__(self) -> None:
                self.selected: List[str] = []
                self.appended = 0

            def select(self, mailbox: str, readonly: bool = False):
                self.selected.append(mailbox)
                return "OK", [b"0"]

            def subscribe(self, mailbox: str):
                return "OK", [b""]

            def logout(self):
                return "OK", []

        fake = EmptyTarget()

        @contextlib.contextmanager
        def fake_factory(*_args, **_kwargs) -> Iterator[EmptyTarget]:
            yield fake

        import_account(account, server, tmp_path, ignore_errors=False, imap_factory=fake_factory)

        assert fake.selected == ["INBOX"]
        assert fake.appended == 0

    def test_import_rejects_incomplete_staged_account_with_no_eml_files(self, tmp_path: Path) -> None:
        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        folder = tmp_path / "user@example.com" / "INBOX"
        folder.mkdir(parents=True)
        (folder / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": 0}))
        (tmp_path / "user@example.com" / "export-state.json").write_text(json.dumps({
            "schema_version": 1,
            "account": "user@example.com",
            "complete": False,
            "mailboxes": [{"mailbox": "INBOX", "path": "INBOX", "message_count": 0}],
        }))
        account = Account(email="user@example.com", password="pass")
        server = ServerConfig(host="dummy", port=993, ssl=True)

        with pytest.raises(RuntimeError, match="no staged \\.eml files"):
            import_account(account, server, tmp_path, ignore_errors=False)

    @pytest.mark.parametrize(
        ("extra_marker", "marker_mailbox", "marker_count"),
        [
            (True, "INBOX", 0),
            (False, "Archive", 0),
            (False, "INBOX", 1),
        ],
    )
    def test_import_rejects_unproven_zero_message_marker_state(
        self,
        tmp_path: Path,
        extra_marker: bool,
        marker_mailbox: str,
        marker_count: int,
    ) -> None:
        from components.imap_ops import legacy_server_endpoint, legacy_server_endpoint_digest, import_account
        from components.models import Account, ServerConfig

        server = ServerConfig(host="dummy", port=993, ssl=True)
        folder = tmp_path / "user@example.com" / "INBOX"
        folder.mkdir(parents=True)
        (folder / ".mailbox.json").write_text(json.dumps({"mailbox": marker_mailbox, "message_count": marker_count}))
        if extra_marker:
            extra = tmp_path / "user@example.com" / "Extra"
            extra.mkdir()
            (extra / ".mailbox.json").write_text(json.dumps({"mailbox": "Extra", "message_count": 0}))
        (tmp_path / "user@example.com" / "export-state.json").write_text(json.dumps({
            "schema_version": 1,
            "account": "user@example.com",
            "source_server": legacy_server_endpoint(server),
            "source_server_sha256": legacy_server_endpoint_digest(server),
            "complete": True,
            "completed_at": 0,
            "mailboxes": [{"mailbox": "INBOX", "path": "INBOX", "message_count": 0}],
        }))
        account = Account(email="user@example.com", password="pass")

        with pytest.raises(RuntimeError, match="no staged \\.eml files"):
            import_account(account, server, tmp_path, ignore_errors=False)

    def test_import_rejects_pending_journal_entry(self, tmp_path: Path) -> None:
        from components.imap_ops import _legacy_import_key, _legacy_import_target_id, import_account
        from components.models import Account, ServerConfig

        in_root = self._make_export(tmp_path)
        account_dir = in_root / "user@example.com"
        eml = account_dir / "INBOX" / "u0000000001.eml"
        data = eml.read_bytes()
        key = _legacy_import_key(account_dir, eml, "INBOX", data)
        account = Account(email="user@example.com", password="pass")
        server = ServerConfig(host="dummy", port=993, ssl=True)
        target_id = _legacy_import_target_id(server, account)
        fake_imap = mock.MagicMock()
        fake_imap.select.return_value = ("OK", [b""])
        (account_dir / "import.journal.jsonl").write_text(json.dumps({
            "key": key,
            "status": "pending",
            "target": target_id,
            "mailbox": "INBOX",
            "path": "INBOX/u0000000001.eml",
        }) + "\n")

        @contextlib.contextmanager
        def fake_factory(*_args, **_kwargs) -> Iterator:
            yield fake_imap

        with pytest.raises(RuntimeError, match="pending append"):
            import_account(account, server, in_root, ignore_errors=False, imap_factory=fake_factory)

    def test_import_ignore_errors_continues_but_raises_aggregate(self, tmp_path: Path) -> None:
        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        account_dir = tmp_path / "user@example.com"
        for mailbox in ("Bad", "Good"):
            folder = account_dir / mailbox
            folder.mkdir(parents=True)
            eml = folder / "u0000000001.eml"
            eml.write_bytes(f"Message-ID: <{mailbox.lower()}@example.com>\r\n\r\nbody".encode("ascii"))
            eml.with_suffix(".json").write_text(json.dumps({
                "mailbox": mailbox,
                "uid": 1,
                "flags": "",
                "internaldate": "",
            }))

        server = ServerConfig(host="dummy", port=993, ssl=True)
        account = Account(email="user@example.com", password="pass")

        class PartialImportImap:
            def __init__(self) -> None:
                self.appended: List[str] = []

            def _normalize(self, mailbox: str) -> str:
                return mailbox.strip('"').replace(r"\"", '"')

            def select(self, mailbox: str, readonly: bool = False):
                selected = self._normalize(mailbox)
                return ("NO", [b"missing"]) if selected == "Bad" else ("OK", [b""])

            def create(self, mailbox: str):
                return "NO", [b"cannot create"]

            def append(self, mailbox: str, flags: str, date_time: str, data: bytes):
                self.appended.append(self._normalize(mailbox))
                return "OK", [b""]

            def logout(self):
                return "OK", []

        fake = PartialImportImap()

        @contextlib.contextmanager
        def fake_factory(*_args, **_kwargs) -> Iterator[PartialImportImap]:
            yield fake

        with pytest.raises(RuntimeError, match="legacy import user@example.com failed"):
            import_account(account, server, tmp_path, ignore_errors=True, imap_factory=fake_factory)

        assert fake.appended == ["Good"]

    def test_import_ignores_committed_journal_from_different_target(self, tmp_path: Path) -> None:
        from components.imap_ops import _legacy_import_key, _legacy_import_target_id, import_account
        from components.models import Account, ServerConfig

        in_root = self._make_export(tmp_path)
        account_dir = in_root / "user@example.com"
        eml = account_dir / "INBOX" / "u0000000001.eml"
        data = eml.read_bytes()
        key = _legacy_import_key(account_dir, eml, "INBOX", data)
        account = Account(email="user@example.com", password="pass")
        old_server = ServerConfig(host="old-target.example.com", port=993, ssl=True)
        new_server = ServerConfig(host="new-target.example.com", port=993, ssl=True)
        (account_dir / "import.journal.jsonl").write_text(json.dumps({
            "key": key,
            "status": "committed",
            "target": _legacy_import_target_id(old_server, account),
            "mailbox": "INBOX",
            "path": "INBOX/u0000000001.eml",
        }) + "\n")
        fake_imap = mock.MagicMock()
        fake_imap.select.return_value = ("OK", [b""])
        fake_imap.append.return_value = ("OK", [b""])

        @contextlib.contextmanager
        def fake_factory(*_args, **_kwargs) -> Iterator:
            yield fake_imap

        import_account(account, new_server, in_root, ignore_errors=False, imap_factory=fake_factory)

        assert fake_imap.append.call_count == 1

    def test_import_repairs_stale_committed_journal_for_current_target(self, tmp_path: Path) -> None:
        from components.imap_ops import _legacy_import_key, _legacy_import_target_id, import_account
        from components.models import Account, ServerConfig

        in_root = self._make_export(tmp_path)
        account_dir = in_root / "user@example.com"
        eml = account_dir / "INBOX" / "u0000000001.eml"
        data = eml.read_bytes()
        key = _legacy_import_key(account_dir, eml, "INBOX", data)
        account = Account(email="user@example.com", password="pass")
        server = ServerConfig(host="target.example.com", port=993, ssl=True)
        (account_dir / "import.journal.jsonl").write_text(json.dumps({
            "key": key,
            "status": "committed",
            "target": _legacy_import_target_id(server, account),
            "mailbox": "INBOX",
            "path": "INBOX/u0000000001.eml",
        }) + "\n")

        class EmptyThenAppendedImap:
            def __init__(self) -> None:
                self.append_count = 0
                self.has_message = False

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"1" if self.has_message else b"0"]

            def search(self, charset, *criteria):
                if self.has_message:
                    return "OK", [b"1"]
                return "OK", [b""]

            def fetch(self, *_args, **_kwargs):
                return "OK", [(b"1 (RFC822.SIZE 77 BODY[] {77}", data)]

            def append(self, mailbox: str, flags: str, date_time: str, payload: bytes):
                self.append_count += 1
                self.has_message = True
                return "OK", [b""]

            def logout(self):
                return "OK", []

        fake_imap = EmptyThenAppendedImap()

        @contextlib.contextmanager
        def fake_factory(*_args, **_kwargs) -> Iterator[EmptyThenAppendedImap]:
            yield fake_imap

        import_account(account, server, in_root, ignore_errors=False, imap_factory=fake_factory)

        assert fake_imap.append_count == 1
        journal = (account_dir / "import.journal.jsonl").read_text()
        assert journal.count('"status": "committed"') == 2

    def test_import_subscribes_migrated_folder_for_roundcube_visibility(self, tmp_path: Path) -> None:
        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        folder = tmp_path / "user@example.com" / "Projects"
        _write_legacy_message_fixture(
            folder,
            mailbox="Projects",
            data=b"Message-ID: <project@example.com>\r\n\r\nbody",
        )
        account = Account(email="user@example.com", password="pass")
        server = ServerConfig(host="dummy", port=993, ssl=True)

        class SubscribeImportImap:
            def __init__(self) -> None:
                self.created: List[str] = []
                self.subscribed: List[str] = []

            def _normalize(self, mailbox: str) -> str:
                return mailbox.strip('"').replace(r"\"", '"').replace(r"\\", "\\")

            def select(self, mailbox: str, readonly: bool = False):
                selected = self._normalize(mailbox)
                if selected == "Projects" and selected not in self.created:
                    return "NO", [b"missing"]
                return "OK", [b"0"]

            def create(self, mailbox: str):
                self.created.append(self._normalize(mailbox))
                return "OK", [b""]

            def subscribe(self, mailbox: str):
                self.subscribed.append(self._normalize(mailbox))
                return "OK", [b""]

            def append(self, mailbox: str, flags: str, date_time: str, payload: bytes):
                return "OK", [b""]

            def logout(self):
                return "OK", []

        fake_imap = SubscribeImportImap()

        @contextlib.contextmanager
        def fake_factory(*_args, **_kwargs) -> Iterator[SubscribeImportImap]:
            yield fake_imap

        import_account(account, server, tmp_path, ignore_errors=False, imap_factory=fake_factory)

        assert fake_imap.created == ["Projects"]
        assert fake_imap.subscribed == ["Projects"]

    def test_reset_archives_committed_journal_for_same_target_before_import(self, tmp_path: Path) -> None:
        from components.imap_ops import _legacy_import_key, _legacy_import_target_id
        from components.main import main
        from components.models import Account, ServerConfig

        in_root = self._make_export(tmp_path)
        account_dir = in_root / "user@example.com"
        eml = account_dir / "INBOX" / "u0000000001.eml"
        account = Account(email="user@example.com", password="pass")
        server = ServerConfig(host="imap.example.com", port=993, ssl=True)
        key = _legacy_import_key(account_dir, eml, "INBOX", eml.read_bytes())
        (account_dir / "import.journal.jsonl").write_text(json.dumps({
            "key": key,
            "status": "committed",
            "target": _legacy_import_target_id(server, account),
            "mailbox": "INBOX",
            "path": "INBOX/u0000000001.eml",
        }) + "\n")
        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": server.host, "port": server.port, "ssl": server.ssl, "starttls": server.starttls},
            "source_server": {"host": server.host, "port": server.port, "ssl": server.ssl, "starttls": server.starttls},
            "accounts": [{"email": account.email, "password": account.password}],
        }))

        class DummyDirectAdminClient:
            def __init__(self, *_args, **_kwargs) -> None:
                pass

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.main.DirectAdminClient", DummyDirectAdminClient), \
            mock.patch("components.da_ensure.reset_accounts_directadmin", return_value=set()), \
            mock.patch("components.main.import_account") as import_mock:
            rc = main([
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(in_root),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--no-connectivity-test",
                "--auto-provision-da",
                "--reset",
                "--reset-confirm", "imap.example.com",
                "--da-url", "https://panel.example.com:2222",
                "--da-username", "admin",
                "--da-password", "login-key",
            ])

        assert rc == 0
        assert not (account_dir / "import.journal.jsonl").exists()
        assert list(account_dir.glob("import.journal.reset-*.jsonl"))
        import_mock.assert_called_once()

    def test_reset_archives_committed_journal_before_connectivity_failure(self, tmp_path: Path) -> None:
        from components.imap_ops import _legacy_import_key, _legacy_import_target_id
        from components.main import main
        from components.models import Account, ServerConfig

        in_root = self._make_export(tmp_path)
        account_dir = in_root / "user@example.com"
        eml = account_dir / "INBOX" / "u0000000001.eml"
        account = Account(email="user@example.com", password="pass")
        server = ServerConfig(host="imap.example.com", port=993, ssl=True)
        key = _legacy_import_key(account_dir, eml, "INBOX", eml.read_bytes())
        (account_dir / "import.journal.jsonl").write_text(json.dumps({
            "key": key,
            "status": "committed",
            "target": _legacy_import_target_id(server, account),
            "mailbox": "INBOX",
            "path": "INBOX/u0000000001.eml",
        }) + "\n")
        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": server.host, "port": server.port, "ssl": server.ssl, "starttls": server.starttls},
            "source_server": {"host": server.host, "port": server.port, "ssl": server.ssl, "starttls": server.starttls},
            "accounts": [{"email": account.email, "password": account.password}],
        }))

        class DummyDirectAdminClient:
            def __init__(self, *_args, **_kwargs) -> None:
                pass

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.utils.ensure_imapsync_available"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.main.DirectAdminClient", DummyDirectAdminClient), \
            mock.patch("components.da_ensure.reset_accounts_directadmin", return_value=set()), \
            mock.patch("components.main.test_accounts", side_effect=RuntimeError("connectivity failed")), \
            mock.patch("components.main.import_account") as import_mock:
            rc = main([
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(in_root),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--auto-provision-da",
                "--reset",
                "--reset-confirm", "imap.example.com",
                "--da-url", "https://panel.example.com:2222",
                "--da-username", "admin",
                "--da-password", "login-key",
            ])

        assert rc == 3
        assert not (account_dir / "import.journal.jsonl").exists()
        assert list(account_dir.glob("import.journal.reset-*.jsonl"))
        import_mock.assert_not_called()


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


class TestCliAndConfigHardening:
    """Regression coverage for CLI/config validation failures."""

    def test_legacy_config_rejects_string_booleans_and_bad_ports(self, tmp_path: Path) -> None:
        from components.models import Config

        bad_bool = tmp_path / "bad-bool.json"
        bad_bool.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": "false", "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))
        with pytest.raises(ValueError, match="server.ssl"):
            Config.from_json_file(bad_bool)

        bad_port = tmp_path / "bad-port.json"
        bad_port.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 70000, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))
        with pytest.raises(ValueError, match="server.port"):
            Config.from_json_file(bad_port)

        bad_tls_combo = tmp_path / "bad-tls-combo.json"
        bad_tls_combo.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": True},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))
        with pytest.raises(ValueError, match="ssl.*starttls"):
            Config.from_json_file(bad_tls_combo)

    def test_legacy_config_rejects_duplicate_accounts(self, tmp_path: Path) -> None:
        from components.models import Config

        duplicate = tmp_path / "duplicate.json"
        duplicate.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [
                {"email": "A@example.com", "password": "secret-a"},
                {"email": "a@example.com", "password": "secret-b"},
            ],
        }))

        with pytest.raises(ValueError, match="duplicates"):
            Config.from_json_file(duplicate)

    def test_legacy_config_rejects_sanitized_account_path_collisions(self, tmp_path: Path) -> None:
        from components.models import Config

        collision = tmp_path / "collision.json"
        collision.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [
                {"email": "a/b@example.com", "password": "secret-a"},
                {"email": "a_b@example.com", "password": "secret-b"},
            ],
        }))

        with pytest.raises(ValueError, match="path collision"):
            Config.from_json_file(collision)

    def test_legacy_config_parses_source_server_and_rejects_known_provider_hosts(self, tmp_path: Path) -> None:
        from components.models import Config

        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "target.example.com", "port": 993, "ssl": True, "starttls": False},
            "source_server": {"host": "source.example.com", "port": 143, "ssl": False, "starttls": True},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))

        config = Config.from_json_file(config_path)

        assert config.source_server is not None
        assert config.source_server.host == "source.example.com"
        assert config.source_server.port == 143
        assert config.source_server.starttls is True

        bad_server = tmp_path / "bad-server.json"
        bad_server.write_text(json.dumps({
            "server": {"host": "imap.gmail.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))
        with pytest.raises(ValueError, match="known gmail IMAP host"):
            Config.from_json_file(bad_server)

        bad_source = tmp_path / "bad-source.json"
        bad_source.write_text(json.dumps({
            "server": {"host": "target.example.com", "port": 993, "ssl": True, "starttls": False},
            "source_server": {"host": "imap.mail.me.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))
        with pytest.raises(ValueError, match="known icloud IMAP host"):
            Config.from_json_file(bad_source)

    def test_main_rejects_invalid_worker_timeout_and_empty_test(self, tmp_path: Path) -> None:
        from components.main import main

        config_path = tmp_path / "export.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))
        log_dir = tmp_path / "logs"

        base = ["--config", str(config_path), "--log-dir", str(log_dir), "--min-free-gb", "0"]
        assert main(["--mode", "audit", *base, "--max-workers", "0"]) == 2
        assert main(["--mode", "audit", *base, "--imap-timeout", "0"]) == 2
        assert main([
            "--mode", "audit",
            "--config", str(config_path),
            "--log-dir", str(log_dir),
            "--min-free-gb", "nan",
        ]) == 2
        assert main(["--mode", "test", *base, "--no-connectivity-test"]) == 2

    def test_setup_logging_creates_private_log_file(self, tmp_path: Path) -> None:
        from components.main import setup_logging

        log_file = setup_logging(tmp_path / "logs")

        assert log_file.stat().st_mode & 0o777 == 0o600

    def test_legacy_validate_returns_failure_on_account_error(self, tmp_path: Path) -> None:
        from components.main import main

        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))
        input_dir = tmp_path / "exported"
        mailbox_dir = input_dir / "a@example.com" / "INBOX"
        mailbox_dir.mkdir(parents=True)
        (mailbox_dir / "u0000000001.eml").write_bytes(b"Message-ID: <m@example.com>\r\n\r\nbody")

        @contextlib.contextmanager
        def broken_connection(*_args, **_kwargs) -> Iterator:
            raise RuntimeError("login failed")
            yield

        with mock.patch("components.imap_ops.imap_connection", broken_connection):
            rc = main([
                "--mode", "validate",
                "--config", str(config_path),
                "--input-dir", str(input_dir),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--no-connectivity-test",
            ])

        assert rc == 4

    def test_legacy_validate_fails_when_remote_has_folder_missing_locally(self, tmp_path: Path) -> None:
        from components.main import main

        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))
        input_dir = tmp_path / "exported"
        input_dir.mkdir()

        class RemoteOnlyImap:
            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"1"]

            def search(self, charset, *criteria):
                return "OK", [b"1"]

            def logout(self):
                return "OK", []

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[RemoteOnlyImap]:
            yield RemoteOnlyImap()

        with mock.patch("components.imap_ops.imap_connection", fake_connection):
            rc = main([
                "--mode", "validate",
                "--config", str(config_path),
                "--input-dir", str(input_dir),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--no-connectivity-test",
            ])

        assert rc == 4

    def test_legacy_validate_fails_when_counts_match_but_message_identity_is_missing(self, tmp_path: Path) -> None:
        from components.main import main

        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))
        input_dir = tmp_path / "exported"
        mailbox_dir = input_dir / "a@example.com" / "INBOX"
        mailbox_dir.mkdir(parents=True)
        (mailbox_dir / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": 1}))
        (mailbox_dir / "u0000000001.eml").write_bytes(b"Message-ID: <local@example.com>\r\n\r\nbody")
        (mailbox_dir / "u0000000001.json").write_text(json.dumps({"uid": 1, "mailbox": "INBOX"}))

        class CountOnlyMatchImap:
            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"1"]

            def search(self, charset, *criteria):
                if criteria == ("ALL",):
                    return "OK", [b"1"]
                if criteria == ("HEADER", "Message-ID", "<local@example.com>"):
                    return "OK", [b""]
                raise AssertionError(criteria)

            def fetch(self, *_args, **_kwargs):
                raise AssertionError("fetch should not run when Message-ID search misses")

            def logout(self):
                return "OK", []

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[CountOnlyMatchImap]:
            yield CountOnlyMatchImap()

        with mock.patch("components.imap_ops.imap_connection", fake_connection):
            rc = main([
                "--mode", "validate",
                "--config", str(config_path),
                "--input-dir", str(input_dir),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--no-connectivity-test",
            ])

        assert rc == 4

    def test_legacy_validate_consumes_remote_identity_matches_for_duplicates(self, tmp_path: Path) -> None:
        from components.main import main

        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))
        input_dir = tmp_path / "exported"
        mailbox_dir = input_dir / "a@example.com" / "INBOX"
        mailbox_dir.mkdir(parents=True)
        duplicate = b"Message-ID: <dup@example.com>\r\n\r\nbody"
        for uid in (1, 2):
            eml = mailbox_dir / f"u{uid:010d}.eml"
            eml.write_bytes(duplicate)
            eml.with_suffix(".json").write_text(json.dumps({"uid": uid, "mailbox": "INBOX"}))
        (mailbox_dir / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": 2}))

        class DuplicateMismatchRemote:
            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"2"]

            def search(self, charset, *criteria):
                if criteria == ("ALL",):
                    return "OK", [b"1 2"]
                if criteria == ("HEADER", "Message-ID", "<dup@example.com>"):
                    return "OK", [b"1"]
                raise AssertionError(criteria)

            def fetch(self, num: bytes, *_args, **_kwargs):
                if num == b"1":
                    return "OK", [(b"1 (RFC822.SIZE 36 BODY[] {36}", duplicate)]
                return "OK", [(b"2 (RFC822.SIZE 37 BODY[] {37}", b"Message-ID: <other@example.com>\r\n\r\nbody")]

            def logout(self):
                return "OK", []

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[DuplicateMismatchRemote]:
            yield DuplicateMismatchRemote()

        with mock.patch("components.imap_ops.imap_connection", fake_connection):
            rc = main([
                "--mode", "validate",
                "--config", str(config_path),
                "--input-dir", str(input_dir),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--no-connectivity-test",
            ])

        assert rc == 4

    def test_legacy_validate_fails_with_pending_current_target_journal(self, tmp_path: Path) -> None:
        from components.imap_ops import _legacy_import_key, _legacy_import_target_id
        from components.main import main
        from components.models import Account, ServerConfig

        server = ServerConfig(host="imap.example.com", port=993, ssl=True, starttls=False)
        account = Account(email="a@example.com", password="secret")
        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": server.host, "port": server.port, "ssl": server.ssl, "starttls": server.starttls},
            "accounts": [{"email": account.email, "password": account.password}],
        }))
        input_dir = tmp_path / "exported"
        account_dir = input_dir / "a@example.com"
        mailbox_dir = account_dir / "INBOX"
        mailbox_dir.mkdir(parents=True)
        eml = mailbox_dir / "u0000000001.eml"
        eml.write_bytes(b"Message-ID: <m@example.com>\r\n\r\nbody")
        eml.with_suffix(".json").write_text(json.dumps({"uid": 1, "mailbox": "INBOX"}))
        (account_dir / "import.journal.jsonl").write_text(json.dumps({
            "key": _legacy_import_key(account_dir, eml, "INBOX", eml.read_bytes()),
            "target": _legacy_import_target_id(server, account),
            "mailbox": "INBOX",
            "path": "INBOX/u0000000001.eml",
            "status": "pending",
        }) + "\n")

        class MatchingRemote:
            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"1"]

            def search(self, charset, *criteria):
                return "OK", [b"1"]

            def fetch(self, *_args, **_kwargs):
                return "OK", [(b"1 (RFC822.SIZE 36 BODY[] {36}", b"Message-ID: <m@example.com>\r\n\r\nbody")]

            def logout(self):
                return "OK", []

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[MatchingRemote]:
            yield MatchingRemote()

        with mock.patch("components.imap_ops.imap_connection", fake_connection):
            rc = main([
                "--mode", "validate",
                "--config", str(config_path),
                "--input-dir", str(input_dir),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--no-connectivity-test",
            ])

        assert rc == 4

    def test_legacy_validate_allows_remote_empty_folder_missing_locally(self, tmp_path: Path) -> None:
        from components.main import main
        from components.imap_ops import legacy_server_endpoint, legacy_server_endpoint_digest
        from components.models import ServerConfig

        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "source_server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))
        input_dir = tmp_path / "exported"
        inbox = input_dir / "a@example.com" / "INBOX"
        inbox.mkdir(parents=True)
        (inbox / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": 0}))
        source_server = ServerConfig(host="imap.example.com", port=993, ssl=True, starttls=False)
        (input_dir / "a@example.com" / "export-state.json").write_text(json.dumps({
            "schema_version": 1,
            "account": "a@example.com",
            "source_server": legacy_server_endpoint(source_server),
            "source_server_sha256": legacy_server_endpoint_digest(source_server),
            "complete": True,
            "completed_at": 0,
            "mailboxes": [{"mailbox": "INBOX", "path": "INBOX", "message_count": 0}],
        }))

        class EmptyRemoteFolderImap:
            def list(self):
                return "OK", [
                    b'(\\HasNoChildren) "/" "INBOX"',
                    b'(\\HasNoChildren) "/" "Projects"',
                ]

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"0"]

            def search(self, charset, *criteria):
                return "OK", [b""]

            def logout(self):
                return "OK", []

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[EmptyRemoteFolderImap]:
            yield EmptyRemoteFolderImap()

        with mock.patch("components.imap_ops.imap_connection", fake_connection):
            rc = main([
                "--mode", "validate",
                "--config", str(config_path),
                "--input-dir", str(input_dir),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--no-connectivity-test",
            ])

        assert rc == 0

    def test_legacy_validate_fails_when_account_export_dir_is_missing_even_if_remote_empty(self, tmp_path: Path) -> None:
        from components.main import main

        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))
        input_dir = tmp_path / "exported"
        input_dir.mkdir()

        class EmptyRemoteFolderImap:
            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"0"]

            def search(self, charset, *criteria):
                return "OK", [b""]

            def logout(self):
                return "OK", []

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[EmptyRemoteFolderImap]:
            yield EmptyRemoteFolderImap()

        with mock.patch("components.imap_ops.imap_connection", fake_connection):
            rc = main([
                "--mode", "validate",
                "--config", str(config_path),
                "--input-dir", str(input_dir),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--no-connectivity-test",
            ])

        assert rc == 4

    def test_legacy_audit_allows_remote_empty_folder_missing_locally(self, tmp_path: Path) -> None:
        from components.audit import audit_account
        from components.models import Account, ServerConfig

        account = Account(email="a@example.com", password="secret")
        account_dir = tmp_path / "a@example.com"
        inbox = account_dir / "INBOX"
        data = b"Message-ID: <local@example.com>\r\nFrom: a@example.com\r\nTo: b@example.com\r\n\r\nbody"
        _write_legacy_message_fixture(inbox, data=data)

        class EmptyRemoteFolderImap:
            def __init__(self) -> None:
                self.selected = ""

            def list(self):
                return "OK", [
                    b'(\\HasNoChildren) "/" "INBOX"',
                    b'(\\HasNoChildren) "/" "Projects"',
                ]

            def select(self, mailbox: str, readonly: bool = False):
                self.selected = mailbox.strip('"')
                return "OK", [b"1" if self.selected == "INBOX" else b"0"]

            def uid(self, command: str, *args):
                return "OK", [b"1" if self.selected == "INBOX" else b""]

            def search(self, charset, *criteria):
                if self.selected == "INBOX":
                    return "OK", [b"1"]
                return "OK", [b""]

            def fetch(self, *_args, **_kwargs):
                return "OK", [(b"1 (RFC822.SIZE 39 BODY[] {39}", data)]

            def logout(self):
                return "OK", []

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[EmptyRemoteFolderImap]:
            yield EmptyRemoteFolderImap()

        with mock.patch("components.audit.imap_connection", fake_connection):
            _email, issues = audit_account(account, tmp_path, ServerConfig(host="imap.example.com"), check_remote=True)

        assert issues == []

    def test_legacy_resync_missing_does_not_replay_import(self, tmp_path: Path) -> None:
        from components.main import main

        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))
        input_dir = tmp_path / "exported"
        mailbox_dir = input_dir / "a@example.com" / "INBOX"
        mailbox_dir.mkdir(parents=True)
        (mailbox_dir / "u0000000001.eml").write_bytes(b"Message-ID: <m@example.com>\r\n\r\nbody")

        class EmptyRemoteImap:
            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"0"]

            def search(self, charset, *criteria):
                return "OK", [b""]

            def logout(self):
                return "OK", []

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[EmptyRemoteImap]:
            yield EmptyRemoteImap()

        with mock.patch("components.imap_ops.imap_connection", fake_connection):
            with mock.patch("components.main.import_account") as import_mock:
                rc = main([
                    "--mode", "validate",
                    "--config", str(config_path),
                    "--input-dir", str(input_dir),
                    "--log-dir", str(tmp_path / "logs"),
                    "--min-free-gb", "0",
                    "--no-connectivity-test",
                    "--resync-missing",
                ])

        assert rc == 4
        import_mock.assert_not_called()


class TestAuditHardening:
    """Audit should fail empty staged accounts instead of treating them as complete."""

    def test_audit_account_flags_empty_account_directory(self, tmp_path: Path) -> None:
        from components.audit import audit_account
        from components.models import Account

        account = Account(email="a@example.com", password="secret")
        (tmp_path / "a@example.com").mkdir()

        _email, issues = audit_account(account, tmp_path, server=None, check_remote=False)

        assert any("no mailbox folders found" in issue for issue in issues)

    def test_audit_account_flags_local_folder_missing_remotely(self, tmp_path: Path) -> None:
        from components.audit import audit_account
        from components.models import Account, ServerConfig

        account = Account(email="a@example.com", password="secret")
        inbox = tmp_path / "a@example.com" / "INBOX"
        inbox.mkdir(parents=True)
        (inbox / "u0000000001.eml").write_bytes(b"Message-ID: <m@example.com>\r\n\r\nbody")
        (inbox / "u0000000001.json").write_text(json.dumps({"uid": 1}))

        class NoInboxRemote:
            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "Archive"']

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"0"]

            def uid(self, command: str, *args):
                return "OK", [b""]

            def logout(self):
                return "OK", []

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[NoInboxRemote]:
            yield NoInboxRemote()

        with mock.patch("components.audit.imap_connection", fake_connection):
            _email, issues = audit_account(account, tmp_path, ServerConfig(host="imap.example.com"), check_remote=True)

        assert any("missing remotely" in issue for issue in issues)

    def test_audit_account_flags_matching_count_with_missing_remote_identity(self, tmp_path: Path) -> None:
        from components.audit import audit_account
        from components.models import Account, ServerConfig

        account = Account(email="a@example.com", password="secret")
        inbox = tmp_path / "a@example.com" / "INBOX"
        inbox.mkdir(parents=True)
        (inbox / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": 1}))
        (inbox / "u0000000001.eml").write_bytes(b"Message-ID: <local@example.com>\r\n\r\nbody")
        (inbox / "u0000000001.json").write_text(json.dumps({"uid": 1, "mailbox": "INBOX"}))

        class CountMatchWrongIdentityRemote:
            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"1"]

            def uid(self, command: str, *args):
                return "OK", [b"1"]

            def search(self, charset, *criteria):
                if criteria == ("HEADER", "Message-ID", "<local@example.com>"):
                    return "OK", [b""]
                if criteria == ("ALL",):
                    return "OK", [b"1"]
                raise AssertionError(criteria)

            def fetch(self, *_args, **_kwargs):
                raise AssertionError("fetch should not run when Message-ID search misses")

            def logout(self):
                return "OK", []

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[CountMatchWrongIdentityRemote]:
            yield CountMatchWrongIdentityRemote()

        with mock.patch("components.audit.imap_connection", fake_connection):
            _email, issues = audit_account(account, tmp_path, ServerConfig(host="imap.example.com"), check_remote=True)

        assert any("remote message identity missing" in issue for issue in issues)

    def test_audit_account_flags_metadata_mailbox_mismatch(self, tmp_path: Path) -> None:
        from components.audit import audit_account
        from components.models import Account

        account = Account(email="a@example.com", password="secret")
        inbox = tmp_path / "a@example.com" / "INBOX"
        inbox.mkdir(parents=True)
        (inbox / "u0000000001.eml").write_bytes(b"Message-ID: <m@example.com>\r\n\r\nbody")
        (inbox / "u0000000001.json").write_text(json.dumps({"uid": 1, "mailbox": "Trash"}))

        _email, issues = audit_account(account, tmp_path, server=None, check_remote=False)

        assert any("mailbox metadata mismatch" in issue for issue in issues)

    def test_audit_account_flags_mailbox_marker_count_mismatch(self, tmp_path: Path) -> None:
        from components.audit import audit_account
        from components.models import Account

        account = Account(email="a@example.com", password="secret")
        inbox = tmp_path / "a@example.com" / "INBOX"
        inbox.mkdir(parents=True)
        (inbox / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": 2}))
        (inbox / "u0000000001.eml").write_bytes(b"Message-ID: <m@example.com>\r\n\r\nbody")
        (inbox / "u0000000001.json").write_text(json.dumps({"uid": 1, "mailbox": "INBOX"}))

        _email, issues = audit_account(account, tmp_path, server=None, check_remote=False)

        assert any("mailbox marker count mismatch" in issue for issue in issues)

    def test_strict_audit_flags_corrupt_message_metadata(self, tmp_path: Path) -> None:
        from components.audit import audit_account
        from components.models import Account

        account = Account(email="a@example.com", password="secret")
        inbox = tmp_path / "a@example.com" / "INBOX"
        _write_legacy_message_fixture(inbox)
        (inbox / "u0000000001.json").write_text("{")

        _email, issues = audit_account(
            account,
            tmp_path,
            server=None,
            check_remote=False,
            require_integrity_metadata=True,
        )

        assert any("failed to parse message metadata" in issue for issue in issues)

    def test_strict_audit_flags_custom_named_corrupt_message_metadata(self, tmp_path: Path) -> None:
        from components.audit import audit_account
        from components.models import Account

        account = Account(email="a@example.com", password="secret")
        inbox = tmp_path / "a@example.com" / "INBOX"
        inbox.mkdir(parents=True)
        (inbox / "custom.eml").write_bytes(b"From: a\r\nTo: b\r\n\r\nbody")
        (inbox / "custom.json").write_text("{")

        _email, issues = audit_account(
            account,
            tmp_path,
            server=None,
            check_remote=False,
            require_integrity_metadata=True,
        )

        assert any("custom.eml" in issue and "failed to parse message metadata" in issue for issue in issues)

    def test_strict_audit_requires_completed_legacy_export_state(self, tmp_path: Path) -> None:
        from components.audit import audit_account
        from components.models import Account

        account = Account(email="a@example.com", password="secret")
        inbox = tmp_path / "a@example.com" / "INBOX"
        inbox.mkdir(parents=True)
        data = b"From: a\r\nTo: b\r\n\r\nbody"
        eml = inbox / "u0000000001.eml"
        eml.write_bytes(data)
        eml.with_suffix(".json").write_text(json.dumps({
            "mailbox": "INBOX",
            "uid": 1,
            "rfc822_size": len(data),
            "content_sha256": hashlib.sha256(data).hexdigest(),
        }))

        _email, issues = audit_account(
            account,
            tmp_path,
            server=None,
            check_remote=False,
            require_integrity_metadata=True,
        )

        assert any("export-state missing" in issue for issue in issues)

    def test_strict_audit_binds_legacy_export_to_source_server(self, tmp_path: Path) -> None:
        from components.audit import audit_account
        from components.models import Account, ServerConfig

        account = Account(email="a@example.com", password="secret")
        source_server = ServerConfig(host="old.example.com", port=993, ssl=True, starttls=False)
        inbox = tmp_path / "a@example.com" / "INBOX"
        _write_legacy_message_fixture(inbox, source_server=source_server)

        _email, matching_issues = audit_account(
            account,
            tmp_path,
            server=None,
            check_remote=False,
            require_integrity_metadata=True,
            expected_source_server=source_server,
        )
        _email, mismatched_issues = audit_account(
            account,
            tmp_path,
            server=None,
            check_remote=False,
            require_integrity_metadata=True,
            expected_source_server=ServerConfig(host="new.example.com", port=993, ssl=True, starttls=False),
        )

        assert matching_issues == []
        assert any("export-state source_server does not match" in issue for issue in mismatched_issues)
        assert any("export-state source_server_sha256 does not match" in issue for issue in mismatched_issues)

    def test_strict_audit_flags_stale_message_integrity_metadata(self, tmp_path: Path) -> None:
        from components.audit import audit_account
        from components.models import Account

        account = Account(email="a@example.com", password="secret")
        inbox = tmp_path / "a@example.com" / "INBOX"
        eml = _write_legacy_message_fixture(inbox)
        eml.write_bytes(b"From: changed\r\nTo: b\r\n\r\nbody")

        _email, issues = audit_account(
            account,
            tmp_path,
            server=None,
            check_remote=False,
            require_integrity_metadata=True,
        )

        assert any("content_sha256 mismatch" in issue for issue in issues)
        assert any("rfc822_size mismatch" in issue for issue in issues)

    def test_audit_account_flags_trailing_imap_fetch_wrapper(self, tmp_path: Path) -> None:
        from components.audit import audit_account
        from components.models import Account

        account = Account(email="a@example.com", password="secret")
        inbox = tmp_path / "a@example.com" / "INBOX"
        inbox.mkdir(parents=True)
        (inbox / "u0000000001.eml").write_bytes(
            b"From: a@example.com\r\nTo: b@example.com\r\nSubject: ok\r\n\r\nbody\r\n"
            b"1 (FLAGS (\\Seen) INTERNALDATE \"01-Jan-2024 00:00:00 +0000\")"
        )
        (inbox / "u0000000001.json").write_text(json.dumps({"uid": 1, "mailbox": "INBOX"}))

        _email, issues = audit_account(account, tmp_path, server=None, check_remote=False)

        assert any("suspicious raw IMAP metadata" in issue for issue in issues)

    def test_audit_account_accepts_marked_empty_mailbox(self, tmp_path: Path) -> None:
        from components.audit import audit_account
        from components.models import Account

        account = Account(email="a@example.com", password="secret")
        projects = tmp_path / "a@example.com" / "Projects"
        projects.mkdir(parents=True)
        (projects / ".mailbox.json").write_text(json.dumps({"mailbox": "Projects", "message_count": 0}))

        _email, issues = audit_account(account, tmp_path, server=None, check_remote=False)

        assert not issues


class TestDirectAdminIndexerHardening:
    """DirectAdmin indexer secrets and generated config should avoid easy leaks."""

    def test_resolve_password_supports_file_and_rejects_multiple_sources(self, tmp_path: Path) -> None:
        import argparse
        from directadmin_indexer import resolve_password

        secret = tmp_path / "login-key"
        secret.write_text("api-secret\n")

        args = argparse.Namespace(password=None, password_file=str(secret), password_env=None)
        assert resolve_password(args) == "api-secret"

        mixed = argparse.Namespace(password="inline", password_file=str(secret), password_env=None)
        with pytest.raises(ValueError, match="only one source"):
            resolve_password(mixed)

    def test_resolve_password_supports_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import argparse
        from directadmin_indexer import resolve_password

        monkeypatch.setenv("DA_LOGIN_KEY", "env-secret")
        args = argparse.Namespace(password=None, password_file=None, password_env="DA_LOGIN_KEY")

        assert resolve_password(args) == "env-secret"

    def test_resolve_default_password_supports_file_and_environment(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import argparse
        from directadmin_indexer import resolve_default_password

        secret = tmp_path / "mailbox-secret"
        secret.write_text("mail-secret\n")
        assert resolve_default_password(argparse.Namespace(
            default_password="",
            default_password_file=str(secret),
            default_password_env=None,
        )) == "mail-secret"

        monkeypatch.setenv("MAILBOX_SECRET", "env-mail-secret")
        assert resolve_default_password(argparse.Namespace(
            default_password="",
            default_password_file=None,
            default_password_env="MAILBOX_SECRET",
        )) == "env-mail-secret"

    def test_write_json_uses_private_permissions(self, tmp_path: Path) -> None:
        from directadmin_indexer import write_json

        out = tmp_path / "export.pass.config.json"
        write_json({"accounts": []}, str(out), overwrite=False)

        assert out.stat().st_mode & 0o777 == 0o600

    def test_write_json_overwrite_replaces_broad_permissions_atomically(self, tmp_path: Path) -> None:
        from directadmin_indexer import write_json

        out = tmp_path / "export.pass.config.json"
        out.write_text("{}")
        out.chmod(0o644)

        write_json({"accounts": [{"email": "a@example.com", "password": "secret"}]}, str(out), overwrite=True)

        assert out.stat().st_mode & 0o777 == 0o600
        assert json.loads(out.read_text())["accounts"][0]["password"] == "secret"

    def test_indexer_list_pop_accounts_raises_on_api_error(self) -> None:
        from directadmin_indexer import DirectAdminClient

        client = object.__new__(DirectAdminClient)
        client._get = lambda *_args, **_kwargs: (None, {"error": ["1"], "text": ["permission denied"]})

        with pytest.raises(RuntimeError, match="permission denied"):
            client.list_pop_accounts("example.com")

    def test_reset_accounts_does_not_create_after_delete_failure(self) -> None:
        from components.da_ensure import reset_accounts_directadmin
        from components.models import Account, Config, ServerConfig

        class BrokenDeleteClient:
            def __init__(self) -> None:
                self.created = False

            def delete_pop_account(self, domain: str, local_part: str) -> None:
                raise RuntimeError("delete failed")

            def create_pop_account(self, domain: str, local_part: str, password: str, quota_mb: int = 0, *, allow_existing: bool = True) -> None:
                self.created = True

        client = BrokenDeleteClient()
        config = Config(
            server=ServerConfig(host="imap.example.com"),
            accounts=[Account(email="a@example.com", password="secret")],
        )

        failed = reset_accounts_directadmin(config, client, ignore_errors=True)

        assert not client.created
        assert failed == {"a@example.com"}

    def test_directadmin_create_delete_require_parseable_status(self) -> None:
        from components.da_client import DirectAdminClient

        client = object.__new__(DirectAdminClient)
        client._post = lambda *_args, **_kwargs: (None, {})

        with pytest.raises(RuntimeError, match="create response"):
            client.create_pop_account("example.com", "a", "secret")
        with pytest.raises(RuntimeError, match="delete response"):
            client.delete_pop_account("example.com", "a")

    def test_directadmin_delete_only_tolerates_specific_not_found_errors(self) -> None:
        from components.da_client import DirectAdminClient

        client = object.__new__(DirectAdminClient)
        client._post = lambda *_args, **_kwargs: ({"error": "1", "text": "Mailbox does not exist"}, None)
        client.delete_pop_account("example.com", "a")

        client._post = lambda *_args, **_kwargs: ({"error": "1", "text": "Deleted mailbox permission denied"}, None)
        with pytest.raises(RuntimeError, match="permission denied"):
            client.delete_pop_account("example.com", "a")

    def test_directadmin_create_delete_send_documented_parameters(self) -> None:
        from components.da_client import DirectAdminClient

        client = object.__new__(DirectAdminClient)
        get_calls = []
        post_calls = []

        def fake_get(path, params=None):
            get_calls.append((path, dict(params or {})))
            return {"error": "0", "list": ["a", "b"]}, None

        def fake_post(path, data=None):
            post_calls.append((path, dict(data or {})))
            return {"error": "0"}, None

        client._get = fake_get
        client._post = fake_post

        assert client.list_pop_accounts("example.com") == ["a", "b"]
        client.create_pop_account("example.com", "a", "secret", quota_mb=512)
        client.delete_pop_account("example.com", "a")

        assert get_calls == [
            ("CMD_API_POP", {"domain": "example.com", "action": "list"}),
        ]
        assert post_calls == [
            (
                "CMD_API_POP",
                {
                    "action": "create",
                    "domain": "example.com",
                    "user": "a",
                    "passwd": "secret",
                    "passwd2": "secret",
                    "quota": "512",
                    "json": "yes",
                },
            ),
            (
                "CMD_API_POP",
                {
                    "action": "delete",
                    "domain": "example.com",
                    "user": "a",
                    "json": "yes",
                },
            ),
        ]

    def test_import_returns_failure_when_reset_skip_occurs_under_ignore_errors(self, tmp_path: Path) -> None:
        from components.main import main

        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "source_server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [
                {"email": "skip@example.com", "password": "secret"},
                {"email": "ok@example.com", "password": "secret"},
            ],
        }))
        input_dir = tmp_path / "exported"
        for email in ("skip@example.com", "ok@example.com"):
            inbox = input_dir / email / "INBOX"
            _write_legacy_message_fixture(inbox)

        class DummyDirectAdminClient:
            def __init__(self, *_args, **_kwargs) -> None:
                pass

        imported: List[str] = []

        def fake_import_account(acc, *_args, **_kwargs) -> None:
            imported.append(acc.email)

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.main.DirectAdminClient", DummyDirectAdminClient), \
            mock.patch("components.da_ensure.reset_accounts_directadmin", return_value={"skip@example.com"}), \
            mock.patch("components.main.import_account", fake_import_account):
            rc = main([
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(input_dir),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--no-connectivity-test",
                "--auto-provision-da",
                "--reset",
                "--reset-confirm", "imap.example.com",
                "--ignore-errors",
                "--da-url", "https://panel.example.com:2222",
                "--da-username", "admin",
                "--da-password", "login-key",
            ])

        assert rc == 3
        assert imported == ["ok@example.com"]

    def test_import_connectivity_skips_reset_failed_accounts_under_ignore_errors(self, tmp_path: Path) -> None:
        from components.main import main

        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "source_server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [
                {"email": "skip@example.com", "password": "secret"},
                {"email": "ok@example.com", "password": "secret"},
            ],
        }))
        input_dir = tmp_path / "exported"
        for email in ("skip@example.com", "ok@example.com"):
            inbox = input_dir / email / "INBOX"
            _write_legacy_message_fixture(inbox)

        class DummyDirectAdminClient:
            def __init__(self, *_args, **_kwargs) -> None:
                pass

        tested: List[List[str]] = []
        imported: List[str] = []

        def fake_test_accounts(config, *_args, **_kwargs) -> None:
            tested.append([acc.email for acc in config.accounts])

        def fake_import_account(acc, *_args, **_kwargs) -> None:
            imported.append(acc.email)

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.utils.ensure_imapsync_available"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.main.DirectAdminClient", DummyDirectAdminClient), \
            mock.patch("components.da_ensure.reset_accounts_directadmin", return_value={"skip@example.com"}), \
            mock.patch("components.main.test_accounts", fake_test_accounts), \
            mock.patch("components.main.import_account", fake_import_account):
            rc = main([
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(input_dir),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--auto-provision-da",
                "--reset",
                "--reset-confirm", "imap.example.com",
                "--ignore-errors",
                "--da-url", "https://panel.example.com:2222",
                "--da-username", "admin",
                "--da-password", "login-key",
            ])

        assert rc == 3
        assert tested == [["ok@example.com"]]
        assert imported == ["ok@example.com"]

    def test_import_skips_all_accounts_when_reset_setup_fails_under_ignore_errors(self, tmp_path: Path) -> None:
        from components.main import main

        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "source_server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))
        input_dir = tmp_path / "exported" / "a@example.com" / "INBOX"
        _write_legacy_message_fixture(input_dir)

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.main.DirectAdminClient", side_effect=RuntimeError("panel unavailable")), \
            mock.patch("components.main.import_account") as import_mock:
            rc = main([
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(tmp_path / "exported"),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--no-connectivity-test",
                "--auto-provision-da",
                "--reset",
                "--reset-confirm", "imap.example.com",
                "--ignore-errors",
                "--da-url", "https://panel.example.com:2222",
                "--da-username", "admin",
                "--da-password", "login-key",
            ])

        assert rc == 3
        import_mock.assert_not_called()


class TestCPanelProvisioning:
    """cPanel UAPI integration should be explicit, parse envelopes, and wire into import."""

    def test_cpanel_call_parses_success_and_failure_envelopes(self) -> None:
        from components.cpanel_client import CPanelClient

        class Response:
            def __init__(self, payload):
                self._payload = payload

            def raise_for_status(self) -> None:
                pass

            def json(self):
                return self._payload

        class Session:
            def __init__(self) -> None:
                self.payload = {
                    "result": {
                        "status": 1,
                        "data": [{"email": "a@example.com"}],
                        "errors": None,
                        "messages": None,
                        "warnings": None,
                    }
                }

            def get(self, *_args, **_kwargs):
                return Response(self.payload)

        client = object.__new__(CPanelClient)
        client.base_url = "https://panel.example.com:2083"
        client.session = Session()
        client.timeout_sec = 20

        assert client._call("Email", "list_pops") == [{"email": "a@example.com"}]
        client.session.payload = {
            "result": {
                "status": 0,
                "data": None,
                "errors": ["already exists"],
                "messages": ["failed"],
                "warnings": None,
            }
        }
        with pytest.raises(RuntimeError, match="already exists.*failed"):
            client._call("Email", "add_pop")

    def test_cpanel_call_uses_get_and_redacts_request_errors(self) -> None:
        from components.cpanel_client import CPanelClient

        class Session:
            verify = True

            def get(self, url, params=None, timeout=None):
                assert params == {"password": "super-secret", "email": "a", "domain": "example.com"}
                raise RuntimeError(f"failed URL {url}?password=super-secret")

            def post(self, *_args, **_kwargs):
                raise AssertionError("POST must not be used for documented cPanel UAPI GET calls")

        client = object.__new__(CPanelClient)
        client.base_url = "https://panel.example.com:2083"
        client.session = Session()
        client.timeout_sec = 20

        with pytest.raises(RuntimeError) as exc_info:
            client._call("Email", "add_pop", {"password": "super-secret", "email": "a", "domain": "example.com"})

        assert "super-secret" not in str(exc_info.value)
        assert "request failed" in str(exc_info.value)

    def test_cpanel_client_uses_token_header_and_parses_accounts(self) -> None:
        from components.cpanel_client import CPanelClient

        class Session:
            def __init__(self) -> None:
                self.headers = {}
                self.auth = None
                self.verify = True

        fake_session = Session()
        with mock.patch("components.cpanel_client.requests.Session", return_value=fake_session):
            client = CPanelClient(
                "https://panel.example.com:2083",
                "cpuser",
                token="api-token",
            )

        assert fake_session.headers["Authorization"] == "cpanel cpuser:api-token"
        calls = []

        def fake_call(module, function, params=None):
            calls.append((module, function, dict(params or {})))
            return [
                {"email": "a@example.com", "login": "a@example.com"},
                {"user": "b", "domain": "example.com"},
                {"email": "other@elsewhere.test"},
            ]

        client._call = fake_call

        assert client.list_pop_accounts("example.com") == ["a", "b"]
        assert client.list_all_email_accounts() == ["a@example.com", "b@example.com", "other@elsewhere.test"]
        assert calls == [
            ("Email", "list_pops", {"skip_main": 1}),
            ("Email", "list_pops", {"skip_main": 1}),
        ]

    def test_cpanel_create_delete_send_documented_parameters(self) -> None:
        from components.cpanel_client import CPanelClient

        client = object.__new__(CPanelClient)
        calls = []

        def fake_call(module, function, params=None):
            calls.append((module, function, dict(params or {})))
            return None

        client._call = fake_call

        client.create_pop_account("example.com", "a", "secret", quota_mb=512)
        client.delete_pop_account("example.com", "a")

        assert calls[0] == (
            "Email",
            "add_pop",
            {
                "email": "a",
                "domain": "example.com",
                "password": "secret",
                "quota": "512",
                "skip_update_db": 1,
            },
        )
        assert calls[1] == (
            "Email",
            "delete_pop",
            {"email": "a@example.com", "domain": "example.com"},
        )

    def test_cpanel_reset_does_not_create_after_delete_failure(self) -> None:
        from components.cpanel_ensure import reset_accounts_cpanel
        from components.models import Account, Config, ServerConfig

        class BrokenDeleteClient:
            def __init__(self) -> None:
                self.created = False

            def delete_pop_account(self, domain: str, local_part: str) -> None:
                raise RuntimeError("delete failed")

            def create_pop_account(self, domain: str, local_part: str, password: str, quota_mb: int = 0, *, allow_existing: bool = True) -> None:
                self.created = True

        client = BrokenDeleteClient()
        config = Config(
            server=ServerConfig(host="imap.example.com"),
            accounts=[Account(email="a@example.com", password="secret")],
        )

        failed = reset_accounts_cpanel(config, client, ignore_errors=True)

        assert not client.created
        assert failed == {"a@example.com"}

    def test_main_import_uses_cpanel_reset_and_reports_skips(self, tmp_path: Path) -> None:
        from components.main import main

        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "source_server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [
                {"email": "skip@example.com", "password": "secret"},
                {"email": "ok@example.com", "password": "secret"},
            ],
        }))
        input_dir = tmp_path / "exported"
        for email in ("skip@example.com", "ok@example.com"):
            inbox = input_dir / email / "INBOX"
            _write_legacy_message_fixture(inbox)

        class DummyCPanelClient:
            def __init__(self, *_args, **_kwargs) -> None:
                pass

        imported: List[str] = []

        def fake_import_account(acc, *_args, **_kwargs) -> None:
            imported.append(acc.email)

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.main.CPanelClient", DummyCPanelClient), \
            mock.patch("components.cpanel_ensure.reset_accounts_cpanel", return_value={"skip@example.com"}), \
            mock.patch("components.main.import_account", fake_import_account):
            rc = main([
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(input_dir),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--no-connectivity-test",
                "--auto-provision-cpanel",
                "--reset",
                "--reset-confirm", "imap.example.com",
                "--ignore-errors",
                "--cpanel-url", "https://panel.example.com:2083",
                "--cpanel-username", "cpuser",
                "--cpanel-token", "api-token",
            ])

        assert rc == 3
        assert imported == ["ok@example.com"]

    def test_cpanel_reset_archives_journal_and_skips_failed_connectivity_account(self, tmp_path: Path) -> None:
        from components.imap_ops import _legacy_import_key, _legacy_import_target_id
        from components.main import main
        from components.models import Account, ServerConfig

        config_path = tmp_path / "import.pass.config.json"
        server = ServerConfig(host="imap.example.com", port=993, ssl=True, starttls=False)
        config_path.write_text(json.dumps({
            "server": {"host": server.host, "port": server.port, "ssl": server.ssl, "starttls": server.starttls},
            "source_server": {"host": server.host, "port": server.port, "ssl": server.ssl, "starttls": server.starttls},
            "accounts": [
                {"email": "skip@example.com", "password": "secret"},
                {"email": "ok@example.com", "password": "secret"},
            ],
        }))
        input_dir = tmp_path / "exported"
        for email in ("skip@example.com", "ok@example.com"):
            inbox = input_dir / email / "INBOX"
            _write_legacy_message_fixture(inbox)

        ok_account = Account(email="ok@example.com", password="secret")
        ok_account_dir = input_dir / "ok@example.com"
        ok_eml = ok_account_dir / "INBOX" / "u0000000001.eml"
        ok_key = _legacy_import_key(ok_account_dir, ok_eml, "INBOX", ok_eml.read_bytes())
        (ok_account_dir / "import.journal.jsonl").write_text(json.dumps({
            "key": ok_key,
            "status": "committed",
            "target": _legacy_import_target_id(server, ok_account),
            "mailbox": "INBOX",
            "path": "INBOX/u0000000001.eml",
        }) + "\n")

        class DummyCPanelClient:
            def __init__(self, *_args, **_kwargs) -> None:
                pass

        tested: List[List[str]] = []
        imported: List[str] = []

        def fake_test_accounts(config, *_args, **_kwargs) -> None:
            tested.append([acc.email for acc in config.accounts])
            assert not (ok_account_dir / "import.journal.jsonl").exists()

        def fake_import_account(acc, *_args, **_kwargs) -> None:
            imported.append(acc.email)

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.utils.ensure_imapsync_available"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.main.CPanelClient", DummyCPanelClient), \
            mock.patch("components.cpanel_ensure.reset_accounts_cpanel", return_value={"skip@example.com"}), \
            mock.patch("components.main.test_accounts", fake_test_accounts), \
            mock.patch("components.main.import_account", fake_import_account):
            rc = main([
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(input_dir),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--auto-provision-cpanel",
                "--reset",
                "--reset-confirm", "imap.example.com",
                "--ignore-errors",
                "--cpanel-url", "https://panel.example.com:2083",
                "--cpanel-username", "cpuser",
                "--cpanel-token", "api-token",
            ])

        assert rc == 3
        assert tested == [["ok@example.com"]]
        assert imported == ["ok@example.com"]
        assert list(ok_account_dir.glob("import.journal.reset-*.jsonl"))

    def test_reset_requires_confirmation_before_panel_calls(self, tmp_path: Path) -> None:
        from components.main import main

        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.CPanelClient") as client_cls:
            rc = main([
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(tmp_path),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--no-connectivity-test",
                "--auto-provision-cpanel",
                "--reset",
                "--cpanel-url", "https://panel.example.com:2083",
                "--cpanel-username", "cpuser",
                "--cpanel-token", "api-token",
            ])

        assert rc == 2
        client_cls.assert_not_called()

    def test_wrong_panel_dry_run_flag_does_not_bypass_directadmin_reset_confirmation(self, tmp_path: Path) -> None:
        from components.main import main

        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.DirectAdminClient") as client_cls:
            rc = main([
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(tmp_path),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--no-connectivity-test",
                "--auto-provision-da",
                "--reset",
                "--cpanel-dry-run",
                "--da-url", "https://panel.example.com:2222",
                "--da-username", "admin",
                "--da-password", "login-key",
            ])

        assert rc == 2
        client_cls.assert_not_called()

    def test_directadmin_reset_validates_staged_input_before_panel_calls(self, tmp_path: Path) -> None:
        from components.main import main

        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.DirectAdminClient") as client_cls:
            rc = main([
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(tmp_path / "missing-export"),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--no-connectivity-test",
                "--auto-provision-da",
                "--reset",
                "--reset-confirm", "imap.example.com",
                "--da-url", "https://panel.example.com:2222",
                "--da-username", "admin",
                "--da-password", "login-key",
            ])

        assert rc == 2
        client_cls.assert_not_called()

    def test_directadmin_create_missing_requires_strict_staged_audit_before_panel_calls(self, tmp_path: Path) -> None:
        from components.main import main

        input_root = tmp_path / "exported"
        _write_legacy_message_fixture(input_root / "a@example.com" / "INBOX")
        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "target.example.com", "port": 993, "ssl": True, "starttls": False},
            "source_server": {"host": "wrong-source.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.main.DirectAdminClient") as client_cls:
            rc = main([
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(input_root),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--no-connectivity-test",
                "--auto-provision-da",
                "--da-url", "https://panel.example.com:2222",
                "--da-username", "admin",
                "--da-password", "login-key",
            ])

        assert rc == 4
        client_cls.assert_not_called()

    def test_panel_reset_audits_staged_input_before_panel_calls_even_with_ignore_errors(self, tmp_path: Path) -> None:
        from components.main import main

        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))
        mailbox_dir = tmp_path / "exported" / "a@example.com" / "INBOX"
        mailbox_dir.mkdir(parents=True)
        (mailbox_dir / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": 1}))

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.main.DirectAdminClient") as client_cls:
            rc = main([
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(tmp_path / "exported"),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--no-connectivity-test",
                "--auto-provision-da",
                "--reset",
                "--reset-confirm", "imap.example.com",
                "--ignore-errors",
                "--da-url", "https://panel.example.com:2222",
                "--da-username", "admin",
                "--da-password", "login-key",
            ])

        assert rc == 4
        client_cls.assert_not_called()

    def test_wrong_panel_dry_run_flag_does_not_bypass_cpanel_reset_confirmation(self, tmp_path: Path) -> None:
        from components.main import main

        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.CPanelClient") as client_cls:
            rc = main([
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(tmp_path),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--no-connectivity-test",
                "--auto-provision-cpanel",
                "--reset",
                "--da-dry-run",
                "--cpanel-url", "https://panel.example.com:2083",
                "--cpanel-username", "cpuser",
                "--cpanel-token", "api-token",
            ])

        assert rc == 2
        client_cls.assert_not_called()

    def test_cpanel_dry_run_exits_before_imap_import(self, tmp_path: Path) -> None:
        from components.main import main

        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))

        class DummyCPanelClient:
            def __init__(self, *_args, **_kwargs) -> None:
                pass

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.CPanelClient", DummyCPanelClient), \
            mock.patch("components.main.ensure_accounts_exist_cpanel") as ensure_mock, \
            mock.patch("components.main.import_account") as import_mock:
            rc = main([
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(tmp_path / "does-not-need-to-exist"),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--no-connectivity-test",
                "--auto-provision-cpanel",
                "--cpanel-dry-run",
                "--cpanel-url", "https://panel.example.com:2083",
                "--cpanel-username", "cpuser",
                "--cpanel-token", "api-token",
            ])

        assert rc == 0
        ensure_mock.assert_called_once()
        assert ensure_mock.call_args.kwargs["dry_run"] is True
        import_mock.assert_not_called()

    def test_cpanel_dry_run_does_not_require_imapsync_binary(self, tmp_path: Path) -> None:
        from components.main import main

        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))

        class DummyCPanelClient:
            def __init__(self, *_args, **_kwargs) -> None:
                pass

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.utils.ensure_imapsync_available", side_effect=RuntimeError("imapsync missing")) as imapsync_mock, \
            mock.patch("components.main.CPanelClient", DummyCPanelClient), \
            mock.patch("components.main.ensure_accounts_exist_cpanel") as ensure_mock, \
            mock.patch("components.main.import_account") as import_mock:
            rc = main([
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(tmp_path / "does-not-need-to-exist"),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--auto-provision-cpanel",
                "--cpanel-dry-run",
                "--cpanel-url", "https://panel.example.com:2083",
                "--cpanel-username", "cpuser",
                "--cpanel-token", "api-token",
            ])

        assert rc == 0
        imapsync_mock.assert_not_called()
        ensure_mock.assert_called_once()
        import_mock.assert_not_called()

    def test_directadmin_dry_run_exits_before_imap_import(self, tmp_path: Path) -> None:
        from components.main import main

        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))

        class DummyDirectAdminClient:
            def __init__(self, *_args, **_kwargs) -> None:
                pass

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.DirectAdminClient", DummyDirectAdminClient), \
            mock.patch("components.main.ensure_accounts_exist_directadmin") as ensure_mock, \
            mock.patch("components.main.import_account") as import_mock:
            rc = main([
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(tmp_path / "does-not-need-to-exist"),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--no-connectivity-test",
                "--auto-provision-da",
                "--da-dry-run",
                "--da-url", "https://panel.example.com:2222",
                "--da-username", "admin",
                "--da-password", "login-key",
            ])

        assert rc == 0
        ensure_mock.assert_called_once()
        assert ensure_mock.call_args.kwargs["dry_run"] is True
        import_mock.assert_not_called()

    def test_directadmin_dry_run_does_not_require_imapsync_binary(self, tmp_path: Path) -> None:
        from components.main import main

        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))

        class DummyDirectAdminClient:
            def __init__(self, *_args, **_kwargs) -> None:
                pass

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.utils.ensure_imapsync_available", side_effect=RuntimeError("imapsync missing")) as imapsync_mock, \
            mock.patch("components.main.DirectAdminClient", DummyDirectAdminClient), \
            mock.patch("components.main.ensure_accounts_exist_directadmin") as ensure_mock, \
            mock.patch("components.main.import_account") as import_mock:
            rc = main([
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(tmp_path / "does-not-need-to-exist"),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--auto-provision-da",
                "--da-dry-run",
                "--da-url", "https://panel.example.com:2222",
                "--da-username", "admin",
                "--da-password", "login-key",
            ])

        assert rc == 0
        imapsync_mock.assert_not_called()
        ensure_mock.assert_called_once()
        import_mock.assert_not_called()

    def test_cpanel_dry_run_failure_is_fatal_even_with_ignore_errors(self, tmp_path: Path) -> None:
        from components.main import main

        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))

        class DummyCPanelClient:
            def __init__(self, *_args, **_kwargs) -> None:
                pass

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.CPanelClient", DummyCPanelClient), \
            mock.patch("components.main.ensure_accounts_exist_cpanel", side_effect=RuntimeError("uapi unavailable")), \
            mock.patch("components.main.import_account") as import_mock:
            rc = main([
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(tmp_path / "does-not-need-to-exist"),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--no-connectivity-test",
                "--auto-provision-cpanel",
                "--cpanel-dry-run",
                "--ignore-errors",
                "--cpanel-url", "https://panel.example.com:2083",
                "--cpanel-username", "cpuser",
                "--cpanel-token", "api-token",
            ])

        assert rc == 3
        import_mock.assert_not_called()

    def test_create_missing_audits_staged_input_before_panel_calls(self, tmp_path: Path) -> None:
        from components.main import main

        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))
        inbox = tmp_path / "exported" / "a@example.com" / "INBOX"
        _write_legacy_message_fixture(inbox)
        (inbox / "u0000000001.json").write_text("{")

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.main.DirectAdminClient") as client_cls, \
            mock.patch("components.main.ensure_accounts_exist_directadmin") as ensure_mock:
            rc = main([
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(tmp_path / "exported"),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--no-connectivity-test",
                "--auto-provision-da",
                "--da-url", "https://panel.example.com:2222",
                "--da-username", "admin",
                "--da-password", "login-key",
            ])

        assert rc == 4
        client_cls.assert_not_called()
        ensure_mock.assert_not_called()

    def test_panel_workflow_rejects_invalid_account_before_client_calls(self, tmp_path: Path) -> None:
        from components.main import main

        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "missing-domain", "password": "secret"}],
        }))

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.DirectAdminClient") as client_cls, \
            mock.patch("components.main.ensure_accounts_exist_directadmin") as ensure_mock:
            rc = main([
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(tmp_path / "does-not-need-to-exist"),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--auto-provision-da",
                "--da-dry-run",
                "--da-url", "https://panel.example.com:2222",
                "--da-username", "admin",
                "--da-password", "login-key",
            ])

        assert rc == 2
        client_cls.assert_not_called()
        ensure_mock.assert_not_called()

    def test_directadmin_create_missing_dry_run_requires_successful_panel_listing(self) -> None:
        from components.da_ensure import ensure_accounts_exist_directadmin
        from components.models import Account, Config, ServerConfig

        class BrokenDirectAdminClient:
            def list_pop_accounts(self, domain: str):
                raise RuntimeError("auth failed")

        config = Config(
            server=ServerConfig(host="imap.example.com"),
            accounts=[Account(email="a@example.com", password="secret")],
        )

        with pytest.raises(RuntimeError, match="auth failed"):
            ensure_accounts_exist_directadmin(config, BrokenDirectAdminClient(), dry_run=True, ignore_errors=True)

    def test_directadmin_rejects_invalid_panel_account_identifiers(self) -> None:
        from components.da_ensure import ensure_accounts_exist_directadmin
        from components.models import Account, Config, ServerConfig

        config = Config(
            server=ServerConfig(host="imap.example.com"),
            accounts=[Account(email="missing-domain", password="secret")],
        )

        with pytest.raises(ValueError, match="local@domain"):
            ensure_accounts_exist_directadmin(config, mock.Mock(), dry_run=True, ignore_errors=True)

    def test_cpanel_create_missing_dry_run_requires_successful_panel_listing(self) -> None:
        from components.cpanel_ensure import ensure_accounts_exist_cpanel
        from components.models import Account, Config, ServerConfig

        class BrokenCPanelClient:
            def list_pop_accounts(self, domain: str):
                raise RuntimeError("uapi unavailable")

        config = Config(
            server=ServerConfig(host="imap.example.com"),
            accounts=[Account(email="a@example.com", password="secret")],
        )

        with pytest.raises(RuntimeError, match="uapi unavailable"):
            ensure_accounts_exist_cpanel(config, BrokenCPanelClient(), dry_run=True, ignore_errors=True)

    def test_cpanel_rejects_invalid_panel_account_identifiers(self) -> None:
        from components.cpanel_ensure import ensure_accounts_exist_cpanel
        from components.models import Account, Config, ServerConfig

        config = Config(
            server=ServerConfig(host="imap.example.com"),
            accounts=[Account(email="@example.com", password="secret")],
        )

        with pytest.raises(ValueError, match="local@domain"):
            ensure_accounts_exist_cpanel(config, mock.Mock(), dry_run=True, ignore_errors=True)

    def test_cpanel_indexer_writes_selected_domains(self, tmp_path: Path) -> None:
        import cpanel_indexer

        class DummyCPanelClient:
            def __init__(self, *_args, **_kwargs) -> None:
                pass

            def list_all_email_accounts(self) -> List[str]:
                return ["a@example.com", "b@example.com", "c@other.test"]

        out = tmp_path / "export.pass.config.json"

        with mock.patch("cpanel_indexer.CPanelClient", DummyCPanelClient), \
            mock.patch("cpanel_indexer.prompt_select_from_list", return_value=[0]):
            rc = cpanel_indexer.main([
                "--url", "https://panel.example.com:2083",
                "--username", "cpuser",
                "--token", "api-token",
                "--imap-host", "mail.example.com",
                "--out", str(out),
            ])

        assert rc == 0
        payload = json.loads(out.read_text())
        assert [account["email"] for account in payload["accounts"]] == ["a@example.com", "b@example.com"]
        assert out.stat().st_mode & 0o777 == 0o600


class TestImapsyncPasswordHandling:
    """imapsync probe must not expose passwords in process arguments."""

    def test_justconnect_uses_passfile_not_password_arg(self) -> None:
        from components.imapsync_cli import run_imapsync_justconnect

        captured_args: List[List[str]] = []

        def fake_run(args, **_kwargs):
            captured_args.append(list(args))
            if args[0] == "imapsync" and "--version" in args:
                return subprocess.CompletedProcess(args, 0, "", "")
            return subprocess.CompletedProcess(args, 0, "ok", "")

        with mock.patch("components.utils.shutil.which", return_value="/usr/bin/imapsync"):
            with mock.patch("components.utils.subprocess.run", side_effect=fake_run):
                with mock.patch("components.imapsync_cli.subprocess.run", side_effect=fake_run):
                    ok, _out = run_imapsync_justconnect(
                        host="imap.example.com",
                        port=993,
                        ssl_enabled=True,
                        starttls=False,
                        user="user@example.com",
                        password="super-secret",
                    )

        assert ok
        imapsync_args = captured_args[-1]
        assert "--passfile1" in imapsync_args
        assert "--password1" not in imapsync_args
        assert "super-secret" not in imapsync_args


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

    def test_verify_export_exits_nonzero_for_genuine_concatenation(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from verify_export import main

        inbox = tmp_path / "exported" / "user@example.com" / "INBOX"
        inbox.mkdir(parents=True)
        (inbox / "u0000000001.eml").write_bytes(
            b"Message-ID: <one@example.com>\r\n"
            b"Message-ID: <two@example.com>\r\n"
            b"From: a@example.com\r\n"
            b"\r\n"
            b"body\r\n"
        )
        monkeypatch.chdir(tmp_path)

        assert main() == 1

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

    def test_lf_only_forwarded_email_no_false_positive(self, tmp_path: Path) -> None:
        """LF-only (no CR) email with forwarded headers in body must not false-positive."""
        from verify_export import analyze_message

        eml_content = (
            b"Return-Path: <sender@example.com>\n"
            b"Message-ID: <abc@example.com>\n"
            b"From: sender@example.com\n"
            b"Subject: Fwd: test\n"
            b"\n"
            b"---------- Forwarded ----------\n"
            b"Return-Path: <other@example.com>\n"
            b"Message-ID: <def@example.com>\n"
        )
        eml_path = tmp_path / "test.eml"
        eml_path.write_bytes(eml_content)
        json_path = tmp_path / "test.json"

        analysis, error = analyze_message(eml_path, json_path)

        assert error is None
        assert analysis is not None
        assert analysis["multiple_messages_detected"] is False, (
            "LF-only email with forwarded headers should NOT be flagged"
        )
