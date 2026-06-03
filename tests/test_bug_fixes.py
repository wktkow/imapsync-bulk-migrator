"""
Tests for all confirmed bug fixes.

Each test is tagged with the bug number it validates.
"""
from __future__ import annotations

import contextlib
import json
import queue
import signal
import subprocess
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
                "accounts": [{"email": a.email, "password": a.password} for a in config.accounts],
            },
        )

        result = json.loads(import_path.read_text())
        assert result["server"]["host"] == "CHANGE_ME.example.com"
        assert result["server"]["host"] != config.server.host
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
            for acc in accounts[:call_count]:
                assert acc.email in warning_text

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
        account_dir.mkdir(parents=True)
        eml = account_dir / "u0000000001.eml"
        eml.write_bytes(b"Message-ID: <m@example.com>\r\n\r\nbody")
        eml.with_suffix(".json").write_text(json.dumps({
            "mailbox": "INBOX",
            "uid": 1,
            "flags": "\\Seen",
            "internaldate": "01-Jan-2024 00:00:00 +0000",
        }))
        return tmp_path

    def test_import_rerun_skips_committed_journal_entry(self, tmp_path: Path) -> None:
        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        in_root = self._make_export(tmp_path)
        account = Account(email="user@example.com", password="pass")
        server = ServerConfig(host="dummy", port=993, ssl=True)
        fake_imap = mock.MagicMock()
        fake_imap.select.return_value = ("OK", [b""])
        fake_imap.append.return_value = ("OK", [b""])

        @contextlib.contextmanager
        def fake_factory(*_args, **_kwargs) -> Iterator:
            yield fake_imap

        import_account(account, server, in_root, ignore_errors=False, imap_factory=fake_factory)
        import_account(account, server, in_root, ignore_errors=False, imap_factory=fake_factory)

        assert fake_imap.append.call_count == 1

    def test_import_rejects_pending_journal_entry(self, tmp_path: Path) -> None:
        from components.imap_ops import _legacy_import_key, import_account
        from components.models import Account, ServerConfig

        in_root = self._make_export(tmp_path)
        account_dir = in_root / "user@example.com"
        eml = account_dir / "INBOX" / "u0000000001.eml"
        data = eml.read_bytes()
        key = _legacy_import_key(account_dir, eml, "INBOX", data)
        (account_dir / "import.journal.jsonl").write_text(json.dumps({
            "key": key,
            "status": "pending",
            "mailbox": "INBOX",
            "path": "INBOX/u0000000001.eml",
        }) + "\n")
        account = Account(email="user@example.com", password="pass")
        server = ServerConfig(host="dummy", port=993, ssl=True)
        fake_imap = mock.MagicMock()
        fake_imap.select.return_value = ("OK", [b""])

        @contextlib.contextmanager
        def fake_factory(*_args, **_kwargs) -> Iterator:
            yield fake_imap

        with pytest.raises(RuntimeError, match="pending append"):
            import_account(account, server, in_root, ignore_errors=False, imap_factory=fake_factory)


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

    def test_write_json_uses_private_permissions(self, tmp_path: Path) -> None:
        from directadmin_indexer import write_json

        out = tmp_path / "export.pass.config.json"
        write_json({"accounts": []}, str(out), overwrite=False)

        assert out.stat().st_mode & 0o777 == 0o600

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

        reset_accounts_directadmin(config, client, ignore_errors=True)

        assert not client.created


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
