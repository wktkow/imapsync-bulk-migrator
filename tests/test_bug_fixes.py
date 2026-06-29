"""
Tests for all confirmed bug fixes.

Each test is tagged with the bug number it validates.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import queue
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Iterator, List, Optional, Tuple
from unittest import mock

import pytest


def _legacy_integrity_metadata(data: bytes, **extra: object) -> dict:
    from components.content_binding import CONTENT_BINDING_FIELD, legacy_content_binding_sha256

    meta = {
        "account": "user@example.com",
        **extra,
        "rfc822_size": len(data),
        "content_sha256": hashlib.sha256(data).hexdigest(),
    }
    meta[CONTENT_BINDING_FIELD] = legacy_content_binding_sha256(meta)
    return meta


def _write_verify_export_state(account_dir: Path, mailboxes: list[dict]) -> None:
    account_dir.mkdir(parents=True, exist_ok=True)
    (account_dir / "export-state.json").write_text(json.dumps({
        "schema_version": 1,
        "account": account_dir.name,
        "complete": True,
        "completed_at": 0,
        "mailboxes": mailboxes,
    }))


def _mkfifo_or_skip(path: Path) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO creation unavailable")
    try:
        os.mkfifo(path)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"FIFO creation unavailable: {exc}")


def _stable_uidvalidity_response(*_args, **_kwargs):
    return "OK", [b"123"]


def _unique_ordered(values: List[str]) -> List[str]:
    return list(dict.fromkeys(values))


def _write_legacy_message_fixture(
    folder: Path,
    *,
    uid: int = 1,
    mailbox: str = "INBOX",
    data: bytes = b"From: a\r\nTo: b\r\n\r\nbody",
    flags: str = "\\Seen",
    source_server=None,
) -> Path:
    from components.imap_ops import legacy_server_endpoint, legacy_server_endpoint_digest
    from components.models import ServerConfig

    source_server = source_server or ServerConfig(host="imap.example.com", port=993, ssl=True, starttls=False)
    folder.mkdir(parents=True, exist_ok=True)
    eml = folder / f"u{uid:010d}.eml"
    eml.write_bytes(data)
    meta = _legacy_integrity_metadata(
        data,
        account=folder.parent.name,
        mailbox=mailbox,
        uid=uid,
        flags=flags,
        internaldate="01-Jan-2024 00:00:00 +0000",
    )
    eml.with_suffix(".json").write_text(json.dumps(meta))
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


def _write_legacy_empty_mailbox_fixture(folder: Path, *, mailbox: str = "INBOX", source_server=None) -> None:
    eml = _write_legacy_message_fixture(
        folder,
        mailbox=mailbox,
        data=b"Message-ID: <placeholder@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody",
        source_server=source_server,
    )
    eml.with_suffix(".json").unlink()
    eml.unlink()
    (folder / ".mailbox.json").write_text(json.dumps({"mailbox": mailbox, "message_count": 0}))
    state_path = folder.parent / "export-state.json"
    state = json.loads(state_path.read_text())
    state["mailboxes"] = [
        entry
        for entry in state.get("mailboxes", [])
        if not isinstance(entry, dict) or entry.get("path") != folder.name
    ]
    state["mailboxes"].append({"mailbox": mailbox, "path": folder.name, "message_count": 0})
    state_path.write_text(json.dumps(state))


def _write_verify_provider_account_fixture(
    account_dir: Path,
    *,
    canonical_id: str = "provider-1",
    body: bytes = b"Message-ID: <provider@example.com>\r\nFrom: a@example.com\r\nTo: b@example.com\r\n\r\nbody",
) -> dict:
    from components.content_binding import CONTENT_BINDING_FIELD, provider_content_binding_sha256
    from components.provider_ops import provider_manifest_digest

    (account_dir / "messages").mkdir(parents=True, exist_ok=True)
    (account_dir / "metadata").mkdir(exist_ok=True)
    eml_rel = f"messages/{canonical_id}.eml"
    meta_rel = f"metadata/{canonical_id}.json"
    (account_dir / eml_rel).write_bytes(body)
    row = {
        "canonical_id": canonical_id,
        "source_provider": "imap",
        "source_account": "source@example.com",
        "target_account": "target@example.com",
        "primary_mailbox": "Archive",
        "message_id_header": "<provider@example.com>",
        "content_sha256": hashlib.sha256(body).hexdigest(),
        "rfc822_size": len(body),
        "flags": "\\Seen",
        "internaldate": "01-Jan-2024 00:00:00 +0000",
        "eml_path": eml_rel,
        "metadata_path": meta_rel,
    }
    row[CONTENT_BINDING_FIELD] = provider_content_binding_sha256(row)
    (account_dir / meta_rel).write_text(json.dumps(row))
    (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")
    (account_dir / "export-state.json").write_text(json.dumps({
        "source_provider": "imap",
        "source_account": "source@example.com",
        "target_account": "target@example.com",
        "target_provider": "imap",
        "complete": True,
        "canonical_messages": 1,
        "manifest_sha256": provider_manifest_digest([row]),
    }))
    return row

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

    def test_case_only_collision_raises_before_writing(self, tmp_path: Path) -> None:
        """Case-only mailbox names alias on common case-insensitive filesystems."""
        from components.imap_ops import export_account
        from components.models import Account, ServerConfig

        server = ServerConfig(host="dummy", port=993, ssl=True)
        account = Account(email="user@example.com", password="pass")
        fake_imap = mock.MagicMock()
        fake_imap.list.return_value = (
            "OK",
            [b'(\\HasNoChildren) "/" "Folder"', b'(\\HasNoChildren) "/" "folder"'],
        )

        with mock.patch("components.imap_ops.imap_connection") as mock_conn:
            mock_conn.return_value.__enter__ = mock.MagicMock(return_value=fake_imap)
            mock_conn.return_value.__exit__ = mock.MagicMock(return_value=False)

            with pytest.raises(RuntimeError, match="case-insensitive"):
                export_account(account, server, tmp_path, ignore_errors=False)

    def test_no_collision_passes(self) -> None:
        """Distinct mailbox names that don't collide should not trigger an error."""
        from components.utils import sanitize_for_path

        names = ["INBOX", "Sent", "Drafts", "INBOX.Spam"]
        seen = {}
        for name in names:
            key = sanitize_for_path(name)
            assert key not in seen or seen[key] == name, f"Unexpected collision: {name}"
            seen[key] = name

    @pytest.mark.parametrize("mailbox_name", ["import.journal.jsonl", "export-state.json", "manifest.jsonl", "Import.Journal.Jsonl"])
    def test_reserved_account_artifact_mailbox_names_raise_before_folder_write(
        self,
        tmp_path: Path,
        mailbox_name: str,
    ) -> None:
        from components.imap_ops import export_account
        from components.models import Account, ServerConfig

        server = ServerConfig(host="dummy", port=993, ssl=True)
        account = Account(email="user@example.com", password="pass")
        fake_imap = mock.MagicMock()
        fake_imap.list.return_value = ("OK", [f'(\\HasNoChildren) "/" "{mailbox_name}"'.encode("ascii")])

        with mock.patch("components.imap_ops.imap_connection") as mock_conn:
            mock_conn.return_value.__enter__ = mock.MagicMock(return_value=fake_imap)
            mock_conn.return_value.__exit__ = mock.MagicMock(return_value=False)

            with pytest.raises(RuntimeError, match="reserved legacy account artifact path"):
                export_account(account, server, tmp_path, ignore_errors=False)

        account_dir = tmp_path / "user@example.com"
        assert not (account_dir / mailbox_name).is_dir()

    def test_audit_and_verify_reject_import_journal_mailbox_directory(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from components.audit import audit_account
        from components.models import Account
        from verify_export import verify_account

        account = Account(email="user@example.com", password="pass")
        folder = tmp_path / "user@example.com" / "import.journal.jsonl"
        _write_legacy_message_fixture(folder, mailbox="import.journal.jsonl")

        _email, audit_issues = audit_account(
            account,
            tmp_path,
            server=None,
            check_remote=False,
            require_integrity_metadata=True,
        )
        stats = verify_account(tmp_path / "user@example.com")
        output = capsys.readouterr().out

        assert any("reserved legacy account artifact path" in issue for issue in audit_issues)
        assert stats["errors"] >= 1
        assert "reserved legacy account artifact path" in output


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

    def test_export_mode_post_audit_uses_export_server_as_source(self, tmp_path: Path) -> None:
        from components.main import main
        from components.models import ServerConfig

        server = ServerConfig("source.example.com", port=993, ssl=True, starttls=False)
        config_path = tmp_path / "export.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": server.host, "port": server.port, "ssl": server.ssl, "starttls": server.starttls},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))
        output_dir = tmp_path / "exported"

        def fake_export(account, _server, out_root, **_kwargs):
            folder = out_root / account.email / "INBOX"
            _write_legacy_message_fixture(
                folder,
                data=b"Message-ID: <post-audit@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody",
                source_server=server,
            )
            (folder / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": 1}))

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.main.export_account", side_effect=fake_export):
            rc = main([
                "--mode", "export",
                "--config", str(config_path),
                "--output-dir", str(output_dir),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--no-connectivity-test",
                "--audit-offline",
            ])

        assert rc == 0

    def test_audit_mode_uses_export_server_as_source_when_source_server_missing(self, tmp_path: Path) -> None:
        from components.main import main
        from components.models import ServerConfig

        server = ServerConfig("source.example.com", port=993, ssl=True, starttls=False)
        config_path = tmp_path / "export.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": server.host, "port": server.port, "ssl": server.ssl, "starttls": server.starttls},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))
        input_dir = tmp_path / "exported"
        folder = input_dir / "a@example.com" / "INBOX"
        _write_legacy_message_fixture(
            folder,
            data=b"Message-ID: <standalone-audit@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody",
            source_server=server,
        )
        (folder / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": 1}))

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"):
            rc = main([
                "--mode", "audit",
                "--config", str(config_path),
                "--input-dir", str(input_dir),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--audit-offline",
            ])

        assert rc == 0

    def test_audit_mode_remote_checks_use_source_server_from_import_config(self, tmp_path: Path) -> None:
        from components.main import main
        from components.models import ServerConfig

        source = ServerConfig("source.example.com", port=993, ssl=True, starttls=False)
        target = ServerConfig("target.example.com", port=993, ssl=True, starttls=False)
        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": target.host, "port": target.port, "ssl": target.ssl, "starttls": target.starttls},
            "source_server": {"host": source.host, "port": source.port, "ssl": source.ssl, "starttls": source.starttls},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))
        input_dir = tmp_path / "exported"
        body = b"Message-ID: <source-audit@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody"
        folder = input_dir / "a@example.com" / "INBOX"
        _write_legacy_message_fixture(folder, data=body, source_server=source)
        (folder / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": 1}))
        seen_hosts: list[str] = []

        class SourceAuditImap:
            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"1"]

            def uid(self, command: str, *args):
                if command == "search":
                    return "OK", [b"1"]
                raise AssertionError(command)

            def search(self, charset, *criteria):
                return "OK", [b"1"]

            def fetch(self, num, query):
                return "OK", [(b"1 (RFC822.SIZE %d FLAGS (\\Seen) INTERNALDATE \"01-Jan-2024 00:00:00 +0000\" BODY[] {%d}" % (len(body), len(body)), body)]

            def logout(self):
                return "OK", []

        @contextlib.contextmanager
        def fake_connection(server: ServerConfig, *_args, **_kwargs) -> Iterator[SourceAuditImap]:
            seen_hosts.append(server.host)
            if server.host != source.host:
                raise AssertionError(f"audit contacted target server: {server.host}")
            yield SourceAuditImap()

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.audit.imap_connection", fake_connection):
            rc = main([
                "--mode", "audit",
                "--config", str(config_path),
                "--input-dir", str(input_dir),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
            ])

        assert rc == 0
        assert seen_hosts == [source.host]

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
# Executor stop_event must stop queued account work and drain running work
# ---------------------------------------------------------------------------


class TestExecutorStopEventPolling:
    """Thread-pool account phases must honor cooperative stop requests."""

    def test_stop_event_stops_queued_accounts_and_drains_running_workers(self) -> None:
        from components.executor import parallel_process_accounts
        from components.models import Account

        accounts = [Account(email=f"user{i}@test.com", password="") for i in range(3)]
        stop_event = threading.Event()
        started: List[str] = []
        finished: List[str] = []
        lock = threading.Lock()

        def worker(acc: Account) -> None:
            with lock:
                started.append(acc.email)
            if acc.email == "user0@test.com":
                stop_event.set()
            time.sleep(0.05)
            with lock:
                finished.append(acc.email)

        with pytest.raises(RuntimeError, match="stop requested before completion"):
            parallel_process_accounts(
                "test",
                worker,
                accounts,
                max_workers=2,
                stop_on_error=True,
                stop_event=stop_event,
            )

        assert "user2@test.com" not in started
        assert sorted(finished) == sorted(started)

    def test_stop_event_stops_submission_when_error_continuation_is_enabled(self) -> None:
        from components.executor import parallel_process_accounts
        from components.models import Account

        accounts = [Account(email=f"user{i}@test.com", password="") for i in range(2)]
        stop_event = threading.Event()
        started: List[str] = []

        def worker(acc: Account) -> None:
            started.append(acc.email)
            stop_event.set()

        with pytest.raises(RuntimeError, match="stop requested before completion"):
            parallel_process_accounts(
                "test",
                worker,
                accounts,
                max_workers=1,
                stop_on_error=False,
                stop_event=stop_event,
            )

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
    """export_account should avoid redundant selects beyond required stability checks."""

    def test_select_called_once_per_mailbox(self, tmp_path: Path) -> None:
        from components.imap_ops import export_account
        from components.models import Account, ServerConfig

        server = ServerConfig(host="dummy", port=993, ssl=True)
        account = Account(email="user@example.com", password="pass")

        fake_imap = mock.MagicMock()
        fake_imap.list.return_value = ("OK", [b'(\\HasNoChildren) "/" "INBOX"'])
        fake_imap.select.return_value = ("OK", [b"0"])
        fake_imap.response.return_value = ("OK", [b"123"])
        fake_imap.uid.side_effect = [
            ("OK", [b""]),  # uid search → no messages
            ("OK", [b""]),  # final stability search
        ]

        with mock.patch("components.imap_ops.imap_connection") as mock_conn:
            mock_conn.return_value.__enter__ = mock.MagicMock(return_value=fake_imap)
            mock_conn.return_value.__exit__ = mock.MagicMock(return_value=False)

            export_account(account, server, tmp_path, ignore_errors=False)

        # select is used for initial discovery and the final stability check.
        select_calls = [c for c in fake_imap.select.call_args_list if c[0][0] == "INBOX"]
        assert len(select_calls) == 2, f"Expected 2 select calls for INBOX, got {len(select_calls)}"
        state = json.loads((tmp_path / "user@example.com" / "export-state.json").read_text())
        assert state["complete"] is True
        assert state["mailboxes"] == [{"mailbox": "INBOX", "message_count": 0, "path": "INBOX", "uidvalidity": "123"}]

    def test_export_writes_private_source_bound_staging_artifacts(self, tmp_path: Path) -> None:
        from components.imap_ops import legacy_server_endpoint, legacy_server_endpoint_digest, export_account
        from components.models import Account, ServerConfig

        server = ServerConfig(host="source.example.com", port=993, ssl=True, starttls=False)
        account = Account(email="user@example.com", password="pass")
        data = b"Message-ID: <m@example.com>\r\nFrom: a@example.com\r\nTo: b@example.com\r\n\r\nbody"

        class SingleMessageExportImap:
            response = _stable_uidvalidity_response

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

    def test_export_rejects_multiple_fetch_message_bodies_for_one_uid(self, tmp_path: Path) -> None:
        from components.imap_ops import export_account
        from components.models import Account, ServerConfig

        server = ServerConfig(host="dummy", port=993, ssl=True)
        account = Account(email="user@example.com", password="pass")
        first = b"Message-ID: <one@example.com>\r\nFrom: a\r\nTo: b\r\n\r\none"
        second = b"Message-ID: <two@example.com>\r\nFrom: a\r\nTo: b\r\n\r\ntwo"

        class MultiBodyFetchImap:
            response = _stable_uidvalidity_response

            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"1"]

            def uid(self, command: str, *args):
                if command == "search":
                    return "OK", [b"1"]
                if command == "fetch":
                    return "OK", [
                        (b'1 (UID 1 FLAGS (\\Seen) INTERNALDATE "01-Jan-2024 00:00:00 +0000")', first),
                        (b'2 (UID 2 FLAGS (\\Seen) INTERNALDATE "01-Jan-2024 00:00:00 +0000")', second),
                    ]
                raise AssertionError(command)

            def logout(self):
                return "OK", []

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[MultiBodyFetchImap]:
            yield MultiBodyFetchImap()

        with mock.patch("components.imap_ops.imap_connection", fake_connection):
            with pytest.raises(RuntimeError, match="multiple message bodies"):
                export_account(account, server, tmp_path, ignore_errors=False)

        account_dir = tmp_path / "user@example.com"
        state_path = account_dir / "export-state.json"
        if state_path.exists():
            assert json.loads(state_path.read_text())["complete"] is False
        eml = account_dir / "INBOX" / "u0000000001.eml"
        assert not eml.exists() or eml.read_bytes() != first + second

    def test_export_ignores_unsolicited_fetch_metadata_for_other_uid(self, tmp_path: Path) -> None:
        from components.imap_ops import export_account
        from components.models import Account, ServerConfig

        server = ServerConfig(host="dummy", port=993, ssl=True)
        account = Account(email="user@example.com", password="pass")
        body = b"Message-ID: <bound-fetch@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody"

        class UnsolicitedMetadataFetchImap:
            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"1"]

            def response(self, name: str):
                return "OK", [b"123"]

            def uid(self, command: str, *args):
                if command == "search":
                    return "OK", [b"42"]
                if command == "fetch":
                    return "OK", [
                        (
                            b'42 (UID 42 FLAGS (\\Seen) INTERNALDATE "01-Jan-2024 00:00:00 +0000")',
                            body,
                        ),
                        b'99 (UID 99 FLAGS (\\Deleted) INTERNALDATE "02-Jan-2024 00:00:00 +0000")',
                    ]
                raise AssertionError(command)

            def logout(self):
                return "OK", []

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[UnsolicitedMetadataFetchImap]:
            yield UnsolicitedMetadataFetchImap()

        with mock.patch("components.imap_ops.imap_connection", fake_connection):
            export_account(account, server, tmp_path, ignore_errors=False)

        meta = json.loads((tmp_path / "user@example.com" / "INBOX" / "u0000000042.json").read_text())
        assert meta["flags"] == "\\Seen"
        assert meta["internaldate"] == "01-Jan-2024 00:00:00 +0000"
        assert meta["uid"] == 42
        assert meta["uidvalidity"] == "123"

    def test_export_accepts_case_insensitive_fetch_metadata(self, tmp_path: Path) -> None:
        from components.imap_ops import export_account
        from components.models import Account, ServerConfig

        server = ServerConfig(host="dummy", port=993, ssl=True)
        account = Account(email="user@example.com", password="pass")
        body = b"Message-ID: <lowercase-fetch@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody"

        class LowercaseMetadataFetchImap:
            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"1"]

            def response(self, name: str):
                return "OK", [b"123"]

            def uid(self, command: str, *args):
                if command == "search":
                    return "OK", [b"1"]
                if command == "fetch":
                    query = str(args[-1])
                    if query == "(FLAGS)":
                        return "OK", [b"1 (uid 1 flags (\\Seen))"]
                    return "OK", [(
                        b'1 (uid 1 flags (\\Seen) internaldate "01-Jan-2024 00:00:00 +0000")',
                        body,
                    )]
                raise AssertionError(command)

            def logout(self):
                return "OK", []

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[LowercaseMetadataFetchImap]:
            yield LowercaseMetadataFetchImap()

        with mock.patch("components.imap_ops.imap_connection", fake_connection):
            export_account(account, server, tmp_path, ignore_errors=False)

        meta = json.loads((tmp_path / "user@example.com" / "INBOX" / "u0000000001.json").read_text())
        assert meta["flags"] == "\\Seen"
        assert meta["internaldate"] == "01-Jan-2024 00:00:00 +0000"
        assert meta["uid"] == 1

    def test_export_raises_when_fetch_has_no_message_bytes(self, tmp_path: Path) -> None:
        from components.imap_ops import export_account
        from components.models import Account, ServerConfig

        server = ServerConfig(host="dummy", port=993, ssl=True)
        account = Account(email="user@example.com", password="pass")

        fake_imap = mock.MagicMock()
        fake_imap.list.return_value = ("OK", [b'(\\HasNoChildren) "/" "INBOX"'])
        fake_imap.select.return_value = ("OK", [b"1"])
        fake_imap.response.return_value = ("OK", [b"123"])
        fake_imap.uid.side_effect = [
            ("OK", [b"1"]),
            ("OK", [b'1 (UID 1 FLAGS (\\Seen) INTERNALDATE "01-Jan-2024 00:00:00 +0000")']),
        ]

        with mock.patch("components.imap_ops.imap_connection") as mock_conn:
            mock_conn.return_value.__enter__ = mock.MagicMock(return_value=fake_imap)
            mock_conn.return_value.__exit__ = mock.MagicMock(return_value=False)

            with pytest.raises(RuntimeError, match="no message bytes"):
                export_account(account, server, tmp_path, ignore_errors=False)

    def test_export_accepts_zero_byte_message_literal(self, tmp_path: Path) -> None:
        from components.imap_ops import export_account
        from components.models import Account, ServerConfig

        server = ServerConfig(host="dummy", port=993, ssl=True)
        account = Account(email="user@example.com", password="pass")

        fake_imap = mock.MagicMock()
        fake_imap.list.return_value = ("OK", [b'(\\HasNoChildren) "/" "INBOX"'])
        fake_imap.select.return_value = ("OK", [b"1"])
        fake_imap.response.return_value = ("OK", [b"123"])
        fake_imap.uid.side_effect = [
            ("OK", [b"1"]),
            ("OK", [(
                b'1 (UID 1 FLAGS (\\Seen) INTERNALDATE \"01-Jan-2024 00:00:00 +0000\" BODY[] {0}',
                b"",
            )]),
            ("OK", [b"1"]),
            ("OK", [b"1 (UID 1 FLAGS (\\Seen))"]),
        ]

        with mock.patch("components.imap_ops.imap_connection") as mock_conn:
            mock_conn.return_value.__enter__ = mock.MagicMock(return_value=fake_imap)
            mock_conn.return_value.__exit__ = mock.MagicMock(return_value=False)
            export_account(account, server, tmp_path, ignore_errors=False)

        account_dir = tmp_path / "user@example.com"
        eml_path = account_dir / "INBOX" / "u0000000001.eml"
        meta = json.loads(eml_path.with_suffix(".json").read_text())
        assert eml_path.read_bytes() == b""
        assert meta["rfc822_size"] == 0
        assert meta["content_sha256"] == hashlib.sha256(b"").hexdigest()

    def test_export_ignore_errors_continues_but_raises_aggregate(self, tmp_path: Path) -> None:
        from components.imap_ops import export_account
        from components.models import Account, ServerConfig

        server = ServerConfig(host="dummy", port=993, ssl=True)
        account = Account(email="user@example.com", password="pass")

        class PartialExportImap:
            response = _stable_uidvalidity_response

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
            response = _stable_uidvalidity_response

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

    def test_export_skips_generic_all_and_covered_flagged_views(self, tmp_path: Path) -> None:
        from components.imap_ops import export_account
        from components.models import Account, ServerConfig

        body = b"Message-ID: <legacy-special-use@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody"

        class SpecialUseSource:
            response = _stable_uidvalidity_response

            def __init__(self) -> None:
                self.selected: List[str] = []
                self.selected_mailbox = ""

            def list(self):
                return "OK", [
                    b'(\\HasNoChildren) "/" "INBOX"',
                    b'(\\HasNoChildren \\All) "/" "All Mail"',
                    b'(\\HasNoChildren \\Flagged) "/" "Flagged"',
                ]

            def select(self, mailbox: str, readonly: bool = False):
                self.selected_mailbox = mailbox.strip('"').replace(r"\"", '"')
                self.selected.append(self.selected_mailbox)
                return "OK", [b"1"]

            def uid(self, command: str, *args):
                if command == "search":
                    return "OK", [b"1"]
                if command == "fetch":
                    return "OK", [(
                        b'1 (UID 1 FLAGS (\\Seen) INTERNALDATE "01-Jan-2024 00:00:00 +0000")',
                        body,
                    )]
                raise AssertionError(command)

            def logout(self):
                return "OK", []

        source = SpecialUseSource()

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[SpecialUseSource]:
            yield source

        with mock.patch("components.imap_ops.imap_connection", fake_connection):
            export_account(
                Account("user@example.com", "secret"),
                ServerConfig("imap.example.com"),
                tmp_path,
                ignore_errors=False,
            )

        account_dir = tmp_path / "user@example.com"
        state = json.loads((account_dir / "export-state.json").read_text())
        assert _unique_ordered(source.selected) == ["INBOX", "All Mail"]
        assert state["mailboxes"] == [
            {"mailbox": "INBOX", "path": "INBOX", "message_count": 1, "uidvalidity": "123"},
            {
                "mailbox": "All Mail",
                "path": "All_Mail",
                "message_count": 0,
                "covered_by_regular_content": True,
                "uidvalidity": "123",
            },
        ]
        assert (account_dir / "INBOX" / "u0000000001.eml").read_bytes() == body
        all_marker = json.loads((account_dir / "All_Mail" / ".mailbox.json").read_text())
        assert all_marker == {
            "mailbox": "All Mail",
            "message_count": 0,
            "covered_by_regular_content": True,
            "uidvalidity": "123",
        }
        assert not list((account_dir / "All_Mail").glob("u*.eml"))
        assert not (account_dir / "Flagged").exists()

    def test_export_keeps_generic_all_archived_only_messages_with_inbox(self, tmp_path: Path) -> None:
        from components.imap_ops import export_account
        from components.models import Account, ServerConfig

        inbox_body = b"Message-ID: <legacy-inbox@example.com>\r\nFrom: a\r\nTo: b\r\n\r\ninbox"
        archived_body = b"Message-ID: <legacy-archived@example.com>\r\nFrom: a\r\nTo: b\r\n\r\narchived"

        class InboxAndAllSource:
            response = _stable_uidvalidity_response

            def __init__(self) -> None:
                self.selected: List[str] = []
                self.selected_mailbox = ""

            def list(self):
                return "OK", [
                    b'(\\HasNoChildren) "/" "INBOX"',
                    b'(\\HasNoChildren \\All) "/" "All Mail"',
                ]

            def select(self, mailbox: str, readonly: bool = False):
                self.selected_mailbox = mailbox.strip('"').replace(r"\"", '"')
                self.selected.append(self.selected_mailbox)
                return "OK", [b"1" if self.selected_mailbox == "INBOX" else b"2"]

            def uid(self, command: str, *args):
                if command == "search":
                    return "OK", [b"1" if self.selected_mailbox == "INBOX" else b"1 2"]
                if command == "fetch":
                    uid = str(args[0])
                    body = inbox_body if uid == "1" else archived_body
                    return "OK", [(
                        f'{uid} (UID {uid} FLAGS (\\Seen) INTERNALDATE "01-Jan-2024 00:00:00 +0000")'.encode("ascii"),
                        body,
                    )]
                raise AssertionError(command)

            def logout(self):
                return "OK", []

        source = InboxAndAllSource()

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[InboxAndAllSource]:
            yield source

        with mock.patch("components.imap_ops.imap_connection", fake_connection):
            export_account(
                Account("user@example.com", "secret"),
                ServerConfig("imap.example.com"),
                tmp_path,
                ignore_errors=False,
            )

        account_dir = tmp_path / "user@example.com"
        state = json.loads((account_dir / "export-state.json").read_text())
        assert _unique_ordered(source.selected) == ["INBOX", "All Mail"]
        assert state["mailboxes"] == [
            {"mailbox": "INBOX", "path": "INBOX", "message_count": 1, "uidvalidity": "123"},
            {"mailbox": "All Mail", "path": "All_Mail", "message_count": 1, "uidvalidity": "123"},
        ]
        assert (account_dir / "INBOX" / "u0000000001.eml").read_bytes() == inbox_body
        assert (account_dir / "All_Mail" / "u0000000002.eml").read_bytes() == archived_body

    def test_export_keeps_generic_flagged_archived_only_messages_with_inbox(self, tmp_path: Path) -> None:
        from components.imap_ops import export_account
        from components.models import Account, ServerConfig

        inbox_body = b"Message-ID: <legacy-inbox@example.com>\r\nFrom: a\r\nTo: b\r\n\r\ninbox"
        flagged_body = b"Message-ID: <legacy-flagged-archived@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nflagged"

        class InboxAndFlaggedSource:
            response = _stable_uidvalidity_response

            def __init__(self) -> None:
                self.selected: List[str] = []
                self.selected_mailbox = ""

            def list(self):
                return "OK", [
                    b'(\\HasNoChildren) "/" "INBOX"',
                    b'(\\HasNoChildren \\Flagged) "/" "Flagged"',
                ]

            def select(self, mailbox: str, readonly: bool = False):
                self.selected_mailbox = mailbox.strip('"').replace(r"\"", '"')
                self.selected.append(self.selected_mailbox)
                return "OK", [b"1"]

            def uid(self, command: str, *args):
                if command == "search":
                    return "OK", [b"1"]
                if command == "fetch":
                    body = flagged_body if self.selected_mailbox == "Flagged" else inbox_body
                    return "OK", [(
                        b'1 (UID 1 FLAGS (\\Seen \\Flagged) INTERNALDATE "01-Jan-2024 00:00:00 +0000")',
                        body,
                    )]
                raise AssertionError(command)

            def logout(self):
                return "OK", []

        source = InboxAndFlaggedSource()

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[InboxAndFlaggedSource]:
            yield source

        with mock.patch("components.imap_ops.imap_connection", fake_connection):
            export_account(
                Account("user@example.com", "secret"),
                ServerConfig("imap.example.com"),
                tmp_path,
                ignore_errors=False,
            )

        account_dir = tmp_path / "user@example.com"
        state = json.loads((account_dir / "export-state.json").read_text())
        assert _unique_ordered(source.selected) == ["INBOX", "Flagged"]
        assert state["mailboxes"] == [
            {"mailbox": "INBOX", "path": "INBOX", "message_count": 1, "uidvalidity": "123"},
            {"mailbox": "Flagged", "path": "Flagged", "message_count": 1, "uidvalidity": "123"},
        ]
        assert (account_dir / "INBOX" / "u0000000001.eml").read_bytes() == inbox_body
        assert (account_dir / "Flagged" / "u0000000001.eml").read_bytes() == flagged_body

    def test_export_dedupes_generic_all_after_later_sorting_physical_mailbox(self, tmp_path: Path) -> None:
        from components.imap_ops import export_account
        from components.models import Account, ServerConfig

        body = b"Message-ID: <legacy-project@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody"

        class ProjectAndAllSource:
            response = _stable_uidvalidity_response

            def __init__(self) -> None:
                self.selected: List[str] = []
                self.selected_mailbox = ""

            def list(self):
                return "OK", [
                    b'(\\HasNoChildren \\All) "/" "All Mail"',
                    b'(\\HasNoChildren) "/" "Projects"',
                ]

            def select(self, mailbox: str, readonly: bool = False):
                self.selected_mailbox = mailbox.strip('"').replace(r"\"", '"')
                self.selected.append(self.selected_mailbox)
                return "OK", [b"1"]

            def uid(self, command: str, *args):
                if command == "search":
                    return "OK", [b"1"]
                if command == "fetch":
                    return "OK", [(
                        b'1 (UID 1 FLAGS (\\Seen) INTERNALDATE "01-Jan-2024 00:00:00 +0000")',
                        body,
                    )]
                raise AssertionError(command)

            def logout(self):
                return "OK", []

        source = ProjectAndAllSource()

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[ProjectAndAllSource]:
            yield source

        with mock.patch("components.imap_ops.imap_connection", fake_connection):
            export_account(
                Account("user@example.com", "secret"),
                ServerConfig("imap.example.com"),
                tmp_path,
                ignore_errors=False,
            )

        account_dir = tmp_path / "user@example.com"
        state = json.loads((account_dir / "export-state.json").read_text())
        assert _unique_ordered(source.selected) == ["Projects", "All Mail"]
        assert state["mailboxes"] == [
            {"mailbox": "Projects", "path": "Projects", "message_count": 1, "uidvalidity": "123"},
            {
                "mailbox": "All Mail",
                "path": "All_Mail",
                "message_count": 0,
                "covered_by_regular_content": True,
                "uidvalidity": "123",
            },
        ]
        assert (account_dir / "Projects" / "u0000000001.eml").read_bytes() == body
        all_marker = json.loads((account_dir / "All_Mail" / ".mailbox.json").read_text())
        assert all_marker["covered_by_regular_content"] is True
        assert all_marker["message_count"] == 0

    def test_export_keeps_generic_flagged_when_no_concrete_mailbox(self, tmp_path: Path) -> None:
        from components.imap_ops import export_account
        from components.models import Account, ServerConfig

        flagged_body = b"Message-ID: <legacy-flagged@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nflagged"

        class FlaggedOnlySource:
            response = _stable_uidvalidity_response

            def __init__(self) -> None:
                self.selected: List[str] = []
                self.selected_mailbox = ""

            def list(self):
                return "OK", [
                    b'(\\HasNoChildren \\Flagged) "/" "Flagged"',
                ]

            def select(self, mailbox: str, readonly: bool = False):
                self.selected_mailbox = mailbox.strip('"').replace(r"\"", '"')
                self.selected.append(self.selected_mailbox)
                return "OK", [b"1"]

            def uid(self, command: str, *args):
                if command == "search":
                    return "OK", [b"1"]
                if command == "fetch":
                    return "OK", [(
                        b'1 (UID 1 FLAGS (\\Seen \\Flagged) INTERNALDATE "01-Jan-2024 00:00:00 +0000")',
                        flagged_body,
                    )]
                raise AssertionError(command)

            def logout(self):
                return "OK", []

        source = FlaggedOnlySource()

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[FlaggedOnlySource]:
            yield source

        with mock.patch("components.imap_ops.imap_connection", fake_connection):
            export_account(
                Account("user@example.com", "secret"),
                ServerConfig("imap.example.com"),
                tmp_path,
                ignore_errors=False,
            )

        account_dir = tmp_path / "user@example.com"
        state = json.loads((account_dir / "export-state.json").read_text())
        assert _unique_ordered(source.selected) == ["Flagged"]
        assert state["mailboxes"] == [
            {"mailbox": "Flagged", "path": "Flagged", "message_count": 1, "uidvalidity": "123"},
        ]
        assert (account_dir / "Flagged" / "u0000000001.eml").read_bytes() == flagged_body

    def test_export_records_covered_generic_flagged_view(self, tmp_path: Path) -> None:
        from components.content_binding import legacy_content_binding_issue
        from components.imap_ops import export_account
        from components.models import Account, ServerConfig

        body = b"Message-ID: <legacy-covered-flagged@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nsame"

        class CoveredFlaggedSource:
            response = _stable_uidvalidity_response

            def __init__(self) -> None:
                self.selected: List[str] = []
                self.selected_mailbox = ""

            def list(self):
                return "OK", [
                    b'(\\HasNoChildren) "/" "Archive"',
                    b'(\\HasNoChildren \\Flagged) "/" "Flagged"',
                ]

            def select(self, mailbox: str, readonly: bool = False):
                self.selected_mailbox = mailbox.strip('"').replace(r"\"", '"')
                self.selected.append(self.selected_mailbox)
                return "OK", [b"1"]

            def uid(self, command: str, *args):
                if command == "search":
                    return "OK", [b"1"]
                if command == "fetch":
                    flags = "\\Seen \\Flagged" if self.selected_mailbox == "Flagged" else "\\Seen"
                    return "OK", [(
                        f'1 (UID 1 FLAGS ({flags}) INTERNALDATE "01-Jan-2024 00:00:00 +0000")'.encode("ascii"),
                        body,
                    )]
                raise AssertionError(command)

            def logout(self):
                return "OK", []

        source = CoveredFlaggedSource()

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[CoveredFlaggedSource]:
            yield source

        with mock.patch("components.imap_ops.imap_connection", fake_connection):
            export_account(
                Account("user@example.com", "secret"),
                ServerConfig("imap.example.com"),
                tmp_path,
                ignore_errors=False,
            )

        account_dir = tmp_path / "user@example.com"
        state = json.loads((account_dir / "export-state.json").read_text())
        assert _unique_ordered(source.selected) == ["Archive", "Flagged"]
        assert state["mailboxes"] == [
            {"mailbox": "Archive", "path": "Archive", "message_count": 1, "uidvalidity": "123"},
            {
                "mailbox": "Flagged",
                "path": "Flagged",
                "message_count": 0,
                "covered_by_regular_content": True,
                "uidvalidity": "123",
            },
        ]
        assert (account_dir / "Archive" / "u0000000001.eml").read_bytes() == body
        archive_meta = json.loads((account_dir / "Archive" / "u0000000001.json").read_text())
        assert archive_meta["flags"] == "\\Seen \\Flagged"
        assert legacy_content_binding_issue(archive_meta) is None
        flagged_marker = json.loads((account_dir / "Flagged" / ".mailbox.json").read_text())
        assert flagged_marker == {
            "mailbox": "Flagged",
            "message_count": 0,
            "covered_by_regular_content": True,
            "uidvalidity": "123",
        }
        assert not list((account_dir / "Flagged").glob("u*.eml"))

    def test_export_merges_covered_flagged_view_by_internaldate_for_identical_duplicates(
        self,
        tmp_path: Path,
    ) -> None:
        from components.content_binding import legacy_content_binding_issue
        from components.imap_ops import export_account
        from components.models import Account, ServerConfig

        body = b"Message-ID: <legacy-identical-flagged@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nsame"

        class DuplicateCoveredFlaggedSource:
            response = _stable_uidvalidity_response

            def __init__(self) -> None:
                self.selected: List[str] = []
                self.selected_mailbox = ""

            def list(self):
                return "OK", [
                    b'(\\HasNoChildren) "/" "Archive"',
                    b'(\\HasNoChildren \\Flagged) "/" "Flagged"',
                ]

            def select(self, mailbox: str, readonly: bool = False):
                self.selected_mailbox = mailbox.strip('"').replace(r"\"", '"')
                self.selected.append(self.selected_mailbox)
                return "OK", [b"2" if self.selected_mailbox == "Archive" else b"1"]

            def uid(self, command: str, *args):
                if command == "search":
                    return "OK", [b"1 2" if self.selected_mailbox == "Archive" else b"2"]
                if command == "fetch":
                    uid = str(args[0])
                    internaldate = "02-Jan-2024 00:00:00 +0000" if uid == "2" else "01-Jan-2024 00:00:00 +0000"
                    flags = "\\Seen \\Flagged" if self.selected_mailbox == "Flagged" else "\\Seen"
                    return "OK", [(
                        f'{uid} (UID {uid} FLAGS ({flags}) INTERNALDATE "{internaldate}")'.encode("ascii"),
                        body,
                    )]
                raise AssertionError(command)

            def logout(self):
                return "OK", []

        source = DuplicateCoveredFlaggedSource()

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[DuplicateCoveredFlaggedSource]:
            yield source

        with mock.patch("components.imap_ops.imap_connection", fake_connection):
            export_account(
                Account("user@example.com", "secret"),
                ServerConfig("imap.example.com"),
                tmp_path,
                ignore_errors=False,
            )

        account_dir = tmp_path / "user@example.com"
        first_meta = json.loads((account_dir / "Archive" / "u0000000001.json").read_text())
        second_meta = json.loads((account_dir / "Archive" / "u0000000002.json").read_text())
        assert first_meta["internaldate"] == "01-Jan-2024 00:00:00 +0000"
        assert second_meta["internaldate"] == "02-Jan-2024 00:00:00 +0000"
        assert first_meta["flags"] == "\\Seen"
        assert second_meta["flags"] == "\\Seen \\Flagged"
        assert legacy_content_binding_issue(first_meta) is None
        assert legacy_content_binding_issue(second_meta) is None
        flagged_marker = json.loads((account_dir / "Flagged" / ".mailbox.json").read_text())
        assert flagged_marker["covered_by_regular_content"] is True
        assert not list((account_dir / "Flagged").glob("u*.eml"))

    def test_export_keeps_generic_all_when_it_is_only_source_mailbox(self, tmp_path: Path) -> None:
        from components.imap_ops import export_account
        from components.models import Account, ServerConfig

        body = b"Message-ID: <legacy-all-only@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody"

        class AllOnlySource:
            response = _stable_uidvalidity_response

            def __init__(self) -> None:
                self.selected: List[str] = []
                self.selected_mailbox = ""

            def list(self):
                return "OK", [
                    b'(\\HasNoChildren \\All) "/" "All Mail"',
                ]

            def select(self, mailbox: str, readonly: bool = False):
                self.selected_mailbox = mailbox.strip('"').replace(r"\"", '"')
                self.selected.append(self.selected_mailbox)
                return "OK", [b"1"]

            def uid(self, command: str, *args):
                if command == "search":
                    return "OK", [b"1"]
                if command == "fetch":
                    return "OK", [(
                        b'1 (UID 1 FLAGS (\\Seen) INTERNALDATE "01-Jan-2024 00:00:00 +0000")',
                        body,
                    )]
                raise AssertionError(command)

            def logout(self):
                return "OK", []

        source = AllOnlySource()

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[AllOnlySource]:
            yield source

        with mock.patch("components.imap_ops.imap_connection", fake_connection):
            export_account(
                Account("user@example.com", "secret"),
                ServerConfig("imap.example.com"),
                tmp_path,
                ignore_errors=False,
            )

        account_dir = tmp_path / "user@example.com"
        state = json.loads((account_dir / "export-state.json").read_text())
        assert _unique_ordered(source.selected) == ["All Mail"]
        assert state["mailboxes"] == [
            {"mailbox": "All Mail", "path": "All_Mail", "message_count": 1, "uidvalidity": "123"},
        ]
        assert (account_dir / "All_Mail" / "u0000000001.eml").read_bytes() == body

    def test_export_keeps_empty_generic_all_when_it_is_only_source_mailbox(self, tmp_path: Path) -> None:
        from components.audit import audit_account
        from components.imap_ops import export_account, import_account
        from components.models import Account, ServerConfig
        from verify_export import verify_account

        class EmptyAllOnlySource:
            response = _stable_uidvalidity_response

            def __init__(self) -> None:
                self.selected: List[str] = []
                self.selected_mailbox = ""

            def list(self):
                return "OK", [
                    b'(\\HasNoChildren \\All) "/" "All Mail"',
                ]

            def select(self, mailbox: str, readonly: bool = False):
                self.selected_mailbox = mailbox.strip('"').replace(r"\"", '"')
                self.selected.append(self.selected_mailbox)
                return "OK", [b"0"]

            def uid(self, command: str, *args):
                if command == "search":
                    return "OK", [b""]
                raise AssertionError(command)

            def logout(self):
                return "OK", []

        class EmptyImportTarget:
            def __init__(self) -> None:
                self.mailboxes = {"INBOX"}
                self.created: List[str] = []
                self.selected: List[str] = []
                self.subscribed: List[str] = []

            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

            def select(self, mailbox: str, readonly: bool = False):
                selected = mailbox.strip('"').replace(r"\"", '"')
                self.selected.append(selected)
                return ("OK", [b"0"]) if selected in self.mailboxes else ("NO", [b"missing"])

            def create(self, mailbox: str):
                selected = mailbox.strip('"').replace(r"\"", '"')
                self.created.append(selected)
                self.mailboxes.add(selected)
                return "OK", [b""]

            def subscribe(self, mailbox: str):
                self.subscribed.append(mailbox.strip('"').replace(r"\"", '"'))
                return "OK", [b""]

            def logout(self):
                return "OK", []

        account = Account("user@example.com", "secret")
        source_server = ServerConfig("source.example.com")
        target_server = ServerConfig("target.example.com")
        source = EmptyAllOnlySource()
        target = EmptyImportTarget()

        @contextlib.contextmanager
        def source_connection(*_args, **_kwargs) -> Iterator[EmptyAllOnlySource]:
            yield source

        @contextlib.contextmanager
        def target_connection(*_args, **_kwargs) -> Iterator[EmptyImportTarget]:
            yield target

        with mock.patch("components.imap_ops.imap_connection", source_connection):
            export_account(account, source_server, tmp_path, ignore_errors=False)

        account_dir = tmp_path / "user@example.com"
        state = json.loads((account_dir / "export-state.json").read_text())
        marker = json.loads((account_dir / "All_Mail" / ".mailbox.json").read_text())

        assert _unique_ordered(source.selected) == ["All Mail"]
        assert state["mailboxes"] == [
            {"mailbox": "All Mail", "path": "All_Mail", "message_count": 0, "uidvalidity": "123"},
        ]
        assert marker == {"mailbox": "All Mail", "message_count": 0, "uidvalidity": "123"}
        assert not list((account_dir / "All_Mail").glob("u*.eml"))

        _email, audit_issues = audit_account(
            account,
            tmp_path,
            server=None,
            check_remote=False,
            require_integrity_metadata=True,
            expected_source_server=source_server,
        )
        assert audit_issues == []
        assert verify_account(account_dir)["errors"] == 0

        import_account(
            account,
            target_server,
            tmp_path,
            ignore_errors=False,
            imap_factory=target_connection,
            source_server=source_server,
        )

        assert target.created == ["All Mail"]
        assert target.subscribed == ["All Mail"]

    def test_export_keeps_identical_generic_all_only_messages_distinct(self, tmp_path: Path) -> None:
        from components.imap_ops import export_account
        from components.models import Account, ServerConfig

        body = b"Message-ID: <legacy-all-only-duplicate@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nsame"

        class DuplicateAllOnlySource:
            response = _stable_uidvalidity_response

            def __init__(self) -> None:
                self.selected: List[str] = []
                self.selected_mailbox = ""

            def list(self):
                return "OK", [
                    b'(\\HasNoChildren \\All) "/" "All Mail"',
                ]

            def select(self, mailbox: str, readonly: bool = False):
                self.selected_mailbox = mailbox.strip('"').replace(r"\"", '"')
                self.selected.append(self.selected_mailbox)
                return "OK", [b"2"]

            def uid(self, command: str, *args):
                if command == "search":
                    return "OK", [b"1 2"]
                if command == "fetch":
                    uid = str(args[0])
                    return "OK", [(
                        f'{uid} (UID {uid} FLAGS (\\Seen) INTERNALDATE "01-Jan-2024 00:00:00 +0000")'.encode("ascii"),
                        body,
                    )]
                raise AssertionError(command)

            def logout(self):
                return "OK", []

        source = DuplicateAllOnlySource()

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[DuplicateAllOnlySource]:
            yield source

        with mock.patch("components.imap_ops.imap_connection", fake_connection):
            export_account(
                Account("user@example.com", "secret"),
                ServerConfig("imap.example.com"),
                tmp_path,
                ignore_errors=False,
            )

        account_dir = tmp_path / "user@example.com"
        state = json.loads((account_dir / "export-state.json").read_text())
        assert _unique_ordered(source.selected) == ["All Mail"]
        assert state["mailboxes"] == [
            {"mailbox": "All Mail", "path": "All_Mail", "message_count": 2, "uidvalidity": "123"},
        ]
        assert (account_dir / "All_Mail" / "u0000000001.eml").read_bytes() == body
        assert (account_dir / "All_Mail" / "u0000000002.eml").read_bytes() == body
        metadata_uids = {
            json.loads(path.read_text())["uid"]
            for path in sorted((account_dir / "All_Mail").glob("u*.json"))
        }
        assert metadata_uids == {1, 2}

    def test_export_persists_and_binds_legacy_uidvalidity(self, tmp_path: Path) -> None:
        from components.imap_ops import export_account
        from components.models import Account, ServerConfig

        body = b"Message-ID: <legacy-uidvalidity@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody"

        class UIDValiditySource:
            def __init__(self) -> None:
                self.selected = ""
                self.response_calls: List[str] = []

            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

            def select(self, mailbox: str, readonly: bool = False):
                self.selected = mailbox.strip('"').replace(r"\"", '"')
                return "OK", [b"1"]

            def response(self, name: str):
                self.response_calls.append(name)
                return "OK", [b"123"]

            def uid(self, command: str, *args):
                if command == "search":
                    return "OK", [b"1"]
                if command == "fetch":
                    return "OK", [(
                        b'1 (UID 1 FLAGS (\\Seen) INTERNALDATE "01-Jan-2024 00:00:00 +0000")',
                        body,
                    )]
                raise AssertionError(command)

            def logout(self):
                return "OK", []

        source = UIDValiditySource()

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[UIDValiditySource]:
            yield source

        with mock.patch("components.imap_ops.imap_connection", fake_connection):
            export_account(Account("user@example.com", "secret"), ServerConfig("imap.example.com"), tmp_path, ignore_errors=False)

        account_dir = tmp_path / "user@example.com"
        marker = json.loads((account_dir / "INBOX" / ".mailbox.json").read_text())
        metadata = json.loads((account_dir / "INBOX" / "u0000000001.json").read_text())
        state = json.loads((account_dir / "export-state.json").read_text())

        assert source.response_calls == ["UIDVALIDITY", "UIDVALIDITY"]
        assert marker["uidvalidity"] == "123"
        assert metadata["uidvalidity"] == "123"
        assert state["mailboxes"][0]["uidvalidity"] == "123"

    def test_export_fails_without_legacy_uidvalidity(self, tmp_path: Path) -> None:
        from components.imap_ops import export_account
        from components.models import Account, ServerConfig

        body = b"Message-ID: <legacy-missing-uidvalidity@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody"

        class MissingUIDValiditySource:
            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"1"]

            def response(self, name: str):
                return "OK", [None]

            def uid(self, command: str, *args):
                if command == "search":
                    return "OK", [b"1"]
                if command == "fetch":
                    return "OK", [(
                        b'1 (UID 1 FLAGS (\\Seen) INTERNALDATE "01-Jan-2024 00:00:00 +0000")',
                        body,
                    )]
                raise AssertionError(command)

            def logout(self):
                return "OK", []

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[MissingUIDValiditySource]:
            yield MissingUIDValiditySource()

        with mock.patch("components.imap_ops.imap_connection", fake_connection):
            with pytest.raises(RuntimeError, match="did not provide valid UIDVALIDITY"):
                export_account(Account("user@example.com", "secret"), ServerConfig("imap.example.com"), tmp_path, ignore_errors=False)

        assert not (tmp_path / "user@example.com" / "INBOX" / "u0000000001.eml").exists()

    def test_export_fails_when_legacy_uidvalidity_changes(self, tmp_path: Path) -> None:
        from components.imap_ops import export_account
        from components.models import Account, ServerConfig

        body = b"Message-ID: <legacy-uidvalidity-changed@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody"

        class ChangingUIDValiditySource:
            def __init__(self) -> None:
                self.select_count = 0

            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

            def select(self, mailbox: str, readonly: bool = False):
                self.select_count += 1
                return "OK", [b"1"]

            def response(self, name: str):
                return "OK", [b"111" if self.select_count == 1 else b"222"]

            def uid(self, command: str, *args):
                if command == "search":
                    return "OK", [b"1"]
                if command == "fetch":
                    return "OK", [(
                        b'1 (UID 1 FLAGS (\\Seen) INTERNALDATE "01-Jan-2024 00:00:00 +0000")',
                        body,
                    )]
                raise AssertionError(command)

            def logout(self):
                return "OK", []

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[ChangingUIDValiditySource]:
            yield ChangingUIDValiditySource()

        with mock.patch("components.imap_ops.imap_connection", fake_connection):
            with pytest.raises(RuntimeError, match="UIDVALIDITY changed during export of INBOX"):
                export_account(Account("user@example.com", "secret"), ServerConfig("imap.example.com"), tmp_path, ignore_errors=False)

    def test_export_fails_when_legacy_uid_set_changes(self, tmp_path: Path) -> None:
        from components.imap_ops import export_account
        from components.models import Account, ServerConfig

        body = b"Message-ID: <legacy-uid-set-changed@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody"

        class ChangingUIDSetSource:
            def __init__(self) -> None:
                self.search_count = 0

            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"1" if self.search_count == 0 else b"2"]

            def response(self, name: str):
                return "OK", [b"123"]

            def uid(self, command: str, *args):
                if command == "search":
                    self.search_count += 1
                    return "OK", [b"1" if self.search_count == 1 else b"1 2"]
                if command == "fetch":
                    return "OK", [(
                        b'1 (UID 1 FLAGS (\\Seen) INTERNALDATE "01-Jan-2024 00:00:00 +0000")',
                        body,
                    )]
                raise AssertionError(command)

            def logout(self):
                return "OK", []

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[ChangingUIDSetSource]:
            yield ChangingUIDSetSource()

        with mock.patch("components.imap_ops.imap_connection", fake_connection):
            with pytest.raises(RuntimeError, match="UID set changed during export of INBOX"):
                export_account(Account("user@example.com", "secret"), ServerConfig("imap.example.com"), tmp_path, ignore_errors=False)

        state = json.loads((tmp_path / "user@example.com" / "export-state.json").read_text())
        assert state["complete"] is False
        assert not (tmp_path / "user@example.com" / "INBOX" / ".mailbox.json").exists()

    def test_export_fails_when_legacy_flags_change(self, tmp_path: Path) -> None:
        from components.imap_ops import export_account
        from components.models import Account, ServerConfig

        body = b"Message-ID: <legacy-flags-changed@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody"

        class ChangingFlagsSource:
            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"1"]

            def response(self, name: str):
                return "OK", [b"123"]

            def uid(self, command: str, *args):
                if command == "search":
                    return "OK", [b"1"]
                if command == "fetch":
                    query = str(args[-1])
                    if query == "(FLAGS)":
                        return "OK", [b"1 (UID 1 FLAGS (\\Seen \\Answered))"]
                    return "OK", [(
                        b'1 (UID 1 FLAGS (\\Seen) INTERNALDATE "01-Jan-2024 00:00:00 +0000")',
                        body,
                    )]
                raise AssertionError(command)

            def logout(self):
                return "OK", []

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[ChangingFlagsSource]:
            yield ChangingFlagsSource()

        with mock.patch("components.imap_ops.imap_connection", fake_connection):
            with pytest.raises(RuntimeError, match=r"FLAGS changed during export of INBOX for UID 1"):
                export_account(Account("user@example.com", "secret"), ServerConfig("imap.example.com"), tmp_path, ignore_errors=False)

        state = json.loads((tmp_path / "user@example.com" / "export-state.json").read_text())
        assert state["complete"] is False
        assert not (tmp_path / "user@example.com" / "INBOX" / ".mailbox.json").exists()

    def test_audit_import_and_verify_reject_legacy_uidvalidity_mismatch(self, tmp_path: Path) -> None:
        from components.audit import audit_account
        from components.content_binding import CONTENT_BINDING_FIELD, legacy_content_binding_sha256
        from components.imap_ops import export_account, import_account
        from components.models import Account, ServerConfig
        from verify_export import verify_account

        body = b"Message-ID: <legacy-uidvalidity-mismatch@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody"

        class UIDValiditySource:
            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"1"]

            def response(self, name: str):
                return "OK", [b"123"]

            def uid(self, command: str, *args):
                if command == "search":
                    return "OK", [b"1"]
                if command == "fetch":
                    return "OK", [(
                        b'1 (UID 1 FLAGS (\\Seen) INTERNALDATE "01-Jan-2024 00:00:00 +0000")',
                        body,
                    )]
                raise AssertionError(command)

            def logout(self):
                return "OK", []

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[UIDValiditySource]:
            yield UIDValiditySource()

        account = Account("user@example.com", "secret")
        server = ServerConfig("imap.example.com")
        with mock.patch("components.imap_ops.imap_connection", fake_connection):
            export_account(account, server, tmp_path, ignore_errors=False)

        metadata_path = tmp_path / "user@example.com" / "INBOX" / "u0000000001.json"
        metadata = json.loads(metadata_path.read_text())
        metadata["uidvalidity"] = "456"
        metadata[CONTENT_BINDING_FIELD] = legacy_content_binding_sha256(metadata)
        metadata_path.write_text(json.dumps(metadata))

        _email, audit_issues = audit_account(
            account,
            tmp_path,
            server=None,
            check_remote=False,
            require_integrity_metadata=True,
        )
        stats = verify_account(tmp_path / "user@example.com")

        assert any("uidvalidity mismatch" in issue for issue in audit_issues)
        assert stats["errors"] > 0
        with pytest.raises(RuntimeError, match="uidvalidity mismatch"):
            import_account(account, server, tmp_path, ignore_errors=False)

    def test_export_uses_generic_all_instead_of_flagged_when_no_concrete_mailbox(self, tmp_path: Path) -> None:
        from components.imap_ops import export_account
        from components.models import Account, ServerConfig

        flagged_body = b"Message-ID: <legacy-all-flagged@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nflagged"
        archived_body = b"Message-ID: <legacy-all-archived@example.com>\r\nFrom: a\r\nTo: b\r\n\r\narchived"

        class AllAndFlaggedSource:
            response = _stable_uidvalidity_response

            def __init__(self) -> None:
                self.selected: List[str] = []
                self.selected_mailbox = ""

            def list(self):
                return "OK", [
                    b'(\\HasNoChildren \\All) "/" "All Mail"',
                    b'(\\HasNoChildren \\Flagged) "/" "Flagged"',
                ]

            def select(self, mailbox: str, readonly: bool = False):
                self.selected_mailbox = mailbox.strip('"').replace(r"\"", '"')
                self.selected.append(self.selected_mailbox)
                count = b"2" if self.selected_mailbox == "All Mail" else b"1"
                return "OK", [count]

            def uid(self, command: str, *args):
                if command == "search":
                    return "OK", [b"1 2"] if self.selected_mailbox == "All Mail" else [b"1"]
                if command == "fetch":
                    uid = str(args[0])
                    body = flagged_body if uid == "1" else archived_body
                    flags = "\\Seen \\Flagged" if uid == "1" else "\\Seen"
                    return "OK", [(
                        f'{uid} (UID {uid} FLAGS ({flags}) INTERNALDATE "01-Jan-2024 00:00:00 +0000")'.encode("ascii"),
                        body,
                    )]
                raise AssertionError(command)

            def logout(self):
                return "OK", []

        source = AllAndFlaggedSource()

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[AllAndFlaggedSource]:
            yield source

        with mock.patch("components.imap_ops.imap_connection", fake_connection):
            export_account(
                Account("user@example.com", "secret"),
                ServerConfig("imap.example.com"),
                tmp_path,
                ignore_errors=False,
            )

        account_dir = tmp_path / "user@example.com"
        state = json.loads((account_dir / "export-state.json").read_text())
        assert _unique_ordered(source.selected) == ["All Mail"]
        assert state["mailboxes"] == [
            {"mailbox": "All Mail", "path": "All_Mail", "message_count": 2, "uidvalidity": "123"},
        ]
        assert (account_dir / "All_Mail" / "u0000000001.eml").read_bytes() == flagged_body
        assert (account_dir / "All_Mail" / "u0000000002.eml").read_bytes() == archived_body
        assert not (account_dir / "Flagged").exists()

    def test_export_requests_special_use_attrs_before_filtering_all_view(self, tmp_path: Path) -> None:
        from components.imap_ops import export_account
        from components.models import Account, ServerConfig

        body = b"Message-ID: <legacy-special-use-return@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody"

        class SpecialUseReturnSource:
            response = _stable_uidvalidity_response

            def __init__(self) -> None:
                self.list_calls: List[tuple] = []
                self.selected: List[str] = []
                self.selected_mailbox = ""

            def list(self, *args):
                self.list_calls.append(args)
                all_attrs = b'(\\HasNoChildren \\All) "/" "All Mail"'
                if args == ('""', '"*" RETURN (SPECIAL-USE)'):
                    return "OK", [
                        b'(\\HasNoChildren) "/" "INBOX"',
                        all_attrs,
                    ]
                return "OK", [
                    b'(\\HasNoChildren) "/" "INBOX"',
                    b'(\\HasNoChildren) "/" "All Mail"',
                ]

            def select(self, mailbox: str, readonly: bool = False):
                self.selected_mailbox = mailbox.strip('"').replace(r"\"", '"')
                self.selected.append(self.selected_mailbox)
                return "OK", [b"1"]

            def uid(self, command: str, *args):
                if command == "search":
                    return "OK", [b"1"]
                if command == "fetch":
                    return "OK", [(
                        b'1 (UID 1 FLAGS (\\Seen) INTERNALDATE "01-Jan-2024 00:00:00 +0000")',
                        body,
                    )]
                raise AssertionError(command)

            def logout(self):
                return "OK", []

        source = SpecialUseReturnSource()

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[SpecialUseReturnSource]:
            yield source

        with mock.patch("components.imap_ops.imap_connection", fake_connection):
            export_account(
                Account("user@example.com", "secret"),
                ServerConfig("imap.example.com"),
                tmp_path,
                ignore_errors=False,
            )

        account_dir = tmp_path / "user@example.com"
        state = json.loads((account_dir / "export-state.json").read_text())
        assert source.list_calls == [('""', '"*" RETURN (SPECIAL-USE)')]
        assert _unique_ordered(source.selected) == ["INBOX", "All Mail"]
        assert state["mailboxes"] == [
            {"mailbox": "INBOX", "path": "INBOX", "message_count": 1, "uidvalidity": "123"},
            {
                "mailbox": "All Mail",
                "path": "All_Mail",
                "message_count": 0,
                "covered_by_regular_content": True,
                "uidvalidity": "123",
            },
        ]
        all_marker = json.loads((account_dir / "All_Mail" / ".mailbox.json").read_text())
        assert all_marker["covered_by_regular_content"] is True

    def test_remote_audit_uses_legacy_export_scope_mailboxes(self, tmp_path: Path) -> None:
        from components.audit import audit_export
        from components.imap_ops import export_account
        from components.models import Account, Config, ServerConfig

        body = b"Message-ID: <legacy-audit-special-use@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody"

        class SpecialUseRemote:
            response = _stable_uidvalidity_response

            def __init__(self) -> None:
                self.selected_mailbox = ""

            def list(self):
                return "OK", [
                    b'(\\HasNoChildren) "/" "INBOX"',
                    b'(\\HasNoChildren \\All) "/" "All Mail"',
                ]

            def select(self, mailbox: str, readonly: bool = False):
                self.selected_mailbox = mailbox.strip('"').replace(r"\"", '"')
                return "OK", [b"1"]

            def uid(self, command: str, *args):
                if command == "search":
                    return "OK", [b"1"]
                if command == "fetch":
                    return "OK", [(
                        b'1 (UID 1 FLAGS (\\Seen) INTERNALDATE "01-Jan-2024 00:00:00 +0000")',
                        body,
                    )]
                raise AssertionError(command)

            def search(self, charset, *criteria):
                if len(criteria) == 3 and criteria[:2] == ("HEADER", "Message-ID"):
                    wanted = str(criteria[2]).strip('"')
                    if wanted == "<legacy-audit-special-use@example.com>":
                        return "OK", [b"1"]
                if criteria == ("ALL",):
                    return "OK", [b"1"]
                return "OK", [b""]

            def fetch(self, num: bytes, query: str):
                return "OK", [(b"1 (RFC822.SIZE 73 FLAGS (\\Seen) INTERNALDATE \"01-Jan-2024 00:00:00 +0000\" BODY[] {73}", body)]

            def logout(self):
                return "OK", []

        remote = SpecialUseRemote()

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[SpecialUseRemote]:
            yield remote

        account = Account("user@example.com", "secret")
        server = ServerConfig("imap.example.com")
        with mock.patch("components.imap_ops.imap_connection", fake_connection):
            export_account(account, server, tmp_path, ignore_errors=False)

        with mock.patch("components.audit.imap_connection", fake_connection):
            ok, issues = audit_export(
                tmp_path,
                Config(server, [account], source_server=server),
                1,
                check_remote=True,
                require_integrity_metadata=True,
            )

        assert ok, issues

    def test_validate_uses_legacy_export_scope_mailboxes(self, tmp_path: Path) -> None:
        from components.imap_ops import export_account
        from components.main import main
        from components.models import Account, ServerConfig

        body = b"Message-ID: <legacy-validate-special-use@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody"

        class SpecialUseRemote:
            response = _stable_uidvalidity_response

            def __init__(self) -> None:
                self.selected_mailbox = ""

            def list(self):
                return "OK", [
                    b'(\\HasNoChildren) "/" "INBOX"',
                    b'(\\HasNoChildren \\All) "/" "All Mail"',
                ]

            def select(self, mailbox: str, readonly: bool = False):
                self.selected_mailbox = mailbox.strip('"').replace(r"\"", '"')
                return "OK", [b"1"]

            def uid(self, command: str, *args):
                if command == "search":
                    return "OK", [b"1"]
                if command == "fetch":
                    return "OK", [(
                        b'1 (UID 1 FLAGS (\\Seen) INTERNALDATE "01-Jan-2024 00:00:00 +0000")',
                        body,
                    )]
                raise AssertionError(command)

            def search(self, charset, *criteria):
                if criteria == ("ALL",):
                    return "OK", [b"1"]
                if len(criteria) == 3 and criteria[:2] == ("HEADER", "Message-ID"):
                    wanted = str(criteria[2]).strip('"')
                    if wanted == "<legacy-validate-special-use@example.com>":
                        return "OK", [b"1"]
                return "OK", [b""]

            def fetch(self, num: bytes, query: str):
                return "OK", [(b"1 (RFC822.SIZE 76 FLAGS (\\Seen) INTERNALDATE \"01-Jan-2024 00:00:00 +0000\" BODY[] {76}", body)]

            def logout(self):
                return "OK", []

        remote = SpecialUseRemote()

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[SpecialUseRemote]:
            yield remote

        account = Account("user@example.com", "secret")
        server = ServerConfig("imap.example.com")
        with mock.patch("components.imap_ops.imap_connection", fake_connection):
            export_account(account, server, tmp_path / "exported", ignore_errors=False)

        config_path = tmp_path / "config.json"
        server_json = {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False}
        config_path.write_text(json.dumps({
            "server": server_json,
            "source_server": server_json,
            "accounts": [{"email": account.email, "password": account.password}],
        }))

        with mock.patch("components.imap_ops.imap_connection", fake_connection):
            rc = main([
                "--mode", "validate",
                "--config", str(config_path),
                "--input-dir", str(tmp_path / "exported"),
                "--log-dir", str(tmp_path / "logs"),
                "--max-workers", "1",
                "--min-free-gb", "0",
                "--no-connectivity-test",
            ])

        assert rc == 0

    def test_audit_and_validate_accept_deduped_all_with_archived_only_message(self, tmp_path: Path) -> None:
        from components.audit import audit_export
        from components.imap_ops import export_account
        from components.main import main
        from components.models import Account, Config, ServerConfig

        inbox_body = b"Message-ID: <legacy-audit-inbox@example.com>\r\nFrom: a\r\nTo: b\r\n\r\ninbox"
        archived_body = b"Message-ID: <legacy-audit-archived@example.com>\r\nFrom: a\r\nTo: b\r\n\r\narchived"

        class InboxAndAllRemote:
            response = _stable_uidvalidity_response

            def __init__(self) -> None:
                self.selected_mailbox = ""

            def list(self):
                return "OK", [
                    b'(\\HasNoChildren) "/" "INBOX"',
                    b'(\\HasNoChildren \\All) "/" "All Mail"',
                ]

            def select(self, mailbox: str, readonly: bool = False):
                self.selected_mailbox = mailbox.strip('"').replace(r"\"", '"')
                return "OK", [b"1" if self.selected_mailbox == "INBOX" else b"2"]

            def uid(self, command: str, *args):
                if command == "search":
                    return "OK", [b"1" if self.selected_mailbox == "INBOX" else b"1 2"]
                if command == "fetch":
                    uid = str(args[0])
                    body = inbox_body if uid == "1" else archived_body
                    return "OK", [(
                        f'{uid} (UID {uid} FLAGS (\\Seen) INTERNALDATE "01-Jan-2024 00:00:00 +0000")'.encode("ascii"),
                        body,
                    )]
                raise AssertionError(command)

            def search(self, charset, *criteria):
                if criteria == ("ALL",):
                    return "OK", [b"1" if self.selected_mailbox == "INBOX" else b"1 2"]
                if len(criteria) == 3 and criteria[:2] == ("HEADER", "Message-ID"):
                    wanted = str(criteria[2]).strip('"')
                    if wanted == "<legacy-audit-inbox@example.com>":
                        return "OK", [b"1"]
                    if wanted == "<legacy-audit-archived@example.com>" and self.selected_mailbox == "All Mail":
                        return "OK", [b"2"]
                return "OK", [b""]

            def fetch(self, num: bytes, query: str):
                body = inbox_body if int(num) == 1 else archived_body
                return "OK", [(b"1 (RFC822.SIZE %d FLAGS (\\Seen) INTERNALDATE \"01-Jan-2024 00:00:00 +0000\" BODY[] {%d}" % (len(body), len(body)), body)]

            def logout(self):
                return "OK", []

        remote = InboxAndAllRemote()

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[InboxAndAllRemote]:
            yield remote

        account = Account("user@example.com", "secret")
        server = ServerConfig("imap.example.com")
        export_root = tmp_path / "exported"
        with mock.patch("components.imap_ops.imap_connection", fake_connection):
            export_account(account, server, export_root, ignore_errors=False)

        account_dir = export_root / "user@example.com"
        state = json.loads((account_dir / "export-state.json").read_text())
        assert state["mailboxes"] == [
            {"mailbox": "INBOX", "path": "INBOX", "message_count": 1, "uidvalidity": "123"},
            {"mailbox": "All Mail", "path": "All_Mail", "message_count": 1, "uidvalidity": "123"},
        ]

        with mock.patch("components.audit.imap_connection", fake_connection):
            ok, issues = audit_export(
                export_root,
                Config(server, [account], source_server=server),
                1,
                check_remote=True,
                require_integrity_metadata=True,
            )
        assert ok, issues

        config_path = tmp_path / "config.json"
        server_json = {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False}
        config_path.write_text(json.dumps({
            "server": server_json,
            "source_server": server_json,
            "accounts": [{"email": account.email, "password": account.password}],
        }))

        with mock.patch("components.imap_ops.imap_connection", fake_connection):
            rc = main([
                "--mode", "validate",
                "--config", str(config_path),
                "--input-dir", str(export_root),
                "--log-dir", str(tmp_path / "logs"),
                "--max-workers", "1",
                "--min-free-gb", "0",
                "--no-connectivity-test",
            ])

        assert rc == 0

    def test_remote_audit_accepts_extra_duplicate_virtual_message_export(self, tmp_path: Path) -> None:
        from components.audit import audit_export
        from components.imap_ops import export_account
        from components.models import Account, Config, ServerConfig

        body = b"Message-ID: <legacy-duplicate-virtual@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nsame"

        class DuplicateAllRemote:
            response = _stable_uidvalidity_response

            def __init__(self) -> None:
                self.selected = ""

            def list(self):
                return "OK", [
                    b'(\\HasNoChildren) "/" "INBOX"',
                    b'(\\HasNoChildren \\All) "/" "All Mail"',
                ]

            def select(self, mailbox: str, readonly: bool = False):
                self.selected = mailbox.strip('"').replace(r"\"", '"')
                return "OK", [b"1" if self.selected == "INBOX" else b"2"]

            def uid(self, command: str, *args):
                if command == "search":
                    return "OK", [b"1" if self.selected == "INBOX" else b"1 2"]
                if command == "fetch":
                    uid = str(args[0])
                    return "OK", [(
                        f'{uid} (UID {uid} FLAGS (\\Seen) INTERNALDATE "01-Jan-2024 00:00:00 +0000")'.encode("ascii"),
                        body,
                    )]
                raise AssertionError(command)

            def search(self, charset, *criteria):
                if criteria == ("ALL",):
                    return "OK", [b"1" if self.selected == "INBOX" else b"1 2"]
                if len(criteria) == 3 and criteria[:2] == ("HEADER", "Message-ID"):
                    return "OK", [b"1" if self.selected == "INBOX" else b"1 2"]
                return "OK", [b""]

            def fetch(self, num: bytes, query: str):
                return "OK", [(b"1 (RFC822.SIZE %d FLAGS (\\Seen) INTERNALDATE \"01-Jan-2024 00:00:00 +0000\" BODY[] {%d}" % (len(body), len(body)), body)]

            def logout(self):
                return "OK", []

        remote = DuplicateAllRemote()

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[DuplicateAllRemote]:
            yield remote

        account = Account("user@example.com", "secret")
        server = ServerConfig("imap.example.com")
        with mock.patch("components.imap_ops.imap_connection", fake_connection):
            export_account(account, server, tmp_path, ignore_errors=False)

        account_dir = tmp_path / "user@example.com"
        state = json.loads((account_dir / "export-state.json").read_text())
        assert state["mailboxes"] == [
            {"mailbox": "INBOX", "path": "INBOX", "message_count": 1, "uidvalidity": "123"},
            {"mailbox": "All Mail", "path": "All_Mail", "message_count": 2, "uidvalidity": "123"},
        ]
        assert (account_dir / "All_Mail" / "u0000000001.eml").read_bytes() == body
        assert (account_dir / "All_Mail" / "u0000000002.eml").read_bytes() == body

        with mock.patch("components.audit.imap_connection", fake_connection):
            ok, issues = audit_export(
                tmp_path,
                Config(server, [account], source_server=server),
                1,
                check_remote=True,
                require_integrity_metadata=True,
            )

        assert ok, issues

    def test_export_preserves_ambiguous_duplicate_virtual_metadata(self, tmp_path: Path) -> None:
        from components.imap_ops import export_account
        from components.models import Account, ServerConfig

        body = b"Message-ID: <legacy-ambiguous-duplicate-virtual@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nsame"

        class AmbiguousDuplicateAllRemote:
            response = _stable_uidvalidity_response

            def __init__(self) -> None:
                self.selected = ""

            def list(self):
                return "OK", [
                    b'(\\HasNoChildren) "/" "INBOX"',
                    b'(\\HasNoChildren \\All) "/" "All Mail"',
                ]

            def select(self, mailbox: str, readonly: bool = False):
                self.selected = mailbox.strip('"').replace(r"\"", '"')
                return "OK", [b"1" if self.selected == "INBOX" else b"2"]

            def uid(self, command: str, *args):
                if command == "search":
                    return "OK", [b"1" if self.selected == "INBOX" else b"1 2"]
                if command == "fetch":
                    uid = str(args[0])
                    flags = "\\Seen \\ArchivedOnly" if self.selected == "All Mail" and uid == "1" else "\\Seen"
                    internaldate = (
                        "01-Jan-2024 00:00:00 +0000"
                        if self.selected == "All Mail" and uid == "1"
                        else "02-Jan-2024 00:00:00 +0000"
                    )
                    return "OK", [(
                        f'{uid} (UID {uid} FLAGS ({flags}) INTERNALDATE "{internaldate}")'.encode("ascii"),
                        body,
                    )]
                raise AssertionError(command)

            def logout(self):
                return "OK", []

        account = Account("user@example.com", "secret")
        server = ServerConfig("imap.example.com")

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[AmbiguousDuplicateAllRemote]:
            yield AmbiguousDuplicateAllRemote()

        with mock.patch("components.imap_ops.imap_connection", fake_connection):
            export_account(account, server, tmp_path, ignore_errors=False)

        account_dir = tmp_path / "user@example.com"
        state = json.loads((account_dir / "export-state.json").read_text())
        assert state["mailboxes"] == [
            {"mailbox": "INBOX", "path": "INBOX", "message_count": 1, "uidvalidity": "123"},
            {"mailbox": "All Mail", "path": "All_Mail", "message_count": 2, "uidvalidity": "123"},
        ]
        all_dir = account_dir / "All_Mail"
        assert (all_dir / "u0000000001.eml").read_bytes() == body
        assert (all_dir / "u0000000002.eml").read_bytes() == body
        archived_meta = json.loads((all_dir / "u0000000001.json").read_text())
        covered_meta = json.loads((all_dir / "u0000000002.json").read_text())
        assert archived_meta["flags"] == "\\Seen \\ArchivedOnly"
        assert archived_meta["internaldate"] == "01-Jan-2024 00:00:00 +0000"
        assert covered_meta["flags"] == "\\Seen"
        assert covered_meta["internaldate"] == "02-Jan-2024 00:00:00 +0000"

    def test_validate_accepts_extra_duplicate_virtual_message_export(self, tmp_path: Path) -> None:
        from components.imap_ops import export_account
        from components.main import main
        from components.models import Account, ServerConfig

        body = b"Message-ID: <legacy-validate-duplicate-virtual@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nsame"

        class DuplicateAllRemote:
            response = _stable_uidvalidity_response

            def __init__(self) -> None:
                self.selected = ""

            def list(self, *args):
                return "OK", [
                    b'(\\HasNoChildren) "/" "INBOX"',
                    b'(\\HasNoChildren \\All) "/" "All Mail"',
                ]

            def select(self, mailbox: str, readonly: bool = False):
                self.selected = mailbox.strip('"').replace(r"\"", '"')
                return "OK", [b"1" if self.selected == "INBOX" else b"2"]

            def uid(self, command: str, *args):
                if command == "search":
                    return "OK", [b"1" if self.selected == "INBOX" else b"1 2"]
                if command == "fetch":
                    uid = str(args[0])
                    return "OK", [(
                        f'{uid} (UID {uid} FLAGS (\\Seen) INTERNALDATE "01-Jan-2024 00:00:00 +0000")'.encode("ascii"),
                        body,
                    )]
                raise AssertionError(command)

            def search(self, charset, *criteria):
                if criteria == ("ALL",):
                    return "OK", [b"1" if self.selected == "INBOX" else b"1 2"]
                if len(criteria) == 3 and criteria[:2] == ("HEADER", "Message-ID"):
                    return "OK", [b"1" if self.selected == "INBOX" else b"1 2"]
                return "OK", [b""]

            def fetch(self, num: bytes, query: str):
                return "OK", [(b"1 (RFC822.SIZE %d FLAGS (\\Seen) INTERNALDATE \"01-Jan-2024 00:00:00 +0000\" BODY[] {%d}" % (len(body), len(body)), body)]

            def logout(self):
                return "OK", []

        account = Account("user@example.com", "secret")
        server = ServerConfig("imap.example.com")

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[DuplicateAllRemote]:
            yield DuplicateAllRemote()

        with mock.patch("components.imap_ops.imap_connection", fake_connection):
            export_account(account, server, tmp_path / "exported", ignore_errors=False)

        config_path = tmp_path / "config.json"
        server_json = {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False}
        config_path.write_text(json.dumps({
            "server": server_json,
            "source_server": server_json,
            "accounts": [{"email": account.email, "password": account.password}],
        }))

        with mock.patch("components.imap_ops.imap_connection", fake_connection):
            rc = main([
                "--mode", "validate",
                "--config", str(config_path),
                "--input-dir", str(tmp_path / "exported"),
                "--log-dir", str(tmp_path / "logs"),
                "--max-workers", "1",
                "--min-free-gb", "0",
                "--no-connectivity-test",
            ])

        assert rc == 0

    def test_import_translates_legacy_source_hierarchy_delimiter(self, tmp_path: Path) -> None:
        from components.imap_ops import export_account, import_account
        from components.models import Account, ServerConfig

        body = b"Message-ID: <legacy-nested@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nnested"

        class SlashSource:
            response = _stable_uidvalidity_response

            def __init__(self) -> None:
                self.selected = ""

            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "Projects/2024"']

            def select(self, mailbox: str, readonly: bool = False):
                self.selected = mailbox.strip('"').replace(r"\"", '"')
                return "OK", [b"1"]

            def uid(self, command: str, *args):
                if command == "search":
                    return "OK", [b"1"]
                if command == "fetch":
                    return "OK", [(
                        b'1 (UID 1 FLAGS (\\Seen) INTERNALDATE "01-Jan-2024 00:00:00 +0000")',
                        body,
                    )]
                raise AssertionError(command)

            def logout(self):
                return "OK", []

        class DotTarget:
            def __init__(self) -> None:
                self.created: List[str] = []
                self.appended: List[str] = []
                self.subscribed: List[str] = []
                self.mailboxes = {"INBOX"}

            def list(self):
                return "OK", [b'(\\HasNoChildren) "." "INBOX"']

            def select(self, mailbox: str, readonly: bool = False):
                selected = mailbox.strip('"').replace(r"\"", '"')
                return ("OK", [b"0"]) if selected in self.mailboxes else ("NO", [b"missing"])

            def create(self, mailbox: str):
                selected = mailbox.strip('"').replace(r"\"", '"')
                self.created.append(selected)
                self.mailboxes.add(selected)
                return "OK", [b""]

            def subscribe(self, mailbox: str):
                self.subscribed.append(mailbox.strip('"').replace(r"\"", '"'))
                return "OK", [b""]

            def search(self, charset, *criteria):
                return "OK", [b""]

            def append(self, mailbox: str, flags: str, date_time: str, payload: bytes):
                self.appended.append(mailbox.strip('"').replace(r"\"", '"'))
                return "OK", [b""]

            def logout(self):
                return "OK", []

        account = Account("user@example.com", "secret")
        source_server = ServerConfig("source.example.com")
        target_server = ServerConfig("target.example.com")
        source = SlashSource()
        target = DotTarget()

        @contextlib.contextmanager
        def source_connection(*_args, **_kwargs) -> Iterator[SlashSource]:
            yield source

        @contextlib.contextmanager
        def target_connection(*_args, **_kwargs) -> Iterator[DotTarget]:
            yield target

        with mock.patch("components.imap_ops.imap_connection", source_connection):
            export_account(account, source_server, tmp_path, ignore_errors=False)

        account_dir = tmp_path / "user@example.com"
        state = json.loads((account_dir / "export-state.json").read_text())
        assert state["mailboxes"] == [{
            "mailbox": "Projects/2024",
            "message_count": 1,
            "path": "Projects_2024",
            "source_delimiter": "/",
            "source_path_segments": ["Projects", "2024"],
            "uidvalidity": "123",
        }]

        with mock.patch("components.imap_ops.imap_connection", target_connection):
            import_account(
                account,
                target_server,
                tmp_path,
                ignore_errors=False,
                source_server=source_server,
            )

        assert target.created == ["Projects.2024"]
        assert target.appended == ["Projects.2024"]
        assert target.subscribed == ["Projects.2024"]

    def test_validate_translates_legacy_source_hierarchy_delimiter(self, tmp_path: Path) -> None:
        from components.imap_ops import export_account
        from components.main import main
        from components.models import Account, ServerConfig

        body = b"Message-ID: <legacy-validate-nested@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nnested"

        class SlashSource:
            response = _stable_uidvalidity_response

            def __init__(self) -> None:
                self.selected = ""

            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "Projects/2024"']

            def select(self, mailbox: str, readonly: bool = False):
                self.selected = mailbox.strip('"').replace(r"\"", '"')
                return "OK", [b"1"]

            def uid(self, command: str, *args):
                if command == "search":
                    return "OK", [b"1"]
                if command == "fetch":
                    return "OK", [(
                        b'1 (UID 1 FLAGS (\\Seen) INTERNALDATE "01-Jan-2024 00:00:00 +0000")',
                        body,
                    )]
                raise AssertionError(command)

            def logout(self):
                return "OK", []

        class DotTarget:
            def __init__(self) -> None:
                self.selected = ""

            def list(self, *args):
                return "OK", [
                    b'(\\HasNoChildren) "." "Projects.2024"',
                ]

            def select(self, mailbox: str, readonly: bool = False):
                self.selected = mailbox.strip('"').replace(r"\"", '"')
                return ("OK", [b"1"]) if self.selected == "Projects.2024" else ("OK", [b"0"])

            def search(self, charset, *criteria):
                if self.selected == "Projects.2024":
                    return "OK", [b"1"]
                return "OK", [b""]

            def fetch(self, num: bytes, query: str):
                return "OK", [(b"1 (RFC822.SIZE %d FLAGS (\\Seen) INTERNALDATE \"01-Jan-2024 00:00:00 +0000\" BODY[] {%d}" % (len(body), len(body)), body)]

            def logout(self):
                return "OK", []

        account = Account("user@example.com", "secret")
        source_server = ServerConfig("source.example.com")

        @contextlib.contextmanager
        def source_connection(*_args, **_kwargs) -> Iterator[SlashSource]:
            yield SlashSource()

        with mock.patch("components.imap_ops.imap_connection", source_connection):
            export_account(account, source_server, tmp_path / "exported", ignore_errors=False)

        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "target.example.com", "port": 993, "ssl": True, "starttls": False},
            "source_server": {"host": "source.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": account.email, "password": account.password}],
        }))

        @contextlib.contextmanager
        def target_connection(*_args, **_kwargs) -> Iterator[DotTarget]:
            yield DotTarget()

        with mock.patch("components.imap_ops.imap_connection", target_connection):
            rc = main([
                "--mode", "validate",
                "--config", str(config_path),
                "--input-dir", str(tmp_path / "exported"),
                "--log-dir", str(tmp_path / "logs"),
                "--max-workers", "1",
                "--min-free-gb", "0",
                "--no-connectivity-test",
            ])

        assert rc == 0

    def test_validate_uses_translated_all_attrs_for_virtual_coverage(self, tmp_path: Path) -> None:
        from components.imap_ops import export_account
        from components.main import main
        from components.models import Account, ServerConfig

        inbox_body = b"Message-ID: <translated-all-inbox@example.com>\r\nFrom: a\r\nTo: b\r\n\r\ninbox"
        archived_body = b"Message-ID: <translated-all-archived@example.com>\r\nFrom: a\r\nTo: b\r\n\r\narchived"

        class SlashAllSource:
            response = _stable_uidvalidity_response

            def __init__(self) -> None:
                self.selected = ""

            def list(self):
                return "OK", [
                    b'(\\HasNoChildren) "/" "INBOX"',
                    b'(\\HasNoChildren \\All) "/" "[Gmail]/All Mail"',
                ]

            def select(self, mailbox: str, readonly: bool = False):
                self.selected = mailbox.strip('"').replace(r"\"", '"')
                return "OK", [b"1" if self.selected == "INBOX" else b"2"]

            def uid(self, command: str, *args):
                if command == "search":
                    return "OK", [b"1" if self.selected == "INBOX" else b"1 2"]
                if command == "fetch":
                    uid = str(args[0])
                    body = inbox_body if uid == "1" else archived_body
                    return "OK", [(
                        f'{uid} (UID {uid} FLAGS (\\Seen) INTERNALDATE "01-Jan-2024 00:00:00 +0000")'.encode("ascii"),
                        body,
                    )]
                raise AssertionError(command)

            def logout(self):
                return "OK", []

        class DotAllTarget:
            def __init__(self) -> None:
                self.selected = ""

            def list(self, *args):
                return "OK", [
                    b'(\\HasNoChildren) "." "INBOX"',
                    b'(\\HasNoChildren \\All) "." "[Gmail].All Mail"',
                ]

            def select(self, mailbox: str, readonly: bool = False):
                self.selected = mailbox.strip('"').replace(r"\"", '"')
                return "OK", [b"1" if self.selected == "INBOX" else b"2"]

            def search(self, charset, *criteria):
                if criteria == ("ALL",):
                    return "OK", [b"1" if self.selected == "INBOX" else b"1 2"]
                if len(criteria) == 3 and criteria[:2] == ("HEADER", "Message-ID"):
                    wanted = str(criteria[2]).strip('"')
                    if wanted == "<translated-all-inbox@example.com>":
                        return "OK", [b"1"]
                    if wanted == "<translated-all-archived@example.com>" and self.selected == "[Gmail].All Mail":
                        return "OK", [b"2"]
                return "OK", [b""]

            def fetch(self, num: bytes, query: str):
                body = inbox_body if int(num) == 1 else archived_body
                return "OK", [(b"1 (RFC822.SIZE %d FLAGS (\\Seen) INTERNALDATE \"01-Jan-2024 00:00:00 +0000\" BODY[] {%d}" % (len(body), len(body)), body)]

            def logout(self):
                return "OK", []

        account = Account("user@example.com", "secret")
        source_server = ServerConfig("source.example.com")

        @contextlib.contextmanager
        def source_connection(*_args, **_kwargs) -> Iterator[SlashAllSource]:
            yield SlashAllSource()

        with mock.patch("components.imap_ops.imap_connection", source_connection):
            export_account(account, source_server, tmp_path / "exported", ignore_errors=False)

        account_dir = tmp_path / "exported" / "user@example.com"
        state = json.loads((account_dir / "export-state.json").read_text())
        assert {
            (row["mailbox"], row["path"], row["message_count"])
            for row in state["mailboxes"]
        } == {
            ("INBOX", "INBOX", 1),
            ("[Gmail]/All Mail", "_Gmail__All_Mail", 1),
        }

        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "target.example.com", "port": 993, "ssl": True, "starttls": False},
            "source_server": {"host": "source.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": account.email, "password": account.password}],
        }))

        @contextlib.contextmanager
        def target_connection(*_args, **_kwargs) -> Iterator[DotAllTarget]:
            yield DotAllTarget()

        with mock.patch("components.imap_ops.imap_connection", target_connection):
            rc = main([
                "--mode", "validate",
                "--config", str(config_path),
                "--input-dir", str(tmp_path / "exported"),
                "--log-dir", str(tmp_path / "logs"),
                "--max-workers", "1",
                "--min-free-gb", "0",
                "--no-connectivity-test",
            ])

        assert rc == 0


class TestLegacyImportJournal:
    """Legacy import should not blindly duplicate committed local messages on rerun."""

    def _source_server(self):
        from components.models import ServerConfig

        return ServerConfig(host="imap.example.com", port=993, ssl=True, starttls=False)

    def _make_export(self, tmp_path: Path) -> Path:
        account_dir = tmp_path / "user@example.com" / "INBOX"
        eml = _write_legacy_message_fixture(
            account_dir,
            data=b"Message-ID: <m@example.com>\r\nFrom: a@example.com\r\nTo: b@example.com\r\n\r\nbody",
            source_server=self._source_server(),
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
                return "OK", [(b"1 (RFC822.SIZE 77 FLAGS (\\Seen) INTERNALDATE \"01-Jan-2024 00:00:00 +0000\" BODY[] {77}", b"Message-ID: <m@example.com>\r\nFrom: a@example.com\r\nTo: b@example.com\r\n\r\nbody")]

            def logout(self):
                return "OK", []

        fake_imap = MatchingImportImap()

        @contextlib.contextmanager
        def fake_factory(*_args, **_kwargs) -> Iterator:
            yield fake_imap

        import_account(
            account,
            server,
            in_root,
            ignore_errors=False,
            imap_factory=fake_factory,
            source_server=self._source_server(),
        )
        import_account(
            account,
            server,
            in_root,
            ignore_errors=False,
            imap_factory=fake_factory,
            source_server=self._source_server(),
        )

        assert fake_imap.append_count == 1

    def test_import_rerun_restores_missing_committed_flags(self, tmp_path: Path) -> None:
        from components.imap_ops import (
            _imap_append_wire_bytes,
            _legacy_import_key,
            _legacy_import_target_id,
            import_account,
        )
        from components.models import Account, ServerConfig

        account = Account(email="user@example.com", password="pass")
        source_server = self._source_server()
        target_server = ServerConfig(host="target.example.com", port=993, ssl=True)
        account_dir = tmp_path / account.email
        folder = account_dir / "INBOX"
        data = b"Message-ID: <flag-restore@example.com>\r\nFrom: a@example.com\r\nTo: b@example.com\r\n\r\nbody"
        eml = _write_legacy_message_fixture(
            folder,
            data=data,
            flags="\\Seen \\Answered",
            source_server=source_server,
        )
        append_data = _imap_append_wire_bytes(data)
        import_key = _legacy_import_key(account_dir, eml, "INBOX", append_data)
        (account_dir / "import.journal.jsonl").write_text(json.dumps({
            "key": import_key,
            "status": "committed",
            "target": _legacy_import_target_id(target_server, account),
            "mailbox": "INBOX",
            "path": eml.relative_to(account_dir).as_posix(),
            "rfc822_size": str(len(append_data)),
            "content_sha256": hashlib.sha256(append_data).hexdigest(),
            "timestamp": "0",
        }) + "\n")

        class MissingFlagTarget:
            def __init__(self) -> None:
                self.append_count = 0
                self.flags = {"\\Seen"}
                self.store_calls: List[Tuple[bytes, str, str]] = []

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"1"]

            def subscribe(self, mailbox: str):
                return "OK", [b""]

            def search(self, charset, *criteria):
                return "OK", [b"1"]

            def fetch(self, num: bytes, query: str):
                flags = " ".join(sorted(self.flags))
                if query == "(FLAGS)":
                    return "OK", [f"1 (FLAGS ({flags}))".encode("ascii")]
                return "OK", [(b"1 (RFC822.SIZE %d FLAGS (%s) INTERNALDATE \"01-Jan-2024 00:00:00 +0000\" BODY[] {%d}" % (
                    len(append_data),
                    flags.encode("ascii"),
                    len(append_data),
                ), append_data)]

            def store(self, num: bytes, command: str, flags: str):
                self.store_calls.append((num, command, flags))
                for flag in flags.strip("()").split():
                    self.flags.add(flag)
                return "OK", [b""]

            def append(self, mailbox: str, flags: str, date_time: str, payload: bytes):
                self.append_count += 1
                return "OK", [b""]

            def logout(self):
                return "OK", []

        target = MissingFlagTarget()

        @contextlib.contextmanager
        def fake_factory(*_args, **_kwargs) -> Iterator[MissingFlagTarget]:
            yield target

        import_account(
            account,
            target_server,
            tmp_path,
            ignore_errors=False,
            imap_factory=fake_factory,
            source_server=source_server,
        )

        assert target.append_count == 0
        assert target.store_calls == [(b"1", "+FLAGS.SILENT", "(\\ANSWERED)")]

    def test_import_skips_committed_same_content_after_uid_renumber(self, tmp_path: Path) -> None:
        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        account = Account(email="user@example.com", password="pass")
        server = ServerConfig(host="dummy", port=993, ssl=True)
        account_dir = tmp_path / account.email
        folder = account_dir / "INBOX"
        data = b"Message-ID: <uid-renumber@example.com>\r\nFrom: a@example.com\r\nTo: b@example.com\r\n\r\nbody"
        eml1 = _write_legacy_message_fixture(folder, uid=1, data=data)

        class ExistingTarget:
            def __init__(self) -> None:
                self.append_count = 0
                self.search_count = 0
                self.fetch_count = 0
                self.stored: List[bytes] = []

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [str(len(self.stored)).encode("ascii")]

            def subscribe(self, mailbox: str):
                return "OK", [b""]

            def append(self, mailbox: str, flags: str, date_time: str, payload: bytes):
                self.append_count += 1
                self.stored.append(payload)
                return "OK", [b""]

            def search(self, charset, *criteria):
                self.search_count += 1
                return "OK", [b" ".join(str(idx).encode("ascii") for idx in range(1, len(self.stored) + 1))]

            def fetch(self, num: bytes, query: str):
                self.fetch_count += 1
                body = self.stored[int(num) - 1]
                return "OK", [(b"1 (RFC822.SIZE %d FLAGS (\\Seen) INTERNALDATE \"01-Jan-2024 00:00:00 +0000\" BODY[] {%d}" % (len(body), len(body)), body)]

            def logout(self):
                return "OK", []

        target = ExistingTarget()

        @contextlib.contextmanager
        def fake_factory(*_args, **_kwargs) -> Iterator[ExistingTarget]:
            yield target

        import_account(
            account,
            server,
            tmp_path,
            ignore_errors=False,
            imap_factory=fake_factory,
            source_server=self._source_server(),
        )
        rows_after_first = [
            json.loads(line)
            for line in (account_dir / "import.journal.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        assert rows_after_first[-1]["rfc822_size"] == str(len(data))
        assert rows_after_first[-1]["content_sha256"] == hashlib.sha256(data).hexdigest()

        eml2 = folder / "u0000000002.eml"
        eml2.write_bytes(data)
        eml2.with_suffix(".json").write_text(json.dumps(_legacy_integrity_metadata(
            data,
            account=account.email,
            mailbox="INBOX",
            uid=2,
            flags="\\Seen",
            internaldate="01-Jan-2024 00:00:00 +0000",
        )))
        eml1.with_suffix(".json").unlink()
        eml1.unlink()

        import_account(
            account,
            server,
            tmp_path,
            ignore_errors=False,
            imap_factory=fake_factory,
            source_server=self._source_server(),
        )

        rows_after_second = [
            json.loads(line)
            for line in (account_dir / "import.journal.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        assert target.append_count == 1
        assert target.search_count == 1
        assert target.fetch_count == 1
        assert len(rows_after_second) == len(rows_after_first)

    def test_import_keeps_identical_staged_messages_distinct(self, tmp_path: Path) -> None:
        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        account = Account(email="user@example.com", password="pass")
        server = ServerConfig(host="dummy", port=993, ssl=True)
        folder = tmp_path / account.email / "INBOX"
        data = b"Message-ID: <duplicate-import@example.com>\r\nFrom: a@example.com\r\nTo: b@example.com\r\n\r\nbody"
        _write_legacy_message_fixture(folder, uid=1, data=data)
        _write_legacy_message_fixture(folder, uid=2, data=data)

        class Target:
            def __init__(self) -> None:
                self.append_count = 0

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"0"]

            def subscribe(self, mailbox: str):
                return "OK", [b""]

            def append(self, mailbox: str, flags: str, date_time: str, payload: bytes):
                self.append_count += 1
                return "OK", [b""]

            def logout(self):
                return "OK", []

        target = Target()

        @contextlib.contextmanager
        def fake_factory(*_args, **_kwargs) -> Iterator[Target]:
            yield target

        import_account(
            account,
            server,
            tmp_path,
            ignore_errors=False,
            imap_factory=fake_factory,
            source_server=self._source_server(),
        )

        assert target.append_count == 2

    def test_import_stale_committed_duplicate_does_not_cover_next_message(self, tmp_path: Path) -> None:
        from components.imap_ops import (
            _imap_append_wire_bytes,
            _legacy_import_key,
            _legacy_import_target_id,
            import_account,
        )
        from components.models import Account, ServerConfig

        account = Account(email="user@example.com", password="pass")
        source_server = self._source_server()
        target_server = ServerConfig(host="target.example.com", port=993, ssl=True)
        account_dir = tmp_path / account.email
        folder = account_dir / "INBOX"
        data = b"Message-ID: <stale-duplicate@example.com>\r\nFrom: a@example.com\r\nTo: b@example.com\r\n\r\nbody"
        eml1 = _write_legacy_message_fixture(folder, uid=1, data=data, source_server=source_server)
        _write_legacy_message_fixture(folder, uid=2, data=data, source_server=source_server)
        append_data = _imap_append_wire_bytes(data)
        import_key = _legacy_import_key(account_dir, eml1, "INBOX", append_data)
        (account_dir / "import.journal.jsonl").write_text(json.dumps({
            "key": import_key,
            "status": "committed",
            "target": _legacy_import_target_id(target_server, account),
            "mailbox": "INBOX",
            "path": eml1.relative_to(account_dir).as_posix(),
            "rfc822_size": str(len(append_data)),
            "content_sha256": hashlib.sha256(append_data).hexdigest(),
            "timestamp": "0",
        }) + "\n")

        class Target:
            def __init__(self) -> None:
                self.append_count = 0
                self.stored: List[bytes] = []

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [str(len(self.stored)).encode("ascii")]

            def subscribe(self, mailbox: str):
                return "OK", [b""]

            def search(self, charset, *criteria):
                nums = b" ".join(str(idx).encode("ascii") for idx in range(1, len(self.stored) + 1))
                return "OK", [nums]

            def fetch(self, num: bytes, query: str):
                body = self.stored[int(num) - 1]
                return "OK", [(b"1 (RFC822.SIZE %d FLAGS (\\Seen) INTERNALDATE \"01-Jan-2024 00:00:00 +0000\" BODY[] {%d}" % (len(body), len(body)), body)]

            def append(self, mailbox: str, flags: str, date_time: str, payload: bytes):
                self.append_count += 1
                self.stored.append(payload)
                return "OK", [b""]

            def logout(self):
                return "OK", []

        target = Target()

        @contextlib.contextmanager
        def fake_factory(*_args, **_kwargs) -> Iterator[Target]:
            yield target

        import_account(
            account,
            target_server,
            tmp_path,
            ignore_errors=False,
            imap_factory=fake_factory,
            source_server=source_server,
        )

        assert target.append_count == 2

    def test_import_rerun_skips_lf_only_message_after_imaplib_normalization(self, tmp_path: Path) -> None:
        import imaplib

        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        account_dir = tmp_path / "user@example.com" / "INBOX"
        data = b"Message-ID: <lf-only@example.com>\nFrom: a@example.com\nTo: b@example.com\n\nbody\n"
        _write_legacy_message_fixture(account_dir, data=data)
        account = Account(email="user@example.com", password="pass")
        server = ServerConfig(host="dummy", port=993, ssl=True)

        class NormalizingAppendImap:
            def __init__(self) -> None:
                self.append_count = 0
                self.stored: List[bytes] = []

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [str(len(self.stored)).encode("ascii")]

            def subscribe(self, mailbox: str):
                return "OK", [b""]

            def append(self, mailbox: str, flags: str, date_time: str, payload: bytes):
                self.append_count += 1
                self.stored.append(imaplib.MapCRLF.sub(imaplib.CRLF, payload))
                return "OK", [b""]

            def search(self, charset, *criteria):
                return "OK", [b" ".join(str(idx).encode("ascii") for idx in range(1, len(self.stored) + 1))]

            def fetch(self, num: bytes, query: str):
                body = self.stored[int(num) - 1]
                return "OK", [(b"1 (RFC822.SIZE %d FLAGS (\\Seen) INTERNALDATE \"01-Jan-2024 00:00:00 +0000\" BODY[] {%d}" % (len(body), len(body)), body)]

            def logout(self):
                return "OK", []

        fake_imap = NormalizingAppendImap()

        @contextlib.contextmanager
        def fake_factory(*_args, **_kwargs) -> Iterator[NormalizingAppendImap]:
            yield fake_imap

        import_account(
            account,
            server,
            tmp_path,
            ignore_errors=False,
            imap_factory=fake_factory,
            source_server=self._source_server(),
        )
        import_account(
            account,
            server,
            tmp_path,
            ignore_errors=False,
            imap_factory=fake_factory,
            source_server=self._source_server(),
        )

        assert fake_imap.append_count == 1
        assert fake_imap.stored == [imaplib.MapCRLF.sub(imaplib.CRLF, data)]

    def test_import_accepts_bound_empty_message(self, tmp_path: Path) -> None:
        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        folder = tmp_path / "user@example.com" / "INBOX"
        _write_legacy_message_fixture(folder, data=b"")

        class EmptyAppendImap:
            def __init__(self) -> None:
                self.appended: List[bytes] = []

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"0"]

            def subscribe(self, mailbox: str):
                return "OK", [b""]

            def append(self, mailbox: str, flags: str, date_time: str, payload: bytes):
                self.appended.append(payload)
                return "OK", [b""]

            def logout(self):
                return "OK", []

        target = EmptyAppendImap()

        @contextlib.contextmanager
        def fake_factory(*_args, **_kwargs) -> Iterator[EmptyAppendImap]:
            yield target

        import_account(
            Account("user@example.com", "secret"),
            ServerConfig("imap.example.com"),
            tmp_path,
            ignore_errors=False,
            imap_factory=fake_factory,
            source_server=self._source_server(),
        )

        assert target.appended == [b""]

    def test_audit_accepts_bound_empty_message(self, tmp_path: Path) -> None:
        from components.audit import audit_account
        from components.models import Account

        folder = tmp_path / "user@example.com" / "INBOX"
        _write_legacy_message_fixture(folder, data=b"")

        _email, issues = audit_account(
            Account("user@example.com", "secret"),
            tmp_path,
            server=None,
            check_remote=False,
            require_integrity_metadata=True,
            expected_source_server=self._source_server(),
        )

        assert issues == []

    def test_import_rejects_empty_message_without_integrity_metadata_before_append(self, tmp_path: Path) -> None:
        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        folder = tmp_path / "user@example.com" / "INBOX"
        eml = _write_legacy_message_fixture(folder, data=b"")
        eml.with_suffix(".json").write_text(json.dumps({"account": "user@example.com", "mailbox": "INBOX", "uid": 1}))

        class NoAppendImap:
            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"0"]

            def subscribe(self, mailbox: str):
                return "OK", [b""]

            def append(self, *_args, **_kwargs):
                raise AssertionError("APPEND should not be reached")

            def logout(self):
                return "OK", []

        @contextlib.contextmanager
        def fake_factory(*_args, **_kwargs) -> Iterator[NoAppendImap]:
            yield NoAppendImap()

        with pytest.raises(RuntimeError, match="invalid rfc822_size metadata"):
            import_account(
                Account("user@example.com", "secret"),
                ServerConfig("imap.example.com"),
                tmp_path,
                ignore_errors=False,
                imap_factory=fake_factory,
            )

    def test_import_skips_covered_virtual_marker_only_mailbox(self, tmp_path: Path) -> None:
        from components.imap_ops import import_account
        from components.main import main
        from components.models import Account, ServerConfig

        server = ServerConfig("imap.example.com")
        account = Account("user@example.com", "secret")
        account_dir = tmp_path / account.email
        body = b"Message-ID: <covered-virtual-import@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody"
        _write_legacy_message_fixture(
            account_dir / "Archive",
            mailbox="Archive",
            data=body,
            source_server=server,
        )
        flagged = account_dir / "Flagged"
        flagged.mkdir()
        (flagged / ".mailbox.json").write_text(json.dumps({
            "mailbox": "Flagged",
            "message_count": 0,
            "covered_by_regular_content": True,
        }))
        state_path = account_dir / "export-state.json"
        state = json.loads(state_path.read_text())
        state["mailboxes"].append({
            "mailbox": "Flagged",
            "path": "Flagged",
            "message_count": 0,
            "covered_by_regular_content": True,
        })
        state_path.write_text(json.dumps(state))

        class Target:
            def __init__(self) -> None:
                self.selected: List[str] = []
                self.subscribed: List[str] = []
                self.appended: List[str] = []
                self.payloads_by_mailbox: dict[str, List[bytes]] = {}

            def _normalize(self, mailbox: str) -> str:
                return mailbox.strip('"').replace(r"\"", '"')

            def select(self, mailbox: str, readonly: bool = False):
                selected = self._normalize(mailbox)
                if selected == "Flagged":
                    raise AssertionError("covered virtual mailbox should not be selected")
                self.selected.append(selected)
                return "OK", [str(len(self.payloads_by_mailbox.get(selected, []))).encode("ascii")]

            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "Archive"']

            def subscribe(self, mailbox: str):
                selected = self._normalize(mailbox)
                if selected == "Flagged":
                    raise AssertionError("covered virtual mailbox should not be subscribed")
                self.subscribed.append(selected)
                return "OK", [b""]

            def append(self, mailbox: str, flags: str, date_time: str, payload: bytes):
                selected = self._normalize(mailbox)
                if selected == "Flagged":
                    raise AssertionError("covered virtual mailbox should not receive appends")
                self.appended.append(selected)
                self.payloads_by_mailbox.setdefault(selected, []).append(bytes(payload))
                return "OK", [b""]

            def search(self, charset, *criteria):
                payloads = self.payloads_by_mailbox.get(self.selected[-1] if self.selected else "", [])
                if criteria == ("ALL",):
                    return "OK", [b" ".join(str(i).encode("ascii") for i in range(1, len(payloads) + 1))]
                if len(criteria) == 3 and criteria[:2] == ("HEADER", "Message-ID"):
                    wanted = str(criteria[2]).strip('"')
                    if wanted == "<covered-virtual-import@example.com>" and payloads:
                        return "OK", [b"1"]
                return "OK", [b""]

            def fetch(self, num: bytes, query: str):
                payloads = self.payloads_by_mailbox.get(self.selected[-1] if self.selected else "", [])
                payload = payloads[int(num) - 1]
                return "OK", [(b"1 (RFC822.SIZE %d FLAGS (\\Seen) INTERNALDATE \"01-Jan-2024 00:00:00 +0000\" BODY[] {%d}" % (len(payload), len(payload)), payload)]

            def logout(self):
                return "OK", []

        target = Target()

        @contextlib.contextmanager
        def fake_factory(*_args, **_kwargs) -> Iterator[Target]:
            yield target

        import_account(
            account,
            server,
            tmp_path,
            ignore_errors=False,
            imap_factory=fake_factory,
            source_server=server,
        )

        assert target.selected == ["Archive"]
        assert target.subscribed == ["Archive"]
        assert target.appended == ["Archive"]

        config_path = tmp_path / "config.json"
        server_json = {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False}
        config_path.write_text(json.dumps({
            "server": server_json,
            "source_server": server_json,
            "accounts": [{"email": account.email, "password": account.password}],
        }))
        target.selected.clear()

        with mock.patch("components.imap_ops.imap_connection", fake_factory):
            rc = main([
                "--mode", "validate",
                "--config", str(config_path),
                "--input-dir", str(tmp_path),
                "--log-dir", str(tmp_path / "logs"),
                "--max-workers", "1",
                "--min-free-gb", "0",
                "--no-connectivity-test",
            ])

        assert rc == 0
        assert "Flagged" not in target.selected

    def test_import_recognizes_existing_raw_committed_key_for_lf_only_message(self, tmp_path: Path) -> None:
        import imaplib

        from components.imap_ops import _legacy_import_key, _legacy_import_target_id, import_account
        from components.models import Account, ServerConfig

        account_dir = tmp_path / "user@example.com"
        folder = account_dir / "INBOX"
        data = b"Message-ID: <legacy-key@example.com>\nFrom: a@example.com\nTo: b@example.com\n\nbody\n"
        eml = _write_legacy_message_fixture(folder, data=data)
        account = Account(email="user@example.com", password="pass")
        server = ServerConfig(host="dummy", port=993, ssl=True)
        raw_key = _legacy_import_key(account_dir, eml, "INBOX", data)
        (account_dir / "import.journal.jsonl").write_text(json.dumps({
            "key": raw_key,
            "status": "committed",
            "target": _legacy_import_target_id(server, account),
            "mailbox": "INBOX",
            "path": "INBOX/u0000000001.eml",
        }) + "\n")

        class ExistingNormalizedMessageImap:
            def __init__(self) -> None:
                self.append_count = 0
                self.stored = imaplib.MapCRLF.sub(imaplib.CRLF, data)

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"1"]

            def search(self, charset, *criteria):
                return "OK", [b"1"]

            def fetch(self, num: bytes, query: str):
                return "OK", [(b"1 (RFC822.SIZE %d FLAGS (\\Seen) INTERNALDATE \"01-Jan-2024 00:00:00 +0000\" BODY[] {%d}" % (len(self.stored), len(self.stored)), self.stored)]

            def append(self, *_args, **_kwargs):
                self.append_count += 1
                return "OK", [b""]

            def logout(self):
                return "OK", []

        fake_imap = ExistingNormalizedMessageImap()

        @contextlib.contextmanager
        def fake_factory(*_args, **_kwargs) -> Iterator[ExistingNormalizedMessageImap]:
            yield fake_imap

        import_account(
            account,
            server,
            tmp_path,
            ignore_errors=False,
            imap_factory=fake_factory,
            source_server=self._source_server(),
        )

        assert fake_imap.append_count == 0

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

        import_account(account, server, tmp_path, ignore_errors=False, imap_factory=fake_factory, source_server=server)

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

        with pytest.raises(
            RuntimeError,
            match=(
                "invalid legacy export-state|no staged \\.eml files|mailbox metadata mismatch|"
                "failed to parse mailbox marker|mailbox marker is not an object|"
                "mailbox marker has invalid message_count"
            ),
        ):
            import_account(account, server, tmp_path, ignore_errors=False)

    @pytest.mark.parametrize(
        ("extra_marker", "marker_mailbox", "marker_count", "marker_text", "state_count"),
        [
            (True, "INBOX", 0, None, 0),
            (False, "Archive", 0, None, 0),
            (False, "INBOX", 1, None, 0),
            (True, "INBOX", 0, "{bad json", 0),
            (True, "INBOX", 0, "[]", 0),
            (False, "INBOX", "0", None, 0),
            (False, "INBOX", False, None, 0),
            (False, "INBOX", 0, None, "0"),
            (False, "INBOX", 0, None, False),
        ],
    )
    def test_import_rejects_unproven_zero_message_marker_state(
        self,
        tmp_path: Path,
        extra_marker: bool,
        marker_mailbox: str,
        marker_count: object,
        marker_text: Optional[str],
        state_count: object,
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
            (extra / ".mailbox.json").write_text(
                marker_text if marker_text is not None else json.dumps({"mailbox": "Extra", "message_count": 0})
            )
        (tmp_path / "user@example.com" / "export-state.json").write_text(json.dumps({
            "schema_version": 1,
            "account": "user@example.com",
            "source_server": legacy_server_endpoint(server),
            "source_server_sha256": legacy_server_endpoint_digest(server),
            "complete": True,
            "completed_at": 0,
            "mailboxes": [{"mailbox": "INBOX", "path": "INBOX", "message_count": state_count}],
        }))
        account = Account(email="user@example.com", password="pass")

        with pytest.raises(
            RuntimeError,
            match=(
                "invalid legacy export-state|no staged \\.eml files|mailbox metadata mismatch|"
                "failed to parse mailbox marker|mailbox marker is not an object|"
                "mailbox marker has invalid message_count|mailbox marker count mismatch"
            ),
        ):
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
        entered_imap = False
        (account_dir / "import.journal.jsonl").write_text(json.dumps({
            "key": key,
            "status": "pending",
            "target": target_id,
            "mailbox": "INBOX",
            "path": "INBOX/u0000000001.eml",
        }) + "\n")

        @contextlib.contextmanager
        def fake_factory(*_args, **_kwargs) -> Iterator:
            nonlocal entered_imap
            entered_imap = True
            yield fake_imap

        with pytest.raises(RuntimeError, match="pending append"):
            import_account(
                account,
                server,
                in_root,
                ignore_errors=False,
                imap_factory=fake_factory,
                source_server=self._source_server(),
            )
        assert entered_imap is False

    def test_import_retries_after_clean_append_no(self, tmp_path: Path) -> None:
        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        in_root = self._make_export(tmp_path)
        account_dir = in_root / "user@example.com"
        account = Account(email="user@example.com", password="pass")
        server = ServerConfig(host="dummy", port=993, ssl=True)

        class AppendNoThenOk:
            def __init__(self) -> None:
                self.append_count = 0

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b""]

            def subscribe(self, mailbox: str):
                return "OK", [b""]

            def append(self, mailbox: str, flags: str, date_time: str, data: bytes):
                self.append_count += 1
                if self.append_count == 1:
                    return "NO", [b"invalid flags"]
                return "OK", [b""]

            def logout(self):
                return "OK", []

        fake_imap = AppendNoThenOk()

        @contextlib.contextmanager
        def fake_factory(*_args, **_kwargs) -> Iterator[AppendNoThenOk]:
            yield fake_imap

        with pytest.raises(RuntimeError, match="append failed"):
            import_account(
                account,
                server,
                in_root,
                ignore_errors=False,
                imap_factory=fake_factory,
                source_server=self._source_server(),
            )

        import_account(
            account,
            server,
            in_root,
            ignore_errors=False,
            imap_factory=fake_factory,
            source_server=self._source_server(),
        )

        statuses = [
            json.loads(line)["status"]
            for line in (account_dir / "import.journal.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        assert statuses == ["pending", "failed", "pending", "committed"]
        assert fake_imap.append_count == 2

    def test_import_stops_after_uncertain_append_exception_even_with_ignore_errors(self, tmp_path: Path) -> None:
        import imaplib

        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        in_root = self._make_export(tmp_path)
        _write_legacy_message_fixture(
            tmp_path / "user@example.com" / "Archive",
            mailbox="Archive",
            data=b"Message-ID: <archive@example.com>\r\nFrom: a@example.com\r\nTo: b@example.com\r\n\r\narchive",
        )
        account_dir = tmp_path / "user@example.com"
        account = Account(email="user@example.com", password="pass")
        server = ServerConfig(host="dummy", port=993, ssl=True)

        class AppendRaisesThenOk:
            def __init__(self) -> None:
                self.appended: List[str] = []

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b""]

            def subscribe(self, mailbox: str):
                return "OK", [b""]

            def append(self, mailbox: str, flags: str, date_time: str, data: bytes):
                self.appended.append(mailbox)
                if len(self.appended) == 1:
                    raise imaplib.IMAP4.abort("connection lost after APPEND")
                return "OK", [b""]

            def logout(self):
                return "OK", []

        fake_imap = AppendRaisesThenOk()

        @contextlib.contextmanager
        def fake_factory(*_args, **_kwargs) -> Iterator[AppendRaisesThenOk]:
            yield fake_imap

        with pytest.raises(RuntimeError, match="append outcome is uncertain"):
            import_account(
                account,
                server,
                in_root,
                ignore_errors=True,
                imap_factory=fake_factory,
                source_server=self._source_server(),
            )

        statuses = [
            json.loads(line)["status"]
            for line in (account_dir / "import.journal.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        assert statuses == ["pending"]
        assert fake_imap.appended == ['"Archive"']

    def test_import_rejects_invalid_legacy_journal_status(self, tmp_path: Path) -> None:
        from components.imap_ops import _legacy_import_key, _legacy_import_target_id, import_account
        from components.models import Account, ServerConfig

        in_root = self._make_export(tmp_path)
        account_dir = in_root / "user@example.com"
        eml = account_dir / "INBOX" / "u0000000001.eml"
        key = _legacy_import_key(account_dir, eml, "INBOX", eml.read_bytes())
        account = Account(email="user@example.com", password="pass")
        server = ServerConfig(host="dummy", port=993, ssl=True)
        (account_dir / "import.journal.jsonl").write_text(json.dumps({
            "key": key,
            "status": "commited",
            "target": _legacy_import_target_id(server, account),
            "mailbox": "INBOX",
            "path": "INBOX/u0000000001.eml",
        }) + "\n")

        with mock.patch("components.imap_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
            with pytest.raises(RuntimeError, match="invalid status"):
                import_account(account, server, in_root, ignore_errors=False)

    def test_import_rejects_pending_journal_entry_missing_key(self, tmp_path: Path) -> None:
        from components.imap_ops import _legacy_import_target_id, import_account
        from components.models import Account, ServerConfig

        in_root = self._make_export(tmp_path)
        account_dir = in_root / "user@example.com"
        account = Account(email="user@example.com", password="pass")
        server = ServerConfig(host="dummy", port=993, ssl=True)
        (account_dir / "import.journal.jsonl").write_text(json.dumps({
            "status": "pending",
            "target": _legacy_import_target_id(server, account),
            "mailbox": "INBOX",
            "path": "INBOX/u0000000001.eml",
        }) + "\n")

        with pytest.raises(RuntimeError, match="import journal row 1 is missing key"):
            import_account(
                account,
                server,
                in_root,
                ignore_errors=False,
                imap_factory=lambda *_args: (_ for _ in ()).throw(AssertionError("IMAP should not be opened")),
            )

    def test_import_rejects_non_object_legacy_journal_row(self, tmp_path: Path) -> None:
        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        in_root = self._make_export(tmp_path)
        account_dir = in_root / "user@example.com"
        account = Account(email="user@example.com", password="pass")
        server = ServerConfig(host="dummy", port=993, ssl=True)
        (account_dir / "import.journal.jsonl").write_text("[]\n")

        with mock.patch("components.imap_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
            with pytest.raises(RuntimeError, match="not an object"):
                import_account(account, server, in_root, ignore_errors=False)

    def test_import_ignore_errors_continues_but_raises_aggregate(self, tmp_path: Path) -> None:
        from components.imap_ops import import_account, legacy_server_endpoint, legacy_server_endpoint_digest
        from components.models import Account, ServerConfig

        account_dir = tmp_path / "user@example.com"
        server = ServerConfig(host="dummy", port=993, ssl=True)
        for mailbox in ("Bad", "Good"):
            folder = account_dir / mailbox
            folder.mkdir(parents=True)
            eml = folder / "u0000000001.eml"
            data = f"Message-ID: <{mailbox.lower()}@example.com>\r\n\r\nbody".encode("ascii")
            eml.write_bytes(data)
            eml.with_suffix(".json").write_text(json.dumps(_legacy_integrity_metadata(
                data,
                account="user@example.com",
                mailbox=mailbox,
                uid=1,
                flags="",
                internaldate="",
            )))
        _write_verify_export_state(account_dir, [
            {"mailbox": "Bad", "path": "Bad", "message_count": 1},
            {"mailbox": "Good", "path": "Good", "message_count": 1},
        ])
        state_path = account_dir / "export-state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["source_server"] = legacy_server_endpoint(server)
        state["source_server_sha256"] = legacy_server_endpoint_digest(server)
        state_path.write_text(json.dumps(state))

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
            import_account(
                account,
                server,
                tmp_path,
                ignore_errors=True,
                imap_factory=fake_factory,
                source_server=server,
            )

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

        import_account(
            account,
            new_server,
            in_root,
            ignore_errors=False,
            imap_factory=fake_factory,
            source_server=self._source_server(),
        )

        assert fake_imap.append.call_count == 1

    def test_import_recognizes_committed_journal_from_normalized_equivalent_target(self, tmp_path: Path) -> None:
        from components.imap_ops import _legacy_import_key, _legacy_import_target_id, import_account
        from components.models import Account, ServerConfig

        in_root = self._make_export(tmp_path)
        account_dir = in_root / "user@example.com"
        eml = account_dir / "INBOX" / "u0000000001.eml"
        data = eml.read_bytes()
        key = _legacy_import_key(account_dir, eml, "INBOX", data)
        account = Account(email="user@example.com", password="pass")
        old_spelling = ServerConfig(host="imap.example.com", port=993, ssl=True)
        equivalent_spelling = ServerConfig(host="IMAP.EXAMPLE.COM.", port=993, ssl=True)
        assert _legacy_import_target_id(old_spelling, account) == _legacy_import_target_id(equivalent_spelling, account)
        (account_dir / "import.journal.jsonl").write_text(json.dumps({
            "key": key,
            "status": "committed",
            "target": _legacy_import_target_id(old_spelling, account),
            "mailbox": "INBOX",
            "path": "INBOX/u0000000001.eml",
        }) + "\n")

        class ExistingMessageImap:
            def __init__(self) -> None:
                self.append_count = 0

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"1"]

            def search(self, charset, *criteria):
                return "OK", [b"1"]

            def fetch(self, *_args, **_kwargs):
                return "OK", [(b"1 (RFC822.SIZE %d FLAGS (\\Seen) INTERNALDATE \"01-Jan-2024 00:00:00 +0000\" BODY[] {%d}" % (len(data), len(data)), data)]

            def append(self, *_args, **_kwargs):
                self.append_count += 1
                return "OK", [b""]

            def logout(self):
                return "OK", []

        fake_imap = ExistingMessageImap()

        @contextlib.contextmanager
        def fake_factory(*_args, **_kwargs) -> Iterator[ExistingMessageImap]:
            yield fake_imap

        import_account(
            account,
            equivalent_spelling,
            in_root,
            ignore_errors=False,
            imap_factory=fake_factory,
            source_server=self._source_server(),
        )

        assert fake_imap.append_count == 0

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
                return "OK", [(b"1 (RFC822.SIZE 77 FLAGS (\\Seen) INTERNALDATE \"01-Jan-2024 00:00:00 +0000\" BODY[] {77}", data)]

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

        import_account(
            account,
            server,
            in_root,
            ignore_errors=False,
            imap_factory=fake_factory,
            source_server=self._source_server(),
        )

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

        import_account(
            account,
            server,
            tmp_path,
            ignore_errors=False,
            imap_factory=fake_factory,
            source_server=self._source_server(),
        )

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

    @pytest.mark.parametrize(
        ("status", "hard_linked"),
        [
            ("pending", False),
            ("committed", True),
        ],
    )
    def test_reset_rejects_uncertain_import_journal_before_panel_reset(
        self,
        tmp_path: Path,
        status: str,
        hard_linked: bool,
    ) -> None:
        from components.imap_ops import _legacy_import_key, _legacy_import_target_id
        from components.main import main
        from components.models import Account, ServerConfig

        in_root = self._make_export(tmp_path)
        account_dir = in_root / "user@example.com"
        eml = account_dir / "INBOX" / "u0000000001.eml"
        account = Account(email="user@example.com", password="pass")
        server = ServerConfig(host="imap.example.com", port=993, ssl=True)
        key = _legacy_import_key(account_dir, eml, "INBOX", eml.read_bytes())
        row = {
            "key": key,
            "status": status,
            "target": _legacy_import_target_id(server, account),
            "mailbox": "INBOX",
            "path": "INBOX/u0000000001.eml",
        }
        journal = account_dir / "import.journal.jsonl"
        journal.write_text(json.dumps(row) + "\n")
        if hard_linked:
            victim = tmp_path / "outside-journal.jsonl"
            victim.write_bytes(journal.read_bytes())
            journal.unlink()
            try:
                journal.hardlink_to(victim)
            except (OSError, NotImplementedError) as exc:
                pytest.skip(f"hard link creation unavailable: {exc}")

        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": server.host, "port": server.port, "ssl": server.ssl, "starttls": server.starttls},
            "source_server": {"host": server.host, "port": server.port, "ssl": server.ssl, "starttls": server.starttls},
            "accounts": [{"email": account.email, "password": account.password}],
        }))

        class DummyDirectAdminClient:
            def __init__(self, *_args, **_kwargs) -> None:
                raise AssertionError("panel client should not be created")

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.main.DirectAdminClient", DummyDirectAdminClient), \
            mock.patch("components.da_ensure.reset_accounts_directadmin") as reset_mock, \
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

        assert rc == 4
        assert journal.exists()
        assert not list(account_dir.glob("import.journal.reset-*.jsonl"))
        reset_mock.assert_not_called()
        import_mock.assert_not_called()

    def test_reset_archive_failure_returns_error_without_import(self, tmp_path: Path) -> None:
        from components.main import main
        from components.models import Account, ServerConfig

        in_root = self._make_export(tmp_path)
        account = Account(email="user@example.com", password="pass")
        server = ServerConfig(host="imap.example.com", port=993, ssl=True)
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
            mock.patch("components.main.archive_legacy_import_journal_for_reset", side_effect=RuntimeError("archive failed")), \
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

        assert rc == 4
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
        from components.imap_ops import import_account, legacy_server_endpoint, legacy_server_endpoint_digest
        from components.models import Account, ServerConfig

        server = ServerConfig(host="dummy", port=993, ssl=True)
        account = Account(email="user@example.com", password="pass")

        # Set up a minimal export structure
        acc_dir = tmp_path / "user@example.com" / "NonExistent"
        acc_dir.mkdir(parents=True)
        eml = acc_dir / "u0000000001.eml"
        data = b"From: a\n\nbody"
        eml.write_bytes(data)
        meta = acc_dir / "u0000000001.json"
        meta.write_text(json.dumps(_legacy_integrity_metadata(
            data,
            account="user@example.com",
            mailbox="NonExistent",
            uid=1,
            flags="",
            internaldate="",
        )))
        _write_verify_export_state(acc_dir.parent, [
            {"mailbox": "NonExistent", "path": "NonExistent", "message_count": 1},
        ])
        state_path = acc_dir.parent / "export-state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["source_server"] = legacy_server_endpoint(server)
        state["source_server_sha256"] = legacy_server_endpoint_digest(server)
        state_path.write_text(json.dumps(state))

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
                    source_server=server,
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
                {"email": "a@example.com", "password": "secret-a"},
                {"email": "a@example.com", "password": "secret-b"},
            ],
        }))

        with pytest.raises(ValueError, match="duplicates"):
            Config.from_json_file(duplicate)

    def test_legacy_config_rejects_case_only_account_path_collisions(self, tmp_path: Path) -> None:
        from components.models import Config

        case_distinct = tmp_path / "case-distinct.json"
        case_distinct.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [
                {"email": "User@example.com", "password": "secret-a"},
                {"email": "user@example.com", "password": "secret-b"},
            ],
        }))

        with pytest.raises(ValueError, match="case-insensitive"):
            Config.from_json_file(case_distinct)

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

    def test_test_accounts_passes_imap_timeout_to_imapsync_probe(self) -> None:
        from components.main import test_accounts
        from components.models import Account, Config, ServerConfig

        config = Config(
            server=ServerConfig(host="imap.example.com", port=993, ssl=True, starttls=False),
            accounts=[Account(email="a@example.com", password="secret")],
        )
        seen_timeouts: List[float] = []

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[object]:
            yield object()

        def fake_justconnect(*_args, timeout_sec, **_kwargs):
            seen_timeouts.append(timeout_sec)
            return True, "ok"

        with mock.patch("components.imap_ops.imap_connection", fake_connection), \
            mock.patch("components.main.run_imapsync_justconnect", fake_justconnect):
            test_accounts(config, max_workers=1, imap_timeout=123.0)

        assert seen_timeouts == [123.0]

    def test_main_passes_imap_timeout_to_legacy_test_mode(self, tmp_path: Path) -> None:
        from components.main import main

        config_path = tmp_path / "test.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))
        seen_calls: List[Tuple[int, float]] = []

        def fake_test_accounts(_config, *, max_workers, imap_timeout, **_kwargs):
            seen_calls.append((max_workers, imap_timeout))

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.utils.ensure_imapsync_available"), \
            mock.patch("components.main.test_accounts", fake_test_accounts):
            rc = main([
                "--mode", "test",
                "--config", str(config_path),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--imap-timeout", "123",
            ])

        assert rc == 0
        assert seen_calls == [(1, 123.0)]

    @pytest.mark.parametrize(
        ("mode", "extra_args"),
        [
            ("audit", ["--audit-offline", "--auto-provision-da"]),
            ("validate", ["--auto-provision-cpanel"]),
            ("export", ["--auto-provision-da", "--reset", "--reset-confirm", "imap.example.com"]),
        ],
    )
    def test_main_rejects_legacy_panel_flags_outside_import(
        self,
        tmp_path: Path,
        mode: str,
        extra_args: List[str],
    ) -> None:
        from components.main import main

        config_path = tmp_path / "export.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))

        with mock.patch("components.main.export_account", side_effect=AssertionError("mode should not run")):
            rc = main([
                "--mode", mode,
                "--config", str(config_path),
                "--log-dir", str(tmp_path / f"logs-{mode}"),
                "--min-free-gb", "0",
                "--no-connectivity-test",
                *extra_args,
            ])

        assert rc == 2

    @pytest.mark.parametrize("extra_args", [[], ["--reset-confirm", "YES"]])
    def test_main_rejects_reset_without_panel_before_confirm_or_input(
        self,
        tmp_path: Path,
        extra_args: List[str],
    ) -> None:
        from components.main import main

        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))

        with mock.patch("components.main.logging.error") as log_error:
            rc = main([
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(tmp_path / "missing-input"),
                "--log-dir", str(tmp_path / "logs-reset-no-panel"),
                "--min-free-gb", "0",
                "--reset",
                *extra_args,
            ])

        assert rc == 2
        error_text = " ".join(str(call) for call in log_error.call_args_list)
        assert "--reset requires --auto-provision-da or --auto-provision-cpanel" in error_text
        assert "--reset-confirm must match" not in error_text
        assert "Input directory does not exist" not in error_text

    def test_main_rejects_multiple_panel_backends_before_input_checks(self, tmp_path: Path) -> None:
        from components.main import main

        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))

        with mock.patch("components.main.logging.error") as log_error:
            rc = main([
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(tmp_path / "missing-input"),
                "--log-dir", str(tmp_path / "logs-panel-conflict"),
                "--min-free-gb", "0",
                "--auto-provision-da",
                "--auto-provision-cpanel",
            ])

        assert rc == 2
        error_text = " ".join(str(call) for call in log_error.call_args_list)
        assert "Choose only one control panel integration" in error_text
        assert "Input directory does not exist" not in error_text

    @pytest.mark.parametrize(
        ("backend_flag", "wrong_dry_run", "expected_error"),
        [
            ("--auto-provision-da", "--cpanel-dry-run", "--cpanel-dry-run requires --auto-provision-cpanel"),
            ("--auto-provision-cpanel", "--da-dry-run", "--da-dry-run requires --auto-provision-da"),
        ],
    )
    def test_main_rejects_wrong_backend_dry_run_before_input_checks(
        self,
        tmp_path: Path,
        backend_flag: str,
        wrong_dry_run: str,
        expected_error: str,
    ) -> None:
        from components.main import main

        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))

        with mock.patch("components.main.logging.error") as log_error:
            rc = main([
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(tmp_path / "missing-input"),
                "--log-dir", str(tmp_path / f"logs-{backend_flag[2:]}"),
                "--min-free-gb", "0",
                backend_flag,
                wrong_dry_run,
            ])

        assert rc == 2
        error_text = " ".join(str(call) for call in log_error.call_args_list)
        assert expected_error in error_text
        assert "Input directory does not exist" not in error_text

    def test_main_free_space_check_uses_requested_output_not_cwd(self, tmp_path: Path) -> None:
        from components.main import main

        config_path = tmp_path / "export.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))
        output_dir = tmp_path / "exported"
        gib = 1024 ** 3

        def fake_disk_usage(path):
            if Path(path).resolve() == Path.cwd().resolve():
                raise AssertionError("CWD free space should not gate requested output path")
            return (100 * gib, 1 * gib, 99 * gib)

        with mock.patch("components.utils.shutil.disk_usage", fake_disk_usage), \
            mock.patch("components.main.export_account"):
            rc = main([
                "--mode", "export",
                "--config", str(config_path),
                "--output-dir", str(output_dir),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "10",
                "--max-workers", "1",
                "--no-connectivity-test",
                "--no-audit-after-export",
            ])

        assert rc == 0

    @pytest.mark.parametrize("mode", ["export", "import", "validate", "audit"])
    def test_main_checks_legacy_free_space_before_connectivity(
        self,
        tmp_path: Path,
        mode: str,
    ) -> None:
        from components.main import main

        config_path = tmp_path / f"{mode}.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "source_server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))
        output_dir = tmp_path / "exported-output"
        input_dir = tmp_path / "exported-input"
        input_dir.mkdir()
        events: List[str] = []

        def fail_free_space(*_args, **_kwargs):
            events.append("free-space")
            raise RuntimeError("low disk")

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.audit_export", return_value=(True, [])), \
            mock.patch("components.main.check_free_space_for_path", fail_free_space), \
            mock.patch("components.utils.ensure_imapsync_available", side_effect=AssertionError("imapsync check should not run")), \
            mock.patch("components.main.test_accounts", side_effect=AssertionError("connectivity should not run")):
            rc = main([
                "--mode", mode,
                "--config", str(config_path),
                "--output-dir", str(output_dir),
                "--input-dir", str(input_dir),
                "--log-dir", str(tmp_path / f"logs-free-space-{mode}"),
                "--min-free-gb", "1000",
                "--max-workers", "1",
                "--no-audit-after-export",
            ])

        assert rc == 2
        assert events == ["free-space"]

    def test_setup_logging_creates_private_log_file(self, tmp_path: Path) -> None:
        from components.main import setup_logging

        log_file = setup_logging(tmp_path / "logs")

        assert log_file.stat().st_mode & 0o777 == 0o600

    def test_setup_logging_rejects_symlinked_log_directory_ancestor(self, tmp_path: Path) -> None:
        from components.main import setup_logging

        outside = tmp_path / "outside"
        outside.mkdir()
        link = tmp_path / "link"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")

        log_dir = link / "logs"
        assert not log_dir.is_symlink()

        with pytest.raises(RuntimeError, match="symlinked log directory"):
            setup_logging(log_dir)

        assert not (outside / "logs").exists()

    def test_setup_logging_does_not_follow_symlinked_log_file(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from components.main import setup_logging

        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        victim = tmp_path / "victim.txt"
        victim.write_text("outside\n", encoding="utf-8")
        victim.chmod(0o644)
        symlink = log_dir / "run-20240101-000000.log"
        try:
            symlink.symlink_to(victim)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")
        monkeypatch.setattr("components.main._utc_log_timestamp", lambda: "20240101-000000")

        log_file = setup_logging(log_dir)

        assert log_file.name == "run-20240101-000000-1.log"
        assert not log_file.is_symlink()
        assert victim.read_text(encoding="utf-8") == "outside\n"
        assert victim.stat().st_mode & 0o777 == 0o644

    def test_setup_logging_rejects_log_directory_swap_before_open(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from components.main import setup_logging

        log_dir = tmp_path / "logs"
        outside = tmp_path / "outside"
        log_dir.mkdir()
        outside.mkdir()
        monkeypatch.setattr("components.main._utc_log_timestamp", lambda: "20240101-000000")

        real_open = os.open
        swapped = False

        def racing_open(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal swapped
            if (
                isinstance(path, str)
                and path.startswith("run-20240101-000000")
                and dir_fd is not None
                and not swapped
            ):
                swapped = True
                try:
                    log_dir.rmdir()
                    log_dir.symlink_to(outside, target_is_directory=True)
                except (OSError, NotImplementedError) as exc:
                    pytest.skip(f"symlink race setup unavailable: {exc}")
            return real_open(path, flags, mode, dir_fd=dir_fd)

        monkeypatch.setattr(os, "open", racing_open)

        with pytest.raises(RuntimeError, match="replaced log directory"):
            setup_logging(log_dir)

        assert swapped
        assert not any(outside.iterdir())

    def test_setup_logging_uses_utc_timestamps_for_z_suffix(self, tmp_path: Path) -> None:
        import logging
        import time

        from components.main import setup_logging

        setup_logging(tmp_path / "logs")
        formatter = logging.getLogger().handlers[0].formatter
        record = logging.LogRecord("test", logging.INFO, __file__, 1, "timestamp-check", (), None)
        record.created = 0

        assert formatter.converter is time.gmtime
        assert formatter.format(record).startswith("1970-01-01T00:00:00Z")

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

    def test_legacy_validate_rejects_remote_message_missing_flags(self, tmp_path: Path) -> None:
        from components.main import main
        from components.models import ServerConfig

        server = ServerConfig("imap.example.com")
        config_path = tmp_path / "import.pass.config.json"
        server_json = {"host": server.host, "port": server.port, "ssl": server.ssl, "starttls": server.starttls}
        config_path.write_text(json.dumps({
            "server": server_json,
            "source_server": server_json,
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))
        input_dir = tmp_path / "exported"
        body = b"Message-ID: <flag-mismatch@example.com>\r\n\r\nbody"
        _write_legacy_message_fixture(
            input_dir / "a@example.com" / "INBOX",
            data=body,
            flags="\\Seen \\Answered",
            source_server=server,
        )

        class MissingFlagRemote:
            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"1"]

            def search(self, charset, *criteria):
                if criteria == ("ALL",):
                    return "OK", [b"1"]
                if len(criteria) == 3 and criteria[:2] == ("HEADER", "Message-ID"):
                    wanted = str(criteria[2]).strip('"')
                    if wanted == "<flag-mismatch@example.com>":
                        return "OK", [b"1"]
                return "OK", [b""]

            def fetch(self, num: bytes, query: str):
                assert "FLAGS" in query
                return "OK", [(b"1 (RFC822.SIZE %d FLAGS (\\Seen) INTERNALDATE \"01-Jan-2024 00:00:00 +0000\" BODY[] {%d}" % (len(body), len(body)), body)]

            def logout(self):
                return "OK", []

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[MissingFlagRemote]:
            yield MissingFlagRemote()

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
                    return "OK", [(b"1 (RFC822.SIZE 36 FLAGS (\\Seen) INTERNALDATE \"01-Jan-2024 00:00:00 +0000\" BODY[] {36}", duplicate)]
                return "OK", [(b"2 (RFC822.SIZE 37 FLAGS (\\Seen) INTERNALDATE \"01-Jan-2024 00:00:00 +0000\" BODY[] {37}", b"Message-ID: <other@example.com>\r\n\r\nbody")]

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
                return "OK", [(b"1 (RFC822.SIZE 36 FLAGS (\\Seen) INTERNALDATE \"01-Jan-2024 00:00:00 +0000\" BODY[] {36}", b"Message-ID: <m@example.com>\r\n\r\nbody")]

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

    def test_legacy_validate_rejects_malformed_import_journal_without_repair(self, tmp_path: Path) -> None:
        from components.main import main
        from components.models import Account, ServerConfig

        source = ServerConfig(host="source.example.com", port=993, ssl=True, starttls=False)
        target = ServerConfig(host="target.example.com", port=993, ssl=True, starttls=False)
        account = Account(email="a@example.com", password="secret")
        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": target.host, "port": target.port, "ssl": target.ssl, "starttls": target.starttls},
            "source_server": {"host": source.host, "port": source.port, "ssl": source.ssl, "starttls": source.starttls},
            "accounts": [{"email": account.email, "password": account.password}],
        }))
        input_dir = tmp_path / "exported"
        account_dir = input_dir / account.email
        folder = account_dir / "INBOX"
        _write_legacy_message_fixture(
            folder,
            data=b"Message-ID: <journal-malformed@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody",
            source_server=source,
        )
        (folder / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": 1}))
        journal = account_dir / "import.journal.jsonl"
        original_journal = json.dumps({"key": "a" * 64, "target": "b" * 64, "status": "committed"}) + "\n{\"key\":"
        journal.write_text(original_journal)

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.imap_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
            rc = main([
                "--mode", "validate",
                "--config", str(config_path),
                "--input-dir", str(input_dir),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--no-connectivity-test",
            ])

        assert rc == 4
        assert journal.read_text() == original_journal

    def test_legacy_validate_allows_pending_resolved_by_later_committed_journal(self, tmp_path: Path) -> None:
        from components.imap_ops import _legacy_import_key, _legacy_import_target_id
        from components.main import main
        from components.models import Account, ServerConfig

        server = ServerConfig(host="imap.example.com", port=993, ssl=True, starttls=False)
        account = Account(email="a@example.com", password="secret")
        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": server.host, "port": server.port, "ssl": server.ssl, "starttls": server.starttls},
            "source_server": {"host": server.host, "port": server.port, "ssl": server.ssl, "starttls": server.starttls},
            "accounts": [{"email": account.email, "password": account.password}],
        }))
        input_dir = tmp_path / "exported"
        account_dir = input_dir / "a@example.com"
        mailbox_dir = account_dir / "INBOX"
        data = (
            b"From: sender@example.com\r\n"
            b"To: recipient@example.com\r\n"
            b"Message-ID: <m@example.com>\r\n"
            b"\r\n"
            b"body"
        )
        eml = _write_legacy_message_fixture(mailbox_dir, data=data, source_server=server)
        key = _legacy_import_key(account_dir, eml, "INBOX", data)
        target_id = _legacy_import_target_id(server, account)
        journal_rows = [
            {
                "key": key,
                "target": target_id,
                "mailbox": "INBOX",
                "path": "INBOX/u0000000001.eml",
                "status": "pending",
            },
            {
                "key": key,
                "target": target_id,
                "mailbox": "INBOX",
                "path": "INBOX/u0000000001.eml",
                "status": "committed",
            },
        ]
        (account_dir / "import.journal.jsonl").write_text(
            "".join(json.dumps(row) + "\n" for row in journal_rows)
        )

        class MatchingRemote:
            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"1"]

            def search(self, charset, *criteria):
                return "OK", [b"1"]

            def fetch(self, *_args, **_kwargs):
                return "OK", [(b"1 (RFC822.SIZE %d FLAGS (\\Seen) INTERNALDATE \"01-Jan-2024 00:00:00 +0000\" BODY[] {%d}" % (len(data), len(data)), data)]

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

        assert rc == 0

    def test_legacy_validate_rejects_sanitized_remote_mailbox_alias(self, tmp_path: Path) -> None:
        from components.main import main
        from components.models import ServerConfig

        server = ServerConfig(host="imap.example.com", port=993, ssl=True, starttls=False)
        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": server.host, "port": server.port, "ssl": server.ssl, "starttls": server.starttls},
            "source_server": {"host": server.host, "port": server.port, "ssl": server.ssl, "starttls": server.starttls},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))
        input_dir = tmp_path / "exported"
        data = (
            b"From: sender@example.com\r\n"
            b"To: recipient@example.com\r\n"
            b"Message-ID: <alias-validate@example.com>\r\n"
            b"\r\n"
            b"body"
        )
        folder = input_dir / "a@example.com" / "A_B"
        _write_legacy_message_fixture(folder, mailbox="A/B", data=data, source_server=server)
        (folder / ".mailbox.json").write_text(json.dumps({"mailbox": "A/B", "message_count": 1}))

        class AliasRemote:
            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "A_B"']

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"1"]

            def search(self, charset, *criteria):
                return "OK", [b"1"]

            def fetch(self, *_args, **_kwargs):
                return "OK", [(b"1 (RFC822.SIZE %d FLAGS (\\Seen) INTERNALDATE \"01-Jan-2024 00:00:00 +0000\" BODY[] {%d}" % (len(data), len(data)), data)]

            def logout(self):
                return "OK", []

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[AliasRemote]:
            yield AliasRemote()

        with mock.patch("components.imap_ops.imap_connection", fake_connection):
            rc = main([
                "--mode", "validate",
                "--config", str(config_path),
                "--input-dir", str(input_dir),
                "--log-dir", str(tmp_path / "logs-alias"),
                "--min-free-gb", "0",
                "--no-connectivity-test",
            ])

        assert rc == 4

    def test_legacy_validate_rejects_pending_journal_before_target_contact(self, tmp_path: Path) -> None:
        from components.imap_ops import _legacy_import_key, _legacy_import_target_id
        from components.main import main
        from components.models import Account, ServerConfig

        server = ServerConfig(host="imap.example.com", port=993, ssl=True, starttls=False)
        account = Account(email="a@example.com", password="secret")
        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": server.host, "port": server.port, "ssl": server.ssl, "starttls": server.starttls},
            "source_server": {"host": server.host, "port": server.port, "ssl": server.ssl, "starttls": server.starttls},
            "accounts": [{"email": account.email, "password": account.password}],
        }))
        input_dir = tmp_path / "exported"
        account_dir = input_dir / account.email
        mailbox_dir = account_dir / "INBOX"
        data = b"Message-ID: <pending-validate@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody"
        eml = _write_legacy_message_fixture(mailbox_dir, data=data, source_server=server)
        key = _legacy_import_key(account_dir, eml, "INBOX", data)
        (account_dir / "import.journal.jsonl").write_text(json.dumps({
            "key": key,
            "target": _legacy_import_target_id(server, account),
            "mailbox": "INBOX",
            "path": "INBOX/u0000000001.eml",
            "status": "pending",
        }) + "\n")
        opened = False

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[object]:
            nonlocal opened
            opened = True
            raise AssertionError("target should not be contacted")
            yield object()

        with mock.patch("components.imap_ops.imap_connection", fake_connection):
            rc = main([
                "--mode", "validate",
                "--config", str(config_path),
                "--input-dir", str(input_dir),
                "--log-dir", str(tmp_path / "logs-pending"),
                "--min-free-gb", "0",
                "--no-connectivity-test",
            ])

        assert rc == 4
        assert opened is False

    def test_legacy_validate_rejects_keyless_pending_journal_before_target_contact(self, tmp_path: Path) -> None:
        from components.imap_ops import _legacy_import_target_id
        from components.main import main
        from components.models import Account, ServerConfig

        server = ServerConfig(host="imap.example.com", port=993, ssl=True, starttls=False)
        account = Account(email="a@example.com", password="secret")
        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": server.host, "port": server.port, "ssl": server.ssl, "starttls": server.starttls},
            "source_server": {"host": server.host, "port": server.port, "ssl": server.ssl, "starttls": server.starttls},
            "accounts": [{"email": account.email, "password": account.password}],
        }))
        input_dir = tmp_path / "exported"
        account_dir = input_dir / account.email
        mailbox_dir = account_dir / "INBOX"
        data = b"Message-ID: <keyless-pending-validate@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody"
        _write_legacy_message_fixture(mailbox_dir, data=data, source_server=server)
        (account_dir / "import.journal.jsonl").write_text(json.dumps({
            "target": _legacy_import_target_id(server, account),
            "mailbox": "INBOX",
            "path": "INBOX/u0000000001.eml",
            "status": "pending",
        }) + "\n")
        opened = False

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[object]:
            nonlocal opened
            opened = True
            raise AssertionError("target should not be contacted")
            yield object()

        with mock.patch("components.imap_ops.imap_connection", fake_connection):
            rc = main([
                "--mode", "validate",
                "--config", str(config_path),
                "--input-dir", str(input_dir),
                "--log-dir", str(tmp_path / "logs-keyless-pending"),
                "--min-free-gb", "0",
                "--no-connectivity-test",
            ])

        assert rc == 4
        assert opened is False

    def test_legacy_validate_rejects_pending_journal_before_connectivity_test(self, tmp_path: Path) -> None:
        from components.imap_ops import _legacy_import_key, _legacy_import_target_id
        from components.main import main
        from components.models import Account, ServerConfig

        server = ServerConfig(host="imap.example.com", port=993, ssl=True, starttls=False)
        account = Account(email="a@example.com", password="secret")
        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": server.host, "port": server.port, "ssl": server.ssl, "starttls": server.starttls},
            "source_server": {"host": server.host, "port": server.port, "ssl": server.ssl, "starttls": server.starttls},
            "accounts": [{"email": account.email, "password": account.password}],
        }))
        input_dir = tmp_path / "exported"
        account_dir = input_dir / account.email
        mailbox_dir = account_dir / "INBOX"
        data = b"Message-ID: <pending-connectivity@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody"
        eml = _write_legacy_message_fixture(mailbox_dir, data=data, source_server=server)
        (account_dir / "import.journal.jsonl").write_text(json.dumps({
            "key": _legacy_import_key(account_dir, eml, "INBOX", data),
            "target": _legacy_import_target_id(server, account),
            "mailbox": "INBOX",
            "path": "INBOX/u0000000001.eml",
            "status": "pending",
        }) + "\n")
        events: List[str] = []

        def record_free_space(*_args, **_kwargs) -> None:
            events.append("free-space")

        def record_imapsync_check() -> None:
            events.append("imapsync")

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path", record_free_space), \
            mock.patch("components.utils.ensure_imapsync_available", record_imapsync_check), \
            mock.patch("components.main.test_accounts", side_effect=AssertionError("connectivity should not run")):
            rc = main([
                "--mode", "validate",
                "--config", str(config_path),
                "--input-dir", str(input_dir),
                "--log-dir", str(tmp_path / "logs-pending-connectivity"),
                "--min-free-gb", "0",
            ])

        assert rc == 4
        assert events == ["free-space"]

    def test_legacy_import_rejects_pending_journal_before_connectivity_test(self, tmp_path: Path) -> None:
        from components.imap_ops import _legacy_import_key, _legacy_import_target_id
        from components.main import main
        from components.models import Account, ServerConfig

        source = ServerConfig(host="source.example.com", port=993, ssl=True, starttls=False)
        target = ServerConfig(host="target.example.com", port=993, ssl=True, starttls=False)
        account = Account(email="a@example.com", password="secret")
        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": target.host, "port": target.port, "ssl": target.ssl, "starttls": target.starttls},
            "source_server": {"host": source.host, "port": source.port, "ssl": source.ssl, "starttls": source.starttls},
            "accounts": [{"email": account.email, "password": account.password}],
        }))
        input_dir = tmp_path / "exported"
        account_dir = input_dir / account.email
        mailbox_dir = account_dir / "INBOX"
        data = b"Message-ID: <pending-import-connectivity@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody"
        eml = _write_legacy_message_fixture(mailbox_dir, data=data, source_server=source)
        (account_dir / "import.journal.jsonl").write_text(json.dumps({
            "key": _legacy_import_key(account_dir, eml, "INBOX", data),
            "target": _legacy_import_target_id(target, account),
            "mailbox": "INBOX",
            "path": "INBOX/u0000000001.eml",
            "status": "pending",
        }) + "\n")
        events: List[str] = []

        def record_free_space(*_args, **_kwargs) -> None:
            events.append("free-space")

        def record_imapsync_check() -> None:
            events.append("imapsync")

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path", record_free_space), \
            mock.patch("components.utils.ensure_imapsync_available", record_imapsync_check), \
            mock.patch("components.main.test_accounts", side_effect=AssertionError("connectivity should not run")), \
            mock.patch("components.main.import_account", side_effect=AssertionError("import should not run")):
            rc = main([
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(input_dir),
                "--log-dir", str(tmp_path / "logs-pending-import-connectivity"),
                "--min-free-gb", "0",
            ])

        assert rc == 4
        assert events == ["free-space"]

    def test_legacy_audit_rejects_pending_import_journal(self, tmp_path: Path) -> None:
        from components.imap_ops import _legacy_import_key, _legacy_import_target_id
        from components.main import main
        from components.models import Account, ServerConfig

        source = ServerConfig(host="source.example.com", port=993, ssl=True, starttls=False)
        target = ServerConfig(host="target.example.com", port=993, ssl=True, starttls=False)
        account = Account(email="a@example.com", password="secret")
        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": target.host, "port": target.port, "ssl": target.ssl, "starttls": target.starttls},
            "source_server": {"host": source.host, "port": source.port, "ssl": source.ssl, "starttls": source.starttls},
            "accounts": [{"email": account.email, "password": account.password}],
        }))
        input_dir = tmp_path / "exported"
        account_dir = input_dir / account.email
        data = b"Message-ID: <pending-audit@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody"
        eml = _write_legacy_message_fixture(account_dir / "INBOX", data=data, source_server=source)
        (account_dir / "import.journal.jsonl").write_text(json.dumps({
            "key": _legacy_import_key(account_dir, eml, "INBOX", data),
            "target": _legacy_import_target_id(target, account),
            "mailbox": "INBOX",
            "path": "INBOX/u0000000001.eml",
            "status": "pending",
        }) + "\n")

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.audit.imap_connection", side_effect=AssertionError("remote audit should not run")):
            rc = main([
                "--mode", "audit",
                "--config", str(config_path),
                "--input-dir", str(input_dir),
                "--log-dir", str(tmp_path / "logs-pending-audit"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--audit-offline",
            ])

        assert rc == 4

    def test_legacy_audit_rejects_malformed_import_journal(self, tmp_path: Path) -> None:
        from components.main import main
        from components.models import Account, ServerConfig

        source = ServerConfig(host="source.example.com", port=993, ssl=True, starttls=False)
        target = ServerConfig(host="target.example.com", port=993, ssl=True, starttls=False)
        account = Account(email="a@example.com", password="secret")
        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": target.host, "port": target.port, "ssl": target.ssl, "starttls": target.starttls},
            "source_server": {"host": source.host, "port": source.port, "ssl": source.ssl, "starttls": source.starttls},
            "accounts": [{"email": account.email, "password": account.password}],
        }))
        input_dir = tmp_path / "exported"
        account_dir = input_dir / account.email
        _write_legacy_message_fixture(
            account_dir / "INBOX",
            data=b"Message-ID: <malformed-audit@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody",
            source_server=source,
        )
        journal = account_dir / "import.journal.jsonl"
        original = '{"key": '
        journal.write_text(original)

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"):
            rc = main([
                "--mode", "audit",
                "--config", str(config_path),
                "--input-dir", str(input_dir),
                "--log-dir", str(tmp_path / "logs-malformed-audit"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--audit-offline",
            ])

        assert rc == 4
        assert journal.read_text() == original

    def test_legacy_import_allows_trailing_journal_repair_before_import(self, tmp_path: Path) -> None:
        from components.main import main
        from components.models import Account, ServerConfig

        source = ServerConfig(host="source.example.com", port=993, ssl=True, starttls=False)
        target = ServerConfig(host="target.example.com", port=993, ssl=True, starttls=False)
        account = Account(email="a@example.com", password="secret")
        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": target.host, "port": target.port, "ssl": target.ssl, "starttls": target.starttls},
            "source_server": {"host": source.host, "port": source.port, "ssl": source.ssl, "starttls": source.starttls},
            "accounts": [{"email": account.email, "password": account.password}],
        }))
        input_dir = tmp_path / "exported"
        account_dir = input_dir / account.email
        data = b"Message-ID: <trailing-import@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody"
        _write_legacy_message_fixture(account_dir / "INBOX", data=data, source_server=source)
        journal = account_dir / "import.journal.jsonl"
        journal.write_text('{"key": ')
        imported: List[str] = []

        def record_import(acc, *_args, **_kwargs) -> None:
            imported.append(acc.email)

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.main.import_account", record_import):
            rc = main([
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(input_dir),
                "--log-dir", str(tmp_path / "logs-trailing-import"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--no-connectivity-test",
            ])

        assert rc == 0
        assert imported == [account.email]
        assert journal.read_text() == ""

    def test_legacy_import_low_disk_does_not_repair_trailing_journal(self, tmp_path: Path) -> None:
        from components.main import main
        from components.models import Account, ServerConfig

        source = ServerConfig(host="source.example.com", port=993, ssl=True, starttls=False)
        target = ServerConfig(host="target.example.com", port=993, ssl=True, starttls=False)
        account = Account(email="a@example.com", password="secret")
        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": target.host, "port": target.port, "ssl": target.ssl, "starttls": target.starttls},
            "source_server": {"host": source.host, "port": source.port, "ssl": source.ssl, "starttls": source.starttls},
            "accounts": [{"email": account.email, "password": account.password}],
        }))
        input_dir = tmp_path / "exported"
        account_dir = input_dir / account.email
        _write_legacy_message_fixture(
            account_dir / "INBOX",
            data=b"Message-ID: <trailing-low-disk@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody",
            source_server=source,
        )
        journal = account_dir / "import.journal.jsonl"
        original = '{"key": '
        journal.write_text(original)

        def fail_free_space(*_args, **_kwargs) -> None:
            raise RuntimeError("low disk")

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path", fail_free_space), \
            mock.patch("components.main.audit_export", side_effect=AssertionError("staged audit should not run")), \
            mock.patch("components.main.import_account", side_effect=AssertionError("import should not run")):
            rc = main([
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(input_dir),
                "--log-dir", str(tmp_path / "logs-trailing-low-disk"),
                "--min-free-gb", "1000",
                "--max-workers", "1",
                "--no-connectivity-test",
            ])

        assert rc == 2
        assert journal.read_text() == original

    def test_legacy_validate_rejects_remote_empty_folder_missing_locally(self, tmp_path: Path) -> None:
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

        assert rc == 4

    def test_legacy_validate_rejects_case_only_remote_mailbox_collision(self, tmp_path: Path) -> None:
        from components.imap_ops import legacy_server_endpoint, legacy_server_endpoint_digest
        from components.main import main
        from components.models import ServerConfig

        source_server = ServerConfig(host="imap.example.com", port=993, ssl=True, starttls=False)
        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": source_server.host, "port": source_server.port, "ssl": source_server.ssl, "starttls": source_server.starttls},
            "source_server": {"host": source_server.host, "port": source_server.port, "ssl": source_server.ssl, "starttls": source_server.starttls},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))
        input_dir = tmp_path / "exported"
        folder = input_dir / "a@example.com" / "Folder"
        folder.mkdir(parents=True)
        (folder / ".mailbox.json").write_text(json.dumps({"mailbox": "Folder", "message_count": 0}))
        (input_dir / "a@example.com" / "export-state.json").write_text(json.dumps({
            "schema_version": 1,
            "account": "a@example.com",
            "source_server": legacy_server_endpoint(source_server),
            "source_server_sha256": legacy_server_endpoint_digest(source_server),
            "complete": True,
            "completed_at": 0,
            "mailboxes": [{"mailbox": "Folder", "path": "Folder", "message_count": 0}],
        }))

        class CaseOnlyCollisionRemote:
            def list(self):
                return "OK", [
                    b'(\\HasNoChildren) "/" "Folder"',
                    b'(\\HasNoChildren) "/" "folder"',
                ]

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"0"]

            def search(self, charset, *criteria):
                return "OK", [b""]

            def logout(self):
                return "OK", []

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[CaseOnlyCollisionRemote]:
            yield CaseOnlyCollisionRemote()

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

    def test_legacy_validate_treats_inbox_case_variants_as_same_mailbox(self, tmp_path: Path) -> None:
        from components.main import main
        from components.models import ServerConfig

        source_server = ServerConfig(host="imap.example.com", port=993, ssl=True, starttls=False)
        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": source_server.host, "port": source_server.port, "ssl": source_server.ssl, "starttls": source_server.starttls},
            "source_server": {"host": source_server.host, "port": source_server.port, "ssl": source_server.ssl, "starttls": source_server.starttls},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))
        input_dir = tmp_path / "exported"
        _write_legacy_empty_mailbox_fixture(
            input_dir / "a@example.com" / "INBOX",
            mailbox="INBOX",
            source_server=source_server,
        )

        class InboxCaseRemote:
            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "Inbox"']

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"0"]

            def search(self, charset, *criteria):
                return "OK", [b""]

            def logout(self):
                return "OK", []

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[InboxCaseRemote]:
            yield InboxCaseRemote()

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

    def test_legacy_audit_rejects_remote_empty_folder_missing_locally(self, tmp_path: Path) -> None:
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
                return "OK", [(b"1 (RFC822.SIZE 39 FLAGS (\\Seen) INTERNALDATE \"01-Jan-2024 00:00:00 +0000\" BODY[] {39}", data)]

            def logout(self):
                return "OK", []

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[EmptyRemoteFolderImap]:
            yield EmptyRemoteFolderImap()

        with mock.patch("components.audit.imap_connection", fake_connection):
            _email, issues = audit_account(account, tmp_path, ServerConfig(host="imap.example.com"), check_remote=True)

        assert any("Projects: missing locally but remote has 0 messages" in issue for issue in issues)

    def test_legacy_audit_treats_inbox_case_variants_as_same_mailbox(self, tmp_path: Path) -> None:
        from components.audit import audit_account
        from components.models import Account, ServerConfig

        source_server = ServerConfig(host="imap.example.com", port=993, ssl=True, starttls=False)
        account = Account(email="a@example.com", password="secret")
        _write_legacy_empty_mailbox_fixture(
            tmp_path / "a@example.com" / "INBOX",
            mailbox="INBOX",
            source_server=source_server,
        )

        class InboxCaseRemote:
            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "Inbox"']

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"0"]

            def uid(self, command: str, *args):
                return "OK", [b""]

            def logout(self):
                return "OK", []

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[InboxCaseRemote]:
            yield InboxCaseRemote()

        with mock.patch("components.audit.imap_connection", fake_connection):
            _email, issues = audit_account(account, tmp_path, source_server, check_remote=True)

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

    def test_audit_account_flags_remote_message_missing_flags(self, tmp_path: Path) -> None:
        from components.audit import audit_account
        from components.models import Account, ServerConfig

        server = ServerConfig(host="imap.example.com")
        account = Account(email="a@example.com", password="secret")
        body = b"Message-ID: <audit-flag-mismatch@example.com>\r\n\r\nbody"
        _write_legacy_message_fixture(
            tmp_path / account.email / "INBOX",
            data=body,
            flags="\\Seen \\Answered",
            source_server=server,
        )

        class CountAndBodyMatchMissingFlagRemote:
            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"1"]

            def uid(self, command: str, *args):
                if command == "search":
                    return "OK", [b"1"]
                raise AssertionError(command)

            def search(self, charset, *criteria):
                if criteria == ("ALL",):
                    return "OK", [b"1"]
                if len(criteria) == 3 and criteria[:2] == ("HEADER", "Message-ID"):
                    wanted = str(criteria[2]).strip('"')
                    if wanted == "<audit-flag-mismatch@example.com>":
                        return "OK", [b"1"]
                return "OK", [b""]

            def fetch(self, num: bytes, query: str):
                assert "FLAGS" in query
                return "OK", [(b"1 (RFC822.SIZE %d FLAGS (\\Seen) INTERNALDATE \"01-Jan-2024 00:00:00 +0000\" BODY[] {%d}" % (len(body), len(body)), body)]

            def logout(self):
                return "OK", []

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[CountAndBodyMatchMissingFlagRemote]:
            yield CountAndBodyMatchMissingFlagRemote()

        with mock.patch("components.audit.imap_connection", fake_connection):
            _email, issues = audit_account(account, tmp_path, server, check_remote=True)

        assert any("remote flags missing" in issue and "\\ANSWERED" in issue for issue in issues)

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

    def test_audit_account_flags_mailbox_marker_missing_mailbox(self, tmp_path: Path) -> None:
        from components.audit import audit_account
        from components.models import Account

        account = Account(email="a@example.com", password="secret")
        inbox = tmp_path / "a@example.com" / "INBOX"
        inbox.mkdir(parents=True)
        (inbox / ".mailbox.json").write_text(json.dumps({"message_count": 0}))

        _email, issues = audit_account(account, tmp_path, server=None, check_remote=False)

        assert any("mailbox marker missing mailbox" in issue for issue in issues)

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
        eml.with_suffix(".json").write_text(json.dumps(_legacy_integrity_metadata(data, mailbox="INBOX", uid=1)))

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

    def test_default_audit_honors_present_message_integrity_metadata(self, tmp_path: Path) -> None:
        from components.audit import audit_account
        from components.models import Account

        account = Account(email="a@example.com", password="secret")
        inbox = tmp_path / "a@example.com" / "INBOX"
        eml = _write_legacy_message_fixture(
            inbox,
            data=b"Message-ID: <m@example.com>\r\n\r\none",
        )
        eml.write_bytes(b"Message-ID: <m@example.com>\r\n\r\ntwo")

        _email, issues = audit_account(
            account,
            tmp_path,
            server=None,
            check_remote=False,
            require_integrity_metadata=False,
        )

        assert any("content_sha256 mismatch" in issue for issue in issues)

    def test_main_legacy_audit_requires_message_integrity_metadata(self, tmp_path: Path) -> None:
        from components.main import main

        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "source_server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))
        input_dir = tmp_path / "exported"
        folder = input_dir / "a@example.com" / "INBOX"
        data = b"Message-ID: <audit-integrity@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody"
        eml = _write_legacy_message_fixture(folder, data=data)
        eml.with_suffix(".json").write_text(json.dumps({
            "account": "a@example.com",
            "mailbox": "INBOX",
            "uid": 1,
            "flags": "\\Seen",
            "internaldate": "01-Jan-2024 00:00:00 +0000",
        }))

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"):
            rc = main([
                "--mode", "audit",
                "--config", str(config_path),
                "--input-dir", str(input_dir),
                "--log-dir", str(tmp_path / "logs-audit-integrity"),
                "--min-free-gb", "0",
                "--audit-offline",
            ])

        assert rc == 4

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

    @pytest.mark.parametrize("overwrite", [False, True])
    def test_write_json_does_not_chmod_replaced_symlink_target(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        overwrite: bool,
    ) -> None:
        import directadmin_indexer

        out = tmp_path / "export.pass.config.json"
        victim = tmp_path / "victim.json"
        victim.write_text("outside\n")
        victim.chmod(0o644)
        original_mode = victim.stat().st_mode & 0o777

        if overwrite:
            out.write_text("{}")
            real_rename = directadmin_indexer.os.rename

            def racing_rename(src: str, dst: str, *args, **kwargs) -> None:
                real_rename(src, dst, *args, **kwargs)
                dst_dir_fd = kwargs.get("dst_dir_fd")
                try:
                    if dst_dir_fd is None:
                        Path(dst).unlink()
                        Path(dst).symlink_to(victim)
                    else:
                        os.unlink(dst, dir_fd=dst_dir_fd)
                        os.symlink(victim, dst, dir_fd=dst_dir_fd)
                except (OSError, NotImplementedError) as exc:
                    pytest.skip(f"symlink creation unavailable: {exc}")

            monkeypatch.setattr(directadmin_indexer.os, "rename", racing_rename)
        else:
            real_link = directadmin_indexer.os.link

            def racing_link(src: str, dst: str, *args, **kwargs) -> None:
                real_link(src, dst, *args, **kwargs)
                dst_dir_fd = kwargs.get("dst_dir_fd")
                try:
                    if dst_dir_fd is None:
                        Path(dst).unlink()
                        Path(dst).symlink_to(victim)
                    else:
                        os.unlink(dst, dir_fd=dst_dir_fd)
                        os.symlink(victim, dst, dir_fd=dst_dir_fd)
                except (OSError, NotImplementedError) as exc:
                    pytest.skip(f"symlink creation unavailable: {exc}")

            monkeypatch.setattr(directadmin_indexer.os, "link", racing_link)

        directadmin_indexer.write_json({"accounts": []}, str(out), overwrite=overwrite)

        assert out.is_symlink()
        assert victim.stat().st_mode & 0o777 == original_mode

    @pytest.mark.parametrize("overwrite", [False, True])
    def test_write_json_rejects_symlinked_output_parent(self, tmp_path: Path, overwrite: bool) -> None:
        from directadmin_indexer import write_json

        outside = tmp_path / "outside"
        outside.mkdir()
        requested = tmp_path / "requested"
        try:
            requested.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")

        out = requested / "export.pass.config.json"

        with pytest.raises(RuntimeError, match="symlinked indexer output directory"):
            write_json({"accounts": [{"email": "a@example.com", "password": "secret"}]}, str(out), overwrite=overwrite)

        assert not (outside / "export.pass.config.json").exists()

    @pytest.mark.parametrize("overwrite", [False, True])
    def test_write_json_refuses_replaced_output_parent_before_publish(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        overwrite: bool,
    ) -> None:
        import directadmin_indexer

        parent = tmp_path / "requested"
        parent.mkdir()
        backup = tmp_path / "requested.old"
        outside = tmp_path / "outside"
        outside.mkdir()
        out = parent / "export.pass.config.json"
        if overwrite:
            out.write_text("{}")

        real_rename = directadmin_indexer.os.rename
        real_link = directadmin_indexer.os.link
        swapped = False

        def swap_parent_once() -> None:
            nonlocal swapped
            if swapped:
                return
            swapped = True
            real_rename(parent, backup)
            try:
                parent.symlink_to(outside, target_is_directory=True)
            except (OSError, NotImplementedError) as exc:
                pytest.skip(f"symlink creation unavailable: {exc}")

        if overwrite:
            def racing_rename(src: str, dst: str, *args, **kwargs) -> None:
                swap_parent_once()
                real_rename(src, dst, *args, **kwargs)

            monkeypatch.setattr(directadmin_indexer.os, "rename", racing_rename)
        else:
            def racing_link(src: str, dst: str, *args, **kwargs) -> None:
                swap_parent_once()
                real_link(src, dst, *args, **kwargs)

            monkeypatch.setattr(directadmin_indexer.os, "link", racing_link)

        with pytest.raises(RuntimeError, match="replaced indexer output directory"):
            directadmin_indexer.write_json(
                {"accounts": [{"email": "a@example.com", "password": "secret"}]},
                str(out),
                overwrite=overwrite,
            )

        assert swapped
        assert parent.is_symlink()
        assert not (outside / "export.pass.config.json").exists()
        assert not (backup / "export.pass.config.json").exists()

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

    def test_reset_confirm_accepts_dns_equivalent_target_host(self, tmp_path: Path) -> None:
        from components.main import main
        from components.models import ServerConfig

        source_server = ServerConfig(host="imap.example.com", port=993, ssl=True, starttls=False)
        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "IMAP.EXAMPLE.COM.", "port": 993, "ssl": True, "starttls": False},
            "source_server": {"host": "IMAP.EXAMPLE.COM.", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))
        input_root = tmp_path / "exported"
        _write_legacy_message_fixture(input_root / "a@example.com" / "INBOX", source_server=source_server)

        class DummyCPanelClient:
            def __init__(self, *_args, **_kwargs) -> None:
                pass

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.CPanelClient", side_effect=DummyCPanelClient) as client_cls, \
            mock.patch("components.cpanel_ensure.reset_accounts_cpanel", return_value={"a@example.com"}) as reset_mock, \
            mock.patch("components.main.import_account", side_effect=AssertionError("reset-failed account should be skipped")):
            rc = main([
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(input_root),
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
        client_cls.assert_called_once()
        reset_mock.assert_called_once()

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

        input_root = tmp_path / "exported"
        _write_legacy_message_fixture(input_root / "a@example.com" / "INBOX")
        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "source_server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
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
                "--input-dir", str(input_root),
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

    @pytest.mark.parametrize(
        ("panel_args", "client_path"),
        [
            (
                [
                    "--auto-provision-da",
                    "--da-dry-run",
                    "--da-url", "https://panel.example.com:2222",
                    "--da-username", "admin",
                    "--da-password", "login-key",
                ],
                "components.main.DirectAdminClient",
            ),
            (
                [
                    "--auto-provision-cpanel",
                    "--cpanel-dry-run",
                    "--cpanel-url", "https://panel.example.com:2083",
                    "--cpanel-username", "cpuser",
                    "--cpanel-token", "api-token",
                ],
                "components.main.CPanelClient",
            ),
        ],
    )
    def test_panel_dry_run_does_not_repair_trailing_import_journal(
        self,
        tmp_path: Path,
        panel_args: List[str],
        client_path: str,
    ) -> None:
        from components.main import main

        input_root = tmp_path / "exported"
        account_dir = input_root / "a@example.com"
        _write_legacy_message_fixture(account_dir / "INBOX")
        journal = account_dir / "import.journal.jsonl"
        original = '{"key": '
        journal.write_text(original)
        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "source_server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))

        with mock.patch("components.main.check_environment"), \
            mock.patch(client_path) as client_cls:
            rc = main([
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(input_root),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--no-connectivity-test",
                *panel_args,
            ])

        assert rc == 4
        assert journal.read_text() == original
        client_cls.assert_not_called()

    def test_cpanel_dry_run_does_not_require_imapsync_binary(self, tmp_path: Path) -> None:
        from components.main import main

        input_root = tmp_path / "exported"
        _write_legacy_message_fixture(input_root / "a@example.com" / "INBOX")
        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "source_server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
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
                "--input-dir", str(input_root),
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

        input_root = tmp_path / "exported"
        _write_legacy_message_fixture(input_root / "a@example.com" / "INBOX")
        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "source_server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
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
                "--input-dir", str(input_root),
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

        input_root = tmp_path / "exported"
        _write_legacy_message_fixture(input_root / "a@example.com" / "INBOX")
        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "source_server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
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
                "--input-dir", str(input_root),
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

        input_root = tmp_path / "exported"
        _write_legacy_message_fixture(input_root / "a@example.com" / "INBOX")
        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "source_server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
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
                "--input-dir", str(input_root),
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

    @pytest.mark.parametrize(
        ("backend_flag", "dry_run_flag", "client_path", "ensure_path", "panel_args"),
        [
            (
                "--auto-provision-cpanel",
                "--cpanel-dry-run",
                "components.main.CPanelClient",
                "components.main.ensure_accounts_exist_cpanel",
                ["--cpanel-url", "https://panel.example.com:2083", "--cpanel-username", "cpuser", "--cpanel-token", "api-token"],
            ),
            (
                "--auto-provision-da",
                "--da-dry-run",
                "components.main.DirectAdminClient",
                "components.main.ensure_accounts_exist_directadmin",
                ["--da-url", "https://panel.example.com:2222", "--da-username", "admin", "--da-password", "login-key"],
            ),
        ],
    )
    def test_panel_dry_run_rejects_missing_input_before_panel_calls(
        self,
        tmp_path: Path,
        backend_flag: str,
        dry_run_flag: str,
        client_path: str,
        ensure_path: str,
        panel_args: List[str],
    ) -> None:
        from components.main import main

        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))

        with mock.patch("components.main.check_environment"), \
            mock.patch(client_path) as client_cls, \
            mock.patch(ensure_path) as ensure_mock:
            rc = main([
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(tmp_path / "missing-export"),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--no-connectivity-test",
                backend_flag,
                dry_run_flag,
                *panel_args,
            ])

        assert rc == 2
        client_cls.assert_not_called()
        ensure_mock.assert_not_called()

    @pytest.mark.parametrize(
        ("backend_flag", "dry_run_flag", "client_path", "ensure_path", "panel_args"),
        [
            (
                "--auto-provision-cpanel",
                "--cpanel-dry-run",
                "components.main.CPanelClient",
                "components.main.ensure_accounts_exist_cpanel",
                ["--cpanel-url", "https://panel.example.com:2083", "--cpanel-username", "cpuser", "--cpanel-token", "api-token"],
            ),
            (
                "--auto-provision-da",
                "--da-dry-run",
                "components.main.DirectAdminClient",
                "components.main.ensure_accounts_exist_directadmin",
                ["--da-url", "https://panel.example.com:2222", "--da-username", "admin", "--da-password", "login-key"],
            ),
        ],
    )
    def test_panel_dry_run_audits_staged_input_before_panel_calls(
        self,
        tmp_path: Path,
        backend_flag: str,
        dry_run_flag: str,
        client_path: str,
        ensure_path: str,
        panel_args: List[str],
    ) -> None:
        from components.main import main

        input_root = tmp_path / "exported"
        inbox = input_root / "a@example.com" / "INBOX"
        _write_legacy_message_fixture(inbox)
        (inbox / "u0000000001.json").write_text("{")
        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "source_server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))

        with mock.patch("components.main.check_environment"), \
            mock.patch(client_path) as client_cls, \
            mock.patch(ensure_path) as ensure_mock:
            rc = main([
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(input_root),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--no-connectivity-test",
                backend_flag,
                dry_run_flag,
                *panel_args,
            ])

        assert rc == 4
        client_cls.assert_not_called()
        ensure_mock.assert_not_called()

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

    def test_imapsync_availability_probe_uses_timeout(self) -> None:
        from components import utils

        captured_kwargs = {}

        def fake_run(_args, **kwargs):
            captured_kwargs.update(kwargs)
            return subprocess.CompletedProcess(_args, 0, "", "")

        with mock.patch("components.utils.shutil.which", return_value="/usr/bin/imapsync"), \
            mock.patch("components.utils.subprocess.run", side_effect=fake_run):
            utils.ensure_imapsync_available()

        assert captured_kwargs["timeout"] == utils.IMAPSYNC_VERSION_TIMEOUT_SEC

    def test_imapsync_availability_probe_timeout_is_dependency_error(self) -> None:
        from components import utils

        with mock.patch("components.utils.shutil.which", return_value="/usr/bin/imapsync"), \
            mock.patch(
                "components.utils.subprocess.run",
                side_effect=subprocess.TimeoutExpired(["/usr/bin/imapsync", "--version"], utils.IMAPSYNC_VERSION_TIMEOUT_SEC),
            ):
            with pytest.raises(RuntimeError, match="did not respond to --version"):
                utils.ensure_imapsync_available()

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

    def test_justconnect_executes_validated_imapsync_binary(self) -> None:
        from components.imapsync_cli import run_imapsync_justconnect

        captured_args: List[List[str]] = []

        def fake_run(args, **_kwargs):
            captured_args.append(list(args))
            return subprocess.CompletedProcess(args, 0, "ok", "")

        with mock.patch("components.utils.shutil.which", return_value="/safe/bin/imapsync"), \
            mock.patch("components.utils.subprocess.run", side_effect=fake_run), \
            mock.patch("components.imapsync_cli.subprocess.run", side_effect=fake_run):
            ok, _out = run_imapsync_justconnect(
                host="imap.example.com",
                port=993,
                ssl_enabled=True,
                starttls=False,
                user="user@example.com",
                password="super-secret",
            )

        assert ok
        assert captured_args[0][0] == "/safe/bin/imapsync"
        assert captured_args[-1][0] == "/safe/bin/imapsync"

    def test_justconnect_terminates_subprocess_when_stop_requested(self) -> None:
        from components.imapsync_cli import run_imapsync_justconnect

        stop_event = threading.Event()
        stop_event.set()

        class FakeProcess:
            def __init__(self, *_args, **_kwargs) -> None:
                self.returncode = None
                self.communicate_calls = 0
                self.terminated = False
                self.killed = False

            def communicate(self, timeout=None):
                self.communicate_calls += 1
                if self.communicate_calls == 1:
                    raise subprocess.TimeoutExpired(["imapsync"], timeout)
                self.returncode = -15 if self.terminated else 0
                return "stopped", None

            def terminate(self):
                self.terminated = True

            def kill(self):
                self.killed = True

        fake_process = FakeProcess()

        with mock.patch("components.imapsync_cli.ensure_imapsync_available"), \
            mock.patch("components.imapsync_cli.subprocess.Popen", return_value=fake_process):
            ok, out = run_imapsync_justconnect(
                host="imap.example.com",
                port=993,
                ssl_enabled=True,
                starttls=False,
                user="user@example.com",
                password="super-secret",
                stop_event=stop_event,
            )

        assert not ok
        assert "stop requested" in out
        assert fake_process.terminated
        assert not fake_process.killed


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

        analysis, error = analyze_message(eml_path, json_path, require_metadata=False)

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

        analysis, error = analyze_message(eml_path, json_path, require_metadata=False)

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

        analysis, error = analyze_message(eml_path, json_path, require_metadata=False)

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

        analysis, error = analyze_message(eml_path, json_path, require_metadata=False)

        assert error is None
        assert analysis is not None
        assert analysis["multiple_messages_detected"] is False, (
            "LF-only email with forwarded headers should NOT be flagged"
        )

    def test_verify_export_checks_metadata_hash_and_size(self, tmp_path: Path) -> None:
        from verify_export import analyze_message

        eml_path = tmp_path / "test.eml"
        eml_path.write_bytes(b"Message-ID: <m@example.com>\r\n\r\ncorrupted")
        json_path = tmp_path / "test.json"
        json_path.write_text(json.dumps(_legacy_integrity_metadata(b"original")))

        analysis, error = analyze_message(eml_path, json_path, require_metadata=False)

        assert analysis is None
        assert error is not None
        assert "content_sha256 mismatch" in error
        assert "rfc822_size mismatch" in error

    def test_verify_export_requires_content_binding_metadata(self, tmp_path: Path) -> None:
        from verify_export import analyze_message

        payload = b"Message-ID: <m@example.com>\r\n\r\nbody"
        eml_path = tmp_path / "test.eml"
        eml_path.write_bytes(payload)
        json_path = tmp_path / "test.json"
        json_path.write_text(json.dumps({
            "content_sha256": hashlib.sha256(payload).hexdigest(),
            "rfc822_size": len(payload),
        }))

        analysis, error = analyze_message(eml_path, json_path)

        assert analysis is None
        assert error is not None
        assert "missing content_binding_sha256" in error

    def test_concatenated_message_after_body_is_detected(self, tmp_path: Path) -> None:
        from verify_export import analyze_message

        eml_path = tmp_path / "test.eml"
        eml_path.write_bytes(
            b"Return-Path: <a@example.com>\r\n"
            b"Message-ID: <one@example.com>\r\n"
            b"From: a@example.com\r\n"
            b"To: b@example.com\r\n"
            b"\r\n"
            b"body\r\n"
            b"Return-Path: <c@example.com>\r\n"
            b"Message-ID: <two@example.com>\r\n"
            b"From: c@example.com\r\n"
            b"To: d@example.com\r\n"
            b"\r\n"
            b"body2\r\n"
        )
        json_path = tmp_path / "test.json"

        analysis, error = analyze_message(eml_path, json_path, require_metadata=False)

        assert error is None
        assert analysis is not None
        assert analysis["multiple_messages_detected"] is True


class TestRound1ConfirmedBugs:
    def test_bad_log_dir_returns_cli_error(self, tmp_path: Path) -> None:
        from components.main import main

        log_path = tmp_path / "logs-as-file"
        log_path.write_text("not a directory")

        assert main(["--mode", "audit", "--config", "missing.json", "--log-dir", str(log_path)]) == 2

    def test_config_rejects_whitespace_only_host_and_email(self, tmp_path: Path) -> None:
        from components.models import load_config_file

        legacy_path = tmp_path / "legacy.json"
        legacy_path.write_text(json.dumps({
            "server": {"host": "   ", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "   ", "password": "secret"}],
        }))
        provider_path = tmp_path / "provider.json"
        provider_path.write_text(json.dumps({
            "source": {"provider": "imap", "host": "   ", "auth": {"method": "password", "password": "x"}},
            "target": {"provider": "imap", "host": "target.example.com", "auth": {"method": "password", "password": "x"}},
            "accounts": [{"source_email": "   ", "target_email": "target@example.com"}],
        }))

        with pytest.raises(ValueError, match="host"):
            load_config_file(legacy_path)
        with pytest.raises(ValueError, match="source.host"):
            load_config_file(provider_path)

    def test_sanitize_for_path_never_returns_unsafe_components(self) -> None:
        from components.utils import sanitize_for_path

        assert sanitize_for_path("") == "_"
        assert sanitize_for_path("   ") == "_"
        assert sanitize_for_path(".") == "_"
        assert sanitize_for_path("..") == "_"

    def test_export_mailbox_dotdot_stays_inside_account_dir(self, tmp_path: Path) -> None:
        from components.imap_ops import export_account
        from components.models import Account, ServerConfig

        class DotDotMailboxImap:
            response = _stable_uidvalidity_response

            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" ".."']

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"1"]

            def uid(self, command: str, *args):
                if command == "search":
                    return "OK", [b"1"]
                if command == "fetch":
                    return "OK", [(
                        b'1 (UID 1 FLAGS () INTERNALDATE "01-Jan-2024 00:00:00 +0000")',
                        b"Message-ID: <m@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody",
                    )]
                raise AssertionError(command)

            def logout(self):
                return "OK", []

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[DotDotMailboxImap]:
            yield DotDotMailboxImap()

        with mock.patch("components.imap_ops.imap_connection", fake_connection):
            export_account(Account("user@example.com", "secret"), ServerConfig("imap.example.com"), tmp_path, ignore_errors=False)

        assert not list(tmp_path.glob("*.eml"))
        assert (tmp_path / "user@example.com" / "_" / "u0000000001.eml").exists()

    def test_audit_reports_remote_sanitized_mailbox_collision(self, tmp_path: Path) -> None:
        from components.audit import audit_account
        from components.models import Account, ServerConfig

        account_dir = tmp_path / "user@example.com" / "A_B"
        account_dir.mkdir(parents=True)
        (account_dir / ".mailbox.json").write_text(json.dumps({"mailbox": "A_B", "message_count": 0}))
        (tmp_path / "user@example.com" / "export-state.json").write_text(json.dumps({
            "schema_version": 1,
            "account": "user@example.com",
            "complete": True,
            "mailboxes": [{"mailbox": "A_B", "path": "A_B", "message_count": 0}],
        }))

        class CollidingRemoteImap:
            selected = ""

            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "A/B"', b'(\\HasNoChildren) "/" "A_B"']

            def select(self, mailbox: str, readonly: bool = False):
                self.selected = mailbox.strip('"')
                return "OK", [b"0"]

            def uid(self, command: str, arg: str):
                assert command == "search"
                return "OK", [b"1 2 3" if self.selected == "A/B" else b""]

            def logout(self):
                return "OK", []

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[CollidingRemoteImap]:
            yield CollidingRemoteImap()

        with mock.patch("components.audit.imap_connection", fake_connection):
            _email, issues = audit_account(
                Account("user@example.com", "secret"),
                tmp_path,
                ServerConfig("imap.example.com"),
                check_remote=True,
            )

        assert any("remote mailbox name collision" in issue for issue in issues)

    def test_audit_rejects_remote_mailbox_alias_for_sanitized_path(self, tmp_path: Path) -> None:
        from components.audit import audit_export
        from components.models import Account, Config, ServerConfig

        server = ServerConfig("imap.example.com")
        folder = tmp_path / "user@example.com" / "A_B"
        _write_legacy_message_fixture(
            folder,
            mailbox="A/B",
            data=b"Message-ID: <alias@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody",
            source_server=server,
        )
        (folder / ".mailbox.json").write_text(json.dumps({"mailbox": "A/B", "message_count": 1}))

        class AliasedRemoteImap:
            selected = ""

            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "A|B"']

            def select(self, mailbox: str, readonly: bool = False):
                self.selected = mailbox.strip('"')
                return "OK", [b"1"]

            def uid(self, command: str, *args):
                assert command == "search"
                return "OK", [b"1"]

            def logout(self):
                return "OK", []

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[AliasedRemoteImap]:
            yield AliasedRemoteImap()

        with mock.patch("components.audit.imap_connection", fake_connection), \
            mock.patch("components.audit._remote_has_message") as remote_has_message:
            ok, issues = audit_export(
                tmp_path,
                Config(server, [Account("user@example.com", "secret")], source_server=server),
                1,
                check_remote=True,
                require_integrity_metadata=True,
            )

        assert not ok
        assert any(
            "remote mailbox name mismatch for sanitized path" in issue
            and "A/B" in issue
            and "A|B" in issue
            for issue in issues
        )
        remote_has_message.assert_not_called()

    def test_negative_panel_quotas_are_rejected(self, tmp_path: Path) -> None:
        from components.main import main

        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))

        with mock.patch("components.main.check_environment"):
            rc_da = main([
                "--mode", "import",
                "--config", str(config_path),
                "--log-dir", str(tmp_path / "logs-da"),
                "--min-free-gb", "0",
                "--auto-provision-da",
                "--da-quota-mb", "-1",
            ])
            rc_cpanel = main([
                "--mode", "import",
                "--config", str(config_path),
                "--log-dir", str(tmp_path / "logs-cpanel"),
                "--min-free-gb", "0",
                "--auto-provision-cpanel",
                "--cpanel-quota-mb", "-1",
            ])

        assert rc_da == 2
        assert rc_cpanel == 2

    def test_directadmin_indexer_fails_on_selected_domain_list_error(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import directadmin_indexer

        class FailingListClient:
            def __init__(self, *_args, **_kwargs) -> None:
                pass

            def list_domains(self) -> List[str]:
                return ["example.com"]

            def list_pop_accounts(self, domain: str) -> List[str]:
                raise RuntimeError("API timeout")

        out = tmp_path / "export.pass.config.json"
        monkeypatch.setattr(directadmin_indexer, "DirectAdminClient", FailingListClient)
        monkeypatch.setattr(directadmin_indexer, "prompt_select_from_list", lambda *_args, **_kwargs: [0])

        rc = directadmin_indexer.main([
            "--url", "https://panel.example.com:2222",
            "--username", "u",
            "--password", "p",
            "--imap-host", "mail.example.com",
            "--out", str(out),
        ])

        assert rc == 2
        assert not out.exists()

    def test_directadmin_list_pop_accounts_accepts_empty_success_shapes(self) -> None:
        from components.da_client import DirectAdminClient
        from directadmin_indexer import DirectAdminClient as IndexerDirectAdminClient

        for client_cls in (DirectAdminClient, IndexerDirectAdminClient):
            client = object.__new__(client_cls)
            client._get = lambda *_args, **_kwargs: ({"error": "0"}, None)
            assert client.list_pop_accounts("example.com") == []
            client._get = lambda *_args, **_kwargs: (None, {"error": ["0"]})
            assert client.list_pop_accounts("example.com") == []
            client._get = lambda *_args, **_kwargs: ([], None)
            assert client.list_pop_accounts("example.com") == []

    def test_directadmin_list_pop_accounts_rejects_malformed_empty_shapes(self) -> None:
        from components.da_client import DirectAdminClient
        from directadmin_indexer import DirectAdminClient as IndexerDirectAdminClient

        for client_cls in (DirectAdminClient, IndexerDirectAdminClient):
            client = object.__new__(client_cls)
            client._get = lambda *_args, **_kwargs: (None, {"<html>login</html>": [""]})
            with pytest.raises(RuntimeError, match="parse POP account list"):
                client.list_pop_accounts("example.com")

    def test_directadmin_indexer_list_domains_rejects_malformed_empty_shapes(self) -> None:
        from directadmin_indexer import DirectAdminClient as IndexerDirectAdminClient

        client = object.__new__(IndexerDirectAdminClient)
        client._get = lambda *_args, **_kwargs: (None, {"<html>login</html>": [""]})

        with pytest.raises(RuntimeError, match="parse domains"):
            client.list_domains()

    def test_cpanel_indexer_import_survives_missing_requests(self) -> None:
        code = r'''
import builtins
real_import = builtins.__import__
def blocked_import(name, *args, **kwargs):
    if name == "requests":
        raise ImportError("blocked")
    return real_import(name, *args, **kwargs)
builtins.__import__ = blocked_import
import cpanel_indexer
print("ok")
'''
        result = subprocess.run(
            [sys.executable, "-c", code],
            cwd=Path(__file__).resolve().parents[1],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

        assert result.returncode == 0
        assert result.stdout.strip() == "ok"

    def test_reexport_removes_stale_message_files(self, tmp_path: Path) -> None:
        from components.imap_ops import export_account
        from components.models import Account, ServerConfig

        class UidExportImap:
            response = _stable_uidvalidity_response

            def __init__(self, uids: List[int]) -> None:
                self.uids = uids

            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [str(len(self.uids)).encode("ascii")]

            def uid(self, command: str, *args):
                if command == "search":
                    return "OK", [" ".join(str(uid) for uid in self.uids).encode("ascii")]
                if command == "fetch":
                    uid = int(args[0])
                    return "OK", [(
                        f'{uid} (UID {uid} FLAGS () INTERNALDATE "01-Jan-2024 00:00:00 +0000")'.encode("ascii"),
                        f"Message-ID: <{uid}@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody".encode("ascii"),
                    )]
                raise AssertionError(command)

            def logout(self):
                return "OK", []

        @contextlib.contextmanager
        def fake_connection_factory(uids: List[int]) -> Iterator[UidExportImap]:
            yield UidExportImap(uids)

        account = Account("user@example.com", "secret")
        server = ServerConfig("imap.example.com")
        with mock.patch("components.imap_ops.imap_connection", lambda *_args: fake_connection_factory([1, 2])):
            export_account(account, server, tmp_path, ignore_errors=False)
        with mock.patch("components.imap_ops.imap_connection", lambda *_args: fake_connection_factory([1])):
            export_account(account, server, tmp_path, ignore_errors=False)

        inbox = tmp_path / "user@example.com" / "INBOX"
        assert sorted(path.name for path in inbox.glob("*.eml")) == ["u0000000001.eml"]
        assert sorted(path.name for path in inbox.glob("*.json") if path.name != ".mailbox.json") == ["u0000000001.json"]

    def test_reexport_removes_deleted_mailbox_directories(self, tmp_path: Path) -> None:
        from components.audit import audit_export
        from components.imap_ops import export_account
        from components.models import Account, Config, ServerConfig

        class MailboxExportImap:
            response = _stable_uidvalidity_response

            def __init__(self, mailboxes: List[str]) -> None:
                self.mailboxes = mailboxes
                self.selected = ""

            def list(self):
                return "OK", [
                    f'(\\HasNoChildren) "/" "{mailbox}"'.encode("ascii")
                    for mailbox in self.mailboxes
                ]

            def select(self, mailbox: str, readonly: bool = False):
                self.selected = mailbox.strip('"')
                return "OK", [b"1"]

            def uid(self, command: str, *args):
                if command == "search":
                    return "OK", [b"1"]
                if command == "fetch":
                    body = f"Message-ID: <{self.selected.lower()}@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody".encode("ascii")
                    return "OK", [(
                        b'1 (UID 1 FLAGS () INTERNALDATE "01-Jan-2024 00:00:00 +0000")',
                        body,
                    )]
                raise AssertionError(command)

            def logout(self):
                return "OK", []

        @contextlib.contextmanager
        def fake_connection_factory(mailboxes: List[str]) -> Iterator[MailboxExportImap]:
            yield MailboxExportImap(mailboxes)

        account = Account("user@example.com", "secret")
        server = ServerConfig("imap.example.com")
        with mock.patch("components.imap_ops.imap_connection", lambda *_args: fake_connection_factory(["INBOX", "Archive"])):
            export_account(account, server, tmp_path, ignore_errors=False)
        with mock.patch("components.imap_ops.imap_connection", lambda *_args: fake_connection_factory(["INBOX"])):
            export_account(account, server, tmp_path, ignore_errors=False)

        assert not (tmp_path / "user@example.com" / "Archive").exists()
        ok, issues = audit_export(
            tmp_path,
            Config(server=server, accounts=[account], source_server=server),
            1,
            check_remote=False,
            require_integrity_metadata=True,
        )
        assert ok
        assert issues == []

    def test_legacy_export_stale_file_cleanup_rejects_mailbox_dir_swap(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from components import imap_ops

        folder_dir = tmp_path / "user@example.com" / "INBOX"
        folder_dir.mkdir(parents=True)
        stale = folder_dir / "u0000000002.eml"
        stale.write_text("stale\n")
        outside = tmp_path / "outside-inbox"
        outside.mkdir()
        outside_stale = outside / stale.name
        outside_stale.write_text("do not delete\n")
        checked_folder = tmp_path / "checked-inbox"
        real_listdir = imap_ops.os.listdir
        swapped = False

        def racing_listdir(fd):
            nonlocal swapped
            names = real_listdir(fd)
            if not swapped:
                folder_dir.rename(checked_folder)
                try:
                    folder_dir.symlink_to(outside, target_is_directory=True)
                except (OSError, NotImplementedError) as exc:
                    pytest.skip(f"symlink creation unavailable: {exc}")
                swapped = True
            return names

        monkeypatch.setattr(imap_ops.os, "listdir", racing_listdir)

        with pytest.raises(RuntimeError, match="replaced legacy mailbox directory"):
            imap_ops._remove_stale_export_files(folder_dir, set())

        assert swapped
        assert folder_dir.is_symlink()
        assert outside_stale.exists()
        assert (checked_folder / stale.name).exists()

    def test_legacy_export_stale_mailbox_cleanup_rejects_account_dir_swap(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from components import imap_ops

        account_dir = tmp_path / "user@example.com"
        stale_dir = account_dir / "Archive"
        stale_dir.mkdir(parents=True)
        (stale_dir / "u0000000001.eml").write_text("stale\n")
        outside = tmp_path / "outside-account"
        outside_stale_dir = outside / "Archive"
        outside_stale_dir.mkdir(parents=True)
        outside_file = outside_stale_dir / "u0000000001.eml"
        outside_file.write_text("do not delete\n")
        checked_account = tmp_path / "checked-account"
        real_listdir = imap_ops.os.listdir
        swapped = False

        def racing_listdir(fd):
            nonlocal swapped
            names = real_listdir(fd)
            if not swapped:
                account_dir.rename(checked_account)
                try:
                    account_dir.symlink_to(outside, target_is_directory=True)
                except (OSError, NotImplementedError) as exc:
                    pytest.skip(f"symlink creation unavailable: {exc}")
                swapped = True
            return names

        monkeypatch.setattr(imap_ops.os, "listdir", racing_listdir)

        with pytest.raises(RuntimeError, match="replaced legacy account directory"):
            imap_ops._remove_stale_mailbox_dirs(account_dir, set())

        assert swapped
        assert account_dir.is_symlink()
        assert outside_file.exists()
        assert (checked_account / "Archive" / "u0000000001.eml").exists()

    def test_legacy_export_rejects_existing_provider_layout_before_connect(self, tmp_path: Path) -> None:
        from components.imap_ops import export_account
        from components.models import Account, ServerConfig

        account_dir = tmp_path / "user@example.com"
        (account_dir / "messages").mkdir(parents=True)
        (account_dir / "metadata").mkdir()
        (account_dir / "manifest.jsonl").write_text("{}\n")
        provider_state = '{"provider": true}\n'
        (account_dir / "export-state.json").write_text(provider_state)

        with mock.patch("components.imap_ops.imap_connection", side_effect=AssertionError("source should not be contacted")):
            with pytest.raises(RuntimeError, match="provider manifest present in legacy output directory"):
                export_account(
                    Account("user@example.com", "secret"),
                    ServerConfig("imap.example.com"),
                    tmp_path,
                    ignore_errors=False,
                )

        assert (account_dir / "export-state.json").read_text() == provider_state
        assert not (account_dir / "INBOX").exists()

    def test_plain_imapsync_probe_disables_ssl_and_tls(self) -> None:
        from components.imapsync_cli import run_imapsync_justconnect

        seen = {}

        def fake_run(args, **_kwargs):
            seen["args"] = args

            class Result:
                returncode = 0
                stdout = "ok"

            return Result()

        with mock.patch("components.imapsync_cli.ensure_imapsync_available"), \
            mock.patch("components.imapsync_cli.subprocess.run", fake_run):
            ok, _out = run_imapsync_justconnect("imap.example.com", 143, False, False, "user", "secret")

        assert ok
        assert "--nossl1" in seen["args"]
        assert "--notls1" in seen["args"]

    def test_legacy_remote_message_search_quotes_special_message_id(self) -> None:
        from components.imap_ops import _legacy_remote_has_message

        message = b"Message-ID: <x@[127.0.0.1]>\r\nFrom: a\r\nTo: b\r\n\r\nbody"

        class SpecialMessageIdImap:
            criteria = None

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"1"]

            def search(self, charset, *criteria):
                self.criteria = criteria
                if criteria == ("HEADER", "Message-ID", '"<x@[127.0.0.1]>"'):
                    return "OK", [b"1"]
                return "BAD", [b"bad search"]

            def fetch(self, num: bytes, query: str):
                return "OK", [(b"1 (RFC822.SIZE 49 FLAGS (\\Seen) INTERNALDATE \"01-Jan-2024 00:00:00 +0000\" BODY[] {49}", message)]

        fake = SpecialMessageIdImap()

        assert _legacy_remote_has_message(fake, "INBOX", message, set())
        assert fake.criteria == ("HEADER", "Message-ID", '"<x@[127.0.0.1]>"')

    def test_imap_search_value_rejects_control_characters(self) -> None:
        from components.utils import quote_imap_search_value

        with pytest.raises(ValueError, match="control characters"):
            quote_imap_search_value("<x\r\nNOOP@example.com>")

    def test_legacy_remote_message_search_rejects_decoded_crlf_message_id(self) -> None:
        from components.imap_ops import _legacy_remote_has_message

        message = b"Message-ID: =?utf-8?q?<x=0D=0ANOOP@example.com>?=\r\nFrom: a\r\nTo: b\r\n\r\nbody"

        class NoSearchImap:
            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"1"]

            def search(self, charset, *criteria):
                raise AssertionError("unsafe Message-ID should not reach IMAP search")

        with pytest.raises(ValueError, match="control characters"):
            _legacy_remote_has_message(NoSearchImap(), "INBOX", message, set())

    def test_validate_remote_identity_matches_imaplib_append_wire_bytes(self) -> None:
        import imaplib

        from components.main import _legacy_remote_has_message

        message = b"Message-ID: <wire@example.com>\nFrom: a\nTo: b\n\nbody\n"
        stored = imaplib.MapCRLF.sub(imaplib.CRLF, message)

        class NormalizedRemote:
            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"1"]

            def search(self, charset, *criteria):
                return "OK", [b"1"]

            def fetch(self, num: bytes, query: str):
                return "OK", [(b"1 (RFC822.SIZE %d FLAGS (\\Seen) INTERNALDATE \"01-Jan-2024 00:00:00 +0000\" BODY[] {%d}" % (len(stored), len(stored)), stored)]

        assert _legacy_remote_has_message(NormalizedRemote(), "INBOX", message, set())


class TestRound2ConfirmedBugs:
    def _legacy_zero_message_import_fixture(self, tmp_path: Path) -> tuple[Path, Path]:
        from components.imap_ops import legacy_server_endpoint, legacy_server_endpoint_digest
        from components.models import ServerConfig

        server = ServerConfig("source.example.com")
        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "target.example.com", "port": 993, "ssl": True, "starttls": False},
            "source_server": {"host": server.host, "port": server.port, "ssl": server.ssl, "starttls": server.starttls},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))
        in_root = tmp_path / "exported"
        inbox = in_root / "a@example.com" / "INBOX"
        inbox.mkdir(parents=True)
        (inbox / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": 0}))
        (in_root / "a@example.com" / "export-state.json").write_text(json.dumps({
            "schema_version": 1,
            "account": "a@example.com",
            "source_server": legacy_server_endpoint(server),
            "source_server_sha256": legacy_server_endpoint_digest(server),
            "complete": True,
            "mailboxes": [{"mailbox": "INBOX", "path": "INBOX", "message_count": 0}],
        }))
        return config_path, in_root

    @pytest.mark.parametrize(
        "backend_args",
        [
            [
                "--auto-provision-da",
                "--da-url", "https://panel.example.com:2222",
                "--da-username", "admin",
            ],
            [
                "--auto-provision-cpanel",
                "--cpanel-url", "https://panel.example.com:2083",
                "--cpanel-username", "cpuser",
            ],
        ],
    )
    def test_panel_auth_setup_failure_returns_config_error_with_ignore_errors(
        self,
        tmp_path: Path,
        backend_args: List[str],
    ) -> None:
        from components.main import main

        config_path, in_root = self._legacy_zero_message_import_fixture(tmp_path)

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.main.audit_export", return_value=(True, [])) as audit_mock, \
            mock.patch("components.main.import_account") as import_mock:
            rc = main([
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(in_root),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--no-connectivity-test",
                "--ignore-errors",
                *backend_args,
            ])

        assert rc == 2
        audit_mock.assert_not_called()
        import_mock.assert_not_called()

    @pytest.mark.parametrize(
        ("backend_args", "dependency_patch"),
        [
            (
                [
                    "--auto-provision-da",
                    "--da-url", "https://panel.example.com:2222",
                    "--da-username", "admin",
                    "--da-password", "login-key",
                ],
                "components.da_client.requests",
            ),
            (
                [
                    "--auto-provision-cpanel",
                    "--cpanel-url", "https://panel.example.com:2083",
                    "--cpanel-username", "cpuser",
                    "--cpanel-token", "api-token",
                ],
                "components.cpanel_client.requests",
            ),
        ],
    )
    def test_panel_missing_requests_returns_config_error_before_staged_audit(
        self,
        tmp_path: Path,
        backend_args: List[str],
        dependency_patch: str,
    ) -> None:
        from components.main import main

        config_path, in_root = self._legacy_zero_message_import_fixture(tmp_path)

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.main.audit_export", side_effect=AssertionError("staged audit should not run")) as audit_mock, \
            mock.patch(dependency_patch, None):
            rc = main([
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(in_root),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--no-connectivity-test",
                *backend_args,
            ])

        assert rc == 2
        audit_mock.assert_not_called()

    @pytest.mark.parametrize(
        "backend_args",
        [
            [
                "--auto-provision-da",
                "--da-username", "admin",
                "--da-password", "login-key",
            ],
            [
                "--auto-provision-cpanel",
                "--cpanel-url", "https://panel.example.com:2083",
                "--cpanel-token", "api-token",
            ],
        ],
    )
    def test_panel_missing_endpoint_fields_return_config_error_before_staged_audit(
        self,
        tmp_path: Path,
        backend_args: List[str],
    ) -> None:
        from components.main import main

        config_path, in_root = self._legacy_zero_message_import_fixture(tmp_path)

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.main.audit_export", side_effect=AssertionError("staged audit should not run")) as audit_mock:
            rc = main([
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(in_root),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--no-connectivity-test",
                *backend_args,
            ])

        assert rc == 2
        audit_mock.assert_not_called()

    def test_audit_reports_remote_mailbox_count_failures(self, tmp_path: Path) -> None:
        from components.audit import audit_export
        from components.imap_ops import legacy_server_endpoint, legacy_server_endpoint_digest
        from components.models import Account, Config, ServerConfig

        server = ServerConfig("imap.example.com")
        inbox = tmp_path / "user@example.com" / "INBOX"
        inbox.mkdir(parents=True)
        (inbox / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": 0}))
        (tmp_path / "user@example.com" / "export-state.json").write_text(json.dumps({
            "schema_version": 1,
            "account": "user@example.com",
            "source_server": legacy_server_endpoint(server),
            "source_server_sha256": legacy_server_endpoint_digest(server),
            "complete": True,
            "mailboxes": [{"mailbox": "INBOX", "path": "INBOX", "message_count": 0}],
        }))

        class UnselectableRemote:
            selected = ""

            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "INBOX"', b'(\\HasNoChildren) "/" "RemoteOnly"']

            def select(self, mailbox: str, readonly: bool = False):
                self.selected = mailbox.strip('"')
                if self.selected == "RemoteOnly":
                    return "NO", [b"cannot select"]
                return "OK", [b"0"]

            def uid(self, command: str, arg: str):
                return "OK", [b""]

            def logout(self):
                return "OK", []

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[UnselectableRemote]:
            yield UnselectableRemote()

        with mock.patch("components.audit.imap_connection", fake_connection):
            ok, issues = audit_export(
                tmp_path,
                Config(server, [Account("user@example.com", "secret")]),
                1,
                check_remote=True,
            )

        assert not ok
        assert any("remote mailbox could not be selected" in issue for issue in issues)

    def test_validate_reports_remote_only_uncountable_mailboxes(self, tmp_path: Path) -> None:
        from components.main import main

        config_path, in_root = self._legacy_zero_message_import_fixture(tmp_path)

        class UncountableRemote:
            selected = ""

            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "INBOX"', b'(\\HasNoChildren) "/" "RemoteOnly"']

            def select(self, mailbox: str, readonly: bool = False):
                self.selected = mailbox.strip('"')
                if self.selected == "RemoteOnly":
                    return "NO", [b"cannot select"]
                return "OK", [b"0"]

            def search(self, charset, *criteria):
                return "OK", [b""]

            def logout(self):
                return "OK", []

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[UncountableRemote]:
            yield UncountableRemote()

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.imap_ops.imap_connection", fake_connection):
            rc = main([
                "--mode", "validate",
                "--config", str(config_path),
                "--input-dir", str(in_root),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--no-connectivity-test",
            ])

        assert rc == 4

    def test_directadmin_indexer_accepts_empty_domain_success_shapes(self) -> None:
        from directadmin_indexer import DirectAdminClient

        for payload in ((None, {}), (None, {"error": ["0"]}), ({"error": "0"}, None), ([], None)):
            client = object.__new__(DirectAdminClient)
            client._get = lambda *_args, _payload=payload, **_kwargs: _payload
            assert client.list_domains() == []

    def test_verify_export_counts_duplicate_headers_case_insensitively(self, tmp_path: Path) -> None:
        from verify_export import analyze_message

        eml_path = tmp_path / "mixed.eml"
        eml_path.write_bytes(
            b"message-id: <one@example.com>\r\n"
            b"Message-Id: <two@example.com>\r\n"
            b"From: a@example.com\r\n"
            b"\r\n"
            b"body"
        )

        analysis, error = analyze_message(eml_path, tmp_path / "mixed.json", require_metadata=False)

        assert error is None
        assert analysis is not None
        assert analysis["message_id_count"] == 2
        assert analysis["multiple_messages_detected"] is True

    def test_verify_export_fails_empty_account_directory(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from verify_export import main, verify_account

        account_dir = tmp_path / "exported" / "user@example.com"
        account_dir.mkdir(parents=True)
        _write_verify_export_state(account_dir, [])

        stats = verify_account(account_dir)
        monkeypatch.chdir(tmp_path)

        assert stats["errors"] == 1
        assert main() == 1

    def test_verify_export_counts_empty_legacy_mailbox_folder(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from verify_export import verify_account

        account_dir = tmp_path / "exported" / "user@example.com"
        inbox = account_dir / "INBOX"
        inbox.mkdir(parents=True)
        (inbox / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": 0}))
        _write_verify_export_state(account_dir, [{"mailbox": "INBOX", "path": "INBOX", "message_count": 0}])

        stats = verify_account(account_dir)
        output = capsys.readouterr().out

        assert stats["errors"] == 0
        assert stats["total_messages"] == 0
        assert stats["folders"] == 1
        assert "INBOX: 0 messages" in output

    def test_verify_export_accepts_provider_layout(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from components.content_binding import CONTENT_BINDING_FIELD, provider_content_binding_sha256
        from components.provider_ops import provider_manifest_digest
        from verify_export import main, verify_account

        account_dir = tmp_path / "exported" / "source@example.com"
        (account_dir / "messages").mkdir(parents=True)
        (account_dir / "metadata").mkdir()
        body = b"Message-ID: <provider@example.com>\r\nFrom: a@example.com\r\nTo: b@example.com\r\n\r\nbody"
        eml_rel = "messages/provider-1.eml"
        meta_rel = "metadata/provider-1.json"
        (account_dir / eml_rel).write_bytes(body)
        row = {
            "canonical_id": "provider-1",
            "source_provider": "imap",
            "source_account": "source@example.com",
            "target_account": "target@example.com",
            "primary_mailbox": "Archive",
            "message_id_header": "<provider@example.com>",
            "content_sha256": hashlib.sha256(body).hexdigest(),
            "rfc822_size": len(body),
            "flags": "\\Seen",
            "internaldate": "01-Jan-2024 00:00:00 +0000",
            "eml_path": eml_rel,
            "metadata_path": meta_rel,
        }
        row[CONTENT_BINDING_FIELD] = provider_content_binding_sha256(row)
        (account_dir / meta_rel).write_text(json.dumps(row))
        (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")
        (account_dir / "export-state.json").write_text(json.dumps({
            "source_provider": "imap",
            "source_account": "source@example.com",
            "target_account": "target@example.com",
            "target_provider": "imap",
            "complete": True,
            "canonical_messages": 1,
            "manifest_sha256": provider_manifest_digest([row]),
        }))

        stats = verify_account(account_dir)
        monkeypatch.chdir(tmp_path)

        assert stats["errors"] == 0
        assert stats["total_messages"] == 1
        assert main() == 0

    def test_verify_export_rejects_mixed_provider_and_legacy_layout(self, tmp_path: Path) -> None:
        from verify_export import verify_account

        account_dir = tmp_path / "exported" / "source@example.com"
        _write_verify_provider_account_fixture(account_dir)
        legacy_folder = account_dir / "INBOX"
        legacy_folder.mkdir()
        (legacy_folder / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": 1}))
        (legacy_folder / "u0000000001.eml").write_bytes(
            b"Message-ID: <legacy@example.com>\r\nFrom: a@example.com\r\nTo: b@example.com\r\n\r\nlegacy"
        )

        stats = verify_account(account_dir)

        assert stats["errors"] == 1

    def test_verify_export_rejects_duplicate_provider_manifest_identity(self, tmp_path: Path) -> None:
        from components.provider_ops import provider_manifest_digest
        from verify_export import verify_account

        account_dir = tmp_path / "exported" / "source@example.com"
        row = _write_verify_provider_account_fixture(account_dir)
        rows = [row, dict(row)]
        (account_dir / "manifest.jsonl").write_text("".join(json.dumps(item) + "\n" for item in rows))
        state = json.loads((account_dir / "export-state.json").read_text(encoding="utf-8"))
        state["canonical_messages"] = 2
        state["manifest_sha256"] = provider_manifest_digest(rows)
        (account_dir / "export-state.json").write_text(json.dumps(state))

        stats = verify_account(account_dir)

        assert stats["errors"] == 1

    def test_verify_export_rejects_provider_account_directory_mismatch(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from components.content_binding import CONTENT_BINDING_FIELD, provider_content_binding_sha256
        from components.provider_ops import provider_manifest_digest
        from verify_export import verify_account

        account_dir = tmp_path / "exported" / "wrong@example.com"
        (account_dir / "messages").mkdir(parents=True)
        (account_dir / "metadata").mkdir()
        body = b"Message-ID: <provider-wrong-dir@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody"
        row = {
            "canonical_id": "provider-wrong-dir",
            "source_provider": "imap",
            "source_account": "source@example.com",
            "target_account": "target@example.com",
            "primary_mailbox": "Archive",
            "message_id_header": "<provider-wrong-dir@example.com>",
            "content_sha256": hashlib.sha256(body).hexdigest(),
            "rfc822_size": len(body),
            "flags": "\\Seen",
            "internaldate": "01-Jan-2024 00:00:00 +0000",
            "eml_path": "messages/provider-wrong-dir.eml",
            "metadata_path": "metadata/provider-wrong-dir.json",
        }
        row[CONTENT_BINDING_FIELD] = provider_content_binding_sha256(row)
        (account_dir / row["eml_path"]).write_bytes(body)
        (account_dir / row["metadata_path"]).write_text(json.dumps(row))
        (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")
        (account_dir / "export-state.json").write_text(json.dumps({
            "source_provider": "imap",
            "source_account": "source@example.com",
            "target_account": "target@example.com",
            "target_provider": "imap",
            "complete": True,
            "canonical_messages": 1,
            "manifest_sha256": provider_manifest_digest([row]),
        }))

        stats = verify_account(account_dir)
        output = capsys.readouterr().out

        assert stats["errors"] >= 1
        assert "provider-wrong-dir: source_account source@example.com does not match provider account directory wrong@example.com" in output

    def test_verify_export_rejects_empty_provider_state_account_directory_mismatch(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from verify_export import verify_account

        account_dir = tmp_path / "exported" / "source@example.com"
        account_dir.mkdir(parents=True)
        (account_dir / "manifest.jsonl").write_text("")
        (account_dir / "export-state.json").write_text(json.dumps({
            "source_provider": "imap",
            "source_account": "other@example.com",
            "complete": True,
            "canonical_messages": 0,
            "manifest_sha256": hashlib.sha256(b"").hexdigest(),
        }))

        stats = verify_account(account_dir)
        output = capsys.readouterr().out

        assert stats["errors"] >= 1
        assert "export-state source_account other@example.com does not match provider account directory source@example.com" in output

    def test_verify_export_rejects_empty_provider_state_missing_account_binding(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from components.provider_ops import provider_manifest_digest
        from verify_export import verify_account

        account_dir = tmp_path / "exported" / "source@example.com"
        account_dir.mkdir(parents=True)
        (account_dir / "manifest.jsonl").write_text("")
        (account_dir / "export-state.json").write_text(json.dumps({
            "source_provider": "imap",
            "complete": True,
            "canonical_messages": 0,
            "manifest_sha256": provider_manifest_digest([]),
        }))

        stats = verify_account(account_dir)
        output = capsys.readouterr().out

        assert stats["errors"] >= 1
        assert "export-state source_account <missing> does not match provider account directory source@example.com" in output

    def test_verify_export_rejects_empty_provider_state_missing_provider_bindings(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from components.provider_ops import provider_manifest_digest
        from verify_export import verify_account

        account_dir = tmp_path / "exported" / "source@example.com"
        account_dir.mkdir(parents=True)
        (account_dir / "manifest.jsonl").write_text("")
        (account_dir / "export-state.json").write_text(json.dumps({
            "source_account": "source@example.com",
            "complete": True,
            "canonical_messages": 0,
            "manifest_sha256": provider_manifest_digest([]),
        }))

        stats = verify_account(account_dir)
        output = capsys.readouterr().out

        assert stats["errors"] >= 3
        assert "export-state source_provider is missing or invalid" in output
        assert "export-state target_account is missing or invalid" in output
        assert "export-state target_provider is missing or invalid" in output

    @pytest.mark.parametrize(
        ("root_name", "needle"),
        [
            ("messages", "symlinked provider message artifact directory: messages"),
            ("metadata", "symlinked provider metadata artifact directory: metadata"),
        ],
    )
    def test_verify_export_rejects_empty_provider_symlinked_artifact_root(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        root_name: str,
        needle: str,
    ) -> None:
        from components.provider_ops import provider_manifest_digest
        from verify_export import verify_account

        account_dir = tmp_path / "exported" / "source@example.com"
        account_dir.mkdir(parents=True)
        (account_dir / "manifest.jsonl").write_text("")
        (account_dir / "export-state.json").write_text(json.dumps({
            "source_provider": "imap",
            "source_account": "source@example.com",
            "target_account": "target@example.com",
            "target_provider": "imap",
            "complete": True,
            "canonical_messages": 0,
            "manifest_sha256": provider_manifest_digest([]),
        }))
        outside = tmp_path / f"outside-{root_name}"
        outside.mkdir()
        try:
            (account_dir / root_name).symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")

        stats = verify_account(account_dir)
        output = capsys.readouterr().out

        assert stats["errors"] >= 1
        assert needle in output

    @pytest.mark.parametrize(
        ("row_updates", "state_updates", "expected"),
        [
            (
                {},
                {"target_account": "wrong-target@example.com"},
                "export-state target_account wrong-target@example.com does not match manifest target_account target@example.com",
            ),
            (
                {},
                {"source_provider": "icloud"},
                "export-state source_provider icloud does not match manifest source_provider imap",
            ),
            (
                {"target_provider": "icloud"},
                {"target_provider": "gmail"},
                "export-state target_provider gmail does not match manifest target_provider icloud",
            ),
            (
                {},
                {"target_provider": "unknown"},
                "export-state target_provider is invalid: unknown",
            ),
        ],
    )
    def test_verify_export_rejects_provider_state_manifest_binding_mismatch(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        row_updates: dict,
        state_updates: dict,
        expected: str,
    ) -> None:
        from components.content_binding import CONTENT_BINDING_FIELD, provider_content_binding_sha256
        from components.provider_ops import provider_manifest_digest
        from verify_export import verify_account

        account_dir = tmp_path / "exported" / "source@example.com"
        (account_dir / "messages").mkdir(parents=True)
        (account_dir / "metadata").mkdir()
        body = b"Message-ID: <provider-state-binding@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody"
        row = {
            "canonical_id": "provider-state-binding",
            "source_provider": "imap",
            "source_account": "source@example.com",
            "target_account": "target@example.com",
            "primary_mailbox": "Archive",
            "message_id_header": "<provider-state-binding@example.com>",
            "content_sha256": hashlib.sha256(body).hexdigest(),
            "rfc822_size": len(body),
            "flags": "\\Seen",
            "internaldate": "01-Jan-2024 00:00:00 +0000",
            "eml_path": "messages/provider-state-binding.eml",
            "metadata_path": "metadata/provider-state-binding.json",
        }
        row.update(row_updates)
        row[CONTENT_BINDING_FIELD] = provider_content_binding_sha256(row)
        (account_dir / row["eml_path"]).write_bytes(body)
        (account_dir / row["metadata_path"]).write_text(json.dumps(row))
        (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")
        state = {
            "source_provider": "imap",
            "source_account": "source@example.com",
            "target_account": "target@example.com",
            "target_provider": "imap",
            "complete": True,
            "canonical_messages": 1,
            "manifest_sha256": provider_manifest_digest([row]),
        }
        state.update(state_updates)
        (account_dir / "export-state.json").write_text(json.dumps(state))

        stats = verify_account(account_dir)
        output = capsys.readouterr().out

        assert stats["errors"] >= 1
        assert expected in output

    def test_verify_export_accepts_sanitized_provider_account_directory(self, tmp_path: Path) -> None:
        from components.content_binding import CONTENT_BINDING_FIELD, provider_content_binding_sha256
        from components.provider_ops import provider_manifest_digest
        from verify_export import verify_account

        account_dir = tmp_path / "exported" / "a_b@example.com"
        (account_dir / "messages").mkdir(parents=True)
        (account_dir / "metadata").mkdir()
        body = b"Message-ID: <provider-sanitized@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody"
        row = {
            "canonical_id": "provider-sanitized",
            "source_provider": "imap",
            "source_account": "a/b@example.com",
            "target_account": "target@example.com",
            "primary_mailbox": "Archive",
            "message_id_header": "<provider-sanitized@example.com>",
            "content_sha256": hashlib.sha256(body).hexdigest(),
            "rfc822_size": len(body),
            "flags": "\\Seen",
            "internaldate": "01-Jan-2024 00:00:00 +0000",
            "eml_path": "messages/provider-sanitized.eml",
            "metadata_path": "metadata/provider-sanitized.json",
        }
        row[CONTENT_BINDING_FIELD] = provider_content_binding_sha256(row)
        (account_dir / row["eml_path"]).write_bytes(body)
        (account_dir / row["metadata_path"]).write_text(json.dumps(row))
        (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")
        (account_dir / "export-state.json").write_text(json.dumps({
            "source_provider": "imap",
            "source_account": "a/b@example.com",
            "target_account": "target@example.com",
            "target_provider": "imap",
            "complete": True,
            "canonical_messages": 1,
            "manifest_sha256": provider_manifest_digest([row]),
        }))

        stats = verify_account(account_dir)

        assert stats["errors"] == 0

    def test_verify_export_accepts_provider_zero_byte_message(self, tmp_path: Path) -> None:
        from components.content_binding import CONTENT_BINDING_FIELD, provider_content_binding_sha256
        from components.provider_ops import provider_manifest_digest
        from verify_export import verify_account

        account_dir = tmp_path / "exported" / "source@example.com"
        (account_dir / "messages").mkdir(parents=True)
        (account_dir / "metadata").mkdir()
        body = b""
        eml_rel = "messages/provider-empty.eml"
        meta_rel = "metadata/provider-empty.json"
        (account_dir / eml_rel).write_bytes(body)
        row = {
            "canonical_id": "provider-empty",
            "source_provider": "imap",
            "source_account": "source@example.com",
            "target_account": "target@example.com",
            "primary_mailbox": "Archive",
            "content_sha256": hashlib.sha256(body).hexdigest(),
            "rfc822_size": 0,
            "flags": "",
            "internaldate": "",
            "eml_path": eml_rel,
            "metadata_path": meta_rel,
        }
        row[CONTENT_BINDING_FIELD] = provider_content_binding_sha256(row)
        (account_dir / meta_rel).write_text(json.dumps(row))
        (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")
        (account_dir / "export-state.json").write_text(json.dumps({
            "source_provider": "imap",
            "source_account": "source@example.com",
            "target_account": "target@example.com",
            "target_provider": "imap",
            "complete": True,
            "canonical_messages": 1,
            "manifest_sha256": provider_manifest_digest([row]),
        }))

        stats = verify_account(account_dir)

        assert stats["errors"] == 0
        assert stats["total_messages"] == 1

    def test_verify_export_rejects_invalid_provider_delivery_metadata(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from components.content_binding import CONTENT_BINDING_FIELD, provider_content_binding_sha256
        from components.provider_ops import provider_manifest_digest
        from verify_export import verify_account

        account_dir = tmp_path / "exported" / "source@example.com"
        (account_dir / "messages").mkdir(parents=True)
        (account_dir / "metadata").mkdir()
        body = b"Message-ID: <provider@example.com>\r\nFrom: a@example.com\r\nTo: b@example.com\r\n\r\nbody"
        eml_rel = "messages/provider-1.eml"
        meta_rel = "metadata/provider-1.json"
        (account_dir / eml_rel).write_bytes(body)
        row = {
            "canonical_id": "provider-1",
            "source_provider": "imap",
            "source_account": "source@example.com",
            "target_account": "target@example.com",
            "primary_mailbox": "Archive",
            "message_id_header": "<provider@example.com>",
            "content_sha256": hashlib.sha256(body).hexdigest(),
            "rfc822_size": len(body),
            "flags": "BAD ))",
            "internaldate": "not a date",
            "eml_path": eml_rel,
            "metadata_path": meta_rel,
        }
        row[CONTENT_BINDING_FIELD] = provider_content_binding_sha256(row)
        (account_dir / meta_rel).write_text(json.dumps(row))
        (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")
        (account_dir / "export-state.json").write_text(json.dumps({
            "source_provider": "imap",
            "source_account": "source@example.com",
            "target_account": "target@example.com",
            "target_provider": "imap",
            "complete": True,
            "canonical_messages": 1,
            "manifest_sha256": provider_manifest_digest([row]),
        }))

        stats = verify_account(account_dir)
        output = capsys.readouterr().out

        assert stats["errors"] >= 2
        assert "provider-1: invalid flags metadata" in output
        assert "provider-1: invalid internaldate metadata" in output

    def test_verify_export_rejects_invalid_provider_manifest_schema(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from components.content_binding import CONTENT_BINDING_FIELD, provider_content_binding_sha256
        from components.provider_ops import provider_manifest_digest
        from verify_export import verify_account

        account_dir = tmp_path / "exported" / "source@example.com"
        (account_dir / "messages").mkdir(parents=True)
        (account_dir / "metadata").mkdir()
        body = b"Message-ID: <provider-schema@example.com>\r\nFrom: a@example.com\r\nTo: b@example.com\r\n\r\nbody"
        eml_rel = "messages/provider-schema.eml"
        meta_rel = "metadata/provider-schema.json"
        (account_dir / eml_rel).write_bytes(body)
        row = {
            "canonical_id": "provider-schema",
            "source_provider": "imap",
            "source_account": "source@example.com",
            "target_account": "target@example.com",
            "primary_mailbox": ["Archive"],
            "message_id_header": "<provider-schema@example.com>",
            "content_sha256": hashlib.sha256(body).hexdigest(),
            "rfc822_size": len(body),
            "flags": "\\Seen",
            "internaldate": "01-Jan-2024 00:00:00 +0000",
            "eml_path": eml_rel,
            "metadata_path": meta_rel,
        }
        row[CONTENT_BINDING_FIELD] = provider_content_binding_sha256(row)
        (account_dir / meta_rel).write_text(json.dumps(row))
        (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")
        (account_dir / "export-state.json").write_text(json.dumps({
            "source_provider": "imap",
            "source_account": "source@example.com",
            "target_account": "target@example.com",
            "target_provider": "imap",
            "complete": True,
            "canonical_messages": 1,
            "manifest_sha256": provider_manifest_digest([row]),
        }))

        stats = verify_account(account_dir)
        output = capsys.readouterr().out

        assert stats["errors"] >= 1
        assert "provider-schema: missing or invalid primary_mailbox" in output

    def test_verify_export_rejects_symlinked_legacy_message_and_sidecar(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from verify_export import verify_account

        account_dir = tmp_path / "exported" / "user@example.com"
        folder = account_dir / "INBOX"
        folder.mkdir(parents=True)
        data = b"Message-ID: <m@example.com>\r\nFrom: a@example.com\r\nTo: b@example.com\r\n\r\nbody"
        outside_eml = tmp_path / "outside.eml"
        outside_json = tmp_path / "outside.json"
        outside_eml.write_bytes(data)
        outside_json.write_text(json.dumps(_legacy_integrity_metadata(data, mailbox="INBOX", uid=1)))
        try:
            (folder / "u0000000001.eml").symlink_to(outside_eml)
            (folder / "u0000000001.json").symlink_to(outside_json)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")
        (folder / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": 1}))
        _write_verify_export_state(account_dir, [{"mailbox": "INBOX", "path": "INBOX", "message_count": 1}])

        stats = verify_account(account_dir)
        output = capsys.readouterr().out

        assert stats["errors"] >= 2
        assert "INBOX/u0000000001.eml: message file is a symlink" in output
        assert "INBOX/u0000000001.json: metadata sidecar is a symlink" in output

    def test_verify_export_main_rejects_symlinked_export_root(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from verify_export import main

        real_exported = tmp_path / "real-exported"
        account_dir = real_exported / "user@example.com"
        inbox = account_dir / "INBOX"
        inbox.mkdir(parents=True)
        (inbox / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": 0}))
        _write_verify_export_state(account_dir, [{"mailbox": "INBOX", "path": "INBOX", "message_count": 0}])
        try:
            (tmp_path / "exported").symlink_to(real_exported, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")
        monkeypatch.chdir(tmp_path)

        assert main() == 1
        assert "path contains a symlink" in capsys.readouterr().out

    def test_verify_account_rejects_symlinked_export_root_ancestor(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from verify_export import verify_account

        real_exported = tmp_path / "real-exported"
        _write_legacy_message_fixture(real_exported / "user@example.com" / "INBOX")
        linked_exported = tmp_path / "linked-exported"
        try:
            linked_exported.symlink_to(real_exported, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")

        stats = verify_account(linked_exported / "user@example.com")
        output = capsys.readouterr().out

        assert stats["errors"] == 1
        assert "account path contains a symlink" in output

    def test_verify_export_main_rejects_symlinked_cwd_ancestor(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from verify_export import main

        real_cwd = tmp_path / "real-cwd"
        _write_legacy_message_fixture(real_cwd / "exported" / "user@example.com" / "INBOX")
        linked_cwd = tmp_path / "linked-cwd"
        try:
            linked_cwd.symlink_to(real_cwd, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")
        monkeypatch.chdir(linked_cwd)
        monkeypatch.setenv("PWD", str(linked_cwd))

        assert main() == 1
        assert "path contains a symlink" in capsys.readouterr().out

    def test_verify_export_main_rejects_file_export_root(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from verify_export import main

        (tmp_path / "exported").write_text("not a directory\n")
        monkeypatch.chdir(tmp_path)

        assert main() == 1
        output = capsys.readouterr().out
        assert "not a directory" in output

    def test_verify_export_main_rejects_broken_account_symlink(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from verify_export import main

        account_dir = tmp_path / "exported" / "user@example.com"
        inbox = account_dir / "INBOX"
        inbox.mkdir(parents=True)
        (inbox / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": 0}))
        _write_verify_export_state(account_dir, [{"mailbox": "INBOX", "path": "INBOX", "message_count": 0}])
        try:
            (tmp_path / "exported" / "broken@example.com").symlink_to(tmp_path / "missing-account", target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")
        monkeypatch.chdir(tmp_path)

        assert main() == 1
        output = capsys.readouterr().out
        assert "broken@example.com" in output
        assert "account path is a symlink" in output

    def test_verify_export_rejects_symlinked_mailbox_marker(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from verify_export import verify_account

        account_dir = tmp_path / "exported" / "user@example.com"
        folder = account_dir / "Archive"
        folder.mkdir(parents=True)
        outside_marker = tmp_path / "outside-mailbox.json"
        outside_marker.write_text(json.dumps({"mailbox": "Archive", "message_count": 0}))
        try:
            (folder / ".mailbox.json").symlink_to(outside_marker)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")
        _write_verify_export_state(account_dir, [{"mailbox": "Archive", "path": "Archive", "message_count": 0}])

        stats = verify_account(account_dir)
        output = capsys.readouterr().out

        assert stats["errors"] >= 1
        assert "Archive: mailbox marker is a symlink" in output


class TestRound3ConfirmedBugs:
    def test_strict_audit_rejects_duplicate_export_state_paths(self, tmp_path: Path) -> None:
        from components.audit import audit_export
        from components.imap_ops import legacy_server_endpoint, legacy_server_endpoint_digest
        from components.models import Account, Config, ServerConfig

        server = ServerConfig("imap.example.com")
        data = b"Message-ID: <m@example.com>\r\nFrom: a@example.com\r\nTo: b@example.com\r\nSubject: x\r\n\r\nbody"
        folder = tmp_path / "user@example.com" / "Sent_Items"
        folder.mkdir(parents=True)
        (folder / "u0000000001.eml").write_bytes(data)
        (folder / "u0000000001.json").write_text(json.dumps(
            _legacy_integrity_metadata(data, mailbox="Sent Items", uid=1)
        ))
        (folder / ".mailbox.json").write_text(json.dumps({"mailbox": "Sent Items", "message_count": 1}))
        (tmp_path / "user@example.com" / "export-state.json").write_text(json.dumps({
            "schema_version": 1,
            "account": "user@example.com",
            "source_server": legacy_server_endpoint(server),
            "source_server_sha256": legacy_server_endpoint_digest(server),
            "complete": True,
            "mailboxes": [
                {"mailbox": "Sent Items", "path": "Sent_Items", "message_count": 1},
                {"mailbox": "Sent/Items", "path": "Sent_Items", "message_count": 1},
            ],
        }))

        ok, issues = audit_export(
            tmp_path,
            Config(server, [Account("user@example.com", "secret")], source_server=server),
            1,
            check_remote=False,
            require_integrity_metadata=True,
        )

        assert not ok
        assert any("export-state mailbox path collision" in issue for issue in issues)

    def test_verify_export_rejects_casefold_export_state_path_collision(self, tmp_path: Path) -> None:
        from verify_export import analyze_export_state

        account_dir = tmp_path / "user@example.com"
        _write_verify_export_state(account_dir, [
            {"mailbox": "Folder", "path": "Folder", "message_count": 0},
            {"mailbox": "folder", "path": "folder", "message_count": 0},
        ])

        issues = analyze_export_state(account_dir, {"Folder": 0, "folder": 0})

        assert any("export-state mailbox path collision: Folder and folder" in issue for issue in issues)

    def test_strict_audit_rejects_content_binding_mismatch(self, tmp_path: Path) -> None:
        from components.audit import audit_account
        from components.models import Account

        folder = tmp_path / "user@example.com" / "INBOX"
        eml = _write_legacy_message_fixture(folder)
        meta_path = eml.with_suffix(".json")
        meta = json.loads(meta_path.read_text())
        meta["content_binding_sha256"] = "0" * 64
        meta_path.write_text(json.dumps(meta))

        _email, issues = audit_account(
            Account(email="user@example.com", password="secret"),
            tmp_path,
            server=None,
            check_remote=False,
            require_integrity_metadata=True,
        )

        assert any("content_binding_sha256 mismatch" in issue for issue in issues)

    def test_direct_import_rejects_sidecar_integrity_mismatch(self, tmp_path: Path) -> None:
        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        folder = tmp_path / "user@example.com" / "INBOX"
        folder.mkdir(parents=True)
        data = b"Message-ID: <m@example.com>\r\nFrom: a@example.com\r\nTo: b@example.com\r\n\r\ncorrupted"
        (folder / "u0000000001.eml").write_bytes(data)
        (folder / "u0000000001.json").write_text(json.dumps(
            _legacy_integrity_metadata(b"original", mailbox="INBOX", uid=1)
        ))
        (folder / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": 1}))
        _write_verify_export_state(folder.parent, [
            {"mailbox": "INBOX", "path": "INBOX", "message_count": 1},
        ])

        opened = False

        @contextlib.contextmanager
        def fake_factory(*_args, **_kwargs) -> Iterator[object]:
            nonlocal opened
            opened = True
            raise AssertionError("IMAP should not be opened")
            yield object()

        with pytest.raises(RuntimeError, match="rfc822_size mismatch|content_sha256 mismatch"):
            import_account(
                Account("user@example.com", "secret"),
                ServerConfig("imap.example.com"),
                tmp_path,
                ignore_errors=False,
                imap_factory=fake_factory,
            )

        assert opened is False

    def test_verify_export_fails_empty_root_and_unmarked_empty_mailbox(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from verify_export import main, verify_account

        (tmp_path / "exported").mkdir()
        monkeypatch.chdir(tmp_path)
        assert main() == 1

        account_dir = tmp_path / "exported" / "user@example.com"
        mailbox_dir = account_dir / "INBOX"
        mailbox_dir.mkdir(parents=True)
        _write_verify_export_state(account_dir, [{"mailbox": "INBOX", "path": "INBOX", "message_count": 0}])
        stats = verify_account(account_dir)

        assert stats["errors"] == 1
        assert main() == 1

    def test_invalid_only_indexer_selection_returns_no_selection(self) -> None:
        from directadmin_indexer import prompt_select_from_list

        for raw in ("999", "abc", "4-6"):
            with mock.patch("builtins.input", return_value=raw):
                assert prompt_select_from_list(["one", "two"], "Available") == []

        with mock.patch("builtins.input", return_value="2,abc"):
            assert prompt_select_from_list(["one", "two"], "Available") == [1]


class TestRound4ConfirmedBugs:
    def test_verify_export_rejects_missing_message_sidecar(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from verify_export import main, verify_account

        inbox = tmp_path / "exported" / "user@example.com" / "INBOX"
        inbox.mkdir(parents=True)
        (inbox / "u0000000001.eml").write_bytes(
            b"Message-ID: <m@example.com>\r\n"
            b"From: a@example.com\r\n"
            b"To: b@example.com\r\n"
            b"\r\n"
            b"body"
        )
        _write_verify_export_state(inbox.parent, [{"mailbox": "INBOX", "path": "INBOX", "message_count": 1}])
        monkeypatch.chdir(tmp_path)

        stats = verify_account(tmp_path / "exported" / "user@example.com")

        assert stats["errors"] == 1
        assert main() == 1

    def test_verify_export_rejects_zero_byte_message(self, tmp_path: Path) -> None:
        from verify_export import analyze_message

        eml_path = tmp_path / "empty.eml"
        eml_path.write_bytes(b"")

        analysis, error = analyze_message(eml_path, tmp_path / "empty.json", require_metadata=False)

        assert analysis is None
        assert error == "empty file"

    def test_verify_export_accepts_bound_legacy_zero_byte_message(self, tmp_path: Path) -> None:
        from verify_export import analyze_message

        eml_path = tmp_path / "empty.eml"
        json_path = tmp_path / "empty.json"
        eml_path.write_bytes(b"")
        json_path.write_text(json.dumps(_legacy_integrity_metadata(
            b"",
            mailbox="INBOX",
            uid=1,
            flags="",
            internaldate="",
        )))

        analysis, error = analyze_message(eml_path, json_path)

        assert error is None
        assert analysis is not None
        assert analysis["size_bytes"] == 0

    @pytest.mark.parametrize(
        ("marker_text", "needle"),
        [
            ("{", "failed to parse mailbox marker"),
            (json.dumps({"mailbox": "INBOX", "message_count": 1}), "mailbox marker count mismatch"),
        ],
    )
    def test_verify_export_rejects_invalid_empty_mailbox_marker(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        marker_text: str,
        needle: str,
    ) -> None:
        from verify_export import analyze_mailbox_marker, main, verify_account

        inbox = tmp_path / "exported" / "user@example.com" / "INBOX"
        inbox.mkdir(parents=True)
        marker_path = inbox / ".mailbox.json"
        marker_path.write_text(marker_text)
        _write_verify_export_state(inbox.parent, [{"mailbox": "INBOX", "path": "INBOX", "message_count": 0}])
        monkeypatch.chdir(tmp_path)

        marker_issues = analyze_mailbox_marker(marker_path, "INBOX", 0)
        stats = verify_account(tmp_path / "exported" / "user@example.com")

        assert any(needle in issue for issue in marker_issues)
        assert stats["errors"] == 1
        assert main() == 1

    def test_verify_export_allows_message_rfc822_attachment(self, tmp_path: Path) -> None:
        from verify_export import analyze_message

        eml_path = tmp_path / "with-attached-eml.eml"
        payload = (
            b"Message-ID: <outer@example.com>\r\n"
            b"From: outer@example.com\r\n"
            b"To: recipient@example.com\r\n"
            b"Subject: attached message\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: multipart/mixed; boundary=\"b\"\r\n"
            b"\r\n"
            b"--b\r\n"
            b"Content-Type: text/plain\r\n"
            b"\r\n"
            b"See attached.\r\n"
            b"--b\r\n"
            b"Content-Type: message/rfc822\r\n"
            b"Content-Disposition: attachment; filename=\"attached.eml\"\r\n"
            b"\r\n"
            b"Message-ID: <inner@example.com>\r\n"
            b"From: inner@example.com\r\n"
            b"To: recipient@example.com\r\n"
            b"Subject: inner\r\n"
            b"\r\n"
            b"inner body\r\n"
            b"--b--\r\n"
        )
        eml_path.write_bytes(payload)
        json_path = tmp_path / "with-attached-eml.json"
        json_path.write_text(json.dumps(_legacy_integrity_metadata(payload)))

        analysis, error = analyze_message(eml_path, json_path)

        assert error is None
        assert analysis is not None
        assert "message/rfc822" in analysis["content_types"]
        assert analysis["attachment_count"] == 1
        assert analysis["multiple_messages_detected"] is False

    def test_verify_export_rejects_orphan_message_sidecar(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from verify_export import main, verify_account

        inbox = tmp_path / "exported" / "user@example.com" / "INBOX"
        inbox.mkdir(parents=True)
        payload = b"Message-ID: <m@example.com>\r\nFrom: a@example.com\r\nTo: b@example.com\r\n\r\nbody"
        (inbox / "u0000000001.eml").write_bytes(payload)
        (inbox / "u0000000001.json").write_text(json.dumps(_legacy_integrity_metadata(payload, mailbox="INBOX")))
        (inbox / "u0000000002.json").write_text(json.dumps(_legacy_integrity_metadata(b"missing", mailbox="INBOX")))
        _write_verify_export_state(inbox.parent, [{"mailbox": "INBOX", "path": "INBOX", "message_count": 1}])
        monkeypatch.chdir(tmp_path)

        stats = verify_account(tmp_path / "exported" / "user@example.com")

        assert stats["errors"] == 1
        assert main() == 1

    def test_strict_audit_rejects_boolean_message_counts(self, tmp_path: Path) -> None:
        from components.audit import audit_export
        from components.models import Account, Config, ServerConfig

        server = ServerConfig("imap.example.com")
        account = Account("user@example.com", "secret")
        folder = tmp_path / "user@example.com" / "INBOX"
        _write_legacy_message_fixture(
            folder,
            mailbox="INBOX",
            data=b"Message-ID: <m@example.com>\r\nFrom: a@example.com\r\nTo: b@example.com\r\n\r\nbody",
            source_server=server,
        )
        (folder / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": True}))
        state_path = tmp_path / "user@example.com" / "export-state.json"
        state = json.loads(state_path.read_text())
        state["mailboxes"][0]["message_count"] = True
        state_path.write_text(json.dumps(state))

        ok, issues = audit_export(
            tmp_path,
            Config(server, [account], source_server=server),
            1,
            check_remote=False,
            require_integrity_metadata=True,
        )

        assert not ok
        assert any("export-state mailbox 'INBOX' has invalid message_count" in issue for issue in issues)
        assert any("mailbox marker has invalid message_count" in issue for issue in issues)


class TestRound6ConfirmedBugs:
    def test_indexer_starttls_generates_loadable_config(self, tmp_path: Path) -> None:
        from components.models import Config
        from cpanel_indexer import ServerSettings as CPanelServerSettings
        from cpanel_indexer import build_config as build_cpanel_config
        from cpanel_indexer import parse_args as parse_cpanel_args
        from directadmin_indexer import ServerSettings as DirectAdminServerSettings
        from directadmin_indexer import build_config as build_directadmin_config
        from directadmin_indexer import parse_args as parse_directadmin_args

        directadmin_args = parse_directadmin_args([
            "--url", "https://panel.example.com:2222",
            "--username", "admin",
            "--password", "secret",
            "--imap-host", "mail.example.com",
            "--imap-starttls",
        ])
        directadmin_server = DirectAdminServerSettings(
            host=directadmin_args.imap_host,
            port=directadmin_args.imap_port,
            ssl=bool(directadmin_args.imap_ssl) and not bool(directadmin_args.imap_starttls),
            starttls=bool(directadmin_args.imap_starttls),
        )
        directadmin_config_path = tmp_path / "directadmin.json"
        directadmin_config_path.write_text(json.dumps(build_directadmin_config(
            directadmin_server,
            ["user@example.com"],
            default_password="secret",
        )))

        cpanel_args = parse_cpanel_args([
            "--url", "https://panel.example.com:2083",
            "--username", "admin",
            "--password", "secret",
            "--imap-host", "mail.example.com",
            "--imap-starttls",
        ])
        cpanel_server = CPanelServerSettings(
            host=cpanel_args.imap_host,
            port=cpanel_args.imap_port,
            ssl=bool(cpanel_args.imap_ssl) and not bool(cpanel_args.imap_starttls),
            starttls=bool(cpanel_args.imap_starttls),
        )
        cpanel_config_path = tmp_path / "cpanel.json"
        cpanel_config_path.write_text(json.dumps(build_cpanel_config(
            cpanel_server,
            ["user@example.com"],
            default_password="secret",
        )))

        directadmin_config = Config.from_json_file(directadmin_config_path)
        cpanel_config = Config.from_json_file(cpanel_config_path)

        assert directadmin_config.server.ssl is False
        assert directadmin_config.server.starttls is True
        assert cpanel_config.server.ssl is False
        assert cpanel_config.server.starttls is True

    def test_remote_audit_rejects_missing_empty_mailbox(self, tmp_path: Path) -> None:
        from components.audit import audit_export
        from components.imap_ops import legacy_server_endpoint, legacy_server_endpoint_digest
        from components.models import Account, Config, ServerConfig

        server = ServerConfig("imap.example.com")
        account_dir = tmp_path / "user@example.com"
        projects = account_dir / "Projects"
        projects.mkdir(parents=True)
        (projects / ".mailbox.json").write_text(json.dumps({"mailbox": "Projects", "message_count": 0}))
        (account_dir / "export-state.json").write_text(json.dumps({
            "schema_version": 1,
            "account": "user@example.com",
            "source_server": legacy_server_endpoint(server),
            "source_server_sha256": legacy_server_endpoint_digest(server),
            "complete": True,
            "mailboxes": [{"mailbox": "Projects", "path": "Projects", "message_count": 0}],
        }))

        class RemoteMissingProjects:
            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"0"]

            def uid(self, command: str, arg: str):
                return "OK", [b""]

            def logout(self):
                return "OK", []

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[RemoteMissingProjects]:
            yield RemoteMissingProjects()

        with mock.patch("components.audit.imap_connection", fake_connection):
            ok, issues = audit_export(
                tmp_path,
                Config(server, [Account("user@example.com", "secret")], source_server=server),
                1,
                check_remote=True,
                require_integrity_metadata=True,
            )

        assert not ok
        assert any("Projects: missing remotely or not selectable but local has 0 messages" in issue for issue in issues)

    def test_verify_export_rejects_mailbox_marker_folder_mismatch(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from verify_export import main, verify_account

        folder = tmp_path / "exported" / "user@example.com" / "Archive"
        folder.mkdir(parents=True)
        (folder / ".mailbox.json").write_text(json.dumps({"mailbox": "Sent", "message_count": 0}))
        _write_verify_export_state(folder.parent, [{"mailbox": "Archive", "path": "Archive", "message_count": 0}])
        monkeypatch.chdir(tmp_path)

        stats = verify_account(tmp_path / "exported" / "user@example.com")

        assert stats["errors"] == 1
        assert main() == 1

    def test_verify_export_rejects_message_sidecar_folder_mismatch(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from verify_export import main, verify_account

        folder = tmp_path / "exported" / "user@example.com" / "Archive"
        eml = _write_legacy_message_fixture(
            folder,
            mailbox="Sent",
            data=b"Message-ID: <m@example.com>\r\nFrom: a@example.com\r\nTo: b@example.com\r\n\r\nbody",
        )
        (folder / ".mailbox.json").write_text(json.dumps({"mailbox": "Archive", "message_count": 1}))
        _write_verify_export_state(folder.parent, [{"mailbox": "Archive", "path": "Archive", "message_count": 1}])
        monkeypatch.chdir(tmp_path)

        stats = verify_account(tmp_path / "exported" / "user@example.com")

        assert eml.exists()
        assert stats["errors"] == 1
        assert main() == 1

    def test_verify_export_requires_export_state(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from verify_export import main, verify_account

        folder = tmp_path / "exported" / "user@example.com" / "INBOX"
        eml = _write_legacy_message_fixture(
            folder,
            data=b"Message-ID: <m@example.com>\r\nFrom: a@example.com\r\nTo: b@example.com\r\n\r\nbody",
        )
        (folder / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": 1}))
        (folder.parent / "export-state.json").unlink()
        monkeypatch.chdir(tmp_path)

        stats = verify_account(tmp_path / "exported" / "user@example.com")

        assert eml.exists()
        assert stats["errors"] == 1
        assert main() == 1

    def test_verify_export_rejects_incomplete_export_state(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from verify_export import main, verify_account

        folder = tmp_path / "exported" / "user@example.com" / "INBOX"
        _write_legacy_message_fixture(
            folder,
            data=b"Message-ID: <m@example.com>\r\nFrom: a@example.com\r\nTo: b@example.com\r\n\r\nbody",
        )
        (folder / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": 1}))
        state_path = folder.parent / "export-state.json"
        state = json.loads(state_path.read_text())
        state["complete"] = False
        state_path.write_text(json.dumps(state))
        monkeypatch.chdir(tmp_path)

        stats = verify_account(tmp_path / "exported" / "user@example.com")

        assert stats["errors"] == 1
        assert main() == 1

    def test_verify_export_detects_appended_message_after_rfc822_attachment(self, tmp_path: Path) -> None:
        from verify_export import analyze_message

        eml_path = tmp_path / "appended-after-attachment.eml"
        payload = (
            b"Message-ID: <outer@example.com>\r\n"
            b"From: outer@example.com\r\n"
            b"To: recipient@example.com\r\n"
            b"Subject: attached message\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: multipart/mixed; boundary=\"b\"\r\n"
            b"\r\n"
            b"--b\r\n"
            b"Content-Type: text/plain\r\n"
            b"\r\n"
            b"See attached.\r\n"
            b"--b\r\n"
            b"Content-Type: message/rfc822\r\n"
            b"Content-Disposition: attachment; filename=\"attached.eml\"\r\n"
            b"\r\n"
            b"Message-ID: <inner@example.com>\r\n"
            b"From: inner@example.com\r\n"
            b"To: recipient@example.com\r\n"
            b"Subject: inner\r\n"
            b"\r\n"
            b"inner body\r\n"
            b"--b--\r\n"
            b"Message-ID: <second@example.com>\r\n"
            b"From: second@example.com\r\n"
            b"To: recipient@example.com\r\n"
            b"\r\n"
            b"second body\r\n"
        )
        eml_path.write_bytes(payload)
        json_path = tmp_path / "appended-after-attachment.json"
        json_path.write_text(json.dumps(_legacy_integrity_metadata(payload)))

        analysis, error = analyze_message(eml_path, json_path)

        assert error is None
        assert analysis is not None
        assert "message/rfc822" in analysis["content_types"]
        assert analysis["multiple_messages_detected"] is True

    def test_strict_audit_rejects_boolean_uid_metadata(self, tmp_path: Path) -> None:
        from components.audit import audit_export
        from components.content_binding import CONTENT_BINDING_FIELD, legacy_content_binding_sha256
        from components.models import Account, Config, ServerConfig

        server = ServerConfig("imap.example.com")
        folder = tmp_path / "user@example.com" / "INBOX"
        eml = _write_legacy_message_fixture(
            folder,
            uid=1,
            mailbox="INBOX",
            data=b"Message-ID: <m@example.com>\r\nFrom: a@example.com\r\nTo: b@example.com\r\n\r\nbody",
            source_server=server,
        )
        meta_path = eml.with_suffix(".json")
        meta = json.loads(meta_path.read_text())
        meta["uid"] = True
        meta[CONTENT_BINDING_FIELD] = legacy_content_binding_sha256(meta)
        meta_path.write_text(json.dumps(meta))

        ok, issues = audit_export(
            tmp_path,
            Config(server, [Account("user@example.com", "secret")], source_server=server),
            1,
            check_remote=False,
            require_integrity_metadata=True,
        )

        assert not ok
        assert any("u0000000001.eml: invalid uid metadata" in issue for issue in issues)


class TestRound7ConfirmedBugs:
    def test_provider_manifest_rejects_non_string_primary_mailbox_before_import(self, tmp_path: Path) -> None:
        from components.content_binding import CONTENT_BINDING_FIELD, provider_content_binding_sha256
        from components.models import AuthConfig, MigrationAccount, ProviderEndpoint, ProviderMigrationConfig
        from components.provider_ops import (
            provider_account_endpoint_state,
            provider_account_endpoint_state_digest,
            provider_audit_account,
            provider_import_account,
            provider_manifest_digest,
        )

        source = ProviderEndpoint(
            provider="imap",
            host="source.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="secret"),
        )
        target = ProviderEndpoint(
            provider="imap",
            host="target.example.com",
            auth=AuthConfig(method="password", username="target@example.com", password="secret"),
        )
        account = MigrationAccount(source_email="source@example.com", target_email="target@example.com")
        config = ProviderMigrationConfig(source=source, target=target, accounts=[account])
        account_dir = tmp_path / "source@example.com"
        (account_dir / "messages").mkdir(parents=True)
        (account_dir / "metadata").mkdir()
        body = b"Message-ID: <bad-primary@example.com>\r\n\r\nbody"
        (account_dir / "messages/provider-1.eml").write_bytes(body)
        row = {
            "canonical_id": "provider-1",
            "source_provider": "imap",
            "source_account": account.source_email,
            "target_account": account.target_email,
            "primary_mailbox": ["Archive"],
            "message_id_header": "<bad-primary@example.com>",
            "content_sha256": hashlib.sha256(body).hexdigest(),
            "rfc822_size": len(body),
            "flags": "\\Seen",
            "internaldate": "01-Jan-2024 00:00:00 +0000",
            "eml_path": "messages/provider-1.eml",
            "metadata_path": "metadata/provider-1.json",
        }
        row[CONTENT_BINDING_FIELD] = provider_content_binding_sha256(row)
        (account_dir / "metadata/provider-1.json").write_text(json.dumps(row))
        (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")
        (account_dir / "export-state.json").write_text(json.dumps({
            "source_provider": source.provider,
            "target_provider": target.provider,
            "source_account": account.source_email,
            "target_account": account.target_email,
            "complete": True,
            "canonical_messages": 1,
            "manifest_sha256": provider_manifest_digest([row]),
            "source_endpoint": provider_account_endpoint_state(source, account, role="source"),
            "source_endpoint_sha256": provider_account_endpoint_state_digest(source, account, role="source"),
            "target_endpoint": provider_account_endpoint_state(target, account, role="target"),
            "target_endpoint_sha256": provider_account_endpoint_state_digest(target, account, role="target"),
        }))

        _email, issues = provider_audit_account(config, account, tmp_path)

        assert any("provider-1: missing or invalid primary_mailbox" in issue for issue in issues)
        with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
            with pytest.raises(RuntimeError, match="missing or invalid primary_mailbox"):
                provider_import_account(config, account, tmp_path)

    def test_audit_remote_identity_matches_imap_append_wire_bytes(self, tmp_path: Path) -> None:
        import imaplib

        from components.audit import audit_export
        from components.models import Account, Config, ServerConfig

        server = ServerConfig("imap.example.com")
        account = Account("user@example.com", "secret")
        body = b"Message-ID: <audit-wire@example.com>\nFrom: a\nTo: b\n\nbody\n"
        stored = imaplib.MapCRLF.sub(imaplib.CRLF, body)
        folder = tmp_path / account.email / "INBOX"
        _write_legacy_message_fixture(folder, data=body, source_server=server)
        (folder / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": 1}))

        class NormalizedAuditRemote:
            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"1"]

            def uid(self, command: str, criterion: str):
                return "OK", [b"1"]

            def search(self, charset, *criteria):
                assert criteria == ("HEADER", "Message-ID", "<audit-wire@example.com>")
                return "OK", [b"1"]

            def fetch(self, num: bytes, query: str):
                return "OK", [(b"1 (RFC822.SIZE %d FLAGS (\\Seen) INTERNALDATE \"01-Jan-2024 00:00:00 +0000\" BODY[] {%d}" % (len(stored), len(stored)), stored)]

        @contextlib.contextmanager
        def fake_connection(_server, _account):
            yield NormalizedAuditRemote()

        with mock.patch("components.audit.imap_connection", fake_connection):
            ok, issues = audit_export(
                tmp_path,
                Config(server, [account], source_server=server),
                1,
                check_remote=True,
                require_integrity_metadata=True,
            )

        assert ok, issues

    def test_direct_import_rejects_orphan_legacy_sidecar_before_connect(self, tmp_path: Path) -> None:
        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        folder = tmp_path / "user@example.com" / "INBOX"
        _write_legacy_message_fixture(
            folder,
            data=b"Message-ID: <orphan-sidecar@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody",
        )
        (folder / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": 1}))
        (folder / "u0000000002.json").write_text(json.dumps({"mailbox": "INBOX", "uid": 2}))

        with pytest.raises(RuntimeError, match=r"metadata file\(s\) without \.eml counterpart"):
            import_account(
                Account("user@example.com", "secret"),
                ServerConfig("imap.example.com"),
                tmp_path,
                ignore_errors=False,
                imap_factory=lambda *_args: (_ for _ in ()).throw(AssertionError("IMAP should not be opened")),
            )

    def test_direct_import_rejects_legacy_marker_count_mismatch_before_connect(self, tmp_path: Path) -> None:
        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        folder = tmp_path / "user@example.com" / "INBOX"
        _write_legacy_message_fixture(
            folder,
            data=b"Message-ID: <marker-count@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody",
        )
        (folder / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": 2}))

        with pytest.raises(RuntimeError, match=r"mailbox marker count mismatch \(marker=2 eml=1\)"):
            import_account(
                Account("user@example.com", "secret"),
                ServerConfig("imap.example.com"),
                tmp_path,
                ignore_errors=False,
                imap_factory=lambda *_args: (_ for _ in ()).throw(AssertionError("IMAP should not be opened")),
            )

    def test_direct_import_rejects_legacy_marker_missing_mailbox_before_connect(self, tmp_path: Path) -> None:
        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        folder = tmp_path / "user@example.com" / "INBOX"
        _write_legacy_message_fixture(
            folder,
            data=b"Message-ID: <marker-missing-mailbox@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody",
        )
        (folder / ".mailbox.json").write_text(json.dumps({"message_count": 1}))

        with pytest.raises(RuntimeError, match="mailbox marker missing mailbox"):
            import_account(
                Account("user@example.com", "secret"),
                ServerConfig("imap.example.com"),
                tmp_path,
                ignore_errors=False,
                imap_factory=lambda *_args: (_ for _ in ()).throw(AssertionError("IMAP should not be opened")),
            )

    def test_direct_import_rejects_legacy_sidecar_missing_mailbox_before_connect(self, tmp_path: Path) -> None:
        from components.content_binding import CONTENT_BINDING_FIELD, legacy_content_binding_sha256
        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        folder = tmp_path / "user@example.com" / "INBOX"
        eml = _write_legacy_message_fixture(
            folder,
            data=b"Message-ID: <sidecar-missing-mailbox@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody",
        )
        (folder / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": 1}))
        meta_path = eml.with_suffix(".json")
        meta = json.loads(meta_path.read_text())
        del meta["mailbox"]
        meta[CONTENT_BINDING_FIELD] = legacy_content_binding_sha256(meta)
        meta_path.write_text(json.dumps(meta))

        with pytest.raises(RuntimeError, match="missing mailbox metadata"):
            import_account(
                Account("user@example.com", "secret"),
                ServerConfig("imap.example.com"),
                tmp_path,
                ignore_errors=False,
                imap_factory=lambda *_args: (_ for _ in ()).throw(AssertionError("IMAP should not be opened")),
            )

    def test_direct_import_rejects_missing_legacy_message_sidecar_before_connect(self, tmp_path: Path) -> None:
        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        folder = tmp_path / "user@example.com" / "INBOX"
        eml = _write_legacy_message_fixture(
            folder,
            data=b"Message-ID: <missing-sidecar-import@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody",
        )
        (folder / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": 1}))
        eml.with_suffix(".json").unlink()

        with pytest.raises(RuntimeError, match="missing message metadata"):
            import_account(
                Account("user@example.com", "secret"),
                ServerConfig("imap.example.com"),
                tmp_path,
                ignore_errors=False,
                imap_factory=lambda *_args: (_ for _ in ()).throw(AssertionError("IMAP should not be opened")),
            )

    @pytest.mark.parametrize(
        ("removed_field", "error"),
        [
            ("rfc822_size", "invalid rfc822_size metadata"),
            ("content_sha256", "invalid content_sha256 metadata"),
            ("content_binding_sha256", "missing content_binding_sha256"),
        ],
    )
    def test_direct_import_rejects_missing_legacy_integrity_metadata_before_connect(
        self,
        tmp_path: Path,
        removed_field: str,
        error: str,
    ) -> None:
        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        folder = tmp_path / "user@example.com" / "INBOX"
        eml = _write_legacy_message_fixture(
            folder,
            data=b"Message-ID: <missing-integrity-import@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody",
        )
        (folder / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": 1}))
        meta_path = eml.with_suffix(".json")
        meta = json.loads(meta_path.read_text())
        del meta[removed_field]
        meta_path.write_text(json.dumps(meta))

        with pytest.raises(RuntimeError, match=error):
            import_account(
                Account("user@example.com", "secret"),
                ServerConfig("imap.example.com"),
                tmp_path,
                ignore_errors=False,
                imap_factory=lambda *_args: (_ for _ in ()).throw(AssertionError("IMAP should not be opened")),
            )

    def test_direct_import_rejects_missing_legacy_export_state_before_connect(self, tmp_path: Path) -> None:
        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        folder = tmp_path / "user@example.com" / "INBOX"
        _write_legacy_message_fixture(folder)
        (folder / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": 1}))
        (folder.parent / "export-state.json").unlink()

        with pytest.raises(RuntimeError, match="export-state missing"):
            import_account(
                Account("user@example.com", "secret"),
                ServerConfig("imap.example.com"),
                tmp_path,
                ignore_errors=False,
                imap_factory=lambda *_args: (_ for _ in ()).throw(AssertionError("IMAP should not be opened")),
            )

    def test_direct_import_rejects_incomplete_legacy_export_state_before_connect(self, tmp_path: Path) -> None:
        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        folder = tmp_path / "user@example.com" / "INBOX"
        _write_legacy_message_fixture(folder)
        (folder / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": 1}))
        state_path = folder.parent / "export-state.json"
        state = json.loads(state_path.read_text())
        state["complete"] = False
        state_path.write_text(json.dumps(state))

        with pytest.raises(RuntimeError, match="export-state is not complete"):
            import_account(
                Account("user@example.com", "secret"),
                ServerConfig("imap.example.com"),
                tmp_path,
                ignore_errors=False,
                imap_factory=lambda *_args: (_ for _ in ()).throw(AssertionError("IMAP should not be opened")),
            )

    def test_direct_import_rejects_wrong_source_legacy_export_state_before_connect(self, tmp_path: Path) -> None:
        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        source_server = ServerConfig("source.example.com")
        wrong_source = ServerConfig("wrong-source.example.com")
        folder = tmp_path / "user@example.com" / "INBOX"
        _write_legacy_message_fixture(folder, source_server=source_server)
        (folder / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": 1}))

        with pytest.raises(RuntimeError, match="source_server does not match config source_server"):
            import_account(
                Account("user@example.com", "secret"),
                ServerConfig("target.example.com"),
                tmp_path,
                ignore_errors=False,
                imap_factory=lambda *_args: (_ for _ in ()).throw(AssertionError("IMAP should not be opened")),
                source_server=wrong_source,
            )

    def test_direct_import_requires_source_server_binding_before_connect(self, tmp_path: Path) -> None:
        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        source_server = ServerConfig("source.example.com")
        folder = tmp_path / "user@example.com" / "INBOX"
        _write_legacy_message_fixture(folder, source_server=source_server)
        (folder / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": 1}))

        with pytest.raises(RuntimeError, match="config source_server missing"):
            import_account(
                Account("user@example.com", "secret"),
                ServerConfig("target.example.com"),
                tmp_path,
                ignore_errors=False,
                imap_factory=lambda *_args: (_ for _ in ()).throw(AssertionError("IMAP should not be opened")),
            )

    def test_direct_zero_message_import_rejects_wrong_source_export_state_before_connect(self, tmp_path: Path) -> None:
        from components.imap_ops import import_account, legacy_server_endpoint, legacy_server_endpoint_digest
        from components.models import Account, ServerConfig

        source_server = ServerConfig("source.example.com")
        wrong_source = ServerConfig("wrong-source.example.com")
        account_dir = tmp_path / "user@example.com"
        folder = account_dir / "INBOX"
        folder.mkdir(parents=True)
        (folder / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": 0}))
        (account_dir / "export-state.json").write_text(json.dumps({
            "schema_version": 1,
            "account": "user@example.com",
            "source_server": legacy_server_endpoint(source_server),
            "source_server_sha256": legacy_server_endpoint_digest(source_server),
            "complete": True,
            "completed_at": 0,
            "mailboxes": [{"mailbox": "INBOX", "path": "INBOX", "message_count": 0}],
        }))

        with pytest.raises(RuntimeError, match="source_server does not match config source_server"):
            import_account(
                Account("user@example.com", "secret"),
                ServerConfig("target.example.com"),
                tmp_path,
                ignore_errors=False,
                imap_factory=lambda *_args: (_ for _ in ()).throw(AssertionError("IMAP should not be opened")),
                source_server=wrong_source,
            )

    def test_direct_import_rejects_original_mailbox_without_marker_before_connect(self, tmp_path: Path) -> None:
        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        folder = tmp_path / "user@example.com" / "Sent_Items"
        _write_legacy_message_fixture(
            folder,
            mailbox="Sent Items",
            data=b"Message-ID: <import-sent-items@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody",
        )

        with pytest.raises(RuntimeError, match="missing mailbox marker for original mailbox Sent Items"):
            import_account(
                Account("user@example.com", "secret"),
                ServerConfig("imap.example.com"),
                tmp_path,
                ignore_errors=False,
                imap_factory=lambda *_args: (_ for _ in ()).throw(AssertionError("IMAP should not be opened")),
            )

    def test_strict_audit_rejects_symlinked_legacy_export_state_without_reading_target(self, tmp_path: Path) -> None:
        from components.audit import audit_export
        from components.models import Account, Config, ServerConfig

        server = ServerConfig("imap.example.com")
        folder = tmp_path / "user@example.com" / "INBOX"
        _write_legacy_message_fixture(
            folder,
            data=b"Message-ID: <state-symlink@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody",
            source_server=server,
        )
        (folder / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": 1}))
        state_path = folder.parent / "export-state.json"
        state_path.unlink()
        outside_state = tmp_path / "outside-state.json"
        outside_state.write_text("{bad json")
        try:
            state_path.symlink_to(outside_state)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")

        ok, issues = audit_export(
            tmp_path,
            Config(server, [Account("user@example.com", "secret")], source_server=server),
            1,
            check_remote=False,
            require_integrity_metadata=True,
        )

        assert not ok
        assert any("export-state is a symlink" in issue for issue in issues)
        assert not any("export-state missing or invalid" in issue for issue in issues)

    def test_strict_audit_rejects_cross_account_legacy_message_pair(self, tmp_path: Path) -> None:
        from components.audit import audit_export
        from components.models import Account, Config, ServerConfig

        server = ServerConfig("imap.example.com")
        account_a_folder = tmp_path / "a@example.com" / "INBOX"
        account_b_folder = tmp_path / "b@example.com" / "INBOX"
        account_a_eml = _write_legacy_message_fixture(
            account_a_folder,
            data=b"Message-ID: <a@example.com>\r\nFrom: a\r\nTo: target\r\n\r\nbody-a",
            source_server=server,
        )
        account_b_eml = _write_legacy_message_fixture(
            account_b_folder,
            data=b"Message-ID: <b@example.com>\r\nFrom: b\r\nTo: target\r\n\r\nbody-b",
            source_server=server,
        )
        (account_a_folder / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": 1}))
        account_a_eml.write_bytes(account_b_eml.read_bytes())
        account_a_eml.with_suffix(".json").write_text(account_b_eml.with_suffix(".json").read_text())

        ok, issues = audit_export(
            tmp_path,
            Config(server, [Account("a@example.com", "secret")], source_server=server),
            1,
            check_remote=False,
            require_integrity_metadata=True,
        )

        assert not ok
        assert any("account metadata mismatch (account=a@example.com meta=b@example.com)" in issue for issue in issues)

    def test_direct_import_rejects_cross_account_legacy_sidecar_before_connect(self, tmp_path: Path) -> None:
        from components.content_binding import CONTENT_BINDING_FIELD, legacy_content_binding_sha256
        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        folder = tmp_path / "a@example.com" / "INBOX"
        eml = _write_legacy_message_fixture(
            folder,
            data=b"Message-ID: <wrong-account@example.com>\r\nFrom: b\r\nTo: a\r\n\r\nbody",
        )
        meta_path = eml.with_suffix(".json")
        meta = json.loads(meta_path.read_text())
        meta["account"] = "b@example.com"
        meta[CONTENT_BINDING_FIELD] = legacy_content_binding_sha256(meta)
        meta_path.write_text(json.dumps(meta))

        with pytest.raises(RuntimeError, match="account metadata mismatch"):
            import_account(
                Account("a@example.com", "secret"),
                ServerConfig("imap.example.com"),
                tmp_path,
                ignore_errors=False,
                imap_factory=lambda *_args: (_ for _ in ()).throw(AssertionError("IMAP should not be opened")),
            )

    def test_verify_export_rejects_cross_account_legacy_sidecar(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        from components.content_binding import CONTENT_BINDING_FIELD, legacy_content_binding_sha256
        from verify_export import verify_account

        account_dir = tmp_path / "exported" / "a@example.com"
        folder = account_dir / "INBOX"
        eml = _write_legacy_message_fixture(
            folder,
            data=b"Message-ID: <verify-account@example.com>\r\nFrom: b\r\nTo: a\r\n\r\nbody",
        )
        meta_path = eml.with_suffix(".json")
        meta = json.loads(meta_path.read_text())
        meta["account"] = "b@example.com"
        meta[CONTENT_BINDING_FIELD] = legacy_content_binding_sha256(meta)
        meta_path.write_text(json.dumps(meta))
        (folder / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": 1}))
        _write_verify_export_state(account_dir, [{"mailbox": "INBOX", "path": "INBOX", "message_count": 1}])

        stats = verify_account(account_dir)
        output = capsys.readouterr().out

        assert stats["errors"] == 1
        assert "account metadata mismatch (account=a@example.com meta=b@example.com)" in output

    def test_verify_export_accepts_sanitized_legacy_account_sidecars(self, tmp_path: Path) -> None:
        from verify_export import verify_account

        account_dir = tmp_path / "exported" / "a_b@example.com"
        inbox = account_dir / "INBOX"
        inbox.mkdir(parents=True)
        body = b"Message-ID: <sanitized-account@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody"
        (inbox / "u0000000001.eml").write_bytes(body)
        (inbox / "u0000000001.json").write_text(json.dumps(
            _legacy_integrity_metadata(body, account="a/b@example.com", mailbox="INBOX", uid=1)
        ))
        (inbox / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": 1}))
        (account_dir / "export-state.json").write_text(json.dumps({
            "schema_version": 1,
            "account": "a/b@example.com",
            "complete": True,
            "mailboxes": [{"mailbox": "INBOX", "path": "INBOX", "message_count": 1}],
        }))

        stats = verify_account(account_dir)

        assert stats["errors"] == 0

    def test_strict_audit_rejects_missing_export_state_account_binding(self, tmp_path: Path) -> None:
        from components.audit import audit_export
        from components.imap_ops import legacy_server_endpoint, legacy_server_endpoint_digest
        from components.models import Account, Config, ServerConfig

        server = ServerConfig("imap.example.com")
        folder = tmp_path / "user@example.com" / "INBOX"
        _write_legacy_message_fixture(
            folder,
            data=b"Message-ID: <state-account@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody",
            source_server=server,
        )
        (folder / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": 1}))
        state = json.loads((folder.parent / "export-state.json").read_text())
        del state["account"]
        state["source_server"] = legacy_server_endpoint(server)
        state["source_server_sha256"] = legacy_server_endpoint_digest(server)
        (folder.parent / "export-state.json").write_text(json.dumps(state))

        ok, issues = audit_export(
            tmp_path,
            Config(server, [Account("user@example.com", "secret")], source_server=server),
            1,
            check_remote=False,
            require_integrity_metadata=True,
        )

        assert not ok
        assert any("export-state account mismatch (None)" in issue for issue in issues)

    def test_provider_export_rejects_symlinked_account_directory_before_source_contact(self, tmp_path: Path) -> None:
        from components.models import AuthConfig, MigrationAccount, ProviderEndpoint, ProviderMigrationConfig
        from components.provider_ops import provider_export_account

        source = ProviderEndpoint(
            provider="imap",
            host="source.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="secret"),
        )
        target = ProviderEndpoint(
            provider="imap",
            host="target.example.com",
            auth=AuthConfig(method="password", username="target@example.com", password="secret"),
        )
        account = MigrationAccount(source_email="source@example.com", target_email="target@example.com")
        config = ProviderMigrationConfig(source=source, target=target, accounts=[account])
        out_root = tmp_path / "exported"
        real_account_dir = tmp_path / "real-account"
        real_account_dir.mkdir()
        out_root.mkdir()
        try:
            (out_root / "source@example.com").symlink_to(real_account_dir, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")

        with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("source should not be contacted")):
            with pytest.raises(RuntimeError, match="symlinked provider account directory"):
                provider_export_account(config, account, out_root)

    def test_provider_export_rejects_symlinked_resume_state_before_source_contact(self, tmp_path: Path) -> None:
        from components.content_binding import CONTENT_BINDING_FIELD, provider_content_binding_sha256
        from components.models import AuthConfig, MigrationAccount, ProviderEndpoint, ProviderMigrationConfig
        from components.provider_ops import provider_export_account

        source = ProviderEndpoint(
            provider="imap",
            host="source.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="secret"),
        )
        target = ProviderEndpoint(
            provider="imap",
            host="target.example.com",
            auth=AuthConfig(method="password", username="target@example.com", password="secret"),
        )
        account = MigrationAccount(source_email="source@example.com", target_email="target@example.com")
        config = ProviderMigrationConfig(source=source, target=target, accounts=[account])
        account_dir = tmp_path / "exported" / "source@example.com"
        (account_dir / "messages").mkdir(parents=True)
        (account_dir / "metadata").mkdir()
        body = b"Message-ID: <resume@example.com>\r\n\r\nbody"
        (account_dir / "messages/provider-1.eml").write_bytes(body)
        row = {
            "canonical_id": "provider-1",
            "source_provider": "imap",
            "source_account": account.source_email,
            "target_account": account.target_email,
            "primary_mailbox": "INBOX",
            "message_id_header": "<resume@example.com>",
            "content_sha256": hashlib.sha256(body).hexdigest(),
            "rfc822_size": len(body),
            "flags": "\\Seen",
            "internaldate": "01-Jan-2024 00:00:00 +0000",
            "eml_path": "messages/provider-1.eml",
            "metadata_path": "metadata/provider-1.json",
        }
        row[CONTENT_BINDING_FIELD] = provider_content_binding_sha256(row)
        (account_dir / "metadata/provider-1.json").write_text(json.dumps(row))
        (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")
        outside_state = tmp_path / "outside-state.json"
        outside_state.write_text(json.dumps({
            "source_provider": source.provider,
            "target_provider": target.provider,
            "source_account": account.source_email,
            "target_account": account.target_email,
            "complete": False,
        }))
        try:
            (account_dir / "export-state.json").symlink_to(outside_state)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")

        with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("source should not be contacted")):
            with pytest.raises(RuntimeError, match="symlinked provider file"):
                provider_export_account(config, account, tmp_path / "exported")

        assert (account_dir / "export-state.json").is_symlink()

    def test_provider_export_rejects_symlinked_fresh_state_before_rewrite(self, tmp_path: Path) -> None:
        from components.models import AuthConfig, MigrationAccount, ProviderEndpoint, ProviderMigrationConfig
        from components.provider_ops import provider_export_account

        source = ProviderEndpoint(
            provider="imap",
            host="source.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="secret"),
        )
        target = ProviderEndpoint(
            provider="imap",
            host="target.example.com",
            auth=AuthConfig(method="password", username="target@example.com", password="secret"),
        )
        account = MigrationAccount(source_email="source@example.com", target_email="target@example.com")
        config = ProviderMigrationConfig(source=source, target=target, accounts=[account])
        account_dir = tmp_path / "exported" / "source@example.com"
        account_dir.mkdir(parents=True)
        outside_state = tmp_path / "outside-state.json"
        outside_state.write_text(json.dumps({"victim": True}))
        try:
            (account_dir / "export-state.json").symlink_to(outside_state)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")

        with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("source should not be contacted")):
            with pytest.raises(RuntimeError, match="symlinked provider file"):
                provider_export_account(config, account, tmp_path / "exported")

        assert (account_dir / "export-state.json").is_symlink()
        assert json.loads(outside_state.read_text()) == {"victim": True}

    @pytest.mark.parametrize("bad_size", [True, 1.0])
    def test_provider_metadata_manifest_rejects_json_type_drift(self, tmp_path: Path, bad_size: object) -> None:
        from components.content_binding import CONTENT_BINDING_FIELD, provider_content_binding_sha256
        from components.provider_ops import metadata_manifest_issues

        account_dir = tmp_path / "source@example.com"
        (account_dir / "metadata").mkdir(parents=True)
        body = b"x"
        row = {
            "canonical_id": "provider-1",
            "source_provider": "imap",
            "source_account": "source@example.com",
            "target_account": "target@example.com",
            "primary_mailbox": "INBOX",
            "content_sha256": hashlib.sha256(body).hexdigest(),
            "rfc822_size": 1,
            "flags": "\\Seen",
            "internaldate": "01-Jan-2024 00:00:00 +0000",
            "eml_path": "messages/provider-1.eml",
            "metadata_path": "metadata/provider-1.json",
        }
        row[CONTENT_BINDING_FIELD] = provider_content_binding_sha256(row)
        metadata = dict(row)
        metadata["rfc822_size"] = bad_size
        (account_dir / "metadata/provider-1.json").write_text(json.dumps(metadata))

        issues = metadata_manifest_issues(account_dir, [row])

        assert any("provider-1: metadata rfc822_size differs from manifest" in issue for issue in issues)

    def test_provider_import_rejects_type_drifted_metadata_before_target_contact(self, tmp_path: Path) -> None:
        from components.content_binding import CONTENT_BINDING_FIELD, provider_content_binding_sha256
        from components.models import AuthConfig, MigrationAccount, ProviderEndpoint, ProviderMigrationConfig
        from components.provider_ops import (
            provider_account_endpoint_state,
            provider_account_endpoint_state_digest,
            provider_import_account,
            provider_manifest_digest,
        )

        source = ProviderEndpoint(
            provider="imap",
            host="source.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="secret"),
        )
        target = ProviderEndpoint(
            provider="imap",
            host="target.example.com",
            auth=AuthConfig(method="password", username="target@example.com", password="secret"),
        )
        account = MigrationAccount(source_email="source@example.com", target_email="target@example.com")
        config = ProviderMigrationConfig(source=source, target=target, accounts=[account])
        account_dir = tmp_path / "source@example.com"
        (account_dir / "messages").mkdir(parents=True)
        (account_dir / "metadata").mkdir()
        body = b"x"
        (account_dir / "messages/provider-1.eml").write_bytes(body)
        row = {
            "canonical_id": "provider-1",
            "source_provider": "imap",
            "source_account": account.source_email,
            "target_account": account.target_email,
            "primary_mailbox": "INBOX",
            "content_sha256": hashlib.sha256(body).hexdigest(),
            "rfc822_size": 1,
            "flags": "\\Seen",
            "internaldate": "01-Jan-2024 00:00:00 +0000",
            "eml_path": "messages/provider-1.eml",
            "metadata_path": "metadata/provider-1.json",
        }
        row[CONTENT_BINDING_FIELD] = provider_content_binding_sha256(row)
        metadata = dict(row)
        metadata["rfc822_size"] = True
        (account_dir / "metadata/provider-1.json").write_text(json.dumps(metadata))
        (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")
        (account_dir / "export-state.json").write_text(json.dumps({
            "source_provider": source.provider,
            "target_provider": target.provider,
            "source_account": account.source_email,
            "target_account": account.target_email,
            "complete": True,
            "canonical_messages": 1,
            "manifest_sha256": provider_manifest_digest([row]),
            "source_endpoint": provider_account_endpoint_state(source, account, role="source"),
            "source_endpoint_sha256": provider_account_endpoint_state_digest(source, account, role="source"),
            "target_endpoint": provider_account_endpoint_state(target, account, role="target"),
            "target_endpoint_sha256": provider_account_endpoint_state_digest(target, account, role="target"),
        }))

        with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
            with pytest.raises(RuntimeError, match="metadata rfc822_size differs from manifest"):
                provider_import_account(config, account, tmp_path)

    def test_provider_import_rejects_symlinked_manifest_payload_before_target_contact(self, tmp_path: Path) -> None:
        from components.content_binding import CONTENT_BINDING_FIELD, provider_content_binding_sha256
        from components.models import AuthConfig, MigrationAccount, ProviderEndpoint, ProviderMigrationConfig
        from components.provider_ops import (
            provider_account_endpoint_state,
            provider_account_endpoint_state_digest,
            provider_import_account,
            provider_manifest_digest,
        )

        source = ProviderEndpoint(
            provider="imap",
            host="source.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="secret"),
        )
        target = ProviderEndpoint(
            provider="imap",
            host="target.example.com",
            auth=AuthConfig(method="password", username="target@example.com", password="secret"),
        )
        account = MigrationAccount(source_email="source@example.com", target_email="target@example.com")
        config = ProviderMigrationConfig(source=source, target=target, accounts=[account])
        account_dir = tmp_path / "source@example.com"
        messages_dir = account_dir / "messages"
        metadata_dir = account_dir / "metadata"
        messages_dir.mkdir(parents=True)
        metadata_dir.mkdir()
        body = b"Message-ID: <provider@example.com>\r\n\r\nbody"
        real_payload = messages_dir / "real.eml"
        real_payload.write_bytes(body)
        try:
            (messages_dir / "provider-1.eml").symlink_to(real_payload)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")
        row = {
            "canonical_id": "provider-1",
            "source_provider": "imap",
            "source_account": account.source_email,
            "target_account": account.target_email,
            "primary_mailbox": "INBOX",
            "message_id_header": "<provider@example.com>",
            "content_sha256": hashlib.sha256(body).hexdigest(),
            "rfc822_size": len(body),
            "flags": "\\Seen",
            "internaldate": "01-Jan-2024 00:00:00 +0000",
            "eml_path": "messages/provider-1.eml",
            "metadata_path": "metadata/provider-1.json",
        }
        row[CONTENT_BINDING_FIELD] = provider_content_binding_sha256(row)
        (metadata_dir / "provider-1.json").write_text(json.dumps(row))
        (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")
        (account_dir / "export-state.json").write_text(json.dumps({
            "source_provider": source.provider,
            "target_provider": target.provider,
            "source_account": account.source_email,
            "target_account": account.target_email,
            "complete": True,
            "canonical_messages": 1,
            "manifest_sha256": provider_manifest_digest([row]),
            "source_endpoint": provider_account_endpoint_state(source, account, role="source"),
            "source_endpoint_sha256": provider_account_endpoint_state_digest(source, account, role="source"),
            "target_endpoint": provider_account_endpoint_state(target, account, role="target"),
            "target_endpoint_sha256": provider_account_endpoint_state_digest(target, account, role="target"),
        }))

        with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
            with pytest.raises(RuntimeError, match="symlinked eml_path"):
                provider_import_account(config, account, tmp_path)

    def test_verify_export_rejects_missing_legacy_mailbox_metadata(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from components.content_binding import CONTENT_BINDING_FIELD, legacy_content_binding_sha256
        from verify_export import main, verify_account

        folder = tmp_path / "exported" / "user@example.com" / "INBOX"
        eml = _write_legacy_message_fixture(
            folder,
            mailbox="INBOX",
            data=b"Message-ID: <missing-mailbox@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody",
        )
        (folder / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": 1}))
        meta_path = eml.with_suffix(".json")
        meta = json.loads(meta_path.read_text())
        del meta["mailbox"]
        meta[CONTENT_BINDING_FIELD] = legacy_content_binding_sha256(meta)
        meta_path.write_text(json.dumps(meta))
        monkeypatch.chdir(tmp_path)

        stats = verify_account(tmp_path / "exported" / "user@example.com")
        output = capsys.readouterr().out

        assert stats["errors"] == 1
        assert "INBOX/u0000000001.eml: missing mailbox metadata" in output
        assert main() == 1

    def test_strict_audit_rejects_missing_original_mailbox_marker(self, tmp_path: Path) -> None:
        from components.audit import audit_export
        from components.models import Account, Config, ServerConfig

        server = ServerConfig("imap.example.com")
        folder = tmp_path / "user@example.com" / "Sent_Items"
        _write_legacy_message_fixture(
            folder,
            mailbox="Sent Items",
            data=b"Message-ID: <sent@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody",
            source_server=server,
        )

        ok, issues = audit_export(
            tmp_path,
            Config(server, [Account("user@example.com", "secret")], source_server=server),
            1,
            check_remote=False,
            require_integrity_metadata=True,
        )

        assert not ok
        assert any("missing mailbox marker for original mailbox Sent Items" in issue for issue in issues)

    def test_verify_export_rejects_missing_original_mailbox_marker(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from verify_export import main, verify_account

        folder = tmp_path / "exported" / "user@example.com" / "Sent_Items"
        _write_legacy_message_fixture(
            folder,
            mailbox="Sent Items",
            data=b"Message-ID: <sent@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody",
        )
        monkeypatch.chdir(tmp_path)

        stats = verify_account(tmp_path / "exported" / "user@example.com")
        output = capsys.readouterr().out

        assert stats["errors"] == 1
        assert "Sent_Items/u0000000001.eml: missing mailbox marker for original mailbox Sent Items" in output
        assert main() == 1

    def test_strict_audit_rejects_marker_sidecar_original_mailbox_mismatch(self, tmp_path: Path) -> None:
        from components.audit import audit_export
        from components.models import Account, Config, ServerConfig

        server = ServerConfig("imap.example.com")
        folder = tmp_path / "user@example.com" / "A_B"
        _write_legacy_message_fixture(
            folder,
            mailbox="A/B",
            data=b"Message-ID: <alias@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody",
            source_server=server,
        )
        (folder / ".mailbox.json").write_text(json.dumps({"mailbox": "A_B", "message_count": 1}))

        ok, issues = audit_export(
            tmp_path,
            Config(server, [Account("user@example.com", "secret")], source_server=server),
            1,
            check_remote=False,
            require_integrity_metadata=True,
        )

        assert not ok
        assert any("mailbox metadata mismatch (marker=A_B meta=A/B)" in issue for issue in issues)

    def test_verify_export_rejects_marker_sidecar_original_mailbox_mismatch(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from verify_export import main, verify_account

        folder = tmp_path / "exported" / "user@example.com" / "A_B"
        _write_legacy_message_fixture(
            folder,
            mailbox="A/B",
            data=b"Message-ID: <alias@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody",
        )
        (folder / ".mailbox.json").write_text(json.dumps({"mailbox": "A_B", "message_count": 1}))
        monkeypatch.chdir(tmp_path)

        stats = verify_account(tmp_path / "exported" / "user@example.com")
        output = capsys.readouterr().out

        assert stats["errors"] == 1
        assert "A_B/u0000000001.eml: mailbox metadata mismatch (marker=A_B meta=A/B)" in output
        assert main() == 1

    def test_legacy_export_rejects_symlinked_output_root_before_connect(self, tmp_path: Path) -> None:
        from components.imap_ops import export_account
        from components.models import Account, ServerConfig

        outside = tmp_path / "outside-output"
        outside.mkdir()
        out_root = tmp_path / "exported"
        try:
            out_root.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")

        with mock.patch("components.imap_ops.imap_connection", side_effect=AssertionError("IMAP should not be opened")):
            with pytest.raises(RuntimeError, match="symlinked legacy export root"):
                export_account(
                    Account("user@example.com", "secret"),
                    ServerConfig("imap.example.com"),
                    out_root,
                    ignore_errors=False,
                )

        assert not (outside / "user@example.com").exists()

    def test_main_rejects_legacy_symlinked_output_root_before_connectivity(self, tmp_path: Path) -> None:
        from components.main import main

        config_path = tmp_path / "export.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "user@example.com", "password": "secret"}],
        }))
        outside = tmp_path / "outside-output"
        outside.mkdir()
        out_root = tmp_path / "exported"
        try:
            out_root.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.utils.ensure_imapsync_available", side_effect=AssertionError("imapsync check should not run")), \
            mock.patch("components.main.test_accounts", side_effect=AssertionError("connectivity should not run")):
            rc = main([
                "--mode", "export",
                "--config", str(config_path),
                "--output-dir", str(out_root),
                "--log-dir", str(tmp_path / "logs-export"),
                "--min-free-gb", "0",
                "--max-workers", "1",
            ])

        assert rc == 2
        assert not (outside / "user@example.com").exists()

    def test_main_rejects_legacy_hidden_symlinked_output_root_before_preflight_side_effects(self, tmp_path: Path) -> None:
        from components.main import main

        config_path = tmp_path / "export.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "user@example.com", "password": "secret"}],
        }))
        outside = tmp_path / "outside-output"
        outside.mkdir()
        link_root = tmp_path / "exported"
        try:
            link_root.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")
        out_root = tmp_path / "missing" / ".." / "exported"
        assert not out_root.exists()
        assert not out_root.is_symlink()
        events: List[str] = []

        def record_free_space(*_args, **_kwargs) -> None:
            events.append("free-space")

        def record_imapsync_check() -> None:
            events.append("imapsync")

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path", record_free_space), \
            mock.patch("components.utils.ensure_imapsync_available", record_imapsync_check), \
            mock.patch("components.main.test_accounts", side_effect=AssertionError("connectivity should not run")):
            rc = main([
                "--mode", "export",
                "--config", str(config_path),
                "--output-dir", str(out_root),
                "--log-dir", str(tmp_path / "logs-hidden-export"),
                "--min-free-gb", "0",
                "--max-workers", "1",
            ])

        assert rc == 2
        assert events == []
        assert not (tmp_path / "missing").exists()
        assert not (outside / "user@example.com").exists()

    def test_main_rejects_legacy_symlinked_output_root_ancestor_before_connectivity(self, tmp_path: Path) -> None:
        from components.main import main

        config_path = tmp_path / "export.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "user@example.com", "password": "secret"}],
        }))
        outside = tmp_path / "outside-output"
        outside.mkdir()
        link_root = tmp_path / "link-output"
        try:
            link_root.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")
        out_root = link_root / "exported"
        assert not out_root.is_symlink()

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.utils.ensure_imapsync_available", side_effect=AssertionError("imapsync check should not run")), \
            mock.patch("components.main.test_accounts", side_effect=AssertionError("connectivity should not run")):
            rc = main([
                "--mode", "export",
                "--config", str(config_path),
                "--output-dir", str(out_root),
                "--log-dir", str(tmp_path / "logs-export-ancestor"),
                "--min-free-gb", "0",
                "--max-workers", "1",
            ])

        assert rc == 2
        assert not (outside / "exported" / "user@example.com").exists()

    def test_main_rejects_legacy_nested_output_symlink_before_preflight_side_effects(self, tmp_path: Path) -> None:
        from components.main import main

        config_path = tmp_path / "export.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "user@example.com", "password": "secret"}],
        }))
        out_root = tmp_path / "exported"
        account_dir = out_root / "user@example.com"
        victim = tmp_path / "outside-inbox"
        victim.mkdir()
        account_dir.mkdir(parents=True)
        try:
            (account_dir / "INBOX").symlink_to(victim, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")
        events: List[str] = []

        def record_free_space(*_args, **_kwargs) -> None:
            events.append("free-space")

        def record_imapsync_check() -> None:
            events.append("imapsync")

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path", record_free_space), \
            mock.patch("components.utils.ensure_imapsync_available", record_imapsync_check), \
            mock.patch("components.main.test_accounts", side_effect=AssertionError("connectivity should not run")), \
            mock.patch("components.main.export_account", side_effect=AssertionError("export should not run")):
            rc = main([
                "--mode", "export",
                "--config", str(config_path),
                "--output-dir", str(out_root),
                "--log-dir", str(tmp_path / "logs-nested-export-symlink"),
                "--min-free-gb", "0",
                "--max-workers", "1",
            ])

        assert rc == 2
        assert events == []
        assert not (account_dir / "export-state.json").exists()

    def test_main_rejects_legacy_broken_account_output_symlink_before_preflight_side_effects(self, tmp_path: Path) -> None:
        from components.main import main

        config_path = tmp_path / "export.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "user@example.com", "password": "secret"}],
        }))
        out_root = tmp_path / "exported"
        out_root.mkdir()
        account_dir = out_root / "user@example.com"
        try:
            account_dir.symlink_to(tmp_path / "missing-account", target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")
        assert not account_dir.exists()
        assert account_dir.is_symlink()
        events: List[str] = []

        def record_free_space(*_args, **_kwargs) -> None:
            events.append("free-space")

        def record_imapsync_check() -> None:
            events.append("imapsync")

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path", record_free_space), \
            mock.patch("components.utils.ensure_imapsync_available", record_imapsync_check), \
            mock.patch("components.main.test_accounts", side_effect=AssertionError("connectivity should not run")), \
            mock.patch("components.main.export_account", side_effect=AssertionError("export should not run")):
            rc = main([
                "--mode", "export",
                "--config", str(config_path),
                "--output-dir", str(out_root),
                "--log-dir", str(tmp_path / "logs-broken-account-symlink"),
                "--min-free-gb", "0",
                "--max-workers", "1",
            ])

        assert rc == 2
        assert events == []

    def test_main_rejects_legacy_file_output_root_before_connectivity(self, tmp_path: Path) -> None:
        from components.main import main

        config_path = tmp_path / "export.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "user@example.com", "password": "secret"}],
        }))
        out_root = tmp_path / "exported"
        out_root.write_text("not a directory\n", encoding="utf-8")

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.utils.ensure_imapsync_available", side_effect=AssertionError("imapsync check should not run")), \
            mock.patch("components.main.test_accounts", side_effect=AssertionError("connectivity should not run")), \
            mock.patch("components.main.export_account", side_effect=AssertionError("export should not run")):
            rc = main([
                "--mode", "export",
                "--config", str(config_path),
                "--output-dir", str(out_root),
                "--log-dir", str(tmp_path / "logs-export-file"),
                "--min-free-gb", "0",
                "--max-workers", "1",
            ])

        assert rc == 2

    def test_strict_audit_rejects_symlinked_input_root(self, tmp_path: Path) -> None:
        from components.audit import audit_export
        from components.models import Account, Config, ServerConfig

        server = ServerConfig("imap.example.com")
        outside = tmp_path / "outside-input"
        _write_legacy_message_fixture(outside / "user@example.com" / "INBOX", source_server=server)
        in_root = tmp_path / "exported"
        try:
            in_root.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")

        ok, issues = audit_export(
            in_root,
            Config(server, [Account("user@example.com", "secret")], source_server=server),
            1,
            check_remote=False,
            require_integrity_metadata=True,
        )

        assert not ok
        assert any("audit root is a symlink" in issue for issue in issues)

    def test_strict_audit_rejects_symlinked_input_root_ancestor(self, tmp_path: Path) -> None:
        from components.audit import audit_export
        from components.models import Account, Config, ServerConfig

        server = ServerConfig("imap.example.com")
        outside = tmp_path / "outside-input"
        staged = outside / "staged"
        _write_legacy_message_fixture(staged / "user@example.com" / "INBOX", source_server=server)
        link_root = tmp_path / "link-input"
        try:
            link_root.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")
        in_root = link_root / "staged"
        assert not in_root.is_symlink()

        ok, issues = audit_export(
            in_root,
            Config(server, [Account("user@example.com", "secret")], source_server=server),
            1,
            check_remote=False,
            require_integrity_metadata=True,
        )

        assert not ok
        assert any("audit root is a symlink" in issue for issue in issues)

    def test_legacy_import_rejects_symlinked_input_root_before_connect(self, tmp_path: Path) -> None:
        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        outside = tmp_path / "outside-input"
        _write_legacy_message_fixture(outside / "user@example.com" / "INBOX")
        in_root = tmp_path / "exported"
        try:
            in_root.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")

        with pytest.raises(RuntimeError, match="symlinked legacy import root"):
            import_account(
                Account("user@example.com", "secret"),
                ServerConfig("imap.example.com"),
                in_root,
                ignore_errors=False,
                imap_factory=lambda *_args: (_ for _ in ()).throw(AssertionError("IMAP should not be opened")),
            )

    def test_legacy_export_rejects_symlinked_output_root_ancestor_before_connect(self, tmp_path: Path) -> None:
        from components.imap_ops import export_account
        from components.models import Account, ServerConfig

        outside = tmp_path / "outside-output"
        outside.mkdir()
        link_root = tmp_path / "link-output"
        try:
            link_root.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")
        out_root = link_root / "exported"
        assert not out_root.is_symlink()

        with mock.patch("components.imap_ops.imap_connection", side_effect=AssertionError("IMAP should not be opened")):
            with pytest.raises(RuntimeError, match="symlinked legacy export root"):
                export_account(
                    Account("user@example.com", "secret"),
                    ServerConfig("imap.example.com"),
                    out_root,
                    ignore_errors=False,
                )

        assert not (outside / "exported" / "user@example.com").exists()

    def test_legacy_import_rejects_symlinked_input_root_ancestor_before_connect(self, tmp_path: Path) -> None:
        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        outside = tmp_path / "outside-input"
        staged = outside / "staged"
        _write_legacy_message_fixture(staged / "user@example.com" / "INBOX")
        link_root = tmp_path / "link-input"
        try:
            link_root.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")
        in_root = link_root / "staged"
        assert not in_root.is_symlink()

        with pytest.raises(RuntimeError, match="symlinked legacy import root"):
            import_account(
                Account("user@example.com", "secret"),
                ServerConfig("imap.example.com"),
                in_root,
                ignore_errors=False,
                imap_factory=lambda *_args: (_ for _ in ()).throw(AssertionError("IMAP should not be opened")),
            )

    @pytest.mark.parametrize("mode", ["import", "validate"])
    def test_main_rejects_legacy_symlinked_input_root_before_connectivity(
        self,
        tmp_path: Path,
        mode: str,
    ) -> None:
        from components.main import main

        config_path = tmp_path / "import.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "user@example.com", "password": "secret"}],
        }))
        outside = tmp_path / "outside-input"
        _write_legacy_message_fixture(outside / "user@example.com" / "INBOX")
        in_root = tmp_path / "exported"
        try:
            in_root.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.utils.ensure_imapsync_available", side_effect=AssertionError("imapsync check should not run")), \
            mock.patch("components.main.test_accounts", side_effect=AssertionError("connectivity should not run")):
            rc = main([
                "--mode", mode,
                "--config", str(config_path),
                "--input-dir", str(in_root),
                "--log-dir", str(tmp_path / f"logs-{mode}"),
                "--min-free-gb", "0",
                "--max-workers", "1",
            ])

        assert rc == 2

    @pytest.mark.parametrize("mode", ["import", "validate"])
    def test_main_rejects_legacy_symlinked_input_root_ancestor_before_connectivity(
        self,
        tmp_path: Path,
        mode: str,
    ) -> None:
        from components.main import main

        config_path = tmp_path / "import.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "user@example.com", "password": "secret"}],
        }))
        outside = tmp_path / "outside-input"
        staged = outside / "staged"
        _write_legacy_message_fixture(staged / "user@example.com" / "INBOX")
        link_root = tmp_path / "link-input"
        try:
            link_root.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")
        in_root = link_root / "staged"
        assert not in_root.is_symlink()

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.utils.ensure_imapsync_available", side_effect=AssertionError("imapsync check should not run")), \
            mock.patch("components.main.test_accounts", side_effect=AssertionError("connectivity should not run")):
            rc = main([
                "--mode", mode,
                "--config", str(config_path),
                "--input-dir", str(in_root),
                "--log-dir", str(tmp_path / f"logs-ancestor-{mode}"),
                "--min-free-gb", "0",
                "--max-workers", "1",
            ])

        assert rc == 2

    @pytest.mark.parametrize("mode", ["import", "validate"])
    def test_main_rejects_legacy_file_input_root_before_connectivity(
        self,
        tmp_path: Path,
        mode: str,
    ) -> None:
        from components.main import main

        config_path = tmp_path / "import.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "user@example.com", "password": "secret"}],
        }))
        in_root = tmp_path / "exported"
        in_root.write_text("not a directory\n", encoding="utf-8")

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.utils.ensure_imapsync_available", side_effect=AssertionError("imapsync check should not run")), \
            mock.patch("components.main.test_accounts", side_effect=AssertionError("connectivity should not run")):
            rc = main([
                "--mode", mode,
                "--config", str(config_path),
                "--input-dir", str(in_root),
                "--log-dir", str(tmp_path / f"logs-file-root-{mode}"),
                "--min-free-gb", "0",
                "--max-workers", "1",
            ])

        assert rc == 2

    @pytest.mark.parametrize("mode", ["import", "validate"])
    def test_main_rejects_legacy_symlinked_staged_account_before_connectivity(
        self,
        tmp_path: Path,
        mode: str,
    ) -> None:
        from components.main import main

        config_path = tmp_path / "import.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "user@example.com", "password": "secret"}],
        }))
        in_root = tmp_path / "exported"
        in_root.mkdir()
        outside_account = tmp_path / "outside-account"
        _write_legacy_message_fixture(outside_account / "INBOX")
        try:
            (in_root / "user@example.com").symlink_to(outside_account, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.utils.ensure_imapsync_available", side_effect=AssertionError("imapsync check should not run")), \
            mock.patch("components.main.test_accounts", side_effect=AssertionError("connectivity should not run")):
            rc = main([
                "--mode", mode,
                "--config", str(config_path),
                "--input-dir", str(in_root),
                "--log-dir", str(tmp_path / f"logs-account-{mode}"),
                "--min-free-gb", "0",
                "--max-workers", "1",
            ])

        assert rc == 2

    @pytest.mark.parametrize("mode", ["import", "validate"])
    def test_main_rejects_legacy_file_staged_account_before_connectivity(
        self,
        tmp_path: Path,
        mode: str,
    ) -> None:
        from components.main import main

        config_path = tmp_path / "import.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "user@example.com", "password": "secret"}],
        }))
        in_root = tmp_path / "exported"
        in_root.mkdir()
        (in_root / "user@example.com").write_text("not a directory\n", encoding="utf-8")

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.utils.ensure_imapsync_available", side_effect=AssertionError("imapsync check should not run")), \
            mock.patch("components.main.test_accounts", side_effect=AssertionError("connectivity should not run")):
            rc = main([
                "--mode", mode,
                "--config", str(config_path),
                "--input-dir", str(in_root),
                "--log-dir", str(tmp_path / f"logs-account-file-{mode}"),
                "--min-free-gb", "0",
                "--max-workers", "1",
            ])

        assert rc == 2

    @pytest.mark.parametrize("mode", ["import", "validate"])
    def test_main_rejects_legacy_wrong_source_export_state_before_connectivity(
        self,
        tmp_path: Path,
        mode: str,
    ) -> None:
        from components.main import main
        from components.models import ServerConfig

        expected_source = ServerConfig("expected-source.example.com")
        actual_source = ServerConfig("actual-source.example.com")
        config_path = tmp_path / "import.json"
        config_path.write_text(json.dumps({
            "server": {"host": "target.example.com", "port": 993, "ssl": True, "starttls": False},
            "source_server": {
                "host": expected_source.host,
                "port": expected_source.port,
                "ssl": expected_source.ssl,
                "starttls": expected_source.starttls,
            },
            "accounts": [{"email": "user@example.com", "password": "secret"}],
        }))
        in_root = tmp_path / "exported"
        folder = in_root / "user@example.com" / "INBOX"
        _write_legacy_message_fixture(
            folder,
            data=b"Message-ID: <wrong-source-cli@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody",
            source_server=actual_source,
        )
        (folder / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": 1}))

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.utils.ensure_imapsync_available", side_effect=AssertionError("imapsync check should not run")), \
            mock.patch("components.main.test_accounts", side_effect=AssertionError("connectivity should not run")):
            rc = main([
                "--mode", mode,
                "--config", str(config_path),
                "--input-dir", str(in_root),
                "--log-dir", str(tmp_path / f"logs-wrong-source-{mode}"),
                "--min-free-gb", "0",
                "--max-workers", "1",
            ])

        assert rc == 4

    @pytest.mark.parametrize("mode", ["import", "validate"])
    def test_main_rejects_legacy_symlinked_staged_mailbox_before_connectivity(
        self,
        tmp_path: Path,
        mode: str,
    ) -> None:
        from components.main import main

        config_path = tmp_path / "import.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "user@example.com", "password": "secret"}],
        }))
        in_root = tmp_path / "exported"
        account_dir = in_root / "user@example.com"
        account_dir.mkdir(parents=True)
        outside_mailbox = tmp_path / "outside-mailbox"
        _write_legacy_message_fixture(outside_mailbox)
        try:
            (account_dir / "INBOX").symlink_to(outside_mailbox, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.utils.ensure_imapsync_available", side_effect=AssertionError("imapsync check should not run")), \
            mock.patch("components.main.test_accounts", side_effect=AssertionError("connectivity should not run")):
            rc = main([
                "--mode", mode,
                "--config", str(config_path),
                "--input-dir", str(in_root),
                "--log-dir", str(tmp_path / f"logs-mailbox-{mode}"),
                "--min-free-gb", "0",
                "--max-workers", "1",
            ])

        assert rc == 2

    def test_legacy_export_rejects_symlinked_mailbox_directory(self, tmp_path: Path) -> None:
        from components.imap_ops import export_account
        from components.models import Account, ServerConfig

        out_root = tmp_path / "exported"
        account_dir = out_root / "user@example.com"
        account_dir.mkdir(parents=True)
        victim = tmp_path / "victim"
        victim.mkdir()
        (victim / "stale.eml").write_bytes(b"do not delete")
        try:
            (account_dir / "INBOX").symlink_to(victim, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")

        class EmptyInbox:
            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"0"]

            def uid(self, command: str, *args):
                return "OK", [b""]

            def logout(self):
                return "OK", []

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[EmptyInbox]:
            yield EmptyInbox()

        with mock.patch("components.imap_ops.imap_connection", fake_connection):
            with pytest.raises(RuntimeError, match="output path is a symlink"):
                export_account(
                    Account("user@example.com", "secret"),
                    ServerConfig("imap.example.com"),
                    out_root,
                    ignore_errors=False,
                )

        assert (victim / "stale.eml").exists()
        assert not (victim / ".mailbox.json").exists()

    def test_legacy_export_rejects_preexisting_nested_output_symlink_before_source_contact(self, tmp_path: Path) -> None:
        from components.imap_ops import export_account
        from components.models import Account, ServerConfig

        out_root = tmp_path / "exported"
        account_dir = out_root / "user@example.com"
        victim = tmp_path / "outside-inbox"
        victim.mkdir()
        account_dir.mkdir(parents=True)
        try:
            (account_dir / "INBOX").symlink_to(victim, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")

        with mock.patch("components.imap_ops.imap_connection", side_effect=AssertionError("source should not be contacted")):
            with pytest.raises(RuntimeError, match="output path is a symlink"):
                export_account(
                    Account("user@example.com", "secret"),
                    ServerConfig("imap.example.com"),
                    out_root,
                    ignore_errors=False,
                )

        assert not (account_dir / "export-state.json").exists()

    def test_legacy_import_rejects_symlinked_import_journal(self, tmp_path: Path) -> None:
        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        folder = tmp_path / "user@example.com" / "INBOX"
        _write_legacy_message_fixture(
            folder,
            data=b"Message-ID: <m@example.com>\r\nFrom: a@example.com\r\nTo: b@example.com\r\n\r\nbody",
        )
        victim = tmp_path / "victim.journal.jsonl"
        victim.write_text("")
        try:
            (tmp_path / "user@example.com" / "import.journal.jsonl").symlink_to(victim)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")

        with pytest.raises(RuntimeError, match="symlinked legacy import journal"):
            import_account(
                Account("user@example.com", "secret"),
                ServerConfig("imap.example.com"),
                tmp_path,
                ignore_errors=False,
            )

        assert victim.read_text() == ""

    def test_legacy_append_import_journal_rejects_hard_linked_journal(self, tmp_path: Path) -> None:
        from components.imap_ops import _append_legacy_import_journal

        account_dir = tmp_path / "user@example.com"
        account_dir.mkdir()
        victim = tmp_path / "victim-hardlink.jsonl"
        victim.write_text("")
        journal = account_dir / "import.journal.jsonl"
        try:
            journal.hardlink_to(victim)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"hard link creation unavailable: {exc}")

        with pytest.raises(RuntimeError, match="hard-linked legacy import journal"):
            _append_legacy_import_journal(account_dir, {
                "key": "k",
                "status": "pending",
                "target": "imap://target",
                "mailbox": "INBOX",
                "path": "INBOX/u0000000001.eml",
                "timestamp": "0",
            })

        assert victim.read_text() == ""

    def test_legacy_append_import_journal_rejects_non_regular_journal_with_reader(self, tmp_path: Path) -> None:
        from components.imap_ops import _append_legacy_import_journal

        account_dir = tmp_path / "user@example.com"
        account_dir.mkdir()
        journal = account_dir / "import.journal.jsonl"
        _mkfifo_or_skip(journal)
        reader_fd = os.open(journal, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        try:
            with pytest.raises(RuntimeError, match="non-regular legacy import journal"):
                _append_legacy_import_journal(account_dir, {
                    "key": "k",
                    "status": "pending",
                    "target": "imap://target",
                    "mailbox": "INBOX",
                    "path": "INBOX/u0000000001.eml",
                    "timestamp": "0",
                })
            assert os.read(reader_fd, 4096) == b""
        finally:
            os.close(reader_fd)

    def test_legacy_append_import_journal_rejects_non_regular_journal_without_reader(self, tmp_path: Path) -> None:
        from components.imap_ops import _append_legacy_import_journal

        account_dir = tmp_path / "user@example.com"
        account_dir.mkdir()
        journal = account_dir / "import.journal.jsonl"
        _mkfifo_or_skip(journal)
        result: queue.Queue[tuple[str, str]] = queue.Queue()

        def append_journal() -> None:
            try:
                _append_legacy_import_journal(account_dir, {
                    "key": "k",
                    "status": "pending",
                    "target": "imap://target",
                    "mailbox": "INBOX",
                    "path": "INBOX/u0000000001.eml",
                    "timestamp": "0",
                })
            except BaseException as exc:
                result.put(("raised", str(exc)))
            else:
                result.put(("returned", ""))

        thread = threading.Thread(target=append_journal, daemon=True)
        thread.start()
        thread.join(1)
        if thread.is_alive():
            reader_fd = os.open(journal, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
            os.close(reader_fd)
            thread.join(1)
            pytest.fail("legacy import journal append blocked on FIFO")
        status, message = result.get_nowait()
        assert status == "raised"
        assert "non-regular legacy import journal" in message

    def test_legacy_atomic_write_does_not_chmod_replaced_symlink_target(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from components import imap_ops

        target = tmp_path / "user@example.com" / "export-state.json"
        victim = tmp_path / "victim.json"
        victim.write_text("outside\n")
        victim.chmod(0o644)
        original_mode = victim.stat().st_mode & 0o777
        real_rename = imap_ops.os.rename

        def racing_rename(src, dst, *args, **kwargs):
            result = real_rename(src, dst, *args, **kwargs)
            target.unlink()
            try:
                target.symlink_to(victim)
            except (OSError, NotImplementedError) as exc:
                pytest.skip(f"symlink creation unavailable: {exc}")
            return result

        monkeypatch.setattr(imap_ops.os, "rename", racing_rename)

        imap_ops._secure_atomic_write_bytes(target, b'{"complete": false}\n')

        assert target.is_symlink()
        assert victim.stat().st_mode & 0o777 == original_mode

    def test_legacy_append_journal_does_not_chmod_replaced_symlink_target(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from components import imap_ops

        account_dir = tmp_path / "user@example.com"
        account_dir.mkdir()
        journal = account_dir / "import.journal.jsonl"
        victim = tmp_path / "victim.journal.jsonl"
        victim.write_text("outside\n")
        victim.chmod(0o644)
        original_mode = victim.stat().st_mode & 0o777
        real_fdopen = imap_ops.os.fdopen

        def racing_fdopen(*args, **kwargs):
            file_cm = real_fdopen(*args, **kwargs)

            class RacingFile:
                def __enter__(self):
                    return file_cm.__enter__()

                def __exit__(self, exc_type, exc, tb):
                    result = file_cm.__exit__(exc_type, exc, tb)
                    journal.unlink()
                    try:
                        journal.symlink_to(victim)
                    except (OSError, NotImplementedError) as symlink_exc:
                        pytest.skip(f"symlink creation unavailable: {symlink_exc}")
                    return result

            return RacingFile()

        monkeypatch.setattr(imap_ops.os, "fdopen", racing_fdopen)

        imap_ops._append_legacy_import_journal(account_dir, {
            "key": "k",
            "status": "pending",
            "target": "imap://target",
            "mailbox": "INBOX",
            "path": "INBOX/u0000000001.eml",
            "timestamp": "0",
        })

        assert journal.is_symlink()
        assert victim.stat().st_mode & 0o777 == original_mode

    def test_legacy_ensure_private_dir_rejects_symlink_inserted_during_mkdir(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from components import imap_ops

        base = tmp_path / "base"
        outside = tmp_path / "outside-legacy-dir"
        base.mkdir()
        outside.mkdir()
        target_dir = base / "account" / "INBOX"
        real_mkdir = imap_ops.os.mkdir
        swapped = False

        def racing_mkdir(path, mode=0o777, *args, **kwargs):
            nonlocal swapped
            if path == "account" and kwargs.get("dir_fd") is not None and not swapped:
                try:
                    (base / "account").symlink_to(outside, target_is_directory=True)
                except (OSError, NotImplementedError) as exc:
                    pytest.skip(f"symlink creation unavailable: {exc}")
                swapped = True
            return real_mkdir(path, mode, *args, **kwargs)

        monkeypatch.setattr(imap_ops.os, "mkdir", racing_mkdir)

        with pytest.raises(RuntimeError, match="symlinked directory|replaced directory"):
            imap_ops.ensure_private_dir(target_dir)

        assert swapped
        assert (base / "account").is_symlink()
        assert not (outside / "INBOX").exists()

    def test_provider_ensure_private_dir_rejects_symlink_inserted_during_mkdir(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from components import provider_ops

        base = tmp_path / "base"
        outside = tmp_path / "outside-provider-dir"
        base.mkdir()
        outside.mkdir()
        target_dir = base / "account" / "messages"
        real_mkdir = provider_ops.os.mkdir
        swapped = False

        def racing_mkdir(path, mode=0o777, *args, **kwargs):
            nonlocal swapped
            if path == "account" and kwargs.get("dir_fd") is not None and not swapped:
                try:
                    (base / "account").symlink_to(outside, target_is_directory=True)
                except (OSError, NotImplementedError) as exc:
                    pytest.skip(f"symlink creation unavailable: {exc}")
                swapped = True
            return real_mkdir(path, mode, *args, **kwargs)

        monkeypatch.setattr(provider_ops.os, "mkdir", racing_mkdir)

        with pytest.raises(RuntimeError, match="symlinked provider directory|replaced provider directory"):
            provider_ops.ensure_private_dir(target_dir)

        assert swapped
        assert (base / "account").is_symlink()
        assert not (outside / "messages").exists()

    def test_setup_logging_rejects_symlink_inserted_during_mkdir(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from components import imap_ops
        from components.main import setup_logging

        base = tmp_path / "base"
        outside = tmp_path / "outside-log-dir"
        base.mkdir()
        outside.mkdir()
        log_dir = base / "logs" / "run"
        real_mkdir = imap_ops.os.mkdir
        swapped = False

        def racing_mkdir(path, mode=0o777, *args, **kwargs):
            nonlocal swapped
            if path == "logs" and kwargs.get("dir_fd") is not None and not swapped:
                try:
                    (base / "logs").symlink_to(outside, target_is_directory=True)
                except (OSError, NotImplementedError) as exc:
                    pytest.skip(f"symlink creation unavailable: {exc}")
                swapped = True
            return real_mkdir(path, mode, *args, **kwargs)

        monkeypatch.setattr(imap_ops.os, "mkdir", racing_mkdir)

        with pytest.raises(RuntimeError, match="symlinked log directory|replaced log directory"):
            setup_logging(log_dir)

        assert swapped
        assert (base / "logs").is_symlink()
        assert not (outside / "run").exists()

    def test_legacy_import_rejects_hard_linked_import_journal(self, tmp_path: Path) -> None:
        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        folder = tmp_path / "user@example.com" / "INBOX"
        _write_legacy_message_fixture(
            folder,
            data=b"Message-ID: <m@example.com>\r\nFrom: a@example.com\r\nTo: b@example.com\r\n\r\nbody",
        )
        victim = tmp_path / "victim-hardlink.jsonl"
        victim.write_text("")
        journal = tmp_path / "user@example.com" / "import.journal.jsonl"
        try:
            journal.hardlink_to(victim)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"hard link creation unavailable: {exc}")

        with pytest.raises(RuntimeError, match="hard-linked legacy import journal"):
            import_account(
                Account("user@example.com", "secret"),
                ServerConfig("imap.example.com"),
                tmp_path,
                ignore_errors=False,
            )

        assert victim.read_text() == ""

    def test_reset_journal_archive_rejects_hard_linked_import_journal(self, tmp_path: Path) -> None:
        from components.imap_ops import archive_legacy_import_journal_for_reset

        account_dir = tmp_path / "user@example.com"
        account_dir.mkdir()
        victim = tmp_path / "outside-journal.jsonl"
        victim.write_text(json.dumps({
            "key": "a" * 64,
            "target": "b" * 64,
            "mailbox": "INBOX",
            "path": "INBOX/u0000000001.eml",
            "status": "committed",
        }) + "\n")
        journal = account_dir / "import.journal.jsonl"
        try:
            journal.hardlink_to(victim)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"hard link creation unavailable: {exc}")

        with pytest.raises(RuntimeError, match="hard-linked legacy import journal"):
            archive_legacy_import_journal_for_reset(account_dir)

        assert journal.exists()
        assert victim.exists()
        assert journal.stat().st_ino == victim.stat().st_ino

    def test_reset_journal_archive_rejects_symlinked_account_path(self, tmp_path: Path) -> None:
        from components.imap_ops import archive_legacy_import_journal_for_reset

        real_account_dir = tmp_path / "real-account"
        real_account_dir.mkdir()
        (real_account_dir / "import.journal.jsonl").write_text(json.dumps({
            "key": "a" * 64,
            "target": "b" * 64,
            "mailbox": "INBOX",
            "path": "INBOX/u0000000001.eml",
            "status": "committed",
        }) + "\n")
        account_dir = tmp_path / "user@example.com"
        try:
            account_dir.symlink_to(real_account_dir, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")

        with pytest.raises(RuntimeError, match="symlinked legacy account directory"):
            archive_legacy_import_journal_for_reset(account_dir)

        assert (real_account_dir / "import.journal.jsonl").exists()
        assert not list(real_account_dir.glob("import.journal.reset-*.jsonl"))

    def test_reset_journal_archive_rejects_account_dir_swap_after_validation(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from components import imap_ops

        row = {
            "key": "a" * 64,
            "target": "b" * 64,
            "mailbox": "INBOX",
            "path": "INBOX/u0000000001.eml",
            "status": "committed",
        }
        account_dir = tmp_path / "user@example.com"
        account_dir.mkdir()
        (account_dir / "import.journal.jsonl").write_text(json.dumps(row) + "\n")
        outside = tmp_path / "outside-account"
        outside.mkdir()
        (outside / "import.journal.jsonl").write_text(json.dumps(row) + "\n")
        checked_account_dir = tmp_path / "checked-account"
        real_load = imap_ops._load_legacy_import_journal
        swapped = False

        def racing_load(path: Path, *args, **kwargs):
            nonlocal swapped
            result = real_load(path, *args, **kwargs)
            if path == account_dir and not swapped:
                account_dir.rename(checked_account_dir)
                try:
                    account_dir.symlink_to(outside, target_is_directory=True)
                except (OSError, NotImplementedError) as exc:
                    pytest.skip(f"symlink creation unavailable: {exc}")
                swapped = True
            return result

        monkeypatch.setattr(imap_ops, "_load_legacy_import_journal", racing_load)

        with pytest.raises(RuntimeError, match="replaced legacy import journal directory"):
            imap_ops.archive_legacy_import_journal_for_reset(account_dir)

        assert swapped
        assert account_dir.is_symlink()
        assert (outside / "import.journal.jsonl").exists()
        assert not list(outside.glob("import.journal.reset-*.jsonl"))
        assert (checked_account_dir / "import.journal.jsonl").exists()

    @pytest.mark.parametrize(
        ("field", "value", "needle"),
        [
            ("key", "not-a-sha256", "invalid key"),
            ("target", "not-a-sha256", "invalid target"),
            ("key", "A" * 64, "invalid key"),
            ("target", "B" * 64, "invalid target"),
        ],
    )
    def test_legacy_load_import_journal_rejects_malformed_digest_ids(
        self,
        tmp_path: Path,
        field: str,
        value: str,
        needle: str,
    ) -> None:
        from components.imap_ops import _load_legacy_import_journal

        account_dir = tmp_path / "user@example.com"
        account_dir.mkdir()
        row = {
            "key": "a" * 64,
            "target": "b" * 64,
            "mailbox": "INBOX",
            "path": "INBOX/u0000000001.eml",
            "status": "committed",
        }
        row[field] = value
        (account_dir / "import.journal.jsonl").write_text(json.dumps(row) + "\n")

        with pytest.raises(RuntimeError, match=needle):
            _load_legacy_import_journal(account_dir)

    @pytest.mark.parametrize(
        ("field", "value", "needle"),
        [
            ("key", "not-a-sha256", "invalid key"),
            ("target", "not-a-sha256", "invalid target"),
            ("key", "A" * 64, "invalid key"),
            ("target", "B" * 64, "invalid target"),
        ],
    )
    def test_legacy_import_rejects_malformed_journal_ids_before_target_contact(
        self,
        tmp_path: Path,
        field: str,
        value: str,
        needle: str,
    ) -> None:
        from components.imap_ops import _legacy_import_key, _legacy_import_target_id, import_account
        from components.models import Account, ServerConfig

        server = ServerConfig("imap.example.com", port=993, ssl=True, starttls=False)
        account = Account("user@example.com", "secret")
        folder = tmp_path / "user@example.com" / "INBOX"
        data = b"Message-ID: <malformed-journal-id@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody"
        eml = _write_legacy_message_fixture(folder, data=data)
        row = {
            "key": _legacy_import_key(folder.parent, eml, "INBOX", data),
            "target": _legacy_import_target_id(server, account),
            "mailbox": "INBOX",
            "path": "INBOX/u0000000001.eml",
            "status": "committed",
        }
        row[field] = value
        (folder.parent / "import.journal.jsonl").write_text(json.dumps(row) + "\n")
        opened = False

        @contextlib.contextmanager
        def fake_factory(*_args, **_kwargs) -> Iterator[object]:
            nonlocal opened
            opened = True
            raise AssertionError("target should not be contacted")
            yield object()

        with pytest.raises(RuntimeError, match=needle):
            import_account(
                account,
                server,
                tmp_path,
                ignore_errors=False,
                imap_factory=fake_factory,
            )

        assert opened is False

    def test_legacy_import_rerun_reappends_committed_wrong_internaldate(self, tmp_path: Path) -> None:
        from components.imap_ops import _legacy_import_key, _legacy_import_target_id, import_account
        from components.models import Account, ServerConfig

        server = ServerConfig("imap.example.com", port=993, ssl=True, starttls=False)
        account = Account("user@example.com", "secret")
        folder = tmp_path / "user@example.com" / "INBOX"
        data = b"Message-ID: <legacy-stale-date@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody"
        eml = _write_legacy_message_fixture(folder, data=data, source_server=server)
        (folder.parent / "import.journal.jsonl").write_text(json.dumps({
            "key": _legacy_import_key(folder.parent, eml, "INBOX", data),
            "target": _legacy_import_target_id(server, account),
            "mailbox": "INBOX",
            "path": "INBOX/u0000000001.eml",
            "status": "committed",
            "rfc822_size": str(len(data)),
            "content_sha256": hashlib.sha256(data).hexdigest(),
            "timestamp": "1",
        }) + "\n")

        class WrongDateTarget:
            def __init__(self) -> None:
                self.appended: List[Tuple[str, str, str, bytes]] = []

            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"1"]

            def subscribe(self, mailbox: str):
                return "OK", [b""]

            def search(self, charset, *criteria):
                return "OK", [b"1"]

            def fetch(self, num: bytes, query: str):
                return "OK", [(
                    b'1 (RFC822.SIZE '
                    + str(len(data)).encode("ascii")
                    + b' FLAGS (\\Seen) INTERNALDATE "02-Jan-2024 00:00:00 +0000" BODY[] {'
                    + str(len(data)).encode("ascii")
                    + b"}",
                    data,
                )]

            def append(self, mailbox: str, flags: str, date_time: str, payload: bytes):
                self.appended.append((mailbox, flags, date_time, payload))
                return "OK", [b""]

        target = WrongDateTarget()

        @contextlib.contextmanager
        def fake_factory(*_args, **_kwargs) -> Iterator[WrongDateTarget]:
            yield target

        import_account(
            account,
            server,
            tmp_path,
            ignore_errors=False,
            imap_factory=fake_factory,
            source_server=server,
        )

        assert len(target.appended) == 1
        assert target.appended[0][2] == '"01-Jan-2024 00:00:00 +0000"'
        assert target.appended[0][3] == data

    def test_legacy_validate_rejects_wrong_remote_internaldate(self, tmp_path: Path) -> None:
        from components.main import main
        from components.models import ServerConfig

        input_root = tmp_path / "exported"
        folder = input_root / "user@example.com" / "INBOX"
        server = ServerConfig("source.example.com", port=993, ssl=True, starttls=False)
        target_server = {"host": "target.example.com", "port": 993, "ssl": True, "starttls": False}
        data = b"Message-ID: <legacy-validate-date@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody"
        _write_legacy_message_fixture(folder, data=data, source_server=server)
        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": target_server,
            "source_server": {
                "host": server.host,
                "port": server.port,
                "ssl": server.ssl,
                "starttls": server.starttls,
            },
            "accounts": [{"email": "user@example.com", "password": "secret"}],
        }))

        class WrongDateTarget:
            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"1"]

            def search(self, charset, *criteria):
                return "OK", [b"1"]

            def fetch(self, num: bytes, query: str):
                return "OK", [(
                    b'1 (RFC822.SIZE '
                    + str(len(data)).encode("ascii")
                    + b' FLAGS (\\Seen) INTERNALDATE "02-Jan-2024 00:00:00 +0000" BODY[] {'
                    + str(len(data)).encode("ascii")
                    + b"}",
                    data,
                )]

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[WrongDateTarget]:
            yield WrongDateTarget()

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.main.audit_export", return_value=(True, [])), \
            mock.patch("components.imap_ops.imap_connection", fake_connection):
            rc = main([
                "--mode", "validate",
                "--config", str(config_path),
                "--input-dir", str(input_root),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--no-connectivity-test",
            ])

        assert rc == 4

    def test_legacy_audit_rejects_wrong_remote_internaldate(self, tmp_path: Path) -> None:
        from components.audit import audit_account
        from components.models import Account, ServerConfig

        server = ServerConfig("imap.example.com", port=993, ssl=True, starttls=False)
        folder = tmp_path / "user@example.com" / "INBOX"
        data = b"Message-ID: <legacy-audit-date@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody"
        _write_legacy_message_fixture(folder, data=data, source_server=server)

        class WrongDateTarget:
            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"1"]

            def uid(self, command: str, *args):
                if command == "search":
                    return "OK", [b"1"]
                raise AssertionError(command)

            def search(self, charset, *criteria):
                return "OK", [b"1"]

            def fetch(self, num: bytes, query: str):
                return "OK", [(
                    b'1 (RFC822.SIZE '
                    + str(len(data)).encode("ascii")
                    + b' FLAGS (\\Seen) INTERNALDATE "02-Jan-2024 00:00:00 +0000" BODY[] {'
                    + str(len(data)).encode("ascii")
                    + b"}",
                    data,
                )]

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[WrongDateTarget]:
            yield WrongDateTarget()

        with mock.patch("components.audit.imap_connection", fake_connection):
            _email, issues = audit_account(
                Account("user@example.com", "secret"),
                tmp_path,
                server=server,
                check_remote=True,
                require_integrity_metadata=True,
            )

        assert any("remote INTERNALDATE mismatch" in issue for issue in issues)

    def test_legacy_audit_rejects_covered_flagged_without_local_flag(self, tmp_path: Path) -> None:
        from components.audit import audit_account
        from components.models import Account, ServerConfig

        server = ServerConfig("imap.example.com", port=993, ssl=True, starttls=False)
        root = tmp_path / "exported"
        account_dir = root / "user@example.com"
        archive = account_dir / "Archive"
        data = b"Message-ID: <covered-flag-loss@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody"
        _write_legacy_message_fixture(archive, mailbox="Archive", data=data, flags="\\Seen", source_server=server)
        flagged = account_dir / "Flagged"
        flagged.mkdir()
        (flagged / ".mailbox.json").write_text(json.dumps({
            "mailbox": "Flagged",
            "message_count": 0,
            "covered_by_regular_content": True,
        }))

        class FlaggedTarget:
            selected = "Archive"

            def list(self, *_args):
                return "OK", [
                    b'(\\HasNoChildren) "/" "Archive"',
                    b'(\\HasNoChildren \\Flagged) "/" "Flagged"',
                ]

            def select(self, mailbox: str, readonly: bool = False):
                self.selected = mailbox.strip('"')
                return "OK", [b"1"]

            def uid(self, command: str, *args):
                if command == "search":
                    return "OK", [b"1"]
                raise AssertionError(command)

            def search(self, charset, *criteria):
                return "OK", [b"1"]

            def fetch(self, num: bytes, query: str):
                flags = b"\\Seen \\Flagged" if self.selected == "Flagged" else b"\\Seen"
                return "OK", [(
                    b"1 (RFC822.SIZE "
                    + str(len(data)).encode("ascii")
                    + b" FLAGS ("
                    + flags
                    + b') INTERNALDATE "01-Jan-2024 00:00:00 +0000" BODY[] {'
                    + str(len(data)).encode("ascii")
                    + b"}",
                    data,
                )]

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[FlaggedTarget]:
            yield FlaggedTarget()

        with mock.patch("components.audit.imap_connection", fake_connection):
            _email, issues = audit_account(
                Account("user@example.com", "secret"),
                root,
                server=server,
                check_remote=True,
                require_integrity_metadata=True,
            )

        assert any("Flagged: local=0 remote=1 mismatch" in issue for issue in issues)

    def test_legacy_validate_rejects_covered_flagged_without_local_flag(self, tmp_path: Path) -> None:
        from components.main import main
        from components.models import ServerConfig

        server = ServerConfig("imap.example.com", port=993, ssl=True, starttls=False)
        input_root = tmp_path / "exported"
        account_dir = input_root / "user@example.com"
        archive = account_dir / "Archive"
        data = b"Message-ID: <covered-flag-validate@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody"
        _write_legacy_message_fixture(archive, mailbox="Archive", data=data, flags="\\Seen", source_server=server)
        flagged = account_dir / "Flagged"
        flagged.mkdir()
        (flagged / ".mailbox.json").write_text(json.dumps({
            "mailbox": "Flagged",
            "message_count": 0,
            "covered_by_regular_content": True,
        }))
        state_path = account_dir / "export-state.json"
        state = json.loads(state_path.read_text())
        state["mailboxes"].append({
            "mailbox": "Flagged",
            "path": "Flagged",
            "message_count": 0,
            "covered_by_regular_content": True,
        })
        state_path.write_text(json.dumps(state))
        config_path = tmp_path / "validate.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": server.host, "port": server.port, "ssl": server.ssl, "starttls": server.starttls},
            "source_server": {"host": server.host, "port": server.port, "ssl": server.ssl, "starttls": server.starttls},
            "accounts": [{"email": "user@example.com", "password": "secret"}],
        }))

        class FlaggedTarget:
            selected = "Archive"

            def list(self, *_args):
                return "OK", [
                    b'(\\HasNoChildren) "/" "Archive"',
                    b'(\\HasNoChildren \\Flagged) "/" "Flagged"',
                ]

            def select(self, mailbox: str, readonly: bool = False):
                self.selected = mailbox.strip('"')
                return "OK", [b"1"]

            def search(self, charset, *criteria):
                return "OK", [b"1"]

            def fetch(self, num: bytes, query: str):
                flags = b"\\Seen \\Flagged" if self.selected == "Flagged" else b"\\Seen"
                return "OK", [(
                    b"1 (RFC822.SIZE "
                    + str(len(data)).encode("ascii")
                    + b" FLAGS ("
                    + flags
                    + b') INTERNALDATE "01-Jan-2024 00:00:00 +0000" BODY[] {'
                    + str(len(data)).encode("ascii")
                    + b"}",
                    data,
                )]

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[FlaggedTarget]:
            yield FlaggedTarget()

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.imap_ops.imap_connection", fake_connection):
            rc = main([
                "--mode", "validate",
                "--config", str(config_path),
                "--input-dir", str(input_root),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--no-connectivity-test",
            ])

        assert rc == 4

    @pytest.mark.parametrize(
        ("artifact", "needle"),
        [
            ("message", "hard-linked legacy message file"),
            ("metadata", "hard-linked legacy message metadata"),
        ],
    )
    def test_legacy_validation_rejects_hard_linked_message_artifacts(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        artifact: str,
        needle: str,
    ) -> None:
        from components.audit import audit_export
        from components.imap_ops import import_account
        from components.models import Account, Config, ServerConfig
        from verify_export import verify_account

        server = ServerConfig("imap.example.com", port=993, ssl=True, starttls=False)
        account = Account("user@example.com", "secret")
        folder = tmp_path / "user@example.com" / "INBOX"
        eml = _write_legacy_message_fixture(
            folder,
            data=b"Message-ID: <hardlink-artifact@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody",
            source_server=server,
        )
        target = eml if artifact == "message" else eml.with_suffix(".json")
        victim = tmp_path / f"outside-{artifact}"
        victim.write_bytes(target.read_bytes())
        target.unlink()
        try:
            target.hardlink_to(victim)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"hard link creation unavailable: {exc}")

        ok, issues = audit_export(
            tmp_path,
            Config(server, [account], source_server=server),
            1,
            check_remote=False,
            require_integrity_metadata=True,
        )
        stats = verify_account(tmp_path / "user@example.com")
        output = capsys.readouterr().out

        assert not ok
        assert any(needle in issue for issue in issues)
        assert stats["errors"] >= 1
        assert "hard-linked" in output

        with pytest.raises(RuntimeError, match=needle):
            import_account(
                account,
                server,
                tmp_path,
                ignore_errors=False,
                imap_factory=lambda *_args: (_ for _ in ()).throw(AssertionError("IMAP should not be opened")),
            )

    @pytest.mark.parametrize(
        ("artifact", "needle", "verify_needle"),
        [
            ("message", "non-regular legacy message file", "message file is not a regular file"),
            ("metadata", "non-regular legacy message metadata", "metadata sidecar is not a regular file"),
        ],
    )
    def test_legacy_validation_rejects_non_regular_message_artifacts(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        artifact: str,
        needle: str,
        verify_needle: str,
    ) -> None:
        from components.audit import audit_export
        from components.imap_ops import import_account
        from components.models import Account, Config, ServerConfig
        from verify_export import verify_account

        server = ServerConfig("imap.example.com", port=993, ssl=True, starttls=False)
        account = Account("user@example.com", "secret")
        folder = tmp_path / "user@example.com" / "INBOX"
        eml = _write_legacy_message_fixture(
            folder,
            data=b"Message-ID: <fifo-artifact@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody",
            source_server=server,
        )
        target = eml if artifact == "message" else eml.with_suffix(".json")
        target.unlink()
        _mkfifo_or_skip(target)

        ok, issues = audit_export(
            tmp_path,
            Config(server, [account], source_server=server),
            1,
            check_remote=False,
            require_integrity_metadata=True,
        )
        stats = verify_account(tmp_path / "user@example.com")
        output = capsys.readouterr().out

        assert not ok
        assert any(needle in issue for issue in issues)
        assert stats["errors"] >= 1
        assert verify_needle in output

        with pytest.raises(RuntimeError, match=needle):
            import_account(
                account,
                server,
                tmp_path,
                ignore_errors=False,
                imap_factory=lambda *_args: (_ for _ in ()).throw(AssertionError("IMAP should not be opened")),
            )

    def test_verify_export_rejects_parent_swap_during_artifact_open(self, tmp_path: Path) -> None:
        import verify_export
        from verify_export import _read_artifact_no_links

        folder = tmp_path / "user@example.com" / "INBOX"
        folder.mkdir(parents=True)
        message = folder / "u0000000001.eml"
        message.write_bytes(b"original")
        outside = tmp_path / "outside-inbox"
        outside.mkdir()
        (outside / message.name).write_bytes(b"outside")
        checked_folder = tmp_path / "checked-inbox"
        real_open = verify_export.os.open
        swapped = False

        def racing_open(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal swapped
            if path == message.name and dir_fd is not None and not swapped:
                folder.rename(checked_folder)
                try:
                    folder.symlink_to(outside, target_is_directory=True)
                except (OSError, NotImplementedError) as exc:
                    pytest.skip(f"symlink creation unavailable: {exc}")
                swapped = True
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with mock.patch("verify_export.os.open", racing_open):
            with pytest.raises(RuntimeError, match="replaced message file directory"):
                _read_artifact_no_links(message, "message file")

        assert swapped
        assert folder.is_symlink()
        assert (outside / message.name).read_bytes() == b"outside"
        assert (checked_folder / message.name).read_bytes() == b"original"

    def test_direct_import_rejects_append_time_hard_link_swap(self, tmp_path: Path) -> None:
        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        server = ServerConfig("imap.example.com", port=993, ssl=True, starttls=False)
        account = Account("user@example.com", "secret")
        body = b"Message-ID: <append-race@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody"
        folder = tmp_path / account.email / "INBOX"
        eml = _write_legacy_message_fixture(folder, data=body, source_server=server)
        victim = tmp_path / "outside-message.eml"
        victim.write_bytes(body)

        class AppendTarget:
            appended = False

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"0"]

            def append(self, *_args, **_kwargs):
                self.appended = True
                return "OK", [b""]

        target = AppendTarget()
        calls = 0

        def fake_factory(*_args, **_kwargs):
            @contextlib.contextmanager
            def manager():
                nonlocal calls
                calls += 1
                if calls == 2:
                    eml.unlink()
                    try:
                        os.link(victim, eml)
                    except (OSError, NotImplementedError) as exc:
                        pytest.skip(f"hard link creation unavailable: {exc}")
                yield target

            return manager()

        with pytest.raises(RuntimeError, match="hard-linked legacy message file"):
            import_account(
                account,
                server,
                tmp_path,
                ignore_errors=False,
                imap_factory=fake_factory,
                source_server=server,
            )

        assert calls == 2
        assert target.appended is False

    def test_direct_import_rejects_zero_message_export_state_symlink_swap(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from components import audit as audit_module
        from components.imap_ops import import_account, legacy_server_endpoint, legacy_server_endpoint_digest
        from components.models import Account, ServerConfig

        server = ServerConfig("imap.example.com", port=993, ssl=True, starttls=False)
        account = Account("user@example.com", "secret")
        account_dir = tmp_path / account.email
        folder = account_dir / "INBOX"
        folder.mkdir(parents=True)
        (folder / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": 0}))
        state = {
            "schema_version": 1,
            "account": account.email,
            "source_server": legacy_server_endpoint(server),
            "source_server_sha256": legacy_server_endpoint_digest(server),
            "complete": True,
            "completed_at": 0,
            "mailboxes": [{"mailbox": "INBOX", "path": "INBOX", "message_count": 0}],
        }
        state_path = account_dir / "export-state.json"
        state_path.write_text(json.dumps(state))
        outside_state = tmp_path / "outside-export-state.json"
        outside_state.write_text(json.dumps(state))
        real_export_state_issues = audit_module._legacy_export_state_issues

        def racing_export_state_issues(*args, **kwargs):
            issues = real_export_state_issues(*args, **kwargs)
            state_path.unlink()
            try:
                state_path.symlink_to(outside_state)
            except (OSError, NotImplementedError) as exc:
                pytest.skip(f"symlink creation unavailable: {exc}")
            return issues

        monkeypatch.setattr(audit_module, "_legacy_export_state_issues", racing_export_state_issues)

        with pytest.raises(RuntimeError, match=r"no staged \.eml files"):
            import_account(
                account,
                server,
                tmp_path,
                ignore_errors=False,
                imap_factory=lambda *_args: (_ for _ in ()).throw(AssertionError("IMAP should not be opened")),
                source_server=server,
            )

    @pytest.mark.parametrize(
        ("artifact", "needle"),
        [
            ("mailbox-marker", "hard-linked legacy mailbox marker"),
            ("export-state", "hard-linked legacy export-state"),
        ],
    )
    def test_legacy_validation_rejects_hard_linked_control_metadata(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        artifact: str,
        needle: str,
    ) -> None:
        from components.audit import audit_export
        from components.models import Account, Config, ServerConfig
        from verify_export import verify_account

        server = ServerConfig("imap.example.com", port=993, ssl=True, starttls=False)
        account = Account("user@example.com", "secret")
        folder = tmp_path / "user@example.com" / "INBOX"
        _write_legacy_message_fixture(
            folder,
            data=b"Message-ID: <hardlink-control@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody",
            source_server=server,
        )
        marker = folder / ".mailbox.json"
        marker.write_text(json.dumps({"mailbox": "INBOX", "message_count": 1}))
        target = marker if artifact == "mailbox-marker" else folder.parent / "export-state.json"
        victim = tmp_path / f"outside-{artifact}.json"
        victim.write_bytes(target.read_bytes())
        target.unlink()
        try:
            target.hardlink_to(victim)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"hard link creation unavailable: {exc}")

        ok, issues = audit_export(
            tmp_path,
            Config(server, [account], source_server=server),
            1,
            check_remote=False,
            require_integrity_metadata=True,
        )
        stats = verify_account(tmp_path / "user@example.com")
        output = capsys.readouterr().out

        assert not ok
        assert any(needle in issue for issue in issues)
        assert stats["errors"] >= 1
        assert "hard-linked" in output

    def test_strict_audit_rejects_symlinked_message_file(self, tmp_path: Path) -> None:
        from components.audit import audit_export
        from components.models import Account, Config, ServerConfig

        server = ServerConfig("imap.example.com")
        folder = tmp_path / "user@example.com" / "INBOX"
        data = b"Message-ID: <m@example.com>\r\nFrom: a@example.com\r\nTo: b@example.com\r\n\r\nbody"
        eml = _write_legacy_message_fixture(folder, data=data, source_server=server)
        outside = tmp_path / "outside.eml"
        outside.write_bytes(data)
        eml.unlink()
        try:
            eml.symlink_to(outside)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")

        ok, issues = audit_export(
            tmp_path,
            Config(server, [Account("user@example.com", "secret")], source_server=server),
            1,
            check_remote=False,
            require_integrity_metadata=True,
        )

        assert not ok
        assert any("u0000000001.eml: message file is a symlink" in issue for issue in issues)

    def test_remote_audit_skips_symlinked_message_identity_check(self, tmp_path: Path) -> None:
        from components.audit import audit_export
        from components.models import Account, Config, ServerConfig

        server = ServerConfig("imap.example.com")
        folder = tmp_path / "user@example.com" / "INBOX"
        data = b"Message-ID: <m@example.com>\r\nFrom: a@example.com\r\nTo: b@example.com\r\n\r\nbody"
        eml = _write_legacy_message_fixture(folder, data=data, source_server=server)
        outside = tmp_path / "outside.eml"
        outside.write_bytes(data)
        eml.unlink()
        try:
            eml.symlink_to(outside)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")

        class FakeRemote:
            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"1"]

            def uid(self, command: str, *args):
                return "OK", [b"1"]

            def logout(self):
                return "OK", []

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[FakeRemote]:
            yield FakeRemote()

        with mock.patch("components.audit.imap_connection", fake_connection), \
            mock.patch("components.audit._remote_has_message", side_effect=AssertionError("symlink should not be checked remotely")):
            ok, issues = audit_export(
                tmp_path,
                Config(server, [Account("user@example.com", "secret")], source_server=server),
                1,
                check_remote=True,
                require_integrity_metadata=True,
            )

        assert not ok
        assert any("u0000000001.eml: message file is a symlink" in issue for issue in issues)

    def test_remote_audit_rechecks_empty_mailbox_directory_symlink_after_local_audit(self, tmp_path: Path) -> None:
        from components.audit import audit_export
        from components.models import Account, Config, ServerConfig

        server = ServerConfig("imap.example.com", port=993, ssl=True, starttls=False)
        folder = tmp_path / "user@example.com" / "INBOX"
        _write_legacy_empty_mailbox_fixture(folder, source_server=server)
        outside = tmp_path / "outside-inbox"
        swapped = False

        class FakeRemote:
            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"0"]

            def uid(self, command: str, *args):
                return "OK", [b""]

            def logout(self):
                return "OK", []

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[FakeRemote]:
            nonlocal swapped
            (folder / ".mailbox.json").unlink()
            folder.rmdir()
            outside.mkdir()
            try:
                folder.symlink_to(outside, target_is_directory=True)
            except (OSError, NotImplementedError) as exc:
                pytest.skip(f"symlink creation unavailable: {exc}")
            swapped = True
            yield FakeRemote()

        with mock.patch("components.audit.imap_connection", fake_connection):
            ok, issues = audit_export(
                tmp_path,
                Config(server, [Account("user@example.com", "secret")], source_server=server),
                1,
                check_remote=True,
                require_integrity_metadata=True,
            )

        assert swapped
        assert folder.is_symlink()
        assert not ok
        assert any("INBOX: mailbox path is a symlink" in issue for issue in issues)

    def test_validate_rejects_message_symlink_swapped_after_audit_before_remote_check(self, tmp_path: Path) -> None:
        from components.audit import audit_export as real_audit_export
        from components.main import main
        from components.models import ServerConfig

        input_root = tmp_path / "exported"
        folder = input_root / "user@example.com" / "INBOX"
        source_server = {
            "host": "source.example.com",
            "port": 993,
            "ssl": True,
            "starttls": False,
        }
        target_server = {
            "host": "target.example.com",
            "port": 993,
            "ssl": True,
            "starttls": False,
        }
        original = b"Message-ID: <original@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody"
        eml = _write_legacy_message_fixture(
            folder,
            data=original,
            source_server=ServerConfig(**source_server),
        )
        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": target_server,
            "source_server": source_server,
            "accounts": [{"email": "user@example.com", "password": "secret"}],
        }))
        outside = tmp_path / "outside.eml"
        outside.write_bytes(b"Message-ID: <outside@example.com>\r\nFrom: x\r\nTo: y\r\n\r\noutside")
        calls = 0

        def audit_then_swap(*args, **kwargs):
            nonlocal calls
            calls += 1
            result = real_audit_export(*args, **kwargs)
            if calls == 2:
                eml.unlink()
                try:
                    eml.symlink_to(outside)
                except (OSError, NotImplementedError) as exc:
                    pytest.skip(f"symlink creation unavailable: {exc}")
            return result

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.main.audit_export", side_effect=audit_then_swap), \
            mock.patch("components.imap_ops.imap_connection", side_effect=AssertionError("remote validate should not run")):
            rc = main([
                "--mode", "validate",
                "--config", str(config_path),
                "--input-dir", str(input_root),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--no-connectivity-test",
            ])

        assert calls == 2
        assert eml.is_symlink()
        assert rc == 4

    def test_validate_rejects_empty_mailbox_symlink_swapped_after_audit_before_remote_check(self, tmp_path: Path) -> None:
        from components.audit import audit_export as real_audit_export
        from components.main import main
        from components.models import ServerConfig

        input_root = tmp_path / "exported"
        folder = input_root / "user@example.com" / "INBOX"
        source_server = {
            "host": "source.example.com",
            "port": 993,
            "ssl": True,
            "starttls": False,
        }
        target_server = {
            "host": "target.example.com",
            "port": 993,
            "ssl": True,
            "starttls": False,
        }
        _write_legacy_empty_mailbox_fixture(folder, source_server=ServerConfig(**source_server))
        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": target_server,
            "source_server": source_server,
            "accounts": [{"email": "user@example.com", "password": "secret"}],
        }))
        outside = tmp_path / "outside-inbox"
        calls = 0

        def audit_then_swap(*args, **kwargs):
            nonlocal calls
            calls += 1
            result = real_audit_export(*args, **kwargs)
            if calls == 2:
                (folder / ".mailbox.json").unlink()
                folder.rmdir()
                outside.mkdir()
                try:
                    folder.symlink_to(outside, target_is_directory=True)
                except (OSError, NotImplementedError) as exc:
                    pytest.skip(f"symlink creation unavailable: {exc}")
            return result

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.main.audit_export", side_effect=audit_then_swap), \
            mock.patch("components.imap_ops.imap_connection", side_effect=AssertionError("remote validate should not run")):
            rc = main([
                "--mode", "validate",
                "--config", str(config_path),
                "--input-dir", str(input_root),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--no-connectivity-test",
            ])

        assert calls == 2
        assert folder.is_symlink()
        assert rc == 4

    def test_validate_rejects_account_dir_swap_after_journal_load_before_remote_check(self, tmp_path: Path) -> None:
        from components import imap_ops
        from components.main import main
        from components.models import ServerConfig

        input_root = tmp_path / "exported"
        account_dir = input_root / "user@example.com"
        folder = account_dir / "INBOX"
        source_server = {
            "host": "source.example.com",
            "port": 993,
            "ssl": True,
            "starttls": False,
        }
        target_server = {
            "host": "target.example.com",
            "port": 993,
            "ssl": True,
            "starttls": False,
        }
        _write_legacy_empty_mailbox_fixture(folder, source_server=ServerConfig(**source_server))
        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": target_server,
            "source_server": source_server,
            "accounts": [{"email": "user@example.com", "password": "secret"}],
        }))
        outside = tmp_path / "outside-account"
        _write_legacy_empty_mailbox_fixture(outside / "INBOX", source_server=ServerConfig(**source_server))
        checked_account = tmp_path / "checked-account"
        real_load = imap_ops._load_legacy_import_journal
        load_calls = 0
        swapped = False

        def racing_load(path: Path, *args, **kwargs):
            nonlocal load_calls, swapped
            result = real_load(path, *args, **kwargs)
            if path == account_dir:
                load_calls += 1
                if load_calls == 2:
                    account_dir.rename(checked_account)
                    try:
                        account_dir.symlink_to(outside, target_is_directory=True)
                    except (OSError, NotImplementedError) as exc:
                        pytest.skip(f"symlink creation unavailable: {exc}")
                    swapped = True
            return result

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.imap_ops._load_legacy_import_journal", side_effect=racing_load), \
            mock.patch("components.imap_ops.imap_connection", side_effect=AssertionError("remote validate should not run")):
            rc = main([
                "--mode", "validate",
                "--config", str(config_path),
                "--input-dir", str(input_root),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--no-connectivity-test",
            ])

        assert load_calls == 2
        assert swapped
        assert account_dir.is_symlink()
        assert rc == 4

    def test_remote_audit_rejects_symlinked_mailbox_marker_without_following_or_connecting(self, tmp_path: Path) -> None:
        from components.audit import _folder_mailbox_name, audit_export
        from components.models import Account, Config, ServerConfig

        server = ServerConfig("imap.example.com")
        folder = tmp_path / "user@example.com" / "INBOX"
        _write_legacy_message_fixture(
            folder,
            data=b"Message-ID: <m@example.com>\r\nFrom: a@example.com\r\nTo: b@example.com\r\n\r\nbody",
            source_server=server,
        )
        outside_marker = tmp_path / "outside-marker.json"
        outside_marker.write_text(json.dumps({"mailbox": "OUTSIDE_FROM_SYMLINK", "message_count": 1}))
        try:
            (folder / ".mailbox.json").symlink_to(outside_marker)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")

        assert _folder_mailbox_name(folder) == "INBOX"

        with mock.patch("components.audit.imap_connection", side_effect=AssertionError("remote audit should not run")):
            ok, issues = audit_export(
                tmp_path,
                Config(server, [Account("user@example.com", "secret")], source_server=server),
                1,
                check_remote=True,
                require_integrity_metadata=True,
            )

        assert not ok
        assert any("INBOX: mailbox marker is a symlink" in issue for issue in issues)
        assert not any("OUTSIDE_FROM_SYMLINK" in issue for issue in issues)

    def test_remote_audit_rejects_hard_linked_mailbox_marker_without_connecting(self, tmp_path: Path) -> None:
        from components.audit import audit_export
        from components.models import Account, Config, ServerConfig

        server = ServerConfig("imap.example.com")
        account = Account("user@example.com", "secret")
        folder = tmp_path / account.email / "INBOX"
        _write_legacy_message_fixture(
            folder,
            data=b"Message-ID: <hardlink-marker-audit@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody",
            source_server=server,
        )
        marker = folder / ".mailbox.json"
        marker.write_text(json.dumps({"mailbox": "INBOX", "message_count": 1}))
        victim = tmp_path / "outside-marker.json"
        victim.write_bytes(marker.read_bytes())
        marker.unlink()
        try:
            marker.hardlink_to(victim)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"hard link creation unavailable: {exc}")

        with mock.patch("components.audit.imap_connection", side_effect=AssertionError("remote audit should not run")):
            ok, issues = audit_export(
                tmp_path,
                Config(server, [account], source_server=server),
                1,
                check_remote=True,
                require_integrity_metadata=True,
            )

        assert not ok
        assert any("hard-linked legacy mailbox marker" in issue for issue in issues)
        assert not any("remote check failed" in issue for issue in issues)

    def test_audit_account_reports_file_account_path(self, tmp_path: Path) -> None:
        from components.audit import audit_account
        from components.models import Account, ServerConfig

        account = Account("user@example.com", "secret")
        (tmp_path / account.email).write_text("not a directory\n")

        name, issues = audit_account(
            account,
            tmp_path,
            ServerConfig("imap.example.com"),
            check_remote=True,
            require_integrity_metadata=True,
            expected_source_server=ServerConfig("imap.example.com"),
        )

        assert name == account.email
        assert any("account path is not a directory" in issue for issue in issues)

    def test_legacy_import_rejects_provider_manifest_layout(self, tmp_path: Path) -> None:
        from components.audit import audit_export
        from components.imap_ops import import_account
        from components.main import main
        from components.models import Account, Config, ServerConfig

        server = ServerConfig("imap.example.com", port=993, ssl=True, starttls=False)
        account = Account("user@example.com", "secret")
        input_root = tmp_path / "exported"
        folder = input_root / account.email / "INBOX"
        _write_legacy_message_fixture(
            folder,
            data=b"Message-ID: <mixed-layout@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nbody",
            source_server=server,
        )
        (folder.parent / "manifest.jsonl").write_text(json.dumps({"provider": True}) + "\n")

        ok, issues = audit_export(
            input_root,
            Config(server, [account], source_server=server),
            1,
            check_remote=False,
            require_integrity_metadata=True,
        )
        assert not ok
        assert any("provider manifest present in legacy account directory" in issue for issue in issues)

        with pytest.raises(RuntimeError, match="provider manifest present"):
            import_account(
                account,
                server,
                input_root,
                ignore_errors=False,
                imap_factory=lambda *_args: (_ for _ in ()).throw(AssertionError("IMAP should not be opened")),
            )

        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": server.host, "port": server.port, "ssl": server.ssl, "starttls": server.starttls},
            "source_server": {"host": server.host, "port": server.port, "ssl": server.ssl, "starttls": server.starttls},
            "accounts": [{"email": account.email, "password": account.password}],
        }))
        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.main.import_account") as import_mock:
            rc = main([
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(input_root),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--no-connectivity-test",
            ])

        assert rc == 4
        import_mock.assert_not_called()

    def test_legacy_import_rejects_symlinked_message_file_before_connect(self, tmp_path: Path) -> None:
        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        folder = tmp_path / "user@example.com" / "INBOX"
        data = b"Message-ID: <m@example.com>\r\nFrom: a@example.com\r\nTo: b@example.com\r\n\r\nbody"
        eml = _write_legacy_message_fixture(folder, data=data)
        outside = tmp_path / "outside.eml"
        outside.write_bytes(data)
        eml.unlink()
        try:
            eml.symlink_to(outside)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")

        with pytest.raises(RuntimeError, match="symlinked legacy message file"):
            import_account(
                Account("user@example.com", "secret"),
                ServerConfig("imap.example.com"),
                tmp_path,
                ignore_errors=False,
                imap_factory=lambda *_args: (_ for _ in ()).throw(AssertionError("IMAP should not be opened")),
            )

    def test_legacy_import_rejects_symlinked_message_metadata_before_connect(self, tmp_path: Path) -> None:
        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        folder = tmp_path / "user@example.com" / "INBOX"
        eml = _write_legacy_message_fixture(folder)
        meta_path = eml.with_suffix(".json")
        outside = tmp_path / "outside.json"
        outside.write_text(meta_path.read_text())
        meta_path.unlink()
        try:
            meta_path.symlink_to(outside)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")

        with pytest.raises(RuntimeError, match="symlinked legacy message metadata"):
            import_account(
                Account("user@example.com", "secret"),
                ServerConfig("imap.example.com"),
                tmp_path,
                ignore_errors=False,
                imap_factory=lambda *_args: (_ for _ in ()).throw(AssertionError("IMAP should not be opened")),
            )

    def test_legacy_import_rejects_broken_symlinked_message_metadata_before_connect(self, tmp_path: Path) -> None:
        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        folder = tmp_path / "user@example.com" / "INBOX"
        eml = _write_legacy_message_fixture(folder)
        meta_path = eml.with_suffix(".json")
        meta_path.unlink()
        try:
            meta_path.symlink_to(tmp_path / "missing.json")
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")

        with pytest.raises(RuntimeError, match="symlinked legacy message metadata"):
            import_account(
                Account("user@example.com", "secret"),
                ServerConfig("imap.example.com"),
                tmp_path,
                ignore_errors=False,
                imap_factory=lambda *_args: (_ for _ in ()).throw(AssertionError("IMAP should not be opened")),
            )

    def test_legacy_import_rejects_broken_symlinked_mailbox_marker_before_connect(self, tmp_path: Path) -> None:
        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        folder = tmp_path / "user@example.com" / "INBOX"
        _write_legacy_message_fixture(folder)
        marker = folder / ".mailbox.json"
        marker.write_text(json.dumps({"mailbox": "INBOX", "message_count": 1}))
        marker.unlink()
        try:
            marker.symlink_to(tmp_path / "missing-mailbox.json")
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")

        with pytest.raises(RuntimeError, match="symlinked legacy mailbox marker"):
            import_account(
                Account("user@example.com", "secret"),
                ServerConfig("imap.example.com"),
                tmp_path,
                ignore_errors=False,
                imap_factory=lambda *_args: (_ for _ in ()).throw(AssertionError("IMAP should not be opened")),
            )

    def test_legacy_import_rejects_hard_linked_mailbox_marker_before_connect(self, tmp_path: Path) -> None:
        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        folder = tmp_path / "user@example.com" / "INBOX"
        _write_legacy_message_fixture(folder)
        marker = folder / ".mailbox.json"
        marker.write_text(json.dumps({"mailbox": "INBOX", "message_count": 1}))
        victim = tmp_path / "outside-mailbox-marker.json"
        victim.write_bytes(marker.read_bytes())
        marker.unlink()
        try:
            marker.hardlink_to(victim)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"hard link creation unavailable: {exc}")

        with pytest.raises(RuntimeError, match="hard-linked legacy mailbox marker"):
            import_account(
                Account("user@example.com", "secret"),
                ServerConfig("imap.example.com"),
                tmp_path,
                ignore_errors=False,
                imap_factory=lambda *_args: (_ for _ in ()).throw(AssertionError("IMAP should not be opened")),
            )

    def test_legacy_import_rejects_sidecar_mailbox_folder_mismatch_before_connect(self, tmp_path: Path) -> None:
        from components.content_binding import CONTENT_BINDING_FIELD, legacy_content_binding_sha256
        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        folder = tmp_path / "user@example.com" / "INBOX"
        eml = _write_legacy_message_fixture(folder, mailbox="INBOX")
        meta_path = eml.with_suffix(".json")
        meta = json.loads(meta_path.read_text())
        meta["mailbox"] = "Archive"
        meta[CONTENT_BINDING_FIELD] = legacy_content_binding_sha256(meta)
        meta_path.write_text(json.dumps(meta))

        with pytest.raises(RuntimeError, match="mailbox metadata mismatch"):
            import_account(
                Account("user@example.com", "secret"),
                ServerConfig("imap.example.com"),
                tmp_path,
                ignore_errors=False,
                imap_factory=lambda *_args: (_ for _ in ()).throw(AssertionError("IMAP should not be opened")),
            )

    def test_legacy_import_rejects_zero_message_marker_folder_mismatch_before_connect(self, tmp_path: Path) -> None:
        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        account_dir = tmp_path / "user@example.com"
        folder = account_dir / "INBOX"
        folder.mkdir(parents=True)
        (folder / ".mailbox.json").write_text(json.dumps({"mailbox": "Archive", "message_count": 0}))
        _write_verify_export_state(account_dir, [{"mailbox": "Archive", "path": "INBOX", "message_count": 0}])

        with pytest.raises(RuntimeError, match="mailbox metadata mismatch"):
            import_account(
                Account("user@example.com", "secret"),
                ServerConfig("imap.example.com"),
                tmp_path,
                ignore_errors=False,
                imap_factory=lambda *_args: (_ for _ in ()).throw(AssertionError("IMAP should not be opened")),
            )

    def test_verify_export_detects_text_part_concatenation_with_rfc822_attachment(self, tmp_path: Path) -> None:
        from verify_export import analyze_message

        eml_path = tmp_path / "text-part-concat-with-attachment.eml"
        payload = (
            b"Message-ID: <outer@example.com>\r\n"
            b"From: outer@example.com\r\n"
            b"To: recipient@example.com\r\n"
            b"Subject: attached message\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: multipart/mixed; boundary=\"b\"\r\n"
            b"\r\n"
            b"--b\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"\r\n"
            b"body before corruption\r\n"
            b"Message-ID: <second@example.com>\r\n"
            b"From: second@example.com\r\n"
            b"To: recipient@example.com\r\n"
            b"\r\n"
            b"second body\r\n"
            b"--b\r\n"
            b"Content-Type: message/rfc822\r\n"
            b"Content-Disposition: attachment; filename=\"attached.eml\"\r\n"
            b"\r\n"
            b"Message-ID: <inner@example.com>\r\n"
            b"From: inner@example.com\r\n"
            b"To: recipient@example.com\r\n"
            b"\r\n"
            b"inner body\r\n"
            b"--b--\r\n"
        )
        eml_path.write_bytes(payload)
        json_path = tmp_path / "text-part-concat-with-attachment.json"
        json_path.write_text(json.dumps(_legacy_integrity_metadata(payload)))

        analysis, error = analyze_message(eml_path, json_path)

        assert error is None
        assert analysis is not None
        assert "message/rfc822" in analysis["content_types"]
        assert analysis["multiple_messages_detected"] is True

    def test_verify_export_accepts_sanitized_account_directory_state(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from verify_export import main, verify_account

        account_dir = tmp_path / "exported" / "a_b@example.com"
        inbox = account_dir / "INBOX"
        inbox.mkdir(parents=True)
        (inbox / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": 0}))
        (account_dir / "export-state.json").write_text(json.dumps({
            "schema_version": 1,
            "account": "a/b@example.com",
            "complete": True,
            "completed_at": 0,
            "mailboxes": [{"mailbox": "INBOX", "path": "INBOX", "message_count": 0}],
        }))
        monkeypatch.chdir(tmp_path)

        stats = verify_account(account_dir)

        assert stats["errors"] == 0
        assert main() == 0

    def test_panel_reset_checks_free_space_before_panel_mutation(self, tmp_path: Path) -> None:
        from components.main import main

        input_root = tmp_path / "exported"
        _write_legacy_message_fixture(input_root / "a@example.com" / "INBOX")
        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "source_server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))
        events: List[str] = []

        def fail_free_space(*_args, **_kwargs):
            events.append("free-space")
            raise RuntimeError("low disk")

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path", fail_free_space), \
            mock.patch("components.main.audit_export") as audit_mock, \
            mock.patch("components.main.CPanelClient") as client_cls, \
            mock.patch("components.cpanel_ensure.reset_accounts_cpanel") as reset_mock:
            rc = main([
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(input_root),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "1000",
                "--max-workers", "1",
                "--no-connectivity-test",
                "--auto-provision-cpanel",
                "--reset",
                "--reset-confirm", "imap.example.com",
                "--cpanel-url", "https://panel.example.com:2083",
                "--cpanel-username", "cpuser",
                "--cpanel-token", "api-token",
            ])

        assert rc == 2
        assert events == ["free-space"]
        audit_mock.assert_not_called()
        client_cls.assert_not_called()
        reset_mock.assert_not_called()

    def test_indexer_write_json_no_overwrite_survives_publish_race(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import directadmin_indexer

        out = tmp_path / "export.pass.config.json"
        real_link = directadmin_indexer.os.link

        def racing_link(src: str, dst: str, *args, **kwargs) -> None:
            dst_dir_fd = kwargs.get("dst_dir_fd")
            if dst_dir_fd is None:
                Path(dst).write_text("raced\n")
            else:
                fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=dst_dir_fd)
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write("raced\n")
            real_link(src, dst, *args, **kwargs)

        monkeypatch.setattr(directadmin_indexer.os, "link", racing_link)

        with pytest.raises(FileExistsError, match="Refusing to overwrite"):
            directadmin_indexer.write_json({"accounts": []}, str(out), overwrite=False)

        assert out.read_text() == "raced\n"

    def test_legacy_export_refuses_preexisting_temp_symlink(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from components.imap_ops import export_account
        from components.models import Account, ServerConfig

        out_root = tmp_path / "exported"
        inbox = out_root / "user@example.com" / "INBOX"
        inbox.mkdir(parents=True)
        victim = tmp_path / "victim.eml"
        victim.write_bytes(b"original")
        try:
            (inbox / ".u0000000001.eml.123.456.tmp").symlink_to(victim)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")
        monkeypatch.setattr("components.imap_ops.os.getpid", lambda: 123)
        monkeypatch.setattr("components.imap_ops.time.time_ns", lambda: 456)

        class OneMessageInbox:
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
                        b"Message-ID: <m@example.com>\r\nFrom: a@example.com\r\nTo: b@example.com\r\n\r\nbody",
                    )]
                raise AssertionError(f"unexpected uid command: {command}")

            def logout(self):
                return "OK", []

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs) -> Iterator[OneMessageInbox]:
            yield OneMessageInbox()

        with mock.patch("components.imap_ops.imap_connection", fake_connection):
            with pytest.raises(RuntimeError, match="output path is a symlink"):
                export_account(
                    Account("user@example.com", "secret"),
                    ServerConfig("imap.example.com"),
                    out_root,
                    ignore_errors=False,
                )

        assert victim.read_bytes() == b"original"
        assert not (inbox / "u0000000001.eml").exists()

    def test_strict_audit_rejects_symlinked_mailbox_directory(self, tmp_path: Path) -> None:
        from components.audit import audit_export
        from components.imap_ops import legacy_server_endpoint, legacy_server_endpoint_digest
        from components.models import Account, Config, ServerConfig

        server = ServerConfig("imap.example.com")
        account_dir = tmp_path / "user@example.com"
        account_dir.mkdir()
        outside_inbox = tmp_path / "outside-inbox"
        outside_inbox.mkdir()
        data = b"Message-ID: <m@example.com>\r\nFrom: a@example.com\r\nTo: b@example.com\r\n\r\nbody"
        (outside_inbox / "u0000000001.eml").write_bytes(data)
        (outside_inbox / "u0000000001.json").write_text(json.dumps(
            _legacy_integrity_metadata(data, mailbox="INBOX", uid=1)
        ))
        (outside_inbox / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": 1}))
        (account_dir / "export-state.json").write_text(json.dumps({
            "schema_version": 1,
            "account": "user@example.com",
            "source_server": legacy_server_endpoint(server),
            "source_server_sha256": legacy_server_endpoint_digest(server),
            "complete": True,
            "mailboxes": [{"mailbox": "INBOX", "path": "INBOX", "message_count": 1}],
        }))
        try:
            (account_dir / "INBOX").symlink_to(outside_inbox, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")

        ok, issues = audit_export(
            tmp_path,
            Config(server, [Account("user@example.com", "secret")], source_server=server),
            1,
            check_remote=False,
            require_integrity_metadata=True,
        )

        assert not ok
        assert any("INBOX: mailbox path is a symlink" in issue for issue in issues)

    def test_panel_reset_rejects_symlinked_account_before_panel_calls(self, tmp_path: Path) -> None:
        from components.main import main

        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "source_server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))
        input_root = tmp_path / "exported"
        input_root.mkdir()
        outside_account = tmp_path / "outside-account"
        _write_legacy_message_fixture(outside_account / "INBOX")
        try:
            (input_root / "a@example.com").symlink_to(outside_account, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.main.CPanelClient") as client_cls, \
            mock.patch("components.cpanel_ensure.reset_accounts_cpanel") as reset_mock:
            rc = main([
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(input_root),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--no-connectivity-test",
                "--auto-provision-cpanel",
                "--reset",
                "--reset-confirm", "imap.example.com",
                "--cpanel-url", "https://panel.example.com:2083",
                "--cpanel-username", "cpuser",
                "--cpanel-token", "api-token",
            ])

        assert rc == 2
        client_cls.assert_not_called()
        reset_mock.assert_not_called()

    def test_cpanel_reset_stop_event_rejects_before_delete(self) -> None:
        from components.cpanel_ensure import reset_accounts_cpanel
        from components.models import Account, Config, ServerConfig

        class Client:
            def __init__(self) -> None:
                self.deleted = False
                self.created = False

            def delete_pop_account(self, domain: str, local_part: str) -> None:
                self.deleted = True

            def create_pop_account(self, domain: str, local_part: str, password: str, quota_mb: int = 0, *, allow_existing: bool = True) -> None:
                self.created = True

        stop_event = threading.Event()
        stop_event.set()
        client = Client()
        config = Config(ServerConfig("imap.example.com"), [Account("a@example.com", "secret")])

        with pytest.raises(RuntimeError, match="stop requested"):
            reset_accounts_cpanel(config, client, stop_event=stop_event)

        assert not client.deleted
        assert not client.created

    def test_directadmin_reset_stop_event_rejects_before_delete(self) -> None:
        from components.da_ensure import reset_accounts_directadmin
        from components.models import Account, Config, ServerConfig

        class Client:
            def __init__(self) -> None:
                self.deleted = False
                self.created = False

            def delete_pop_account(self, domain: str, local_part: str) -> None:
                self.deleted = True

            def create_pop_account(self, domain: str, local_part: str, password: str, quota_mb: int = 0, *, allow_existing: bool = True) -> None:
                self.created = True

        stop_event = threading.Event()
        stop_event.set()
        client = Client()
        config = Config(ServerConfig("imap.example.com"), [Account("a@example.com", "secret")])

        with pytest.raises(RuntimeError, match="stop requested"):
            reset_accounts_directadmin(config, client, stop_event=stop_event)

        assert not client.deleted
        assert not client.created

    def test_main_registers_signal_before_cpanel_reset_and_aborts_before_import(self, tmp_path: Path) -> None:
        from components.main import main

        input_root = tmp_path / "exported"
        _write_legacy_message_fixture(input_root / "a@example.com" / "INBOX")
        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "source_server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))
        handlers = {}

        class DummyCPanelClient:
            def __init__(self, *_args, **_kwargs) -> None:
                pass

        def fake_signal(signum, handler):
            handlers[signum] = handler

        def fake_reset(*_args, **kwargs):
            assert "stop_event" in kwargs
            assert signal.SIGTERM in handlers
            handlers[signal.SIGTERM](signal.SIGTERM, None)
            return set()

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.main.signal.signal", fake_signal), \
            mock.patch("components.main.CPanelClient", DummyCPanelClient), \
            mock.patch("components.cpanel_ensure.reset_accounts_cpanel", fake_reset), \
            mock.patch("components.main.import_account", side_effect=AssertionError("import should not run after stop")):
            rc = main([
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(input_root),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--no-connectivity-test",
                "--auto-provision-cpanel",
                "--reset",
                "--reset-confirm", "imap.example.com",
                "--cpanel-url", "https://panel.example.com:2083",
                "--cpanel-username", "cpuser",
                "--cpanel-token", "api-token",
            ])

        assert rc == 130

    def test_main_registers_signal_before_legacy_staged_audit(self, tmp_path: Path) -> None:
        from components.main import main

        input_root = tmp_path / "exported"
        _write_legacy_message_fixture(input_root / "a@example.com" / "INBOX")
        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "source_server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))
        handlers = {}

        def fake_signal(signum, handler):
            handlers[signum] = handler

        def fake_audit(*_args, **_kwargs):
            assert signal.SIGTERM in handlers
            handlers[signal.SIGTERM](signal.SIGTERM, None)
            return True, []

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.main.signal.signal", fake_signal), \
            mock.patch("components.main.audit_export", side_effect=fake_audit), \
            mock.patch("components.main._legacy_pending_import_journal_issues", side_effect=AssertionError("pending journal check should not run after stop")), \
            mock.patch("components.main.test_accounts", side_effect=AssertionError("connectivity should not run after stop")):
            rc = main([
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(input_root),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
            ])

        assert rc == 130

    def test_main_returns_130_when_post_export_audit_raises_after_stop(self, tmp_path: Path) -> None:
        from components.main import main

        config_path = tmp_path / "export.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))
        handlers = {}

        def fake_signal(signum, handler):
            handlers[signum] = handler

        def fake_audit(*_args, **_kwargs):
            assert signal.SIGTERM in handlers
            handlers[signal.SIGTERM](signal.SIGTERM, None)
            raise RuntimeError("audit interrupted")

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.main.signal.signal", fake_signal), \
            mock.patch("components.main.export_account"), \
            mock.patch("components.main.audit_export", side_effect=fake_audit):
            rc = main([
                "--mode", "export",
                "--config", str(config_path),
                "--output-dir", str(tmp_path / "exported"),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--no-connectivity-test",
            ])

        assert rc == 130

    def test_main_returns_130_when_second_staged_import_audit_raises_after_stop(self, tmp_path: Path) -> None:
        from components.main import main

        input_root = tmp_path / "exported"
        _write_legacy_message_fixture(input_root / "a@example.com" / "INBOX")
        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "source_server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))
        handlers = {}
        audit_calls = 0

        class DummyCPanelClient:
            def __init__(self, *_args, **_kwargs) -> None:
                pass

        def fake_signal(signum, handler):
            handlers[signum] = handler

        def fake_audit(*_args, **_kwargs):
            nonlocal audit_calls
            audit_calls += 1
            if audit_calls == 1:
                return True, []
            handlers[signal.SIGTERM](signal.SIGTERM, None)
            raise RuntimeError("staged audit interrupted")

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.main.signal.signal", fake_signal), \
            mock.patch("components.main._ensure_cpanel_client_dependency"), \
            mock.patch("components.main.CPanelClient", DummyCPanelClient), \
            mock.patch("components.main.ensure_accounts_exist_cpanel"), \
            mock.patch("components.main.audit_export", side_effect=fake_audit), \
            mock.patch("components.main.import_account", side_effect=AssertionError("import should not start after stop")):
            rc = main([
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(input_root),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--no-connectivity-test",
                "--auto-provision-cpanel",
                "--cpanel-url", "https://panel.example.com:2083",
                "--cpanel-username", "cpuser",
                "--cpanel-token", "api-token",
            ])

        assert audit_calls == 2
        assert rc == 130

    def test_legacy_audit_export_stop_event_stops_queued_accounts_and_drains_running_worker(self, tmp_path: Path) -> None:
        from components.audit import audit_export
        from components.models import Account, Config, ServerConfig

        stop_event = threading.Event()
        accounts = [
            Account("a@example.com", "secret-a"),
            Account("b@example.com", "secret-b"),
        ]
        config = Config(ServerConfig("imap.example.com"), accounts)
        started: List[str] = []
        finished: List[str] = []

        def fake_audit_account(account: Account, *_args, **_kwargs):
            started.append(account.email)
            stop_event.set()
            time.sleep(0.05)
            finished.append(account.email)
            return account.email, []

        with mock.patch("components.audit.audit_account", side_effect=fake_audit_account):
            with pytest.raises(RuntimeError, match="stop requested before completion"):
                audit_export(
                    tmp_path,
                    config,
                    max_workers=1,
                    check_remote=False,
                    stop_event=stop_event,
                )

        assert started == ["a@example.com"]
        assert finished == ["a@example.com"]

    def test_remote_audit_rechecks_regular_message_file_against_sidecar(self, tmp_path: Path) -> None:
        from components.audit import audit_export
        from components.models import Account, Config, ServerConfig

        server = ServerConfig("imap.example.com")
        folder = tmp_path / "user@example.com" / "INBOX"
        original = b"Message-ID: <regular-swap@example.com>\r\nFrom: a\r\nTo: b\r\n\r\noriginal"
        swapped = b"Message-ID: <regular-swap@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nswapped"
        eml = _write_legacy_message_fixture(folder, data=original, source_server=server)
        swapped_once = False

        class FakeRemote:
            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

            def select(self, *_args, **_kwargs):
                return "OK", [b"1"]

            def uid(self, command: str, *args):
                if command == "search":
                    return "OK", [b"1"]
                raise AssertionError(command)

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs):
            nonlocal swapped_once
            eml.write_bytes(swapped)
            swapped_once = True
            yield FakeRemote()

        with mock.patch("components.audit.imap_connection", fake_connection), \
            mock.patch("components.audit._remote_has_message", return_value=True):
            ok, issues = audit_export(
                tmp_path,
                Config(server, [Account("user@example.com", "secret")], source_server=server),
                1,
                check_remote=True,
                require_integrity_metadata=True,
            )

        assert swapped_once
        assert not ok
        assert any("mismatch" in issue for issue in issues)

    def test_validate_rechecks_regular_message_file_against_sidecar_after_audit(self, tmp_path: Path) -> None:
        from components.audit import audit_export as real_audit_export
        from components.main import main
        from components.models import ServerConfig

        input_root = tmp_path / "exported"
        folder = input_root / "user@example.com" / "INBOX"
        source_server = {
            "host": "source.example.com",
            "port": 993,
            "ssl": True,
            "starttls": False,
        }
        target_server = {
            "host": "target.example.com",
            "port": 993,
            "ssl": True,
            "starttls": False,
        }
        original = b"Message-ID: <validate-regular-swap@example.com>\r\nFrom: a\r\nTo: b\r\n\r\noriginal"
        swapped = b"Message-ID: <validate-regular-swap@example.com>\r\nFrom: a\r\nTo: b\r\n\r\nswapped"
        eml = _write_legacy_message_fixture(
            folder,
            data=original,
            source_server=ServerConfig(**source_server),
        )
        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": target_server,
            "source_server": source_server,
            "accounts": [{"email": "user@example.com", "password": "secret"}],
        }))
        calls = 0

        class FakeRemote:
            def list(self):
                return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

            def select(self, *_args, **_kwargs):
                return "OK", [b"1"]

            def uid(self, command: str, *args):
                if command == "search":
                    return "OK", [b"1"]
                raise AssertionError(command)

        @contextlib.contextmanager
        def fake_connection(*_args, **_kwargs):
            yield FakeRemote()

        def audit_then_swap(*args, **kwargs):
            nonlocal calls
            calls += 1
            result = real_audit_export(*args, **kwargs)
            if calls == 2:
                eml.write_bytes(swapped)
            return result

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.main.audit_export", side_effect=audit_then_swap), \
            mock.patch("components.imap_ops.imap_connection", fake_connection), \
            mock.patch("components.imap_ops._legacy_remote_has_message", return_value=True):
            rc = main([
                "--mode", "validate",
                "--config", str(config_path),
                "--input-dir", str(input_root),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--no-connectivity-test",
            ])

        assert calls == 2
        assert eml.read_bytes() == swapped
        assert rc == 4

    def test_main_signal_handler_sets_stop_without_logging_first(self, tmp_path: Path) -> None:
        from components.main import main

        config_path = tmp_path / "test.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))
        handlers = {}

        def fake_signal(signum, handler):
            handlers[signum] = handler

        def fake_test_accounts(*_args, **kwargs):
            stop_event = kwargs["stop_event"]
            with mock.patch("components.main.logging.warning", side_effect=AssertionError("signal handler must not log")):
                handlers[signal.SIGTERM](signal.SIGTERM, None)
            assert stop_event.is_set()

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.utils.ensure_imapsync_available"), \
            mock.patch("components.main.signal.signal", fake_signal), \
            mock.patch("components.main.test_accounts", side_effect=fake_test_accounts):
            rc = main([
                "--mode", "test",
                "--config", str(config_path),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
            ])

        assert rc == 130

    def test_main_returns_130_when_signal_arrives_during_panel_staged_audit(self, tmp_path: Path) -> None:
        from components.main import main

        input_root = tmp_path / "exported"
        _write_legacy_message_fixture(input_root / "a@example.com" / "INBOX")
        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "source_server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))
        handlers = {}

        def fake_signal(signum, handler):
            handlers[signum] = handler

        def fake_audit(*_args, **_kwargs):
            assert signal.SIGTERM in handlers
            handlers[signal.SIGTERM](signal.SIGTERM, None)
            return True, []

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.main.signal.signal", fake_signal), \
            mock.patch("components.main._ensure_cpanel_client_dependency"), \
            mock.patch("components.main.audit_export", side_effect=fake_audit), \
            mock.patch("components.main.CPanelClient", side_effect=AssertionError("panel client should not be created after stop")):
            rc = main([
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(input_root),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--no-connectivity-test",
                "--auto-provision-cpanel",
                "--cpanel-url", "https://panel.example.com:2083",
                "--cpanel-username", "cpuser",
                "--cpanel-token", "api-token",
            ])

        assert rc == 130

    def test_main_returns_130_when_cpanel_reset_raises_after_stop(self, tmp_path: Path) -> None:
        from components.main import main

        input_root = tmp_path / "exported"
        _write_legacy_message_fixture(input_root / "a@example.com" / "INBOX")
        config_path = tmp_path / "import.pass.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "source_server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))
        handlers = {}

        class DummyCPanelClient:
            def __init__(self, *_args, **_kwargs) -> None:
                pass

        def fake_signal(signum, handler):
            handlers[signum] = handler

        def fake_reset(*_args, **kwargs):
            assert "stop_event" in kwargs
            handlers[signal.SIGTERM](signal.SIGTERM, None)
            raise RuntimeError("stop requested")

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.main.signal.signal", fake_signal), \
            mock.patch("components.main._ensure_cpanel_client_dependency"), \
            mock.patch("components.main.audit_export", return_value=(True, [])), \
            mock.patch("components.main.CPanelClient", DummyCPanelClient), \
            mock.patch("components.cpanel_ensure.reset_accounts_cpanel", side_effect=fake_reset):
            rc = main([
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(input_root),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                "--no-connectivity-test",
                "--auto-provision-cpanel",
                "--reset",
                "--reset-confirm", "imap.example.com",
                "--cpanel-url", "https://panel.example.com:2083",
                "--cpanel-username", "cpuser",
                "--cpanel-token", "api-token",
            ])

        assert rc == 130

    def test_main_returns_130_when_signal_arrives_during_legacy_test_connectivity(self, tmp_path: Path) -> None:
        from components.main import main

        config_path = tmp_path / "test.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))
        handlers = {}

        def fake_signal(signum, handler):
            handlers[signum] = handler

        def fake_test_accounts(*_args, **_kwargs):
            handlers[signal.SIGINT](signal.SIGINT, None)

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.utils.ensure_imapsync_available"), \
            mock.patch("components.main.signal.signal", fake_signal), \
            mock.patch("components.main.test_accounts", side_effect=fake_test_accounts):
            rc = main([
                "--mode", "test",
                "--config", str(config_path),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
            ])

        assert rc == 130

    def test_legacy_test_accounts_stop_event_prevents_later_account_probes(self) -> None:
        from components.main import test_accounts
        from components.models import Account, Config, ServerConfig

        stop_event = threading.Event()
        config = Config(
            ServerConfig("imap.example.com"),
            [
                Account("a@example.com", "secret-a"),
                Account("b@example.com", "secret-b"),
            ],
        )
        imap_probes: List[str] = []
        imapsync_probes: List[str] = []

        @contextlib.contextmanager
        def fake_connection(_server, account):
            imap_probes.append(account.email)
            if account.email == "a@example.com":
                stop_event.set()
            yield object()

        def fake_justconnect(*_args, user, **_kwargs):
            imapsync_probes.append(user)
            return True, "ok"

        with mock.patch("components.imap_ops.imap_connection", fake_connection), \
            mock.patch("components.main.run_imapsync_justconnect", fake_justconnect):
            with pytest.raises(RuntimeError, match="stop requested"):
                test_accounts(config, max_workers=1, stop_event=stop_event)

        assert imap_probes == ["a@example.com"]
        assert imapsync_probes == []

    def test_legacy_test_accounts_stop_waits_for_running_probe_to_finish(self) -> None:
        from components.main import test_accounts
        from components.models import Account, Config, ServerConfig

        stop_event = threading.Event()
        worker_finished = threading.Event()
        config = Config(
            ServerConfig("imap.example.com"),
            [Account("a@example.com", "secret-a")],
        )

        @contextlib.contextmanager
        def fake_connection(_server, _account):
            stop_event.set()
            time.sleep(0.05)
            worker_finished.set()
            yield object()

        with mock.patch("components.imap_ops.imap_connection", fake_connection), \
            mock.patch("components.main.run_imapsync_justconnect", side_effect=AssertionError("imapsync should not run after stop")):
            with pytest.raises(RuntimeError, match="stop requested"):
                test_accounts(config, max_workers=1, stop_event=stop_event)

        assert worker_finished.is_set()

    def test_main_returns_130_when_signal_arrives_during_provider_preflight_success(self, tmp_path: Path) -> None:
        from components.main import main

        config_path = tmp_path / "provider.config.json"
        config_path.write_text(json.dumps({
            "source": {
                "provider": "imap",
                "host": "source.example.com",
                "auth": {"method": "password", "username": "source@example.com", "password": "secret"},
            },
            "target": {
                "provider": "imap",
                "host": "target.example.com",
                "auth": {"method": "password", "username": "target@example.com", "password": "secret"},
            },
            "accounts": [{"source_email": "source@example.com", "target_email": "target@example.com"}],
        }))
        handlers = {}

        def fake_signal(signum, handler):
            handlers[signum] = handler

        def fake_preflight(*_args, **kwargs):
            stop_event = kwargs.get("stop_event")
            assert stop_event is not None
            handlers[signal.SIGINT](signal.SIGINT, None)
            assert stop_event.is_set()
            return True, []

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.main.signal.signal", fake_signal), \
            mock.patch("components.main.provider_preflight", side_effect=fake_preflight):
            rc = main([
                "--mode", "preflight",
                "--config", str(config_path),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
            ])

        assert rc == 130

    def test_main_returns_130_for_stop_requested_worker_exception(self, tmp_path: Path) -> None:
        from components.main import main

        config_path = tmp_path / "export.config.json"
        config_path.write_text(json.dumps({
            "server": {"host": "imap.example.com", "port": 993, "ssl": True, "starttls": False},
            "accounts": [{"email": "a@example.com", "password": "secret"}],
        }))
        handlers = {}

        def fake_signal(signum, handler):
            handlers[signum] = handler

        def fake_export(*_args, **_kwargs):
            handlers[signal.SIGTERM](signal.SIGTERM, None)
            raise RuntimeError("legacy export a@example.com: stop requested before completion")

        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.main.signal.signal", fake_signal), \
            mock.patch("components.main.export_account", side_effect=fake_export):
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

        assert rc == 130

    def test_provider_private_read_rejects_ancestor_swap_during_final_open(self, tmp_path: Path) -> None:
        from components import provider_ops

        account_dir = tmp_path / "source@example.com"
        account_dir.mkdir()
        (account_dir / "manifest.jsonl").write_text("original\n")
        outside = tmp_path / "outside-provider"
        outside.mkdir()
        (outside / "manifest.jsonl").write_text("evil\n")
        backup = tmp_path / "checked-provider"
        real_open = provider_ops.os.open
        swapped = False

        def racing_open(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal swapped
            if path == "manifest.jsonl" and dir_fd is not None and not swapped:
                account_dir.rename(backup)
                account_dir.symlink_to(outside, target_is_directory=True)
                swapped = True
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with mock.patch("components.provider_ops.os.open", racing_open):
            with pytest.raises(RuntimeError, match="replaced provider file directory"):
                provider_ops._read_provider_private_file(account_dir / "manifest.jsonl")

        assert swapped
        assert account_dir.is_symlink()

    def test_provider_atomic_write_rejects_ancestor_swap_after_directory_check(self, tmp_path: Path) -> None:
        from components import provider_ops

        account_dir = tmp_path / "source@example.com"
        outside = tmp_path / "outside-provider-write"
        backup = tmp_path / "checked-provider-write"
        real_ensure = provider_ops.ensure_private_dir
        swapped = False

        def racing_ensure(path: Path) -> None:
            nonlocal swapped
            real_ensure(path)
            if path == account_dir and not swapped:
                account_dir.rename(backup)
                outside.mkdir()
                account_dir.symlink_to(outside, target_is_directory=True)
                swapped = True

        with mock.patch("components.provider_ops.ensure_private_dir", racing_ensure):
            with pytest.raises(RuntimeError, match="symlinked provider file|replaced provider file directory"):
                provider_ops._atomic_json(account_dir / "export-state.json", {"where": "payload"})

        assert swapped
        assert account_dir.is_symlink()
        assert not (outside / "export-state.json").exists()

    def test_legacy_private_read_rejects_ancestor_swap_during_final_open(self, tmp_path: Path) -> None:
        from components import imap_ops

        folder = tmp_path / "user@example.com" / "INBOX"
        folder.mkdir(parents=True)
        message = folder / "u0000000001.eml"
        message.write_bytes(b"original")
        outside = tmp_path / "outside-legacy"
        outside.mkdir()
        (outside / "u0000000001.eml").write_bytes(b"evil")
        backup = tmp_path / "checked-legacy"
        real_open = imap_ops.os.open
        swapped = False

        def racing_open(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal swapped
            if path == "u0000000001.eml" and dir_fd is not None and not swapped:
                folder.rename(backup)
                folder.symlink_to(outside, target_is_directory=True)
                swapped = True
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with mock.patch("components.imap_ops.os.open", racing_open):
            with pytest.raises(RuntimeError, match="replaced legacy message file directory"):
                imap_ops._read_file_no_symlink(message, "legacy message file", reject_hard_links=True)

        assert swapped
        assert folder.is_symlink()

    def test_legacy_atomic_write_rejects_ancestor_swap_after_directory_check(self, tmp_path: Path) -> None:
        from components import imap_ops

        folder = tmp_path / "user@example.com" / "INBOX"
        outside = tmp_path / "outside-legacy-write"
        backup = tmp_path / "checked-legacy-write"
        real_ensure = imap_ops.ensure_private_dir
        swapped = False

        def racing_ensure(path: Path) -> None:
            nonlocal swapped
            real_ensure(path)
            if path == folder and not swapped:
                folder.rename(backup)
                outside.mkdir()
                folder.symlink_to(outside, target_is_directory=True)
                swapped = True

        with mock.patch("components.imap_ops.ensure_private_dir", racing_ensure):
            with pytest.raises(RuntimeError, match="symlinked legacy file|replaced legacy file directory"):
                imap_ops._secure_atomic_write_bytes(folder / "u0000000001.eml", b"payload")

        assert swapped
        assert folder.is_symlink()
        assert not (outside / "u0000000001.eml").exists()

    def test_strict_audit_rejects_invalid_legacy_delivery_metadata(self, tmp_path: Path) -> None:
        from components.audit import audit_export
        from components.content_binding import CONTENT_BINDING_FIELD, legacy_content_binding_sha256
        from components.models import Account, Config, ServerConfig

        server = ServerConfig("imap.example.com")
        folder = tmp_path / "user@example.com" / "INBOX"
        eml = _write_legacy_message_fixture(
            folder,
            uid=1,
            mailbox="INBOX",
            data=b"Message-ID: <m@example.com>\r\nFrom: a@example.com\r\nTo: b@example.com\r\n\r\nbody",
            source_server=server,
        )
        meta_path = eml.with_suffix(".json")
        meta = json.loads(meta_path.read_text())
        meta["flags"] = ["\\Seen"]
        meta["internaldate"] = {"bad": "date"}
        meta[CONTENT_BINDING_FIELD] = legacy_content_binding_sha256(meta)
        meta_path.write_text(json.dumps(meta))

        ok, issues = audit_export(
            tmp_path,
            Config(server, [Account("user@example.com", "secret")], source_server=server),
            1,
            check_remote=False,
            require_integrity_metadata=True,
        )

        assert not ok
        assert any("invalid flags metadata" in issue for issue in issues)
        assert any("invalid internaldate metadata" in issue for issue in issues)

    def test_direct_import_rejects_invalid_legacy_delivery_metadata_before_append(self, tmp_path: Path) -> None:
        from components.content_binding import CONTENT_BINDING_FIELD, legacy_content_binding_sha256
        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        folder = tmp_path / "user@example.com" / "INBOX"
        eml = _write_legacy_message_fixture(
            folder,
            uid=1,
            mailbox="INBOX",
            data=b"Message-ID: <m@example.com>\r\nFrom: a@example.com\r\nTo: b@example.com\r\n\r\nbody",
        )
        meta_path = eml.with_suffix(".json")
        meta = json.loads(meta_path.read_text())
        meta["flags"] = "BAD ))"
        meta["internaldate"] = "not a date"
        meta[CONTENT_BINDING_FIELD] = legacy_content_binding_sha256(meta)
        meta_path.write_text(json.dumps(meta))

        with pytest.raises(RuntimeError, match="invalid flags metadata.*invalid internaldate metadata"):
            import_account(
                Account("user@example.com", "secret"),
                ServerConfig("imap.example.com"),
                tmp_path,
                ignore_errors=False,
                imap_factory=lambda *_args: (_ for _ in ()).throw(AssertionError("IMAP should not be opened")),
            )

    def test_direct_import_rejects_non_ascii_legacy_flags_before_connect(self, tmp_path: Path) -> None:
        from components.content_binding import CONTENT_BINDING_FIELD, legacy_content_binding_sha256
        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        folder = tmp_path / "user@example.com" / "INBOX"
        eml = _write_legacy_message_fixture(
            folder,
            uid=1,
            mailbox="INBOX",
            data=b"Message-ID: <m@example.com>\r\nFrom: a@example.com\r\nTo: b@example.com\r\n\r\nbody",
        )
        meta_path = eml.with_suffix(".json")
        meta = json.loads(meta_path.read_text())
        meta["flags"] = "flag\xe9"
        meta[CONTENT_BINDING_FIELD] = legacy_content_binding_sha256(meta)
        meta_path.write_text(json.dumps(meta))

        with pytest.raises(RuntimeError, match="invalid flags metadata"):
            import_account(
                Account("user@example.com", "secret"),
                ServerConfig("imap.example.com"),
                tmp_path,
                ignore_errors=False,
                imap_factory=lambda *_args: (_ for _ in ()).throw(AssertionError("IMAP should not be opened")),
            )

    def test_direct_import_rejects_non_imap_internaldate_before_connect(self, tmp_path: Path) -> None:
        from components.content_binding import CONTENT_BINDING_FIELD, legacy_content_binding_sha256
        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        folder = tmp_path / "user@example.com" / "INBOX"
        eml = _write_legacy_message_fixture(
            folder,
            uid=1,
            mailbox="INBOX",
            data=b"Message-ID: <m@example.com>\r\nFrom: a@example.com\r\nTo: b@example.com\r\n\r\nbody",
        )
        meta_path = eml.with_suffix(".json")
        meta = json.loads(meta_path.read_text())
        meta["internaldate"] = "Mon, 1 Jan 2024 00:00:00 +0000"
        meta[CONTENT_BINDING_FIELD] = legacy_content_binding_sha256(meta)
        meta_path.write_text(json.dumps(meta))

        with pytest.raises(RuntimeError, match="invalid internaldate metadata"):
            import_account(
                Account("user@example.com", "secret"),
                ServerConfig("imap.example.com"),
                tmp_path,
                ignore_errors=False,
                imap_factory=lambda *_args: (_ for _ in ()).throw(AssertionError("IMAP should not be opened")),
            )

    @pytest.mark.parametrize(
        ("uid_value", "message"),
        [
            (2, "uid mismatch"),
            ("1", "invalid uid metadata"),
        ],
    )
    def test_direct_import_rejects_legacy_uid_metadata_before_connect(
        self,
        tmp_path: Path,
        uid_value: object,
        message: str,
    ) -> None:
        from components.content_binding import CONTENT_BINDING_FIELD, legacy_content_binding_sha256
        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        folder = tmp_path / "user@example.com" / "INBOX"
        eml = _write_legacy_message_fixture(
            folder,
            uid=1,
            mailbox="INBOX",
            data=b"Message-ID: <uid-mismatch@example.com>\r\nFrom: a@example.com\r\nTo: b@example.com\r\n\r\nbody",
        )
        meta_path = eml.with_suffix(".json")
        meta = json.loads(meta_path.read_text())
        meta["uid"] = uid_value
        meta[CONTENT_BINDING_FIELD] = legacy_content_binding_sha256(meta)
        meta_path.write_text(json.dumps(meta))

        with pytest.raises(RuntimeError, match=message):
            import_account(
                Account("user@example.com", "secret"),
                ServerConfig("imap.example.com"),
                tmp_path,
                ignore_errors=False,
                imap_factory=lambda *_args: (_ for _ in ()).throw(AssertionError("IMAP should not be opened")),
            )

    def test_strict_audit_import_and_verify_reject_legacy_hierarchy_tamper(
        self,
        tmp_path: Path,
    ) -> None:
        from components.audit import audit_export
        from components.content_binding import CONTENT_BINDING_FIELD, legacy_content_binding_sha256
        from components.imap_ops import import_account
        from components.models import Account, Config, ServerConfig
        from verify_export import verify_account

        server = ServerConfig("source.example.com")
        account = Account("user@example.com", "secret")
        folder = tmp_path / account.email / "Projects_2024"
        eml = _write_legacy_message_fixture(
            folder,
            uid=1,
            mailbox="Projects/2024",
            data=b"Message-ID: <hierarchy-tamper@example.com>\r\nFrom: a@example.com\r\nTo: b@example.com\r\n\r\nbody",
            source_server=server,
        )
        marker = {
            "mailbox": "Projects/2024",
            "message_count": 1,
            "source_delimiter": "/",
            "source_path_segments": ["Projects", "2024"],
        }
        (folder / ".mailbox.json").write_text(json.dumps(marker))
        meta_path = eml.with_suffix(".json")
        meta = json.loads(meta_path.read_text())
        meta["source_delimiter"] = "/"
        meta["source_path_segments"] = ["Projects", "2024"]
        meta[CONTENT_BINDING_FIELD] = legacy_content_binding_sha256(meta)
        meta_path.write_text(json.dumps(meta))
        state_path = folder.parent / "export-state.json"
        state = json.loads(state_path.read_text())
        state["mailboxes"] = [{
            "mailbox": "Projects/2024",
            "path": "Projects_2024",
            "message_count": 1,
            "source_delimiter": "/",
            "source_path_segments": ["Projects", "2024"],
        }]
        state_path.write_text(json.dumps(state))

        tampered_hierarchy = {
            "source_delimiter": "j",
            "source_path_segments": ["Pro", "ects/2024"],
        }
        marker.update(tampered_hierarchy)
        (folder / ".mailbox.json").write_text(json.dumps(marker))
        meta.update(tampered_hierarchy)
        meta[CONTENT_BINDING_FIELD] = legacy_content_binding_sha256(meta)
        meta_path.write_text(json.dumps(meta))

        ok, issues = audit_export(
            tmp_path,
            Config(server, [account], source_server=server),
            1,
            check_remote=False,
            require_integrity_metadata=True,
        )

        assert not ok
        assert any("source_path_segments mismatch with export-state" in issue for issue in issues)
        with pytest.raises(RuntimeError, match="source_path_segments mismatch with export-state"):
            import_account(
                account,
                ServerConfig("target.example.com"),
                tmp_path,
                ignore_errors=False,
                imap_factory=lambda *_args: (_ for _ in ()).throw(AssertionError("IMAP should not be opened")),
                source_server=server,
            )
        stats = verify_account(folder.parent)
        assert stats["errors"] >= 1

    def test_verify_export_rejects_invalid_legacy_delivery_metadata(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from verify_export import main, verify_account

        account_dir = tmp_path / "exported" / "user@example.com"
        inbox = account_dir / "INBOX"
        inbox.mkdir(parents=True)
        data = b"Message-ID: <m@example.com>\r\nFrom: a@example.com\r\nTo: b@example.com\r\n\r\nbody"
        (inbox / "u0000000001.eml").write_bytes(data)
        (inbox / "u0000000001.json").write_text(json.dumps(_legacy_integrity_metadata(
            data,
            mailbox="INBOX",
            uid=True,
            flags=["\\Seen"],
            internaldate={"bad": "date"},
        )))
        (inbox / ".mailbox.json").write_text(json.dumps({"mailbox": "INBOX", "message_count": 1}))
        _write_verify_export_state(account_dir, [{"mailbox": "INBOX", "path": "INBOX", "message_count": 1}])
        monkeypatch.chdir(tmp_path)

        stats = verify_account(account_dir)

        assert stats["errors"] == 1
        assert main() == 1

    @pytest.mark.parametrize("flag", ["project[2024", "project}2024"])
    def test_direct_import_allows_valid_atom_special_flag_keywords(self, tmp_path: Path, flag: str) -> None:
        from components.content_binding import CONTENT_BINDING_FIELD, legacy_content_binding_sha256
        from components.imap_ops import import_account
        from components.models import Account, ServerConfig

        folder = tmp_path / "user@example.com" / "INBOX"
        eml = _write_legacy_message_fixture(
            folder,
            uid=1,
            mailbox="INBOX",
            data=b"Message-ID: <m@example.com>\r\nFrom: a@example.com\r\nTo: b@example.com\r\n\r\nbody",
        )
        meta_path = eml.with_suffix(".json")
        meta = json.loads(meta_path.read_text())
        meta["flags"] = flag
        meta[CONTENT_BINDING_FIELD] = legacy_content_binding_sha256(meta)
        meta_path.write_text(json.dumps(meta))

        class AppendTarget:
            appended_flags: List[str] = []

            def select(self, mailbox: str, readonly: bool = False):
                return "OK", [b"0"]

            def append(self, mailbox: str, flags: str, date_time: str, payload: bytes):
                self.appended_flags.append(flags)
                return "OK", [b""]

            def subscribe(self, mailbox: str):
                return "OK", [b""]

            def logout(self):
                return "OK", [b""]

        target = AppendTarget()

        @contextlib.contextmanager
        def fake_factory(*_args, **_kwargs) -> Iterator[AppendTarget]:
            yield target

        import_account(
            Account("user@example.com", "secret"),
            ServerConfig("imap.example.com"),
            tmp_path,
            ignore_errors=False,
            imap_factory=fake_factory,
            source_server=ServerConfig("imap.example.com"),
        )

        assert target.appended_flags == [f"({flag})"]
