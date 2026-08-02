from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import contextlib
import errno
import hashlib
import json
from pathlib import Path
import stat
import subprocess
import sys
import threading
from types import SimpleNamespace
from unittest import mock

import pytest

from components.main import main
from components.models import (
    Account,
    AuthConfig,
    Config,
    MigrationAccount,
    MigrationSettings,
    ProviderEndpoint,
    ProviderMigrationConfig,
    ServerConfig,
)
from components.provider_ops import ProviderImportIntegrityGateError
from components.routing import RoutingConfig


@pytest.fixture(autouse=True)
def _isolate_legacy_global_target_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from components import imap_ops

    monkeypatch.setattr(
        imap_ops,
        "LEGACY_GLOBAL_STATE_PARENT",
        tmp_path / ".legacy-global-state-parent",
    )


def _provider_config(*, routing: bool) -> ProviderMigrationConfig:
    return ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="source.example.com",
            auth=AuthConfig(method="password", password="source-secret"),
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(
                method="app_password",
                username="target@example.com",
                password="target-secret",
            ),
        ),
        accounts=[
            MigrationAccount(
                source_email="source@example.com",
                target_email="target@example.com",
            )
        ],
        migration=MigrationSettings(
            target_mode="merge",
            routing=RoutingConfig(enabled=routing),
        ),
    )


def _base_args(tmp_path: Path, mode: str) -> list[str]:
    config_path = tmp_path / "config.json"
    config_path.write_text("{}\n", encoding="utf-8")
    return [
        "--mode",
        mode,
        "--config",
        str(config_path),
        "--output-dir",
        str(tmp_path / "staged"),
        "--input-dir",
        str(tmp_path / "staged"),
        "--log-dir",
        str(tmp_path / "logs"),
        "--min-free-gb",
        "0",
        "--max-workers",
        "1",
    ]


def test_legacy_reset_and_journal_archive_run_under_import_lock(
    tmp_path: Path,
) -> None:
    from components import imap_ops

    server = ServerConfig(
        host="target.example.com",
        port=993,
        ssl=True,
        starttls=False,
    )
    account = Account(email="user@example.com", password="mail-secret")
    config = Config(server=server, accounts=[account], source_server=server)
    config_path = tmp_path / "legacy-import.json"
    config_path.write_text("{}\n", encoding="utf-8")
    input_root = tmp_path / "legacy-staged"
    account_dir = input_root / account.email
    account_dir.mkdir(parents=True, mode=0o700)
    journal = account_dir / "import.journal.jsonl"
    journal.write_text(
        json.dumps(
            {
                "key": "a" * 64,
                "target": "b" * 64,
                "status": "committed",
                "mailbox": "INBOX",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    journal.chmod(0o600)
    events: list[str] = []
    client = object()
    child_probe = (
        "import fcntl, os, sys; "
        "fd = os.open(sys.argv[1], os.O_RDWR); "
        "\ntry:\n fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)"
        "\nexcept BlockingIOError:\n sys.exit(23)"
        "\nfinally:\n os.close(fd)"
    )

    def reset_one(single_config: Config, actual_client, **kwargs):
        assert actual_client is client
        assert [item.email for item in single_config.accounts] == [account.email]
        assert kwargs["dry_run"] is False
        assert not journal.exists()
        assert len(list(account_dir.glob("import.journal.reset-*.jsonl"))) == 1
        reset_state = json.loads(
            (account_dir / imap_ops.LEGACY_RESET_STATE_FILENAME).read_text()
        )
        assert reset_state["phase"] == "reset_started"
        lock_path = imap_ops._legacy_import_lock_path(server, account, input_root)
        blocked = subprocess.run(
            [sys.executable, "-c", child_probe, str(lock_path)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert blocked.returncode == 23, blocked.stderr
        events.append("reset-under-lock")
        return set()

    def unlocked_import(*_args, **_kwargs) -> None:
        assert events == ["reset-under-lock"]
        assert not (account_dir / imap_ops.LEGACY_RESET_STATE_FILENAME).exists()
        events.append("import-after-reset")

    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.check_free_space_for_path"), \
        mock.patch("components.main.load_config_file", return_value=config), \
        mock.patch("components.main.audit_export", return_value=(True, [])), \
        mock.patch("components.utils.ensure_imapsync_available"), \
        mock.patch("components.main._ensure_cpanel_client_dependency"), \
        mock.patch("components.main.CPanelClient", return_value=client), \
        mock.patch("components.main.test_accounts", side_effect=AssertionError("pre-reset connectivity must not run")), \
        mock.patch("components.cpanel_ensure.reset_accounts_cpanel", side_effect=reset_one), \
        mock.patch("components.imap_ops._import_account_unlocked", side_effect=unlocked_import):
        rc = main([
            "--mode", "import",
            "--config", str(config_path),
            "--input-dir", str(input_root),
            "--log-dir", str(tmp_path / "legacy-logs"),
            "--min-free-gb", "0",
            "--max-workers", "1",
            "--auto-provision-cpanel",
            "--reset",
            "--reset-confirm", server.host,
            "--cpanel-url", "https://panel.example.com:2083",
            "--cpanel-username", "admin",
            "--cpanel-token", "panel-token",
        ])

    assert rc == 0
    assert events == ["reset-under-lock", "import-after-reset"]
    assert not journal.exists()
    assert not (account_dir / imap_ops.LEGACY_RESET_STATE_FILENAME).exists()


def test_local_reset_marker_symlink_is_rc4_before_audit_connectivity_or_import(
    tmp_path: Path,
) -> None:
    from components import imap_ops

    server = ServerConfig(
        host="target.example.com",
        port=993,
        ssl=True,
        starttls=False,
    )
    account = Account(email="user@example.com", password="mail-secret")
    config = Config(server=server, accounts=[account], source_server=server)
    input_root = tmp_path / "staged-reset-link"
    account_dir = input_root / account.email
    account_dir.mkdir(parents=True, mode=0o700)
    outside = tmp_path / "outside-reset-state.json"
    outside.write_text("{}\n", encoding="utf-8")
    marker = account_dir / imap_ops.LEGACY_RESET_STATE_FILENAME
    try:
        marker.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")
    config_path = tmp_path / "legacy-reset-link.json"
    config_path.write_text("{}\n", encoding="utf-8")

    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.check_free_space_for_path"), \
        mock.patch("components.main.load_config_file", return_value=config), \
        mock.patch("components.main.audit_export") as audit, \
        mock.patch("components.utils.ensure_imapsync_available") as dependency, \
        mock.patch("components.main.test_accounts") as connectivity, \
        mock.patch("components.main.import_account") as importer:
        rc = main([
            "--mode", "import",
            "--config", str(config_path),
            "--input-dir", str(input_root),
            "--log-dir", str(tmp_path / "logs-reset-link"),
            "--min-free-gb", "0",
            "--max-workers", "1",
        ])

    assert rc == 4
    audit.assert_not_called()
    dependency.assert_not_called()
    connectivity.assert_not_called()
    importer.assert_not_called()


def test_generic_legacy_staged_symlink_remains_rc2(
    tmp_path: Path,
) -> None:
    server = ServerConfig(
        host="target.example.com",
        port=993,
        ssl=True,
        starttls=False,
    )
    account = Account(email="user@example.com", password="mail-secret")
    config = Config(server=server, accounts=[account], source_server=server)
    input_root = tmp_path / "staged-generic-link"
    account_dir = input_root / account.email
    account_dir.mkdir(parents=True, mode=0o700)
    outside = tmp_path / "outside-message.eml"
    outside.write_bytes(b"message")
    staged_link = account_dir / "message.eml"
    try:
        staged_link.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")
    config_path = tmp_path / "legacy-generic-link.json"
    config_path.write_text("{}\n", encoding="utf-8")

    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.load_config_file", return_value=config), \
        mock.patch("components.main.legacy_reset_state_issues") as reset_gate, \
        mock.patch("components.main.audit_export") as audit, \
        mock.patch("components.main.test_accounts") as connectivity, \
        mock.patch("components.main.import_account") as importer:
        rc = main([
            "--mode", "import",
            "--config", str(config_path),
            "--input-dir", str(input_root),
            "--log-dir", str(tmp_path / "logs-generic-link"),
            "--min-free-gb", "0",
            "--max-workers", "1",
        ])

    assert rc == 2
    reset_gate.assert_not_called()
    audit.assert_not_called()
    connectivity.assert_not_called()
    importer.assert_not_called()


@pytest.mark.parametrize("panel", ["directadmin", "cpanel"])
def test_pending_legacy_reset_blocks_panel_and_target_contact(
    tmp_path: Path,
    panel: str,
) -> None:
    from components import imap_ops

    server = ServerConfig(
        host="target.example.com",
        port=993,
        ssl=True,
        starttls=False,
    )
    account = Account(email="user@example.com", password="mail-secret")
    config = Config(server=server, accounts=[account], source_server=server)
    input_root = tmp_path / "staged"
    account_dir = input_root / account.email
    account_dir.mkdir(parents=True, mode=0o700)
    imap_ops._begin_legacy_reset_state(account_dir, account, server)

    if panel == "directadmin":
        panel_args = [
            "--auto-provision-da",
            "--da-url", "https://panel.example.com:2222",
            "--da-username", "admin",
            "--da-password", "panel-secret",
        ]
    else:
        panel_args = [
            "--auto-provision-cpanel",
            "--cpanel-url", "https://panel.example.com:2083",
            "--cpanel-username", "admin",
            "--cpanel-token", "panel-token",
        ]

    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.check_free_space_for_path"), \
        mock.patch("components.main.load_config_file", return_value=config), \
        mock.patch("components.main._ensure_directadmin_client_dependency"), \
        mock.patch("components.main._ensure_cpanel_client_dependency"), \
        mock.patch("components.main.DirectAdminClient") as da_client_cls, \
        mock.patch("components.main.CPanelClient") as cpanel_client_cls, \
        mock.patch("components.main.audit_export") as audit_mock, \
        mock.patch("components.main.test_accounts") as connectivity_mock, \
        mock.patch("components.main.import_account") as import_mock:
        rc = main([
            *_base_args(tmp_path, "import"),
            *panel_args,
        ])

    assert rc == 4
    da_client_cls.assert_not_called()
    cpanel_client_cls.assert_not_called()
    audit_mock.assert_not_called()
    connectivity_mock.assert_not_called()
    import_mock.assert_not_called()


@pytest.mark.parametrize(
    "marker_kind",
    ["local-malformed", "local-mismatched", "global-malformed", "global-mismatched"],
)
def test_reset_authoritative_marker_error_returns_rc4_without_target_mutation(
    tmp_path: Path,
    marker_kind: str,
) -> None:
    from components import imap_ops

    server = ServerConfig(
        host="target.example.com",
        port=993,
        ssl=True,
        starttls=False,
    )
    other_server = ServerConfig(
        host="other-target.example.com",
        port=993,
        ssl=True,
        starttls=False,
    )
    account = Account(email="user@example.com", password="mail-secret")
    config = Config(server=server, accounts=[account], source_server=server)
    input_root = tmp_path / "staged"
    account_dir = input_root / account.email
    account_dir.mkdir(parents=True, mode=0o700)
    local_path = account_dir / imap_ops.LEGACY_RESET_STATE_FILENAME
    imap_ops._ensure_legacy_global_state_dirs()
    global_path = imap_ops._legacy_global_reset_state_path(server, account)

    if marker_kind.endswith("malformed"):
        marker_path = local_path if marker_kind.startswith("local") else global_path
        marker_path.write_bytes(b"{malformed\n")
        marker_path.chmod(0o600)
    else:
        mismatched = imap_ops._new_legacy_reset_state(
            account_dir,
            account,
            other_server,
            phase="prepared",
            started_at=1,
            reset_id=hashlib.sha256(b"mismatched-reset").hexdigest(),
        )
        marker_path = local_path if marker_kind.startswith("local") else global_path
        marker_path.write_text(json.dumps(mismatched) + "\n", encoding="utf-8")
        marker_path.chmod(0o600)

    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.check_free_space_for_path"), \
        mock.patch("components.main.load_config_file", return_value=config), \
        mock.patch("components.main.legacy_reset_state_issues", return_value=[]), \
        mock.patch("components.main.audit_export", return_value=(True, [])), \
        mock.patch("components.main._ensure_cpanel_client_dependency"), \
        mock.patch("components.main.CPanelClient", return_value=object()), \
        mock.patch("components.cpanel_ensure.reset_accounts_cpanel") as reset_mock, \
        mock.patch("components.imap_ops._import_account_unlocked") as import_mock:
        rc = main([
            *_base_args(tmp_path, "import"),
            "--no-connectivity-test",
            "--auto-provision-cpanel",
            "--reset",
            "--reset-confirm", server.host,
            "--cpanel-url", "https://panel.example.com:2083",
            "--cpanel-username", "admin",
            "--cpanel-token", "panel-token",
        ])

    assert rc == 4
    reset_mock.assert_not_called()
    import_mock.assert_not_called()


def test_cross_root_reset_gate_with_ignore_errors_continues_independent_account(
    tmp_path: Path,
) -> None:
    from components import imap_ops

    server = ServerConfig(
        host="target.example.com",
        port=993,
        ssl=True,
        starttls=False,
    )
    blocked = Account(email="blocked@example.com", password="blocked-secret")
    healthy = Account(email="healthy@example.com", password="healthy-secret")
    config = Config(
        server=server,
        accounts=[blocked, healthy],
        source_server=server,
    )
    owner_root = tmp_path / "owner-staged"
    ordinary_root = tmp_path / "ordinary-staged"
    owner_account_dir = owner_root / blocked.email
    owner_account_dir.mkdir(parents=True, mode=0o700)
    for account in config.accounts:
        (ordinary_root / account.email).mkdir(parents=True, mode=0o700)
    config_path = tmp_path / "config.json"
    config_path.write_text("{}\n", encoding="utf-8")
    with imap_ops._legacy_import_lock(server, blocked, owner_root, stop_event=None):
        imap_ops._begin_legacy_reset_state(owner_account_dir, blocked, server)

    imported: list[str] = []
    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.check_free_space_for_path"), \
        mock.patch("components.main.load_config_file", return_value=config), \
        mock.patch("components.main.audit_export", return_value=(True, [])), \
        mock.patch("components.imap_ops._import_account_unlocked", side_effect=lambda acc, *_args, **_kwargs: imported.append(acc.email)):
        rc = main([
                "--mode", "import",
                "--config", str(config_path),
            "--input-dir", str(ordinary_root),
            "--log-dir", str(tmp_path / "logs"),
            "--min-free-gb", "0",
            "--max-workers", "2",
            "--no-connectivity-test",
            "--ignore-errors",
        ])

    assert rc == 4
    assert imported == [healthy.email]


@pytest.mark.parametrize("target_step", ["directadmin", "cpanel", "connectivity"])
def test_concurrent_reset_after_unlocked_snapshot_blocks_all_ordinary_target_steps(
    tmp_path: Path,
    target_step: str,
) -> None:
    from components import imap_ops
    from components import main as main_module

    server = ServerConfig(
        host="target.example.com",
        port=993,
        ssl=True,
        starttls=False,
    )
    account = Account(email="user@example.com", password="mail-secret")
    config = Config(server=server, accounts=[account], source_server=server)
    input_root = tmp_path / "staged"
    account_dir = input_root / account.email
    account_dir.mkdir(parents=True, mode=0o700)
    reset_root = tmp_path / "independent-reset-staged"
    reset_account_dir = reset_root / account.email
    reset_account_dir.mkdir(parents=True, mode=0o700)
    assert (
        imap_ops._legacy_import_lock_path(server, account, input_root)
        == imap_ops._legacy_import_lock_path(server, account, reset_root)
    )
    config_path = tmp_path / "config.json"
    config_path.write_text("{}\n", encoding="utf-8")

    panel_args: list[str] = []
    if target_step == "directadmin":
        panel_args = [
            "--auto-provision-da",
            "--da-url", "https://panel.example.com:2222",
            "--da-username", "admin",
            "--da-password", "panel-secret",
        ]
    elif target_step == "cpanel":
        panel_args = [
            "--auto-provision-cpanel",
            "--cpanel-url", "https://panel.example.com:2083",
            "--cpanel-username", "admin",
            "--cpanel-token", "panel-token",
        ]

    stale_snapshot_taken = threading.Event()
    reset_holding_target_lock = threading.Event()
    ordinary_attempting_target_lock = threading.Event()
    reset_finished = threading.Event()
    reset_errors: list[BaseException] = []
    real_unlocked_gate = main_module.legacy_reset_state_issues
    real_import_lock = imap_ops._legacy_import_lock

    @contextlib.contextmanager
    def observing_import_lock(*args, **kwargs):
        if threading.current_thread().name != "concurrent-reset":
            ordinary_attempting_target_lock.set()
        with real_import_lock(*args, **kwargs):
            yield

    def interrupt_reset_while_holding_lock() -> None:
        reset_holding_target_lock.set()
        if not ordinary_attempting_target_lock.wait(timeout=5):
            raise TimeoutError("ordinary import never attempted the held target lock")
        raise RuntimeError("simulated concurrent reset interruption")

    def concurrent_reset() -> None:
        if not stale_snapshot_taken.wait(timeout=5):
            reset_errors.append(TimeoutError("ordinary import never took its unlocked snapshot"))
            reset_finished.set()
            return
        try:
            imap_ops.import_account(
                account,
                server,
                reset_root,
                ignore_errors=False,
                reset_before_import=interrupt_reset_while_holding_lock,
            )
        except RuntimeError as exc:
            if "simulated concurrent reset interruption" not in str(exc):
                reset_errors.append(exc)
        except BaseException as exc:  # pragma: no cover - assertion aid
            reset_errors.append(exc)
        else:  # pragma: no cover - assertion aid
            reset_errors.append(AssertionError("concurrent reset unexpectedly completed"))
        finally:
            reset_finished.set()

    def stale_unlocked_gate(*args, **kwargs):
        issues = real_unlocked_gate(*args, **kwargs)
        assert issues == []
        stale_snapshot_taken.set()
        assert reset_holding_target_lock.wait(timeout=5), "concurrent reset did not hold its target lock"
        return issues

    reset_thread = threading.Thread(target=concurrent_reset, name="concurrent-reset")
    reset_thread.start()
    try:
        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.main.load_config_file", return_value=config), \
            mock.patch("components.main.audit_export", return_value=(True, [])), \
            mock.patch("components.utils.ensure_imapsync_available"), \
            mock.patch("components.main._ensure_directadmin_client_dependency"), \
            mock.patch("components.main._ensure_cpanel_client_dependency"), \
            mock.patch("components.main.DirectAdminClient", return_value=object()), \
            mock.patch("components.main.CPanelClient", return_value=object()), \
            mock.patch("components.main.legacy_reset_state_issues", side_effect=stale_unlocked_gate), \
            mock.patch("components.imap_ops._legacy_import_lock", side_effect=observing_import_lock), \
            mock.patch("components.main.ensure_accounts_exist_directadmin") as da_ensure, \
            mock.patch("components.main.ensure_accounts_exist_cpanel") as cpanel_ensure, \
            mock.patch("components.main.test_accounts") as connectivity, \
            mock.patch("components.imap_ops._import_account_unlocked") as unlocked_import:
            rc = main([
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(input_root),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
                *panel_args,
            ])
    finally:
        reset_thread.join(timeout=5)

    assert not reset_thread.is_alive()
    assert ordinary_attempting_target_lock.is_set()
    assert reset_finished.is_set()
    assert reset_errors == []
    assert rc == 4
    reset_state = json.loads(
        (reset_account_dir / imap_ops.LEGACY_RESET_STATE_FILENAME).read_text()
    )
    assert reset_state["owner_staging_root"] == str(reset_root)
    assert not (account_dir / imap_ops.LEGACY_RESET_STATE_FILENAME).exists()
    assert reset_state["phase"] == "reset_started"
    da_ensure.assert_not_called()
    cpanel_ensure.assert_not_called()
    connectivity.assert_not_called()
    unlocked_import.assert_not_called()


def test_validate_stale_snapshot_waits_for_cross_root_reset_and_makes_no_target_calls(
    tmp_path: Path,
) -> None:
    from components import imap_ops
    from components import main as main_module

    server = ServerConfig(
        host="target.example.com",
        port=993,
        ssl=True,
        starttls=False,
    )
    account = Account(email="user@example.com", password="mail-secret")
    config = Config(server=server, accounts=[account], source_server=server)
    validate_root = tmp_path / "validate-staged"
    reset_root = tmp_path / "reset-staged"
    (validate_root / account.email).mkdir(parents=True, mode=0o700)
    reset_account_dir = reset_root / account.email
    reset_account_dir.mkdir(parents=True, mode=0o700)
    config_path = tmp_path / "config.json"
    config_path.write_text("{}\n", encoding="utf-8")

    stale_snapshot_taken = threading.Event()
    reset_holding_target_lock = threading.Event()
    validate_attempting_target_lock = threading.Event()
    reset_errors: list[BaseException] = []
    real_unlocked_gate = main_module.legacy_reset_state_issues
    real_import_lock = imap_ops._legacy_import_lock

    @contextlib.contextmanager
    def observing_import_lock(*args, **kwargs):
        if threading.current_thread().name != "concurrent-reset":
            validate_attempting_target_lock.set()
        with real_import_lock(*args, **kwargs):
            yield

    def interrupt_reset_while_holding_lock() -> None:
        reset_holding_target_lock.set()
        if not validate_attempting_target_lock.wait(timeout=5):
            raise TimeoutError("validate never attempted the held target lock")
        raise RuntimeError("simulated concurrent reset interruption")

    def concurrent_reset() -> None:
        if not stale_snapshot_taken.wait(timeout=5):
            reset_errors.append(TimeoutError("validate never took its unlocked snapshot"))
            return
        try:
            imap_ops.import_account(
                account,
                server,
                reset_root,
                ignore_errors=False,
                reset_before_import=interrupt_reset_while_holding_lock,
            )
        except RuntimeError as exc:
            if "simulated concurrent reset interruption" not in str(exc):
                reset_errors.append(exc)
        except BaseException as exc:  # pragma: no cover - assertion aid
            reset_errors.append(exc)
        else:  # pragma: no cover - assertion aid
            reset_errors.append(AssertionError("concurrent reset unexpectedly completed"))

    def stale_unlocked_gate(*args, **kwargs):
        issues = real_unlocked_gate(*args, **kwargs)
        assert issues == []
        stale_snapshot_taken.set()
        assert reset_holding_target_lock.wait(timeout=5), "reset did not hold its target lock"
        return issues

    reset_thread = threading.Thread(target=concurrent_reset, name="concurrent-reset")
    reset_thread.start()
    try:
        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.main.load_config_file", return_value=config), \
            mock.patch("components.main.audit_export", return_value=(True, [])), \
            mock.patch("components.utils.ensure_imapsync_available"), \
            mock.patch("components.main.legacy_reset_state_issues", side_effect=stale_unlocked_gate), \
            mock.patch("components.imap_ops._legacy_import_lock", side_effect=observing_import_lock), \
            mock.patch("components.main.test_accounts") as connectivity, \
            mock.patch("components.imap_ops.imap_connection") as validation_imap, \
            mock.patch("components.imap_ops._import_account_unlocked") as unlocked_import:
            rc = main([
                "--mode", "validate",
                "--config", str(config_path),
                "--input-dir", str(validate_root),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
            ])
    finally:
        reset_thread.join(timeout=5)

    assert not reset_thread.is_alive()
    assert validate_attempting_target_lock.is_set()
    assert reset_errors == []
    assert rc == 4
    reset_state = json.loads(
        (reset_account_dir / imap_ops.LEGACY_RESET_STATE_FILENAME).read_text()
    )
    assert reset_state["phase"] == "reset_started"
    connectivity.assert_not_called()
    validation_imap.assert_not_called()
    unlocked_import.assert_not_called()


def test_remote_audit_stale_snapshot_keeps_contacted_endpoint_lock_with_unrelated_local_marker(
    tmp_path: Path,
) -> None:
    from components import imap_ops
    from components import main as main_module

    target_server = ServerConfig(
        host="target.example.com",
        port=993,
        ssl=True,
        starttls=False,
    )
    source_server = ServerConfig(
        host="source.example.com",
        port=993,
        ssl=True,
        starttls=False,
    )
    account = Account(email="user@example.com", password="mail-secret")
    config = Config(
        server=target_server,
        accounts=[account],
        source_server=source_server,
    )
    audit_root = tmp_path / "audit-staged"
    reset_root = tmp_path / "reset-staged"
    audit_account_dir = audit_root / account.email
    audit_account_dir.mkdir(parents=True, mode=0o700)
    reset_account_dir = reset_root / account.email
    reset_account_dir.mkdir(parents=True, mode=0o700)
    config_path = tmp_path / "config.json"
    config_path.write_text("{}\n", encoding="utf-8")

    with imap_ops._legacy_import_lock(
        target_server,
        account,
        audit_root,
        stop_event=None,
    ):
        imap_ops._begin_legacy_reset_state(
            audit_account_dir,
            account,
            target_server,
        )

    stale_snapshot_taken = threading.Event()
    reset_holding_target_lock = threading.Event()
    audit_attempting_target_lock = threading.Event()
    reset_errors: list[BaseException] = []
    real_unlocked_gate = main_module.legacy_reset_state_issues
    real_import_lock = imap_ops._legacy_import_lock

    @contextlib.contextmanager
    def observing_import_lock(*args, **kwargs):
        if threading.current_thread().name != "concurrent-reset":
            audit_attempting_target_lock.set()
        with real_import_lock(*args, **kwargs):
            yield

    def interrupt_reset_while_holding_lock() -> None:
        reset_holding_target_lock.set()
        if not audit_attempting_target_lock.wait(timeout=5):
            raise TimeoutError("audit never attempted the held target lock")
        raise RuntimeError("simulated concurrent reset interruption")

    def concurrent_reset() -> None:
        if not stale_snapshot_taken.wait(timeout=5):
            reset_errors.append(TimeoutError("audit never took its unlocked snapshot"))
            return
        try:
            imap_ops.import_account(
                account,
                source_server,
                reset_root,
                ignore_errors=False,
                reset_before_import=interrupt_reset_while_holding_lock,
            )
        except RuntimeError as exc:
            if "simulated concurrent reset interruption" not in str(exc):
                reset_errors.append(exc)
        except BaseException as exc:  # pragma: no cover - assertion aid
            reset_errors.append(exc)
        else:  # pragma: no cover - assertion aid
            reset_errors.append(AssertionError("concurrent reset unexpectedly completed"))

    def stale_unlocked_gate(*args, **kwargs):
        issues = real_unlocked_gate(*args, **kwargs)
        assert issues == []
        stale_snapshot_taken.set()
        assert reset_holding_target_lock.wait(timeout=5), "reset did not hold its target lock"
        return issues

    reset_thread = threading.Thread(target=concurrent_reset, name="concurrent-reset")
    reset_thread.start()
    try:
        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.main.load_config_file", return_value=config), \
            mock.patch("components.main.legacy_reset_state_issues", side_effect=stale_unlocked_gate), \
            mock.patch("components.imap_ops._legacy_import_lock", side_effect=observing_import_lock), \
            mock.patch("components.main.audit_export") as remote_audit, \
            mock.patch("components.imap_ops._import_account_unlocked") as unlocked_import:
            rc = main([
                "--mode", "audit",
                "--config", str(config_path),
                "--input-dir", str(audit_root),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--max-workers", "1",
            ])
    finally:
        reset_thread.join(timeout=5)

    assert not reset_thread.is_alive()
    assert audit_attempting_target_lock.is_set()
    assert reset_errors == []
    assert rc == 4
    assert json.loads(
        (reset_account_dir / imap_ops.LEGACY_RESET_STATE_FILENAME).read_text()
    )["phase"] == "reset_started"
    assert json.loads(
        (audit_account_dir / imap_ops.LEGACY_RESET_STATE_FILENAME).read_text()
    )["target_server"]["host"] == target_server.host
    remote_audit.assert_not_called()
    unlocked_import.assert_not_called()


def test_offline_audit_does_not_consult_target_reset_gate(tmp_path: Path) -> None:
    from components import imap_ops

    server = ServerConfig(
        host="target.example.com",
        port=993,
        ssl=True,
        starttls=False,
    )
    account = Account(email="user@example.com", password="mail-secret")
    config = Config(server=server, accounts=[account], source_server=server)
    audit_root = tmp_path / "audit-staged"
    reset_root = tmp_path / "reset-staged"
    (audit_root / account.email).mkdir(parents=True, mode=0o700)
    reset_account_dir = reset_root / account.email
    reset_account_dir.mkdir(parents=True, mode=0o700)
    config_path = tmp_path / "config.json"
    config_path.write_text("{}\n", encoding="utf-8")

    with imap_ops._legacy_import_lock(server, account, reset_root, stop_event=None):
        imap_ops._begin_legacy_reset_state(reset_account_dir, account, server)

    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.check_free_space_for_path"), \
        mock.patch("components.main.load_config_file", return_value=config), \
        mock.patch(
            "components.main.legacy_reset_state_issues",
            side_effect=AssertionError("offline audit must not consult the target gate"),
        ), \
        mock.patch("components.main.audit_export", return_value=(True, [])) as local_audit:
        rc = main([
            "--mode", "audit",
            "--config", str(config_path),
            "--input-dir", str(audit_root),
            "--log-dir", str(tmp_path / "logs"),
            "--min-free-gb", "0",
            "--audit-offline",
        ])

    assert rc == 0
    local_audit.assert_called_once()
    assert local_audit.call_args.kwargs["check_remote"] is False


def test_remote_audit_ignores_secure_same_root_local_marker_for_other_target(
    tmp_path: Path,
) -> None:
    from components import imap_ops
    from components import main as main_module

    target_server = ServerConfig(
        host="target.example.com",
        port=993,
        ssl=True,
        starttls=False,
    )
    source_server = ServerConfig(
        host="source.example.com",
        port=993,
        ssl=True,
        starttls=False,
    )
    account = Account(email="user@example.com", password="mail-secret")
    config = Config(
        server=target_server,
        accounts=[account],
        source_server=source_server,
    )
    audit_root = tmp_path / "audit-staged"
    audit_account_dir = audit_root / account.email
    audit_account_dir.mkdir(parents=True, mode=0o700)
    config_path = tmp_path / "config.json"
    config_path.write_text("{}\n", encoding="utf-8")

    with imap_ops._legacy_import_lock(
        target_server,
        account,
        audit_root,
        stop_event=None,
    ):
        imap_ops._begin_legacy_reset_state(
            audit_account_dir,
            account,
            target_server,
        )

    real_gate = main_module.legacy_reset_state_issues
    gate_servers: list[ServerConfig] = []

    def observe_gate(root, accounts, server, **kwargs):
        gate_servers.append(server)
        return real_gate(root, accounts, server, **kwargs)

    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.check_free_space_for_path"), \
        mock.patch("components.main.load_config_file", return_value=config), \
        mock.patch("components.main.legacy_reset_state_issues", side_effect=observe_gate), \
        mock.patch("components.main.audit_export", return_value=(True, [])) as remote_audit:
        rc = main([
            "--mode", "audit",
            "--config", str(config_path),
            "--input-dir", str(audit_root),
            "--log-dir", str(tmp_path / "logs"),
            "--min-free-gb", "0",
            "--max-workers", "1",
        ])

    assert rc == 0
    assert gate_servers == [source_server]
    remote_audit.assert_called_once()
    assert remote_audit.call_args.kwargs["check_remote"] is True
    assert (audit_account_dir / imap_ops.LEGACY_RESET_STATE_FILENAME).exists()
    assert imap_ops._legacy_global_reset_state_path(target_server, account).exists()


def test_remote_audit_honors_contacted_source_global_gate_with_unrelated_local_marker(
    tmp_path: Path,
) -> None:
    from components import imap_ops

    target_server = ServerConfig(
        host="target.example.com",
        port=993,
        ssl=True,
        starttls=False,
    )
    source_server = ServerConfig(
        host="source.example.com",
        port=993,
        ssl=True,
        starttls=False,
    )
    account = Account(email="user@example.com", password="mail-secret")
    config = Config(
        server=target_server,
        accounts=[account],
        source_server=source_server,
    )
    audit_root = tmp_path / "audit-staged"
    source_reset_root = tmp_path / "source-reset-staged"
    audit_account_dir = audit_root / account.email
    source_reset_account_dir = source_reset_root / account.email
    audit_account_dir.mkdir(parents=True, mode=0o700)
    source_reset_account_dir.mkdir(parents=True, mode=0o700)
    config_path = tmp_path / "config.json"
    config_path.write_text("{}\n", encoding="utf-8")

    with imap_ops._legacy_import_lock(
        target_server,
        account,
        audit_root,
        stop_event=None,
    ):
        imap_ops._begin_legacy_reset_state(
            audit_account_dir,
            account,
            target_server,
        )
    with imap_ops._legacy_import_lock(
        source_server,
        account,
        source_reset_root,
        stop_event=None,
    ):
        imap_ops._begin_legacy_reset_state(
            source_reset_account_dir,
            account,
            source_server,
        )

    assert imap_ops.legacy_reset_state_issues(
        audit_root,
        [account],
        source_server,
        allow_unrelated_local_target=True,
    )

    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.check_free_space_for_path"), \
        mock.patch("components.main.load_config_file", return_value=config), \
        mock.patch("components.main.legacy_reset_state_issues", return_value=[]), \
        mock.patch("components.main.audit_export") as remote_audit:
        rc = main([
            "--mode", "audit",
            "--config", str(config_path),
            "--input-dir", str(audit_root),
            "--log-dir", str(tmp_path / "logs"),
            "--min-free-gb", "0",
            "--max-workers", "1",
        ])

    assert rc == 4
    remote_audit.assert_not_called()


@pytest.mark.parametrize("artifact_kind", ["malformed", "symlink", "hardlink"])
def test_remote_audit_rejects_untrusted_local_marker_for_other_endpoint(
    tmp_path: Path,
    artifact_kind: str,
) -> None:
    from components import imap_ops

    target_server = ServerConfig(
        host="target.example.com",
        port=993,
        ssl=True,
        starttls=False,
    )
    source_server = ServerConfig(
        host="source.example.com",
        port=993,
        ssl=True,
        starttls=False,
    )
    account = Account(email="user@example.com", password="mail-secret")
    config = Config(
        server=target_server,
        accounts=[account],
        source_server=source_server,
    )
    audit_root = tmp_path / "audit-staged"
    audit_account_dir = audit_root / account.email
    audit_account_dir.mkdir(parents=True, mode=0o700)
    marker_path = audit_account_dir / imap_ops.LEGACY_RESET_STATE_FILENAME
    if artifact_kind == "malformed":
        marker_path.write_bytes(b"{malformed\n")
        marker_path.chmod(0o600)
    else:
        victim = tmp_path / f"{artifact_kind}-marker-victim.json"
        victim.write_bytes(b"{}\n")
        victim.chmod(0o600)
        try:
            if artifact_kind == "symlink":
                marker_path.symlink_to(victim)
            else:
                marker_path.hardlink_to(victim)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"{artifact_kind} creation unavailable: {exc}")
    config_path = tmp_path / "config.json"
    config_path.write_text("{}\n", encoding="utf-8")

    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.check_free_space_for_path"), \
        mock.patch("components.main.load_config_file", return_value=config), \
        mock.patch("components.main.legacy_reset_state_issues", return_value=[]), \
        mock.patch("components.main.audit_export") as remote_audit:
        rc = main([
            "--mode", "audit",
            "--config", str(config_path),
            "--input-dir", str(audit_root),
            "--log-dir", str(tmp_path / "logs"),
            "--min-free-gb", "0",
            "--max-workers", "1",
        ])

    assert rc == 4
    remote_audit.assert_not_called()


def test_legacy_test_mode_global_gate_needs_no_staging_root(tmp_path: Path) -> None:
    from components import imap_ops

    server = ServerConfig(
        host="target.example.com",
        port=993,
        ssl=True,
        starttls=False,
    )
    account = Account(email="user@example.com", password="mail-secret")
    config = Config(server=server, accounts=[account], source_server=server)
    reset_root = tmp_path / "reset-staged"
    reset_account_dir = reset_root / account.email
    reset_account_dir.mkdir(parents=True, mode=0o700)
    input_root = tmp_path / "does-not-exist"
    config_path = tmp_path / "config.json"
    config_path.write_text("{}\n", encoding="utf-8")
    with imap_ops._legacy_import_lock(server, account, reset_root, stop_event=None):
        imap_ops._begin_legacy_reset_state(reset_account_dir, account, server)

    with mock.patch("components.main.check_environment"), \
        mock.patch("components.utils.ensure_imapsync_available"), \
        mock.patch("components.main.load_config_file", return_value=config), \
        mock.patch("components.main.test_accounts") as connectivity:
        rc = main([
            "--mode", "test",
            "--config", str(config_path),
            "--input-dir", str(input_root),
            "--log-dir", str(tmp_path / "logs"),
            "--max-workers", "1",
        ])

    assert rc == 4
    assert not input_root.exists()
    connectivity.assert_not_called()


def test_legacy_test_mode_stale_snapshot_waits_for_concurrent_reset(
    tmp_path: Path,
) -> None:
    from components import imap_ops
    from components import main as main_module

    server = ServerConfig(
        host="target.example.com",
        port=993,
        ssl=True,
        starttls=False,
    )
    account = Account(email="user@example.com", password="mail-secret")
    config = Config(server=server, accounts=[account], source_server=server)
    reset_root = tmp_path / "reset-staged"
    reset_account_dir = reset_root / account.email
    reset_account_dir.mkdir(parents=True, mode=0o700)
    input_root = tmp_path / "does-not-exist"
    config_path = tmp_path / "config.json"
    config_path.write_text("{}\n", encoding="utf-8")
    stale_snapshot_taken = threading.Event()
    reset_holding_lock = threading.Event()
    test_attempting_lock = threading.Event()
    reset_errors: list[BaseException] = []
    real_snapshot = main_module.legacy_global_reset_state_issues
    real_target_lock = imap_ops._legacy_global_target_lock

    @contextlib.contextmanager
    def observing_target_lock(*args, **kwargs):
        if threading.current_thread().name != "concurrent-reset":
            test_attempting_lock.set()
        with real_target_lock(*args, **kwargs):
            yield

    def interrupt_reset() -> None:
        reset_holding_lock.set()
        if not test_attempting_lock.wait(timeout=5):
            raise TimeoutError("test mode never attempted the held target lock")
        raise RuntimeError("simulated concurrent reset interruption")

    def concurrent_reset() -> None:
        if not stale_snapshot_taken.wait(timeout=5):
            reset_errors.append(TimeoutError("test mode never took its snapshot"))
            return
        try:
            imap_ops.import_account(
                account,
                server,
                reset_root,
                ignore_errors=False,
                reset_before_import=interrupt_reset,
            )
        except RuntimeError as exc:
            if "simulated concurrent reset interruption" not in str(exc):
                reset_errors.append(exc)
        except BaseException as exc:  # pragma: no cover - assertion aid
            reset_errors.append(exc)
        else:  # pragma: no cover - assertion aid
            reset_errors.append(AssertionError("concurrent reset unexpectedly completed"))

    def stale_snapshot(*args, **kwargs):
        issues = real_snapshot(*args, **kwargs)
        assert issues == []
        stale_snapshot_taken.set()
        assert reset_holding_lock.wait(timeout=5), "reset did not hold its target lock"
        return issues

    reset_thread = threading.Thread(target=concurrent_reset, name="concurrent-reset")
    reset_thread.start()
    try:
        with mock.patch("components.main.check_environment"), \
            mock.patch("components.utils.ensure_imapsync_available"), \
            mock.patch("components.main.load_config_file", return_value=config), \
            mock.patch(
                "components.main.legacy_global_reset_state_issues",
                side_effect=stale_snapshot,
            ), \
            mock.patch(
                "components.imap_ops._legacy_global_target_lock",
                side_effect=observing_target_lock,
            ), \
            mock.patch("components.main.test_accounts") as connectivity:
            rc = main([
                "--mode", "test",
                "--config", str(config_path),
                "--input-dir", str(input_root),
                "--log-dir", str(tmp_path / "logs"),
                "--max-workers", "1",
            ])
    finally:
        reset_thread.join(timeout=5)

    assert not reset_thread.is_alive()
    assert test_attempting_lock.is_set()
    assert reset_errors == []
    assert rc == 4
    assert not input_root.exists()
    connectivity.assert_not_called()


def test_legacy_test_mode_preserves_max_workers_without_staging_root(
    tmp_path: Path,
) -> None:
    first = Account(email="first@example.com", password="first-secret")
    second = Account(email="second@example.com", password="second-secret")
    server = ServerConfig(
        host="target.example.com",
        port=993,
        ssl=True,
        starttls=False,
    )
    config = Config(server=server, accounts=[first, second], source_server=server)
    config_path = tmp_path / "config.json"
    config_path.write_text("{}\n", encoding="utf-8")
    input_root = tmp_path / "does-not-exist"
    both_connecting = threading.Barrier(2, timeout=5)
    connected: list[str] = []
    connected_lock = threading.Lock()

    def concurrent_connectivity(single_config: Config, **_kwargs) -> None:
        with connected_lock:
            connected.append(single_config.accounts[0].email)
        both_connecting.wait()

    with mock.patch("components.main.check_environment"), \
        mock.patch("components.utils.ensure_imapsync_available"), \
        mock.patch("components.main.load_config_file", return_value=config), \
        mock.patch("components.main.test_accounts", side_effect=concurrent_connectivity):
        rc = main([
            "--mode", "test",
            "--config", str(config_path),
            "--input-dir", str(input_root),
            "--log-dir", str(tmp_path / "logs"),
            "--max-workers", "2",
        ])

    assert rc == 0
    assert not input_root.exists()
    assert sorted(connected) == sorted([first.email, second.email])


def test_legacy_export_global_gate_blocks_without_connectivity_or_local_marker(
    tmp_path: Path,
) -> None:
    from components import imap_ops

    server = ServerConfig(
        host="target.example.com",
        port=993,
        ssl=True,
        starttls=False,
    )
    account = Account(email="user@example.com", password="mail-secret")
    config = Config(server=server, accounts=[account], source_server=server)
    reset_root = tmp_path / "reset-staged"
    reset_account_dir = reset_root / account.email
    reset_account_dir.mkdir(parents=True, mode=0o700)
    output_root = tmp_path / "new-export"
    config_path = tmp_path / "config.json"
    config_path.write_text("{}\n", encoding="utf-8")
    (tmp_path / "import.pass.config.json").write_text("{}\n", encoding="utf-8")
    with imap_ops._legacy_import_lock(server, account, reset_root, stop_event=None):
        imap_ops._begin_legacy_reset_state(reset_account_dir, account, server)

    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.check_free_space_for_path"), \
        mock.patch("components.utils.ensure_imapsync_available"), \
        mock.patch("components.main.load_config_file", return_value=config), \
        mock.patch("components.main.test_accounts") as connectivity, \
        mock.patch("components.main.export_account") as exporter:
        rc = main([
            "--mode", "export",
            "--config", str(config_path),
            "--output-dir", str(output_root),
            "--log-dir", str(tmp_path / "logs"),
            "--min-free-gb", "0",
            "--no-connectivity-test",
            "--no-audit-after-export",
        ])

    assert rc == 4
    assert not output_root.exists()
    connectivity.assert_not_called()
    exporter.assert_not_called()


def test_legacy_export_stale_snapshot_waits_for_concurrent_reset(
    tmp_path: Path,
) -> None:
    from components import imap_ops
    from components import main as main_module

    server = ServerConfig(
        host="target.example.com",
        port=993,
        ssl=True,
        starttls=False,
    )
    account = Account(email="user@example.com", password="mail-secret")
    config = Config(server=server, accounts=[account], source_server=server)
    reset_root = tmp_path / "reset-staged"
    reset_account_dir = reset_root / account.email
    reset_account_dir.mkdir(parents=True, mode=0o700)
    output_root = tmp_path / "new-export"
    config_path = tmp_path / "config.json"
    config_path.write_text("{}\n", encoding="utf-8")
    (tmp_path / "import.pass.config.json").write_text("{}\n", encoding="utf-8")
    stale_snapshot_taken = threading.Event()
    reset_holding_lock = threading.Event()
    export_attempting_lock = threading.Event()
    reset_errors: list[BaseException] = []
    real_snapshot = main_module.legacy_global_reset_state_issues
    real_target_lock = imap_ops._legacy_global_target_lock

    @contextlib.contextmanager
    def observing_target_lock(*args, **kwargs):
        if threading.current_thread().name != "concurrent-reset":
            export_attempting_lock.set()
        with real_target_lock(*args, **kwargs):
            yield

    def interrupt_reset() -> None:
        reset_holding_lock.set()
        if not export_attempting_lock.wait(timeout=5):
            raise TimeoutError("export never attempted the held target lock")
        raise RuntimeError("simulated concurrent reset interruption")

    def concurrent_reset() -> None:
        if not stale_snapshot_taken.wait(timeout=5):
            reset_errors.append(TimeoutError("export never took its snapshot"))
            return
        try:
            imap_ops.import_account(
                account,
                server,
                reset_root,
                ignore_errors=False,
                reset_before_import=interrupt_reset,
            )
        except RuntimeError as exc:
            if "simulated concurrent reset interruption" not in str(exc):
                reset_errors.append(exc)
        except BaseException as exc:  # pragma: no cover - assertion aid
            reset_errors.append(exc)
        else:  # pragma: no cover - assertion aid
            reset_errors.append(AssertionError("concurrent reset unexpectedly completed"))

    def stale_snapshot(*args, **kwargs):
        issues = real_snapshot(*args, **kwargs)
        assert issues == []
        stale_snapshot_taken.set()
        assert reset_holding_lock.wait(timeout=5), "reset did not hold its target lock"
        return issues

    reset_thread = threading.Thread(target=concurrent_reset, name="concurrent-reset")
    reset_thread.start()
    try:
        with mock.patch("components.main.check_environment"), \
            mock.patch("components.main.check_free_space_for_path"), \
            mock.patch("components.main.load_config_file", return_value=config), \
            mock.patch(
                "components.main.legacy_global_reset_state_issues",
                side_effect=stale_snapshot,
            ), \
            mock.patch(
                "components.imap_ops._legacy_global_target_lock",
                side_effect=observing_target_lock,
            ), \
            mock.patch("components.main.test_accounts") as connectivity, \
            mock.patch("components.main.export_account") as exporter:
            rc = main([
                "--mode", "export",
                "--config", str(config_path),
                "--output-dir", str(output_root),
                "--log-dir", str(tmp_path / "logs"),
                "--min-free-gb", "0",
                "--no-connectivity-test",
                "--no-audit-after-export",
            ])
    finally:
        reset_thread.join(timeout=5)

    assert not reset_thread.is_alive()
    assert export_attempting_lock.is_set()
    assert reset_errors == []
    assert rc == 4
    assert not output_root.exists()
    connectivity.assert_not_called()
    exporter.assert_not_called()


def test_legacy_export_connectivity_and_export_preserve_account_parallelism(
    tmp_path: Path,
) -> None:
    first = Account(email="first@example.com", password="first-secret")
    second = Account(email="second@example.com", password="second-secret")
    server = ServerConfig(
        host="target.example.com",
        port=993,
        ssl=True,
        starttls=False,
    )
    config = Config(server=server, accounts=[first, second], source_server=server)
    config_path = tmp_path / "config.json"
    config_path.write_text("{}\n", encoding="utf-8")
    (tmp_path / "import.pass.config.json").write_text("{}\n", encoding="utf-8")
    output_root = tmp_path / "new-export"
    both_connecting = threading.Barrier(2, timeout=5)
    connected: list[str] = []
    exported: list[str] = []
    result_lock = threading.Lock()

    def concurrent_connectivity(single_config: Config, **_kwargs) -> None:
        with result_lock:
            connected.append(single_config.accounts[0].email)
        both_connecting.wait()

    def record_export(account: Account, *_args, **_kwargs) -> None:
        with result_lock:
            exported.append(account.email)

    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.check_free_space_for_path"), \
        mock.patch("components.utils.ensure_imapsync_available"), \
        mock.patch("components.main.load_config_file", return_value=config), \
        mock.patch("components.main.test_accounts", side_effect=concurrent_connectivity), \
        mock.patch("components.main.export_account", side_effect=record_export):
        rc = main([
            "--mode", "export",
            "--config", str(config_path),
            "--output-dir", str(output_root),
            "--log-dir", str(tmp_path / "logs"),
            "--min-free-gb", "0",
            "--max-workers", "2",
            "--no-audit-after-export",
        ])

    assert rc == 0
    assert sorted(connected) == sorted([first.email, second.email])
    assert sorted(exported) == sorted([first.email, second.email])


@pytest.mark.parametrize("mode", ["export", "test"])
def test_legacy_global_only_modes_ignore_errors_continue_independent_account(
    tmp_path: Path,
    mode: str,
) -> None:
    from components import imap_ops

    blocked = Account(email="blocked@example.com", password="blocked-secret")
    healthy = Account(email="healthy@example.com", password="healthy-secret")
    server = ServerConfig(
        host="target.example.com",
        port=993,
        ssl=True,
        starttls=False,
    )
    config = Config(
        server=server,
        accounts=[blocked, healthy],
        source_server=server,
    )
    reset_root = tmp_path / "reset-staged"
    reset_account_dir = reset_root / blocked.email
    reset_account_dir.mkdir(parents=True, mode=0o700)
    config_path = tmp_path / "config.json"
    config_path.write_text("{}\n", encoding="utf-8")
    (tmp_path / "import.pass.config.json").write_text("{}\n", encoding="utf-8")
    with imap_ops._legacy_import_lock(server, blocked, reset_root, stop_event=None):
        imap_ops._begin_legacy_reset_state(reset_account_dir, blocked, server)

    contacted: list[str] = []

    def record_connectivity(single_config: Config, **_kwargs) -> None:
        contacted.append(single_config.accounts[0].email)

    def record_export(account: Account, *_args, **_kwargs) -> None:
        contacted.append(account.email)

    args = [
        "--mode", mode,
        "--config", str(config_path),
        "--log-dir", str(tmp_path / "logs"),
        "--max-workers", "2",
        "--ignore-errors",
    ]
    if mode == "export":
        args.extend([
            "--output-dir", str(tmp_path / "new-export"),
            "--min-free-gb", "0",
            "--no-connectivity-test",
            "--no-audit-after-export",
        ])
    else:
        args.extend(["--input-dir", str(tmp_path / "does-not-exist")])

    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.check_free_space_for_path"), \
        mock.patch("components.utils.ensure_imapsync_available"), \
        mock.patch("components.main.load_config_file", return_value=config), \
        mock.patch("components.main.test_accounts", side_effect=record_connectivity), \
        mock.patch("components.main.export_account", side_effect=record_export):
        rc = main(args)

    assert rc == 4
    assert contacted == [healthy.email]


@pytest.mark.parametrize("mode", ["export", "test"])
def test_legacy_global_only_mode_connectivity_failure_returns_rc3(
    tmp_path: Path,
    mode: str,
) -> None:
    server = ServerConfig(
        host="target.example.com",
        port=993,
        ssl=True,
        starttls=False,
    )
    account = Account(email="user@example.com", password="mail-secret")
    config = Config(server=server, accounts=[account], source_server=server)
    config_path = tmp_path / "config.json"
    config_path.write_text("{}\n", encoding="utf-8")
    (tmp_path / "import.pass.config.json").write_text("{}\n", encoding="utf-8")
    args = [
        "--mode", mode,
        "--config", str(config_path),
        "--log-dir", str(tmp_path / "logs"),
        "--max-workers", "1",
    ]
    if mode == "export":
        args.extend([
            "--output-dir", str(tmp_path / "new-export"),
            "--min-free-gb", "0",
            "--no-audit-after-export",
        ])
    else:
        args.extend(["--input-dir", str(tmp_path / "does-not-exist")])

    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.check_free_space_for_path"), \
        mock.patch("components.utils.ensure_imapsync_available"), \
        mock.patch("components.main.load_config_file", return_value=config), \
        mock.patch(
            "components.main.test_accounts",
            side_effect=RuntimeError("simulated connectivity failure"),
        ), \
        mock.patch("components.main.export_account") as exporter:
        rc = main(args)

    assert rc == 3
    exporter.assert_not_called()


def test_validate_preserves_max_workers_for_independent_target_accounts(
    tmp_path: Path,
) -> None:
    first = Account(email="first@example.com", password="first-secret")
    second = Account(email="second@example.com", password="second-secret")
    server = ServerConfig(
        host="target.example.com",
        port=993,
        ssl=True,
        starttls=False,
    )
    config = Config(server=server, accounts=[first, second], source_server=server)
    input_root = tmp_path / "staged"
    for account in config.accounts:
        (input_root / account.email).mkdir(parents=True, mode=0o700)
    config_path = tmp_path / "config.json"
    config_path.write_text("{}\n", encoding="utf-8")
    both_connecting = threading.Barrier(2, timeout=5)
    connected: list[str] = []
    connected_lock = threading.Lock()

    def concurrent_connectivity(single_config: Config, **_kwargs) -> None:
        with connected_lock:
            connected.append(single_config.accounts[0].email)
        both_connecting.wait()

    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.check_free_space_for_path"), \
        mock.patch("components.main.load_config_file", return_value=config), \
        mock.patch("components.main.audit_export", return_value=(True, [])), \
        mock.patch("components.utils.ensure_imapsync_available"), \
        mock.patch("components.main.test_accounts", side_effect=concurrent_connectivity):
        rc = main([
            "--mode", "validate",
            "--config", str(config_path),
            "--input-dir", str(input_root),
            "--log-dir", str(tmp_path / "logs"),
            "--min-free-gb", "0",
            "--max-workers", "2",
        ])

    # Empty fixture directories make local validation fail after connectivity;
    # the barrier proves both independent target locks were active together.
    assert rc == 4
    assert sorted(connected) == sorted([first.email, second.email])


@pytest.mark.parametrize("panel", ["directadmin", "cpanel"])
def test_reset_dry_run_preserves_interrupted_reset_gate(
    tmp_path: Path,
    panel: str,
) -> None:
    from components import imap_ops

    server = ServerConfig(
        host="target.example.com",
        port=993,
        ssl=True,
        starttls=False,
    )
    account = Account(email="user@example.com", password="mail-secret")
    config = Config(server=server, accounts=[account], source_server=server)
    input_root = tmp_path / "staged"
    account_dir = input_root / account.email
    account_dir.mkdir(parents=True, mode=0o700)
    imap_ops._begin_legacy_reset_state(account_dir, account, server)
    state_path = account_dir / imap_ops.LEGACY_RESET_STATE_FILENAME
    original_state = state_path.read_bytes()

    if panel == "directadmin":
        panel_args = [
            "--auto-provision-da",
            "--da-dry-run",
            "--da-url", "https://panel.example.com:2222",
            "--da-username", "admin",
            "--da-password", "panel-secret",
        ]
    else:
        panel_args = [
            "--auto-provision-cpanel",
            "--cpanel-dry-run",
            "--cpanel-url", "https://panel.example.com:2083",
            "--cpanel-username", "admin",
            "--cpanel-token", "panel-token",
        ]

    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.check_free_space_for_path"), \
        mock.patch("components.main.load_config_file", return_value=config), \
        mock.patch("components.main.audit_export", return_value=(True, [])), \
        mock.patch("components.main._ensure_directadmin_client_dependency"), \
        mock.patch("components.main._ensure_cpanel_client_dependency"), \
        mock.patch("components.main.DirectAdminClient"), \
        mock.patch("components.main.CPanelClient"), \
        mock.patch("components.da_ensure.reset_accounts_directadmin", return_value=set()) as da_reset, \
        mock.patch("components.cpanel_ensure.reset_accounts_cpanel", return_value=set()) as cpanel_reset, \
        mock.patch("components.main.test_accounts") as connectivity_mock, \
        mock.patch("components.main.import_account") as import_mock:
        rc = main([
            *_base_args(tmp_path, "import"),
            "--reset",
            "--reset-confirm", server.host,
            *panel_args,
        ])

    assert rc == 0
    expected_reset = da_reset if panel == "directadmin" else cpanel_reset
    other_reset = cpanel_reset if panel == "directadmin" else da_reset
    expected_reset.assert_called_once()
    assert expected_reset.call_args.kwargs["dry_run"] is True
    other_reset.assert_not_called()
    connectivity_mock.assert_not_called()
    import_mock.assert_not_called()
    assert state_path.read_bytes() == original_state


def _run_two_account_locked_reset_policy(
    tmp_path: Path,
    *,
    ignore_errors: bool,
) -> tuple[int, list[str]]:
    from components import imap_ops

    server = ServerConfig(
        host="target.example.com",
        port=993,
        ssl=True,
        starttls=False,
    )
    failed_account = Account(email="first@example.com", password="first-secret")
    healthy_account = Account(email="second@example.com", password="second-secret")
    config = Config(
        server=server,
        accounts=[failed_account, healthy_account],
        source_server=server,
    )
    config_path = tmp_path / "legacy-reset-policy.json"
    config_path.write_text("{}\n", encoding="utf-8")
    input_root = tmp_path / "legacy-reset-policy-staged"
    for account in config.accounts:
        (input_root / account.email).mkdir(parents=True, mode=0o700)

    events: list[str] = []
    client = object()

    def reset_one(single_config: Config, actual_client, **kwargs):
        assert actual_client is client
        assert len(single_config.accounts) == 1
        account = single_config.accounts[0]
        assert kwargs["dry_run"] is False
        assert kwargs["ignore_errors"] is ignore_errors
        events.append(f"reset:{account.email}")
        if account.email == failed_account.email:
            if ignore_errors:
                return {account.email}
            raise RuntimeError("sensitive-panel-response")
        return set()

    def unlocked_import(account: Account, *_args, **_kwargs) -> None:
        events.append(f"import:{account.email}")

    args = [
        "--mode", "import",
        "--config", str(config_path),
        "--input-dir", str(input_root),
        "--log-dir", str(tmp_path / "legacy-reset-policy-logs"),
        "--min-free-gb", "0",
        "--max-workers", "1",
        "--no-connectivity-test",
        "--auto-provision-cpanel",
        "--reset",
        "--reset-confirm", server.host,
        "--cpanel-url", "https://panel.example.com:2083",
        "--cpanel-username", "admin",
        "--cpanel-token", "panel-token",
    ]
    if ignore_errors:
        args.append("--ignore-errors")

    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.check_free_space_for_path"), \
        mock.patch("components.main.load_config_file", return_value=config), \
        mock.patch("components.main.audit_export", return_value=(True, [])), \
        mock.patch("components.utils.ensure_imapsync_available"), \
        mock.patch("components.main._ensure_cpanel_client_dependency"), \
        mock.patch("components.main.CPanelClient", return_value=client), \
        mock.patch("components.main.test_accounts", side_effect=AssertionError("pre-reset connectivity must not run")), \
        mock.patch("components.cpanel_ensure.reset_accounts_cpanel", side_effect=reset_one), \
        mock.patch("components.imap_ops._import_account_unlocked", side_effect=unlocked_import):
        rc = main(args)

    # A reset exception must never strand the per-target lock.
    with imap_ops._legacy_import_lock(
        server,
        failed_account,
        input_root,
        stop_event=None,
    ):
        pass
    return rc, events


def test_locked_panel_reset_failure_is_fail_fast_without_ignore_errors(
    tmp_path: Path,
    capsys,
) -> None:
    rc, events = _run_two_account_locked_reset_policy(
        tmp_path,
        ignore_errors=False,
    )

    assert rc == 3
    assert events == ["reset:first@example.com"]
    assert "sensitive-panel-response" not in capsys.readouterr().err


def test_locked_panel_reset_failure_aggregates_and_continues_with_ignore_errors(
    tmp_path: Path,
) -> None:
    rc, events = _run_two_account_locked_reset_policy(
        tmp_path,
        ignore_errors=True,
    )

    assert rc == 3
    assert events == [
        "reset:first@example.com",
        "reset:second@example.com",
        "import:second@example.com",
    ]


def test_migrate_dry_run_delegates_once_and_keeps_stdout_clean(
    tmp_path: Path,
    capsys,
) -> None:
    config = _provider_config(routing=True)
    expected = {
        "version": 1,
        "ok": True,
        "dry_run": True,
        "status": "planned",
        "issues": [],
        "stage_order": ["discover_plan", "persist_plan", "final_report"],
        "artifacts": {
            "routing_plan": str(tmp_path / "staged" / "routing-plan.json"),
            "gmail_configuration_plan": str(
                tmp_path / "staged" / "gmail-configuration-plan.json"
            ),
            "report": str(
                tmp_path / "staged" / "reports" / "custom-report.json"
            ),
        },
    }
    report_path = tmp_path / "staged" / "reports" / "custom-report.json"
    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.check_free_space_for_path"), \
        mock.patch("components.main.load_config_file", return_value=config), \
        mock.patch(
            "components.main.provider_test_accounts",
            side_effect=AssertionError("migrate must use workflow preflight, not separate connectivity"),
        ), \
        mock.patch(
            "components.main.run_provider_migration_workflow",
            return_value=expected,
        ) as workflow:
        rc = main(
            _base_args(tmp_path, "migrate")
            + ["--dry-run", "--report-file", str(report_path)]
        )

    assert rc == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "top-secret" not in captured.out
    assert "status=planned" in captured.err
    assert str(tmp_path / "staged" / "routing-plan.json") in captured.err
    assert str(tmp_path / "staged" / "gmail-configuration-plan.json") in captured.err
    assert str(report_path) in captured.err
    workflow.assert_called_once()
    assert workflow.call_args.args[:2] == (config, tmp_path / "staged")
    assert workflow.call_args.kwargs["dry_run"] is True
    assert workflow.call_args.kwargs["report_path"] == report_path


def test_migrate_failure_report_returns_validation_exit_code(
    tmp_path: Path,
    capsys,
) -> None:
    config = _provider_config(routing=False)
    expected = {
        "version": 1,
        "ok": False,
        "status": "failed",
        "issues": ["filter conflict"],
    }
    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.check_free_space_for_path"), \
        mock.patch("components.main.load_config_file", return_value=config), \
        mock.patch("components.main.run_provider_migration_workflow", return_value=expected):
        rc = main(_base_args(tmp_path, "migrate"))

    assert rc == 4
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "status=failed" in captured.err
    assert "Provider migrate issue | filter conflict" in captured.err


def test_routing_preflight_uses_read_only_workflow_and_persists_to_output_root(
    tmp_path: Path,
    capsys,
) -> None:
    config = _provider_config(routing=True)
    expected = {
        "version": 1,
        "ok": True,
        "dry_run": True,
        "status": "planned",
        "issues": [],
        "artifacts": {
            "routing_plan": str(tmp_path / "staged" / "routing-plan.json"),
            "gmail_configuration_plan": str(
                tmp_path / "staged" / "gmail-configuration-plan.json"
            ),
            "report": str(tmp_path / "staged" / "migration-report.json"),
        },
    }
    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.check_free_space_for_path"), \
        mock.patch("components.main.load_config_file", return_value=config), \
        mock.patch("components.main.provider_preflight", side_effect=AssertionError("workflow owns preflight")), \
        mock.patch("components.main.run_provider_migration_workflow", return_value=expected) as workflow:
        rc = main(_base_args(tmp_path, "preflight"))

    assert rc == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "status=planned" in captured.err
    assert str(tmp_path / "staged" / "routing-plan.json") in captured.err
    assert str(tmp_path / "staged" / "gmail-configuration-plan.json") in captured.err
    assert str(tmp_path / "staged" / "migration-report.json") in captured.err
    assert workflow.call_args.args[:2] == (config, tmp_path / "staged")
    assert workflow.call_args.kwargs["dry_run"] is True


def test_nonrouting_preflight_with_report_file_uses_reporting_workflow(
    tmp_path: Path,
    capsys,
) -> None:
    config = _provider_config(routing=False)
    report_path = tmp_path / "staged" / "reports" / "requested.json"
    expected = {
        "version": 1,
        "ok": True,
        "dry_run": True,
        "status": "planned",
        "issues": [],
        "artifacts": {
            "staging_root": str(tmp_path / "staged"),
            "report": str(report_path),
        },
    }
    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.check_free_space_for_path"), \
        mock.patch("components.main.load_config_file", return_value=config), \
        mock.patch(
            "components.main.provider_preflight",
            side_effect=AssertionError("reporting workflow owns explicit report preflight"),
        ), \
        mock.patch(
            "components.main.run_provider_migration_workflow",
            return_value=expected,
        ) as workflow:
        rc = main(
            _base_args(tmp_path, "preflight")
            + ["--report-file", str(report_path)]
        )

    assert rc == 0
    assert capsys.readouterr().out == ""
    workflow.assert_called_once()
    assert workflow.call_args.args[:2] == (config, tmp_path / "staged")
    assert workflow.call_args.kwargs["dry_run"] is True
    assert workflow.call_args.kwargs["report_path"] == report_path


def test_nonrouting_preflight_writes_explicit_requested_report(
    tmp_path: Path,
) -> None:
    config = _provider_config(routing=False)
    report_path = tmp_path / "staged" / "reports" / "requested.json"
    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.check_free_space_for_path"), \
        mock.patch("components.main.load_config_file", return_value=config), \
        mock.patch(
            "components.main.provider_preflight",
            side_effect=AssertionError("explicit report must not use unreported preflight"),
        ), \
        mock.patch(
            "components.provider_workflow.provider_ops.provider_preflight",
            return_value=(True, []),
        ):
        rc = main(
            _base_args(tmp_path, "preflight")
            + ["--report-file", str(report_path)]
        )

    assert rc == 0
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    assert payload["status"] == "planned"
    assert payload["artifacts"] == {
        "staging_root": str(tmp_path / "staged"),
        "report": str(report_path),
    }
    assert "migration report" in payload["actions_required"][0]
    assert "routing plan" not in payload["actions_required"][0]


def test_migrate_preserves_exit_130_after_structured_cancellation_report(
    tmp_path: Path,
    capsys,
) -> None:
    config = _provider_config(routing=True)

    def cancelled_workflow(*_args, **kwargs):
        kwargs["stop_event"].set()
        return {
            "version": 1,
            "ok": False,
            "dry_run": False,
            "status": "failed",
            "issues": ["Gmail filter reconciliation cancelled: stop requested"],
            "artifacts": {},
        }

    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.check_free_space_for_path"), \
        mock.patch("components.main.load_config_file", return_value=config), \
        mock.patch(
            "components.main.run_provider_migration_workflow",
            side_effect=cancelled_workflow,
        ):
        rc = main(_base_args(tmp_path, "migrate"))

    assert rc == 130
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "stop requested before completion" in captured.err


@pytest.mark.parametrize(
    ("mode", "status"),
    [("migrate", "completed"), ("preflight", "planned")],
)
def test_provider_workflow_late_stop_after_terminal_commit_returns_zero(
    tmp_path: Path,
    capsys,
    mode: str,
    status: str,
) -> None:
    config = _provider_config(routing=True)

    def committed_workflow(*_args, **kwargs):
        kwargs["stop_event"].set()
        return {
            "version": 1,
            "ok": True,
            "dry_run": mode == "preflight",
            "status": status,
            "issues": [],
            "terminal_commit_id": "late-stop-commit",
            "terminal_commit_spec_sha256": "a" * 64,
            "terminal_target_status": status,
            "terminal_committed": True,
            "report_persisted": True,
            "artifacts": {},
        }

    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.check_free_space_for_path"), \
        mock.patch("components.main.load_config_file", return_value=config), \
        mock.patch(
            "components.main.run_provider_migration_workflow",
            side_effect=committed_workflow,
        ):
        rc = main(_base_args(tmp_path, mode))

    assert rc == 0
    captured = capsys.readouterr()
    assert "stop requested after terminal success commit" in captured.err
    assert "stop requested before completion" not in captured.err


def test_provider_workflow_stop_without_terminal_commit_returns_130(
    tmp_path: Path,
    capsys,
) -> None:
    config = _provider_config(routing=True)

    def uncommitted_workflow(*_args, **kwargs):
        kwargs["stop_event"].set()
        return {
            "version": 1,
            "ok": True,
            "dry_run": False,
            "status": "completed",
            "issues": [],
            "terminal_committed": False,
            "artifacts": {},
        }

    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.check_free_space_for_path"), \
        mock.patch("components.main.load_config_file", return_value=config), \
        mock.patch(
            "components.main.run_provider_migration_workflow",
            side_effect=uncommitted_workflow,
        ):
        rc = main(_base_args(tmp_path, "migrate"))

    assert rc == 130
    assert "stop requested before completion" in capsys.readouterr().err


def test_migrate_preserves_exit_130_when_terminal_write_failure_races_stop(
    tmp_path: Path,
    capsys,
) -> None:
    config = _provider_config(routing=True)
    report_path = tmp_path / "staged" / "migration-report.json"

    def failed_terminal_write(*_args, **kwargs):
        kwargs["stop_event"].set()
        return {
            "version": 1,
            "ok": False,
            "dry_run": False,
            "status": "failed",
            "issues": ["Failed to write the terminal migration report: disk full"],
            "report_write_error": "disk full",
            "report_persisted": False,
            "artifacts": {"report": str(report_path)},
        }

    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.check_free_space_for_path"), \
        mock.patch("components.main.load_config_file", return_value=config), \
        mock.patch(
            "components.main.run_provider_migration_workflow",
            side_effect=failed_terminal_write,
        ):
        rc = main(_base_args(tmp_path, "migrate"))

    assert rc == 130
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "stop requested before completion" in captured.err
    assert "terminal migration report: disk full" in captured.err
    assert "report write error | disk full" in captured.err
    assert "artifact | migration report=" not in captured.err


def test_provider_workflow_cli_diagnostics_redact_common_secret_forms(
    tmp_path: Path,
    capsys,
) -> None:
    config = _provider_config(routing=False)
    secret_values = [
        "auth-header-value",
        "basic-auth-value",
        "json-basic-auth-value",
        "bare-bearer-value",
        "password-value",
        "access-token-value",
        "refresh-token-value",
        "client-secret-value",
        "api-key-value",
        "plain-token-value",
        "oauth-token-value",
        "authorization-token-value",
        "api-token-value",
        "url-token-value",
        "write-password-value",
        "write-api-token-value",
        "removal-secret-value",
    ]
    expected = {
        "version": 1,
        "ok": False,
        "dry_run": False,
        "status": "failed",
        "issues": [
            "Authorization: Bearer auth-header-value",
            "authorization=Basic basic-auth-value",
            '"AUTHORIZATION": "Basic json-basic-auth-value"',
            "BEARER bare-bearer-value",
            "PASSWORD=password-value",
            "access_token: access-token-value",
            '"refresh-token": "refresh-token-value"',
            "client_secret=client-secret-value",
            "API-Key: api-key-value",
            "token is plain-token-value",
            "OAUTH_TOKEN=oauth-token-value",
            "Authorization_Token: authorization-token-value",
            "api_token is api-token-value",
            "callback?ToKeN%3Durl-token-value%26state%3Dok",
        ],
        "report_write_error": (
            "PASSWORD=write-password-value API_TOKEN=write-api-token-value"
        ),
        "report_removal_error": "Secret: removal-secret-value",
        "report_persisted": False,
        "artifacts": {},
    }
    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.check_free_space_for_path"), \
        mock.patch("components.main.load_config_file", return_value=config), \
        mock.patch(
            "components.main.run_provider_migration_workflow",
            return_value=expected,
        ):
        rc = main(_base_args(tmp_path, "migrate"))

    assert rc == 4
    diagnostics = capsys.readouterr().err
    assert diagnostics.count("[REDACTED]") >= len(secret_values)
    for secret in secret_values:
        assert secret not in diagnostics


def test_cli_logs_recovered_report_durability_warning_without_token_leaks(
    tmp_path: Path,
    capsys,
) -> None:
    config = _provider_config(routing=False)
    report_path = tmp_path / "staged" / "migration-report.json"
    report_path.parent.mkdir(parents=True)
    report_path.write_text('{"status":"completed"}\n', encoding="utf-8")
    secret_values = (
        "durability-oauth-value",
        "durability-authorization-value",
        "durability-api-value",
        "durability-url-value",
    )
    expected = {
        "version": 1,
        "ok": True,
        "dry_run": False,
        "status": "completed",
        "issues": [],
        "report_persisted": True,
        "report_durability_uncertain": (
            "directory fsync failed: "
            f"OAUTH_TOKEN={secret_values[0]} "
            f"authorization_token={secret_values[1]} "
            f"Api_Token={secret_values[2]} "
            f"callback?token%3D{secret_values[3]}%26state%3Dok"
        ),
        "artifacts": {"report": str(report_path)},
    }
    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.check_free_space_for_path"), \
        mock.patch("components.main.load_config_file", return_value=config), \
        mock.patch(
            "components.main.run_provider_migration_workflow",
            return_value=expected,
        ):
        rc = main(_base_args(tmp_path, "migrate"))

    assert rc == 0
    diagnostics = capsys.readouterr().err
    assert "report durability uncertain | directory fsync failed:" in diagnostics
    assert diagnostics.count("[REDACTED]") >= len(secret_values)
    assert f"artifact | migration report={report_path}" in diagnostics
    for secret in secret_values:
        assert secret not in diagnostics


def test_early_workflow_failure_logs_each_issue_and_absent_report_write_error(
    tmp_path: Path,
    capsys,
) -> None:
    config = _provider_config(routing=False)
    report_path = tmp_path / "staged" / "migration-report.json"
    expected = {
        "version": 1,
        "ok": False,
        "dry_run": False,
        "status": "failed",
        "stage_order": ["discover_plan"],
        "issues": ["preflight issue one", "preflight issue two\ncontinued"],
        "report_write_error": "disk full\nwhile writing failure report",
        "report_persisted": False,
        "artifacts": {"report": str(report_path)},
        "provider": {"authorization": "top-secret-provider-token"},
    }
    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.check_free_space_for_path"), \
        mock.patch("components.main.load_config_file", return_value=config), \
        mock.patch(
            "components.main.run_provider_migration_workflow",
            return_value=expected,
        ):
        rc = main(_base_args(tmp_path, "migrate"))

    assert rc == 4
    captured = capsys.readouterr()
    assert "Provider migrate issue | preflight issue one" in captured.err
    assert "preflight issue two\\x0acontinued" in captured.err
    assert "disk full\\x0awhile writing failure report" in captured.err
    assert "artifact | migration report=" not in captured.err
    assert str(report_path) not in captured.err
    assert "top-secret-provider-token" not in captured.err


def test_post_mutation_failure_logs_issue_and_persisted_report_artifact(
    tmp_path: Path,
    capsys,
) -> None:
    config = _provider_config(routing=False)
    report_path = tmp_path / "staged" / "migration-report.json"
    report_path.parent.mkdir(parents=True)
    report_path.write_text('{"status":"failed"}\n', encoding="utf-8")
    expected = {
        "version": 1,
        "ok": False,
        "dry_run": False,
        "status": "failed",
        "stage_order": ["discover_plan", "export", "import", "provision_filters"],
        "issues": ["post-import filter permission denied"],
        "report_persisted": True,
        "artifacts": {"report": str(report_path)},
    }
    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.check_free_space_for_path"), \
        mock.patch("components.main.load_config_file", return_value=config), \
        mock.patch(
            "components.main.run_provider_migration_workflow",
            return_value=expected,
        ):
        rc = main(_base_args(tmp_path, "migrate"))

    assert rc == 4
    captured = capsys.readouterr()
    assert "Provider migrate issue | post-import filter permission denied" in captured.err
    assert f"artifact | migration report={report_path}" in captured.err


def test_workspace_alias_preflight_logs_immutable_plan_artifact(
    tmp_path: Path,
    capsys,
) -> None:
    config = _provider_config(routing=True)
    config.target.workspace_aliases = SimpleNamespace(enabled=True)  # type: ignore[assignment]
    alias_plan = tmp_path / "staged" / "workspace-alias-plan.json"
    expected = {
        "version": 1,
        "ok": True,
        "dry_run": True,
        "status": "planned",
        "issues": [],
        "artifacts": {
            "workspace_alias_plan": str(alias_plan),
            "report": str(tmp_path / "staged" / "migration-report.json"),
        },
    }
    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.check_free_space_for_path"), \
        mock.patch("components.main.load_config_file", return_value=config), \
        mock.patch(
            "components.main.run_provider_migration_workflow",
            return_value=expected,
        ) as workflow:
        rc = main(_base_args(tmp_path, "preflight"))

    assert rc == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert str(alias_plan) in captured.err
    assert "workspace-alias-plan.json" in captured.err
    assert workflow.call_args.kwargs["dry_run"] is True


def test_migrate_rejects_report_path_outside_staging_without_chmod(
    tmp_path: Path,
    capsys,
) -> None:
    outside = tmp_path / "unrelated"
    outside.mkdir(mode=0o755)
    report_path = outside / "report.json"
    with mock.patch("components.main.run_provider_migration_workflow") as workflow:
        rc = main(
            _base_args(tmp_path, "migrate")
            + ["--report-file", str(report_path)]
        )

    captured = capsys.readouterr()
    assert rc == 2
    assert captured.out == ""
    assert "must be inside the staging directory" in captured.err
    workflow.assert_not_called()
    assert not report_path.exists()
    assert stat.S_IMODE(outside.stat().st_mode) == 0o755


@pytest.mark.parametrize(
    "filename",
    [
        "routing-plan.json",
        "gmail-configuration-plan.json",
        "workspace-alias-plan.json",
    ],
)
def test_migrate_rejects_report_path_reserved_for_plan_artifact(
    tmp_path: Path,
    capsys,
    filename: str,
) -> None:
    report_path = tmp_path / "staged" / filename
    with mock.patch("components.main.run_provider_migration_workflow") as workflow:
        rc = main(
            _base_args(tmp_path, "migrate")
            + ["--report-file", str(report_path)]
        )

    assert rc == 2
    assert "reserved staged artifact" in capsys.readouterr().err
    workflow.assert_not_called()


@pytest.mark.parametrize(
    "relative",
    [
        ".import-locks/provider-workflow.lock",
        ".import-locks/provider-deadbeef.lock",
        ".import-locks/nested/custom-report.json",
    ],
)
@pytest.mark.parametrize("preexisting", [False, True])
def test_migrate_rejects_entire_internal_lock_namespace_without_staging_changes(
    tmp_path: Path,
    capsys,
    relative: str,
    preexisting: bool,
) -> None:
    staged = tmp_path / "staged"
    report_path = staged / relative
    if preexisting:
        report_path.parent.mkdir(parents=True, mode=0o700)
        report_path.write_text("preexisting internal file\n", encoding="utf-8")
        report_path.chmod(0o600)
    with mock.patch("components.main.run_provider_migration_workflow") as workflow:
        rc = main(
            _base_args(tmp_path, "migrate")
            + ["--report-file", str(report_path)]
        )

    assert rc == 2
    assert "reserved internal staging namespace" in capsys.readouterr().err
    workflow.assert_not_called()
    if preexisting:
        assert report_path.read_text(encoding="utf-8") == "preexisting internal file\n"
        assert stat.S_IMODE(report_path.stat().st_mode) == 0o600
    else:
        assert not staged.exists()


def test_migrate_rejects_report_path_inside_configured_account_directory(
    tmp_path: Path,
    capsys,
) -> None:
    config = _provider_config(routing=True)
    report_path = tmp_path / "staged" / "source@example.com" / "report.json"
    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.load_config_file", return_value=config), \
        mock.patch("components.main.run_provider_migration_workflow") as workflow:
        rc = main(
            _base_args(tmp_path, "migrate")
            + ["--report-file", str(report_path)]
        )

    assert rc == 2
    assert "provider account directory" in capsys.readouterr().err
    workflow.assert_not_called()


@pytest.mark.parametrize("mode", ["export", "import", "validate"])
def test_alias_enabled_standalone_export_import_and_validate_are_migrate_only(
    tmp_path: Path,
    capsys,
    mode: str,
) -> None:
    config = _provider_config(routing=True)
    config.target.workspace_aliases = SimpleNamespace(enabled=True)  # type: ignore[assignment]
    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.load_config_file", return_value=config), \
        mock.patch("components.main.provider_export_all") as exporter, \
        mock.patch("components.main.provider_import_all") as importer, \
        mock.patch("components.main.provider_validate_all") as validator, \
        mock.patch("components.main.run_provider_migration_workflow") as workflow:
        rc = main(_base_args(tmp_path, mode) + ["--no-connectivity-test"])

    assert rc == 2
    captured = capsys.readouterr()
    assert "Alias-enabled provider" in captured.err
    assert "migrate-only" in captured.err
    exporter.assert_not_called()
    importer.assert_not_called()
    validator.assert_not_called()
    workflow.assert_not_called()


def test_standalone_export_waits_for_workflow_or_direct_import_root_lock(
    tmp_path: Path,
) -> None:
    from components import provider_ops

    config = _provider_config(routing=True)
    staged = tmp_path / "staged"
    plan = SimpleNamespace(mapping_digest="a" * 64)
    events: list[str] = []
    lock_contended = threading.Event()
    real_flock = provider_ops.fcntl.flock

    def recording_flock(fd: int, operation: int) -> None:
        try:
            real_flock(fd, operation)
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK}:
                lock_contended.set()
            raise

    def record(name: str, result=None):
        def inner(*_args, **_kwargs):
            events.append(name)
            return result

        return inner

    with mock.patch("components.main.setup_logging", return_value=tmp_path / "run.log"), \
        mock.patch("components.main.check_environment"), \
        mock.patch("components.main.check_free_space_for_path"), \
        mock.patch("components.main.load_config_file", return_value=config), \
        mock.patch(
            "components.main.load_provider_routing_plan",
            side_effect=record("load-plan", plan),
        ), \
        mock.patch(
            "components.main.require_gmail_configuration_plan",
            side_effect=record("require-gmail-plan"),
        ), \
        mock.patch(
            "components.main.provider_export_all",
            side_effect=record("export"),
        ), \
        mock.patch(
            "components.main.provider_audit_all",
            side_effect=record("audit", (True, [])),
        ), \
        mock.patch.object(provider_ops.fcntl, "flock", side_effect=recording_flock):
        with ThreadPoolExecutor(max_workers=1) as executor:
            with provider_ops.provider_workflow_lock(staged, stop_event=None):
                future = executor.submit(
                    main,
                    _base_args(tmp_path, "export") + ["--no-connectivity-test"],
                )
                assert lock_contended.wait(5), "standalone export never contended"
                assert events == []
                assert not future.done()
            rc = future.result(timeout=5)

    assert rc == 0
    assert events == ["load-plan", "require-gmail-plan", "export", "audit"]


@pytest.mark.parametrize(
    ("mode", "expected_events"),
    [
        ("import", ["staged:stable", "import"]),
        ("validate", ["staged:stable", "validate"]),
        ("audit", ["audit:stable"]),
    ],
)
def test_standalone_provider_consumers_wait_for_stable_root_generation(
    tmp_path: Path,
    mode: str,
    expected_events: list[str],
) -> None:
    from components import provider_ops

    config = _provider_config(routing=False)
    staged = tmp_path / "staged"
    staged.mkdir()
    generation = staged / "generation"
    generation.write_text("transient", encoding="utf-8")
    events: list[str] = []
    lock_contended = threading.Event()
    real_flock = provider_ops.fcntl.flock
    local_validation = {
        "duplicates": [],
        "failed": [],
        "missing": [],
    }

    def recording_flock(fd: int, operation: int) -> None:
        try:
            real_flock(fd, operation)
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK}:
                lock_contended.set()
            raise

    def staged_validation(*_args, **_kwargs):
        observed = generation.read_text(encoding="utf-8")
        events.append(f"staged:{observed}")
        return "source@example.com", local_validation

    def import_all(*_args, **_kwargs) -> None:
        events.append("import")

    def validate_all(*_args, **_kwargs):
        events.append("validate")
        return True, []

    def audit_all(*_args, **_kwargs):
        observed = generation.read_text(encoding="utf-8")
        events.append(f"audit:{observed}")
        return True, []

    with mock.patch("components.main.setup_logging", return_value=tmp_path / "run.log"), \
        mock.patch("components.main.check_environment"), \
        mock.patch("components.main.check_free_space_for_path"), \
        mock.patch("components.main.load_config_file", return_value=config), \
        mock.patch("components.main.provider_validate_account", side_effect=staged_validation), \
        mock.patch("components.main.provider_import_all", side_effect=import_all), \
        mock.patch("components.main.provider_validate_all", side_effect=validate_all), \
        mock.patch("components.main.provider_audit_all", side_effect=audit_all), \
        mock.patch.object(provider_ops.fcntl, "flock", side_effect=recording_flock):
        with ThreadPoolExecutor(max_workers=1) as executor:
            with provider_ops.provider_workflow_lock(staged, stop_event=None):
                future = executor.submit(
                    main,
                    _base_args(tmp_path, mode) + ["--no-connectivity-test"],
                )
                assert lock_contended.wait(5), f"standalone provider {mode} never contended"
                assert events == []
                assert not future.done()
                generation.write_text("stable", encoding="utf-8")
            rc = future.result(timeout=5)

    assert rc == 0
    assert events == expected_events


@pytest.mark.parametrize(
    "journal_issue",
    [
        "journal row 1 has invalid status: unknown",
        "journal msg-1 target_endpoint_sha256 does not match config target endpoint",
        "journal committed content_sha256 does not match manifest: msg-1 in INBOX",
    ],
)
def test_routed_import_hard_journal_gate_precedes_all_remote_operations(
    tmp_path: Path,
    journal_issue: str,
) -> None:
    config = _provider_config(routing=True)
    staged = tmp_path / "staged"
    staged.mkdir()
    plan = SimpleNamespace(mapping_digest="a" * 64)
    hard_failure = {
        "duplicates": [],
        "failed": [journal_issue],
        "missing": [],
    }

    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.check_free_space_for_path"), \
        mock.patch("components.main.load_config_file", return_value=config), \
        mock.patch("components.main.load_provider_routing_plan", return_value=plan), \
        mock.patch("components.main.require_gmail_configuration_plan"), \
        mock.patch(
            "components.main.provider_validate_account",
            return_value=("source@example.com", hard_failure),
        ) as staged_validator, \
        mock.patch("components.main.provider_test_accounts") as connectivity, \
        mock.patch("components.main.gmail_api_client_if_required") as gmail_client, \
        mock.patch("components.main.plan_live_gmail_configuration") as live_plan, \
        mock.patch("components.main.provision_gmail_labels") as labels, \
        mock.patch("components.main.provider_import_all") as importer, \
        mock.patch("components.main.provision_gmail_filters") as filters:
        rc = main(_base_args(tmp_path, "import"))

    assert rc == 4
    validation_kwargs = staged_validator.call_args.kwargs
    assert validation_kwargs["check_target"] is False
    assert validation_kwargs["write_report"] is False
    assert validation_kwargs["allow_unresolved_pending"] is True
    assert validation_kwargs["repair_trailing_journal"] is True
    assert validation_kwargs["allow_missing_gmail_target_msgid"] is True
    assert validation_kwargs["include_journal"] is True
    assert validation_kwargs["routing_plan"] is plan
    connectivity.assert_not_called()
    gmail_client.assert_not_called()
    live_plan.assert_not_called()
    labels.assert_not_called()
    importer.assert_not_called()
    filters.assert_not_called()


def test_standalone_routing_import_reconciles_and_verifies_gmail_before_import(
    tmp_path: Path,
) -> None:
    config = _provider_config(routing=True)
    staged = tmp_path / "staged"
    staged.mkdir()
    plan = SimpleNamespace(mapping_digest="a" * 64)
    client = object()
    events: list[str] = []

    def record(name: str, result=None):
        def inner(*_args, **_kwargs):
            events.append(name)
            return result

        return inner

    local_validation = {
        "duplicates": [],
        "failed": [],
        "missing": [],
    }
    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.check_free_space_for_path"), \
        mock.patch("components.main.load_config_file", return_value=config), \
        mock.patch("components.main.load_provider_routing_plan", return_value=plan), \
        mock.patch("components.main.require_gmail_configuration_plan"), \
        mock.patch("components.main.provider_validate_account", return_value=("source", local_validation)), \
        mock.patch("components.main.gmail_api_client_if_required", return_value=client), \
        mock.patch("components.main.plan_live_gmail_configuration", side_effect=record("live-plan", object())), \
        mock.patch("components.main.require_live_gmail_plan_ok", side_effect=record("live-gate")), \
        mock.patch(
            "components.main.provision_gmail_labels",
            side_effect=record(
                "labels",
                SimpleNamespace(ok=True, labels=(), issues=(), conflicts=()),
            ),
        ), \
        mock.patch("components.main.provider_import_all", side_effect=record("import")) as importer, \
        mock.patch(
            "components.main.provision_gmail_filters",
            side_effect=record(
                "filters",
                SimpleNamespace(ok=True, filters=(), issues=(), conflicts=()),
            ),
        ), \
        mock.patch(
            "components.main.verify_gmail_configuration",
            side_effect=record("verify", SimpleNamespace(ok=True, issues=())),
        ):
        rc = main(_base_args(tmp_path, "import") + ["--no-connectivity-test"])

    assert rc == 0
    assert events == ["live-plan", "live-gate", "labels", "filters", "verify", "import"]
    assert importer.call_args.kwargs["routing_plan"] is plan


@pytest.mark.parametrize("failure_phase", ["filters", "verification"])
def test_standalone_routing_import_gmail_failure_precedes_provider_import(
    tmp_path: Path,
    failure_phase: str,
) -> None:
    config = _provider_config(routing=True)
    staged = tmp_path / "staged"
    staged.mkdir()
    plan = SimpleNamespace(mapping_digest="a" * 64)
    local_validation = {
        "duplicates": [],
        "failed": [],
        "missing": [],
    }
    filters = (
        mock.Mock(side_effect=RuntimeError("gmail.settings.basic denied"))
        if failure_phase == "filters"
        else mock.Mock(
            return_value=SimpleNamespace(
                ok=True,
                filters=(),
                issues=(),
                conflicts=(),
            )
        )
    )
    verification = SimpleNamespace(
        ok=failure_phase != "verification",
        issues=("required Gmail filter is missing",)
        if failure_phase == "verification"
        else (),
    )

    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.check_free_space_for_path"), \
        mock.patch("components.main.load_config_file", return_value=config), \
        mock.patch("components.main.load_provider_routing_plan", return_value=plan), \
        mock.patch("components.main.require_gmail_configuration_plan"), \
        mock.patch(
            "components.main.provider_validate_account",
            return_value=("source", local_validation),
        ), \
        mock.patch("components.main.gmail_api_client_if_required", return_value=object()), \
        mock.patch("components.main.plan_live_gmail_configuration", return_value=object()), \
        mock.patch("components.main.require_live_gmail_plan_ok"), \
        mock.patch(
            "components.main.provision_gmail_labels",
            return_value=SimpleNamespace(
                ok=True,
                labels=(),
                issues=(),
                conflicts=(),
            ),
        ), \
        mock.patch("components.main.provision_gmail_filters", filters), \
        mock.patch(
            "components.main.verify_gmail_configuration",
            return_value=verification,
        ) as verifier, \
        mock.patch("components.main.provider_import_all") as importer:
        rc = main(_base_args(tmp_path, "import") + ["--no-connectivity-test"])

    assert rc == (1 if failure_phase == "filters" else 4)
    importer.assert_not_called()
    if failure_phase == "filters":
        verifier.assert_not_called()
    else:
        verifier.assert_called_once_with(plan, mock.ANY)


@pytest.mark.parametrize(
    ("failure", "expected_rc"),
    [
        (
            ProviderImportIntegrityGateError(
                "merge group unresolved pending APPENDs have incompatible INTERNALDATE values"
            ),
            4,
        ),
        (RuntimeError("target IMAP service failed during import"), 1),
    ],
    ids=("integrity-gate", "operational-runtime"),
)
def test_standalone_provider_import_maps_only_typed_integrity_gate_to_rc4(
    tmp_path: Path,
    failure: RuntimeError,
    expected_rc: int,
) -> None:
    config = _provider_config(routing=False)
    staged = tmp_path / "staged"
    staged.mkdir()
    local_validation = {
        "duplicates": [],
        "failed": [],
        "missing": [],
    }
    import_calls: list[str] = []

    def fail_import(*_args, **_kwargs) -> None:
        import_calls.append("import-gate")
        raise failure

    with mock.patch("components.main.setup_logging", return_value=tmp_path / "run.log"), \
        mock.patch("components.main.check_environment"), \
        mock.patch("components.main.check_free_space_for_path"), \
        mock.patch("components.main.load_config_file", return_value=config), \
        mock.patch("components.main.provider_validate_account", return_value=("source", local_validation)), \
        mock.patch("components.main.gmail_api_client_if_required") as gmail_factory, \
        mock.patch("components.main.plan_live_gmail_configuration") as live_plan, \
        mock.patch("components.main.provision_gmail_labels") as labels, \
        mock.patch("components.main.provision_gmail_filters") as filters, \
        mock.patch("components.main.verify_gmail_configuration") as gmail_verify, \
        mock.patch("components.main.provider_import_all", side_effect=fail_import):
        rc = main(_base_args(tmp_path, "import") + ["--no-connectivity-test"])

    assert rc == expected_rc
    assert import_calls == ["import-gate"]
    gmail_factory.assert_not_called()
    live_plan.assert_not_called()
    labels.assert_not_called()
    filters.assert_not_called()
    gmail_verify.assert_not_called()


def test_standalone_routing_validate_combines_gmail_verification(
    tmp_path: Path,
) -> None:
    config = _provider_config(routing=True)
    staged = tmp_path / "staged"
    staged.mkdir()
    plan = SimpleNamespace(mapping_digest="a" * 64)
    local_validation = {
        "duplicates": [],
        "failed": [],
        "missing": [],
    }
    verification = SimpleNamespace(ok=False, issues=("required filter missing",))
    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.check_free_space_for_path"), \
        mock.patch("components.main.load_config_file", return_value=config), \
        mock.patch("components.main.load_provider_routing_plan", return_value=plan), \
        mock.patch("components.main.require_gmail_configuration_plan"), \
        mock.patch("components.main.provider_validate_account", return_value=("source", local_validation)), \
        mock.patch("components.main.gmail_api_client_if_required", return_value=object()), \
        mock.patch("components.main.provider_validate_all", return_value=(True, [])), \
        mock.patch("components.main.verify_gmail_configuration", return_value=verification):
        rc = main(_base_args(tmp_path, "validate") + ["--no-connectivity-test"])

    assert rc == 4
