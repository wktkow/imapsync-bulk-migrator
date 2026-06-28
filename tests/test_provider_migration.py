from __future__ import annotations

import contextlib
import hashlib
import imaplib
import json
import os
import re
import threading
from pathlib import Path
from typing import Iterator, List, Optional
from unittest import mock

import pytest

from components.content_binding import CONTENT_BINDING_FIELD, provider_content_binding_sha256
from components.models import (
    AuthConfig,
    MigrationAccount,
    MigrationSettings,
    ProviderEndpoint,
    ProviderMigrationConfig,
    load_config_file,
)
from components.provider_ops import (
    MailboxInfo,
    _atomic_json,
    _provider_account_worker_results,
    _prune_provider_artifact_orphans,
    _safe_identity,
    build_xoauth2_payload,
    consume_target_match_num,
    effective_auth,
    fetch_all_uids_and_uidvalidity,
    gmail_labels_for_restore,
    imap_connection,
    list_mailboxes,
    append_journal,
    load_import_journal,
    load_manifest,
    offline_journal_target_mailbox_issues,
    parse_list_line,
    parse_provider_fetch_response,
    provider_audit_account,
    provider_audit_all,
    provider_export_account,
    provider_export_all,
    provider_import_account,
    provider_import_all,
    provider_manifest_digest,
    provider_account_endpoint_state_digest,
    provider_endpoint_state,
    provider_endpoint_state_digest,
    provider_target_journal_binding,
    provider_preflight,
    provider_test_accounts,
    provider_validate_account,
    provider_validate_all,
    quote_mailbox_name,
    RateLimiter,
    resolve_secret,
    resolve_primary_mailbox,
    resolve_target_mailbox,
    restore_gmail_labels,
    restore_gmail_starred_flag,
    target_merge_group_key,
    target_has_message,
    translate_source_mailbox_for_target,
    translated_target_mailboxes_for_rows,
    xoauth2_authenticator,
)
from components.utils import encode_imap_utf7


def _provider_config(*, target_mode: str = "empty") -> ProviderMigrationConfig:
    return ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="source@example.com", password="token"),
            gmail_full_visibility_verified=True,
        ),
        target=ProviderEndpoint(
            provider="icloud",
            host="imap.mail.me.com",
            auth=AuthConfig(method="app_password", username="target", password="secret"),
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@icloud.com")],
        migration=MigrationSettings(target_mode=target_mode),
    )


def _generic_target_config(*, target_mode: str = "empty") -> ProviderMigrationConfig:
    return ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="source@example.com", password="token"),
            gmail_full_visibility_verified=True,
        ),
        target=ProviderEndpoint(
            provider="imap",
            host="mail.target.example.com",
            auth=AuthConfig(method="password", username="target@example.com", password="secret"),
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@example.com")],
        migration=MigrationSettings(target_mode=target_mode),
    )


def test_provider_atomic_json_rejects_symlinked_account_dir(tmp_path: Path) -> None:
    export_root = tmp_path / "export"
    outside = tmp_path / "outside"
    export_root.mkdir()
    outside.mkdir()
    account_dir = export_root / "source@example.com"
    try:
        account_dir.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(RuntimeError, match="symlinked provider directory"):
        _atomic_json(account_dir / "export-state.json", {"complete": False})

    assert not (outside / "export-state.json").exists()


def test_provider_atomic_json_refuses_preexisting_temp_symlink(tmp_path: Path) -> None:
    account_dir = tmp_path / "source@example.com"
    account_dir.mkdir()
    victim = tmp_path / "victim.txt"
    victim.write_text("do not overwrite", encoding="utf-8")
    path = account_dir / "export-state.json"
    temp_path = account_dir / f".{path.name}.{os.getpid()}.123456.tmp"
    try:
        temp_path.symlink_to(victim)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    with mock.patch("components.provider_ops.time.time_ns", return_value=123456):
        with pytest.raises(RuntimeError, match="unsafe provider temporary file|symlinked provider file"):
            _atomic_json(path, {"complete": False})

    assert victim.read_text(encoding="utf-8") == "do not overwrite"


def test_provider_atomic_json_rejects_symlinked_ancestor(tmp_path: Path) -> None:
    real_root = tmp_path / "real-root"
    real_root.mkdir()
    linked_root = tmp_path / "linked-root"
    try:
        linked_root.symlink_to(real_root, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")
    account_dir = linked_root / "source@example.com"

    with pytest.raises(RuntimeError, match="symlinked provider directory"):
        _atomic_json(account_dir / "export-state.json", {"complete": False})

    assert not (real_root / "source@example.com" / "export-state.json").exists()


def test_provider_append_journal_rejects_symlinked_journal(tmp_path: Path) -> None:
    account_dir = tmp_path / "source@example.com"
    account_dir.mkdir()
    account = MigrationAccount(source_email="source@example.com", target_email="target@example.com")
    victim = tmp_path / "victim.jsonl"
    victim.write_text("outside\n", encoding="utf-8")
    journal = account_dir / "import-target@example.com.journal.jsonl"
    try:
        journal.symlink_to(victim)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(RuntimeError, match="symlinked provider file"):
        append_journal(account_dir, account, {"status": "pending", "canonical_id": "id"})

    assert victim.read_text(encoding="utf-8") == "outside\n"


def test_provider_append_journal_rejects_hard_linked_journal(tmp_path: Path) -> None:
    account_dir = tmp_path / "source@example.com"
    account_dir.mkdir()
    account = MigrationAccount(source_email="source@example.com", target_email="target@example.com")
    victim = tmp_path / "victim-hardlink.jsonl"
    victim.write_text("outside\n", encoding="utf-8")
    journal = account_dir / "import-target@example.com.journal.jsonl"
    try:
        os.link(victim, journal)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"hard link creation unavailable: {exc}")

    with pytest.raises(RuntimeError, match="hard-linked provider file"):
        append_journal(account_dir, account, {"status": "pending", "canonical_id": "id"})

    assert victim.read_text(encoding="utf-8") == "outside\n"
    assert os.stat(victim).st_ino == os.stat(journal).st_ino


def test_provider_append_journal_rejects_non_regular_journal(tmp_path: Path) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO creation unavailable")
    account_dir = tmp_path / "source@example.com"
    account_dir.mkdir()
    account = MigrationAccount(source_email="source@example.com", target_email="target@example.com")
    journal = account_dir / "import-target@example.com.journal.jsonl"
    try:
        os.mkfifo(journal)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"FIFO creation unavailable: {exc}")

    with pytest.raises(RuntimeError, match="non-regular provider file"):
        append_journal(account_dir, account, {"status": "pending", "canonical_id": "id"})


def test_provider_load_manifest_rejects_non_regular_manifest(tmp_path: Path) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO creation unavailable")
    account_dir = tmp_path / "source@example.com"
    account_dir.mkdir()
    try:
        os.mkfifo(account_dir / "manifest.jsonl")
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"FIFO creation unavailable: {exc}")

    with pytest.raises(RuntimeError, match="non-regular provider file"):
        load_manifest(account_dir)


@pytest.mark.parametrize("writer_name", ["json", "jsonl"])
def test_provider_atomic_writers_do_not_chmod_replaced_symlink_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    writer_name: str,
) -> None:
    from components import provider_ops

    target = tmp_path / "source@example.com" / (
        "export-state.json" if writer_name == "json" else "manifest.jsonl"
    )
    victim = tmp_path / "victim.json"
    victim.write_text("outside\n", encoding="utf-8")
    victim.chmod(0o644)
    original_mode = victim.stat().st_mode & 0o777
    real_rename = provider_ops.os.rename

    def racing_rename(src, dst, *args, **kwargs):
        result = real_rename(src, dst, *args, **kwargs)
        target.unlink()
        try:
            target.symlink_to(victim)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")
        return result

    monkeypatch.setattr(provider_ops.os, "rename", racing_rename)

    if writer_name == "json":
        _atomic_json(target, {"complete": False})
    else:
        provider_ops._write_jsonl(target, [{"canonical_id": "id"}])

    assert target.is_symlink()
    assert victim.stat().st_mode & 0o777 == original_mode


def test_provider_append_journal_does_not_chmod_replaced_symlink_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from components import provider_ops

    account_dir = tmp_path / "source@example.com"
    account_dir.mkdir()
    account = MigrationAccount(source_email="source@example.com", target_email="target@example.com")
    journal = account_dir / "import-target@example.com.journal.jsonl"
    victim = tmp_path / "victim.journal.jsonl"
    victim.write_text("outside\n", encoding="utf-8")
    victim.chmod(0o644)
    original_mode = victim.stat().st_mode & 0o777
    real_fdopen = provider_ops.os.fdopen

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

    monkeypatch.setattr(provider_ops.os, "fdopen", racing_fdopen)

    provider_ops.append_journal(account_dir, account, {"status": "pending", "canonical_id": "id"})

    assert journal.is_symlink()
    assert victim.stat().st_mode & 0o777 == original_mode


@pytest.mark.parametrize("rel_path", ["messages/gmail-123.eml", "metadata/gmail-123.json"])
def test_provider_validation_rejects_hard_linked_message_artifacts(tmp_path: Path, rel_path: str) -> None:
    from verify_export import verify_account

    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    artifact = account_dir / rel_path
    victim = tmp_path / f"victim-{artifact.name}"
    victim.write_bytes(artifact.read_bytes())
    artifact.unlink()
    try:
        os.link(victim, artifact)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"hard link creation unavailable: {exc}")

    _name, audit_issues = provider_audit_account(config, account, tmp_path)
    _name, report = provider_validate_account(config, account, tmp_path, check_target=False)
    stats = verify_account(account_dir)

    assert any("hard-linked provider file" in issue for issue in audit_issues)
    assert any("hard-linked provider file" in issue for issue in report["failed"])
    assert stats["errors"] >= 1

    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
        with pytest.raises(RuntimeError, match="hard-linked provider file"):
            provider_import_account(config, account, tmp_path)


@pytest.mark.parametrize("rel_path", ["messages/gmail-123.eml", "metadata/gmail-123.json"])
def test_provider_validation_rejects_non_regular_message_artifacts(tmp_path: Path, rel_path: str) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO creation unavailable")
    from verify_export import verify_account

    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    artifact = account_dir / rel_path
    artifact.unlink()
    try:
        os.mkfifo(artifact)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"FIFO creation unavailable: {exc}")

    _name, audit_issues = provider_audit_account(config, account, tmp_path)
    _name, report = provider_validate_account(config, account, tmp_path, check_target=False)
    stats = verify_account(account_dir)

    assert any("non-regular provider file" in issue for issue in audit_issues)
    assert any("non-regular provider file" in issue for issue in report["failed"])
    assert stats["errors"] >= 1

    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
        with pytest.raises(RuntimeError, match="non-regular provider file"):
            provider_import_account(config, account, tmp_path)


@pytest.mark.parametrize(
    ("rel_path", "needle"),
    [
        ("messages/broken-orphan.eml", "symlinked provider message artifact"),
        ("metadata/broken-orphan.json", "symlinked provider metadata artifact"),
    ],
)
def test_provider_validation_reports_broken_orphan_symlink_artifacts(
    tmp_path: Path,
    rel_path: str,
    needle: str,
) -> None:
    from verify_export import verify_account

    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    symlink_path = account_dir / rel_path
    try:
        symlink_path.symlink_to(tmp_path / "missing-artifact")
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    _name, audit_issues = provider_audit_account(config, account, tmp_path)
    _name, report = provider_validate_account(config, account, tmp_path, check_target=False)
    stats = verify_account(account_dir)

    assert any(needle in issue for issue in audit_issues)
    assert any(needle in issue for issue in report["failed"])
    assert stats["errors"] >= 1

    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
        with pytest.raises(RuntimeError, match=needle):
            provider_import_account(config, account, tmp_path)


@pytest.mark.parametrize(
    ("root_name", "needle"),
    [
        ("messages", "symlinked provider message artifact directory"),
        ("metadata", "symlinked provider metadata artifact directory"),
    ],
)
def test_provider_validation_reports_broken_artifact_root_symlinks(
    tmp_path: Path,
    root_name: str,
    needle: str,
) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="imap-secret"),
        ),
        target=ProviderEndpoint(
            provider="icloud",
            host="imap.mail.me.com",
            auth=AuthConfig(method="app_password", username="target@icloud.com", password="secret"),
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@icloud.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = tmp_path / account.source_email
    account_dir.mkdir()
    (account_dir / "manifest.jsonl").write_text("")
    _write_provider_export_state(account_dir, source=account.source_email, target=account.target_email, canonical_messages=0)
    symlink_path = account_dir / root_name
    try:
        symlink_path.symlink_to(tmp_path / "missing-artifact-root", target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")
    assert symlink_path.is_symlink()
    assert not symlink_path.exists()

    _name, audit_issues = provider_audit_account(config, account, tmp_path)
    _name, report = provider_validate_account(config, account, tmp_path, check_target=False)

    assert any(needle in issue for issue in audit_issues)
    assert any(needle in issue for issue in report["failed"])

    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
        with pytest.raises(RuntimeError, match=needle):
            provider_import_account(config, account, tmp_path)


def test_provider_read_paths_reject_symlinked_account_dir(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    outside_root = tmp_path / "outside"
    outside_account_dir = _write_manifest_fixture(outside_root)
    account_dir = tmp_path / "source@example.com"
    try:
        account_dir.symlink_to(outside_account_dir, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    _name, audit_issues = provider_audit_account(config, account, tmp_path)
    _name, report = provider_validate_account(config, account, tmp_path)

    assert any("symlinked provider account directory" in issue for issue in audit_issues)
    assert any("symlinked provider account directory" in issue for issue in report["failed"])

    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
        with pytest.raises(RuntimeError, match="symlinked provider account directory"):
            provider_import_account(config, account, tmp_path)


def test_provider_export_rejects_symlinked_output_root_before_source_contact(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    outside_root = tmp_path / "outside"
    outside_root.mkdir()
    out_root = tmp_path / "exported"
    try:
        out_root.symlink_to(outside_root, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("source should not be contacted")):
        with pytest.raises(RuntimeError, match="symlinked provider export root"):
            provider_export_account(config, account, out_root)
        with pytest.raises(RuntimeError, match="symlinked provider export root"):
            provider_export_all(config, out_root, max_workers=1, ignore_errors=False)

    assert not (outside_root / account.source_email).exists()


def test_provider_import_rejects_symlinked_input_root_before_target_contact(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    outside_root = tmp_path / "outside"
    _write_manifest_fixture(outside_root)
    in_root = tmp_path / "exported"
    try:
        in_root.symlink_to(outside_root, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
        with pytest.raises(RuntimeError, match="symlinked provider import root"):
            provider_import_account(config, account, in_root)
        with pytest.raises(RuntimeError, match="symlinked provider import root"):
            provider_import_all(config, in_root, max_workers=1, ignore_errors=False)


def test_provider_retry_stops_during_backoff_wait() -> None:
    from components.provider_ops import with_retry

    class StopDuringWait:
        def __init__(self) -> None:
            self.stopped = False
            self.delays: List[float] = []

        def is_set(self) -> bool:
            return self.stopped

        def wait(self, delay: float) -> bool:
            self.delays.append(delay)
            self.stopped = True
            return True

    stop = StopDuringWait()
    calls = 0

    def flaky() -> None:
        nonlocal calls
        calls += 1
        raise imaplib.IMAP4.abort("temporary disconnect")

    with pytest.raises(RuntimeError, match="stop requested before retry"):
        with_retry(flaky, attempts=2, label="provider export source@example.com", stop_event=stop)

    assert calls == 1
    assert stop.delays == [1.0]


def test_provider_export_all_stops_retry_when_stop_event_is_set(tmp_path: Path) -> None:
    config = _provider_config()
    stop = mock.Mock()
    stop.is_set.return_value = False
    calls = 0

    def fake_export(*_args, **_kwargs) -> None:
        nonlocal calls
        calls += 1
        stop.is_set.return_value = True
        raise imaplib.IMAP4.abort("temporary disconnect")

    with mock.patch("components.provider_ops.provider_export_account", fake_export):
        with pytest.raises(RuntimeError, match="stop requested"):
            provider_export_all(config, tmp_path, max_workers=1, ignore_errors=False, stop_event=stop)

    assert calls == 1


def test_provider_import_all_stops_retry_when_stop_event_is_set(tmp_path: Path) -> None:
    config = _provider_config()
    stop = mock.Mock()
    stop.is_set.return_value = False
    calls = 0

    def fake_import(*_args, **_kwargs) -> None:
        nonlocal calls
        calls += 1
        stop.is_set.return_value = True
        raise imaplib.IMAP4.abort("temporary disconnect")

    with mock.patch("components.provider_ops.provider_import_account", fake_import):
        with pytest.raises(RuntimeError, match="stop requested"):
            provider_import_all(config, tmp_path, max_workers=1, ignore_errors=False, stop_event=stop)

    assert calls == 1


def test_provider_audit_and_validate_reject_symlinked_input_root(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    outside_root = tmp_path / "outside"
    _write_manifest_fixture(outside_root)
    in_root = tmp_path / "exported"
    try:
        in_root.symlink_to(outside_root, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    _name, audit_issues = provider_audit_account(config, account, in_root)
    audit_ok, audit_all_issues = provider_audit_all(config, in_root, max_workers=1)
    _name, report = provider_validate_account(config, account, in_root, check_target=True)
    validate_ok, validate_all_issues = provider_validate_all(config, in_root, max_workers=1)

    assert any("symlinked provider audit root" in issue for issue in audit_issues)
    assert not audit_ok
    assert any("symlinked provider audit root" in issue for issue in audit_all_issues)
    assert any("symlinked provider validate root" in issue for issue in report["failed"])
    assert not validate_ok
    assert any("symlinked provider validate root" in issue for issue in validate_all_issues)


def test_provider_rejects_symlinked_input_root_ancestor_before_target_contact(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    outside_root = tmp_path / "outside"
    staged_root = outside_root / "staged"
    _write_manifest_fixture(staged_root)
    link_root = tmp_path / "link"
    try:
        link_root.symlink_to(outside_root, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")
    in_root = link_root / "staged"
    assert not in_root.is_symlink()

    audit_ok, audit_issues = provider_audit_all(config, in_root, max_workers=1)
    _name, report = provider_validate_account(config, account, in_root, check_target=True)
    validate_ok, validate_issues = provider_validate_all(config, in_root, max_workers=1)

    assert not audit_ok
    assert any("symlinked provider audit root" in issue for issue in audit_issues)
    assert any("symlinked provider validate root" in issue for issue in report["failed"])
    assert not validate_ok
    assert any("symlinked provider validate root" in issue for issue in validate_issues)
    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
        with pytest.raises(RuntimeError, match="symlinked provider import root"):
            provider_import_account(config, account, in_root)


@pytest.mark.parametrize(
    ("artifact_name", "needle"),
    [
        ("manifest.jsonl", "manifest load failed|symlinked provider file"),
        ("export-state.json", "export-state"),
        ("import-target@icloud.com.journal.jsonl", "import journal load failed|symlinked provider file"),
    ],
)
def test_provider_read_paths_reject_symlinked_control_artifacts(
    tmp_path: Path,
    artifact_name: str,
    needle: str,
) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    artifact = account_dir / artifact_name
    if artifact_name.startswith("import-"):
        artifact.write_text(json.dumps(_journal_fixture(config, {
            "canonical_id": "gmail-123",
            "target_account": "target@icloud.com",
            "target_mailbox": "Archive",
            "status": "committed",
        })) + "\n")
    outside = tmp_path / f"outside-{artifact_name.replace('/', '_')}"
    outside.write_text(artifact.read_text(encoding="utf-8"), encoding="utf-8")
    artifact.unlink()
    try:
        artifact.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    _name, audit_issues = provider_audit_account(config, account, tmp_path)
    _name, report = provider_validate_account(config, account, tmp_path)

    assert any(re.search(needle, issue) for issue in audit_issues)
    assert any(re.search(needle, issue) for issue in report["failed"])

    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
        with pytest.raises(RuntimeError, match="symlinked provider file|export-state"):
            provider_import_account(config, account, tmp_path)


def test_provider_prune_rejects_symlinked_artifact_root(tmp_path: Path) -> None:
    account_dir = tmp_path / "source@example.com"
    outside = tmp_path / "outside-messages"
    account_dir.mkdir()
    outside.mkdir()
    stale = outside / "stale.eml"
    stale.write_bytes(b"do not delete")
    try:
        (account_dir / "messages").symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(RuntimeError, match="symlinked provider artifact directory"):
        _prune_provider_artifact_orphans(account_dir, [])

    assert stale.exists()


def test_provider_prune_rejects_artifact_root_swap_before_unlink(tmp_path: Path) -> None:
    account_dir = tmp_path / "source@example.com"
    messages = account_dir / "messages"
    messages.mkdir(parents=True)
    stale = messages / "stale.eml"
    stale.write_bytes(b"stale")
    outside = tmp_path / "outside-messages"
    outside.mkdir()
    outside_stale = outside / "stale.eml"
    outside_stale.write_bytes(b"do not delete")
    checked_messages = tmp_path / "checked-messages"
    real_listdir = os.listdir
    swapped = False

    def racing_listdir(fd):
        nonlocal swapped
        names = real_listdir(fd)
        if not swapped:
            messages.rename(checked_messages)
            try:
                messages.symlink_to(outside, target_is_directory=True)
            except OSError as exc:
                pytest.skip(f"symlink creation unavailable: {exc}")
            swapped = True
        return names

    with mock.patch("components.provider_ops.os.listdir", racing_listdir):
        with pytest.raises(RuntimeError, match="replaced provider artifact directory"):
            _prune_provider_artifact_orphans(account_dir, [])

    assert swapped
    assert messages.is_symlink()
    assert outside_stale.exists()
    assert (checked_messages / "stale.eml").exists()


def test_provider_prune_rejects_non_regular_orphan_artifact(tmp_path: Path) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO creation unavailable")
    account_dir = tmp_path / "source@example.com"
    messages = account_dir / "messages"
    messages.mkdir(parents=True)
    stale = messages / "stale.eml"
    try:
        os.mkfifo(stale)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"FIFO creation unavailable: {exc}")

    with pytest.raises(RuntimeError, match="non-regular provider artifact"):
        _prune_provider_artifact_orphans(account_dir, [])

    assert stale.exists()


def _many_to_one_config(*, target_mode: str = "empty") -> ProviderMigrationConfig:
    return ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.source.example.com",
            auth=AuthConfig(method="password"),
        ),
        target=ProviderEndpoint(
            provider="imap",
            host="mail.target.example.com",
            auth=AuthConfig(method="password", username="merged@example.com", password="target-secret"),
        ),
        accounts=[
            MigrationAccount(
                source_email="a@example.com",
                target_email="merged@example.com",
                source_auth=AuthConfig(method="password", username="a@example.com", password="source-a"),
            ),
            MigrationAccount(
                source_email="b@example.com",
                target_email="merged@example.com",
                source_auth=AuthConfig(method="password", username="b@example.com", password="source-b"),
            ),
        ],
        migration=MigrationSettings(target_mode=target_mode, account_merge_mode="many_to_one"),
    )


def _many_to_one_gmail_config(*, target_mode: str = "empty") -> ProviderMigrationConfig:
    return ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.source.example.com",
            auth=AuthConfig(method="password"),
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="merged@gmail.com", password="target-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[
            MigrationAccount(
                source_email="a@example.com",
                target_email="merged@gmail.com",
                source_auth=AuthConfig(method="password", username="a@example.com", password="source-a"),
            ),
            MigrationAccount(
                source_email="b@example.com",
                target_email="merged@gmail.com",
                source_auth=AuthConfig(method="password", username="b@example.com", password="source-b"),
            ),
        ],
        migration=MigrationSettings(target_mode=target_mode, account_merge_mode="many_to_one"),
    )


def _hybrid_many_to_one_config(*, target_mode: str = "empty") -> ProviderMigrationConfig:
    return ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.source.example.com",
            auth=AuthConfig(method="password"),
        ),
        target=ProviderEndpoint(
            provider="imap",
            host="mail.target.example.com",
            auth=AuthConfig(method="password"),
        ),
        accounts=[
            MigrationAccount(
                source_email="a@example.com",
                target_email="a@example.com",
                source_auth=AuthConfig(method="password", username="a@example.com", password="source-a"),
                target_auth=AuthConfig(method="password", username="a@example.com", password="target-a"),
            ),
            MigrationAccount(
                source_email="b@example.com",
                target_email="a@example.com",
                source_auth=AuthConfig(method="password", username="b@example.com", password="source-b"),
                target_auth=AuthConfig(method="password", username="a@example.com", password="target-a"),
            ),
            MigrationAccount(
                source_email="c@example.com",
                target_email="a@example.com",
                source_auth=AuthConfig(method="password", username="c@example.com", password="source-c"),
                target_auth=AuthConfig(method="password", username="a@example.com", password="target-a"),
            ),
            MigrationAccount(
                source_email="d@example.com",
                target_email="d@example.com",
                source_auth=AuthConfig(method="password", username="d@example.com", password="source-d"),
                target_auth=AuthConfig(method="password", username="d@example.com", password="target-d"),
            ),
            MigrationAccount(
                source_email="e@example.com",
                target_email="e@example.com",
                source_auth=AuthConfig(method="password", username="e@example.com", password="source-e"),
                target_auth=AuthConfig(method="password", username="e@example.com", password="target-e"),
            ),
        ],
        migration=MigrationSettings(target_mode=target_mode, account_merge_mode="many_to_one"),
    )


def test_provider_config_parse_and_legacy_detection(tmp_path: Path) -> None:
    provider_path = tmp_path / "provider.json"
    provider_path.write_text(json.dumps({
        "source": {
            "provider": "gmail",
            "host": "imap.gmail.com",
            "auth": {"method": "xoauth2", "username": "source@example.com", "token_file": "token.txt"},
        },
        "target": {
            "provider": "icloud",
            "host": "imap.mail.me.com",
            "auth": {"method": "app_password", "username": "target", "password_file": "icloud.txt"},
        },
        "accounts": [{"source_email": "source@example.com", "target_email": "target@icloud.com"}],
    }))
    parsed = load_config_file(provider_path)
    assert isinstance(parsed, ProviderMigrationConfig)
    assert parsed.source.provider == "gmail"
    assert parsed.target.auth.method == "app_password"
    assert parsed.source.auth.token_file == str(tmp_path / "token.txt")
    assert parsed.target.auth.password_file == str(tmp_path / "icloud.txt")

    bad_path = tmp_path / "bad.json"
    bad_path.write_text(json.dumps({"source": {"provider": "gmail"}, "accounts": []}))
    with pytest.raises(ValueError):
        load_config_file(bad_path)

    wrong_provider = tmp_path / "wrong-provider.json"
    wrong_provider.write_text(json.dumps({
        "source": {"provider": "exchange", "host": "example.com", "auth": {"method": "password", "password": "x"}},
        "target": {"provider": "icloud", "host": "imap.mail.me.com", "auth": {"method": "app_password", "password": "x"}},
        "accounts": [{"source_email": "source@example.com", "target_email": "target@icloud.com"}],
    }))
    with pytest.raises(ValueError, match="source.provider"):
        load_config_file(wrong_provider)

    bad_auth = tmp_path / "bad-auth.json"
    bad_auth.write_text(json.dumps({
        "source": {"provider": "gmail", "host": "imap.gmail.com", "auth": {"method": "xoauth2", "password_file": "bad"}},
        "target": {"provider": "icloud", "host": "imap.mail.me.com", "auth": {"method": "app_password", "password": "x"}},
        "accounts": [{"source_email": "source@example.com", "target_email": "target@icloud.com"}],
    }))
    with pytest.raises(ValueError, match="password_file"):
        load_config_file(bad_auth)

    insecure = tmp_path / "insecure.json"
    insecure.write_text(json.dumps({
        "source": {"provider": "gmail", "host": "imap.gmail.com", "ssl": False, "auth": {"method": "xoauth2", "password": "x"}},
        "target": {"provider": "icloud", "host": "imap.mail.me.com", "auth": {"method": "app_password", "password": "x"}},
        "accounts": [{"source_email": "source@example.com", "target_email": "target@icloud.com"}],
    }))
    with pytest.raises(ValueError, match="source.ssl"):
        load_config_file(insecure)

    wrong_host = tmp_path / "wrong-host.json"
    wrong_host.write_text(json.dumps({
        "source": {"provider": "gmail", "host": "mail.example.com", "auth": {"method": "xoauth2", "password": "x"}},
        "target": {"provider": "icloud", "host": "imap.mail.me.com", "auth": {"method": "app_password", "password": "x"}},
        "accounts": [{"source_email": "source@example.com", "target_email": "target@icloud.com"}],
    }))
    with pytest.raises(ValueError, match="source.host"):
        load_config_file(wrong_host)

    imap_gmail_host = tmp_path / "imap-gmail-host.json"
    imap_gmail_host.write_text(json.dumps({
        "source": {"provider": "imap", "host": "imap.gmail.com", "auth": {"method": "password", "password": "x"}},
        "target": {"provider": "icloud", "host": "imap.mail.me.com", "auth": {"method": "app_password", "password": "x"}},
        "accounts": [{"source_email": "source@example.com", "target_email": "target@icloud.com"}],
    }))
    with pytest.raises(ValueError, match="known gmail IMAP host"):
        load_config_file(imap_gmail_host)

    imap_gmail_host_trailing_dot = tmp_path / "imap-gmail-host-trailing-dot.json"
    imap_gmail_host_trailing_dot.write_text(json.dumps({
        "source": {"provider": "imap", "host": "IMAP.GMAIL.COM.", "auth": {"method": "password", "password": "x"}},
        "target": {"provider": "icloud", "host": "imap.mail.me.com", "auth": {"method": "app_password", "password": "x"}},
        "accounts": [{"source_email": "source@example.com", "target_email": "target@icloud.com"}],
    }))
    with pytest.raises(ValueError, match="known gmail IMAP host"):
        load_config_file(imap_gmail_host_trailing_dot)

    imap_icloud_host = tmp_path / "imap-icloud-host.json"
    imap_icloud_host.write_text(json.dumps({
        "source": {"provider": "imap", "host": "mail.example.com", "auth": {"method": "password", "password": "x"}},
        "target": {"provider": "imap", "host": "imap.mail.me.com", "auth": {"method": "password", "password": "x"}},
        "accounts": [{"source_email": "source@example.com", "target_email": "target@example.com"}],
    }))
    with pytest.raises(ValueError, match="known icloud IMAP host"):
        load_config_file(imap_icloud_host)

    canonical_gmail_host = tmp_path / "canonical-gmail-host.json"
    canonical_gmail_host.write_text(json.dumps({
        "source": {"provider": "gmail", "host": "IMAP.GMAIL.COM.", "auth": {"method": "xoauth2", "password": "x"}},
        "target": {"provider": "icloud", "host": "imap.mail.me.com", "auth": {"method": "app_password", "password": "x"}},
        "accounts": [{"source_email": "source@example.com", "target_email": "target@icloud.com"}],
    }))
    parsed_canonical = load_config_file(canonical_gmail_host)
    assert isinstance(parsed_canonical, ProviderMigrationConfig)
    assert parsed_canonical.source.host == "imap.gmail.com"

    legacy_gmail_host = tmp_path / "legacy-gmail-host.json"
    legacy_gmail_host.write_text(json.dumps({
        "server": {"host": "imap.gmail.com", "port": 993, "ssl": True},
        "accounts": [{"email": "user@gmail.com", "password": "x"}],
    }))
    with pytest.raises(ValueError, match="known gmail IMAP host"):
        load_config_file(legacy_gmail_host)

    legacy_icloud_host = tmp_path / "legacy-icloud-host.json"
    legacy_icloud_host.write_text(json.dumps({
        "server": {"host": "IMAP.MAIL.ME.COM.", "port": 993, "ssl": True},
        "accounts": [{"email": "user@icloud.com", "password": "x"}],
    }))
    with pytest.raises(ValueError, match="known icloud IMAP host"):
        load_config_file(legacy_icloud_host)

    wrong_gmail_user = tmp_path / "wrong-gmail-user.json"
    wrong_gmail_user.write_text(json.dumps({
        "source": {"provider": "gmail", "host": "imap.gmail.com", "auth": {"method": "xoauth2", "username": "other@example.com", "password": "x"}},
        "target": {"provider": "icloud", "host": "imap.mail.me.com", "auth": {"method": "app_password", "password": "x"}},
        "accounts": [{"source_email": "source@example.com", "target_email": "target@icloud.com"}],
    }))
    with pytest.raises(ValueError, match="username must match source_email"):
        load_config_file(wrong_gmail_user)

    wrong_source_icloud_user = tmp_path / "wrong-source-icloud-user.json"
    wrong_source_icloud_user.write_text(json.dumps({
        "source": {"provider": "icloud", "host": "imap.mail.me.com", "auth": {"method": "app_password", "username": "other", "password": "x"}},
        "target": {"provider": "imap", "host": "mail.example.com", "auth": {"method": "password", "password": "x"}},
        "accounts": [{"source_email": "source@icloud.com", "target_email": "target@example.com"}],
    }))
    with pytest.raises(ValueError, match="username must match source_email"):
        load_config_file(wrong_source_icloud_user)

    wrong_target_icloud_user = tmp_path / "wrong-target-icloud-user.json"
    wrong_target_icloud_user.write_text(json.dumps({
        "source": {"provider": "imap", "host": "mail.example.com", "auth": {"method": "password", "password": "x"}},
        "target": {"provider": "icloud", "host": "imap.mail.me.com", "auth": {"method": "app_password", "username": "wrongtarget", "password": "x"}},
        "accounts": [{"source_email": "source@example.com", "target_email": "target@icloud.com"}],
    }))
    with pytest.raises(ValueError, match="username must match target_email"):
        load_config_file(wrong_target_icloud_user)

    icloud_username_aliases = tmp_path / "icloud-username-aliases.json"
    icloud_username_aliases.write_text(json.dumps({
        "source": {"provider": "icloud", "host": "imap.mail.me.com", "auth": {"method": "app_password", "username": "source", "password": "x"}},
        "target": {"provider": "icloud", "host": "imap.mail.me.com", "auth": {"method": "app_password", "username": "target@me.com", "password": "x"}},
        "accounts": [{"source_email": "source@icloud.com", "target_email": "target@icloud.com"}],
    }))
    parsed_aliases = load_config_file(icloud_username_aliases)
    assert isinstance(parsed_aliases, ProviderMigrationConfig)

    icloud_xoauth = tmp_path / "icloud-xoauth.json"
    icloud_xoauth.write_text(json.dumps({
        "source": {"provider": "gmail", "host": "imap.gmail.com", "auth": {"method": "xoauth2", "password": "x"}},
        "target": {"provider": "icloud", "host": "imap.mail.me.com", "auth": {"method": "xoauth2", "password": "x"}},
        "accounts": [{"source_email": "source@example.com", "target_email": "target@icloud.com"}],
    }))
    with pytest.raises(ValueError, match="target.auth.method"):
        load_config_file(icloud_xoauth)

    misplaced_visibility = tmp_path / "misplaced-gmail-visibility.json"
    misplaced_visibility.write_text(json.dumps({
        "source": {
            "provider": "imap",
            "host": "mail.example.com",
            "gmail_full_visibility_verified": True,
            "auth": {"method": "password", "password": "x"},
        },
        "target": {"provider": "icloud", "host": "imap.mail.me.com", "auth": {"method": "app_password", "password": "x"}},
        "accounts": [{"source_email": "source@example.com", "target_email": "target@icloud.com"}],
    }))
    with pytest.raises(ValueError, match="gmail_full_visibility_verified"):
        load_config_file(misplaced_visibility)

    shared_secret = tmp_path / "shared-secret.json"
    shared_secret.write_text(json.dumps({
        "source": {"provider": "gmail", "host": "imap.gmail.com", "auth": {"method": "xoauth2", "password": "same-token"}},
        "target": {"provider": "icloud", "host": "imap.mail.me.com", "auth": {"method": "app_password", "password": "same-pass"}},
        "accounts": [
            {"source_email": "a@gmail.com", "target_email": "a@icloud.com"},
            {"source_email": "b@gmail.com", "target_email": "b@icloud.com"},
        ],
    }))
    with pytest.raises(ValueError, match="multi-account"):
        load_config_file(shared_secret)

    multi_gmail_visibility = tmp_path / "multi-gmail-visibility.json"
    multi_gmail_visibility.write_text(json.dumps({
        "source": {
            "provider": "gmail",
            "host": "imap.gmail.com",
            "auth": {"method": "xoauth2"},
        },
        "target": {
            "provider": "icloud",
            "host": "imap.mail.me.com",
            "auth": {"method": "app_password"},
        },
        "accounts": [
            {
                "source_email": "a@gmail.com",
                "target_email": "a@icloud.com",
                "source_auth": {"method": "xoauth2", "username": "a@gmail.com", "password": "token-a"},
                "target_auth": {"method": "app_password", "username": "a@icloud.com", "password": "secret-a"},
            },
            {
                "source_email": "b@gmail.com",
                "target_email": "b@icloud.com",
                "source_auth": {"method": "xoauth2", "username": "b@gmail.com", "password": "token-b"},
                "target_auth": {"method": "app_password", "username": "b@icloud.com", "password": "secret-b"},
            },
        ],
    }))
    with pytest.raises(ValueError, match=r"accounts\[0\]\.gmail_full_visibility_verified"):
        load_config_file(multi_gmail_visibility)

    attested_multi = json.loads(multi_gmail_visibility.read_text())
    for account in attested_multi["accounts"]:
        account["gmail_full_visibility_verified"] = True
    multi_gmail_visibility.write_text(json.dumps(attested_multi))
    assert isinstance(load_config_file(multi_gmail_visibility), ProviderMigrationConfig)

    multi_gmail_target_visibility = tmp_path / "multi-gmail-target-visibility.json"
    multi_gmail_target_visibility.write_text(json.dumps({
        "source": {
            "provider": "imap",
            "host": "mail.example.com",
            "auth": {"method": "password"},
        },
        "target": {
            "provider": "gmail",
            "host": "imap.gmail.com",
            "gmail_full_visibility_verified": True,
            "auth": {"method": "xoauth2"},
        },
        "accounts": [
            {
                "source_email": "a@example.com",
                "target_email": "a@gmail.com",
                "source_auth": {"method": "password", "username": "a@example.com", "password": "source-a"},
                "target_auth": {"method": "xoauth2", "username": "a@gmail.com", "password": "token-a"},
            },
            {
                "source_email": "b@example.com",
                "target_email": "b@gmail.com",
                "source_auth": {"method": "password", "username": "b@example.com", "password": "source-b"},
                "target_auth": {"method": "xoauth2", "username": "b@gmail.com", "password": "token-b"},
            },
        ],
    }))
    with pytest.raises(ValueError, match=r"accounts\[0\]\.target_gmail_full_visibility_verified"):
        load_config_file(multi_gmail_target_visibility)

    attested_target_multi = json.loads(multi_gmail_target_visibility.read_text())
    for account in attested_target_multi["accounts"]:
        account["target_gmail_full_visibility_verified"] = True
    multi_gmail_target_visibility.write_text(json.dumps(attested_target_multi))
    assert isinstance(load_config_file(multi_gmail_target_visibility), ProviderMigrationConfig)

    duplicate_source = tmp_path / "duplicate-source.json"
    duplicate_source.write_text(json.dumps({
        "source": {"provider": "gmail", "host": "imap.gmail.com", "auth": {"method": "xoauth2"}},
        "target": {"provider": "icloud", "host": "imap.mail.me.com", "auth": {"method": "app_password"}},
        "accounts": [
            {
                "source_email": "same@gmail.com",
                "target_email": "a@icloud.com",
                "source_auth": {"method": "xoauth2", "password": "token-a"},
                "target_auth": {"method": "app_password", "password": "secret-a"},
            },
            {
                "source_email": "same@gmail.com",
                "target_email": "b@icloud.com",
                "source_auth": {"method": "xoauth2", "password": "token-b"},
                "target_auth": {"method": "app_password", "password": "secret-b"},
            },
        ],
    }))
    with pytest.raises(ValueError, match="source_email duplicates"):
        load_config_file(duplicate_source)

    invalid_source_override = tmp_path / "invalid-source-override.json"
    invalid_source_override.write_text(json.dumps({
        "source": {"provider": "gmail", "host": "imap.gmail.com", "auth": {"method": "xoauth2"}},
        "target": {"provider": "icloud", "host": "imap.mail.me.com", "auth": {"method": "app_password"}},
        "accounts": [{
            "source_email": "source@example.com",
            "target_email": "target@icloud.com",
            "source_auth": {"method": "password", "password": "plain-password"},
            "target_auth": {"method": "app_password", "password": "icloud-secret"},
        }],
    }))
    with pytest.raises(ValueError, match=r"accounts\[0\]\.source_auth\.method"):
        load_config_file(invalid_source_override)

    invalid_target_override = tmp_path / "invalid-target-override.json"
    invalid_target_override.write_text(json.dumps({
        "source": {"provider": "gmail", "host": "imap.gmail.com", "auth": {"method": "xoauth2"}},
        "target": {"provider": "icloud", "host": "imap.mail.me.com", "auth": {"method": "app_password"}},
        "accounts": [{
            "source_email": "source@example.com",
            "target_email": "target@icloud.com",
            "source_auth": {"method": "xoauth2", "password": "token"},
            "target_auth": {"method": "xoauth2", "password": "token"},
        }],
    }))
    with pytest.raises(ValueError, match=r"accounts\[0\]\.target_auth\.method"):
        load_config_file(invalid_target_override)


@pytest.mark.parametrize(
    "folder_map",
    [
        {"Projects": None},
        {"Projects": 123},
        {"Projects": ""},
        {"": "Archive"},
    ],
)
def test_provider_config_rejects_invalid_folder_map_entries(tmp_path: Path, folder_map: dict) -> None:
    path = tmp_path / "invalid-folder-map.json"
    path.write_text(json.dumps({
        "source": {
            "provider": "gmail",
            "host": "imap.gmail.com",
            "auth": {"method": "xoauth2", "username": "source@example.com", "password": "token"},
        },
        "target": {
            "provider": "icloud",
            "host": "imap.mail.me.com",
            "auth": {"method": "app_password", "username": "target", "password": "secret"},
        },
        "accounts": [{"source_email": "source@example.com", "target_email": "target@icloud.com"}],
        "migration": {"folder_map": folder_map},
    }))

    with pytest.raises(ValueError, match="migration\\.folder_map"):
        load_config_file(path)


def test_migration_settings_rejects_non_string_folder_map_keys() -> None:
    with pytest.raises(ValueError, match="migration\\.folder_map keys"):
        MigrationSettings.from_dict({"folder_map": {1: "Archive"}})


def test_readme_minimal_provider_config_does_not_preverify_gmail_visibility() -> None:
    readme = Path("README.md").read_text(encoding="utf-8")
    marker = "Minimal provider config:"
    start = readme.index(marker)
    code_start = readme.index("```json", start) + len("```json")
    code_end = readme.index("```", code_start)
    sample = json.loads(readme[code_start:code_end])

    assert sample["source"]["gmail_full_visibility_verified"] is False


def test_readme_hybrid_many_to_one_example_parses(tmp_path: Path) -> None:
    readme = Path("README.md").read_text(encoding="utf-8")
    marker = "Hybrid merge example:"
    start = readme.index(marker)
    code_start = readme.index("```json", start) + len("```json")
    code_end = readme.index("```", code_start)
    sample = json.loads(readme[code_start:code_end])
    path = tmp_path / "hybrid-many-to-one.json"
    path.write_text(json.dumps(sample))

    parsed = load_config_file(path)

    assert isinstance(parsed, ProviderMigrationConfig)
    assert parsed.migration.account_merge_mode == "many_to_one"
    assert [account.target_email for account in parsed.accounts] == [
        "a@example.com",
        "a@example.com",
        "a@example.com",
        "d@example.com",
        "e@example.com",
    ]
    merge_key = target_merge_group_key(parsed, parsed.accounts[0])
    assert target_merge_group_key(parsed, parsed.accounts[1]) == merge_key
    assert target_merge_group_key(parsed, parsed.accounts[2]) == merge_key
    assert target_merge_group_key(parsed, parsed.accounts[3]) != merge_key
    assert target_merge_group_key(parsed, parsed.accounts[4]) != merge_key
    assert target_merge_group_key(parsed, parsed.accounts[3]) != target_merge_group_key(parsed, parsed.accounts[4])


def test_provider_config_supports_requested_imap_routes(tmp_path: Path) -> None:
    cases = {
        "icloud-to-imap": {
            "source": {"provider": "icloud", "host": "imap.mail.me.com", "auth": {"method": "app_password", "password": "icloud-secret"}},
            "target": {"provider": "imap", "host": "mail.example.com", "auth": {"method": "password", "password": "imap-secret"}},
            "accounts": [{"source_email": "user@icloud.com", "target_email": "user@example.com"}],
        },
        "gmail-to-imap": {
            "source": {"provider": "gmail", "host": "imap.gmail.com", "auth": {"method": "xoauth2", "password": "gmail-token"}},
            "target": {"provider": "imap", "host": "mail.example.com", "auth": {"method": "password", "password": "imap-secret"}},
            "accounts": [{"source_email": "user@gmail.com", "target_email": "user@example.com"}],
        },
        "imap-to-gmail": {
            "source": {"provider": "imap", "host": "mail.example.com", "auth": {"method": "password", "password": "imap-secret"}},
            "target": {"provider": "gmail", "host": "imap.gmail.com", "auth": {"method": "xoauth2", "password": "gmail-token"}},
            "accounts": [{"source_email": "user@example.com", "target_email": "user@gmail.com"}],
        },
        "imap-to-icloud": {
            "source": {"provider": "imap", "host": "mail.example.com", "ssl": False, "starttls": True, "auth": {"method": "password", "username": "imap-login", "password": "imap-secret"}},
            "target": {"provider": "icloud", "host": "imap.mail.me.com", "auth": {"method": "app_password", "username": "user", "password": "icloud-secret"}},
            "accounts": [{"source_email": "user@example.com", "target_email": "user@icloud.com"}],
        },
    }
    for name, payload in cases.items():
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps(payload))

        parsed = load_config_file(path)

        assert isinstance(parsed, ProviderMigrationConfig)
        assert parsed.accounts[0].source_email == payload["accounts"][0]["source_email"]
        assert parsed.accounts[0].target_email == payload["accounts"][0]["target_email"]
        assert parsed.source.provider == payload["source"]["provider"]
        assert parsed.target.provider == payload["target"]["provider"]
        assert parsed.source.host == payload["source"]["host"]
        assert parsed.target.host == payload["target"]["host"]
        assert parsed.source.ssl == payload["source"].get("ssl", True)
        assert parsed.source.starttls == payload["source"].get("starttls", False)
        assert parsed.target.ssl == payload["target"].get("ssl", True)
        assert parsed.target.starttls == payload["target"].get("starttls", False)
        assert parsed.source.auth.method == payload["source"]["auth"]["method"]
        assert parsed.target.auth.method == payload["target"]["auth"]["method"]

    bad_imap_tls = tmp_path / "bad-imap-tls.json"
    bad_imap_tls.write_text(json.dumps({
        "source": {"provider": "icloud", "host": "imap.mail.me.com", "auth": {"method": "app_password", "password": "icloud-secret"}},
        "target": {"provider": "imap", "host": "mail.example.com", "ssl": True, "starttls": True, "auth": {"method": "password", "password": "imap-secret"}},
        "accounts": [{"source_email": "user@icloud.com", "target_email": "user@example.com"}],
    }))
    with pytest.raises(ValueError, match="target.ssl.*target.starttls"):
        load_config_file(bad_imap_tls)


def test_provider_config_accepts_full_gmail_icloud_imap_matrix(tmp_path: Path) -> None:
    endpoint_templates = {
        "gmail": {"provider": "gmail", "host": "imap.gmail.com", "auth": {"method": "xoauth2", "password": "gmail-token"}},
        "icloud": {"provider": "icloud", "host": "imap.mail.me.com", "auth": {"method": "app_password", "password": "icloud-secret"}},
        "imap": {"provider": "imap", "host": "mail.example.com", "auth": {"method": "password", "password": "imap-secret"}},
    }
    for source_name, source in endpoint_templates.items():
        for target_name, target in endpoint_templates.items():
            payload = {
                "source": source,
                "target": target,
                "accounts": [{
                    "source_email": f"user@{source_name}.example.com",
                    "target_email": f"user@{target_name}.example.com",
                }],
            }
            path = tmp_path / f"{source_name}-to-{target_name}.json"
            path.write_text(json.dumps(payload))

            parsed = load_config_file(path)

            assert isinstance(parsed, ProviderMigrationConfig)
            assert parsed.source.provider == source_name
            assert parsed.target.provider == target_name


@pytest.mark.parametrize("source_provider", ["gmail", "icloud", "imap"])
@pytest.mark.parametrize("target_provider", ["gmail", "icloud", "imap"])
def test_provider_export_import_operational_matrix(tmp_path: Path, source_provider: str, target_provider: str) -> None:
    def account_email(provider: str, *, role: str) -> str:
        if provider == "gmail":
            return f"{role}@gmail.com"
        if provider == "icloud":
            return f"{role}@icloud.com"
        return f"{role}@example.com"

    source_email = account_email(source_provider, role="source")
    target_email = account_email(target_provider, role="target")

    def endpoint_payload(provider: str, *, role: str, email: str) -> dict:
        if provider == "gmail":
            return {
                "provider": "gmail",
                "host": "imap.gmail.com",
                "auth": {"method": "xoauth2", "username": email, "password": "gmail-token"},
                "gmail_full_visibility_verified": True,
            }
        if provider == "icloud":
            return {
                "provider": "icloud",
                "host": "imap.mail.me.com",
                "auth": {"method": "app_password", "username": email, "password": "icloud-secret"},
            }
        return {
            "provider": "imap",
            "host": f"{role}.imap.example.com",
            "auth": {"method": "password", "username": email, "password": "imap-secret"},
        }

    class OneMessageImapSource(FakeIcloudInboxSourceImap):
        def uid(self, command: str, *args):
            if command == "search":
                return "OK", [b"1"]
            if command == "fetch":
                query = args[-1]
                body = b"Message-ID: <one@example.com>\r\nFrom: a@example.com\r\nTo: b@example.com\r\n\r\nbody"
                meta = b'1 (UID 1 RFC822.SIZE %d FLAGS (\\Seen) INTERNALDATE "01-Jan-2024 00:00:00 +0000")' % len(body)
                if "BODY.PEEK[]" not in query:
                    return "OK", [meta]
                return "OK", [(meta + b" BODY[] {%d}" % len(body), body)]
            raise AssertionError(command)

    account_payload = {"source_email": source_email, "target_email": target_email}
    if target_provider == "gmail":
        account_payload["target_gmail_full_visibility_verified"] = True
    config = ProviderMigrationConfig.from_dict({
        "source": endpoint_payload(source_provider, role="source", email=source_email),
        "target": endpoint_payload(target_provider, role="target", email=target_email),
        "accounts": [account_payload],
        "migration": {"target_mode": "empty"},
    })

    class StoredGmailMatrixTarget(StoredMessageTarget):
        def __init__(self) -> None:
            super().__init__()
            self.stored_labels: List[tuple[bytes, str, str]] = []

        def capability(self):
            return "OK", [b"IMAP4rev1 X-GM-EXT-1"]

        def list(self):
            return "OK", [
                b'(\\HasNoChildren) "/" "INBOX"',
                b'(\\HasNoChildren \\All) "/" "[Gmail]/All Mail"',
                b'(\\HasNoChildren \\Sent) "/" "[Gmail]/Sent Mail"',
            ]

        def fetch(self, num: bytes, query: str):
            if "X-GM-MSGID" in query:
                gmail_msgid = 9000 + int(num)
                return "OK", [f"{num.decode('ascii')} (X-GM-MSGID {gmail_msgid})".encode("ascii")]
            if "X-GM-LABELS" in query:
                return "OK", [b'1 (FLAGS (\\Seen) X-GM-LABELS ("\\Inbox"))']
            return super().fetch(num, query)

        def store(self, num: bytes, command: str, labels: str):
            self.stored_labels.append((num, command, labels))
            return "OK", [b""]

    source_fake = FakeSourceImap() if source_provider == "gmail" else OneMessageImapSource()
    target_fake = StoredGmailMatrixTarget() if target_provider == "gmail" else StoredMessageTarget()

    @contextlib.contextmanager
    def fake_connection(endpoint_obj, *_args, **kwargs):
        yield source_fake if kwargs.get("role") == "source" else target_fake

    with mock.patch("components.provider_ops.imap_connection", fake_connection):
        provider_export_account(config, config.accounts[0], tmp_path)
        provider_import_account(config, config.accounts[0], tmp_path)
        _name, report = provider_validate_account(config, config.accounts[0], tmp_path)

    assert target_fake.appended
    assert report["ok"]
    account_dir = tmp_path / source_email
    rows = [json.loads(line) for line in (account_dir / "manifest.jsonl").read_text().splitlines()]
    assert rows
    assert all(row["source_provider"] == source_provider for row in rows)
    assert all(row["target_account"] == target_email for row in rows)


def test_provider_config_treats_roundcube_as_generic_imap(tmp_path: Path) -> None:
    path = tmp_path / "roundcube-to-icloud.json"
    path.write_text(json.dumps({
        "source": {
            "provider": "imap",
            "host": "mail.roundcube-backed.example.com",
            "auth": {"method": "password", "username": "user@example.com", "password": "imap-secret"},
        },
        "target": {
            "provider": "icloud",
            "host": "imap.mail.me.com",
            "auth": {"method": "app_password", "username": "user", "password": "icloud-secret"},
        },
        "accounts": [{"source_email": "user@example.com", "target_email": "user@icloud.com"}],
    }))

    parsed = load_config_file(path)

    assert isinstance(parsed, ProviderMigrationConfig)
    assert parsed.source.provider == "imap"
    assert parsed.target.provider == "icloud"


def test_imap_connection_uses_canonical_provider_host() -> None:
    endpoint = ProviderEndpoint(
        provider="gmail",
        host="IMAP.GMAIL.COM.",
        auth=AuthConfig(method="xoauth2", username="user@gmail.com", password="token"),
    )
    account = MigrationAccount(source_email="user@gmail.com", target_email="target@example.com")

    class RecordingImap:
        host = ""
        port = 0

        def __init__(self, host: str, port: int, ssl_context=None) -> None:
            RecordingImap.host = host
            RecordingImap.port = port

        def authenticate(self, *_args):
            return "OK", []

        def logout(self):
            return "OK", []

    with mock.patch("imaplib.IMAP4_SSL", RecordingImap):
        with imap_connection(endpoint, account, role="source"):
            pass

    assert RecordingImap.host == "imap.gmail.com"
    assert RecordingImap.port == 993


def test_multi_account_provider_auth_requires_per_account_usernames(tmp_path: Path) -> None:
    path = tmp_path / "shared-username.json"
    path.write_text(json.dumps({
        "source": {"provider": "imap", "host": "mail.example.com", "auth": {"method": "password", "username": "shared-login"}},
        "target": {"provider": "imap", "host": "target.example.com", "auth": {"method": "password"}},
        "accounts": [
            {
                "source_email": "a@example.com",
                "target_email": "a@target.example.com",
                "source_auth": {"method": "password", "password": "source-a"},
                "target_auth": {"method": "password", "username": "a", "password": "target-a"},
            },
            {
                "source_email": "b@example.com",
                "target_email": "b@target.example.com",
                "source_auth": {"method": "password", "password": "source-b"},
                "target_auth": {"method": "password", "username": "b", "password": "target-b"},
            },
        ],
    }))

    with pytest.raises(ValueError, match="source_auth.username"):
        load_config_file(path)


def test_provider_config_rejects_duplicate_effective_source_usernames(tmp_path: Path) -> None:
    path = tmp_path / "duplicate-source-login.json"
    path.write_text(json.dumps({
        "source": {"provider": "imap", "host": "mail.example.com", "auth": {"method": "password"}},
        "target": {"provider": "imap", "host": "target.example.com", "auth": {"method": "password"}},
        "accounts": [
            {
                "source_email": "a@example.com",
                "target_email": "a@target.example.com",
                "source_auth": {"method": "password", "username": "shared-login", "password": "source-a"},
                "target_auth": {"method": "password", "username": "a@target.example.com", "password": "target-a"},
            },
            {
                "source_email": "b@example.com",
                "target_email": "b@target.example.com",
                "source_auth": {"method": "password", "username": "shared-login", "password": "source-b"},
                "target_auth": {"method": "password", "username": "b@target.example.com", "password": "target-b"},
            },
        ],
    }))

    with pytest.raises(ValueError, match="effective source_auth.username"):
        load_config_file(path)


def test_provider_config_rejects_duplicate_target_email_without_merge_mode(tmp_path: Path) -> None:
    path = tmp_path / "duplicate-target.json"
    path.write_text(json.dumps({
        "source": {"provider": "imap", "host": "mail.example.com", "auth": {"method": "password"}},
        "target": {
            "provider": "imap",
            "host": "target.example.com",
            "auth": {"method": "password", "username": "merged@example.com", "password": "target-secret"},
        },
        "accounts": [
            {
                "source_email": "a@example.com",
                "target_email": "merged@example.com",
                "source_auth": {"method": "password", "username": "a@example.com", "password": "source-a"},
            },
            {
                "source_email": "b@example.com",
                "target_email": "merged@example.com",
                "source_auth": {"method": "password", "username": "b@example.com", "password": "source-b"},
            },
        ],
    }))

    with pytest.raises(ValueError, match="target_email duplicates"):
        load_config_file(path)


def test_provider_config_rejects_duplicate_effective_target_login_without_merge_mode(tmp_path: Path) -> None:
    path = tmp_path / "duplicate-target-login.json"
    path.write_text(json.dumps({
        "source": {"provider": "imap", "host": "mail.example.com", "auth": {"method": "password"}},
        "target": {
            "provider": "imap",
            "host": "target.example.com",
            "auth": {"method": "password"},
        },
        "accounts": [
            {
                "source_email": "a@example.com",
                "target_email": "target-alias-a@example.com",
                "source_auth": {"method": "password", "username": "a@example.com", "password": "source-a"},
                "target_auth": {"method": "password", "username": "merged@example.com", "password": "target-a"},
            },
            {
                "source_email": "b@example.com",
                "target_email": "target-alias-b@example.com",
                "source_auth": {"method": "password", "username": "b@example.com", "password": "source-b"},
                "target_auth": {"method": "password", "username": "merged@example.com", "password": "target-b"},
            },
        ],
    }))

    with pytest.raises(ValueError, match="migration.account_merge_mode=many_to_one"):
        load_config_file(path)


def test_provider_config_rejects_dotted_personal_gmail_source_aliases(tmp_path: Path) -> None:
    path = tmp_path / "dotted-gmail-source.json"
    path.write_text(json.dumps({
        "source": {
            "provider": "gmail",
            "host": "imap.gmail.com",
            "auth": {"method": "xoauth2", "password": "token"},
            "gmail_full_visibility_verified": True,
        },
        "target": {"provider": "imap", "host": "target.example.com", "auth": {"method": "password"}},
        "accounts": [
            {
                "source_email": "johnsmith@gmail.com",
                "target_email": "a@example.com",
                "source_auth": {"method": "xoauth2", "username": "johnsmith@gmail.com", "password": "token-a"},
                "target_auth": {"method": "password", "username": "a@example.com", "password": "target-a"},
            },
            {
                "source_email": "john.smith@gmail.com",
                "target_email": "b@example.com",
                "source_auth": {"method": "xoauth2", "username": "john.smith@gmail.com", "password": "token-b"},
                "target_auth": {"method": "password", "username": "b@example.com", "password": "target-b"},
            },
        ],
    }))

    with pytest.raises(ValueError, match="source_email duplicates"):
        load_config_file(path)


def test_provider_config_rejects_dotted_personal_gmail_target_aliases(tmp_path: Path) -> None:
    path = tmp_path / "dotted-gmail-target.json"
    path.write_text(json.dumps({
        "source": {"provider": "imap", "host": "mail.example.com", "auth": {"method": "password"}},
        "target": {
            "provider": "gmail",
            "host": "imap.gmail.com",
            "auth": {"method": "xoauth2", "password": "token"},
            "gmail_full_visibility_verified": True,
        },
        "accounts": [
            {
                "source_email": "a@example.com",
                "target_email": "johnsmith@gmail.com",
                "source_auth": {"method": "password", "username": "a@example.com", "password": "source-a"},
                "target_auth": {"method": "xoauth2", "username": "johnsmith@gmail.com", "password": "token-a"},
            },
            {
                "source_email": "b@example.com",
                "target_email": "john.smith@gmail.com",
                "source_auth": {"method": "password", "username": "b@example.com", "password": "source-b"},
                "target_auth": {"method": "xoauth2", "username": "john.smith@gmail.com", "password": "token-b"},
            },
        ],
    }))

    with pytest.raises(ValueError, match="target_email duplicates"):
        load_config_file(path)


def test_provider_config_rejects_googlemail_personal_gmail_target_aliases(tmp_path: Path) -> None:
    path = tmp_path / "googlemail-gmail-target.json"
    path.write_text(json.dumps({
        "source": {"provider": "imap", "host": "mail.example.com", "auth": {"method": "password"}},
        "target": {
            "provider": "gmail",
            "host": "imap.gmail.com",
            "auth": {"method": "xoauth2", "password": "token"},
            "gmail_full_visibility_verified": True,
        },
        "accounts": [
            {
                "source_email": "a@example.com",
                "target_email": "johnsmith@gmail.com",
                "source_auth": {"method": "password", "username": "a@example.com", "password": "source-a"},
                "target_auth": {"method": "xoauth2", "username": "johnsmith@gmail.com", "password": "token-a"},
            },
            {
                "source_email": "b@example.com",
                "target_email": "john.smith@googlemail.com",
                "source_auth": {"method": "password", "username": "b@example.com", "password": "source-b"},
                "target_auth": {"method": "xoauth2", "username": "john.smith@googlemail.com", "password": "token-b"},
            },
        ],
    }))

    with pytest.raises(ValueError, match="target_email duplicates"):
        load_config_file(path)


def test_many_to_one_gmail_target_group_folds_googlemail_aliases() -> None:
    config = ProviderMigrationConfig.from_dict({
        "source": {"provider": "imap", "host": "mail.source.example.com", "auth": {"method": "password"}},
        "target": {
            "provider": "gmail",
            "host": "imap.gmail.com",
            "auth": {"method": "xoauth2"},
            "gmail_full_visibility_verified": True,
        },
        "migration": {"target_mode": "empty", "account_merge_mode": "many_to_one"},
        "accounts": [
            {
                "source_email": "a@example.com",
                "target_email": "johnsmith@gmail.com",
                "source_auth": {"method": "password", "username": "a@example.com", "password": "source-a"},
                "target_auth": {"method": "xoauth2", "username": "johnsmith@gmail.com", "password": "token-a"},
                "target_gmail_full_visibility_verified": True,
            },
            {
                "source_email": "b@example.com",
                "target_email": "john.smith@googlemail.com",
                "source_auth": {"method": "password", "username": "b@example.com", "password": "source-b"},
                "target_auth": {"method": "xoauth2", "username": "john.smith@googlemail.com", "password": "token-b"},
                "target_gmail_full_visibility_verified": True,
            },
        ],
    })

    first, second = config.accounts
    assert target_merge_group_key(config, first) == target_merge_group_key(config, second)


def test_provider_config_accepts_dotted_personal_gmail_source_auth_username(tmp_path: Path) -> None:
    path = tmp_path / "dotted-gmail-source-auth.json"
    path.write_text(json.dumps({
        "source": {
            "provider": "gmail",
            "host": "imap.gmail.com",
            "auth": {"method": "xoauth2", "password": "token"},
            "gmail_full_visibility_verified": True,
        },
        "target": {"provider": "imap", "host": "target.example.com", "auth": {"method": "password", "password": "target"}},
        "accounts": [{
            "source_email": "johnsmith@gmail.com",
            "target_email": "target@example.com",
            "source_auth": {"method": "xoauth2", "username": "john.smith@gmail.com", "password": "token"},
        }],
    }))

    parsed = load_config_file(path)

    assert isinstance(parsed, ProviderMigrationConfig)


def test_provider_config_strips_auth_username_whitespace(tmp_path: Path) -> None:
    path = tmp_path / "spaced-gmail-source-auth.json"
    path.write_text(json.dumps({
        "source": {
            "provider": "gmail",
            "host": "imap.gmail.com",
            "auth": {"method": "xoauth2", "password": "token"},
            "gmail_full_visibility_verified": True,
        },
        "target": {"provider": "imap", "host": "target.example.com", "auth": {"method": "password", "password": "target"}},
        "accounts": [{
            "source_email": "johnsmith@gmail.com",
            "target_email": "target@example.com",
            "source_auth": {"method": "xoauth2", "username": " john.smith@gmail.com ", "password": "token"},
        }],
    }))

    parsed = load_config_file(path)

    assert isinstance(parsed, ProviderMigrationConfig)
    assert parsed.accounts[0].source_auth is not None
    assert parsed.accounts[0].source_auth.username == "john.smith@gmail.com"
    assert effective_auth(parsed.source, parsed.accounts[0], role="source")[0] == "john.smith@gmail.com"


def test_provider_config_accepts_dotted_personal_gmail_target_auth_username(tmp_path: Path) -> None:
    path = tmp_path / "dotted-gmail-target-auth.json"
    path.write_text(json.dumps({
        "source": {"provider": "imap", "host": "mail.example.com", "auth": {"method": "password", "password": "source"}},
        "target": {
            "provider": "gmail",
            "host": "imap.gmail.com",
            "auth": {"method": "xoauth2", "password": "token"},
            "gmail_full_visibility_verified": True,
        },
        "accounts": [{
            "source_email": "source@example.com",
            "target_email": "johnsmith@gmail.com",
            "target_auth": {"method": "xoauth2", "username": "john.smith@gmail.com", "password": "token"},
        }],
    }))

    parsed = load_config_file(path)

    assert isinstance(parsed, ProviderMigrationConfig)


def test_provider_config_many_to_one_allows_shared_target_auth(tmp_path: Path) -> None:
    path = tmp_path / "many-to-one.json"
    path.write_text(json.dumps({
        "source": {"provider": "imap", "host": "mail.example.com", "auth": {"method": "password"}},
        "target": {
            "provider": "imap",
            "host": "target.example.com",
            "auth": {"method": "password", "username": "merged@example.com", "password": "target-secret"},
        },
        "migration": {"account_merge_mode": "many_to_one"},
        "accounts": [
            {
                "source_email": "a@example.com",
                "target_email": "merged@example.com",
                "source_auth": {"method": "password", "username": "a@example.com", "password": "source-a"},
            },
            {
                "source_email": "b@example.com",
                "target_email": "merged@example.com",
                "source_auth": {"method": "password", "username": "b@example.com", "password": "source-b"},
            },
        ],
    }))

    parsed = load_config_file(path)

    assert isinstance(parsed, ProviderMigrationConfig)
    assert parsed.migration.account_merge_mode == "many_to_one"
    assert [account.target_email for account in parsed.accounts] == ["merged@example.com", "merged@example.com"]


def test_provider_config_many_to_one_rejects_same_effective_target_login_with_alias_labels(tmp_path: Path) -> None:
    path = tmp_path / "many-to-one-target-aliases.json"
    path.write_text(json.dumps({
        "source": {"provider": "imap", "host": "mail.example.com", "auth": {"method": "password"}},
        "target": {
            "provider": "imap",
            "host": "target.example.com",
            "auth": {"method": "password"},
        },
        "migration": {"account_merge_mode": "many_to_one"},
        "accounts": [
            {
                "source_email": "a@example.com",
                "target_email": "target-alias-a@example.com",
                "source_auth": {"method": "password", "username": "a@example.com", "password": "source-a"},
                "target_auth": {"method": "password", "username": "merged@example.com", "password": "target-a"},
            },
            {
                "source_email": "b@example.com",
                "target_email": "target-alias-b@example.com",
                "source_auth": {"method": "password", "username": "b@example.com", "password": "source-b"},
                "target_auth": {"method": "password", "username": "merged@example.com", "password": "target-b"},
            },
        ],
    }))

    with pytest.raises(ValueError, match="cannot reuse effective target_auth.username"):
        load_config_file(path)


def test_provider_config_many_to_one_rejects_singleton_reusing_merge_target_login(tmp_path: Path) -> None:
    path = tmp_path / "hybrid-accidental-target-login-reuse.json"
    path.write_text(json.dumps({
        "source": {"provider": "imap", "host": "mail.example.com", "auth": {"method": "password"}},
        "target": {
            "provider": "imap",
            "host": "target.example.com",
            "auth": {"method": "password"},
        },
        "migration": {"account_merge_mode": "many_to_one"},
        "accounts": [
            {
                "source_email": "a@example.com",
                "target_email": "a@example.com",
                "source_auth": {"method": "password", "username": "a@example.com", "password": "source-a"},
                "target_auth": {"method": "password", "username": "a@example.com", "password": "target-a"},
            },
            {
                "source_email": "b@example.com",
                "target_email": "a@example.com",
                "source_auth": {"method": "password", "username": "b@example.com", "password": "source-b"},
                "target_auth": {"method": "password", "username": "a@example.com", "password": "target-b"},
            },
            {
                "source_email": "d@example.com",
                "target_email": "d@example.com",
                "source_auth": {"method": "password", "username": "d@example.com", "password": "source-d"},
                "target_auth": {"method": "password", "username": "a@example.com", "password": "target-d"},
            },
        ],
    }))

    with pytest.raises(ValueError, match="different target_email labels"):
        load_config_file(path)


def test_provider_config_generic_imap_case_only_target_usernames_are_distinct(tmp_path: Path) -> None:
    path = tmp_path / "many-to-one-case-targets.json"
    path.write_text(json.dumps({
        "source": {"provider": "imap", "host": "mail.example.com", "auth": {"method": "password"}},
        "target": {
            "provider": "imap",
            "host": "target.example.com",
            "auth": {"method": "password"},
        },
        "migration": {"account_merge_mode": "many_to_one"},
        "accounts": [
            {
                "source_email": "a@example.com",
                "target_email": "target-alias-a@example.com",
                "source_auth": {"method": "password", "username": "a@example.com", "password": "source-a"},
                "target_auth": {"method": "password", "username": "CaseUser", "password": "target-a"},
            },
            {
                "source_email": "b@example.com",
                "target_email": "target-alias-b@example.com",
                "source_auth": {"method": "password", "username": "b@example.com", "password": "source-b"},
                "target_auth": {"method": "password", "username": "caseuser", "password": "target-b"},
            },
        ],
    }))

    parsed = load_config_file(path)

    assert isinstance(parsed, ProviderMigrationConfig)
    assert target_merge_group_key(parsed, parsed.accounts[0]) != target_merge_group_key(parsed, parsed.accounts[1])


def test_provider_config_many_to_one_rejects_shared_endpoint_secret_for_distinct_generic_targets(tmp_path: Path) -> None:
    path = tmp_path / "distinct-generic-targets.json"
    path.write_text(json.dumps({
        "source": {"provider": "imap", "host": "mail.example.com", "auth": {"method": "password"}},
        "target": {
            "provider": "imap",
            "host": "target.example.com",
            "auth": {"method": "password", "password": "shared-target-secret"},
        },
        "migration": {"account_merge_mode": "many_to_one"},
        "accounts": [
            {
                "source_email": "a@example.com",
                "target_email": "first@example.com",
                "source_auth": {"method": "password", "username": "a@example.com", "password": "source-a"},
            },
            {
                "source_email": "b@example.com",
                "target_email": "second@example.com",
                "source_auth": {"method": "password", "username": "b@example.com", "password": "source-b"},
            },
        ],
    }))

    with pytest.raises(ValueError, match="target_auth must be set"):
        load_config_file(path)


def test_provider_config_many_to_one_rejects_mismatched_effective_target_login(tmp_path: Path) -> None:
    path = tmp_path / "many-to-one-wrong-target-login.json"
    path.write_text(json.dumps({
        "source": {"provider": "imap", "host": "mail.example.com", "auth": {"method": "password"}},
        "target": {
            "provider": "imap",
            "host": "target.example.com",
            "auth": {"method": "password"},
        },
        "migration": {"account_merge_mode": "many_to_one"},
        "accounts": [
            {
                "source_email": "a@example.com",
                "target_email": "merged@example.com",
                "source_auth": {"method": "password", "username": "a@example.com", "password": "source-a"},
                "target_auth": {"method": "password", "username": "merged@example.com", "password": "target-a"},
            },
            {
                "source_email": "b@example.com",
                "target_email": "merged@example.com",
                "source_auth": {"method": "password", "username": "b@example.com", "password": "source-b"},
                "target_auth": {"method": "password", "username": "other-login@example.com", "password": "target-b"},
            },
        ],
    }))

    with pytest.raises(ValueError, match="same effective target_auth.username"):
        load_config_file(path)


def test_provider_config_many_to_one_accepts_documented_three_sources_to_self_target(tmp_path: Path) -> None:
    path = tmp_path / "abc-to-a.json"
    path.write_text(json.dumps({
        "source": {"provider": "imap", "host": "imap.old.example.com", "auth": {"method": "password"}},
        "target": {
            "provider": "imap",
            "host": "imap.new.example.com",
            "auth": {"method": "password", "username": "a@example.com", "password": "target-a"},
        },
        "migration": {"target_mode": "empty", "account_merge_mode": "many_to_one"},
        "accounts": [
            {
                "source_email": "a@example.com",
                "target_email": "a@example.com",
                "source_auth": {"method": "password", "username": "a@example.com", "password": "source-a"},
            },
            {
                "source_email": "b@example.com",
                "target_email": "a@example.com",
                "source_auth": {"method": "password", "username": "b@example.com", "password": "source-b"},
            },
            {
                "source_email": "c@example.com",
                "target_email": "a@example.com",
                "source_auth": {"method": "password", "username": "c@example.com", "password": "source-c"},
            },
        ],
    }))

    parsed = load_config_file(path)

    assert isinstance(parsed, ProviderMigrationConfig)
    assert parsed.migration.account_merge_mode == "many_to_one"
    assert [account.source_email for account in parsed.accounts] == ["a@example.com", "b@example.com", "c@example.com"]
    assert {account.target_email for account in parsed.accounts} == {"a@example.com"}


def test_provider_config_rejects_sanitized_account_path_collisions(tmp_path: Path) -> None:
    path = tmp_path / "provider-collision.json"
    path.write_text(json.dumps({
        "source": {"provider": "imap", "host": "mail.example.com", "auth": {"method": "password"}},
        "target": {"provider": "imap", "host": "target.example.com", "auth": {"method": "password"}},
        "accounts": [
            {
                "source_email": "a/b@example.com",
                "target_email": "a@target.example.com",
                "source_auth": {"method": "password", "username": "a/b@example.com", "password": "source-a"},
                "target_auth": {"method": "password", "username": "a", "password": "target-a"},
            },
            {
                "source_email": "a_b@example.com",
                "target_email": "b@target.example.com",
                "source_auth": {"method": "password", "username": "a_b@example.com", "password": "source-b"},
                "target_auth": {"method": "password", "username": "b", "password": "target-b"},
            },
        ],
    }))

    with pytest.raises(ValueError, match="path collision"):
        load_config_file(path)

    case_only = tmp_path / "provider-case-collision.json"
    case_only.write_text(json.dumps({
        "source": {"provider": "imap", "host": "mail.example.com", "auth": {"method": "password"}},
        "target": {"provider": "imap", "host": "target.example.com", "auth": {"method": "password"}},
        "accounts": [
            {
                "source_email": "User@example.com",
                "target_email": "first@target.example.com",
                "source_auth": {"method": "password", "username": "User@example.com", "password": "source-a"},
                "target_auth": {"method": "password", "username": "first", "password": "target-a"},
            },
            {
                "source_email": "user@example.com",
                "target_email": "second@target.example.com",
                "source_auth": {"method": "password", "username": "user@example.com", "password": "source-b"},
                "target_auth": {"method": "password", "username": "second", "password": "target-b"},
            },
        ],
    }))

    with pytest.raises(ValueError, match="case-insensitive"):
        load_config_file(case_only)


def test_xoauth2_payload_generation() -> None:
    payload = build_xoauth2_payload("user@gmail.com", "access-token").decode("utf-8")
    assert payload == "user=user@gmail.com\x01auth=Bearer access-token\x01\x01"
    auth = xoauth2_authenticator("user@gmail.com", "access-token")
    assert auth(b"") == build_xoauth2_payload("user@gmail.com", "access-token")
    assert auth(b'{"status":"401"}') == b""


def test_provider_secret_files_must_not_be_empty(tmp_path: Path) -> None:
    secret = tmp_path / "empty-token"
    secret.write_text("\n")

    with pytest.raises(RuntimeError, match="empty secret"):
        resolve_secret(AuthConfig(method="xoauth2", token_file=str(secret)))


def test_provider_inline_password_preserves_boundary_spaces() -> None:
    auth = AuthConfig.from_dict(
        {"method": "password", "username": "user@example.com", "password": " pass with spaces "},
        context="target",
    )

    assert auth is not None
    assert auth.password == " pass with spaces "
    assert resolve_secret(auth) == " pass with spaces "


def test_provider_password_file_preserves_boundary_spaces(tmp_path: Path) -> None:
    secret = tmp_path / "password.txt"
    secret.write_text(" pass with spaces \n")

    assert resolve_secret(AuthConfig(method="password", password_file=str(secret))) == " pass with spaces "


def test_provider_imap_login_receives_untrimmed_password(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: List[Tuple[str, str]] = []

    class FakeIMAP:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def login(self, username: str, password: str):
            captured.append((username, password))
            return "OK", [b""]

        def logout(self):
            return "OK", [b""]

    monkeypatch.setattr("components.provider_ops.imaplib.IMAP4_SSL", FakeIMAP)
    endpoint = ProviderEndpoint(
        provider="imap",
        host="mail.example.com",
        auth=AuthConfig(method="password", username="user@example.com", password=" pass with spaces "),
    )
    account = MigrationAccount(source_email="user@example.com", target_email="target@example.com")

    with imap_connection(endpoint, account, role="source"):
        pass

    assert captured == [("user@example.com", " pass with spaces ")]


def test_account_auth_override_preserves_endpoint_username() -> None:
    endpoint = ProviderEndpoint(
        provider="imap",
        host="mail.example.com",
        auth=AuthConfig(method="password", username="login-name", password="endpoint-secret"),
    )
    account = MigrationAccount(
        source_email="source@example.com",
        target_email="target@example.com",
        source_auth=AuthConfig(method="password", password="account-secret"),
    )

    username, auth = effective_auth(endpoint, account, role="source")

    assert username == "login-name"
    assert auth.password == "account-secret"


def test_icloud_effective_auth_defaults_to_local_part_username() -> None:
    endpoint = ProviderEndpoint(
        provider="icloud",
        host="imap.mail.me.com",
        auth=AuthConfig(method="app_password", password="icloud-secret"),
    )
    account = MigrationAccount(source_email="person@icloud.com", target_email="target@example.com")

    username, auth = effective_auth(endpoint, account, role="source")

    assert username == "person"
    assert auth.password == "icloud-secret"


def test_icloud_endpoint_state_treats_local_part_and_full_address_as_same_login() -> None:
    from components.provider_ops import (
        provider_account_endpoint_state,
        provider_account_endpoint_state_digest,
        provider_export_state_contract_issues,
    )

    account = MigrationAccount(source_email="source@example.com", target_email="target@icloud.com")
    local_part_endpoint = ProviderEndpoint(
        provider="icloud",
        host="imap.mail.me.com",
        auth=AuthConfig(method="app_password", username="target", password="icloud-secret"),
    )
    full_address_endpoint = ProviderEndpoint(
        provider="icloud",
        host="imap.mail.me.com",
        auth=AuthConfig(method="app_password", username="target@icloud.com", password="icloud-secret"),
    )

    local_state = provider_account_endpoint_state(local_part_endpoint, account, role="target")
    full_state = provider_account_endpoint_state(full_address_endpoint, account, role="target")
    state = {
        "source_account": "source@example.com",
        "target_account": "target@icloud.com",
        "target_provider": "icloud",
        "target_endpoint": local_state,
        "target_endpoint_sha256": provider_account_endpoint_state_digest(local_part_endpoint, account, role="target"),
    }

    assert local_state == full_state
    assert provider_export_state_contract_issues(
        state,
        account=account,
        target_provider="icloud",
        target_endpoint=full_address_endpoint,
    ) == []


def test_provider_endpoint_state_canonicalizes_gmail_username_case() -> None:
    gmail = ProviderEndpoint(provider="gmail", host="imap.gmail.com")
    generic = ProviderEndpoint(provider="imap", host="mail.example.com")

    assert provider_endpoint_state(gmail, username="User.Name@Gmail.com")["username"] == "username@gmail.com"
    assert provider_endpoint_state_digest(gmail, username="User.Name@Gmail.com") == provider_endpoint_state_digest(
        gmail,
        username="username@gmail.com",
    )
    assert provider_endpoint_state(gmail, username="User.Name@example.com")["username"] == "user.name@example.com"
    assert provider_endpoint_state(generic, username="User@Example.com")["username"] == "User@Example.com"


def test_list_and_gmail_fetch_parsers() -> None:
    mailbox = parse_list_line(b'(\\HasNoChildren \\Sent) "/" "[Gmail]/Sent Mail"')
    assert mailbox is not None
    assert mailbox.name == "[Gmail]/Sent Mail"
    assert "\\Sent" in mailbox.attributes

    utf7_mailbox = parse_list_line(f'(\\HasNoChildren) NIL "{encode_imap_utf7("Föld & Team")}"'.encode("ascii"))
    assert utf7_mailbox is not None
    assert utf7_mailbox.delimiter == ""
    assert utf7_mailbox.name == "Föld & Team"
    assert quote_mailbox_name("Föld & Team") == f'"{encode_imap_utf7("Föld & Team")}"'

    utf8_mailbox = parse_list_line(b'(\\HasNoChildren) "/" "F\xc3\xb6lder"')
    assert utf8_mailbox is not None
    assert utf8_mailbox.name == "Földer"

    parsed = parse_provider_fetch_response([
        (
            b'1 (UID 7 RFC822.SIZE 42 FLAGS (\\Seen) INTERNALDATE "01-Jan-2024 00:00:00 +0000" '
            b'X-GM-MSGID 123 X-GM-THRID 456 X-GM-LABELS ("Project A" \\Inbox))',
            b"Message-ID: <m1@example.com>\r\n\r\nbody",
        )
    ])
    assert parsed["gmail_msgid"] == "123"
    assert parsed["gmail_thrid"] == "456"
    assert parsed["gmail_labels"] == ["Project A", "\\Inbox"]
    assert parsed["flags"] == "\\Seen"
    assert parsed["rfc822_size"] == 42

    too_large = str(1 << 64)
    overlong_ids = parse_provider_fetch_response([
        (
            f"1 (RFC822.SIZE 10 X-GM-MSGID {too_large} X-GM-THRID {too_large})".encode("ascii"),
            b"Message-ID: <too-large@example.com>\r\n\r\nbody",
        )
    ])
    assert overlong_ids["gmail_msgid"] == ""
    assert overlong_ids["gmail_thrid"] == ""

    with_parens = parse_provider_fetch_response([
        (
            b'1 (RFC822.SIZE 10 X-GM-LABELS ("Team (Old)" "Project B"))',
            b"Message-ID: <m2@example.com>\r\n\r\nbody",
        )
    ])
    assert with_parens["gmail_labels"] == ["Team (Old)", "Project B"]

    utf7_labels = parse_provider_fetch_response([
        (
            f'1 (RFC822.SIZE 10 X-GM-LABELS ("{encode_imap_utf7("Föld & Team")}"))'.encode("ascii"),
            b"Message-ID: <m3@example.com>\r\n\r\nbody",
        )
    ])
    assert utf7_labels["gmail_labels"] == ["Föld & Team"]

    literal_label = parse_provider_fetch_response([
        (b'1 (RFC822.SIZE 35 X-GM-LABELS {9}', b"Project A"),
        (b'BODY[] {35}', b"Message-ID: <m4@example.com>\r\n\r\nbody"),
    ])
    assert literal_label["message_bytes"] == b"Message-ID: <m4@example.com>\r\n\r\nbody"
    assert literal_label["gmail_labels"] == ["Project A"]
    assert "{9}" not in literal_label["gmail_labels"]
    assert literal_label["rfc822_size"] == 35

    empty_body = parse_provider_fetch_response([
        (b'1 (UID 8 RFC822.SIZE 0 FLAGS () INTERNALDATE "01-Jan-2024 00:00:00 +0000" BODY[] {0}', b""),
    ])
    assert empty_body["message_bytes"] == b""
    assert empty_body["rfc822_size"] == 0

    quoted_literal_marker_label = parse_provider_fetch_response([
        (b'1 (RFC822.SIZE 10 X-GM-LABELS ("{9}" "Project A"))', b""),
    ])
    assert quoted_literal_marker_label["gmail_labels"] == ["{9}", "Project A"]

    multi_literal_labels = parse_provider_fetch_response([
        (b'1 (RFC822.SIZE 10 X-GM-LABELS ({5}', b"Label"),
        (b'{6}', b"Second"),
        b'))',
    ])
    assert multi_literal_labels["gmail_labels"] == ["Label", "Second"]

    with pytest.raises(RuntimeError, match="multiple message bodies"):
        parse_provider_fetch_response([
            (b"1 (RFC822.SIZE 10 BODY[] {5}", b"hello"),
            (b" BODY[] {5}", b"world"),
            b")",
        ])


def test_provider_safe_identity_hashes_truncated_names() -> None:
    first = "gmail-" + ("1" * 174) + "2"
    second = "gmail-" + ("1" * 174) + "3"

    assert _safe_identity("gmail-123") == "gmail-123"
    assert len(_safe_identity(first)) == 180
    assert len(_safe_identity(second)) == 180
    assert _safe_identity(first) != _safe_identity(second)


def test_list_parser_accepts_literal_mailbox_names() -> None:
    class LiteralListImap:
        def list(self):
            return "OK", [(b'(\\HasNoChildren) "/" {13}', encode_imap_utf7("Föld & Team").encode("ascii"))]

    mailboxes = list_mailboxes(LiteralListImap())

    assert len(mailboxes) == 1
    assert mailboxes[0].name == "Föld & Team"


def test_list_mailboxes_requests_special_use_attrs() -> None:
    class SpecialUseReturnImap:
        def __init__(self) -> None:
            self.calls: List[tuple] = []

        def list(self, *args):
            self.calls.append(args)
            if args == ('""', '"*" RETURN (SPECIAL-USE)'):
                return "OK", [
                    b'(\\HasNoChildren \\All) "/" "All Mail"',
                    b'(\\HasNoChildren \\Trash) "/" "Papierkorb"',
                ]
            return "OK", [
                b'(\\HasNoChildren) "/" "All Mail"',
                b'(\\HasNoChildren) "/" "Papierkorb"',
            ]

    imap = SpecialUseReturnImap()
    mailboxes = list_mailboxes(imap)

    assert imap.calls == [('""', '"*" RETURN (SPECIAL-USE)')]
    assert {mailbox.name: mailbox.attributes for mailbox in mailboxes} == {
        "All Mail": ("\\HasNoChildren", "\\All"),
        "Papierkorb": ("\\HasNoChildren", "\\Trash"),
    }
    assert resolve_target_mailbox("Deleted Messages", mailboxes, target_provider="imap") == "Papierkorb"


def test_primary_folder_resolution_is_deterministic() -> None:
    assert resolve_primary_mailbox(["[Gmail]/Sent Mail", "[Gmail]/All Mail"], [], {}) == "Sent"
    assert resolve_primary_mailbox(["[Gmail]/Trash"], [], {}) == "Deleted Messages"
    assert resolve_primary_mailbox(["[Gmail]/Spam"], [], {}) == "Junk"
    assert resolve_primary_mailbox(["[Gmail]/Important", "[Gmail]/All Mail"], [], {}) == "Archive"
    assert resolve_primary_mailbox(["[Gmail]/All Mail"], ["Important"], {}) == "Archive"
    assert resolve_primary_mailbox(["INBOX", "[Gmail]/Important"], ["Important"], {}) == "INBOX"
    assert resolve_primary_mailbox(["[Gmail]/Sent Mail", "[Gmail]/Important"], ["Important"], {}) == "Sent"
    assert resolve_primary_mailbox(["[Gmail]/All Mail"], [], {}) == "Archive"
    assert resolve_primary_mailbox(["All Mail"], [], {}) == "Archive"
    assert resolve_primary_mailbox(["All Mail", "\\All"], [], {}) == "Archive"
    assert resolve_primary_mailbox(["Archive", "\\Archive"], [], {}) == "Archive"
    assert resolve_primary_mailbox(["Project A", "[Gmail]/All Mail"], [], {}) == "Project A"
    assert resolve_primary_mailbox(["All Mail", "Project A"], [], {}) == "Project A"
    assert resolve_primary_mailbox(["Project A"], [], {}) == "Project A"
    assert resolve_primary_mailbox(["[GoogleMail]/All Mail"], [], {}) == "Archive"
    assert resolve_primary_mailbox(["[GoogleMail]/Sent Mail", "[GoogleMail]/All Mail"], [], {}) == "Sent"
    assert resolve_primary_mailbox(["[Gmail]/Sent Mail"], [], {"[Gmail]/Sent Mail": "Sent Messages"}) == "Sent Messages"
    folder_map = {
        "[Gmail]/All Mail": "Archive",
        "[Gmail]/Sent Mail": "Sent",
        "[Gmail]/Drafts": "Drafts",
        "[Gmail]/Trash": "Deleted Messages",
        "[Gmail]/Spam": "Junk",
    }
    assert resolve_primary_mailbox(["[Gmail]/All Mail", "[Gmail]/Sent Mail"], [], folder_map) == "Sent"
    assert resolve_primary_mailbox(["[Gmail]/All Mail", "[Gmail]/Drafts"], [], folder_map) == "Drafts"
    assert resolve_primary_mailbox(["[Gmail]/All Mail", "[Gmail]/Trash"], [], folder_map) == "Deleted Messages"
    assert resolve_primary_mailbox(["[Gmail]/All Mail", "[Gmail]/Spam"], [], folder_map) == "Junk"
    assert resolve_primary_mailbox(["[Gmail]/All Mail", "[Gmail]/Important"], [], folder_map) == "Archive"


def test_generic_source_primary_mailbox_preserves_case_distinct_special_names() -> None:
    assert resolve_primary_mailbox(["sent"], [], {}, source_provider="imap") == "sent"
    assert resolve_primary_mailbox(["Sent"], [], {}, source_provider="imap") == "Sent"
    assert resolve_primary_mailbox(["sent", "\\Sent"], [], {}, source_provider="imap") == "Sent"
    assert resolve_primary_mailbox(["INBOX"], [], {}, source_provider="imap") == "INBOX"
    assert resolve_primary_mailbox(["inbox"], [], {}, source_provider="imap") == "INBOX"


def test_gmail_target_folder_resolution_uses_special_use_and_gmail_names() -> None:
    gmail_mailboxes = [
        MailboxInfo(name="INBOX", delimiter="/", attributes=("\\HasNoChildren",)),
        MailboxInfo(name="[Gmail]/All Mail", delimiter="/", attributes=("\\HasNoChildren", "\\All")),
        MailboxInfo(name="[Gmail]/Sent Mail", delimiter="/", attributes=("\\HasNoChildren", "\\Sent")),
        MailboxInfo(name="[Gmail]/Trash", delimiter="/", attributes=("\\HasNoChildren", "\\Trash")),
        MailboxInfo(name="[Gmail]/Spam", delimiter="/", attributes=("\\HasNoChildren", "\\Junk")),
        MailboxInfo(name="[Gmail]/Important", delimiter="/", attributes=("\\HasNoChildren", "\\Important")),
        MailboxInfo(name="[Gmail]/Starred", delimiter="/", attributes=("\\HasNoChildren", "\\Flagged")),
    ]

    assert resolve_target_mailbox("INBOX", gmail_mailboxes, target_provider="gmail") == "INBOX"
    assert resolve_target_mailbox("Archive", gmail_mailboxes, target_provider="gmail") == "[Gmail]/All Mail"
    assert resolve_target_mailbox("Sent", gmail_mailboxes, target_provider="gmail") == "[Gmail]/Sent Mail"
    assert resolve_target_mailbox("Deleted Messages", gmail_mailboxes, target_provider="gmail") == "[Gmail]/Trash"
    assert resolve_target_mailbox("Junk", gmail_mailboxes, target_provider="gmail") == "[Gmail]/Spam"
    assert resolve_target_mailbox("Important", gmail_mailboxes, target_provider="gmail") == "[Gmail]/Important"
    assert resolve_target_mailbox("Starred", gmail_mailboxes, target_provider="gmail") == "[Gmail]/Starred"


def test_gmail_target_system_mailbox_issues_require_important_and_starred() -> None:
    from components.provider_ops import gmail_target_system_mailbox_issues

    rows = [
        {"canonical_id": "important-message", "primary_mailbox": "Important"},
        {"canonical_id": "starred-message", "primary_mailbox": "Starred"},
    ]
    base_mailboxes = [
        MailboxInfo(name="INBOX", delimiter="/", attributes=("\\HasNoChildren",)),
        MailboxInfo(name="[Gmail]/All Mail", delimiter="/", attributes=("\\HasNoChildren", "\\All")),
    ]

    issues = gmail_target_system_mailbox_issues(rows, base_mailboxes)

    assert any("required important system mailbox" in issue for issue in issues)
    assert any("required starred system mailbox" in issue for issue in issues)
    assert gmail_target_system_mailbox_issues(rows, [
        *base_mailboxes,
        MailboxInfo(name="[Gmail]/Important", delimiter="/", attributes=("\\HasNoChildren", "\\Important")),
        MailboxInfo(name="[Gmail]/Starred", delimiter="/", attributes=("\\HasNoChildren", "\\Flagged")),
    ]) == []


def test_target_folder_resolution_is_target_provider_aware() -> None:
    mailboxes = [
        MailboxInfo(name="Archive", delimiter="/", attributes=("\\HasNoChildren", "\\Archive")),
        MailboxInfo(name="All Mail", delimiter="/", attributes=("\\HasNoChildren", "\\All")),
    ]
    gmail_mailboxes = [
        MailboxInfo(name="Archive", delimiter="/", attributes=("\\HasNoChildren",)),
        MailboxInfo(name="[Gmail]/All Mail", delimiter="/", attributes=("\\HasNoChildren", "\\All")),
    ]

    assert resolve_target_mailbox("Archive", mailboxes, target_provider="imap") == "Archive"
    assert resolve_target_mailbox("Archive", mailboxes, target_provider="icloud") == "Archive"
    assert resolve_target_mailbox("Archive", gmail_mailboxes, target_provider="gmail") == "[Gmail]/All Mail"


def test_generic_target_folder_resolution_preserves_case_distinct_mailboxes() -> None:
    mailboxes = [
        MailboxInfo(name="Project", delimiter="/", attributes=("\\HasNoChildren",)),
        MailboxInfo(name="project", delimiter="/", attributes=("\\HasNoChildren",)),
    ]

    assert resolve_target_mailbox("Project", mailboxes, target_provider="imap") == "Project"
    assert resolve_target_mailbox("project", mailboxes, target_provider="imap") == "project"


def test_generic_target_folder_resolution_preserves_lowercase_special_like_physical_name() -> None:
    mailboxes = [
        MailboxInfo(name="INBOX", delimiter="/", attributes=("\\HasNoChildren",)),
        MailboxInfo(name="Sent", delimiter="/", attributes=("\\HasNoChildren", "\\Sent")),
    ]
    gmail_mailboxes = [
        MailboxInfo(name="INBOX", delimiter="/", attributes=("\\HasNoChildren",)),
        MailboxInfo(name="[Gmail]/Sent Mail", delimiter="/", attributes=("\\HasNoChildren", "\\Sent")),
    ]
    row = {
        "canonical_id": "physical-1",
        "primary_mailbox": "sent",
        "source_mailbox_paths": {"sent": ["sent"]},
    }

    assert resolve_target_mailbox("sent", mailboxes, target_provider="imap") == "sent"
    assert resolve_target_mailbox("Sent", mailboxes, target_provider="imap") == "Sent"
    assert resolve_target_mailbox("sent", gmail_mailboxes, target_provider="gmail") == "sent"
    assert resolve_target_mailbox("Sent", gmail_mailboxes, target_provider="gmail") == "[Gmail]/Sent Mail"
    assert translated_target_mailboxes_for_rows([row], mailboxes, target_provider="imap") == {"physical-1": "sent"}


def test_translated_target_mailboxes_allows_case_distinct_generic_targets() -> None:
    mailboxes = [
        MailboxInfo(name="Project", delimiter="/", attributes=("\\HasNoChildren",)),
        MailboxInfo(name="project", delimiter="/", attributes=("\\HasNoChildren",)),
    ]
    rows = [
        {
            "canonical_id": "upper",
            "primary_mailbox": "Project",
            "source_mailbox_paths": {"Project": ["Project"]},
        },
        {
            "canonical_id": "lower",
            "primary_mailbox": "project",
            "source_mailbox_paths": {"project": ["project"]},
        },
    ]

    translated = translated_target_mailboxes_for_rows(rows, mailboxes, target_provider="imap")

    assert translated == {"upper": "Project", "lower": "project"}


def test_target_match_bookkeeping_keeps_case_distinct_generic_mailboxes_separate() -> None:
    row = {
        "message_id_header": "<m1@example.com>",
        "content_sha256": hashlib.sha256(b"Message-ID: <m1@example.com>\r\n\r\nbody").hexdigest(),
        "rfc822_size": 36,
    }
    fake = StoredMessageTarget({
        "Project": [b"Message-ID: <m1@example.com>\r\n\r\nbody"],
        "project": [b"Message-ID: <m1@example.com>\r\n\r\nbody"],
    })
    used_by_mailbox: dict[str, set[bytes]] = {}

    assert consume_target_match_num(fake, "Project", row, used_by_mailbox, create_if_missing=False) == b"1"
    assert consume_target_match_num(fake, "project", row, used_by_mailbox, create_if_missing=False) == b"1"


def test_icloud_target_default_folder_resolution() -> None:
    icloud_mailboxes = [
        MailboxInfo(name="INBOX", delimiter="/", attributes=("\\HasNoChildren",)),
        MailboxInfo(name="Archive", delimiter="/", attributes=("\\HasNoChildren", "\\Archive")),
        MailboxInfo(name="Sent", delimiter="/", attributes=("\\HasNoChildren", "\\Sent")),
        MailboxInfo(name="Drafts", delimiter="/", attributes=("\\HasNoChildren", "\\Drafts")),
        MailboxInfo(name="Trash", delimiter="/", attributes=("\\HasNoChildren", "\\Trash")),
        MailboxInfo(name="Junk", delimiter="/", attributes=("\\HasNoChildren", "\\Junk")),
        MailboxInfo(name="VIP", delimiter="/", attributes=("\\HasNoChildren",)),
    ]

    assert resolve_target_mailbox("Archive", icloud_mailboxes, target_provider="icloud") == "Archive"
    assert resolve_target_mailbox("Sent", icloud_mailboxes, target_provider="icloud") == "Sent"
    assert resolve_target_mailbox("Drafts", icloud_mailboxes, target_provider="icloud") == "Drafts"
    assert resolve_target_mailbox("Deleted Messages", icloud_mailboxes, target_provider="icloud") == "Trash"
    assert resolve_target_mailbox("Junk", icloud_mailboxes, target_provider="icloud") == "Junk"


def test_offline_journal_target_mailbox_accepts_icloud_default_trash_target() -> None:
    manifest_rows = [
        {
            "canonical_id": "physical-trash",
            "primary_mailbox": "Deleted Messages",
        }
    ]
    journal_rows = [
        {
            "canonical_id": "physical-trash",
            "target_mailbox": "Trash",
            "target_account": "target@example.com",
            "status": "committed",
        }
    ]

    assert offline_journal_target_mailbox_issues(
        journal_rows,
        manifest_rows,
        target_provider="icloud",
    ) == []


def test_offline_journal_target_mailbox_defers_generic_special_use_alias() -> None:
    manifest_rows = [
        {
            "canonical_id": "physical-trash",
            "primary_mailbox": "Deleted Messages",
        }
    ]
    journal_rows = [
        {
            "canonical_id": "physical-trash",
            "target_mailbox": "Papierkorb",
            "target_account": "target@example.com",
            "status": "committed",
        }
    ]

    assert offline_journal_target_mailbox_issues(
        journal_rows,
        manifest_rows,
        target_provider="imap",
    ) == []


def test_offline_journal_target_mailbox_rejects_generic_custom_folder_mismatch() -> None:
    manifest_rows = [
        {
            "canonical_id": "custom-folder",
            "primary_mailbox": "Projects",
        }
    ]
    journal_rows = [
        {
            "canonical_id": "custom-folder",
            "target_mailbox": "Other",
            "target_account": "target@example.com",
            "status": "committed",
        }
    ]

    issues = offline_journal_target_mailbox_issues(
        journal_rows,
        manifest_rows,
        target_provider="imap",
    )

    assert any("wrong target mailbox" in issue for issue in issues)


def test_custom_folder_translation_uses_target_delimiter_and_preserves_flat_targets() -> None:
    row = {
        "source_mailbox_paths": {
            "Projects.2024": ["Projects", "2024"],
            "Clients/ACME": ["Clients", "ACME"],
        },
    }
    slash_target = [MailboxInfo(name="INBOX", delimiter="/", attributes=())]
    dot_target = [MailboxInfo(name="INBOX", delimiter=".", attributes=())]
    flat_target = [MailboxInfo(name="INBOX", delimiter="", attributes=())]

    assert translate_source_mailbox_for_target(
        row,
        "Projects.2024",
        slash_target,
        target_provider="imap",
    ) == "Projects/2024"
    assert translate_source_mailbox_for_target(
        row,
        "Clients/ACME",
        dot_target,
        target_provider="imap",
    ) == "Clients.ACME"
    assert translate_source_mailbox_for_target(
        row,
        "Projects.2024",
        flat_target,
        target_provider="imap",
    ) == "Projects.2024"
    assert translate_source_mailbox_for_target(
        row,
        "Projects.2024",
        slash_target,
        target_provider="gmail",
    ) == "Projects/2024"
    assert translate_source_mailbox_for_target(
        row,
        "Archive",
        slash_target,
        target_provider="gmail",
    ) == "Archive"


def test_gmail_target_system_folder_resolution_ignores_shadowing_user_labels() -> None:
    mailboxes = [
        MailboxInfo(name="Sent", delimiter="/", attributes=("\\HasNoChildren",)),
        MailboxInfo(name="Trash", delimiter="/", attributes=("\\HasNoChildren",)),
        MailboxInfo(name="Junk", delimiter="/", attributes=("\\HasNoChildren",)),
        MailboxInfo(name="[Gmail]/Sent Mail", delimiter="/", attributes=("\\HasNoChildren", "\\Sent")),
        MailboxInfo(name="[Gmail]/Trash", delimiter="/", attributes=("\\HasNoChildren", "\\Trash")),
        MailboxInfo(name="[Gmail]/Spam", delimiter="/", attributes=("\\HasNoChildren", "\\Junk")),
    ]

    assert resolve_target_mailbox("Sent", mailboxes, target_provider="gmail") == "[Gmail]/Sent Mail"
    assert resolve_target_mailbox("Trash", mailboxes, target_provider="gmail") == "[Gmail]/Trash"
    assert resolve_target_mailbox("Junk", mailboxes, target_provider="gmail") == "[Gmail]/Spam"


class FakeSourceImap:
    def __init__(self) -> None:
        self.selected = ""
        self.body_fetches = 0

    def capability(self):
        return "OK", [b"IMAP4rev1 X-GM-EXT-1"]

    def list(self):
        return "OK", [
            b'(\\Noselect) "/" "[Gmail]"',
            b'(\\HasNoChildren) "/" "INBOX"',
            b'(\\HasNoChildren \\All) "/" "[Gmail]/All Mail"',
        ]

    def select(self, mailbox: str, readonly: bool = False):
        self.selected = mailbox.strip('"').replace(r"\"", '"')
        if self.selected == "[Gmail]":
            return "NO", [b"not selectable"]
        return "OK", [b"1"]

    def response(self, name: str):
        return "OK", [b"777"]

    def uid(self, command: str, *args):
        if command == "search":
            return "OK", [b"1"]
        if command == "fetch":
            query = args[-1]
            labels = b"(\\Inbox \"Project A\")" if self.selected == "INBOX" else b"(\"Project A\")"
            meta = (
                b'1 (UID 1 RFC822.SIZE 36 FLAGS (\\Seen) INTERNALDATE "01-Jan-2024 00:00:00 +0000" '
                b"X-GM-MSGID 123 X-GM-THRID 456 X-GM-LABELS " + labels + b")"
            )
            if "BODY.PEEK[]" not in query:
                return "OK", [meta]
            self.body_fetches += 1
            return "OK", [(meta + b" BODY[] {36}", b"Message-ID: <m1@example.com>\r\n\r\nbody")]
        raise AssertionError(command)

    def logout(self):
        return "OK", []


class FakeGmailSourceNoExtensions(FakeSourceImap):
    def capability(self):
        return "OK", [b"IMAP4rev1"]


class FakeGmailSourceNoAllMail(FakeSourceImap):
    def list(self):
        return "OK", [b'(\\HasNoChildren) "/" "INBOX"']


class FakeGmailSourceAllMailWithoutSpecialUse(FakeSourceImap):
    def list(self):
        return "OK", [
            b'(\\HasNoChildren) "/" "INBOX"',
            b'(\\HasNoChildren) "/" "[Gmail]/All Mail"',
        ]


class FakeGmailSourceAllMailNotSelectable(FakeSourceImap):
    def select(self, mailbox: str, readonly: bool = False):
        self.selected = mailbox.strip('"').replace(r"\"", '"')
        if self.selected == "[Gmail]/All Mail":
            return "NO", [b"All Mail disabled"]
        return super().select(mailbox, readonly=readonly)


class FakeGmailEmptySource(FakeSourceImap):
    def select(self, mailbox: str, readonly: bool = False):
        self.selected = mailbox.strip('"').replace(r"\"", '"')
        return "OK", [b"0"]

    def uid(self, command: str, *args):
        if command == "search":
            return "OK", [b""]
        raise AssertionError("empty source should not fetch messages")


class FakeGmailSourceNoMsgid(FakeSourceImap):
    def uid(self, command: str, *args):
        if command == "search":
            return "OK", [b"1"]
        if command == "fetch":
            query = args[-1]
            labels = b"(\\Inbox \"Project A\")" if self.selected == "INBOX" else b"(\"Project A\")"
            meta = (
                b'1 (UID 1 RFC822.SIZE 36 FLAGS (\\Seen) INTERNALDATE "01-Jan-2024 00:00:00 +0000" '
                b"X-GM-THRID 456 X-GM-LABELS " + labels + b")"
            )
            if "BODY.PEEK[]" not in query:
                return "OK", [meta]
            self.body_fetches += 1
            return "OK", [(meta + b" BODY[] {36}", b"Message-ID: <m1@example.com>\r\n\r\nbody")]
        raise AssertionError(command)


class FakeIcloudInboxSourceImap:
    def capability(self):
        return "OK", [b"IMAP4rev1"]

    def list(self):
        return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

    def select(self, mailbox: str, readonly: bool = False):
        return "OK", [b"1"]

    def response(self, name: str):
        return "OK", [b"555"]

    def uid(self, command: str, *args):
        if command == "search":
            return "OK", [b"1"]
        if command == "fetch":
            query = args[-1]
            meta = b'1 (UID 1 RFC822.SIZE 40 FLAGS (\\Seen) INTERNALDATE "01-Jan-2024 00:00:00 +0000")'
            if "BODY.PEEK[]" not in query:
                return "OK", [meta]
            return "OK", [(meta + b" BODY[] {40}", b"Message-ID: <icloud@example.com>\r\n\r\nbody")]
        raise AssertionError(command)

    def logout(self):
        return "OK", []


class FakeIcloudVipOnlySourceImap(FakeIcloudInboxSourceImap):
    def list(self):
        return "OK", [b'(\\HasNoChildren) "/" "VIP"']

    def uid(self, command: str, *args):
        raise AssertionError("VIP should be skipped before UID commands")


class FakeNonGmailDuplicateSourceImap:
    def __init__(self) -> None:
        self.selected = ""

    def capability(self):
        return "OK", [b"IMAP4rev1"]

    def list(self):
        return "OK", [
            b'(\\HasNoChildren) "/" "INBOX"',
            b'(\\HasNoChildren) "/" "Projects"',
        ]

    def select(self, mailbox: str, readonly: bool = False):
        self.selected = mailbox.strip('"').replace(r"\"", '"')
        return "OK", [b"1"]

    def response(self, name: str):
        return "OK", [b"111" if self.selected == "INBOX" else b"222"]

    def uid(self, command: str, *args):
        if command == "search":
            return "OK", [b"1"]
        if command == "fetch":
            query = args[-1]
            meta = b'1 (UID 1 RFC822.SIZE 43 FLAGS (\\Seen) INTERNALDATE "01-Jan-2024 00:00:00 +0000")'
            if "BODY.PEEK[]" not in query:
                return "OK", [meta]
            return "OK", [(meta + b" BODY[] {43}", b"Message-ID: <copy@example.com>\r\n\r\nsame body")]
        raise AssertionError(command)

    def logout(self):
        return "OK", []


class FakeNonGmailGmailMetadataDuplicateSourceImap(FakeNonGmailDuplicateSourceImap):
    def __init__(self) -> None:
        super().__init__()
        self.fetch_queries: List[str] = []

    def capability(self):
        return "OK", [b"IMAP4rev1 X-GM-EXT-1"]

    def uid(self, command: str, *args):
        if command == "search":
            return "OK", [b"1"]
        if command == "fetch":
            query = str(args[-1])
            self.fetch_queries.append(query)
            meta = (
                b'1 (UID 1 RFC822.SIZE 43 FLAGS (\\Seen) INTERNALDATE "01-Jan-2024 00:00:00 +0000" '
                b'X-GM-MSGID 123 X-GM-THRID 456 X-GM-LABELS ("\\Inbox" "Project A"))'
            )
            if "BODY.PEEK[]" not in query:
                return "OK", [meta]
            return "OK", [(meta + b" BODY[] {43}", b"Message-ID: <copy@example.com>\r\n\r\nsame body")]
        raise AssertionError(command)


class FakeGenericVirtualViewsSourceImap(FakeNonGmailDuplicateSourceImap):
    def list(self):
        return "OK", [
            b'(\\HasNoChildren) "/" "INBOX"',
            b'(\\HasNoChildren \\All) "/" "All Mail"',
            b'(\\HasNoChildren \\Flagged) "/" "Flagged"',
        ]

    def uid(self, command: str, *args):
        return super().uid(command, *args)


class FakeGenericVirtualViewsSpecialUseReturnSourceImap(FakeGenericVirtualViewsSourceImap):
    def __init__(self) -> None:
        super().__init__()
        self.list_calls: List[tuple] = []

    def list(self, *args):
        self.list_calls.append(args)
        if args == ('""', '"*" RETURN (SPECIAL-USE)'):
            return "OK", [
                b'(\\HasNoChildren) "/" "INBOX"',
                b'(\\HasNoChildren \\All) "/" "All Mail"',
                b'(\\HasNoChildren \\Flagged) "/" "Flagged"',
            ]
        return "OK", [
            b'(\\HasNoChildren) "/" "INBOX"',
            b'(\\HasNoChildren) "/" "All Mail"',
            b'(\\HasNoChildren \\Flagged) "/" "Flagged"',
        ]


class FakeGenericFlaggedOnlySourceImap(FakeNonGmailDuplicateSourceImap):
    def list(self):
        return "OK", [b'(\\HasNoChildren \\Flagged) "/" "Flagged"']


class FakeGenericAllOnlySourceImap(FakeNonGmailDuplicateSourceImap):
    def __init__(self) -> None:
        super().__init__()
        self.fetch_queries: List[str] = []

    def list(self):
        return "OK", [b'(\\HasNoChildren \\All) "/" "Archive"']

    def uid(self, command: str, *args):
        if command == "fetch":
            self.fetch_queries.append(str(args[-1]))
        return super().uid(command, *args)


class FakeGenericAllAndFlaggedOnlySourceImap(FakeNonGmailDuplicateSourceImap):
    def __init__(self) -> None:
        super().__init__()
        self.fetch_queries_by_mailbox: dict[str, List[str]] = {}

    def list(self):
        return "OK", [
            b'(\\HasNoChildren \\All) "/" "All Mail"',
            b'(\\HasNoChildren \\Flagged) "/" "Flagged"',
        ]

    def response(self, name: str):
        return "OK", [b"333" if self.selected == "All Mail" else b"444"]

    def uid(self, command: str, *args):
        if command == "search":
            return ("OK", [b"1 2"]) if self.selected == "All Mail" else ("OK", [b"1"])
        if command == "fetch":
            query = str(args[-1])
            self.fetch_queries_by_mailbox.setdefault(self.selected, []).append(query)
            uid = str(args[0])
            if self.selected == "All Mail" and uid == "2":
                meta = b'2 (UID 2 RFC822.SIZE 45 FLAGS (\\Seen) INTERNALDATE "01-Jan-2024 00:00:00 +0000")'
                body = b"Message-ID: <unflagged@example.com>\r\n\r\nunique"
            else:
                meta = b'1 (UID 1 RFC822.SIZE 43 FLAGS (\\Flagged) INTERNALDATE "01-Jan-2024 00:00:00 +0000")'
                body = b"Message-ID: <flagged@example.com>\r\n\r\nshared"
            if "BODY.PEEK[]" not in query:
                return "OK", [meta]
            return "OK", [(meta + f" BODY[] {{{len(body)}}}".encode("ascii"), body)]
        raise AssertionError(command)


class FakeGenericInboxAndAllSourceImap:
    def __init__(self) -> None:
        self.selected = ""
        self.selected_mailboxes: List[str] = []
        self.fetch_queries_by_mailbox: dict[str, List[str]] = {}
        self.inbox_body = b"Message-ID: <inbox@example.com>\r\n\r\ninbox"
        self.archived_body = b"Message-ID: <archived@example.com>\r\n\r\narchived"

    def capability(self):
        return "OK", [b"IMAP4rev1"]

    def list(self):
        return "OK", [
            b'(\\HasNoChildren) "/" "INBOX"',
            b'(\\HasNoChildren \\All) "/" "All Mail"',
        ]

    def select(self, mailbox: str, readonly: bool = False):
        self.selected = mailbox.strip('"').replace(r"\"", '"')
        self.selected_mailboxes.append(self.selected)
        count = b"1" if self.selected == "INBOX" else b"2"
        return "OK", [count]

    def response(self, name: str):
        return "OK", [b"111" if self.selected == "INBOX" else b"222"]

    def uid(self, command: str, *args):
        if command == "search":
            return "OK", [b"1"] if self.selected == "INBOX" else [b"1 2"]
        if command == "fetch":
            query = str(args[-1])
            self.fetch_queries_by_mailbox.setdefault(self.selected, []).append(query)
            uid = str(args[0])
            body = self.inbox_body if uid == "1" else self.archived_body
            meta = (
                f'{uid} (UID {uid} RFC822.SIZE {len(body)} FLAGS (\\Seen) '
                'INTERNALDATE "01-Jan-2024 00:00:00 +0000")'
            ).encode("ascii")
            if "BODY.PEEK[]" not in query:
                return "OK", [meta]
            return "OK", [(meta + f" BODY[] {{{len(body)}}}".encode("ascii"), body)]
        raise AssertionError(command)

    def logout(self):
        return "OK", []


@contextlib.contextmanager
def _fake_source_connection(*_args, **_kwargs) -> Iterator[FakeSourceImap]:
    yield FakeSourceImap()


def test_provider_export_dedupes_gmail_labels(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    fake = FakeSourceImap()

    @contextlib.contextmanager
    def fake_source_connection(*_args, **_kwargs) -> Iterator[FakeSourceImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_source_connection):
        provider_export_account(config, account, tmp_path)

    account_dir = tmp_path / "source@example.com"
    manifest = [json.loads(line) for line in (account_dir / "manifest.jsonl").read_text().splitlines()]
    assert len(manifest) == 1
    row = manifest[0]
    assert row["canonical_id"] == "gmail-123"
    assert row["primary_mailbox"] == "INBOX"
    assert row["source_mailboxes"] == ["INBOX", "[Gmail]/All Mail"]
    assert row["gmail_labels"] == ["Project A", "\\Inbox"]
    assert (account_dir / row["eml_path"]).exists()
    assert (account_dir / row["metadata_path"]).exists()
    state = json.loads((account_dir / "export-state.json").read_text())
    assert state["canonical_messages"] == 1
    assert state["manifest_sha256"] == provider_manifest_digest(manifest)
    assert fake.body_fetches == 1


def test_rate_limiter_stop_event_aborts_throttled_wait() -> None:
    limiter = RateLimiter(1)
    limiter.wait_for(10)
    stop_event = threading.Event()
    stop_event.set()

    with pytest.raises(RuntimeError, match="stop requested"):
        limiter.wait_for(1, stop_event=stop_event, label="provider export source@example.com")


def test_provider_export_stop_event_after_throttle_prevents_body_fetch(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    source = FakeSourceImap()
    stop_event = threading.Event()

    class StopAfterWaitLimiter:
        def wait_for(self, byte_count: int) -> None:
            assert byte_count == 36
            stop_event.set()

    @contextlib.contextmanager
    def fake_source_connection(*_args, **_kwargs) -> Iterator[FakeSourceImap]:
        yield source

    with mock.patch("components.provider_ops.imap_connection", fake_source_connection):
        with pytest.raises(RuntimeError, match="stop requested"):
            provider_export_account(config, account, tmp_path, stop_event=stop_event, limiter=StopAfterWaitLimiter())

    assert source.body_fetches == 0
    assert not (tmp_path / account.source_email / "manifest.jsonl").exists()


def test_provider_export_resume_rewrites_corrupt_existing_payload(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    first_fake = FakeSourceImap()

    @contextlib.contextmanager
    def first_source_connection(*_args, **_kwargs) -> Iterator[FakeSourceImap]:
        yield first_fake

    with mock.patch("components.provider_ops.imap_connection", first_source_connection):
        provider_export_account(config, account, tmp_path)

    account_dir = tmp_path / "source@example.com"
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    eml_path = account_dir / row["eml_path"]
    original_payload = eml_path.read_bytes()
    eml_path.write_bytes(b"corrupt")
    second_fake = FakeSourceImap()

    @contextlib.contextmanager
    def second_source_connection(*_args, **_kwargs) -> Iterator[FakeSourceImap]:
        yield second_fake

    with mock.patch("components.provider_ops.imap_connection", second_source_connection):
        provider_export_account(config, account, tmp_path)

    updated_row = json.loads((account_dir / "manifest.jsonl").read_text())
    assert eml_path.read_bytes() == original_payload
    assert second_fake.body_fetches == 1
    assert updated_row["rfc822_size"] == len(original_payload)
    assert updated_row["content_sha256"] == hashlib.sha256(original_payload).hexdigest()


def test_provider_export_resume_rejects_hard_linked_existing_payload(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    first_fake = FakeSourceImap()

    @contextlib.contextmanager
    def first_source_connection(*_args, **_kwargs) -> Iterator[FakeSourceImap]:
        yield first_fake

    with mock.patch("components.provider_ops.imap_connection", first_source_connection):
        provider_export_account(config, account, tmp_path)

    account_dir = tmp_path / "source@example.com"
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    eml_path = account_dir / row["eml_path"]
    victim = tmp_path / "outside-copy.eml"
    try:
        os.link(eml_path, victim)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"hard link creation unavailable: {exc}")

    second_fake = FakeSourceChangedMetadataNoBody()

    @contextlib.contextmanager
    def second_source_connection(*_args, **_kwargs) -> Iterator[FakeSourceChangedMetadataNoBody]:
        yield second_fake

    with mock.patch("components.provider_ops.imap_connection", second_source_connection):
        with pytest.raises(RuntimeError, match="hard-linked provider file"):
            provider_export_account(config, account, tmp_path)

    assert second_fake.body_fetches == 0
    assert os.stat(eml_path).st_ino == os.stat(victim).st_ino
    assert os.stat(eml_path).st_nlink > 1


def test_provider_export_incomplete_resume_refetches_self_consistent_payload(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    eml_path = account_dir / row["eml_path"]
    source_payload = b"Message-ID: <m1@example.com>\r\n\r\nbody"
    local_payload = b"Message-ID: <m1@example.com>\r\n\r\nhack"
    eml_path.write_bytes(local_payload)
    row["content_sha256"] = hashlib.sha256(local_payload).hexdigest()
    row["rfc822_size"] = len(local_payload)
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir, complete=False)
    fake = FakeSourceImap()

    @contextlib.contextmanager
    def fake_source_connection(*_args, **_kwargs) -> Iterator[FakeSourceImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_source_connection):
        provider_export_account(config, account, tmp_path)

    updated_row = json.loads((account_dir / "manifest.jsonl").read_text())
    assert fake.body_fetches == 1
    assert eml_path.read_bytes() == source_payload
    assert updated_row["content_sha256"] == hashlib.sha256(source_payload).hexdigest()
    assert updated_row[CONTENT_BINDING_FIELD] == provider_content_binding_sha256(updated_row)


class FakeSourceChangedMetadataNoBody(FakeSourceImap):
    def uid(self, command: str, *args):
        if command == "search":
            return "OK", [b"1"]
        if command == "fetch":
            query = args[-1]
            labels = b"(\\Inbox \"Project A\")" if self.selected == "INBOX" else b"(\"Project A\")"
            meta = (
                b'1 (UID 1 RFC822.SIZE 36 FLAGS (\\Answered) INTERNALDATE "02-Jan-2024 03:04:05 +0000" '
                b"X-GM-MSGID 123 X-GM-THRID 456 X-GM-LABELS " + labels + b")"
            )
            if "BODY.PEEK[]" not in query:
                return "OK", [meta]
            raise AssertionError("resume with a valid payload should not fetch the body")
        raise AssertionError(command)


def test_provider_export_resume_refreshes_delivery_metadata_without_body_fetch(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    first_fake = FakeSourceImap()

    @contextlib.contextmanager
    def first_source_connection(*_args, **_kwargs) -> Iterator[FakeSourceImap]:
        yield first_fake

    with mock.patch("components.provider_ops.imap_connection", first_source_connection):
        provider_export_account(config, account, tmp_path)

    account_dir = tmp_path / "source@example.com"
    initial_row = json.loads((account_dir / "manifest.jsonl").read_text())
    assert initial_row["flags"] == "\\Seen"
    assert initial_row["internaldate"] == "01-Jan-2024 00:00:00 +0000"
    second_fake = FakeSourceChangedMetadataNoBody()

    @contextlib.contextmanager
    def second_source_connection(*_args, **_kwargs) -> Iterator[FakeSourceImap]:
        yield second_fake

    with mock.patch("components.provider_ops.imap_connection", second_source_connection):
        provider_export_account(config, account, tmp_path)

    updated_row = json.loads((account_dir / "manifest.jsonl").read_text())
    assert updated_row["flags"] == "\\Answered"
    assert updated_row["internaldate"] == "02-Jan-2024 03:04:05 +0000"
    assert updated_row[CONTENT_BINDING_FIELD] == provider_content_binding_sha256(updated_row)


@pytest.mark.parametrize(
    ("fake_cls", "needle"),
    [
        (FakeGmailSourceNoExtensions, "X-GM-EXT-1"),
        (FakeGmailSourceNoAllMail, "All Mail"),
        (FakeGmailSourceAllMailWithoutSpecialUse, "All Mail"),
        (FakeGmailSourceAllMailNotSelectable, "not selectable"),
    ],
)
def test_provider_export_rejects_gmail_without_required_imap_readiness(tmp_path: Path, fake_cls, needle: str) -> None:
    config = _provider_config()
    account = config.accounts[0]
    fake = fake_cls()

    @contextlib.contextmanager
    def fake_source_connection(*_args, **_kwargs):
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_source_connection):
        with pytest.raises(RuntimeError, match=needle):
            provider_export_account(config, account, tmp_path)

    assert fake.body_fetches == 0


def test_provider_export_rejects_gmail_without_full_visibility_attestation(tmp_path: Path) -> None:
    config = _provider_config()
    config.source.gmail_full_visibility_verified = False
    account = config.accounts[0]
    fake = FakeSourceImap()

    @contextlib.contextmanager
    def fake_source_connection(*_args, **_kwargs):
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_source_connection):
        with pytest.raises(RuntimeError, match="full IMAP visibility is not attested"):
            provider_export_account(config, account, tmp_path)

    state = json.loads((tmp_path / "source@example.com" / "export-state.json").read_text())
    assert state["complete"] is False


def test_provider_export_accepts_account_gmail_visibility_attestation(tmp_path: Path) -> None:
    config = _provider_config()
    config.source.gmail_full_visibility_verified = False
    account = config.accounts[0]
    account.gmail_full_visibility_verified = True
    fake = FakeSourceImap()

    @contextlib.contextmanager
    def fake_source_connection(*_args, **_kwargs):
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_source_connection):
        provider_export_account(config, account, tmp_path)

    state = json.loads((tmp_path / "source@example.com" / "export-state.json").read_text())
    assert state["complete"] is True
    assert state["gmail_full_visibility_verified"] is True


def test_provider_export_resume_preserves_complete_state_on_manifest_account_mismatch(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    before = json.loads((account_dir / "export-state.json").read_text())
    account.target_email = "other@icloud.com"

    @contextlib.contextmanager
    def fail_if_connected(*_args, **_kwargs):
        raise AssertionError("export should reject staged manifest before reconnecting")
        yield

    with mock.patch("components.provider_ops.imap_connection", fail_if_connected):
        with pytest.raises(RuntimeError, match="manifest target_account"):
            provider_export_account(config, account, tmp_path)

    after = json.loads((account_dir / "export-state.json").read_text())
    assert after == before
    assert after["complete"] is True


def test_provider_export_resume_preserves_complete_state_on_manifest_source_provider_mismatch(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["source_provider"] = "imap"
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir)
    before = json.loads((account_dir / "export-state.json").read_text())

    @contextlib.contextmanager
    def fail_if_connected(*_args, **_kwargs):
        raise AssertionError("export should reject staged source provider before reconnecting")
        yield

    with mock.patch("components.provider_ops.imap_connection", fail_if_connected):
        with pytest.raises(RuntimeError, match="manifest source_provider"):
            provider_export_account(config, account, tmp_path)

    after = json.loads((account_dir / "export-state.json").read_text())
    assert after == before
    assert after["complete"] is True


def test_provider_export_resume_rejects_stale_complete_state_before_rewrite(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    state = json.loads((account_dir / "export-state.json").read_text())
    state["manifest_sha256"] = "0" * 64
    (account_dir / "export-state.json").write_text(json.dumps(state))
    before = json.loads((account_dir / "export-state.json").read_text())

    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("source should not be contacted")):
        with pytest.raises(RuntimeError, match="export-state manifest_sha256"):
            provider_export_account(config, account, tmp_path)

    after = json.loads((account_dir / "export-state.json").read_text())
    assert after == before
    assert after["complete"] is True


def test_provider_export_resume_rejects_incomplete_state_source_endpoint_mismatch_before_rewrite(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    state = json.loads((account_dir / "export-state.json").read_text())
    state["complete"] = False
    state["source_endpoint"] = {
        "provider": "gmail",
        "host": "imap.gmail.com",
        "port": 1993,
        "ssl": True,
        "starttls": False,
    }
    state["source_endpoint_sha256"] = "0" * 64
    (account_dir / "export-state.json").write_text(json.dumps(state))
    before = json.loads((account_dir / "export-state.json").read_text())

    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("source should not be contacted")):
        with pytest.raises(RuntimeError, match="export-state source_endpoint"):
            provider_export_account(config, account, tmp_path)

    after = json.loads((account_dir / "export-state.json").read_text())
    assert after == before
    assert after["complete"] is False


def test_provider_export_rerun_prunes_stale_manifest_rows(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    assert len(load_manifest(account_dir)) == 1

    @contextlib.contextmanager
    def empty_source_connection(*_args, **_kwargs) -> Iterator[FakeGmailEmptySource]:
        yield FakeGmailEmptySource()

    with mock.patch("components.provider_ops.imap_connection", empty_source_connection):
        provider_export_account(config, account, tmp_path)

    assert (account_dir / "manifest.jsonl").read_text() == ""
    assert not list((account_dir / "messages").glob("*.eml"))
    assert not list((account_dir / "metadata").glob("*.json"))
    state = json.loads((account_dir / "export-state.json").read_text())
    assert state["complete"] is True
    assert state["canonical_messages"] == 0
    assert state["manifest_sha256"] == provider_manifest_digest([])


def test_provider_export_resume_preserves_complete_state_on_gmail_readiness_failure(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    before = json.loads((account_dir / "export-state.json").read_text())
    config.source.gmail_full_visibility_verified = False
    fake = FakeSourceImap()

    @contextlib.contextmanager
    def fake_source_connection(*_args, **_kwargs):
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_source_connection):
        with pytest.raises(RuntimeError, match="full IMAP visibility is not attested"):
            provider_export_account(config, account, tmp_path)

    after = json.loads((account_dir / "export-state.json").read_text())
    assert after == before
    assert after["complete"] is True


def test_provider_export_rejects_gmail_row_without_x_gm_msgid(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    fake = FakeGmailSourceNoMsgid()

    @contextlib.contextmanager
    def fake_source_connection(*_args, **_kwargs):
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_source_connection):
        with pytest.raises(RuntimeError, match="X-GM-MSGID"):
            provider_export_account(config, account, tmp_path)


def test_provider_export_icloud_inbox_to_generic_imap_layout(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="icloud",
            host="imap.mail.me.com",
            auth=AuthConfig(method="app_password", username="source", password="icloud-secret"),
        ),
        target=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="target@example.com", password="imap-secret"),
        ),
        accounts=[MigrationAccount(source_email="source@icloud.com", target_email="target@example.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]

    @contextlib.contextmanager
    def fake_source_connection(*_args, **_kwargs) -> Iterator[FakeIcloudInboxSourceImap]:
        yield FakeIcloudInboxSourceImap()

    with mock.patch("components.provider_ops.imap_connection", fake_source_connection):
        provider_export_account(config, account, tmp_path)

    account_dir = tmp_path / "source@icloud.com"
    manifest = [json.loads(line) for line in (account_dir / "manifest.jsonl").read_text().splitlines()]
    assert len(manifest) == 1
    assert manifest[0]["source_provider"] == "icloud"
    assert manifest[0]["primary_mailbox"] == "INBOX"
    assert manifest[0]["source_mailboxes"] == ["INBOX"]
    assert manifest[0]["gmail_msgid"] == ""


def test_provider_export_skips_icloud_vip_virtual_mailbox(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="icloud",
            host="imap.mail.me.com",
            auth=AuthConfig(method="app_password", username="source", password="icloud-secret"),
        ),
        target=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="target@example.com", password="imap-secret"),
        ),
        accounts=[MigrationAccount(source_email="source@icloud.com", target_email="target@example.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]

    @contextlib.contextmanager
    def fake_source_connection(*_args, **_kwargs) -> Iterator[FakeIcloudVipOnlySourceImap]:
        yield FakeIcloudVipOnlySourceImap()

    with mock.patch("components.provider_ops.imap_connection", fake_source_connection):
        provider_export_account(config, account, tmp_path)

    manifest_path = tmp_path / "source@icloud.com" / "manifest.jsonl"
    assert manifest_path.exists()
    assert manifest_path.read_text() == ""


def test_provider_export_preserves_non_gmail_physical_copies(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="imap-secret"),
        ),
        target=ProviderEndpoint(
            provider="icloud",
            host="imap.mail.me.com",
            auth=AuthConfig(method="app_password", username="target", password="icloud-secret"),
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@icloud.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]

    @contextlib.contextmanager
    def fake_source_connection(*_args, **_kwargs) -> Iterator[FakeNonGmailDuplicateSourceImap]:
        yield FakeNonGmailDuplicateSourceImap()

    with mock.patch("components.provider_ops.imap_connection", fake_source_connection):
        provider_export_account(config, account, tmp_path)

    account_dir = tmp_path / "source@example.com"
    manifest = [json.loads(line) for line in (account_dir / "manifest.jsonl").read_text().splitlines()]
    assert len(manifest) == 2
    assert {row["primary_mailbox"] for row in manifest} == {"INBOX", "Projects"}
    assert all(row["canonical_id"].startswith("physical-") for row in manifest)


def test_provider_export_ignores_gmail_identity_metadata_for_generic_imap(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="imap-secret"),
        ),
        target=ProviderEndpoint(
            provider="icloud",
            host="imap.mail.me.com",
            auth=AuthConfig(method="app_password", username="target", password="icloud-secret"),
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@icloud.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    fake = FakeNonGmailGmailMetadataDuplicateSourceImap()

    @contextlib.contextmanager
    def fake_source_connection(*_args, **_kwargs) -> Iterator[FakeNonGmailGmailMetadataDuplicateSourceImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_source_connection):
        provider_export_account(config, account, tmp_path)

    account_dir = tmp_path / "source@example.com"
    manifest = [json.loads(line) for line in (account_dir / "manifest.jsonl").read_text().splitlines()]
    assert len(manifest) == 2
    assert {row["primary_mailbox"] for row in manifest} == {"INBOX", "Projects"}
    assert all(row["canonical_id"].startswith("physical-") for row in manifest)
    assert all(row["gmail_msgid"] == "" for row in manifest)
    assert all(row["gmail_thrid"] == "" for row in manifest)
    assert all(row["gmail_labels"] == [] for row in manifest)
    assert all("X-GM-" not in query for query in fake.fetch_queries)


def test_provider_export_binds_non_gmail_physical_identity_to_source_account(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="imap-secret"),
        ),
        target=ProviderEndpoint(
            provider="icloud",
            host="imap.mail.me.com",
            auth=AuthConfig(method="app_password", username="target", password="icloud-secret"),
        ),
        accounts=[
            MigrationAccount(source_email="a@example.com", target_email="merged@icloud.com"),
            MigrationAccount(source_email="b@example.com", target_email="merged@icloud.com"),
        ],
        migration=MigrationSettings(target_mode="empty"),
    )

    ids_by_source = {}
    for account in config.accounts:
        @contextlib.contextmanager
        def fake_source_connection(*_args, **_kwargs) -> Iterator[FakeIcloudInboxSourceImap]:
            yield FakeIcloudInboxSourceImap()

        with mock.patch("components.provider_ops.imap_connection", fake_source_connection):
            provider_export_account(config, account, tmp_path)

        account_dir = tmp_path / account.source_email
        row = json.loads((account_dir / "manifest.jsonl").read_text())
        assert row["canonical_id"].startswith("physical-")
        ids_by_source[account.source_email] = row["canonical_id"]

    assert ids_by_source["a@example.com"] != ids_by_source["b@example.com"]


def test_provider_export_skips_generic_virtual_views_when_physical_mailbox_exists(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="imap-secret"),
        ),
        target=ProviderEndpoint(
            provider="icloud",
            host="imap.mail.me.com",
            auth=AuthConfig(method="app_password", username="target", password="icloud-secret"),
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@icloud.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]

    @contextlib.contextmanager
    def fake_source_connection(*_args, **_kwargs) -> Iterator[FakeGenericVirtualViewsSourceImap]:
        yield FakeGenericVirtualViewsSourceImap()

    with mock.patch("components.provider_ops.imap_connection", fake_source_connection):
        provider_export_account(config, account, tmp_path)

    account_dir = tmp_path / "source@example.com"
    manifest = [json.loads(line) for line in (account_dir / "manifest.jsonl").read_text().splitlines()]
    assert len(manifest) == 1
    assert manifest[0]["source_mailboxes"] == ["INBOX"]
    assert manifest[0]["primary_mailbox"] == "INBOX"
    assert all(row["canonical_id"].startswith("physical-") for row in manifest)

    target = StoredMessageTarget()

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[StoredMessageTarget]:
        yield target

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        provider_import_account(config, account, tmp_path)

    assert target.appended == ["INBOX"]


def test_provider_export_scans_generic_all_with_physical_mailbox_for_archived_only_messages(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="imap-secret"),
        ),
        target=ProviderEndpoint(
            provider="icloud",
            host="imap.mail.me.com",
            auth=AuthConfig(method="app_password", username="target", password="icloud-secret"),
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@icloud.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    source = FakeGenericInboxAndAllSourceImap()

    @contextlib.contextmanager
    def fake_source_connection(*_args, **_kwargs) -> Iterator[FakeGenericInboxAndAllSourceImap]:
        yield source

    with mock.patch("components.provider_ops.imap_connection", fake_source_connection):
        provider_export_account(config, account, tmp_path)

    account_dir = tmp_path / "source@example.com"
    manifest = [json.loads(line) for line in (account_dir / "manifest.jsonl").read_text().splitlines()]
    rows_by_message_id = {row["message_id_header"]: row for row in manifest}
    assert set(source.fetch_queries_by_mailbox) == {"INBOX", "All Mail"}
    assert set(rows_by_message_id) == {"<inbox@example.com>", "<archived@example.com>"}
    assert rows_by_message_id["<inbox@example.com>"]["source_mailboxes"] == ["INBOX"]
    assert rows_by_message_id["<archived@example.com>"]["source_mailboxes"] == ["All Mail"]


def test_provider_export_requests_special_use_attrs_before_filtering_generic_all_view(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="imap-secret"),
        ),
        target=ProviderEndpoint(
            provider="icloud",
            host="imap.mail.me.com",
            auth=AuthConfig(method="app_password", username="target", password="icloud-secret"),
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@icloud.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    source = FakeGenericVirtualViewsSpecialUseReturnSourceImap()

    @contextlib.contextmanager
    def fake_source_connection(*_args, **_kwargs) -> Iterator[FakeGenericVirtualViewsSpecialUseReturnSourceImap]:
        yield source

    with mock.patch("components.provider_ops.imap_connection", fake_source_connection):
        provider_export_account(config, account, tmp_path)

    account_dir = tmp_path / "source@example.com"
    manifest = [json.loads(line) for line in (account_dir / "manifest.jsonl").read_text().splitlines()]
    assert source.list_calls == [('""', '"*" RETURN (SPECIAL-USE)')]
    assert [row["source_mailboxes"] for row in manifest] == [["INBOX"]]
    assert not any(row["primary_mailbox"] in {"All Mail", "Flagged"} for row in manifest)


def test_provider_export_scans_generic_all_view_when_it_is_only_source_mailbox(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="imap-secret"),
        ),
        target=ProviderEndpoint(
            provider="icloud",
            host="imap.mail.me.com",
            auth=AuthConfig(method="app_password", username="target", password="icloud-secret"),
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@icloud.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    source = FakeGenericAllOnlySourceImap()

    @contextlib.contextmanager
    def fake_source_connection(*_args, **_kwargs) -> Iterator[FakeGenericAllOnlySourceImap]:
        yield source

    with mock.patch("components.provider_ops.imap_connection", fake_source_connection):
        provider_export_account(config, account, tmp_path)

    account_dir = tmp_path / "source@example.com"
    manifest = [json.loads(line) for line in (account_dir / "manifest.jsonl").read_text().splitlines()]
    assert len(manifest) == 1
    assert manifest[0]["primary_mailbox"] == "Archive"
    assert manifest[0]["source_mailboxes"] == ["Archive"]
    assert source.fetch_queries


def test_provider_export_scans_generic_all_when_only_flagged_view_is_alternative(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="imap-secret"),
        ),
        target=ProviderEndpoint(
            provider="icloud",
            host="imap.mail.me.com",
            auth=AuthConfig(method="app_password", username="target", password="icloud-secret"),
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@icloud.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    source = FakeGenericAllAndFlaggedOnlySourceImap()

    @contextlib.contextmanager
    def fake_source_connection(*_args, **_kwargs) -> Iterator[FakeGenericAllAndFlaggedOnlySourceImap]:
        yield source

    with mock.patch("components.provider_ops.imap_connection", fake_source_connection):
        provider_export_account(config, account, tmp_path)

    account_dir = tmp_path / "source@example.com"
    manifest = [json.loads(line) for line in (account_dir / "manifest.jsonl").read_text().splitlines()]
    payloads = [
        (account_dir / row["eml_path"]).read_bytes()
        for row in manifest
    ]
    assert len(manifest) == 2
    assert {row["message_id_header"] for row in manifest} == {"<flagged@example.com>", "<unflagged@example.com>"}
    assert all(row["source_mailboxes"] == ["All Mail"] for row in manifest)
    assert set(source.fetch_queries_by_mailbox) == {"All Mail"}
    assert any(b"<unflagged@example.com>" in payload for payload in payloads)


def test_provider_export_keeps_generic_flagged_only_mailbox(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="imap-secret"),
        ),
        target=ProviderEndpoint(
            provider="icloud",
            host="imap.mail.me.com",
            auth=AuthConfig(method="app_password", username="target", password="icloud-secret"),
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@icloud.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]

    @contextlib.contextmanager
    def fake_source_connection(*_args, **_kwargs) -> Iterator[FakeGenericFlaggedOnlySourceImap]:
        yield FakeGenericFlaggedOnlySourceImap()

    with mock.patch("components.provider_ops.imap_connection", fake_source_connection):
        provider_export_account(config, account, tmp_path)

    account_dir = tmp_path / "source@example.com"
    manifest = [json.loads(line) for line in (account_dir / "manifest.jsonl").read_text().splitlines()]
    assert len(manifest) == 1
    assert manifest[0]["source_mailboxes"] == ["Flagged"]
    assert manifest[0]["primary_mailbox"] == "Flagged"


def test_provider_uid_search_uses_rfc_valid_signature() -> None:
    class StrictSearchImap(FakeSourceImap):
        def __init__(self) -> None:
            super().__init__()
            self.search_args: Optional[tuple] = None

        def uid(self, command: str, *args):
            if command == "search":
                self.search_args = args
                return "OK", [b"1"]
            return super().uid(command, *args)

    fake = StrictSearchImap()

    uids, uidvalidity = fetch_all_uids_and_uidvalidity(fake, "INBOX")

    assert uids == [1]
    assert uidvalidity == "777"
    assert fake.search_args == ("ALL",)


class FakeSourceNoBodyImap(FakeSourceImap):
    def uid(self, command: str, *args):
        if command == "search":
            return "OK", [b"1"]
        if command == "fetch":
            meta = (
                b'1 (UID 1 RFC822.SIZE 36 FLAGS (\\Seen) INTERNALDATE "01-Jan-2024 00:00:00 +0000" '
                b'X-GM-MSGID 123 X-GM-THRID 456 X-GM-LABELS (\\Inbox))'
            )
            return "OK", [meta]
        raise AssertionError(command)


class FakeSourceZeroByteImap(FakeSourceImap):
    def uid(self, command: str, *args):
        if command == "search":
            return "OK", [b"1"]
        if command == "fetch":
            query = args[-1]
            meta = (
                b'1 (UID 1 RFC822.SIZE 0 FLAGS () INTERNALDATE "01-Jan-2024 00:00:00 +0000" '
                b"X-GM-MSGID 123 X-GM-THRID 456 X-GM-LABELS (\\Inbox))"
            )
            if "BODY.PEEK[]" not in query:
                return "OK", [meta]
            self.body_fetches += 1
            return "OK", [(meta + b" BODY[] {0}", b"")]
        raise AssertionError(command)


class FakeSourceUidValidityChangedImap(FakeSourceImap):
    def __init__(self) -> None:
        super().__init__()
        self.response_calls = 0

    def list(self):
        return "OK", [
            b'(\\HasNoChildren) "/" "INBOX"',
            b'(\\HasNoChildren \\All) "/" "[Gmail]/All Mail"',
        ]

    def response(self, name: str):
        self.response_calls += 1
        value = b"777" if self.response_calls == 1 else b"888"
        return "OK", [value]


class FakeSourceUidSetChangedImap(FakeSourceImap):
    def __init__(self) -> None:
        super().__init__()
        self.search_calls = 0

    def list(self):
        return "OK", [
            b'(\\HasNoChildren) "/" "INBOX"',
            b'(\\HasNoChildren \\All) "/" "[Gmail]/All Mail"',
        ]

    def uid(self, command: str, *args):
        if command == "search":
            self.search_calls += 1
            return "OK", [b"1 2"] if self.search_calls > 1 else [b"1"]
        return super().uid(command, *args)


def test_provider_export_fails_when_body_fetch_has_no_message_bytes(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]

    @contextlib.contextmanager
    def fake_source_connection(*_args, **_kwargs) -> Iterator[FakeSourceNoBodyImap]:
        yield FakeSourceNoBodyImap()

    with mock.patch("components.provider_ops.imap_connection", fake_source_connection):
        with pytest.raises(RuntimeError, match="no message bytes"):
            provider_export_account(config, account, tmp_path)


def test_provider_migrates_zero_octet_message(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    source = FakeSourceZeroByteImap()
    target = StoredMessageTarget()

    @contextlib.contextmanager
    def fake_connection(*_args, **kwargs):
        yield source if kwargs.get("role") == "source" else target

    with mock.patch("components.provider_ops.imap_connection", fake_connection):
        provider_export_account(config, account, tmp_path)
        provider_import_account(config, account, tmp_path)

    account_dir = tmp_path / "source@example.com"
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    eml_path = account_dir / row["eml_path"]

    assert row["rfc822_size"] == 0
    assert row["content_sha256"] == hashlib.sha256(b"").hexdigest()
    assert eml_path.read_bytes() == b""
    assert target.bodies_by_mailbox["INBOX"] == [b""]


def test_provider_import_matches_imaplib_append_wire_bytes(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    body = b"Message-ID: <lf-provider@example.com>\nFrom: a@example.com\nTo: b@example.com\n\nbody\n"
    account_dir = _write_provider_account_fixture(
        tmp_path,
        source=account.source_email,
        target=account.target_email,
        canonical_id="lf-provider",
        message_id="<lf-provider@example.com>",
        body=body,
        source_provider=config.source.provider,
        source_host=config.source.host,
    )
    target = ImaplibNormalizingStoredMessageTarget()

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[ImaplibNormalizingStoredMessageTarget]:
        yield target

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        provider_import_account(config, account, tmp_path)

    stored = imaplib.MapCRLF.sub(imaplib.CRLF, body)
    journal = load_import_journal(account_dir, account)
    assert target.bodies_by_mailbox["Archive"] == [stored]
    assert journal[-1]["status"] == "committed"
    assert journal[-1]["action"] == "appended"


def test_provider_validate_matches_imaplib_append_wire_bytes(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    body = b"Message-ID: <lf-validated@example.com>\nFrom: a@example.com\nTo: b@example.com\n\nbody\n"
    account_dir = _write_provider_account_fixture(
        tmp_path,
        source=account.source_email,
        target=account.target_email,
        canonical_id="lf-validated",
        message_id="<lf-validated@example.com>",
        body=body,
        source_provider=config.source.provider,
        source_host=config.source.host,
    )
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    (account_dir / "import-target@icloud.com.journal.jsonl").write_text(json.dumps(_journal_fixture(config, {
        "canonical_id": "lf-validated",
        "target_account": account.target_email,
        "target_mailbox": "Archive",
        "status": "committed",
        "content_sha256": row["content_sha256"],
        "rfc822_size": row["rfc822_size"],
        CONTENT_BINDING_FIELD: row[CONTENT_BINDING_FIELD],
    })) + "\n")
    target = ImaplibNormalizingStoredMessageTarget({
        "Archive": [imaplib.MapCRLF.sub(imaplib.CRLF, body)],
    })

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[ImaplibNormalizingStoredMessageTarget]:
        yield target

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        _name, report = provider_validate_account(config, account, tmp_path, check_target=True)

    assert report["ok"], report


def test_provider_export_fails_when_uidvalidity_changes(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]

    @contextlib.contextmanager
    def fake_source_connection(*_args, **_kwargs) -> Iterator[FakeSourceUidValidityChangedImap]:
        yield FakeSourceUidValidityChangedImap()

    with mock.patch("components.provider_ops.imap_connection", fake_source_connection):
        with pytest.raises(RuntimeError, match="UIDVALIDITY changed"):
            provider_export_account(config, account, tmp_path)


def test_provider_export_resume_fails_when_uidvalidity_changed_since_previous_run(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="icloud",
            host="imap.mail.me.com",
            auth=AuthConfig(method="app_password", username="source", password="icloud-secret"),
        ),
        target=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="target@example.com", password="imap-secret"),
        ),
        accounts=[MigrationAccount(source_email="source@icloud.com", target_email="target@example.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]

    class ChangedUidValiditySource(FakeIcloudInboxSourceImap):
        def response(self, name: str):
            return "OK", [b"999"]

    @contextlib.contextmanager
    def first_connection(*_args, **_kwargs) -> Iterator[FakeIcloudInboxSourceImap]:
        yield FakeIcloudInboxSourceImap()

    @contextlib.contextmanager
    def changed_connection(*_args, **_kwargs) -> Iterator[ChangedUidValiditySource]:
        yield ChangedUidValiditySource()

    with mock.patch("components.provider_ops.imap_connection", first_connection):
        provider_export_account(config, account, tmp_path)

    with mock.patch("components.provider_ops.imap_connection", changed_connection):
        with pytest.raises(RuntimeError, match="UIDVALIDITY changed since previous export"):
            provider_export_account(config, account, tmp_path)


def test_provider_export_fails_when_uid_set_changes(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]

    @contextlib.contextmanager
    def fake_source_connection(*_args, **_kwargs) -> Iterator[FakeSourceUidSetChangedImap]:
        yield FakeSourceUidSetChangedImap()

    with mock.patch("components.provider_ops.imap_connection", fake_source_connection):
        with pytest.raises(RuntimeError, match="UID set changed"):
            provider_export_account(config, account, tmp_path)


class FakeTargetImap:
    def __init__(
        self,
        *,
        has_existing: bool = False,
        existing_message_id: str = "<m1@example.com>",
        existing_body: bytes = b"Message-ID: <m1@example.com>\r\n\r\nbody",
        existing_mailbox: str = "Archive",
        messages_by_mailbox: Optional[dict[str, int]] = None,
        permanent_flags: Optional[str] = None,
        existing_flags: str = "\\Seen",
    ) -> None:
        self.appended: List[str] = []
        self.appended_flags: List[str] = []
        self.stored_flags: List[tuple[bytes, str, str]] = []
        self.has_existing = has_existing
        self.existing_message_id = existing_message_id
        self.existing_body = existing_body
        self.existing_mailbox = existing_mailbox
        self.existing_flags = existing_flags
        self.permanent_flags = permanent_flags
        self.messages = 0
        self.messages_by_mailbox = dict(messages_by_mailbox or {})
        self.selected_mailbox = ""
        self.fetch_queries: List[str] = []
        self.search_queries: List[tuple] = []
        self.select_readonly: List[bool] = []
        self.subscribed: List[str] = []

    def _normalize_mailbox(self, mailbox: str) -> str:
        return mailbox.strip('"').replace(r"\"", '"').replace(r"\\", "\\")

    def _message_count(self, mailbox: str) -> int:
        if mailbox in self.messages_by_mailbox:
            return self.messages_by_mailbox[mailbox]
        return self.messages if mailbox == "Archive" else 0

    def list(self):
        return "OK", [
            b'(\\HasNoChildren) "/" "INBOX"',
            b'(\\HasNoChildren \\Archive) "/" "Archive"',
        ]

    def select(self, mailbox: str, readonly: bool = False):
        self.selected_mailbox = self._normalize_mailbox(mailbox)
        self.select_readonly.append(readonly)
        return "OK", [str(self._message_count(self.selected_mailbox)).encode("ascii")]

    def create(self, mailbox: str):
        self.messages_by_mailbox.setdefault(self._normalize_mailbox(mailbox), 0)
        return "OK", [b""]

    def subscribe(self, mailbox: str):
        self.subscribed.append(self._normalize_mailbox(mailbox))
        return "OK", [b""]

    def response(self, name: str):
        if name.upper() == "PERMANENTFLAGS" and self.permanent_flags is not None:
            return "OK", [self.permanent_flags.encode("ascii")]
        return "OK", [None]

    def append(self, mailbox: str, flags: str, date_time: str, data: bytes):
        target = self._normalize_mailbox(mailbox)
        self.appended.append(target)
        self.appended_flags.append(flags)
        if flags:
            self.existing_flags = flags.strip("()")
        self.messages_by_mailbox[target] = self._message_count(target) + 1
        self.messages += 1
        self.has_existing = True
        self.existing_mailbox = target
        return "OK", [b""]

    def store(self, num: bytes, command: str, flags: str):
        self.stored_flags.append((num, command, flags))
        if flags:
            current = [flag for flag in self.existing_flags.split() if flag]
            for flag in flags.strip("()").split():
                if flag not in current:
                    current.append(flag)
            self.existing_flags = " ".join(current)
        return "OK", [b""]

    def search(self, charset: Optional[str], *criteria):
        self.search_queries.append(criteria)
        if criteria == ("ALL",):
            count = self._message_count(self.selected_mailbox)
            return "OK", [b" ".join(str(i).encode("ascii") for i in range(1, count + 1))]
        if (
            criteria == ("HEADER", "Message-ID", self.existing_message_id)
            and self.has_existing
            and self.selected_mailbox == self.existing_mailbox
        ):
            return "OK", [b"99"]
        return "OK", [b""]

    def fetch(self, num: bytes, query: str):
        self.fetch_queries.append(query)
        if "FLAGS" in query and "BODY" not in query and "RFC822" not in query:
            return "OK", [b"99 (FLAGS (" + self.existing_flags.encode("ascii") + b"))"]
        return "OK", [(
            b"99 (RFC822.SIZE "
            + str(len(self.existing_body)).encode("ascii")
            + b" FLAGS ("
            + self.existing_flags.encode("ascii")
            + b")"
            + b" BODY[] {"
            + str(len(self.existing_body)).encode("ascii")
            + b"}",
            self.existing_body,
        )]

    def logout(self):
        return "OK", []


class FakeGmailTargetImap(FakeTargetImap):
    def __init__(self, **kwargs) -> None:
        self.gmail_labels = list(kwargs.pop("gmail_labels", []))
        self.gmail_flags = str(kwargs.pop("gmail_flags", ""))
        self.gmail_msgid = str(kwargs.pop("gmail_msgid", "9001"))
        super().__init__(**kwargs)
        self.stored_labels: List[tuple[bytes, str, str]] = []

    def capability(self):
        return "OK", [b"IMAP4rev1 X-GM-EXT-1"]

    def list(self):
        return "OK", [
            b'(\\HasNoChildren) "/" "INBOX"',
            b'(\\HasNoChildren \\All) "/" "[Gmail]/All Mail"',
            b'(\\HasNoChildren \\Sent) "/" "[Gmail]/Sent Mail"',
        ]

    def _visible_existing_mailboxes(self) -> set[str]:
        visible = {self.existing_mailbox}
        for label in self.gmail_labels:
            label_key = str(label).casefold()
            if label_key in {"\\inbox", "inbox"}:
                visible.add("INBOX")
            elif label_key in {"\\sent", "sent", "[gmail]/sent mail"}:
                visible.add("[Gmail]/Sent Mail")
            elif not str(label).startswith("\\"):
                visible.add(str(label))
        return visible

    def _message_count(self, mailbox: str) -> int:
        base = super()._message_count(mailbox)
        if self.has_existing and mailbox in self._visible_existing_mailboxes():
            return max(base, 1)
        return base

    def search(self, charset: Optional[str], *criteria):
        if (
            len(criteria) == 3
            and criteria[0] == "HEADER"
            and criteria[1] == "Message-ID"
            and str(criteria[2]) == self.existing_message_id
            and self.has_existing
            and self.selected_mailbox in self._visible_existing_mailboxes()
        ):
            self.search_queries.append(criteria)
            return "OK", [b"99"]
        return super().search(charset, *criteria)

    def store(self, num: bytes, command: str, labels: str):
        self.stored_labels.append((num, command, labels))
        tokens = [
            quoted or atom
            for quoted, atom in re.findall(r'"([^"]*)"|(\\\S+|[^()\s]+)', labels.strip("()"))
            if quoted or atom
        ]
        if command == "+X-GM-LABELS":
            for label in tokens:
                if label not in self.gmail_labels:
                    self.gmail_labels.append(label)
        elif command == "+FLAGS":
            current = [flag for flag in self.gmail_flags.split() if flag]
            for flag in tokens:
                if flag not in current:
                    current.append(flag)
            self.gmail_flags = " ".join(current)
        return "OK", [b""]

    def fetch(self, num: bytes, query: str):
        if "X-GM-MSGID" in query:
            return "OK", [f"{num.decode('ascii', errors='ignore')} (X-GM-MSGID {self.gmail_msgid})".encode("ascii")]
        if "X-GM-LABELS" in query:
            labels = []
            for label in self.gmail_labels:
                if str(label).startswith("\\"):
                    labels.append(str(label))
                else:
                    labels.append(f'"{label}"')
            flags = self.gmail_flags or "\\Seen"
            return "OK", [f'99 (FLAGS ({flags}) X-GM-LABELS ({" ".join(labels)}))'.encode("ascii")]
        return super().fetch(num, query)


class FakeGmailTargetAllMailNotSelectable(FakeGmailTargetImap):
    def select(self, mailbox: str, readonly: bool = False):
        self.selected_mailbox = self._normalize_mailbox(mailbox)
        self.select_readonly.append(readonly)
        if self.selected_mailbox == "[Gmail]/All Mail":
            return "NO", [b"All Mail disabled"]
        return "OK", [str(self._message_count(self.selected_mailbox)).encode("ascii")]


class StoredMessageTarget(FakeTargetImap):
    def __init__(
        self,
        bodies_by_mailbox: Optional[dict[str, List[bytes]]] = None,
        *,
        permanent_flags: Optional[str] = None,
    ) -> None:
        super().__init__(has_existing=False, messages_by_mailbox={}, permanent_flags=permanent_flags)
        self.bodies_by_mailbox = {
            mailbox: list(bodies)
            for mailbox, bodies in (bodies_by_mailbox or {}).items()
        }
        self.flags_by_mailbox = {
            mailbox: ["\\Seen" for _body in bodies]
            for mailbox, bodies in self.bodies_by_mailbox.items()
        }

    def _message_count(self, mailbox: str) -> int:
        return len(self.bodies_by_mailbox.get(mailbox, []))

    def create(self, mailbox: str):
        self.bodies_by_mailbox.setdefault(self._normalize_mailbox(mailbox), [])
        return "OK", [b""]

    def append(self, mailbox: str, flags: str, date_time: str, data: bytes):
        target = self._normalize_mailbox(mailbox)
        self.appended.append(target)
        self.appended_flags.append(flags)
        self.bodies_by_mailbox.setdefault(target, []).append(bytes(data))
        self.flags_by_mailbox.setdefault(target, []).append(flags.strip("()") if flags else "")
        return "OK", [b""]

    def _message_id_for_body(self, body: bytes) -> str:
        for line in body.splitlines():
            if line.lower().startswith(b"message-id:"):
                return line.split(b":", 1)[1].strip().decode("utf-8")
        return ""

    def search(self, charset: Optional[str], *criteria):
        self.search_queries.append(criteria)
        bodies = self.bodies_by_mailbox.get(self.selected_mailbox, [])
        if criteria == ("ALL",):
            return "OK", [b" ".join(str(i).encode("ascii") for i in range(1, len(bodies) + 1))]
        if len(criteria) == 3 and criteria[0] == "HEADER" and criteria[1] == "Message-ID":
            wanted = str(criteria[2])
            nums = [
                str(i).encode("ascii")
                for i, body in enumerate(bodies, 1)
                if self._message_id_for_body(body) == wanted
            ]
            return "OK", [b" ".join(nums)]
        return "OK", [b""]

    def fetch(self, num: bytes, query: str):
        self.fetch_queries.append(query)
        index = int(num) - 1
        body = self.bodies_by_mailbox[self.selected_mailbox][index]
        flags = self.flags_by_mailbox.get(self.selected_mailbox, [""] * len(self.bodies_by_mailbox.get(self.selected_mailbox, [])))[index]
        if "FLAGS" in query and "BODY" not in query and "RFC822" not in query:
            return "OK", [num + b" (FLAGS (" + flags.encode("ascii") + b"))"]
        return "OK", [(
            num
            + f" (RFC822.SIZE {len(body)} FLAGS ({flags}) BODY[] {{{len(body)}}}".encode("ascii"),
            body,
        )]


class ImaplibNormalizingStoredMessageTarget(StoredMessageTarget):
    def append(self, mailbox: str, flags: str, date_time: str, data: bytes):
        return super().append(mailbox, flags, date_time, imaplib.MapCRLF.sub(imaplib.CRLF, data))


class GenericSpecialUseTarget(StoredMessageTarget):
    def list(self):
        return "OK", [
            b'(\\HasNoChildren) "/" "INBOX"',
            b'(\\HasNoChildren \\Archive) "/" "Archive"',
            b'(\\HasNoChildren \\All) "/" "All Mail"',
            b'(\\HasNoChildren \\Flagged) "/" "Flagged"',
        ]


def _default_manifest_fixture_row() -> dict:
    row = {
        "canonical_id": "gmail-123",
        "source_provider": "gmail",
        "source_account": "source@example.com",
        "target_account": "target@icloud.com",
        "primary_mailbox": "Archive",
        "message_id_header": "<m1@example.com>",
        "content_sha256": "995d8eb3156d06d7386db1ff7e5311221731ee1e67235155b521b4e71929c9df",
        "rfc822_size": 36,
        "flags": "\\Seen",
        "internaldate": "01-Jan-2024 00:00:00 +0000",
        "eml_path": "messages/gmail-123.eml",
        "metadata_path": "metadata/gmail-123.json",
    }
    row[CONTENT_BINDING_FIELD] = provider_content_binding_sha256(row)
    return row


def _write_manifest_fixture(root: Path) -> Path:
    account_dir = root / "source@example.com"
    (account_dir / "messages").mkdir(parents=True)
    (account_dir / "metadata").mkdir()
    eml = account_dir / "messages" / "gmail-123.eml"
    eml.write_bytes(b"Message-ID: <m1@example.com>\r\n\r\nbody")
    row = _default_manifest_fixture_row()
    (account_dir / "metadata" / "gmail-123.json").write_text(json.dumps(row))
    (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")
    _write_provider_export_state(account_dir)
    return account_dir


def _remove_default_manifest_fixture_artifacts(account_dir: Path) -> None:
    (account_dir / "messages" / "gmail-123.eml").unlink(missing_ok=True)
    (account_dir / "metadata" / "gmail-123.json").unlink(missing_ok=True)


def _write_provider_account_fixture(
    root: Path,
    *,
    source: str,
    target: str,
    canonical_id: str,
    message_id: str,
    body: bytes,
    source_provider: str = "imap",
    source_host: str = "mail.source.example.com",
    primary_mailbox: str = "Archive",
    flags: str = "\\Seen",
) -> Path:
    account_dir = root / source
    (account_dir / "messages").mkdir(parents=True)
    (account_dir / "metadata").mkdir()
    eml_rel = f"messages/{canonical_id}.eml"
    meta_rel = f"metadata/{canonical_id}.json"
    (account_dir / eml_rel).write_bytes(body)
    row = {
        "canonical_id": canonical_id,
        "source_provider": source_provider,
        "source_account": source,
        "target_account": target,
        "primary_mailbox": primary_mailbox,
        "message_id_header": message_id,
        "content_sha256": hashlib.sha256(body).hexdigest(),
        "rfc822_size": len(body),
        "flags": flags,
        "internaldate": "01-Jan-2024 00:00:00 +0000",
        "eml_path": eml_rel,
        "metadata_path": meta_rel,
    }
    row[CONTENT_BINDING_FIELD] = provider_content_binding_sha256(row)
    (account_dir / meta_rel).write_text(json.dumps(row))
    (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")
    _write_provider_export_state(
        account_dir,
        source=source,
        target=target,
        source_endpoint=ProviderEndpoint(provider=source_provider, host=source_host),
    )
    return account_dir


def _write_provider_export_state(
    account_dir: Path,
    *,
    source: str = "source@example.com",
    target: str = "target@icloud.com",
    canonical_messages: Optional[int] = None,
    complete: bool = True,
    source_endpoint: Optional[ProviderEndpoint] = None,
    source_username: Optional[str] = None,
    target_endpoint: Optional[ProviderEndpoint] = None,
    target_username: Optional[str] = None,
) -> None:
    manifest_rows = [
        json.loads(line)
        for line in account_dir.joinpath("manifest.jsonl").read_text().splitlines()
        if line.strip()
    ]
    for row in manifest_rows:
        _refresh_provider_binding(row)
    account_dir.joinpath("manifest.jsonl").write_text("".join(json.dumps(row) + "\n" for row in manifest_rows))
    for row in manifest_rows:
        metadata_path = row.get("metadata_path")
        if isinstance(metadata_path, str) and metadata_path:
            account_dir.joinpath(metadata_path).write_text(json.dumps(row))
    source_provider = str(manifest_rows[0].get("source_provider") or "imap") if manifest_rows else "imap"
    if target.endswith("@gmail.com"):
        target_provider = "gmail"
    elif target.endswith("@icloud.com"):
        target_provider = "icloud"
    else:
        target_provider = "imap"
    if source_endpoint is None:
        source_endpoint = ProviderEndpoint(
            provider=source_provider,
            host={
                "gmail": "imap.gmail.com",
                "icloud": "imap.mail.me.com",
            }.get(source_provider, "mail.example.com"),
        )
    if source_username is None:
        source_username = source.split("@", 1)[0] if source_provider == "icloud" and "@" in source else source
    if target_endpoint is None:
        target_endpoint = ProviderEndpoint(
            provider=target_provider,
            host={
                "gmail": "imap.gmail.com",
                "icloud": "imap.mail.me.com",
            }.get(target_provider, "mail.target.example.com"),
        )
    if target_username is None:
        target_username = target.split("@", 1)[0] if target_provider == "icloud" and "@" in target else target
    account_dir.joinpath("export-state.json").write_text(json.dumps({
        "source_account": source,
        "target_account": target,
        "source_provider": source_provider,
        "target_provider": target_provider,
        "source_endpoint": provider_endpoint_state(source_endpoint, username=source_username),
        "source_endpoint_sha256": provider_endpoint_state_digest(source_endpoint, username=source_username),
        "target_endpoint": provider_endpoint_state(target_endpoint, username=target_username),
        "target_endpoint_sha256": provider_endpoint_state_digest(target_endpoint, username=target_username),
        "gmail_full_visibility_verified": True if source_provider == "gmail" else None,
        "complete": complete,
        "canonical_messages": len(manifest_rows) if canonical_messages is None else canonical_messages,
        "manifest_sha256": provider_manifest_digest(manifest_rows),
    }))


def _refresh_provider_binding(row: dict) -> None:
    try:
        row[CONTENT_BINDING_FIELD] = provider_content_binding_sha256(row)
    except ValueError:
        pass


def _write_single_manifest_row(account_dir: Path, row: dict, *, refresh_binding: bool = True) -> None:
    if refresh_binding:
        _refresh_provider_binding(row)
    (account_dir / str(row["metadata_path"])).write_text(json.dumps(row))
    (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")


def test_provider_audit_rejects_route_tamper_with_recomputed_manifest_state(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    original_binding = row[CONTENT_BINDING_FIELD]
    row["primary_mailbox"] = "Sent"
    row["source_mailboxes"] = ["[Gmail]/Sent Mail"]
    row["source_mailbox_paths"] = {"[Gmail]/Sent Mail": ["[Gmail]", "Sent Mail"]}
    row["source_mailbox_attributes"] = {"[Gmail]/Sent Mail": ["\\Sent"]}
    row["gmail_labels"] = ["\\Sent"]
    assert row[CONTENT_BINDING_FIELD] == original_binding
    (account_dir / str(row["metadata_path"])).write_text(json.dumps(row))
    (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")
    state = json.loads((account_dir / "export-state.json").read_text())
    state["manifest_sha256"] = provider_manifest_digest([row])
    (account_dir / "export-state.json").write_text(json.dumps(state))

    _email, issues = provider_audit_account(config, account, tmp_path)

    assert any(CONTENT_BINDING_FIELD in issue for issue in issues)


def _journal_fixture(
    config: ProviderMigrationConfig,
    row: dict,
    *,
    account: Optional[MigrationAccount] = None,
) -> dict:
    account = account or config.accounts[0]
    journal_row = {**provider_target_journal_binding(config, account), **row}
    if journal_row.get("canonical_id") == "gmail-123":
        manifest_row = _default_manifest_fixture_row()
        manifest_row["source_provider"] = config.source.provider
        manifest_row["source_account"] = account.source_email
        manifest_row["target_account"] = account.target_email
        journal_row.setdefault("content_sha256", manifest_row["content_sha256"])
        journal_row.setdefault("rfc822_size", manifest_row["rfc822_size"])
        manifest_row[CONTENT_BINDING_FIELD] = provider_content_binding_sha256(manifest_row)
        journal_row.setdefault(CONTENT_BINDING_FIELD, manifest_row[CONTENT_BINDING_FIELD])
    return journal_row


def _journal_fixture_for_manifest_row(
    config: ProviderMigrationConfig,
    manifest_row: dict,
    row: dict,
    *,
    account: Optional[MigrationAccount] = None,
) -> dict:
    return _journal_fixture(config, {
        "content_sha256": manifest_row["content_sha256"],
        "rfc822_size": manifest_row["rfc822_size"],
        CONTENT_BINDING_FIELD: manifest_row[CONTENT_BINDING_FIELD],
        **row,
    }, account=account)


def _mark_manifest_source_provider(row: dict, provider: str) -> dict:
    row["source_provider"] = provider
    return row


def test_provider_import_is_idempotent_from_journal(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    _write_manifest_fixture(tmp_path)
    fake = FakeTargetImap()

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        provider_import_account(config, account, tmp_path)
        provider_import_account(config, account, tmp_path)

    assert fake.appended == ["Archive"]


def test_provider_import_stop_event_after_throttle_prevents_journal_and_append(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    fake = FakeTargetImap()
    stop_event = threading.Event()

    class StopAfterWaitLimiter:
        def wait_for(self, byte_count: int) -> None:
            assert byte_count == 36
            stop_event.set()

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        with pytest.raises(RuntimeError, match="stop requested"):
            provider_import_account(config, account, tmp_path, stop_event=stop_event, limiter=StopAfterWaitLimiter())

    assert fake.appended == []
    assert not (account_dir / "import-target@icloud.com.journal.jsonl").exists()


def test_provider_import_preserves_supported_imap_keywords(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["flags"] = "\\Seen $Forwarded NonJunk \\Recent"
    _write_single_manifest_row(account_dir, row)
    (account_dir / row["metadata_path"]).write_text(json.dumps(row))
    _write_provider_export_state(account_dir)
    fake = FakeTargetImap(permanent_flags="(\\Answered \\Flagged \\Deleted \\Seen \\Draft $Forwarded NonJunk \\*)")

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        provider_import_account(config, account, tmp_path)

    assert fake.appended == ["Archive"]
    assert fake.appended_flags == ["(\\Seen $Forwarded NonJunk)"]


def test_provider_import_allows_keywords_when_permanentflags_absent(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["flags"] = "\\Seen $Forwarded NonJunk \\Recent"
    _write_single_manifest_row(account_dir, row)
    (account_dir / row["metadata_path"]).write_text(json.dumps(row))
    _write_provider_export_state(account_dir)
    fake = FakeTargetImap()

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        provider_import_account(config, account, tmp_path)

    assert fake.appended == ["Archive"]
    assert fake.appended_flags == ["(\\Seen $Forwarded NonJunk)"]


def test_provider_import_rejects_unsupported_imap_keywords_before_pending_journal(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["flags"] = "\\Seen $Forwarded"
    _write_single_manifest_row(account_dir, row)
    (account_dir / row["metadata_path"]).write_text(json.dumps(row))
    _write_provider_export_state(account_dir)
    fake = FakeTargetImap(permanent_flags="(\\Answered \\Flagged \\Deleted \\Seen \\Draft)")

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        with pytest.raises(RuntimeError, match=r"IMAP flag/keyword\(s\): \$Forwarded"):
            provider_import_account(config, account, tmp_path)

    assert fake.appended == []
    journal = account_dir / "import-target@icloud.com.journal.jsonl"
    assert not journal.exists() or '"status": "pending"' not in journal.read_text()


def test_provider_import_merge_mode_restores_supported_imap_keywords_on_existing_match(tmp_path: Path) -> None:
    config = _provider_config(target_mode="merge")
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["flags"] = "\\Seen $Forwarded NonJunk \\Recent"
    _write_single_manifest_row(account_dir, row)
    (account_dir / row["metadata_path"]).write_text(json.dumps(row))
    _write_provider_export_state(account_dir)
    fake = FakeTargetImap(
        has_existing=True,
        existing_flags="",
        permanent_flags="(\\Answered \\Flagged \\Deleted \\Seen \\Draft $Forwarded NonJunk \\*)",
    )

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        provider_import_account(config, account, tmp_path)

    assert fake.appended == []
    assert fake.stored_flags == [(b"99", "+FLAGS.SILENT", "(\\Seen $Forwarded NonJunk)")]
    journal = load_import_journal(account_dir, account)
    assert journal[-1]["action"] == "existing"


def test_provider_validation_rejects_missing_supported_imap_keyword(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["flags"] = "\\Seen $Forwarded"
    _write_single_manifest_row(account_dir, row)
    (account_dir / row["metadata_path"]).write_text(json.dumps(row))
    _write_provider_export_state(account_dir)
    (account_dir / "import-target@icloud.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, row, {
        "canonical_id": "gmail-123",
        "target_account": "target@icloud.com",
        "target_mailbox": "Archive",
        "status": "committed",
    })) + "\n")
    fake = FakeTargetImap(
        has_existing=True,
        existing_flags="\\Seen",
        permanent_flags="(\\Answered \\Flagged \\Deleted \\Seen \\Draft $Forwarded \\*)",
    )

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        _name, report = provider_validate_account(config, account, tmp_path, check_target=True)

    assert not report["ok"]
    assert any("target IMAP flags missing" in item and "$FORWARDED" in item for item in report["failed"])


def test_provider_validation_ignores_readonly_permanentflags_when_flags_present(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["flags"] = "\\Seen \\Answered"
    _write_single_manifest_row(account_dir, row)
    (account_dir / row["metadata_path"]).write_text(json.dumps(row))
    _write_provider_export_state(account_dir)
    (account_dir / "import-target@icloud.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, row, {
        "canonical_id": "gmail-123",
        "target_account": "target@icloud.com",
        "target_mailbox": "Archive",
        "status": "committed",
    })) + "\n")
    fake = FakeTargetImap(
        has_existing=True,
        existing_flags="\\Seen \\Answered",
        permanent_flags="()",
    )

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        _name, report = provider_validate_account(config, account, tmp_path, check_target=True)

    assert report["ok"]


def test_provider_validation_empty_mode_rejects_unjournaled_target_content(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    body = (account_dir / "messages" / "gmail-123.eml").read_bytes()
    extra_body = b"Message-ID: <extra@example.com>\r\n\r\nextra"
    (account_dir / "import-target@icloud.com.journal.jsonl").write_text(json.dumps(_journal_fixture(config, {
        "canonical_id": "gmail-123",
        "target_account": "target@icloud.com",
        "target_mailbox": "Archive",
        "status": "committed",
    })) + "\n")
    fake = StoredMessageTarget({"Archive": [body, extra_body]})

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[StoredMessageTarget]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        _name, report = provider_validate_account(config, account, tmp_path, check_target=True)

    assert not report["ok"]
    assert any("target_mode=empty" in item for item in report["failed"])


def test_provider_import_many_to_one_empty_mode_accepts_journaled_merge_group_target(tmp_path: Path) -> None:
    config = _many_to_one_config()
    first, second = config.accounts
    target = first.target_email
    first_body = b"Message-ID: <a@example.com>\r\n\r\nfrom-a"
    second_body = b"Message-ID: <b@example.com>\r\n\r\nfrom-b"
    first_dir = _write_provider_account_fixture(
        tmp_path,
        source=first.source_email,
        target=target,
        canonical_id="physical-a",
        message_id="<a@example.com>",
        body=first_body,
    )
    second_dir = _write_provider_account_fixture(
        tmp_path,
        source=second.source_email,
        target=target,
        canonical_id="physical-b",
        message_id="<b@example.com>",
        body=second_body,
    )
    first_row = json.loads((first_dir / "manifest.jsonl").read_text())
    (first_dir / "import-merged@example.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, first_row, {
        "canonical_id": "physical-a",
        "target_account": target,
        "target_mailbox": "Archive",
        "status": "committed",
    }, account=first)) + "\n")
    fake = StoredMessageTarget({"Archive": [(first_dir / first_row["eml_path"]).read_bytes()]})

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[StoredMessageTarget]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        provider_import_account(config, second, tmp_path)

    assert fake.appended == ["Archive"]
    second_journal = (second_dir / "import-merged@example.com.journal.jsonl").read_text()
    assert '"canonical_id": "physical-b"' in second_journal
    assert '"action": "appended"' in second_journal


def test_provider_import_many_to_one_rejects_missing_group_committed_target_before_append(tmp_path: Path) -> None:
    config = _many_to_one_config()
    first, second = config.accounts
    target = first.target_email
    first_body = b"Message-ID: <a@example.com>\r\n\r\nfrom-a"
    second_body = b"Message-ID: <b@example.com>\r\n\r\nfrom-b"
    first_dir = _write_provider_account_fixture(
        tmp_path,
        source=first.source_email,
        target=target,
        canonical_id="physical-a",
        message_id="<a@example.com>",
        body=first_body,
    )
    _write_provider_account_fixture(
        tmp_path,
        source=second.source_email,
        target=target,
        canonical_id="physical-b",
        message_id="<b@example.com>",
        body=second_body,
    )
    first_row = json.loads((first_dir / "manifest.jsonl").read_text())
    (first_dir / "import-merged@example.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, first_row, {
        "canonical_id": "physical-a",
        "target_account": target,
        "target_mailbox": "Archive",
        "status": "committed",
    }, account=first)) + "\n")
    fake = StoredMessageTarget({"Archive": []})

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[StoredMessageTarget]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        with pytest.raises(RuntimeError, match="merge group journal says physical-a"):
            provider_import_account(config, second, tmp_path)

    assert fake.appended == []


def test_provider_import_many_to_one_rejects_group_pending_before_append(tmp_path: Path) -> None:
    config = _many_to_one_config()
    first, second = config.accounts
    target = first.target_email
    first_body = b"Message-ID: <a@example.com>\r\n\r\nfrom-a"
    second_body = b"Message-ID: <b@example.com>\r\n\r\nfrom-b"
    first_dir = _write_provider_account_fixture(
        tmp_path,
        source=first.source_email,
        target=target,
        canonical_id="physical-a",
        message_id="<a@example.com>",
        body=first_body,
    )
    _write_provider_account_fixture(
        tmp_path,
        source=second.source_email,
        target=target,
        canonical_id="physical-b",
        message_id="<b@example.com>",
        body=second_body,
    )
    first_row = json.loads((first_dir / "manifest.jsonl").read_text())
    (first_dir / "import-merged@example.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, first_row, {
        "canonical_id": "physical-a",
        "target_account": target,
        "target_mailbox": "Archive",
        "status": "pending",
    }, account=first)) + "\n")
    fake = StoredMessageTarget({"Archive": [first_body]})

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[StoredMessageTarget]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        with pytest.raises(RuntimeError, match="unresolved pending import journal row"):
            provider_import_account(config, second, tmp_path)

    assert fake.appended == []


def test_provider_import_many_to_one_rejects_cross_source_canonical_id_collision_before_target_contact(
    tmp_path: Path,
) -> None:
    config = _many_to_one_config()
    first, second = config.accounts
    target = first.target_email
    _write_provider_account_fixture(
        tmp_path,
        source=first.source_email,
        target=target,
        canonical_id="provider-shared",
        message_id="<a@example.com>",
        body=b"Message-ID: <a@example.com>\r\n\r\nfrom-a",
    )
    _write_provider_account_fixture(
        tmp_path,
        source=second.source_email,
        target=target,
        canonical_id="provider-shared",
        message_id="<b@example.com>",
        body=b"Message-ID: <b@example.com>\r\n\r\nfrom-b",
    )

    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
        with pytest.raises(RuntimeError, match="merge group canonical_id collision: provider-shared"):
            provider_import_account(config, second, tmp_path)


def test_provider_validation_many_to_one_reports_cross_source_canonical_id_collision_without_target_contact(
    tmp_path: Path,
) -> None:
    config = _many_to_one_config()
    first, second = config.accounts
    target = first.target_email
    _write_provider_account_fixture(
        tmp_path,
        source=first.source_email,
        target=target,
        canonical_id="provider-shared",
        message_id="<a@example.com>",
        body=b"Message-ID: <a@example.com>\r\n\r\nfrom-a",
    )
    _write_provider_account_fixture(
        tmp_path,
        source=second.source_email,
        target=target,
        canonical_id="provider-shared",
        message_id="<b@example.com>",
        body=b"Message-ID: <b@example.com>\r\n\r\nfrom-b",
    )

    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")) as conn:
        _name, report = provider_validate_account(config, second, tmp_path, check_target=True)

    assert conn.call_count == 0
    assert not report["ok"]
    assert any("merge group canonical_id collision: provider-shared" in item for item in report["failed"])


def test_provider_audit_many_to_one_reports_cross_source_canonical_id_collision(tmp_path: Path) -> None:
    config = _many_to_one_config()
    first, second = config.accounts
    target = first.target_email
    _write_provider_account_fixture(
        tmp_path,
        source=first.source_email,
        target=target,
        canonical_id="provider-shared",
        message_id="<a@example.com>",
        body=b"Message-ID: <a@example.com>\r\n\r\nfrom-a",
    )
    _write_provider_account_fixture(
        tmp_path,
        source=second.source_email,
        target=target,
        canonical_id="provider-shared",
        message_id="<b@example.com>",
        body=b"Message-ID: <b@example.com>\r\n\r\nfrom-b",
    )

    ok, issues = provider_audit_all(config, tmp_path, max_workers=1)

    assert not ok
    assert any("merge group canonical_id collision: provider-shared" in issue for issue in issues)


def test_provider_import_many_to_one_empty_mode_rejects_unjournaled_target_content(tmp_path: Path) -> None:
    config = _many_to_one_config()
    first, second = config.accounts
    target = first.target_email
    first_body = b"Message-ID: <a@example.com>\r\n\r\nfrom-a"
    second_body = b"Message-ID: <b@example.com>\r\n\r\nfrom-b"
    _write_provider_account_fixture(
        tmp_path,
        source=first.source_email,
        target=target,
        canonical_id="physical-a",
        message_id="<a@example.com>",
        body=first_body,
    )
    _write_provider_account_fixture(
        tmp_path,
        source=second.source_email,
        target=target,
        canonical_id="physical-b",
        message_id="<b@example.com>",
        body=second_body,
    )
    fake = StoredMessageTarget({"Archive": [first_body]})

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[StoredMessageTarget]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        with pytest.raises(RuntimeError, match="target_mode=empty"):
            provider_import_account(config, second, tmp_path)

    assert fake.appended == []


def test_provider_validation_many_to_one_empty_mode_rejects_unjournaled_group_target_content(tmp_path: Path) -> None:
    config = _many_to_one_config()
    first, second = config.accounts
    target = first.target_email
    first_body = b"Message-ID: <a@example.com>\r\n\r\nfrom-a"
    second_body = b"Message-ID: <b@example.com>\r\n\r\nfrom-b"
    extra_body = b"Message-ID: <extra@example.com>\r\n\r\nextra"
    first_dir = _write_provider_account_fixture(
        tmp_path,
        source=first.source_email,
        target=target,
        canonical_id="physical-a",
        message_id="<a@example.com>",
        body=first_body,
    )
    second_dir = _write_provider_account_fixture(
        tmp_path,
        source=second.source_email,
        target=target,
        canonical_id="physical-b",
        message_id="<b@example.com>",
        body=second_body,
    )
    first_row = json.loads((first_dir / "manifest.jsonl").read_text())
    second_row = json.loads((second_dir / "manifest.jsonl").read_text())
    (first_dir / "import-merged@example.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, first_row, {
        "canonical_id": "physical-a",
        "target_account": target,
        "target_mailbox": "Archive",
        "status": "committed",
    }, account=first)) + "\n")
    (second_dir / "import-merged@example.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, second_row, {
        "canonical_id": "physical-b",
        "target_account": target,
        "target_mailbox": "Archive",
        "status": "committed",
    }, account=second)) + "\n")
    fake = StoredMessageTarget({"Archive": [first_body, second_body, extra_body]})

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[StoredMessageTarget]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        _name, report = provider_validate_account(config, second, tmp_path, check_target=True)

    assert not report["ok"]
    assert any("target_mode=empty" in item for item in report["failed"])


def test_provider_validation_many_to_one_rejects_missing_group_committed_target(tmp_path: Path) -> None:
    config = _many_to_one_config()
    first, second = config.accounts
    target = first.target_email
    first_body = b"Message-ID: <a@example.com>\r\n\r\nfrom-a"
    second_body = b"Message-ID: <b@example.com>\r\n\r\nfrom-b"
    first_dir = _write_provider_account_fixture(
        tmp_path,
        source=first.source_email,
        target=target,
        canonical_id="physical-a",
        message_id="<a@example.com>",
        body=first_body,
    )
    second_dir = _write_provider_account_fixture(
        tmp_path,
        source=second.source_email,
        target=target,
        canonical_id="physical-b",
        message_id="<b@example.com>",
        body=second_body,
    )
    first_row = json.loads((first_dir / "manifest.jsonl").read_text())
    second_row = json.loads((second_dir / "manifest.jsonl").read_text())
    (first_dir / "import-merged@example.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, first_row, {
        "canonical_id": "physical-a",
        "target_account": target,
        "target_mailbox": "Archive",
        "status": "committed",
    }, account=first)) + "\n")
    (second_dir / "import-merged@example.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, second_row, {
        "canonical_id": "physical-b",
        "target_account": target,
        "target_mailbox": "Archive",
        "status": "committed",
    }, account=second)) + "\n")
    fake = StoredMessageTarget({"Archive": [second_body]})

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[StoredMessageTarget]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        _name, report = provider_validate_account(config, second, tmp_path, check_target=True)

    assert not report["ok"]
    assert any("merge group journal says physical-a" in item for item in report["failed"])


def test_provider_import_many_to_one_deduplicates_existing_group_message(tmp_path: Path) -> None:
    config = _many_to_one_config()
    first, second = config.accounts
    target = first.target_email
    shared_body = b"Message-ID: <shared@example.com>\r\n\r\nsame-body"
    first_dir = _write_provider_account_fixture(
        tmp_path,
        source=first.source_email,
        target=target,
        canonical_id="physical-a",
        message_id="<shared@example.com>",
        body=shared_body,
    )
    second_dir = _write_provider_account_fixture(
        tmp_path,
        source=second.source_email,
        target=target,
        canonical_id="physical-b",
        message_id="<shared@example.com>",
        body=shared_body,
    )
    first_row = json.loads((first_dir / "manifest.jsonl").read_text())
    (first_dir / "import-merged@example.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, first_row, {
        "canonical_id": "physical-a",
        "target_account": target,
        "target_mailbox": "Archive",
        "status": "committed",
    }, account=first)) + "\n")
    fake = StoredMessageTarget({"Archive": [shared_body]})

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[StoredMessageTarget]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        provider_import_account(config, second, tmp_path)
        _name, report = provider_validate_account(config, second, tmp_path, check_target=True)

    assert fake.appended == []
    assert report["ok"]
    second_journal = (second_dir / "import-merged@example.com.journal.jsonl").read_text()
    assert '"action": "existing"' in second_journal


@pytest.mark.parametrize(
    ("defect", "needle"),
    [
        ("corrupt-payload", "payload does not match manifest for merge source a@example.com"),
        ("orphan-artifacts", "invalid provider artifacts for merge source a@example.com"),
    ],
)
def test_provider_many_to_one_rejects_peer_stage_artifact_defects(
    tmp_path: Path,
    defect: str,
    needle: str,
) -> None:
    config = _many_to_one_config()
    first, second = config.accounts
    target = first.target_email
    first_body = b"Message-ID: <a@example.com>\r\n\r\nfrom-a"
    second_body = b"Message-ID: <b@example.com>\r\n\r\nfrom-b"
    first_dir = _write_provider_account_fixture(
        tmp_path,
        source=first.source_email,
        target=target,
        canonical_id="physical-a",
        message_id="<a@example.com>",
        body=first_body,
    )
    second_dir = _write_provider_account_fixture(
        tmp_path,
        source=second.source_email,
        target=target,
        canonical_id="physical-b",
        message_id="<b@example.com>",
        body=second_body,
    )
    first_row = json.loads((first_dir / "manifest.jsonl").read_text())
    second_row = json.loads((second_dir / "manifest.jsonl").read_text())
    (first_dir / "import-merged@example.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, first_row, {
        "canonical_id": "physical-a",
        "target_account": target,
        "target_mailbox": "Archive",
        "status": "committed",
    }, account=first)) + "\n")
    (second_dir / "import-merged@example.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, second_row, {
        "canonical_id": "physical-b",
        "target_account": target,
        "target_mailbox": "Archive",
        "status": "committed",
    }, account=second)) + "\n")

    if defect == "corrupt-payload":
        (first_dir / first_row["eml_path"]).write_bytes(b"corrupted")
    else:
        (first_dir / "messages" / "stale.eml").write_bytes(b"stale")
        (first_dir / "metadata" / "stale.json").write_text(json.dumps({"stale": True}))

    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
        _name, report = provider_validate_account(config, second, tmp_path, check_target=True)
        with pytest.raises(RuntimeError, match=re.escape(needle)):
            provider_import_account(config, second, tmp_path)

    assert not report["ok"]
    assert any(needle in item for item in report["failed"])


def test_provider_import_all_many_to_one_serializes_same_target_group(tmp_path: Path) -> None:
    config = _many_to_one_config()
    first, second = config.accounts
    target = first.target_email
    first_body = b"Message-ID: <a@example.com>\r\n\r\nfrom-a"
    second_body = b"Message-ID: <b@example.com>\r\n\r\nfrom-b"
    _write_provider_account_fixture(
        tmp_path,
        source=first.source_email,
        target=target,
        canonical_id="physical-a",
        message_id="<a@example.com>",
        body=first_body,
    )
    _write_provider_account_fixture(
        tmp_path,
        source=second.source_email,
        target=target,
        canonical_id="physical-b",
        message_id="<b@example.com>",
        body=second_body,
    )
    fake = StoredMessageTarget()

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[StoredMessageTarget]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        provider_import_all(config, tmp_path, max_workers=8, ignore_errors=False)

    assert fake.appended == ["Archive", "Archive"]
    assert (tmp_path / "a@example.com" / "import-merged@example.com.journal.jsonl").exists()
    assert (tmp_path / "b@example.com" / "import-merged@example.com.journal.jsonl").exists()


def test_provider_import_all_hybrid_many_to_one_keeps_distinct_target_groups(tmp_path: Path) -> None:
    config = _hybrid_many_to_one_config()
    bodies_by_source = {
        account.source_email: f"Message-ID: <{account.source_email}>\r\n\r\nfrom-{account.source_email}".encode("ascii")
        for account in config.accounts
    }
    for account in config.accounts:
        _write_provider_account_fixture(
            tmp_path,
            source=account.source_email,
            target=account.target_email,
            canonical_id=f"physical-{account.source_email[0]}",
            message_id=f"<{account.source_email}>",
            body=bodies_by_source[account.source_email],
        )
    targets = {
        "a@example.com": StoredMessageTarget(),
        "d@example.com": StoredMessageTarget(),
        "e@example.com": StoredMessageTarget(),
    }

    @contextlib.contextmanager
    def fake_target_connection(endpoint, account, *, role: str) -> Iterator[StoredMessageTarget]:
        assert role == "target"
        username, _auth = effective_auth(endpoint, account, role=role)
        yield targets[username]

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        provider_import_all(config, tmp_path, max_workers=8, ignore_errors=False)

    assert targets["a@example.com"].bodies_by_mailbox["Archive"] == [
        bodies_by_source["a@example.com"],
        bodies_by_source["b@example.com"],
        bodies_by_source["c@example.com"],
    ]
    assert targets["d@example.com"].bodies_by_mailbox["Archive"] == [bodies_by_source["d@example.com"]]
    assert targets["e@example.com"].bodies_by_mailbox["Archive"] == [bodies_by_source["e@example.com"]]
    assert (tmp_path / "a@example.com" / "import-a@example.com.journal.jsonl").exists()
    assert (tmp_path / "b@example.com" / "import-a@example.com.journal.jsonl").exists()
    assert (tmp_path / "c@example.com" / "import-a@example.com.journal.jsonl").exists()
    assert (tmp_path / "d@example.com" / "import-d@example.com.journal.jsonl").exists()
    assert (tmp_path / "e@example.com" / "import-e@example.com.journal.jsonl").exists()


def test_provider_validation_hybrid_many_to_one_checks_distinct_target_groups(tmp_path: Path) -> None:
    config = _hybrid_many_to_one_config()
    bodies_by_source = {
        account.source_email: f"Message-ID: <{account.source_email}>\r\n\r\nfrom-{account.source_email}".encode("ascii")
        for account in config.accounts
    }
    for account in config.accounts:
        account_dir = _write_provider_account_fixture(
            tmp_path,
            source=account.source_email,
            target=account.target_email,
            canonical_id=f"physical-{account.source_email[0]}",
            message_id=f"<{account.source_email}>",
            body=bodies_by_source[account.source_email],
        )
        manifest_row = json.loads((account_dir / "manifest.jsonl").read_text())
        (account_dir / f"import-{account.target_email}.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, manifest_row, {
            "canonical_id": f"physical-{account.source_email[0]}",
            "target_account": account.target_email,
            "target_mailbox": "Archive",
            "status": "committed",
        }, account=account)) + "\n")
    targets = {
        "a@example.com": StoredMessageTarget({
            "Archive": [
                bodies_by_source["a@example.com"],
                bodies_by_source["b@example.com"],
                bodies_by_source["c@example.com"],
            ],
        }),
        "d@example.com": StoredMessageTarget({"Archive": [bodies_by_source["d@example.com"]]}),
        "e@example.com": StoredMessageTarget({"Archive": [bodies_by_source["e@example.com"]]}),
    }

    @contextlib.contextmanager
    def fake_target_connection(endpoint, account, *, role: str) -> Iterator[StoredMessageTarget]:
        assert role == "target"
        username, _auth = effective_auth(endpoint, account, role=role)
        yield targets[username]

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        ok, issues = provider_validate_all(config, tmp_path, max_workers=1)

    assert ok
    assert issues == []


def test_provider_import_and_validation_many_to_one_reject_cross_source_folder_collision(tmp_path: Path) -> None:
    config = _many_to_one_config()
    first, second = config.accounts
    target = first.target_email
    first_dir = _write_provider_account_fixture(
        tmp_path,
        source=first.source_email,
        target=target,
        canonical_id="physical-a",
        message_id="<a@example.com>",
        body=b"Message-ID: <a@example.com>\r\n\r\nfrom-a",
        primary_mailbox="Projects/Foo",
    )
    second_dir = _write_provider_account_fixture(
        tmp_path,
        source=second.source_email,
        target=target,
        canonical_id="physical-b",
        message_id="<b@example.com>",
        body=b"Message-ID: <b@example.com>\r\n\r\nfrom-b",
        primary_mailbox="Projects/Foo",
    )
    first_row = json.loads((first_dir / "manifest.jsonl").read_text())
    first_row["source_mailboxes"] = ["Projects/Foo"]
    first_row["source_mailbox_paths"] = {"Projects/Foo": ["Projects", "Foo"]}
    _write_single_manifest_row(first_dir, first_row)
    _write_provider_export_state(
        first_dir,
        source=first.source_email,
        target=target,
        source_endpoint=ProviderEndpoint(provider="imap", host="mail.source.example.com"),
    )
    second_row = json.loads((second_dir / "manifest.jsonl").read_text())
    second_row["source_mailboxes"] = ["Projects/Foo"]
    second_row["source_mailbox_paths"] = {"Projects/Foo": ["Projects/Foo"]}
    _write_single_manifest_row(second_dir, second_row)
    _write_provider_export_state(
        second_dir,
        source=second.source_email,
        target=target,
        source_endpoint=ProviderEndpoint(provider="imap", host="mail.source.example.com"),
    )
    fake = StoredMessageTarget()

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[StoredMessageTarget]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        with pytest.raises(RuntimeError, match="target mailbox translation collision"):
            provider_import_account(config, second, tmp_path)
        _name, report = provider_validate_account(config, second, tmp_path, check_target=True)

    assert any("target mailbox translation collision" in item for item in report["failed"])


def test_provider_import_many_to_one_rejects_gmail_group_journal_missing_msgid(tmp_path: Path) -> None:
    config = _many_to_one_gmail_config()
    first, second = config.accounts
    target = first.target_email
    first_dir = _write_provider_account_fixture(
        tmp_path,
        source=first.source_email,
        target=target,
        canonical_id="physical-a",
        message_id="<a@example.com>",
        body=b"Message-ID: <a@example.com>\r\n\r\nfrom-a",
    )
    _write_provider_account_fixture(
        tmp_path,
        source=second.source_email,
        target=target,
        canonical_id="physical-b",
        message_id="<b@example.com>",
        body=b"Message-ID: <b@example.com>\r\n\r\nfrom-b",
    )
    first_row = json.loads((first_dir / "manifest.jsonl").read_text())
    (first_dir / "import-merged@gmail.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, first_row, {
        "canonical_id": "physical-a",
        "target_account": target,
        "target_mailbox": "[Gmail]/All Mail",
        "status": "committed",
    }, account=first)) + "\n")
    fake = FakeGmailTargetImap()

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeGmailTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        with pytest.raises(RuntimeError, match="invalid Gmail import journal"):
            provider_import_account(config, second, tmp_path)


def test_provider_import_many_to_one_gmail_dedupes_cross_label_existing_message(tmp_path: Path) -> None:
    config = _many_to_one_gmail_config()
    first, second = config.accounts
    target = first.target_email
    shared_body = b"Message-ID: <shared@example.com>\r\n\r\nsame-body"
    first_dir = _write_provider_account_fixture(
        tmp_path,
        source=first.source_email,
        target=target,
        canonical_id="physical-a",
        message_id="<shared@example.com>",
        body=shared_body,
        primary_mailbox="Archive",
    )
    second_dir = _write_provider_account_fixture(
        tmp_path,
        source=second.source_email,
        target=target,
        canonical_id="physical-b",
        message_id="<shared@example.com>",
        body=shared_body,
        primary_mailbox="INBOX",
    )
    first_row = json.loads((first_dir / "manifest.jsonl").read_text())
    (first_dir / "import-merged@gmail.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, first_row, {
        "canonical_id": "physical-a",
        "target_account": target,
        "target_mailbox": "[Gmail]/All Mail",
        "status": "committed",
        "target_gmail_msgid": "9001",
    }, account=first)) + "\n")
    fake = FakeGmailTargetImap(
        has_existing=True,
        existing_message_id="<shared@example.com>",
        existing_body=shared_body,
        existing_mailbox="[Gmail]/All Mail",
        messages_by_mailbox={"[Gmail]/All Mail": 1},
        gmail_msgid="9001",
    )

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeGmailTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        provider_import_account(config, second, tmp_path)
        _name, report = provider_validate_account(config, second, tmp_path, check_target=True)

    assert fake.appended == []
    assert report["ok"]
    assert any(command == "+X-GM-LABELS" and "\\Inbox" in labels for _num, command, labels in fake.stored_labels)
    second_journal = (second_dir / "import-merged@gmail.com.journal.jsonl").read_text()
    assert '"target_mailbox": "INBOX"' in second_journal
    assert '"target_gmail_msgid": "9001"' in second_journal


def test_provider_import_many_to_one_gmail_rejects_stale_group_target_msgid(tmp_path: Path) -> None:
    config = _many_to_one_gmail_config()
    first, second = config.accounts
    target = first.target_email
    shared_body = b"Message-ID: <shared@example.com>\r\n\r\nsame-body"
    first_dir = _write_provider_account_fixture(
        tmp_path,
        source=first.source_email,
        target=target,
        canonical_id="physical-a",
        message_id="<shared@example.com>",
        body=shared_body,
        primary_mailbox="Archive",
    )
    _write_provider_account_fixture(
        tmp_path,
        source=second.source_email,
        target=target,
        canonical_id="physical-b",
        message_id="<other@example.com>",
        body=b"Message-ID: <other@example.com>\r\n\r\nother",
        primary_mailbox="Archive",
    )
    first_row = json.loads((first_dir / "manifest.jsonl").read_text())
    (first_dir / "import-merged@gmail.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, first_row, {
        "canonical_id": "physical-a",
        "target_account": target,
        "target_mailbox": "[Gmail]/All Mail",
        "status": "committed",
        "target_gmail_msgid": "9001",
    }, account=first)) + "\n")
    fake = FakeGmailTargetImap(
        has_existing=True,
        existing_message_id="<shared@example.com>",
        existing_body=shared_body,
        existing_mailbox="[Gmail]/All Mail",
        messages_by_mailbox={"[Gmail]/All Mail": 1},
        gmail_msgid="9002",
    )

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeGmailTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        with pytest.raises(RuntimeError, match="Gmail target message 9001"):
            provider_import_account(config, second, tmp_path)


def test_provider_import_inbox_to_generic_imap_appends_to_inbox(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="icloud",
            host="imap.mail.me.com",
            auth=AuthConfig(method="app_password", username="source", password="icloud-secret"),
        ),
        target=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="target@example.com", password="imap-secret"),
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@example.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["source_provider"] = "icloud"
    row["target_account"] = "target@example.com"
    row["primary_mailbox"] = "INBOX"
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(
        account_dir,
        target="target@example.com",
        target_endpoint=ProviderEndpoint(provider="imap", host="mail.example.com"),
    )
    fake = FakeTargetImap()

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        provider_import_account(config, account, tmp_path)

    assert fake.appended == ["INBOX"]


def test_provider_import_to_gmail_strips_deleted_append_flag(tmp_path: Path) -> None:
    class RecordingGmailTarget(FakeGmailTargetImap):
        def __init__(self) -> None:
            super().__init__()
            self.append_flags: List[str] = []

        def append(self, mailbox: str, flags: str, date_time: str, data: bytes):
            self.append_flags.append(flags)
            return super().append(mailbox, flags, date_time, data)

    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="imap-secret"),
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["source_provider"] = "imap"
    row["target_account"] = "target@gmail.com"
    row["primary_mailbox"] = "INBOX"
    row["flags"] = "\\Seen \\Deleted \\Flagged"
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir, target="target@gmail.com")
    fake = RecordingGmailTarget()

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[RecordingGmailTarget]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        provider_import_account(config, account, tmp_path)

    assert fake.append_flags == ["(\\Seen \\Flagged)"]
    journal = load_import_journal(account_dir, account)
    assert journal[-1]["target_gmail_msgid"] == "9001"


def test_provider_import_to_gmail_requires_x_gm_ext_before_append(tmp_path: Path) -> None:
    class NoGmailExtensionTarget(FakeGmailTargetImap):
        def capability(self):
            return "OK", [b"IMAP4rev1"]

    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="imap-secret"),
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["source_provider"] = "imap"
    row["target_account"] = "target@gmail.com"
    row["primary_mailbox"] = "INBOX"
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir, target="target@gmail.com")
    fake = NoGmailExtensionTarget()

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[NoGmailExtensionTarget]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        with pytest.raises(RuntimeError, match="X-GM-EXT-1"):
            provider_import_account(config, account, tmp_path)

    assert fake.appended == []
    assert not (account_dir / "import-target@gmail.com.journal.jsonl").exists()


def test_provider_import_to_gmail_requires_selectable_all_mail_before_append(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="imap-secret"),
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["source_provider"] = "imap"
    row["target_account"] = "target@gmail.com"
    row["primary_mailbox"] = "INBOX"
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir, target="target@gmail.com")
    fake = FakeGmailTargetAllMailNotSelectable()

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeGmailTargetAllMailNotSelectable]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        with pytest.raises(RuntimeError, match="All Mail is not selectable"):
            provider_import_account(config, account, tmp_path)

    assert fake.appended == []
    assert not (account_dir / "import-target@gmail.com.journal.jsonl").exists()


@pytest.mark.parametrize(("primary_mailbox", "system_key"), [("Important", "important"), ("Starred", "starred")])
def test_provider_import_to_gmail_requires_important_and_starred_system_mailboxes_before_append(
    tmp_path: Path,
    primary_mailbox: str,
    system_key: str,
) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="imap-secret"),
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["source_provider"] = "imap"
    row["target_account"] = "target@gmail.com"
    row["primary_mailbox"] = primary_mailbox
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir, target="target@gmail.com")
    fake = FakeGmailTargetImap()

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeGmailTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        with pytest.raises(RuntimeError, match=f"missing required {system_key} system mailbox"):
            provider_import_account(config, account, tmp_path)

    assert fake.appended == []
    assert not (account_dir / "import-target@gmail.com.journal.jsonl").exists()


def test_provider_import_to_gmail_requires_target_visibility_attestation(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="imap-secret"),
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["source_provider"] = "imap"
    row["target_account"] = "target@gmail.com"
    row["primary_mailbox"] = "INBOX"
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir, target="target@gmail.com")
    fake = FakeGmailTargetImap()

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeGmailTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        with pytest.raises(RuntimeError, match="full IMAP visibility is not attested"):
            provider_import_account(config, account, tmp_path)

    assert fake.appended == []
    assert not (account_dir / "import-target@gmail.com.journal.jsonl").exists()


def test_provider_import_resume_uses_journaled_gmail_target_msgid(tmp_path: Path) -> None:
    class DuplicateContentGmailTarget(FakeGmailTargetImap):
        def __init__(self) -> None:
            super().__init__(messages_by_mailbox={"INBOX": 2})

        def search(self, charset: Optional[str], *criteria):
            self.search_queries.append(criteria)
            if criteria == ("ALL",):
                return "OK", [b"1 2"]
            if criteria == ("HEADER", "Message-ID", "<m1@example.com>"):
                return "OK", [b"1 2"]
            return "OK", [b""]

        def fetch(self, num: bytes, query: str):
            if "X-GM-MSGID" in query:
                gmail_msgid = b"9001" if num == b"1" else b"9002"
                return "OK", [num + b" (X-GM-MSGID " + gmail_msgid + b")"]
            if "X-GM-LABELS" in query:
                return "OK", [num + b" (FLAGS (\\Seen) X-GM-LABELS (\\Inbox))"]
            return "OK", [(num + b" (RFC822.SIZE 36 BODY[] {36}", b"Message-ID: <m1@example.com>\r\n\r\nbody")]

    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="source@example.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="merge"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["target_account"] = "target@gmail.com"
    row["primary_mailbox"] = "INBOX"
    row["gmail_labels"] = ["\\Inbox", "Project A"]
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir, target="target@gmail.com")
    (account_dir / "import-target@gmail.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, row, {
        "canonical_id": "gmail-123",
        "target_account": "target@gmail.com",
        "target_mailbox": "INBOX",
        "status": "committed",
        "target_gmail_msgid": "9002",
    })) + "\n")
    fake = DuplicateContentGmailTarget()

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[DuplicateContentGmailTarget]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        provider_import_account(config, account, tmp_path)

    assert fake.appended == []
    assert fake.stored_labels == [(b"2", "+X-GM-LABELS", '("Project A")')]


def test_provider_import_merge_fails_closed_when_journaled_gmail_msgid_missing(tmp_path: Path) -> None:
    class OnlyDifferentGmailTarget(FakeGmailTargetImap):
        def __init__(self) -> None:
            super().__init__(messages_by_mailbox={"INBOX": 1})

        def search(self, charset: Optional[str], *criteria):
            self.search_queries.append(criteria)
            if criteria == ("ALL",):
                return "OK", [b"1"]
            if criteria == ("HEADER", "Message-ID", "<m1@example.com>"):
                return "OK", [b"1"]
            return "OK", [b""]

        def fetch(self, num: bytes, query: str):
            if "X-GM-MSGID" in query:
                return "OK", [num + b" (X-GM-MSGID 9002)"]
            if "X-GM-LABELS" in query:
                return "OK", [num + b" (FLAGS (\\Seen) X-GM-LABELS (\\Inbox))"]
            return "OK", [(num + b" (RFC822.SIZE 36 BODY[] {36}", b"Message-ID: <m1@example.com>\r\n\r\nbody")]

    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="source@example.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="merge"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["target_account"] = "target@gmail.com"
    row["primary_mailbox"] = "INBOX"
    row["gmail_labels"] = ["\\Inbox", "Project A"]
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir, target="target@gmail.com")
    (account_dir / "import-target@gmail.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, row, {
        "canonical_id": "gmail-123",
        "target_account": "target@gmail.com",
        "target_mailbox": "INBOX",
        "status": "committed",
        "target_gmail_msgid": "9001",
    })) + "\n")
    fake = OnlyDifferentGmailTarget()

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[OnlyDifferentGmailTarget]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        with pytest.raises(RuntimeError, match="9001"):
            provider_import_account(config, account, tmp_path)

    assert fake.appended == []
    assert fake.stored_labels == []


def test_provider_import_translates_custom_folder_delimiter_to_target(tmp_path: Path) -> None:
    class DotDelimiterTarget(FakeTargetImap):
        def list(self):
            return "OK", [
                b'(\\HasNoChildren) "." "INBOX"',
            ]

    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="imap-secret"),
        ),
        target=ProviderEndpoint(
            provider="imap",
            host="target.example.com",
            auth=AuthConfig(method="password", username="target@example.com", password="imap-secret"),
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@example.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["source_provider"] = "imap"
    row["target_account"] = "target@example.com"
    row["primary_mailbox"] = "Projects/2024"
    row["source_mailboxes"] = ["Projects/2024"]
    row["source_mailbox_delimiters"] = {"Projects/2024": "/"}
    row["source_mailbox_paths"] = {"Projects/2024": ["Projects", "2024"]}
    (account_dir / "metadata" / "gmail-123.json").write_text(json.dumps(row))
    (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")
    _write_provider_export_state(
        account_dir,
        target="target@example.com",
        target_endpoint=ProviderEndpoint(provider="imap", host="target.example.com"),
    )
    fake = DotDelimiterTarget()

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[DotDelimiterTarget]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        provider_import_account(config, account, tmp_path)

    assert fake.appended == ["Projects.2024"]
    assert fake.subscribed == ["Projects.2024"]


def test_provider_import_subscribes_existing_target_folder_for_roundcube_visibility(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="imap-secret"),
        ),
        target=ProviderEndpoint(
            provider="imap",
            host="target.example.com",
            auth=AuthConfig(method="password", username="target@example.com", password="imap-secret"),
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@example.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["source_provider"] = "imap"
    row["target_account"] = "target@example.com"
    row["primary_mailbox"] = "Projects"
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(
        account_dir,
        target="target@example.com",
        target_endpoint=ProviderEndpoint(provider="imap", host="target.example.com"),
    )
    fake = FakeTargetImap()

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        provider_import_account(config, account, tmp_path)

    assert fake.appended == ["Projects"]
    assert fake.subscribed == ["Projects"]


def test_provider_import_rejects_ambiguous_translated_folder_collision(tmp_path: Path) -> None:
    class SlashDelimiterTarget(FakeTargetImap):
        def list(self):
            return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="imap-secret"),
        ),
        target=ProviderEndpoint(
            provider="imap",
            host="target.example.com",
            auth=AuthConfig(method="password", username="target@example.com", password="imap-secret"),
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@example.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    first = json.loads((account_dir / "manifest.jsonl").read_text())
    first["source_provider"] = "imap"
    first["target_account"] = "target@example.com"
    first["canonical_id"] = "first"
    first["primary_mailbox"] = "A/B.C"
    first["source_mailboxes"] = ["A/B.C"]
    first["source_mailbox_paths"] = {"A/B.C": ["A/B", "C"]}
    first["eml_path"] = "messages/first.eml"
    first["metadata_path"] = "metadata/first.json"
    second = dict(first)
    second["canonical_id"] = "second"
    second["primary_mailbox"] = "A.B/C"
    second["source_mailboxes"] = ["A.B/C"]
    second["source_mailbox_paths"] = {"A.B/C": ["A", "B/C"]}
    second["eml_path"] = "messages/second.eml"
    second["metadata_path"] = "metadata/second.json"
    body = (account_dir / "messages" / "gmail-123.eml").read_bytes()
    _remove_default_manifest_fixture_artifacts(account_dir)
    (account_dir / "messages" / "first.eml").write_bytes(body)
    (account_dir / "messages" / "second.eml").write_bytes(body)
    (account_dir / "metadata" / "first.json").write_text(json.dumps(first))
    (account_dir / "metadata" / "second.json").write_text(json.dumps(second))
    (account_dir / "manifest.jsonl").write_text(json.dumps(first) + "\n" + json.dumps(second) + "\n")
    _write_provider_export_state(
        account_dir,
        target="target@example.com",
        target_endpoint=ProviderEndpoint(provider="imap", host="target.example.com"),
        canonical_messages=2,
    )
    fake = SlashDelimiterTarget()

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[SlashDelimiterTarget]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        with pytest.raises(RuntimeError, match="target mailbox translation collision"):
            provider_import_account(config, account, tmp_path)

    assert fake.appended == []
    assert not (account_dir / "import-target@example.com.journal.jsonl").exists()


def test_provider_import_rejects_gmail_collision_before_label_mutation(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="imap-secret"),
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    first = json.loads((account_dir / "manifest.jsonl").read_text())
    first["source_provider"] = "imap"
    first["target_account"] = "target@gmail.com"
    first["canonical_id"] = "first"
    first["primary_mailbox"] = "A/B.C"
    first["source_mailboxes"] = ["A/B.C"]
    first["source_mailbox_paths"] = {"A/B.C": ["A/B", "C"]}
    first["gmail_labels"] = ["Project A", "\\Starred"]
    first["eml_path"] = "messages/first.eml"
    first["metadata_path"] = "metadata/first.json"
    second = dict(first)
    second["canonical_id"] = "second"
    second["primary_mailbox"] = "A.B/C"
    second["source_mailboxes"] = ["A.B/C"]
    second["source_mailbox_paths"] = {"A.B/C": ["A", "B/C"]}
    second["eml_path"] = "messages/second.eml"
    second["metadata_path"] = "metadata/second.json"
    body = (account_dir / "messages" / "gmail-123.eml").read_bytes()
    _remove_default_manifest_fixture_artifacts(account_dir)
    (account_dir / "messages" / "first.eml").write_bytes(body)
    (account_dir / "messages" / "second.eml").write_bytes(body)
    (account_dir / "metadata" / "first.json").write_text(json.dumps(first))
    (account_dir / "metadata" / "second.json").write_text(json.dumps(second))
    (account_dir / "manifest.jsonl").write_text(json.dumps(first) + "\n" + json.dumps(second) + "\n")
    _write_provider_export_state(account_dir, target="target@gmail.com", canonical_messages=2)
    fake = FakeGmailTargetImap()

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeGmailTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        with pytest.raises(RuntimeError, match="target mailbox translation collision"):
            provider_import_account(config, account, tmp_path)

    assert fake.appended == []
    assert fake.stored_labels == []
    assert not (account_dir / "import-target@gmail.com.journal.jsonl").exists()


def test_provider_import_allows_repeated_rows_from_same_translated_source_folder(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="imap-secret"),
        ),
        target=ProviderEndpoint(
            provider="imap",
            host="target.example.com",
            auth=AuthConfig(method="password", username="target@example.com", password="imap-secret"),
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@example.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    first = json.loads((account_dir / "manifest.jsonl").read_text())
    first["source_provider"] = "imap"
    first["target_account"] = "target@example.com"
    first["canonical_id"] = "first"
    first["primary_mailbox"] = "Projects.2024"
    first["source_mailboxes"] = ["Projects.2024"]
    first["source_mailbox_paths"] = {"Projects.2024": ["Projects", "2024"]}
    first["eml_path"] = "messages/first.eml"
    first["metadata_path"] = "metadata/first.json"
    second = dict(first)
    second["canonical_id"] = "second"
    second["eml_path"] = "messages/second.eml"
    second["metadata_path"] = "metadata/second.json"
    body = (account_dir / "messages" / "gmail-123.eml").read_bytes()
    _remove_default_manifest_fixture_artifacts(account_dir)
    (account_dir / "messages" / "first.eml").write_bytes(body)
    (account_dir / "messages" / "second.eml").write_bytes(body)
    (account_dir / "metadata" / "first.json").write_text(json.dumps(first))
    (account_dir / "metadata" / "second.json").write_text(json.dumps(second))
    (account_dir / "manifest.jsonl").write_text(json.dumps(first) + "\n" + json.dumps(second) + "\n")
    _write_provider_export_state(
        account_dir,
        target="target@example.com",
        target_endpoint=ProviderEndpoint(provider="imap", host="target.example.com"),
        canonical_messages=2,
    )
    fake = StoredMessageTarget()

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[StoredMessageTarget]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        provider_import_account(config, account, tmp_path)

    assert fake.appended == ["Projects/2024", "Projects/2024"]


def test_provider_import_imap_archive_to_gmail_all_mail(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="imap-secret"),
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    _mark_manifest_source_provider(row, "imap")
    row["target_account"] = "target@gmail.com"
    row["primary_mailbox"] = "Archive"
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir, target="target@gmail.com")
    fake = FakeGmailTargetImap()

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeGmailTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        provider_import_account(config, account, tmp_path)

    assert fake.appended == ["[Gmail]/All Mail"]


def test_provider_import_rejects_gmail_target_missing_required_system_mailbox(tmp_path: Path) -> None:
    class MissingSentGmailTarget(FakeGmailTargetImap):
        def list(self):
            return "OK", [
                b'(\\HasNoChildren) "/" "INBOX"',
                b'(\\HasNoChildren \\All) "/" "[Gmail]/All Mail"',
            ]

    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="imap-secret"),
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    _mark_manifest_source_provider(row, "imap")
    row["target_account"] = "target@gmail.com"
    row["primary_mailbox"] = "Sent"
    row["gmail_labels"] = ["\\Sent"]
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir, target="target@gmail.com")
    fake = MissingSentGmailTarget()

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[MissingSentGmailTarget]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        with pytest.raises(RuntimeError, match="missing required sent system mailbox"):
            provider_import_account(config, account, tmp_path)

    assert fake.appended == []


def test_gmail_label_restore_filters_system_labels() -> None:
    row = {
        "gmail_labels": ["\\Inbox", "\\AllMail", "Project A", "[Gmail]/All Mail", "Team Blue", "\\Important", "Important", "Starred", "Project A"],
    }

    assert gmail_labels_for_restore(row, "INBOX") == ["Important", "Project A", "Team Blue"]


def test_gmail_label_restore_preserves_secondary_system_labels() -> None:
    row = {
        "gmail_labels": ["\\Sent", "\\Inbox", "Project A"],
    }

    assert gmail_labels_for_restore(row, "[Gmail]/Sent Mail") == ["\\Inbox", "Project A"]
    assert gmail_labels_for_restore(row, "INBOX") == ["Project A"]


def test_gmail_label_restore_uses_target_special_use_attributes() -> None:
    row = {
        "gmail_labels": ["\\Trash", "Project A"],
    }
    target_mailboxes = [
        MailboxInfo(name="[Gmail]/Papierkorb", delimiter="/", attributes=("\\HasNoChildren", "\\Trash")),
    ]

    assert gmail_labels_for_restore(row, "[Gmail]/Papierkorb", target_mailboxes) == ["Project A"]


def test_provider_import_to_gmail_restores_custom_labels(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="source@example.com", password="gmail-token"),
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    _mark_manifest_source_provider(row, "gmail")
    row["target_account"] = "target@gmail.com"
    row["primary_mailbox"] = "INBOX"
    row["gmail_labels"] = ["\\Inbox", "Project A", "Team/Blue", "[Gmail]/All Mail"]
    (account_dir / "metadata" / "gmail-123.json").write_text(json.dumps(row))
    (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")
    _write_provider_export_state(account_dir, target="target@gmail.com")
    fake = FakeGmailTargetImap()

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeGmailTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        provider_import_account(config, account, tmp_path)

    assert fake.appended == ["INBOX"]
    assert fake.stored_labels == [(b"99", "+X-GM-LABELS", '("Project A" "Team/Blue")')]
    journal = load_import_journal(account_dir, account)
    assert journal[-1]["status"] == "committed"


def test_provider_import_to_gmail_restores_important_without_moving_from_inbox(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="source@example.com", password="gmail-token"),
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    _mark_manifest_source_provider(row, "gmail")
    row["target_account"] = "target@gmail.com"
    row["primary_mailbox"] = "INBOX"
    row["gmail_labels"] = ["\\Inbox", "Important"]
    (account_dir / "metadata" / "gmail-123.json").write_text(json.dumps(row))
    (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")
    _write_provider_export_state(account_dir, target="target@gmail.com")
    fake = FakeGmailTargetImap()

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeGmailTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        provider_import_account(config, account, tmp_path)

    assert fake.appended == ["INBOX"]
    assert fake.stored_labels == [(b"99", "+X-GM-LABELS", '("Important")')]


def test_provider_import_to_gmail_restores_important_from_flags_without_append_flag(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="source@example.com", password="gmail-token"),
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    _mark_manifest_source_provider(row, "gmail")
    row["target_account"] = "target@gmail.com"
    row["primary_mailbox"] = "INBOX"
    row["gmail_labels"] = ["\\Inbox"]
    row["flags"] = "\\Seen \\Important"
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir, target="target@gmail.com")
    fake = FakeGmailTargetImap()

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeGmailTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        provider_import_account(config, account, tmp_path)

    assert fake.appended == ["INBOX"]
    assert fake.stored_labels == [(b"99", "+X-GM-LABELS", '("Important")')]


def test_provider_import_to_gmail_restores_secondary_system_label(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="source@example.com", password="gmail-token"),
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    _mark_manifest_source_provider(row, "gmail")
    row["target_account"] = "target@gmail.com"
    row["primary_mailbox"] = "Sent"
    row["gmail_labels"] = ["\\Sent", "\\Inbox", "Project A"]
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir, target="target@gmail.com")
    fake = FakeGmailTargetImap()

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeGmailTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        provider_import_account(config, account, tmp_path)

    assert fake.appended == ["[Gmail]/Sent Mail"]
    assert fake.stored_labels == [(b"99", "+X-GM-LABELS", '(\\Inbox "Project A")')]


def test_provider_import_empty_mode_allows_restored_secondary_system_view_on_rerun(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="source@example.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["source_provider"] = "gmail"
    row["target_account"] = "target@gmail.com"
    row["primary_mailbox"] = "Sent"
    row["gmail_labels"] = ["\\Sent", "\\Inbox"]
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir, target="target@gmail.com")
    (account_dir / "import-target@gmail.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, row, {
        "canonical_id": "gmail-123",
        "target_account": "target@gmail.com",
        "target_mailbox": "[Gmail]/Sent Mail",
        "status": "committed",
        "target_gmail_msgid": "9001",
    })) + "\n")

    class MultiViewGmailTarget(FakeGmailTargetImap):
        def list(self):
            return "OK", [
                b'(\\HasNoChildren) "/" "INBOX"',
                b'(\\HasNoChildren \\All) "/" "[Gmail]/All Mail"',
                b'(\\HasNoChildren \\Sent) "/" "[Gmail]/Sent Mail"',
            ]

        def _message_count(self, mailbox: str) -> int:
            return 1 if mailbox in {"INBOX", "[Gmail]/All Mail", "[Gmail]/Sent Mail"} else 0

        def search(self, charset: Optional[str], *criteria):
            self.search_queries.append(criteria)
            if self.selected_mailbox in {"INBOX", "[Gmail]/All Mail", "[Gmail]/Sent Mail"}:
                if criteria == ("ALL",):
                    return "OK", [b"99"]
                if criteria == ("HEADER", "Message-ID", "<m1@example.com>"):
                    return "OK", [b"99"]
            return "OK", [b""]

        def fetch(self, num: bytes, query: str):
            if "X-GM-MSGID" in query:
                return "OK", [b"99 (X-GM-MSGID 9001)"]
            if "X-GM-LABELS" in query:
                return "OK", [b"99 (FLAGS (\\Seen) X-GM-LABELS (\\Sent \\Inbox))"]
            return "OK", [(b"99 (RFC822.SIZE 36 BODY[] {36}", b"Message-ID: <m1@example.com>\r\n\r\nbody")]

    fake = MultiViewGmailTarget()

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[MultiViewGmailTarget]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        provider_import_account(config, account, tmp_path)

    assert fake.appended == []


def test_provider_import_to_gmail_restores_starred_as_flag_not_plain_label(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="source@example.com", password="gmail-token"),
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    _mark_manifest_source_provider(row, "gmail")
    row["target_account"] = "target@gmail.com"
    row["primary_mailbox"] = "INBOX"
    row["gmail_labels"] = ["\\Inbox", "Starred", "Project A"]
    (account_dir / "metadata" / "gmail-123.json").write_text(json.dumps(row))
    (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")
    _write_provider_export_state(account_dir, target="target@gmail.com")
    fake = FakeGmailTargetImap()

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeGmailTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        provider_import_account(config, account, tmp_path)

    assert fake.appended == ["INBOX"]
    assert fake.stored_labels == [
        (b"99", "+X-GM-LABELS", '("Project A")'),
        (b"99", "+FLAGS", "(\\Flagged)"),
    ]


def test_restore_gmail_labels_can_match_without_message_id() -> None:
    fake = FakeGmailTargetImap(messages_by_mailbox={"INBOX": 1})
    row = {
        "canonical_id": "m",
        "gmail_labels": ["Project A"],
        "message_id_header": "",
        "content_sha256": "995d8eb3156d06d7386db1ff7e5311221731ee1e67235155b521b4e71929c9df",
        "rfc822_size": 36,
    }

    restore_gmail_labels(fake, "INBOX", row)

    assert fake.stored_labels == [(b"1", "+X-GM-LABELS", '("Project A")')]


def test_restore_gmail_labels_quotes_unknown_backslash_labels() -> None:
    fake = FakeGmailTargetImap(has_existing=True, existing_mailbox="INBOX", messages_by_mailbox={"INBOX": 1})
    row = {
        "canonical_id": "m",
        "gmail_labels": ["\\Bad Label", "Project A"],
        "message_id_header": "<m1@example.com>",
        "content_sha256": "995d8eb3156d06d7386db1ff7e5311221731ee1e67235155b521b4e71929c9df",
        "rfc822_size": 36,
    }

    restore_gmail_labels(fake, "INBOX", row)

    assert fake.stored_labels == [(b"99", "+X-GM-LABELS", '("\\\\Bad Label" "Project A")')]


def test_restore_gmail_labels_updates_only_one_matching_target_message() -> None:
    class DuplicateGmailTarget(FakeGmailTargetImap):
        def search(self, charset: Optional[str], *criteria):
            self.search_queries.append(criteria)
            if criteria == ("HEADER", "Message-ID", self.existing_message_id):
                return "OK", [b"1 2"]
            if criteria == ("ALL",):
                return "OK", [b"1 2"]
            return "OK", [b""]

        def fetch(self, num: bytes, query: str):
            if "X-GM-LABELS" in query:
                return super().fetch(num, query)
            return "OK", [(num + b" (RFC822.SIZE 36 BODY[] {36}", b"Message-ID: <m1@example.com>\r\n\r\nbody")]

    fake = DuplicateGmailTarget(has_existing=True, existing_mailbox="INBOX", messages_by_mailbox={"INBOX": 2})
    row = {"canonical_id": "m", "gmail_labels": ["Project A"], "message_id_header": "<m1@example.com>"}

    restore_gmail_labels(fake, "INBOX", row)

    assert fake.stored_labels == [(b"1", "+X-GM-LABELS", '("Project A")')]


def test_restore_gmail_starred_flag_uses_selected_target_message() -> None:
    fake = FakeGmailTargetImap(has_existing=True, existing_mailbox="INBOX", messages_by_mailbox={"INBOX": 2})
    row = {"canonical_id": "m", "gmail_labels": ["\\Starred"], "message_id_header": "<m1@example.com>"}

    restore_gmail_starred_flag(fake, "INBOX", row, target_num=b"2")

    assert fake.stored_labels == [(b"2", "+FLAGS", "(\\Flagged)")]


def test_restore_gmail_labels_requires_target_match() -> None:
    fake = FakeGmailTargetImap()

    with pytest.raises(RuntimeError, match="cannot find target message"):
        restore_gmail_labels(fake, "INBOX", {"canonical_id": "m", "gmail_labels": ["Project A"]})


def test_provider_import_rejects_manifest_paths_outside_export_dir(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["eml_path"] = "../secret.eml"
    (tmp_path / "secret.eml").write_bytes(b"Message-ID: <leak@example.com>\r\n\r\nsecret")
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir)
    fake = FakeTargetImap()

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        with pytest.raises(RuntimeError, match="unsafe eml_path"):
            provider_import_account(config, account, tmp_path)


def test_provider_rejects_manifest_artifacts_outside_canonical_roots(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from verify_export import verify_account

    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    old_eml = account_dir / row["eml_path"]
    old_metadata = account_dir / row["metadata_path"]
    (account_dir / "payload.bin").write_bytes(old_eml.read_bytes())
    old_eml.unlink()
    old_metadata.unlink()
    row["eml_path"] = "payload.bin"
    row["metadata_path"] = "sidecar.dat"
    _refresh_provider_binding(row)
    (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")
    (account_dir / "sidecar.dat").write_text(json.dumps(row))
    _write_provider_export_state(account_dir)

    _name, audit_issues = provider_audit_account(config, account, tmp_path)
    _name, report = provider_validate_account(config, account, tmp_path, check_target=False)
    stats = verify_account(account_dir)
    output = capsys.readouterr().out

    assert any("invalid eml_path layout" in issue for issue in audit_issues)
    assert any("invalid metadata_path layout" in issue for issue in audit_issues)
    assert any("invalid eml_path layout" in issue for issue in report["failed"])
    assert any("invalid metadata_path layout" in issue for issue in report["failed"])
    assert stats["errors"] >= 1
    assert "invalid eml_path layout" in output
    assert "invalid metadata_path layout" in output

    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
        with pytest.raises(RuntimeError, match="invalid metadata_path layout|invalid eml_path layout"):
            provider_import_account(config, account, tmp_path)


def test_provider_import_rejects_duplicate_manifest_identity(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    duplicate = dict(row)
    duplicate["primary_mailbox"] = "INBOX"
    (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n" + json.dumps(duplicate) + "\n")

    with pytest.raises(RuntimeError, match="duplicate manifest identity"):
        provider_import_account(config, account, tmp_path)


def test_provider_import_rejects_incomplete_export_state(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    (account_dir / "export-state.json").write_text(json.dumps({"complete": False}))

    with pytest.raises(RuntimeError, match="export-state is not complete"):
        provider_import_account(config, account, tmp_path)


def test_provider_import_rejects_mismatched_export_state_before_target_connect(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    _write_provider_export_state(account_dir, target="other@icloud.com")

    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
        with pytest.raises(RuntimeError, match="export-state target_account"):
            provider_import_account(config, account, tmp_path)

    _write_provider_export_state(account_dir)
    state = json.loads((account_dir / "export-state.json").read_text())
    state["target_provider"] = "gmail"
    (account_dir / "export-state.json").write_text(json.dumps(state))
    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
        with pytest.raises(RuntimeError, match="export-state target_provider"):
            provider_import_account(config, account, tmp_path)

    _write_provider_export_state(
        account_dir,
        source_endpoint=ProviderEndpoint(provider="gmail", host="imap.gmail.com", port=1993),
    )
    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
        with pytest.raises(RuntimeError, match="export-state source_endpoint"):
            provider_import_account(config, account, tmp_path)

    _write_provider_export_state(
        account_dir,
        target_endpoint=ProviderEndpoint(provider="icloud", host="imap.mail.me.com", port=1993),
    )
    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
        with pytest.raises(RuntimeError, match="export-state target_endpoint"):
            provider_import_account(config, account, tmp_path)

    _write_provider_export_state(account_dir)
    state = json.loads((account_dir / "export-state.json").read_text())
    state["source_endpoint_sha256"] = "0" * 64
    (account_dir / "export-state.json").write_text(json.dumps(state))
    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
        with pytest.raises(RuntimeError, match="export-state source_endpoint_sha256"):
            provider_import_account(config, account, tmp_path)

    _write_provider_export_state(account_dir, canonical_messages=2)
    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
        with pytest.raises(RuntimeError, match="export-state canonical_messages"):
            provider_import_account(config, account, tmp_path)

    _write_provider_export_state(account_dir)
    state = json.loads((account_dir / "export-state.json").read_text())
    state["canonical_messages"] = False
    (account_dir / "export-state.json").write_text(json.dumps(state))
    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
        with pytest.raises(RuntimeError, match="export-state canonical_messages"):
            provider_import_account(config, account, tmp_path)

    _write_provider_export_state(account_dir)
    state = json.loads((account_dir / "export-state.json").read_text())
    state["canonical_messages"] = True
    (account_dir / "export-state.json").write_text(json.dumps(state))
    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
        with pytest.raises(RuntimeError, match="export-state canonical_messages"):
            provider_import_account(config, account, tmp_path)

    _write_provider_export_state(account_dir)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["primary_mailbox"] = "INBOX"
    _refresh_provider_binding(row)
    (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")
    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
        with pytest.raises(RuntimeError, match="export-state manifest_sha256"):
            provider_import_account(config, account, tmp_path)


def test_provider_audit_and_validation_reject_source_endpoint_mismatch(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    _write_provider_export_state(
        account_dir,
        source_endpoint=ProviderEndpoint(provider="gmail", host="imap.gmail.com", port=1993),
    )

    _name, audit_issues = provider_audit_account(config, account, tmp_path)
    _name, report = provider_validate_account(config, account, tmp_path)

    assert any("export-state source_endpoint" in issue for issue in audit_issues)
    assert any("export-state source_endpoint" in issue for issue in report["failed"])


def test_provider_audit_and_validation_reject_malformed_gmail_source_endpoint_host(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    state = json.loads((account_dir / "export-state.json").read_text())
    source_endpoint = dict(state["source_endpoint"])
    source_endpoint["host"] = "evil.example.com"
    state["source_endpoint"] = source_endpoint
    state["source_endpoint_sha256"] = hashlib.sha256(
        json.dumps(source_endpoint, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    (account_dir / "export-state.json").write_text(json.dumps(state))

    _name, audit_issues = provider_audit_account(config, account, tmp_path)
    _name, report = provider_validate_account(config, account, tmp_path)

    assert any("export-state source_endpoint" in issue for issue in audit_issues)
    assert any("export-state source_endpoint" in issue for issue in report["failed"])


@pytest.mark.parametrize("refresh_digest", [False, True])
def test_provider_audit_and_validation_reject_source_endpoint_string_booleans(
    tmp_path: Path,
    refresh_digest: bool,
) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    state = json.loads((account_dir / "export-state.json").read_text())
    source_endpoint = dict(state["source_endpoint"])
    source_endpoint["ssl"] = "false"
    state["source_endpoint"] = source_endpoint
    if refresh_digest:
        state["source_endpoint_sha256"] = hashlib.sha256(
            json.dumps(source_endpoint, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
    (account_dir / "export-state.json").write_text(json.dumps(state))

    _name, audit_issues = provider_audit_account(config, account, tmp_path)
    _name, report = provider_validate_account(config, account, tmp_path)

    assert any("export-state source_endpoint" in issue for issue in audit_issues)
    assert any("export-state source_endpoint" in issue for issue in report["failed"])


def test_provider_audit_and_validation_reject_target_endpoint_mismatch(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    _write_provider_export_state(
        account_dir,
        target_endpoint=ProviderEndpoint(provider="icloud", host="imap.mail.me.com", port=1993),
    )

    _name, audit_issues = provider_audit_account(config, account, tmp_path)
    _name, report = provider_validate_account(config, account, tmp_path)

    assert any("export-state target_endpoint" in issue for issue in audit_issues)
    assert any("export-state target_endpoint" in issue for issue in report["failed"])


def test_provider_audit_and_validation_reject_source_login_username_mismatch(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="new-login", password="imap-secret"),
        ),
        target=ProviderEndpoint(
            provider="icloud",
            host="imap.mail.me.com",
            auth=AuthConfig(method="app_password", username="target", password="icloud-secret"),
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@icloud.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["source_provider"] = "imap"
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(
        account_dir,
        source_endpoint=ProviderEndpoint(provider="imap", host="mail.example.com"),
        source_username="old-login",
    )

    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
        with pytest.raises(RuntimeError, match="export-state source_endpoint"):
            provider_import_account(config, account, tmp_path)
    _name, audit_issues = provider_audit_account(config, account, tmp_path)
    _name, report = provider_validate_account(config, account, tmp_path)

    assert any("export-state source_endpoint" in issue for issue in audit_issues)
    assert any("export-state source_endpoint" in issue for issue in report["failed"])


def test_provider_audit_and_validation_accept_gmail_source_username_case_only_change(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    state = json.loads((account_dir / "export-state.json").read_text())
    source_endpoint = dict(state["source_endpoint"])
    source_endpoint["username"] = "SOURCE@EXAMPLE.COM"
    state["source_endpoint"] = source_endpoint
    state["source_endpoint_sha256"] = provider_account_endpoint_state_digest(config.source, account, role="source")
    (account_dir / "export-state.json").write_text(json.dumps(state))

    _name, audit_issues = provider_audit_account(config, account, tmp_path)
    _name, report = provider_validate_account(config, account, tmp_path)

    assert not any("source_endpoint" in issue for issue in audit_issues)
    assert not any("source_endpoint" in issue for issue in report["failed"])


def test_provider_import_rejects_corrupt_staged_payload_before_append(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    (account_dir / "messages" / "gmail-123.eml").write_bytes(b"Message-ID: <m1@example.com>\r\n\r\ncorrupted")

    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
        with pytest.raises(RuntimeError, match="content_sha256 mismatch|rfc822_size mismatch"):
            provider_import_account(config, account, tmp_path)

    journal = account_dir / "import-target@icloud.com.journal.jsonl"
    assert not journal.exists()


def test_provider_rejects_invalid_delivery_metadata_before_target_contact(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["flags"] = "BAD ))"
    row["internaldate"] = "not a date"
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir)

    _name, audit_issues = provider_audit_account(config, account, tmp_path)
    _name, report = provider_validate_account(config, account, tmp_path, check_target=False)

    assert any("gmail-123: invalid flags metadata" in issue for issue in audit_issues)
    assert any("gmail-123: invalid internaldate metadata" in issue for issue in audit_issues)
    assert any("gmail-123: invalid flags metadata" in issue for issue in report["failed"])
    assert any("gmail-123: invalid internaldate metadata" in issue for issue in report["failed"])

    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
        with pytest.raises(RuntimeError, match="invalid provider delivery metadata.*invalid flags metadata.*invalid internaldate metadata"):
            provider_import_account(config, account, tmp_path)


def test_provider_append_metadata_formatters_reject_invalid_values() -> None:
    from components.provider_ops import _flags_for_provider_append, _internaldate_for_append

    with pytest.raises(RuntimeError, match="invalid provider flags"):
        _flags_for_provider_append("BAD ))", target_provider="imap", permanent_flags=None)

    with pytest.raises(RuntimeError, match="invalid provider internaldate"):
        _internaldate_for_append("not a date")


@pytest.mark.parametrize(
    ("payload_action", "needle"),
    [
        ("missing", "missing eml_path"),
        ("corrupt", "content_sha256 mismatch|rfc822_size mismatch"),
    ],
)
def test_provider_validation_rejects_missing_or_corrupt_staged_payload(
    tmp_path: Path,
    payload_action: str,
    needle: str,
) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    payload_path = account_dir / "messages" / "gmail-123.eml"
    if payload_action == "missing":
        payload_path.unlink()
    else:
        payload_path.write_bytes(b"Message-ID: <m1@example.com>\r\n\r\ncorrupted")

    _name, report = provider_validate_account(config, account, tmp_path)

    assert not report["ok"]
    assert any(re.search(needle, issue) for issue in report["failed"])


def test_provider_import_rejects_corrupt_payload_before_merge_probe(tmp_path: Path) -> None:
    config = _provider_config(target_mode="merge")
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    (account_dir / "messages" / "gmail-123.eml").write_bytes(b"Message-ID: <m1@example.com>\r\n\r\ncorrupted")

    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
        with pytest.raises(RuntimeError, match="content_sha256 mismatch|rfc822_size mismatch"):
            provider_import_account(config, account, tmp_path)

    assert not (account_dir / "import-target@icloud.com.journal.jsonl").exists()


def test_provider_import_rejects_corrupt_payload_before_committed_resume_probe(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    (account_dir / "messages" / "gmail-123.eml").write_bytes(b"Message-ID: <m1@example.com>\r\n\r\ncorrupted")
    (account_dir / "import-target@icloud.com.journal.jsonl").write_text(json.dumps(_journal_fixture(config, {
        "canonical_id": "gmail-123",
        "target_account": "target@icloud.com",
        "target_mailbox": "Archive",
        "status": "committed",
    })) + "\n")
    before = (account_dir / "import-target@icloud.com.journal.jsonl").read_text()

    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
        with pytest.raises(RuntimeError, match="content_sha256 mismatch|rfc822_size mismatch"):
            provider_import_account(config, account, tmp_path)

    assert (account_dir / "import-target@icloud.com.journal.jsonl").read_text() == before


def test_provider_import_merge_mode_uses_target_probe(tmp_path: Path) -> None:
    config = _provider_config(target_mode="merge")
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    fake = FakeTargetImap(has_existing=True)

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        provider_import_account(config, account, tmp_path)

    assert fake.appended == []
    assert any("BODY.PEEK[]" in query for query in fake.fetch_queries)
    assert ("HEADER", "Message-ID", "<m1@example.com>") in fake.search_queries
    assert True in fake.select_readonly
    journal = (account_dir / "import-target@icloud.com.journal.jsonl").read_text()
    assert '"action": "existing"' in journal


def test_provider_import_merge_mode_consumes_existing_matches_by_occurrence(tmp_path: Path) -> None:
    config = _provider_config(target_mode="merge")
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    duplicate = dict(row)
    duplicate["canonical_id"] = "physical-duplicate"
    duplicate["eml_path"] = "messages/physical-duplicate.eml"
    duplicate["metadata_path"] = "metadata/physical-duplicate.json"
    body = (account_dir / "messages" / "gmail-123.eml").read_bytes()
    (account_dir / "messages" / "physical-duplicate.eml").write_bytes(body)
    (account_dir / "metadata" / "physical-duplicate.json").write_text(json.dumps(duplicate))
    (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n" + json.dumps(duplicate) + "\n")
    _write_provider_export_state(account_dir, canonical_messages=2)
    fake = StoredMessageTarget({"Archive": [body]})

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[StoredMessageTarget]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        provider_import_account(config, account, tmp_path)

    assert fake.appended == ["Archive"]
    journal = (account_dir / "import-target@icloud.com.journal.jsonl").read_text()
    assert '"action": "existing"' in journal
    assert '"action": "appended"' in journal


def test_provider_import_merge_mode_marks_appended_matches_used(tmp_path: Path) -> None:
    config = _provider_config(target_mode="merge")
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    duplicate = dict(row)
    duplicate["canonical_id"] = "physical-duplicate"
    duplicate["eml_path"] = "messages/physical-duplicate.eml"
    duplicate["metadata_path"] = "metadata/physical-duplicate.json"
    (account_dir / "messages" / "physical-duplicate.eml").write_bytes((account_dir / "messages" / "gmail-123.eml").read_bytes())
    (account_dir / "metadata" / "physical-duplicate.json").write_text(json.dumps(duplicate))
    (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n" + json.dumps(duplicate) + "\n")
    _write_provider_export_state(account_dir, canonical_messages=2)
    fake = StoredMessageTarget()

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[StoredMessageTarget]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        provider_import_account(config, account, tmp_path)

    assert fake.appended == ["Archive", "Archive"]
    journal = (account_dir / "import-target@icloud.com.journal.jsonl").read_text()
    assert journal.count('"action": "appended"') == 2


def test_target_probe_can_match_without_message_id(tmp_path: Path) -> None:
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["message_id_header"] = ""
    fake = FakeTargetImap(has_existing=True)
    fake.messages = 1
    assert target_has_message(fake, "Archive", row, create_if_missing=False)
    assert fake.fetch_queries == ["(RFC822.SIZE BODY.PEEK[])"]


def test_target_probe_rejects_wrong_hash(tmp_path: Path) -> None:
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["content_sha256"] = "0" * 64
    fake = FakeTargetImap(has_existing=True)

    assert not target_has_message(fake, "Archive", row, create_if_missing=False)


def test_target_probe_accepts_uppercase_content_hash(tmp_path: Path) -> None:
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["content_sha256"] = str(row["content_sha256"]).upper()
    fake = FakeTargetImap(has_existing=True)

    assert target_has_message(fake, "Archive", row, create_if_missing=False)


def test_provider_import_empty_mode_resumes_with_journaled_target_messages(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    rows = [json.loads(line) for line in (account_dir / "manifest.jsonl").read_text().splitlines()]
    second_body = b"Message-ID: <m2@example.com>\r\n\r\nbody2"
    second = dict(rows[0])
    second.update({
        "canonical_id": "gmail-456",
        "message_id_header": "<m2@example.com>",
        "content_sha256": hashlib.sha256(second_body).hexdigest(),
        "rfc822_size": len(second_body),
        "eml_path": "messages/gmail-456.eml",
        "metadata_path": "metadata/gmail-456.json",
    })
    (account_dir / "messages" / "gmail-456.eml").write_bytes(second_body)
    (account_dir / "metadata" / "gmail-456.json").write_text(json.dumps(second))
    (account_dir / "manifest.jsonl").write_text("\n".join(json.dumps(row) for row in rows + [second]) + "\n")
    _write_provider_export_state(account_dir, canonical_messages=2)
    (account_dir / "import-target@icloud.com.journal.jsonl").write_text(json.dumps(_journal_fixture(config, {
        "canonical_id": "gmail-123",
        "target_account": "target@icloud.com",
        "target_mailbox": "Archive",
        "status": "committed",
    })) + "\n")
    fake = StoredMessageTarget({"Archive": [(account_dir / "messages" / "gmail-123.eml").read_bytes()]})

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[StoredMessageTarget]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        provider_import_account(config, account, tmp_path)

    assert fake.appended == ["Archive"]


def test_provider_import_empty_mode_permits_journaled_generic_all_view(tmp_path: Path) -> None:
    config = _generic_target_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["target_account"] = account.target_email
    row["primary_mailbox"] = "Archive"
    (account_dir / "metadata" / "gmail-123.json").write_text(json.dumps(row))
    (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")
    _write_provider_export_state(account_dir, target=account.target_email)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    (account_dir / "import-target@example.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, row, {
        "canonical_id": "gmail-123",
        "target_account": account.target_email,
        "target_mailbox": "Archive",
        "status": "committed",
    })) + "\n")
    body = (account_dir / "messages" / "gmail-123.eml").read_bytes()
    fake = GenericSpecialUseTarget({"Archive": [body], "All Mail": [body]})

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[GenericSpecialUseTarget]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        provider_import_account(config, account, tmp_path)

    assert fake.appended == []


def test_provider_import_empty_mode_permits_journaled_generic_flagged_view(tmp_path: Path) -> None:
    config = _generic_target_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["target_account"] = account.target_email
    row["primary_mailbox"] = "Archive"
    row["flags"] = "\\Seen \\Flagged"
    (account_dir / "metadata" / "gmail-123.json").write_text(json.dumps(row))
    (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")
    _write_provider_export_state(account_dir, target=account.target_email)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    (account_dir / "import-target@example.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, row, {
        "canonical_id": "gmail-123",
        "target_account": account.target_email,
        "target_mailbox": "Archive",
        "status": "committed",
    })) + "\n")
    body = (account_dir / "messages" / "gmail-123.eml").read_bytes()
    fake = GenericSpecialUseTarget({"Archive": [body], "Flagged": [body]})

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[GenericSpecialUseTarget]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        provider_import_account(config, account, tmp_path)

    assert fake.appended == []


def test_provider_import_empty_mode_rejects_unmatched_generic_all_view(tmp_path: Path) -> None:
    config = _generic_target_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["target_account"] = account.target_email
    row["primary_mailbox"] = "Archive"
    (account_dir / "metadata" / "gmail-123.json").write_text(json.dumps(row))
    (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")
    _write_provider_export_state(account_dir, target=account.target_email)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    (account_dir / "import-target@example.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, row, {
        "canonical_id": "gmail-123",
        "target_account": account.target_email,
        "target_mailbox": "Archive",
        "status": "committed",
    })) + "\n")
    body = (account_dir / "messages" / "gmail-123.eml").read_bytes()
    other_body = b"Message-ID: <other@example.com>\r\n\r\nother"
    fake = GenericSpecialUseTarget({"Archive": [body], "All Mail": [other_body]})

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[GenericSpecialUseTarget]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        with pytest.raises(RuntimeError, match="target_mode=empty"):
            provider_import_account(config, account, tmp_path)


def test_provider_import_empty_mode_rejects_duplicate_matches_in_concrete_generic_all_mailbox(tmp_path: Path) -> None:
    config = _generic_target_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["target_account"] = account.target_email
    row["primary_mailbox"] = "All Mail"
    (account_dir / "metadata" / "gmail-123.json").write_text(json.dumps(row))
    (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")
    _write_provider_export_state(account_dir, target=account.target_email)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    (account_dir / "import-target@example.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, row, {
        "canonical_id": "gmail-123",
        "target_account": account.target_email,
        "target_mailbox": "All Mail",
        "status": "committed",
    })) + "\n")
    body = (account_dir / "messages" / "gmail-123.eml").read_bytes()
    fake = GenericSpecialUseTarget({"All Mail": [body, body]})

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[GenericSpecialUseTarget]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        with pytest.raises(RuntimeError, match="target_mode=empty"):
            provider_import_account(config, account, tmp_path)


def test_provider_import_empty_mode_permits_journaled_gmail_all_mail_message(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="imap-secret"),
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    _mark_manifest_source_provider(row, "imap")
    row["target_account"] = "target@gmail.com"
    row["primary_mailbox"] = "Archive"
    (account_dir / "metadata" / "gmail-123.json").write_text(json.dumps(row))
    (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")
    _write_provider_export_state(account_dir, target="target@gmail.com")
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    (account_dir / "import-target@gmail.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, row, {
        "canonical_id": "gmail-123",
        "target_account": "target@gmail.com",
        "target_mailbox": "[Gmail]/All Mail",
        "status": "committed",
        "target_gmail_msgid": "9001",
    })) + "\n")
    fake = FakeGmailTargetImap(
        has_existing=True,
        existing_mailbox="[Gmail]/All Mail",
        messages_by_mailbox={"[Gmail]/All Mail": 1},
    )

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeGmailTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        provider_import_account(config, account, tmp_path)

    assert fake.appended == []


def test_provider_import_and_validation_match_googlemail_all_mail_journal_alias(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="imap-secret"),
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    _mark_manifest_source_provider(row, "imap")
    row["target_account"] = "target@gmail.com"
    row["primary_mailbox"] = "Archive"
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir, target="target@gmail.com")
    (account_dir / "import-target@gmail.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, row, {
        "canonical_id": "gmail-123",
        "target_account": "target@gmail.com",
        "target_mailbox": "[GoogleMail]/All Mail",
        "status": "committed",
        "target_gmail_msgid": "9001",
    })) + "\n")
    fake = FakeGmailTargetImap(
        has_existing=True,
        existing_mailbox="[Gmail]/All Mail",
        messages_by_mailbox={"[Gmail]/All Mail": 1},
        gmail_msgid="9001",
    )

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeGmailTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        provider_import_account(config, account, tmp_path)
        _name, report = provider_validate_account(config, account, tmp_path, check_target=True)

    assert fake.appended == []
    assert report["ok"], report
    assert report["remote_missing"] == []
    assert report["failed"] == []


def test_provider_import_recovers_pending_localized_gmail_sent_journal(tmp_path: Path) -> None:
    class LocalizedSentTarget(FakeGmailTargetImap):
        def list(self):
            return "OK", [
                b'(\\HasNoChildren) "/" "INBOX"',
                b'(\\HasNoChildren \\All) "/" "[Gmail]/All Mail"',
                b'(\\HasNoChildren \\Sent) "/" "Gesendet"',
            ]

    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="imap-secret"),
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    _mark_manifest_source_provider(row, "imap")
    row["target_account"] = "target@gmail.com"
    row["primary_mailbox"] = "Sent"
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir, target="target@gmail.com")
    (account_dir / "import-target@gmail.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, row, {
        "canonical_id": "gmail-123",
        "target_account": "target@gmail.com",
        "target_mailbox": "Gesendet",
        "status": "pending",
    })) + "\n")
    fake = LocalizedSentTarget(
        has_existing=True,
        existing_mailbox="Gesendet",
        messages_by_mailbox={"Gesendet": 1},
        gmail_labels=["\\Sent"],
        gmail_msgid="9001",
    )

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[LocalizedSentTarget]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        provider_import_account(config, account, tmp_path)

    journal = [
        json.loads(line)
        for line in (account_dir / "import-target@gmail.com.journal.jsonl").read_text().splitlines()
    ]
    assert fake.appended == []
    assert journal[-1]["status"] == "committed"
    assert journal[-1]["target_mailbox"] == "Gesendet"
    assert journal[-1]["target_gmail_msgid"] == "9001"


def test_provider_import_empty_mode_permits_journaled_gmail_starred_view(tmp_path: Path) -> None:
    class StarredGmailTarget(FakeGmailTargetImap):
        def __init__(self, **kwargs) -> None:
            super().__init__(**kwargs)
            self.matching_mailboxes = {"INBOX", "[Gmail]/Starred"}

        def list(self):
            return "OK", [
                b'(\\HasNoChildren) "/" "INBOX"',
                b'(\\HasNoChildren \\All) "/" "[Gmail]/All Mail"',
                b'(\\HasNoChildren \\Flagged) "/" "[Gmail]/Starred"',
            ]

        def search(self, charset: Optional[str], *criteria):
            self.search_queries.append(criteria)
            if criteria == ("ALL",):
                count = self._message_count(self.selected_mailbox)
                return "OK", [b" ".join(str(i).encode("ascii") for i in range(1, count + 1))]
            if (
                criteria == ("HEADER", "Message-ID", self.existing_message_id)
                and self.has_existing
                and self.selected_mailbox in self.matching_mailboxes
            ):
                return "OK", [b"99"]
            return "OK", [b""]

    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="imap-secret"),
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    _mark_manifest_source_provider(row, "imap")
    row["target_account"] = "target@gmail.com"
    row["primary_mailbox"] = "INBOX"
    row["flags"] = "\\Seen \\Flagged"
    (account_dir / "metadata" / "gmail-123.json").write_text(json.dumps(row))
    (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")
    _write_provider_export_state(account_dir, target="target@gmail.com")
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    (account_dir / "import-target@gmail.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, row, {
        "canonical_id": "gmail-123",
        "target_account": "target@gmail.com",
        "target_mailbox": "INBOX",
        "status": "committed",
        "target_gmail_msgid": "9001",
    })) + "\n")
    fake = StarredGmailTarget(
        has_existing=True,
        existing_mailbox="INBOX",
        messages_by_mailbox={"INBOX": 1, "[Gmail]/Starred": 1},
    )

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[StarredGmailTarget]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        provider_import_account(config, account, tmp_path)

    assert fake.appended == []


def test_gmail_system_views_include_plain_starred_label() -> None:
    from components.provider_ops import gmail_system_view_mailboxes_for_row

    mailboxes = [
        MailboxInfo(name="INBOX", delimiter="/", attributes=("\\HasNoChildren",)),
        MailboxInfo(name="[Gmail]/Starred", delimiter="/", attributes=("\\HasNoChildren", "\\Flagged")),
    ]
    row = {
        "canonical_id": "gmail-123",
        "gmail_labels": ["Starred"],
        "flags": "",
    }

    assert gmail_system_view_mailboxes_for_row(row, mailboxes) == ["[Gmail]/Starred"]


def test_provider_import_empty_mode_permits_journaled_gmail_important_view_plain_label(tmp_path: Path) -> None:
    class ImportantGmailTarget(FakeGmailTargetImap):
        def __init__(self, **kwargs) -> None:
            super().__init__(**kwargs)
            self.matching_mailboxes = {"INBOX", "[Gmail]/Important"}

        def list(self):
            return "OK", [
                b'(\\HasNoChildren) "/" "INBOX"',
                b'(\\HasNoChildren \\All) "/" "[Gmail]/All Mail"',
                b'(\\HasNoChildren \\Important) "/" "[Gmail]/Important"',
            ]

        def search(self, charset: Optional[str], *criteria):
            self.search_queries.append(criteria)
            if criteria == ("ALL",):
                count = self._message_count(self.selected_mailbox)
                return "OK", [b" ".join(str(i).encode("ascii") for i in range(1, count + 1))]
            if (
                criteria == ("HEADER", "Message-ID", self.existing_message_id)
                and self.has_existing
                and self.selected_mailbox in self.matching_mailboxes
            ):
                return "OK", [b"99"]
            return "OK", [b""]

    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="imap-secret"),
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["source_provider"] = "imap"
    row["target_account"] = "target@gmail.com"
    row["primary_mailbox"] = "INBOX"
    row["gmail_labels"] = ["Important"]
    (account_dir / "metadata" / "gmail-123.json").write_text(json.dumps(row))
    (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")
    _write_provider_export_state(account_dir, target="target@gmail.com")
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    (account_dir / "import-target@gmail.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, row, {
        "canonical_id": "gmail-123",
        "target_account": "target@gmail.com",
        "target_mailbox": "INBOX",
        "status": "committed",
        "target_gmail_msgid": "9001",
    })) + "\n")
    fake = ImportantGmailTarget(
        has_existing=True,
        existing_mailbox="INBOX",
        messages_by_mailbox={"INBOX": 1, "[Gmail]/Important": 1},
    )

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[ImportantGmailTarget]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        provider_import_account(config, account, tmp_path)

    assert fake.appended == []


def test_provider_import_empty_mode_rejects_stale_pending_unmatched_target(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    (account_dir / "import-target@icloud.com.journal.jsonl").write_text(json.dumps(_journal_fixture(config, {
        "canonical_id": "gmail-123",
        "target_account": "target@icloud.com",
        "target_mailbox": "Archive",
        "status": "pending",
    })) + "\n")
    fake = FakeTargetImap(has_existing=False)
    fake.messages = 1

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        with pytest.raises(RuntimeError, match="target_mode=empty"):
            provider_import_account(config, account, tmp_path)


def test_provider_import_rejects_pending_journal_wrong_target_mailbox_before_append(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    (account_dir / "import-target@icloud.com.journal.jsonl").write_text(json.dumps(_journal_fixture(config, {
        "canonical_id": "gmail-123",
        "target_account": "target@icloud.com",
        "target_mailbox": "INBOX",
        "status": "pending",
    })) + "\n")
    fake = FakeTargetImap(has_existing=False)

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        with pytest.raises(RuntimeError, match="pending identity in wrong target mailbox"):
            provider_import_account(config, account, tmp_path)

    assert fake.appended == []


def test_provider_import_rejects_committed_journal_missing_target_message(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    (account_dir / "import-target@icloud.com.journal.jsonl").write_text(json.dumps(_journal_fixture(config, {
        "canonical_id": "gmail-123",
        "target_account": "target@icloud.com",
        "target_mailbox": "Archive",
        "status": "committed",
    })) + "\n")
    fake = FakeTargetImap(has_existing=False)

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        with pytest.raises(RuntimeError, match="journal says gmail-123 is committed"):
            provider_import_account(config, account, tmp_path)


def test_provider_import_merge_mode_reimports_stale_committed_journal_row(tmp_path: Path) -> None:
    config = _provider_config(target_mode="merge")
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    (account_dir / "import-target@icloud.com.journal.jsonl").write_text(json.dumps(_journal_fixture(config, {
        "canonical_id": "gmail-123",
        "target_account": "target@icloud.com",
        "target_mailbox": "Archive",
        "status": "committed",
    })) + "\n")
    fake = FakeTargetImap(has_existing=False)

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        provider_import_account(config, account, tmp_path)
        _name, report = provider_validate_account(config, account, tmp_path, check_target=True)

    assert fake.appended == ["Archive"]
    journal = (account_dir / "import-target@icloud.com.journal.jsonl").read_text()
    assert '"action": "appended"' in journal
    assert report["ok"]
    assert report["duplicates"] == []
    assert report["committed"] == 1


def test_provider_import_merge_mode_rejects_wrong_mailbox_committed_journal_row(tmp_path: Path) -> None:
    config = _provider_config(target_mode="merge")
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    (account_dir / "import-target@icloud.com.journal.jsonl").write_text(json.dumps(_journal_fixture(config, {
        "canonical_id": "gmail-123",
        "target_account": "target@icloud.com",
        "target_mailbox": "INBOX",
        "status": "committed",
    })) + "\n")
    fake = FakeTargetImap(has_existing=False)

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        with pytest.raises(RuntimeError, match="wrong target mailbox"):
            provider_import_account(config, account, tmp_path)

    assert fake.appended == []


def test_provider_import_merge_mode_rejects_generic_special_use_alias_journal_before_append(tmp_path: Path) -> None:
    config = _generic_target_config(target_mode="merge")
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["target_account"] = account.target_email
    row["primary_mailbox"] = "Deleted Messages"
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir, target=account.target_email)
    (account_dir / "import-target@example.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, row, {
        "canonical_id": "gmail-123",
        "target_account": account.target_email,
        "target_mailbox": "Trash",
        "status": "committed",
    })) + "\n")
    body = (account_dir / "messages" / "gmail-123.eml").read_bytes()

    class TrashAndDeletedTarget(StoredMessageTarget):
        def list(self):
            return "OK", [
                b'(\\HasNoChildren) "/" "INBOX"',
                b'(\\HasNoChildren \\Trash) "/" "Deleted Messages"',
                b'(\\HasNoChildren \\Trash) "/" "Trash"',
            ]

    fake = TrashAndDeletedTarget({"Trash": [body]})

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[TrashAndDeletedTarget]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        with pytest.raises(RuntimeError, match="wrong target mailbox"):
            provider_import_account(config, account, tmp_path)

    assert fake.appended == []
    assert fake.bodies_by_mailbox == {"Trash": [body]}


def test_provider_online_validation_uses_live_special_use_target_mailbox(tmp_path: Path) -> None:
    config = _generic_target_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["target_account"] = account.target_email
    row["primary_mailbox"] = "Deleted Messages"
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir, target=account.target_email)
    (account_dir / "import-target@example.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, row, {
        "canonical_id": "gmail-123",
        "target_account": account.target_email,
        "target_mailbox": "Trash",
        "status": "committed",
    })) + "\n")
    body = (account_dir / "messages" / "gmail-123.eml").read_bytes()

    class TrashTarget(StoredMessageTarget):
        def list(self):
            return "OK", [
                b'(\\HasNoChildren) "/" "INBOX"',
                b'(\\HasNoChildren \\Trash) "/" "Trash"',
            ]

    fake = TrashTarget({"Trash": [body]})

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[TrashTarget]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        _name, report = provider_validate_account(config, account, tmp_path, check_target=True)

    assert report["ok"], report
    assert report["failed"] == []
    assert report["missing"] == []
    assert report["remote_missing"] == []
    assert report["remote_checked"] == 1


def test_provider_offline_validation_defers_generic_special_use_target_mailbox(tmp_path: Path) -> None:
    from components.main import _provider_cli_staged_validation_issues

    config = _generic_target_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["target_account"] = account.target_email
    row["primary_mailbox"] = "Deleted Messages"
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir, target=account.target_email)
    (account_dir / "import-target@example.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, row, {
        "canonical_id": "gmail-123",
        "target_account": account.target_email,
        "target_mailbox": "Papierkorb",
        "status": "committed",
    })) + "\n")

    _name, audit_issues = provider_audit_account(config, account, tmp_path)
    _name, report = provider_validate_account(config, account, tmp_path, check_target=False)
    cli_issues = _provider_cli_staged_validation_issues(tmp_path, config, mode="import")

    assert not any("wrong target mailbox" in issue for issue in audit_issues)
    assert report["ok"], report
    assert not any("wrong target mailbox" in issue for issue in cli_issues)


@pytest.mark.parametrize("status", ["committed", "pending"])
def test_provider_offline_validation_defers_icloud_special_use_target_mailbox(
    tmp_path: Path,
    status: str,
) -> None:
    from components.main import _provider_cli_staged_validation_issues

    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["target_account"] = account.target_email
    row["primary_mailbox"] = "Sent"
    row["gmail_labels"] = ["\\Sent"]
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir, target=account.target_email)
    (account_dir / "import-target@icloud.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, row, {
        "canonical_id": "gmail-123",
        "target_account": account.target_email,
        "target_mailbox": "Sent Messages",
        "status": status,
    })) + "\n")

    _name, audit_issues = provider_audit_account(config, account, tmp_path)
    _name, report = provider_validate_account(
        config,
        account,
        tmp_path,
        check_target=False,
        allow_unresolved_pending=status == "pending",
    )
    cli_issues = _provider_cli_staged_validation_issues(tmp_path, config, mode="import")

    assert not any("wrong target mailbox" in issue for issue in audit_issues)
    assert not any("wrong target mailbox" in issue for issue in report["failed"])
    assert not any("wrong target mailbox" in issue for issue in cli_issues)


def test_provider_offline_validation_rejects_icloud_custom_target_mismatch(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["target_account"] = account.target_email
    row["primary_mailbox"] = "Projects"
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir, target=account.target_email)
    (account_dir / "import-target@icloud.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, row, {
        "canonical_id": "gmail-123",
        "target_account": account.target_email,
        "target_mailbox": "Other Projects",
        "status": "committed",
    })) + "\n")

    _name, audit_issues = provider_audit_account(config, account, tmp_path)
    _name, report = provider_validate_account(config, account, tmp_path, check_target=False)

    assert any("wrong target mailbox" in issue for issue in audit_issues)
    assert any("wrong target mailbox" in issue for issue in report["failed"])


def test_provider_offline_validation_defers_localized_gmail_special_use_target_mailbox(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="source@example.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["source_provider"] = "gmail"
    row["target_account"] = "target@gmail.com"
    row["primary_mailbox"] = "Sent"
    row["gmail_labels"] = ["\\Sent"]
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir, target="target@gmail.com")
    (account_dir / "import-target@gmail.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, row, {
        "canonical_id": "gmail-123",
        "target_account": "target@gmail.com",
        "target_mailbox": "Gesendet",
        "status": "committed",
        "target_gmail_msgid": "9001",
    })) + "\n")

    _name, audit_issues = provider_audit_account(config, account, tmp_path)
    _name, report = provider_validate_account(config, account, tmp_path, check_target=False)

    assert not any("wrong target mailbox" in issue for issue in audit_issues)
    assert report["ok"], report
    assert not any("wrong target mailbox" in issue for issue in report["failed"])


def test_provider_validation_is_manifest_exact(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    _name, report = provider_validate_account(config, account, tmp_path)
    assert not report["ok"]
    assert report["missing"] == ["gmail-123"]

    (account_dir / "import-target@icloud.com.journal.jsonl").write_text(json.dumps(_journal_fixture(config, {
        "canonical_id": "gmail-123",
        "target_account": "target@icloud.com",
        "target_mailbox": "Archive",
        "status": "committed",
    })) + "\n")
    _name, report = provider_validate_account(config, account, tmp_path)
    assert report["ok"]
    assert report["committed"] == 1


def test_provider_audit_and_offline_validate_reject_stale_journal_content(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    stale = _journal_fixture(config, {
        "canonical_id": "gmail-123",
        "target_account": "target@icloud.com",
        "target_mailbox": "Archive",
        "status": "committed",
        "content_sha256": "0" * 64,
        "rfc822_size": 1,
        CONTENT_BINDING_FIELD: "0" * 64,
    })
    (account_dir / "import-target@icloud.com.journal.jsonl").write_text(json.dumps(stale) + "\n")

    _name, issues = provider_audit_account(config, account, tmp_path)
    _name, report = provider_validate_account(config, account, tmp_path, check_target=False)

    assert any("journal committed content_sha256 does not match manifest" in issue for issue in issues)
    assert any("journal committed rfc822_size does not match manifest" in issue for issue in issues)
    assert not report["ok"]
    assert any("journal committed content_sha256 does not match manifest" in issue for issue in report["failed"])


@pytest.mark.parametrize(
    ("mutations", "needle"),
    [
        ({"canonical_id": 123}, "non-string canonical_id"),
        ({"rfc822_size": True}, "journal committed rfc822_size does not match manifest"),
        ({"target_mailbox": True}, "non-string target_mailbox"),
    ],
)
def test_provider_audit_validation_and_import_reject_malformed_journal_field_types(
    tmp_path: Path,
    mutations: dict,
    needle: str,
) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = _journal_fixture(config, {
        "canonical_id": "gmail-123",
        "target_account": "target@icloud.com",
        "target_mailbox": "Archive",
        "status": "committed",
    })
    row.update(mutations)
    (account_dir / "import-target@icloud.com.journal.jsonl").write_text(json.dumps(row) + "\n")

    _name, issues = provider_audit_account(config, account, tmp_path)
    _name, report = provider_validate_account(config, account, tmp_path, check_target=False)

    assert any(needle in issue for issue in issues)
    assert any(needle in issue for issue in report["failed"])
    assert not report["ok"]
    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
        with pytest.raises(RuntimeError, match=needle):
            provider_import_account(config, account, tmp_path)


def test_provider_import_audit_and_validation_reject_stale_journal_content_binding(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    stale = _journal_fixture(config, {
        "canonical_id": "gmail-123",
        "target_account": "target@icloud.com",
        "target_mailbox": "Archive",
        "status": "committed",
        CONTENT_BINDING_FIELD: "0" * 64,
    })
    (account_dir / "import-target@icloud.com.journal.jsonl").write_text(json.dumps(stale) + "\n")

    _name, issues = provider_audit_account(config, account, tmp_path)
    _name, report = provider_validate_account(config, account, tmp_path, check_target=False)

    assert any(f"journal committed {CONTENT_BINDING_FIELD} does not match manifest" in issue for issue in issues)
    assert not report["ok"]
    assert any(f"journal committed {CONTENT_BINDING_FIELD} does not match manifest" in issue for issue in report["failed"])
    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
        with pytest.raises(RuntimeError, match=CONTENT_BINDING_FIELD):
            provider_import_account(config, account, tmp_path)


def test_provider_validation_requires_gmail_target_extensions(tmp_path: Path) -> None:
    class NoGmailExtensionTarget(FakeGmailTargetImap):
        def capability(self):
            return "OK", [b"IMAP4rev1"]

    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="source@example.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["target_account"] = "target@gmail.com"
    row["primary_mailbox"] = "INBOX"
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir, target="target@gmail.com")
    (account_dir / "import-target@gmail.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, row, {
        "canonical_id": "gmail-123",
        "target_account": "target@gmail.com",
        "target_mailbox": "INBOX",
        "status": "committed",
        "target_gmail_msgid": "9001",
    })) + "\n")

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[NoGmailExtensionTarget]:
        yield NoGmailExtensionTarget()

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        _name, report = provider_validate_account(config, account, tmp_path, check_target=True)

    assert not report["ok"]
    assert any("target Gmail" in item and "X-GM-EXT-1" in item for item in report["failed"])
    assert report["remote_checked"] == 0


def test_provider_validation_requires_gmail_target_all_mail_visibility(tmp_path: Path) -> None:
    class NoAllMailTarget(FakeGmailTargetImap):
        def list(self):
            return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="source@example.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["target_account"] = "target@gmail.com"
    row["primary_mailbox"] = "INBOX"
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir, target="target@gmail.com")
    (account_dir / "import-target@gmail.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, row, {
        "canonical_id": "gmail-123",
        "target_account": "target@gmail.com",
        "target_mailbox": "INBOX",
        "status": "committed",
        "target_gmail_msgid": "9001",
    })) + "\n")

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[NoAllMailTarget]:
        yield NoAllMailTarget(messages_by_mailbox={"INBOX": 1})

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        _name, report = provider_validate_account(config, account, tmp_path, check_target=True)

    assert not report["ok"]
    assert any("Gmail target All Mail is not visible" in item for item in report["failed"])
    assert report["remote_checked"] == 0


def test_provider_validation_requires_gmail_target_selectable_all_mail(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="source@example.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["target_account"] = "target@gmail.com"
    row["primary_mailbox"] = "INBOX"
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir, target="target@gmail.com")
    (account_dir / "import-target@gmail.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, row, {
        "canonical_id": "gmail-123",
        "target_account": "target@gmail.com",
        "target_mailbox": "INBOX",
        "status": "committed",
        "target_gmail_msgid": "9001",
    })) + "\n")

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeGmailTargetAllMailNotSelectable]:
        yield FakeGmailTargetAllMailNotSelectable(messages_by_mailbox={"INBOX": 1})

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        _name, report = provider_validate_account(config, account, tmp_path, check_target=True)

    assert not report["ok"]
    assert any("Gmail target All Mail is not selectable" in item for item in report["failed"])
    assert report["remote_checked"] == 0


def test_provider_import_audit_and_validation_require_manifest_integrity_metadata(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row.pop("content_sha256")
    row.pop("rfc822_size")
    (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")
    (account_dir / "metadata" / "gmail-123.json").write_text(json.dumps(row))

    _name, issues = provider_audit_account(config, account, tmp_path)
    assert any("missing or invalid content_sha256" in issue for issue in issues)
    assert any("missing or invalid rfc822_size" in issue for issue in issues)

    _name, report = provider_validate_account(config, account, tmp_path)
    assert any("missing or invalid content_sha256" in issue for issue in report["failed"])
    assert any("missing or invalid rfc822_size" in issue for issue in report["failed"])

    with pytest.raises(RuntimeError, match="invalid manifest integrity metadata"):
        provider_import_account(config, account, tmp_path)


def test_provider_import_audit_and_validation_reject_content_binding_mismatch(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row[CONTENT_BINDING_FIELD] = "0" * 64
    (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")
    (account_dir / "metadata" / "gmail-123.json").write_text(json.dumps(row))

    _name, issues = provider_audit_account(config, account, tmp_path)
    assert any("content_binding_sha256 mismatch" in issue for issue in issues)

    _name, report = provider_validate_account(config, account, tmp_path)
    assert any("content_binding_sha256 mismatch" in issue for issue in report["failed"])

    with pytest.raises(RuntimeError, match="content_binding_sha256 mismatch"):
        provider_import_account(config, account, tmp_path)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_mailbox_paths", "Archive"),
        ("source_mailbox_paths", {"Archive": "Archive"}),
        ("source_mailbox_paths", {1: ["Archive"]}),
        ("source_mailbox_attributes", "Archive"),
        ("source_mailbox_attributes", {"Archive": "\\Archive"}),
        ("source_mailbox_attributes", {1: ["\\Archive"]}),
    ],
)
def test_provider_content_binding_rejects_malformed_route_map_shapes(field: str, value: object) -> None:
    row = _default_manifest_fixture_row()
    row[field] = value

    with pytest.raises(ValueError, match=field):
        provider_content_binding_sha256(row)


@pytest.mark.parametrize("value", [["<m1@example.com>"], "bad\rvalue"])
def test_provider_content_binding_rejects_malformed_message_id_header(value: object) -> None:
    row = _default_manifest_fixture_row()
    row["message_id_header"] = value

    with pytest.raises(ValueError, match="message_id_header"):
        provider_content_binding_sha256(row)


def test_provider_import_audit_and_validation_reject_boolean_manifest_size(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["rfc822_size"] = True
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir)

    _name, issues = provider_audit_account(config, account, tmp_path)
    assert any("missing or invalid rfc822_size" in issue for issue in issues)

    _name, report = provider_validate_account(config, account, tmp_path)
    assert any("missing or invalid rfc822_size" in issue for issue in report["failed"])

    with pytest.raises(RuntimeError, match="invalid manifest integrity metadata"):
        provider_import_account(config, account, tmp_path)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("gmail_labels", "Project A"),
        ("source_mailboxes", "Archive"),
        ("gmail_labels", ["Project A", 42]),
        ("message_id_header", ["<m1@example.com>"]),
        ("message_id_header", "bad\rvalue"),
    ],
)
def test_provider_manifest_rejects_malformed_structured_fields_before_import(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row[field] = value
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir)

    _name, issues = provider_audit_account(config, account, tmp_path)
    _name, report = provider_validate_account(config, account, tmp_path)

    assert any(f"invalid {field}" in issue for issue in issues)
    assert any(f"invalid {field}" in issue for issue in report["failed"])
    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
        with pytest.raises(RuntimeError, match=f"invalid {field}"):
            provider_import_account(config, account, tmp_path)


def test_provider_import_rejects_malformed_message_id_before_target_journal(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["message_id_header"] = ["<m1@example.com>"]
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir)

    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
        with pytest.raises(RuntimeError, match="invalid message_id_header"):
            provider_import_account(config, account, tmp_path)

    assert not (account_dir / "import-target@icloud.com.journal.jsonl").exists()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_mailbox_paths", "Archive"),
        ("source_mailbox_paths", {"Archive": "Archive"}),
        ("source_mailbox_paths", {"Other": ["Other"]}),
        ("source_mailbox_paths", {"Archive": []}),
        ("source_mailbox_paths", {"Archive": [""]}),
        ("source_mailbox_attributes", "Archive"),
        ("source_mailbox_attributes", {"Archive": "\\Archive"}),
        ("source_mailbox_attributes", {"Other": []}),
        ("source_mailbox_attributes", {1: []}),
        ("source_mailbox_attributes", {"Archive": [42]}),
    ],
)
def test_provider_manifest_rejects_malformed_route_maps_before_import(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["source_mailboxes"] = ["Archive"]
    row[field] = value
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir)

    _name, issues = provider_audit_account(config, account, tmp_path)
    _name, report = provider_validate_account(config, account, tmp_path)

    assert any(f"invalid {field}" in issue for issue in issues)
    assert any(f"invalid {field}" in issue for issue in report["failed"])
    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
        with pytest.raises(RuntimeError, match=f"invalid {field}"):
            provider_import_account(config, account, tmp_path)


def test_provider_validation_rejects_incomplete_export_state(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    (account_dir / "export-state.json").write_text(json.dumps({"complete": False}))

    _name, report = provider_validate_account(config, account, tmp_path)

    assert not report["ok"]
    assert any("export-state is not complete" in item for item in report["failed"])


def test_provider_validation_rejects_gmail_export_state_without_visibility_attestation(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["source_provider"] = "gmail"
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir)
    state = json.loads((account_dir / "export-state.json").read_text())
    state["gmail_full_visibility_verified"] = False
    (account_dir / "export-state.json").write_text(json.dumps(state))

    _name, report = provider_validate_account(config, account, tmp_path)

    assert not report["ok"]
    assert any("Gmail full visibility attestation" in item for item in report["failed"])


def test_provider_configured_gmail_rejects_export_state_with_wrong_source_provider(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="source@example.com", password="token"),
            gmail_full_visibility_verified=True,
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["target_account"] = "target@gmail.com"
    row["source_provider"] = "imap"
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir, target="target@gmail.com")
    state = json.loads((account_dir / "export-state.json").read_text())
    state["source_provider"] = "imap"
    state.pop("gmail_full_visibility_verified", None)
    (account_dir / "export-state.json").write_text(json.dumps(state))
    (account_dir / "import-target@gmail.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, row, {
        "canonical_id": "gmail-123",
        "target_account": "target@gmail.com",
        "target_mailbox": "Archive",
        "status": "committed",
        "target_gmail_msgid": "9001",
    })) + "\n")

    _name, issues = provider_audit_account(config, account, tmp_path)
    assert any("source_provider does not match" in issue for issue in issues)

    fake = FakeGmailTargetImap()

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeGmailTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        with pytest.raises(RuntimeError, match="source_provider does not match"):
            provider_import_account(config, account, tmp_path)

    _name, report = provider_validate_account(config, account, tmp_path)
    assert not report["ok"]
    assert any("source_provider does not match" in item for item in report["failed"])


def test_provider_validation_rejects_duplicate_manifest_identity(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n" + json.dumps(dict(row)) + "\n")

    _name, report = provider_validate_account(config, account, tmp_path)

    assert not report["ok"]
    assert report["duplicates"] == [{"canonical_id": "gmail-123", "count": 2, "source": "manifest"}]


def test_provider_import_and_validation_reject_target_account_mismatch(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["target_account"] = "other@icloud.com"
    (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")
    _write_provider_export_state(account_dir)

    with pytest.raises(RuntimeError, match="target_account"):
        provider_import_account(config, account, tmp_path)

    _name, report = provider_validate_account(config, account, tmp_path)
    assert not report["ok"]
    assert any("target_account" in item for item in report["failed"])


def test_provider_import_audit_and_validation_reject_source_account_mismatch(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["source_account"] = "other@example.com"
    (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")
    _write_provider_export_state(account_dir)

    with pytest.raises(RuntimeError, match="source_account"):
        provider_import_account(config, account, tmp_path)

    _name, issues = provider_audit_account(config, account, tmp_path)
    assert any("source_account" in item for item in issues)

    _name, report = provider_validate_account(config, account, tmp_path)
    assert not report["ok"]
    assert any("source_account" in item for item in report["failed"])


def test_provider_import_rejects_metadata_mismatch_before_target_connect(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    metadata_path = account_dir / "metadata" / "gmail-123.json"
    metadata = json.loads(metadata_path.read_text())
    metadata["target_account"] = "other@icloud.com"
    metadata_path.write_text(json.dumps(metadata))

    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
        with pytest.raises(RuntimeError, match="metadata target_account differs from manifest"):
            provider_import_account(config, account, tmp_path)


def test_provider_import_audit_and_validation_reject_mixed_legacy_layout(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    legacy_mailbox = account_dir / "INBOX"
    legacy_mailbox.mkdir()
    (legacy_mailbox / ".mailbox.json").write_text("{}")
    (legacy_mailbox / "u00000001.eml").write_bytes(b"Message-ID: <legacy@example.com>\r\n\r\nlegacy")

    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
        with pytest.raises(RuntimeError, match="legacy mailbox directory present in provider account layout"):
            provider_import_account(config, account, tmp_path)

    _name, audit_issues = provider_audit_account(config, account, tmp_path)
    _name, report = provider_validate_account(config, account, tmp_path, check_target=False)

    assert any("legacy mailbox directory present in provider account layout: INBOX" in item for item in audit_issues)
    assert not report["ok"]
    assert any("legacy mailbox directory present in provider account layout: INBOX" in item for item in report["failed"])


def test_provider_import_and_validation_reject_journal_target_account_mismatch(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    (account_dir / "import-target@icloud.com.journal.jsonl").write_text(json.dumps(_journal_fixture(config, {
        "canonical_id": "gmail-123",
        "target_account": "other@icloud.com",
        "target_mailbox": "Archive",
        "status": "committed",
    })) + "\n")

    with pytest.raises(RuntimeError, match="invalid import journal"):
        provider_import_account(config, account, tmp_path)

    _name, report = provider_validate_account(config, account, tmp_path)
    assert not report["ok"]
    assert any("journal gmail-123 target_account" in item for item in report["failed"])


def test_provider_import_audit_and_validation_reject_journal_target_endpoint_mismatch(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = _journal_fixture(config, {
        "canonical_id": "gmail-123",
        "target_account": "target@icloud.com",
        "target_mailbox": "Archive",
        "status": "committed",
    })
    row["target_endpoint"] = dict(row["target_endpoint"])
    row["target_endpoint"]["host"] = "other-target.example.com"
    row["target_endpoint_sha256"] = "0" * 64
    (account_dir / "import-target@icloud.com.journal.jsonl").write_text(json.dumps(row) + "\n")

    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
        with pytest.raises(RuntimeError, match="target_endpoint"):
            provider_import_account(config, account, tmp_path)
    _name, audit_issues = provider_audit_account(config, account, tmp_path)
    _name, report = provider_validate_account(config, account, tmp_path)

    assert any("target_endpoint" in issue for issue in audit_issues)
    assert any("target_endpoint" in issue for issue in report["failed"])


def test_provider_audit_and_validation_reject_self_consistent_journal_endpoint_digest(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = _journal_fixture(config, {
        "canonical_id": "gmail-123",
        "target_account": "target@icloud.com",
        "target_mailbox": "Archive",
        "status": "committed",
    })
    target_endpoint = dict(row["target_endpoint"])
    target_endpoint["host"] = "IMAP.MAIL.ME.COM."
    target_endpoint["unexpected"] = "ignored-by-canonical-endpoint-match"
    row["target_endpoint"] = target_endpoint
    row["target_endpoint_sha256"] = hashlib.sha256(
        json.dumps(target_endpoint, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    (account_dir / "import-target@icloud.com.journal.jsonl").write_text(json.dumps(row) + "\n")

    _name, audit_issues = provider_audit_account(config, account, tmp_path)
    _name, report = provider_validate_account(config, account, tmp_path)

    assert any("target_endpoint_sha256" in issue for issue in audit_issues)
    assert any("target_endpoint_sha256" in issue for issue in report["failed"])


def test_provider_audit_and_validation_reject_malformed_gmail_journal_target_endpoint_host(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="source@example.com", password="token"),
            gmail_full_visibility_verified=True,
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_provider_account_fixture(
        tmp_path,
        source=account.source_email,
        target=account.target_email,
        canonical_id="gmail-123",
        message_id="<m1@example.com>",
        body=b"Message-ID: <m1@example.com>\r\n\r\nbody",
        source_provider="gmail",
        source_host="imap.gmail.com",
    )
    row = _journal_fixture(config, {
        "canonical_id": "gmail-123",
        "target_account": "target@gmail.com",
        "target_mailbox": "[Gmail]/All Mail",
        "status": "committed",
        "target_gmail_msgid": "9001",
    })
    target_endpoint = dict(row["target_endpoint"])
    target_endpoint["host"] = "evil.example.com"
    row["target_endpoint"] = target_endpoint
    row["target_endpoint_sha256"] = hashlib.sha256(
        json.dumps(target_endpoint, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    (account_dir / "import-target@gmail.com.journal.jsonl").write_text(json.dumps(row) + "\n")

    _name, audit_issues = provider_audit_account(config, account, tmp_path)
    _name, report = provider_validate_account(config, account, tmp_path)

    assert any("target_endpoint" in issue for issue in audit_issues)
    assert any("target_endpoint" in issue for issue in report["failed"])


def test_provider_audit_and_validation_accept_gmail_target_username_case_only_change(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="source@example.com", password="token"),
            gmail_full_visibility_verified=True,
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_provider_account_fixture(
        tmp_path,
        source=account.source_email,
        target=account.target_email,
        canonical_id="gmail-123",
        message_id="<m1@example.com>",
        body=b"Message-ID: <m1@example.com>\r\n\r\nbody",
        source_provider="gmail",
        source_host="imap.gmail.com",
    )
    row = _journal_fixture(config, {
        "canonical_id": "gmail-123",
        "target_account": "target@gmail.com",
        "target_mailbox": "Archive",
        "status": "committed",
        "target_gmail_msgid": "9001",
    })
    target_endpoint = dict(row["target_endpoint"])
    target_endpoint["username"] = "Target@Gmail.com"
    row["target_endpoint"] = target_endpoint
    row["target_endpoint_sha256"] = provider_account_endpoint_state_digest(config.target, account, role="target")
    (account_dir / "import-target@gmail.com.journal.jsonl").write_text(json.dumps(row) + "\n")

    _name, audit_issues = provider_audit_account(config, account, tmp_path)
    _name, report = provider_validate_account(config, account, tmp_path)

    assert not any("target_endpoint" in issue for issue in audit_issues)
    assert not any("target_endpoint" in issue for issue in report["failed"])
    assert report["ok"]


def test_provider_validation_rejects_journal_missing_target_mailbox(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    (account_dir / "import-target@icloud.com.journal.jsonl").write_text(json.dumps(_journal_fixture(config, {
        "canonical_id": "gmail-123",
        "target_account": "target@icloud.com",
        "status": "committed",
    })) + "\n")

    _name, report = provider_validate_account(config, account, tmp_path)

    assert not report["ok"]
    assert any("missing target_mailbox" in item for item in report["failed"])


def test_provider_validation_rejects_unresolved_pending_journal_row(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    (account_dir / "import-target@icloud.com.journal.jsonl").write_text(json.dumps(_journal_fixture(config, {
        "canonical_id": "gmail-123",
        "target_account": "target@icloud.com",
        "target_mailbox": "Archive",
        "status": "pending",
    })) + "\n")

    _name, report = provider_validate_account(config, account, tmp_path)

    assert not report["ok"]
    assert any("pending identity has no committed resolution" in item for item in report["failed"])


def test_provider_validation_rejects_pending_journal_row_after_committed_resolution(tmp_path: Path) -> None:
    config = _generic_target_config(target_mode="merge")
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["target_account"] = account.target_email
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir, target=account.target_email)
    committed = _journal_fixture(config, {
        "canonical_id": "gmail-123",
        "target_account": account.target_email,
        "target_mailbox": "Archive",
        "status": "committed",
    })
    pending = _journal_fixture(config, {
        "canonical_id": "gmail-123",
        "target_account": account.target_email,
        "target_mailbox": "Archive",
        "status": "pending",
    })
    (account_dir / "import-target@example.com.journal.jsonl").write_text(
        json.dumps(committed) + "\n" + json.dumps(pending) + "\n"
    )
    body = (account_dir / row["eml_path"]).read_bytes()
    fake = StoredMessageTarget({"Archive": [body, body]})

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[StoredMessageTarget]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        _name, report = provider_validate_account(config, account, tmp_path, check_target=True)

    assert not report["ok"]
    assert any("pending identity has no committed resolution" in item for item in report["failed"])


def test_provider_validation_rejects_wrong_target_mailbox_commit(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    (account_dir / "import-target@icloud.com.journal.jsonl").write_text(json.dumps(_journal_fixture(config, {
        "canonical_id": "gmail-123",
        "target_account": "target@icloud.com",
        "target_mailbox": "INBOX",
        "status": "committed",
    })) + "\n")
    fake = FakeTargetImap()

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        _name, report = provider_validate_account(config, account, tmp_path, check_target=True)

    assert not report["ok"]
    assert report["missing"] == ["gmail-123"]
    assert any("wrong target mailbox" in item for item in report["failed"])


def test_provider_audit_and_offline_validation_reject_wrong_target_mailbox_commit(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    (account_dir / "import-target@icloud.com.journal.jsonl").write_text(json.dumps(_journal_fixture(config, {
        "canonical_id": "gmail-123",
        "target_account": "target@icloud.com",
        "target_mailbox": "INBOX",
        "status": "committed",
    })) + "\n")

    _name, audit_issues = provider_audit_account(config, account, tmp_path)
    _name, report = provider_validate_account(config, account, tmp_path, check_target=False)

    assert any("journal committed identity in wrong target mailbox" in issue for issue in audit_issues)
    assert not report["ok"]
    assert any("journal committed identity in wrong target mailbox" in item for item in report["failed"])


def test_provider_validation_rejects_translated_folder_collision(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="imap-secret"),
        ),
        target=ProviderEndpoint(
            provider="imap",
            host="target.example.com",
            auth=AuthConfig(method="password", username="target@example.com", password="imap-secret"),
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@example.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    first = json.loads((account_dir / "manifest.jsonl").read_text())
    first["target_account"] = "target@example.com"
    first["canonical_id"] = "first"
    first["primary_mailbox"] = "A/B.C"
    first["source_mailboxes"] = ["A/B.C"]
    first["source_mailbox_paths"] = {"A/B.C": ["A/B", "C"]}
    first["eml_path"] = "messages/first.eml"
    first["metadata_path"] = "metadata/first.json"
    second = dict(first)
    second["canonical_id"] = "second"
    second["primary_mailbox"] = "A.B/C"
    second["source_mailboxes"] = ["A.B/C"]
    second["source_mailbox_paths"] = {"A.B/C": ["A", "B/C"]}
    second["eml_path"] = "messages/second.eml"
    second["metadata_path"] = "metadata/second.json"
    body = (account_dir / "messages" / "gmail-123.eml").read_bytes()
    (account_dir / "messages" / "first.eml").write_bytes(body)
    (account_dir / "messages" / "second.eml").write_bytes(body)
    (account_dir / "metadata" / "first.json").write_text(json.dumps(first))
    (account_dir / "metadata" / "second.json").write_text(json.dumps(second))
    (account_dir / "manifest.jsonl").write_text(json.dumps(first) + "\n" + json.dumps(second) + "\n")
    _write_provider_export_state(account_dir, target="target@example.com", canonical_messages=2)
    (account_dir / "import-target@example.com.journal.jsonl").write_text(
        json.dumps(_journal_fixture(config, {
            "canonical_id": "first",
            "target_account": "target@example.com",
            "target_mailbox": "A/B/C",
            "status": "committed",
        })) + "\n" + json.dumps(_journal_fixture(config, {
            "canonical_id": "second",
            "target_account": "target@example.com",
            "target_mailbox": "A/B/C",
            "status": "committed",
        })) + "\n"
    )
    fake = FakeTargetImap()

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        _name, report = provider_validate_account(config, account, tmp_path, check_target=True)

    assert not report["ok"]
    assert any("target mailbox translation collision" in item for item in report["failed"])


def test_provider_validation_checks_target_occurrences_not_only_boolean_match(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    duplicate = dict(row)
    duplicate["canonical_id"] = "physical-duplicate"
    duplicate["eml_path"] = "messages/physical-duplicate.eml"
    duplicate["metadata_path"] = "metadata/physical-duplicate.json"
    (account_dir / "messages" / "physical-duplicate.eml").write_bytes((account_dir / "messages" / "gmail-123.eml").read_bytes())
    (account_dir / "metadata" / "physical-duplicate.json").write_text(json.dumps(duplicate))
    (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n" + json.dumps(duplicate) + "\n")
    _write_provider_export_state(account_dir, canonical_messages=2)
    (account_dir / "import-target@icloud.com.journal.jsonl").write_text(
        json.dumps(_journal_fixture(config, {
            "canonical_id": "gmail-123",
            "target_account": "target@icloud.com",
            "target_mailbox": "Archive",
            "status": "committed",
        })) + "\n" + json.dumps(_journal_fixture(config, {
            "canonical_id": "physical-duplicate",
            "target_account": "target@icloud.com",
            "target_mailbox": "Archive",
            "status": "committed",
        })) + "\n"
    )
    fake = FakeTargetImap(has_existing=True)

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        _name, report = provider_validate_account(config, account, tmp_path, check_target=True)

    assert not report["ok"]
    assert report["remote_missing"] == ["physical-duplicate"]


def test_provider_validation_rejects_extra_matching_generic_target_copy_in_merge_mode(tmp_path: Path) -> None:
    config = _provider_config(target_mode="merge")
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    _write_provider_export_state(account_dir)
    (account_dir / "import-target@icloud.com.journal.jsonl").write_text(json.dumps(_journal_fixture(config, {
        "canonical_id": "gmail-123",
        "target_account": "target@icloud.com",
        "target_mailbox": "Archive",
        "status": "committed",
    })) + "\n")

    class DuplicateGenericTarget(FakeTargetImap):
        def search(self, charset: Optional[str], *criteria):
            self.search_queries.append(criteria)
            if criteria == ("HEADER", "Message-ID", row["message_id_header"]):
                return "OK", [b"1 2"]
            if criteria == ("ALL",):
                return "OK", [b"1 2"]
            return "OK", [b""]

        def fetch(self, num: bytes, query: str):
            return "OK", [(num + b" (RFC822.SIZE 36 BODY[] {36}", b"Message-ID: <m1@example.com>\r\n\r\nbody")]

    fake = DuplicateGenericTarget(messages_by_mailbox={"Archive": 2})

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[DuplicateGenericTarget]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        _name, report = provider_validate_account(config, account, tmp_path, check_target=True)

    assert not report["ok"]
    assert report["duplicates"] == [{"canonical_id": "gmail-123", "count": 2, "source": "target"}]


def test_provider_validation_rejects_single_gmail_message_for_two_physical_source_rows(tmp_path: Path) -> None:
    class OneGmailMessageInTwoLabels(FakeGmailTargetImap):
        def __init__(self, body: bytes) -> None:
            super().__init__(messages_by_mailbox={"Folder A": 1, "Folder B": 1}, gmail_msgid="9001")
            self.body = body

        def list(self):
            return "OK", [
                b'(\\HasNoChildren) "/" "INBOX"',
                b'(\\HasNoChildren \\All) "/" "[Gmail]/All Mail"',
                b'(\\HasNoChildren) "/" "Folder A"',
                b'(\\HasNoChildren) "/" "Folder B"',
            ]

        def search(self, charset: Optional[str], *criteria):
            self.search_queries.append(criteria)
            if criteria == ("ALL",):
                count = self._message_count(self.selected_mailbox)
                return "OK", [b" ".join(str(i).encode("ascii") for i in range(1, count + 1))]
            if criteria == ("HEADER", "Message-ID", "<m1@example.com>") and self.selected_mailbox in {"Folder A", "Folder B"}:
                return "OK", [b"1"]
            return "OK", [b""]

        def fetch(self, num: bytes, query: str):
            self.fetch_queries.append(query)
            if "X-GM-MSGID" in query:
                return "OK", [b"1 (X-GM-MSGID 9001)"]
            if "X-GM-LABELS" in query:
                return "OK", [b"1 (FLAGS (\\Seen) X-GM-LABELS ())"]
            return "OK", [(b"1 (RFC822.SIZE 36 BODY[] {36}", self.body)]

    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="icloud",
            host="imap.mail.me.com",
            auth=AuthConfig(method="app_password", username="source", password="icloud-secret"),
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    body = (account_dir / "messages" / "gmail-123.eml").read_bytes()
    first = json.loads((account_dir / "manifest.jsonl").read_text())
    first.update({
        "canonical_id": "physical-a",
        "source_provider": "icloud",
        "target_account": "target@gmail.com",
        "primary_mailbox": "Folder A",
        "source_mailboxes": ["Folder A"],
        "source_mailbox_paths": {"Folder A": ["Folder A"]},
        "eml_path": "messages/physical-a.eml",
        "metadata_path": "metadata/physical-a.json",
        "gmail_msgid": "",
        "gmail_thrid": "",
        "gmail_labels": [],
    })
    second = dict(first)
    second.update({
        "canonical_id": "physical-b",
        "primary_mailbox": "Folder B",
        "source_mailboxes": ["Folder B"],
        "source_mailbox_paths": {"Folder B": ["Folder B"]},
        "eml_path": "messages/physical-b.eml",
        "metadata_path": "metadata/physical-b.json",
    })
    (account_dir / "messages" / "physical-a.eml").write_bytes(body)
    (account_dir / "messages" / "physical-b.eml").write_bytes(body)
    (account_dir / "metadata" / "physical-a.json").write_text(json.dumps(first))
    (account_dir / "metadata" / "physical-b.json").write_text(json.dumps(second))
    (account_dir / "manifest.jsonl").write_text(json.dumps(first) + "\n" + json.dumps(second) + "\n")
    _write_provider_export_state(account_dir, target="target@gmail.com", canonical_messages=2)
    (account_dir / "import-target@gmail.com.journal.jsonl").write_text(
        json.dumps(_journal_fixture(config, {
            "canonical_id": "physical-a",
            "target_account": "target@gmail.com",
            "target_mailbox": "Folder A",
            "status": "committed",
        })) + "\n" + json.dumps(_journal_fixture(config, {
            "canonical_id": "physical-b",
            "target_account": "target@gmail.com",
            "target_mailbox": "Folder B",
            "status": "committed",
        })) + "\n"
    )
    fake = OneGmailMessageInTwoLabels(body)

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[OneGmailMessageInTwoLabels]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        _name, report = provider_validate_account(config, account, tmp_path, check_target=True)

    assert not report["ok"]
    assert report["remote_missing"] == ["physical-b"]


def test_provider_validation_checks_gmail_target_labels(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="source@example.com", password="gmail-token"),
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    _mark_manifest_source_provider(row, "gmail")
    row["target_account"] = "target@gmail.com"
    row["primary_mailbox"] = "INBOX"
    row["gmail_labels"] = ["\\Inbox", "Important", "Project A"]
    (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")
    (account_dir / "metadata" / "gmail-123.json").write_text(json.dumps(row))
    _write_provider_export_state(account_dir, target="target@gmail.com")
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    (account_dir / "import-target@gmail.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, row, {
        "canonical_id": "gmail-123",
        "target_account": "target@gmail.com",
        "target_mailbox": "INBOX",
        "status": "committed",
        "target_gmail_msgid": "9001",
    })) + "\n")
    missing_labels = FakeGmailTargetImap(
        has_existing=True,
        existing_mailbox="INBOX",
        messages_by_mailbox={"INBOX": 1},
        gmail_labels=["\\Inbox"],
    )

    @contextlib.contextmanager
    def missing_connection(*_args, **_kwargs) -> Iterator[FakeGmailTargetImap]:
        yield missing_labels

    with mock.patch("components.provider_ops.imap_connection", missing_connection):
        _name, report = provider_validate_account(config, account, tmp_path, check_target=True)

    assert not report["ok"]
    assert any("target Gmail labels missing" in item and "important" in item and "project a" in item for item in report["failed"])

    matching_labels = FakeGmailTargetImap(
        has_existing=True,
        existing_mailbox="INBOX",
        messages_by_mailbox={"INBOX": 1},
        gmail_labels=["\\Inbox", "\\Important", "Project A"],
    )

    @contextlib.contextmanager
    def matching_connection(*_args, **_kwargs) -> Iterator[FakeGmailTargetImap]:
        yield matching_labels

    with mock.patch("components.provider_ops.imap_connection", matching_connection):
        _name, report = provider_validate_account(config, account, tmp_path, check_target=True)

    assert report["ok"]


def test_provider_validation_rejects_missing_gmail_imap_flags(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="source@example.com", password="gmail-token"),
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    _mark_manifest_source_provider(row, "gmail")
    row["target_account"] = "target@gmail.com"
    row["primary_mailbox"] = "INBOX"
    row["flags"] = "\\Seen \\Answered"
    row["gmail_labels"] = ["\\Inbox"]
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir, target="target@gmail.com")
    (account_dir / "import-target@gmail.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, row, {
        "canonical_id": "gmail-123",
        "target_account": "target@gmail.com",
        "target_mailbox": "INBOX",
        "status": "committed",
        "target_gmail_msgid": "9001",
    })) + "\n")
    missing_flags = FakeGmailTargetImap(
        has_existing=True,
        existing_mailbox="INBOX",
        messages_by_mailbox={"INBOX": 1},
        gmail_labels=["\\Inbox"],
        gmail_flags="",
    )

    @contextlib.contextmanager
    def missing_connection(*_args, **_kwargs) -> Iterator[FakeGmailTargetImap]:
        yield missing_flags

    with mock.patch("components.provider_ops.imap_connection", missing_connection):
        _name, report = provider_validate_account(config, account, tmp_path, check_target=True)

    assert not report["ok"]
    assert any("target Gmail flags missing" in item and "\\ANSWERED" in item for item in report["failed"])

    matching_flags = FakeGmailTargetImap(
        has_existing=True,
        existing_mailbox="INBOX",
        messages_by_mailbox={"INBOX": 1},
        gmail_labels=["\\Inbox"],
        gmail_flags="\\Seen \\Answered",
    )

    @contextlib.contextmanager
    def matching_connection(*_args, **_kwargs) -> Iterator[FakeGmailTargetImap]:
        yield matching_flags

    with mock.patch("components.provider_ops.imap_connection", matching_connection):
        _name, report = provider_validate_account(config, account, tmp_path, check_target=True)

    assert report["ok"]


def test_provider_validation_accepts_journaled_gmail_target_ids_for_identical_source_messages(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="source@example.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = tmp_path / "source@example.com"
    (account_dir / "messages").mkdir(parents=True)
    (account_dir / "metadata").mkdir()
    body = b"Message-ID: <m1@example.com>\r\n\r\nbody"
    body_hash = hashlib.sha256(body).hexdigest()
    rows = []
    for canonical_id in ("gmail-111", "gmail-222"):
        eml_path = f"messages/{canonical_id}.eml"
        metadata_path = f"metadata/{canonical_id}.json"
        row = {
            "canonical_id": canonical_id,
            "source_provider": "gmail",
            "source_account": "source@example.com",
            "target_account": "target@gmail.com",
            "primary_mailbox": "INBOX",
            "message_id_header": "<m1@example.com>",
            "content_sha256": body_hash,
            "rfc822_size": len(body),
            "flags": "\\Seen",
            "internaldate": "01-Jan-2024 00:00:00 +0000",
            "gmail_labels": ["\\Inbox"],
            "eml_path": eml_path,
            "metadata_path": metadata_path,
        }
        row[CONTENT_BINDING_FIELD] = provider_content_binding_sha256(row)
        (account_dir / eml_path).write_bytes(body)
        (account_dir / metadata_path).write_text(json.dumps(row))
        rows.append(row)
    (account_dir / "manifest.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))
    _write_provider_export_state(account_dir, target="target@gmail.com")
    row_by_id = {row["canonical_id"]: row for row in rows}
    (account_dir / "import-target@gmail.com.journal.jsonl").write_text("".join(
        json.dumps(_journal_fixture(config, {
            "canonical_id": canonical_id,
            "target_account": "target@gmail.com",
            "target_mailbox": "INBOX",
            "status": "committed",
            "target_gmail_msgid": target_gmail_msgid,
            "content_sha256": row_by_id[canonical_id]["content_sha256"],
            "rfc822_size": row_by_id[canonical_id]["rfc822_size"],
            CONTENT_BINDING_FIELD: row_by_id[canonical_id][CONTENT_BINDING_FIELD],
        })) + "\n"
        for canonical_id, target_gmail_msgid in (("gmail-111", "9001"), ("gmail-222", "9002"))
    ))

    class DuplicateSourceGmailTarget(FakeGmailTargetImap):
        def list(self):
            return "OK", [
                b'(\\HasNoChildren) "/" "INBOX"',
                b'(\\HasNoChildren \\All) "/" "[Gmail]/All Mail"',
            ]

        def _message_count(self, mailbox: str) -> int:
            return {"INBOX": 2, "[Gmail]/All Mail": 2}.get(mailbox, 0)

        def search(self, charset: Optional[str], *criteria):
            self.search_queries.append(criteria)
            if criteria == ("ALL",):
                return "OK", [b"1 2"]
            if criteria == ("HEADER", "Message-ID", "<m1@example.com>"):
                return "OK", [b"1 2"]
            return "OK", [b""]

        def fetch(self, num: bytes, query: str):
            if "X-GM-MSGID" in query:
                gmail_msgid = b"9001" if num == b"1" else b"9002"
                return "OK", [num + b" (X-GM-MSGID " + gmail_msgid + b")"]
            if "X-GM-LABELS" in query:
                return "OK", [num + b" (FLAGS (\\Seen) X-GM-LABELS (\\Inbox))"]
            return "OK", [(num + b" (RFC822.SIZE 36 BODY[] {36}", body)]

    fake = DuplicateSourceGmailTarget()

    @contextlib.contextmanager
    def duplicate_source_connection(*_args, **_kwargs) -> Iterator[DuplicateSourceGmailTarget]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", duplicate_source_connection):
        _name, report = provider_validate_account(config, account, tmp_path, check_target=True)

    assert report["ok"]
    assert report["duplicates"] == []


def test_provider_validation_and_import_reject_duplicate_journaled_gmail_target_msgid(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="source@example.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    base = json.loads((account_dir / "manifest.jsonl").read_text())
    body = (account_dir / "messages" / "gmail-123.eml").read_bytes()
    _remove_default_manifest_fixture_artifacts(account_dir)
    rows = []
    for canonical_id in ("gmail-111", "gmail-222"):
        row = dict(base)
        row.update({
            "canonical_id": canonical_id,
            "target_account": "target@gmail.com",
            "primary_mailbox": "INBOX",
            "gmail_labels": ["\\Inbox"],
            "eml_path": f"messages/{canonical_id}.eml",
            "metadata_path": f"metadata/{canonical_id}.json",
        })
        (account_dir / row["eml_path"]).write_bytes(body)
        (account_dir / row["metadata_path"]).write_text(json.dumps(row))
        rows.append(row)
    (account_dir / "manifest.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))
    _write_provider_export_state(account_dir, target="target@gmail.com")
    rows = [json.loads(line) for line in (account_dir / "manifest.jsonl").read_text().splitlines()]
    row_by_id = {row["canonical_id"]: row for row in rows}
    (account_dir / "import-target@gmail.com.journal.jsonl").write_text("".join(
        json.dumps(_journal_fixture_for_manifest_row(config, row_by_id[canonical_id], {
            "canonical_id": canonical_id,
            "target_account": "target@gmail.com",
            "target_mailbox": "INBOX",
            "status": "committed",
            "target_gmail_msgid": "9001",
        })) + "\n"
        for canonical_id in ("gmail-111", "gmail-222")
    ))

    _name, report = provider_validate_account(config, account, tmp_path, check_target=False)

    assert not report["ok"]
    assert any(
        item.get("source") == "journal-target-gmail-msgid"
        and item.get("target_gmail_msgid") == "9001"
        and item.get("count") == 2
        for item in report["duplicates"]
    )
    _name, audit_issues = provider_audit_account(config, account, tmp_path)
    assert any("target_gmail_msgid 9001" in issue for issue in audit_issues)
    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
        with pytest.raises(RuntimeError, match="target_gmail_msgid 9001"):
            provider_import_account(config, account, tmp_path)


def test_provider_audit_validation_and_import_reject_invalid_gmail_target_msgid(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="source@example.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["target_account"] = "target@gmail.com"
    row["primary_mailbox"] = "INBOX"
    row["gmail_labels"] = ["\\Inbox"]
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir, target="target@gmail.com")
    (account_dir / "import-target@gmail.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, row, {
        "canonical_id": "gmail-123",
        "target_account": "target@gmail.com",
        "target_mailbox": "INBOX",
        "status": "committed",
        "target_gmail_msgid": "not-a-gmail-id",
    })) + "\n")

    _name, audit_issues = provider_audit_account(config, account, tmp_path)
    _name, report = provider_validate_account(config, account, tmp_path, check_target=False)

    assert any("invalid target_gmail_msgid" in issue for issue in audit_issues)
    assert any("invalid target_gmail_msgid" in issue for issue in report["failed"])
    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
        with pytest.raises(RuntimeError, match="invalid target_gmail_msgid"):
            provider_import_account(config, account, tmp_path)


def test_provider_validation_reports_and_import_repairs_missing_journaled_gmail_target_msgid(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="source@example.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="merge"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["target_account"] = "target@gmail.com"
    row["primary_mailbox"] = "INBOX"
    row["gmail_labels"] = ["\\Inbox", "Project A"]
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir, target="target@gmail.com")
    (account_dir / "import-target@gmail.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, row, {
        "canonical_id": "gmail-123",
        "target_account": "target@gmail.com",
        "target_mailbox": "INBOX",
        "status": "committed",
    })) + "\n")

    _name, report = provider_validate_account(config, account, tmp_path, check_target=False)

    assert not report["ok"]
    assert any("missing target_gmail_msgid" in issue for issue in report["failed"])
    _name, audit_issues = provider_audit_account(config, account, tmp_path)
    assert any("missing target_gmail_msgid" in issue for issue in audit_issues)

    fake = FakeGmailTargetImap(
        has_existing=True,
        existing_mailbox="INBOX",
        messages_by_mailbox={"INBOX": 1},
    )

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeGmailTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        provider_import_account(config, account, tmp_path)

    journal = load_import_journal(account_dir, account)
    assert journal[-1]["action"] == "verified"
    assert journal[-1]["target_gmail_msgid"] == "9001"
    assert fake.appended == []


def test_provider_import_rejects_ambiguous_missing_journaled_gmail_target_msgid(tmp_path: Path) -> None:
    class DuplicateContentGmailTarget(FakeGmailTargetImap):
        def __init__(self) -> None:
            super().__init__(messages_by_mailbox={"INBOX": 2})

        def search(self, charset: Optional[str], *criteria):
            self.search_queries.append(criteria)
            if criteria == ("ALL",):
                return "OK", [b"1 2"]
            if criteria == ("HEADER", "Message-ID", "<m1@example.com>"):
                return "OK", [b"1 2"]
            return "OK", [b""]

        def fetch(self, num: bytes, query: str):
            if "X-GM-MSGID" in query:
                gmail_msgid = b"9001" if num == b"1" else b"9002"
                return "OK", [num + b" (X-GM-MSGID " + gmail_msgid + b")"]
            if "X-GM-LABELS" in query:
                return "OK", [num + b" (FLAGS (\\Seen) X-GM-LABELS (\\Inbox))"]
            return "OK", [(num + b" (RFC822.SIZE 36 BODY[] {36}", b"Message-ID: <m1@example.com>\r\n\r\nbody")]

    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="source@example.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="merge"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["target_account"] = "target@gmail.com"
    row["primary_mailbox"] = "INBOX"
    row["gmail_labels"] = ["\\Inbox", "Project A"]
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir, target="target@gmail.com")
    (account_dir / "import-target@gmail.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, row, {
        "canonical_id": "gmail-123",
        "target_account": "target@gmail.com",
        "target_mailbox": "INBOX",
        "status": "committed",
    })) + "\n")
    fake = DuplicateContentGmailTarget()

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[DuplicateContentGmailTarget]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        with pytest.raises(RuntimeError, match="matched multiple target Gmail messages"):
            provider_import_account(config, account, tmp_path)

    journal = load_import_journal(account_dir, account)
    assert all(row.get("target_gmail_msgid") is None for row in journal)


def test_provider_validation_and_import_reject_multiple_gmail_msgids_for_one_identity(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="source@example.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["target_account"] = "target@gmail.com"
    row["primary_mailbox"] = "INBOX"
    row["gmail_labels"] = ["\\Inbox", "Project A"]
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir, target="target@gmail.com")
    (account_dir / "import-target@gmail.com.journal.jsonl").write_text(
        json.dumps(_journal_fixture(config, {
            "canonical_id": "gmail-123",
            "target_account": "target@gmail.com",
            "target_mailbox": "INBOX",
            "status": "committed",
            "target_gmail_msgid": "9001",
        })) + "\n" + json.dumps(_journal_fixture(config, {
            "canonical_id": "gmail-123",
            "target_account": "target@gmail.com",
            "target_mailbox": "Project A",
            "status": "committed",
            "target_gmail_msgid": "9002",
        })) + "\n"
    )

    _name, report = provider_validate_account(config, account, tmp_path, check_target=False)

    assert not report["ok"]
    assert any(
        item.get("source") == "journal-target-gmail-msgid"
        and item.get("canonical_id") == "gmail-123"
        and item.get("count") == 2
        and item.get("target_gmail_msgids") == ["9001", "9002"]
        for item in report["duplicates"]
    )
    _name, audit_issues = provider_audit_account(config, account, tmp_path)
    assert any("gmail-123" in issue and "9001" in issue and "9002" in issue for issue in audit_issues)
    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
        with pytest.raises(RuntimeError, match="gmail-123"):
            provider_import_account(config, account, tmp_path)


def test_provider_validation_and_import_reject_same_mailbox_gmail_recommit_to_new_msgid(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="source@example.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["target_account"] = "target@gmail.com"
    row["primary_mailbox"] = "INBOX"
    row["gmail_labels"] = ["\\Inbox"]
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir, target="target@gmail.com")
    (account_dir / "import-target@gmail.com.journal.jsonl").write_text(
        json.dumps(_journal_fixture(config, {
            "canonical_id": "gmail-123",
            "target_account": "target@gmail.com",
            "target_mailbox": "INBOX",
            "status": "committed",
            "target_gmail_msgid": "9001",
        })) + "\n" + json.dumps(_journal_fixture(config, {
            "canonical_id": "gmail-123",
            "target_account": "target@gmail.com",
            "target_mailbox": "INBOX",
            "status": "committed",
            "target_gmail_msgid": "9002",
        })) + "\n"
    )

    _name, report = provider_validate_account(config, account, tmp_path, check_target=False)

    assert not report["ok"]
    assert any(
        item.get("source") == "journal-target-gmail-msgid"
        and item.get("canonical_id") == "gmail-123"
        and item.get("target_gmail_msgids") == ["9001", "9002"]
        for item in report["duplicates"]
    )
    _name, audit_issues = provider_audit_account(config, account, tmp_path)
    assert any("gmail-123" in issue and "9001" in issue and "9002" in issue for issue in audit_issues)
    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
        with pytest.raises(RuntimeError, match="gmail-123"):
            provider_import_account(config, account, tmp_path)


def test_provider_validation_rejects_extra_matching_gmail_target_copy(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="source@example.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["source_provider"] = "gmail"
    row["target_account"] = "target@gmail.com"
    row["primary_mailbox"] = "INBOX"
    row["gmail_labels"] = ["\\Inbox"]
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir, target="target@gmail.com")
    (account_dir / "import-target@gmail.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, row, {
        "canonical_id": "gmail-123",
        "target_account": "target@gmail.com",
        "target_mailbox": "INBOX",
        "status": "committed",
        "target_gmail_msgid": "9001",
    })) + "\n")

    class DuplicateGmailTarget(FakeGmailTargetImap):
        def search(self, charset: Optional[str], *criteria):
            self.search_queries.append(criteria)
            if criteria == ("ALL",):
                return "OK", [b"1 2"]
            if criteria == ("HEADER", "Message-ID", "<m1@example.com>"):
                return "OK", [b"1 2"]
            return "OK", [b""]

        def fetch(self, num: bytes, query: str):
            if "X-GM-MSGID" in query:
                gmail_msgid = b"9001" if num == b"1" else b"9002"
                return "OK", [num + b" (X-GM-MSGID " + gmail_msgid + b")"]
            if "X-GM-LABELS" in query:
                return "OK", [num + b" (FLAGS (\\Seen) X-GM-LABELS (\\Inbox))"]
            return "OK", [(num + b" (RFC822.SIZE 36 BODY[] {36}", b"Message-ID: <m1@example.com>\r\n\r\nbody")]

    fake = DuplicateGmailTarget(messages_by_mailbox={"INBOX": 2})

    @contextlib.contextmanager
    def duplicate_connection(*_args, **_kwargs) -> Iterator[DuplicateGmailTarget]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", duplicate_connection):
        _name, report = provider_validate_account(config, account, tmp_path, check_target=True)

    assert not report["ok"]
    assert any(item.get("source") == "target" and item.get("count") == 2 for item in report["duplicates"])


def test_provider_validation_rejects_extra_matching_gmail_copy_in_restored_label(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="source@example.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["source_provider"] = "gmail"
    row["target_account"] = "target@gmail.com"
    row["primary_mailbox"] = "INBOX"
    row["gmail_labels"] = ["\\Inbox", "Project A"]
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir, target="target@gmail.com")
    (account_dir / "import-target@gmail.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, row, {
        "canonical_id": "gmail-123",
        "target_account": "target@gmail.com",
        "target_mailbox": "INBOX",
        "status": "committed",
        "target_gmail_msgid": "9001",
    })) + "\n")

    class DuplicateInLabelGmailTarget(FakeGmailTargetImap):
        def list(self):
            return "OK", [
                b'(\\HasNoChildren) "/" "INBOX"',
                b'(\\HasNoChildren \\All) "/" "[Gmail]/All Mail"',
                b'(\\HasNoChildren) "/" "Project A"',
            ]

        def _message_count(self, mailbox: str) -> int:
            return {"INBOX": 1, "[Gmail]/All Mail": 1, "Project A": 2}.get(mailbox, 0)

        def search(self, charset: Optional[str], *criteria):
            self.search_queries.append(criteria)
            if criteria == ("ALL",):
                count = self._message_count(self.selected_mailbox)
                return "OK", [b" ".join(str(i).encode("ascii") for i in range(1, count + 1))]
            if criteria == ("HEADER", "Message-ID", "<m1@example.com>"):
                if self.selected_mailbox == "Project A":
                    return "OK", [b"1 2"]
                if self.selected_mailbox in {"INBOX", "[Gmail]/All Mail"}:
                    return "OK", [b"1"]
            return "OK", [b""]

        def fetch(self, num: bytes, query: str):
            if "X-GM-MSGID" in query:
                if self.selected_mailbox == "Project A" and num == b"2":
                    return "OK", [b"2 (X-GM-MSGID 9002)"]
                return "OK", [num + b" (X-GM-MSGID 9001)"]
            if "X-GM-LABELS" in query:
                return "OK", [num + b' (FLAGS (\\Seen) X-GM-LABELS (\\Inbox "Project A"))']
            return "OK", [(num + b" (RFC822.SIZE 36 BODY[] {36}", b"Message-ID: <m1@example.com>\r\n\r\nbody")]

    fake = DuplicateInLabelGmailTarget(messages_by_mailbox={"INBOX": 1})

    @contextlib.contextmanager
    def duplicate_connection(*_args, **_kwargs) -> Iterator[DuplicateInLabelGmailTarget]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", duplicate_connection):
        _name, report = provider_validate_account(config, account, tmp_path, check_target=True)

    assert not report["ok"]
    assert any(item.get("source") == "target" and item.get("count") == 2 for item in report["duplicates"])


def test_provider_validation_rejects_gmail_copy_missing_from_primary_target_mailbox(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="source@example.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["source_provider"] = "gmail"
    row["target_account"] = "target@gmail.com"
    row["primary_mailbox"] = "INBOX"
    row["gmail_labels"] = ["\\Inbox"]
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir, target="target@gmail.com")
    (account_dir / "import-target@gmail.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, row, {
        "canonical_id": "gmail-123",
        "target_account": "target@gmail.com",
        "target_mailbox": "INBOX",
        "status": "committed",
        "target_gmail_msgid": "9001",
    })) + "\n")

    class AllMailOnlyTarget(FakeGmailTargetImap):
        def search(self, charset: Optional[str], *criteria):
            self.search_queries.append(criteria)
            if criteria == ("ALL",):
                return "OK", [b"1"] if self.selected_mailbox == "[Gmail]/All Mail" else [b""]
            if criteria == ("HEADER", "Message-ID", "<m1@example.com>"):
                return "OK", [b"1"] if self.selected_mailbox == "[Gmail]/All Mail" else [b""]
            return "OK", [b""]

        def fetch(self, num: bytes, query: str):
            if "X-GM-MSGID" in query:
                return "OK", [num + b" (X-GM-MSGID 9001)"]
            if "X-GM-LABELS" in query:
                return "OK", [num + b" (FLAGS (\\Seen) X-GM-LABELS ())"]
            return "OK", [(num + b" (RFC822.SIZE 36 BODY[] {36}", b"Message-ID: <m1@example.com>\r\n\r\nbody")]

    @contextlib.contextmanager
    def all_mail_only_connection(*_args, **_kwargs) -> Iterator[AllMailOnlyTarget]:
        yield AllMailOnlyTarget(messages_by_mailbox={"INBOX": 0, "[Gmail]/All Mail": 1})

    with mock.patch("components.provider_ops.imap_connection", all_mail_only_connection):
        _name, report = provider_validate_account(config, account, tmp_path, check_target=True)

    assert not report["ok"]
    assert report["remote_missing"] == ["gmail-123"]
    assert report["remote_checked"] == 1


def test_provider_validation_checks_bare_gmail_starred_label(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="source@example.com", password="gmail-token"),
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    _mark_manifest_source_provider(row, "gmail")
    row["target_account"] = "target@gmail.com"
    row["primary_mailbox"] = "INBOX"
    row["gmail_labels"] = ["\\Inbox", "Starred"]
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir, target="target@gmail.com")
    (account_dir / "import-target@gmail.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, row, {
        "canonical_id": "gmail-123",
        "target_account": "target@gmail.com",
        "target_mailbox": "INBOX",
        "status": "committed",
        "target_gmail_msgid": "9001",
    })) + "\n")

    missing_star = FakeGmailTargetImap(
        has_existing=True,
        existing_mailbox="INBOX",
        messages_by_mailbox={"INBOX": 1},
        gmail_labels=["\\Inbox"],
        gmail_flags="\\Seen",
    )

    @contextlib.contextmanager
    def missing_connection(*_args, **_kwargs) -> Iterator[FakeGmailTargetImap]:
        yield missing_star

    with mock.patch("components.provider_ops.imap_connection", missing_connection):
        _name, report = provider_validate_account(config, account, tmp_path, check_target=True)

    assert not report["ok"]
    assert any("target Gmail labels missing" in item and "starred" in item for item in report["failed"])

    matching_star = FakeGmailTargetImap(
        has_existing=True,
        existing_mailbox="INBOX",
        messages_by_mailbox={"INBOX": 1},
        gmail_labels=["\\Inbox"],
        gmail_flags="\\Seen \\Flagged",
    )

    @contextlib.contextmanager
    def matching_connection(*_args, **_kwargs) -> Iterator[FakeGmailTargetImap]:
        yield matching_star

    with mock.patch("components.provider_ops.imap_connection", matching_connection):
        _name, report = provider_validate_account(config, account, tmp_path, check_target=True)

    assert report["ok"]


def test_provider_validation_checks_secondary_gmail_system_label(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="source@example.com", password="gmail-token"),
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    _mark_manifest_source_provider(row, "gmail")
    row["target_account"] = "target@gmail.com"
    row["primary_mailbox"] = "Sent"
    row["gmail_labels"] = ["\\Sent", "\\Inbox"]
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir, target="target@gmail.com")
    (account_dir / "import-target@gmail.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, row, {
        "canonical_id": "gmail-123",
        "target_account": "target@gmail.com",
        "target_mailbox": "[Gmail]/Sent Mail",
        "status": "committed",
        "target_gmail_msgid": "9001",
    })) + "\n")

    missing_inbox = FakeGmailTargetImap(
        has_existing=True,
        existing_mailbox="[Gmail]/Sent Mail",
        messages_by_mailbox={"[Gmail]/Sent Mail": 1},
        gmail_labels=["\\Sent"],
    )

    @contextlib.contextmanager
    def missing_connection(*_args, **_kwargs) -> Iterator[FakeGmailTargetImap]:
        yield missing_inbox

    with mock.patch("components.provider_ops.imap_connection", missing_connection):
        _name, report = provider_validate_account(config, account, tmp_path, check_target=True)

    assert not report["ok"]
    assert any("target Gmail labels missing" in item and "inbox" in item for item in report["failed"])

    matching = FakeGmailTargetImap(
        has_existing=True,
        existing_mailbox="[Gmail]/Sent Mail",
        messages_by_mailbox={"[Gmail]/Sent Mail": 1},
        gmail_labels=["\\Sent", "\\Inbox"],
    )

    @contextlib.contextmanager
    def matching_connection(*_args, **_kwargs) -> Iterator[FakeGmailTargetImap]:
        yield matching

    with mock.patch("components.provider_ops.imap_connection", matching_connection):
        _name, report = provider_validate_account(config, account, tmp_path, check_target=True)

    assert report["ok"]


def test_provider_import_empty_mode_rejects_populated_target(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    _write_manifest_fixture(tmp_path)
    fake = FakeTargetImap()
    fake.messages = 1

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        with pytest.raises(RuntimeError, match="target_mode=empty"):
            provider_import_account(config, account, tmp_path)


def test_provider_import_empty_mode_ignores_icloud_vip_virtual_target_view(tmp_path: Path) -> None:
    class TargetWithIcloudVipView(FakeTargetImap):
        def list(self):
            return "OK", [
                b'(\\HasNoChildren) "/" "INBOX"',
                b'(\\HasNoChildren \\Archive) "/" "Archive"',
                b'(\\HasNoChildren) "/" "VIP"',
            ]

    config = _provider_config()
    account = config.accounts[0]
    _write_manifest_fixture(tmp_path)
    fake = TargetWithIcloudVipView(messages_by_mailbox={"VIP": 1})

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[TargetWithIcloudVipView]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        provider_import_account(config, account, tmp_path)

    assert fake.appended == ["Archive"]


def test_provider_import_empty_mode_rejects_populated_unrelated_target_folder(tmp_path: Path) -> None:
    class TargetWithUnrelatedFolder(FakeTargetImap):
        def list(self):
            return "OK", [
                b'(\\HasNoChildren) "/" "INBOX"',
                b'(\\HasNoChildren \\Archive) "/" "Archive"',
                b'(\\HasNoChildren) "/" "Old Mail"',
            ]

    config = _provider_config()
    account = config.accounts[0]
    _write_manifest_fixture(tmp_path)
    fake = TargetWithUnrelatedFolder(messages_by_mailbox={"Old Mail": 1})

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[TargetWithUnrelatedFolder]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        with pytest.raises(RuntimeError, match="Old Mail"):
            provider_import_account(config, account, tmp_path)


def test_provider_audit_detects_corrupted_message(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    (account_dir / "messages" / "gmail-123.eml").write_bytes(b"corrupted")

    _name, issues = provider_audit_account(config, account, tmp_path)
    assert any("content_sha256 mismatch" in issue or "rfc822_size mismatch" in issue for issue in issues)


def test_provider_audit_rejects_metadata_that_differs_from_manifest(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    metadata_path = account_dir / "metadata" / "gmail-123.json"
    metadata = json.loads(metadata_path.read_text())
    metadata["source_account"] = "other@example.com"
    metadata["target_account"] = "other@icloud.com"
    metadata_path.write_text(json.dumps(metadata))

    _name, issues = provider_audit_account(config, account, tmp_path)

    assert any("metadata source_account differs from manifest" in issue for issue in issues)
    assert any("metadata target_account differs from manifest" in issue for issue in issues)

    _name, report = provider_validate_account(config, account, tmp_path)
    assert not report["ok"]
    assert any("metadata source_account differs from manifest" in issue for issue in report["failed"])
    assert any("metadata target_account differs from manifest" in issue for issue in report["failed"])


def test_provider_audit_and_validation_reject_orphan_provider_artifacts(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    (account_dir / "messages" / "stale.eml").write_bytes(b"stale")
    (account_dir / "metadata" / "stale.json").write_text(json.dumps({"stale": True}))

    _name, issues = provider_audit_account(config, account, tmp_path)
    _name, report = provider_validate_account(config, account, tmp_path)

    assert any("unmanifested provider message artifact: messages/stale.eml" in issue for issue in issues)
    assert any("unmanifested provider metadata artifact: metadata/stale.json" in issue for issue in issues)
    assert any("unmanifested provider message artifact: messages/stale.eml" in item for item in report["failed"])
    assert any("unmanifested provider metadata artifact: metadata/stale.json" in item for item in report["failed"])

    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
        with pytest.raises(RuntimeError, match="unmanifested provider message artifact"):
            provider_import_account(config, account, tmp_path)


def test_provider_audit_and_validation_reject_non_regular_orphan_provider_artifacts(tmp_path: Path) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO creation unavailable")
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    message_orphan = account_dir / "messages" / "stale.eml"
    metadata_orphan = account_dir / "metadata" / "stale.json"
    try:
        os.mkfifo(message_orphan)
        os.mkfifo(metadata_orphan)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"FIFO creation unavailable: {exc}")

    _name, issues = provider_audit_account(config, account, tmp_path)
    _name, report = provider_validate_account(config, account, tmp_path)

    assert any("unmanifested non-regular provider message artifact: messages/stale.eml" in issue for issue in issues)
    assert any("unmanifested non-regular provider metadata artifact: metadata/stale.json" in issue for issue in issues)
    assert any("unmanifested non-regular provider message artifact: messages/stale.eml" in item for item in report["failed"])
    assert any("unmanifested non-regular provider metadata artifact: metadata/stale.json" in item for item in report["failed"])

    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
        with pytest.raises(RuntimeError, match="unmanifested non-regular provider message artifact"):
            provider_import_account(config, account, tmp_path)


@pytest.mark.parametrize(
    ("root_name", "filename", "broken", "needle"),
    [
        ("messages", "outside.eml", False, "symlinked provider message artifact directory: messages/linked-dir"),
        ("metadata", "outside.json", False, "symlinked provider metadata artifact directory: metadata/linked-dir"),
        ("messages", "outside.eml", True, "symlinked provider message artifact directory: messages/linked-dir"),
        ("metadata", "outside.json", True, "symlinked provider metadata artifact directory: metadata/linked-dir"),
    ],
)
def test_provider_audit_and_validation_reject_symlinked_artifact_subdirectories(
    tmp_path: Path,
    root_name: str,
    filename: str,
    broken: bool,
    needle: str,
) -> None:
    from verify_export import verify_account

    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    outside = tmp_path / f"outside-{root_name}"
    if not broken:
        outside.mkdir()
        (outside / filename).write_text("outside", encoding="utf-8")
    link_dir = account_dir / root_name / "linked-dir"
    try:
        link_dir.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    _name, issues = provider_audit_account(config, account, tmp_path)
    _name, report = provider_validate_account(config, account, tmp_path, check_target=False)
    stats = verify_account(account_dir)

    assert any(needle in issue for issue in issues)
    assert any(needle in item for item in report["failed"])
    assert stats["errors"] >= 1


def test_provider_audit_and_validation_reject_metadata_extra_null_key(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    metadata_path = account_dir / "metadata" / "gmail-123.json"
    metadata = json.loads(metadata_path.read_text())
    metadata["extra"] = None
    metadata_path.write_text(json.dumps(metadata))

    _name, issues = provider_audit_account(config, account, tmp_path)
    assert any("metadata extra absent from manifest" in issue for issue in issues)

    _name, report = provider_validate_account(config, account, tmp_path)
    assert not report["ok"]
    assert any("metadata extra absent from manifest" in issue for issue in report["failed"])


def test_provider_audit_rejects_non_object_metadata_json(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    (account_dir / "metadata" / "gmail-123.json").write_text(json.dumps(["not", "an", "object"]))

    _name, issues = provider_audit_account(config, account, tmp_path)

    assert any("metadata json is not an object" in issue for issue in issues)

    _name, report = provider_validate_account(config, account, tmp_path)
    assert not report["ok"]
    assert any("metadata json is not an object" in issue for issue in report["failed"])


def test_provider_audit_rejects_incomplete_export_state(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    (account_dir / "export-state.json").write_text(json.dumps({
        "source_account": account.source_email,
        "target_account": account.target_email,
        "complete": False,
    }))

    _name, issues = provider_audit_account(config, account, tmp_path)

    assert any("export-state is not complete" in issue for issue in issues)


def test_provider_audit_and_validation_reject_mismatched_export_state(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    _write_provider_export_state(account_dir, source="other@example.com", canonical_messages=2)

    _name, issues = provider_audit_account(config, account, tmp_path)
    assert any("export-state source_account" in issue for issue in issues)
    assert any("export-state canonical_messages" in issue for issue in issues)

    _name, report = provider_validate_account(config, account, tmp_path)
    assert not report["ok"]
    assert any("export-state source_account" in issue for issue in report["failed"])
    assert any("export-state canonical_messages" in issue for issue in report["failed"])


def test_provider_audit_and_validation_reject_stale_manifest_digest(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    _write_provider_export_state(account_dir)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["primary_mailbox"] = "INBOX"
    (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")

    _name, issues = provider_audit_account(config, account, tmp_path)
    assert any("export-state manifest_sha256" in issue for issue in issues)

    _name, report = provider_validate_account(config, account, tmp_path)
    assert not report["ok"]
    assert any("export-state manifest_sha256" in issue for issue in report["failed"])


def test_load_import_journal_recovers_incomplete_trailing_row(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    journal = account_dir / "import-target@icloud.com.journal.jsonl"
    valid = {"canonical_id": "gmail-123", "target_account": "target@icloud.com", "target_mailbox": "Archive", "status": "pending"}
    journal.write_text(json.dumps(valid) + "\n" + '{"canonical_id": ')

    rows = load_import_journal(account_dir, account, repair_trailing=True)

    assert rows == [valid]
    assert journal.read_text().strip() == json.dumps(valid, sort_keys=True)


def test_provider_audit_and_validation_do_not_repair_incomplete_trailing_journal(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    valid = {"canonical_id": "gmail-123", "target_account": "target@icloud.com", "target_mailbox": "Archive", "status": "pending"}
    journal = account_dir / "import-target@icloud.com.journal.jsonl"
    original = json.dumps(valid) + "\n" + '{"canonical_id": '
    journal.write_text(original)

    _name, audit_issues = provider_audit_account(config, account, tmp_path)
    _name, report = provider_validate_account(config, account, tmp_path)

    assert any("import journal load failed" in issue for issue in audit_issues)
    assert any("Expecting value" in issue for issue in report["failed"])
    assert journal.read_text() == original


def test_provider_audit_validation_and_import_reject_non_object_import_journal_row(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    (account_dir / "import-target@icloud.com.journal.jsonl").write_text("[]\n")

    _name, audit_issues = provider_audit_account(config, account, tmp_path)
    _name, report = provider_validate_account(config, account, tmp_path)

    assert any("journal row 1 is not an object" in issue for issue in audit_issues)
    assert any("journal row 1 is not an object" in issue for issue in report["failed"])
    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
        with pytest.raises(ValueError, match="journal row 1 is not an object"):
            provider_import_account(config, account, tmp_path)


def test_provider_audit_validation_and_import_reject_unknown_import_journal_status(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    (account_dir / "import-target@icloud.com.journal.jsonl").write_text(json.dumps(_journal_fixture(config, {
        "canonical_id": "gmail-123",
        "target_account": "target@icloud.com",
        "target_mailbox": "Archive",
        "status": "commited",
    })) + "\n")

    _name, audit_issues = provider_audit_account(config, account, tmp_path)
    _name, report = provider_validate_account(config, account, tmp_path)

    assert any("invalid status: commited" in issue for issue in audit_issues)
    assert any("invalid status: commited" in issue for issue in report["failed"])
    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
        with pytest.raises(RuntimeError, match="invalid status: commited"):
            provider_import_account(config, account, tmp_path)


def test_provider_audit_requires_gmail_target_visibility_attestation(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="imap-secret"),
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["source_provider"] = "imap"
    row["target_account"] = "target@gmail.com"
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir, target="target@gmail.com")

    _name, issues = provider_audit_account(config, account, tmp_path)
    _name, report = provider_validate_account(config, account, tmp_path, check_target=False)

    assert any("Gmail target full IMAP visibility is not attested" in issue for issue in issues)
    assert any("Gmail target full IMAP visibility is not attested" in issue for issue in report["failed"])


def test_provider_audit_reports_malformed_gmail_import_journal(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="source@example.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["target_account"] = "target@gmail.com"
    row["primary_mailbox"] = "INBOX"
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir, target="target@gmail.com")
    (account_dir / "import-target@gmail.com.journal.jsonl").write_text(
        '{"canonical_id": "broken"\n'
        + json.dumps(_journal_fixture(config, {
            "canonical_id": "gmail-123",
            "target_account": "target@gmail.com",
            "target_mailbox": "INBOX",
            "status": "committed",
            "target_gmail_msgid": "9001",
        })) + "\n"
    )

    _name, issues = provider_audit_account(config, account, tmp_path)

    assert any("import journal load failed" in issue for issue in issues)


def test_provider_audit_reports_malformed_non_gmail_import_journal(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="imap-secret"),
        ),
        target=ProviderEndpoint(
            provider="icloud",
            host="imap.mail.me.com",
            auth=AuthConfig(method="app_password", username="target@icloud.com", password="secret"),
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@icloud.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["source_provider"] = "imap"
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir)
    (account_dir / "import-target@icloud.com.journal.jsonl").write_text(
        '{"canonical_id": "broken"\n'
        + json.dumps(_journal_fixture(config, {
            "canonical_id": "gmail-123",
            "target_account": "target@icloud.com",
            "target_mailbox": "Archive",
            "status": "committed",
        })) + "\n"
    )

    _name, issues = provider_audit_account(config, account, tmp_path)

    assert any("import journal load failed" in issue for issue in issues)


class FakePreflightSourceFailure:
    def capability(self):
        return "OK", [b"IMAP4rev1 X-GM-EXT-1"]

    def list(self):
        return "OK", [
            b'(\\HasNoChildren) "/" "INBOX"',
            b'(\\HasNoChildren \\All) "/" "[Gmail]/All Mail"',
        ]

    def select(self, mailbox: str, readonly: bool = False):
        return "OK", [b"1"]

    def response(self, name: str):
        return "OK", [b"777"]

    def uid(self, command: str, *args):
        if command == "search":
            return "OK", [b"1"]
        if command == "fetch":
            return "NO", [b"temporary fetch failure"]
        raise AssertionError(command)


class FakePreflightSourceMissingSize(FakePreflightSourceFailure):
    def uid(self, command: str, *args):
        if command == "search":
            return "OK", [b"1"]
        if command == "fetch":
            return "OK", [b'1 (UID 1 FLAGS (\\Seen) INTERNALDATE "01-Jan-2024 00:00:00 +0000")']
        raise AssertionError(command)


class FakePreflightSourceMissingGmailMsgid(FakePreflightSourceFailure):
    def uid(self, command: str, *args):
        if command == "search":
            return "OK", [b"1"]
        if command == "fetch":
            query = " ".join(str(arg) for arg in args)
            assert "X-GM-MSGID" in query
            return "OK", [
                b'1 (UID 1 FLAGS (\\Seen) INTERNALDATE "01-Jan-2024 00:00:00 +0000" RFC822.SIZE 42)'
            ]
        raise AssertionError(command)


class FakePreflightTarget:
    def capability(self):
        return "OK", [b"IMAP4rev1 X-GM-EXT-1"]

    def list(self):
        return "OK", [b'(\\HasNoChildren) "/" "INBOX"']


class FakePreflightTargetNoGmailExtensions(FakePreflightTarget):
    def capability(self):
        return "OK", [b"IMAP4rev1"]


class FakePreflightTargetAllMailWithoutSpecialUse(FakePreflightTarget):
    def list(self):
        return "OK", [
            b'(\\HasNoChildren) "/" "INBOX"',
            b'(\\HasNoChildren) "/" "[Gmail]/All Mail"',
        ]


class FakePreflightTargetAllMailNotSelectable(FakePreflightTarget):
    def list(self):
        return "OK", [
            b'(\\HasNoChildren) "/" "INBOX"',
            b'(\\HasNoChildren \\All) "/" "[Gmail]/All Mail"',
        ]

    def select(self, mailbox: str, readonly: bool = False):
        selected = mailbox.strip('"').replace(r"\"", '"')
        if selected == "[Gmail]/All Mail":
            return "NO", [b"All Mail disabled"]
        return "OK", [b"0"]


class FakePreflightSourceNoExtensions(FakePreflightSourceFailure):
    def capability(self):
        return "OK", [b"IMAP4rev1"]

    def uid(self, command: str, *args):
        if command == "search":
            return "OK", [b""]
        return super().uid(command, *args)


class FakePreflightSourceNoAllMail(FakePreflightSourceFailure):
    def list(self):
        return "OK", [b'(\\HasNoChildren) "/" "INBOX"']


class FakePreflightSourceStopsDuringFetch(FakePreflightSourceFailure):
    def __init__(self, stop_event: threading.Event) -> None:
        self.stop_event = stop_event
        self.fetch_count = 0

    def uid(self, command: str, *args):
        if command == "search":
            return "OK", [b"1 2"]
        if command == "fetch":
            self.fetch_count += 1
            self.stop_event.set()
            return "OK", [
                b'1 (UID 1 FLAGS (\\Seen) INTERNALDATE "01-Jan-2024 00:00:00 +0000" RFC822.SIZE 42)'
            ]
        raise AssertionError(command)


def test_provider_preflight_stop_event_aborts_during_source_metadata_fetch(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="imap-secret"),
        ),
        target=ProviderEndpoint(
            provider="icloud",
            host="imap.mail.me.com",
            auth=AuthConfig(method="app_password", username="target@icloud.com", password="secret"),
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@icloud.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    stop_event = threading.Event()
    source = FakePreflightSourceStopsDuringFetch(stop_event)
    target_connections = 0

    @contextlib.contextmanager
    def fake_connection(endpoint, *_args, **_kwargs):
        nonlocal target_connections
        if endpoint.provider == "imap":
            yield source
            return
        target_connections += 1
        yield FakePreflightTarget()

    with mock.patch("components.provider_ops.imap_connection", fake_connection):
        with pytest.raises(RuntimeError, match="stop requested"):
            provider_preflight(config, max_workers=1, stop_event=stop_event)

    assert source.fetch_count == 1
    assert target_connections == 0


def test_provider_test_accounts_stop_event_aborts_before_target_role(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="imap-secret"),
        ),
        target=ProviderEndpoint(
            provider="icloud",
            host="imap.mail.me.com",
            auth=AuthConfig(method="app_password", username="target@icloud.com", password="secret"),
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@icloud.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    stop_event = threading.Event()
    target_connections = 0

    @contextlib.contextmanager
    def fake_connection(endpoint, *_args, **_kwargs):
        nonlocal target_connections
        if endpoint.provider == "imap":
            stop_event.set()
            yield object()
            return
        target_connections += 1
        yield object()

    with mock.patch("components.provider_ops.imap_connection", fake_connection):
        with pytest.raises(RuntimeError, match="stop requested"):
            provider_test_accounts(config, max_workers=1, roles=("source", "target"), stop_event=stop_event)

    assert target_connections == 0


def test_provider_account_worker_results_stop_waits_for_running_worker() -> None:
    account = MigrationAccount(source_email="source@example.com", target_email="target@icloud.com")
    stop_event = threading.Event()
    worker_finished = threading.Event()

    def worker(_account: MigrationAccount) -> str:
        stop_event.set()
        stop_event.wait(0.05)
        worker_finished.set()
        return "done"

    with pytest.raises(RuntimeError, match="stop requested"):
        _provider_account_worker_results(
            "provider-test",
            [account],
            1,
            worker,
            stop_event,
        )

    assert worker_finished.is_set()


def test_provider_preflight_reports_metadata_fetch_failures(tmp_path: Path) -> None:
    config = _provider_config()

    @contextlib.contextmanager
    def fake_connection(endpoint, *_args, **_kwargs):
        yield FakePreflightSourceFailure() if endpoint.provider == "gmail" else FakePreflightTarget()

    with mock.patch("components.provider_ops.imap_connection", fake_connection):
        ok, issues = provider_preflight(config, max_workers=1)

    assert not ok
    assert any("metadata fetch failed" in issue for issue in issues)


def test_provider_preflight_reports_missing_metadata_size(tmp_path: Path) -> None:
    config = _provider_config()
    config.target.available_bytes = 1

    @contextlib.contextmanager
    def fake_connection(endpoint, *_args, **_kwargs):
        yield FakePreflightSourceMissingSize() if endpoint.provider == "gmail" else FakePreflightTarget()

    with mock.patch("components.provider_ops.imap_connection", fake_connection):
        ok, issues = provider_preflight(config, max_workers=1)

    assert not ok
    assert any("metadata fetch missing RFC822.SIZE" in issue for issue in issues)


def test_provider_preflight_reports_missing_gmail_msgid(tmp_path: Path) -> None:
    config = _provider_config()

    @contextlib.contextmanager
    def fake_connection(endpoint, *_args, **_kwargs):
        yield FakePreflightSourceMissingGmailMsgid() if endpoint.provider == "gmail" else FakePreflightTarget()

    with mock.patch("components.provider_ops.imap_connection", fake_connection):
        ok, issues = provider_preflight(config, max_workers=1)

    assert not ok
    assert any("metadata fetch missing X-GM-MSGID" in issue for issue in issues)


def test_provider_preflight_ignores_gmail_identity_metadata_for_generic_imap(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="imap-secret"),
        ),
        target=ProviderEndpoint(
            provider="icloud",
            host="imap.mail.me.com",
            auth=AuthConfig(method="app_password", username="target", password="icloud-secret"),
            available_bytes=43,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@icloud.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    source = FakeNonGmailGmailMetadataDuplicateSourceImap()

    @contextlib.contextmanager
    def fake_connection(endpoint, *_args, **_kwargs):
        yield source if endpoint.provider == "imap" else FakePreflightTarget()

    with mock.patch("components.provider_ops.imap_connection", fake_connection):
        ok, issues = provider_preflight(config, max_workers=1)

    assert not ok
    assert any("estimated source bytes 86 exceed target.available_bytes 43" in issue for issue in issues)
    assert all("X-GM-" not in query for query in source.fetch_queries)


def test_provider_preflight_counts_generic_flagged_only_mailbox(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="imap-secret"),
        ),
        target=ProviderEndpoint(
            provider="icloud",
            host="imap.mail.me.com",
            auth=AuthConfig(method="app_password", username="target", password="icloud-secret"),
            available_bytes=42,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@icloud.com")],
        migration=MigrationSettings(target_mode="empty"),
    )

    @contextlib.contextmanager
    def fake_connection(endpoint, *_args, **_kwargs):
        yield FakeGenericFlaggedOnlySourceImap() if endpoint.provider == "imap" else FakePreflightTarget()

    with mock.patch("components.provider_ops.imap_connection", fake_connection):
        ok, issues = provider_preflight(config, max_workers=1)

    assert not ok
    assert any("estimated source bytes 43 exceed target.available_bytes 42" in issue for issue in issues)


def test_provider_preflight_counts_generic_all_when_it_is_only_source_mailbox(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="imap-secret"),
        ),
        target=ProviderEndpoint(
            provider="icloud",
            host="imap.mail.me.com",
            auth=AuthConfig(method="app_password", username="target", password="icloud-secret"),
            available_bytes=42,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@icloud.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    source = FakeGenericAllOnlySourceImap()

    @contextlib.contextmanager
    def fake_connection(endpoint, *_args, **_kwargs):
        yield source if endpoint.provider == "imap" else FakePreflightTarget()

    with mock.patch("components.provider_ops.imap_connection", fake_connection):
        ok, issues = provider_preflight(config, max_workers=1)

    assert not ok
    assert any("estimated source bytes 43 exceed target.available_bytes 42" in issue for issue in issues)
    assert source.fetch_queries


def test_provider_preflight_dedupes_generic_all_overlap_for_capacity(tmp_path: Path) -> None:
    source = FakeGenericInboxAndAllSourceImap()
    unique_source_bytes = len(source.inbox_body) + len(source.archived_body)
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="imap-secret"),
        ),
        target=ProviderEndpoint(
            provider="icloud",
            host="imap.mail.me.com",
            auth=AuthConfig(method="app_password", username="target", password="icloud-secret"),
            available_bytes=unique_source_bytes,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@icloud.com")],
        migration=MigrationSettings(target_mode="empty"),
    )

    @contextlib.contextmanager
    def fake_connection(endpoint, *_args, **_kwargs):
        yield source if endpoint.provider == "imap" else FakePreflightTarget()

    with mock.patch("components.provider_ops.imap_connection", fake_connection):
        ok, issues = provider_preflight(config, max_workers=1)

    assert ok, issues
    assert source.fetch_queries_by_mailbox["INBOX"]
    assert source.fetch_queries_by_mailbox["All Mail"]
    assert all(
        "BODY.PEEK[]" in query
        for queries in source.fetch_queries_by_mailbox.values()
        for query in queries
    )


def test_provider_preflight_many_to_one_aggregates_target_available_bytes(tmp_path: Path) -> None:
    config = _many_to_one_config()
    config.target.available_bytes = 60

    @contextlib.contextmanager
    def fake_connection(endpoint, *_args, **_kwargs):
        yield FakeIcloudInboxSourceImap() if endpoint.provider == "imap" and endpoint.host == "mail.source.example.com" else FakePreflightTarget()

    with mock.patch("components.provider_ops.imap_connection", fake_connection):
        ok, issues = provider_preflight(config, max_workers=2)

    assert not ok
    assert any(
        "target merge group merged@example.com" in issue
        and "estimated source bytes 80 exceed target.available_bytes 60" in issue
        for issue in issues
    )


def test_provider_preflight_hybrid_many_to_one_aggregates_by_target_group(tmp_path: Path) -> None:
    config = _hybrid_many_to_one_config()
    config.target.available_bytes = 80

    @contextlib.contextmanager
    def fake_connection(endpoint, *_args, **_kwargs):
        yield FakeIcloudInboxSourceImap() if endpoint.provider == "imap" and endpoint.host == "mail.source.example.com" else FakePreflightTarget()

    with mock.patch("components.provider_ops.imap_connection", fake_connection):
        ok, issues = provider_preflight(config, max_workers=5)

    assert not ok
    assert any(
        "target merge group a@example.com" in issue
        and "estimated source bytes 120 exceed target.available_bytes 80" in issue
        for issue in issues
    )
    assert not any("target merge group d@example.com" in issue for issue in issues)
    assert not any("target merge group e@example.com" in issue for issue in issues)


def test_provider_preflight_reports_source_and_target_exceptions(tmp_path: Path) -> None:
    config = _provider_config()

    @contextlib.contextmanager
    def fake_connection(endpoint, *_args, **_kwargs):
        if endpoint.provider == "gmail":
            raise RuntimeError("source login failed")
        raise RuntimeError("target login failed")
        yield

    with mock.patch("components.provider_ops.imap_connection", fake_connection):
        ok, issues = provider_preflight(config, max_workers=1)

    assert not ok
    assert any("source preflight failed" in issue for issue in issues)
    assert any("target preflight failed" in issue for issue in issues)


def test_provider_preflight_reports_missing_gmail_extensions(tmp_path: Path) -> None:
    config = _provider_config()

    @contextlib.contextmanager
    def fake_connection(endpoint, *_args, **_kwargs):
        yield FakePreflightSourceNoExtensions() if endpoint.provider == "gmail" else FakePreflightTarget()

    with mock.patch("components.provider_ops.imap_connection", fake_connection):
        ok, issues = provider_preflight(config, max_workers=1)

    assert not ok
    assert any("X-GM-EXT-1" in issue for issue in issues)


def test_provider_preflight_reports_missing_gmail_target_extensions(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="imap-secret"),
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )

    @contextlib.contextmanager
    def fake_connection(endpoint, *_args, **_kwargs):
        yield FakeIcloudInboxSourceImap() if endpoint.provider == "imap" else FakePreflightTargetNoGmailExtensions()

    with mock.patch("components.provider_ops.imap_connection", fake_connection):
        ok, issues = provider_preflight(config, max_workers=1)

    assert not ok
    assert any("target Gmail" in issue and "X-GM-EXT-1" in issue for issue in issues)


def test_provider_preflight_reports_missing_gmail_target_all_mail(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="imap-secret"),
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )

    @contextlib.contextmanager
    def fake_connection(endpoint, *_args, **_kwargs):
        yield FakeIcloudInboxSourceImap() if endpoint.provider == "imap" else FakePreflightTarget()

    with mock.patch("components.provider_ops.imap_connection", fake_connection):
        ok, issues = provider_preflight(config, max_workers=1)

    assert not ok
    assert any("Gmail target All Mail is not visible" in issue for issue in issues)


def test_provider_preflight_rejects_gmail_target_all_mail_without_special_use(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="imap-secret"),
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )

    @contextlib.contextmanager
    def fake_connection(endpoint, *_args, **_kwargs):
        yield FakeIcloudInboxSourceImap() if endpoint.provider == "imap" else FakePreflightTargetAllMailWithoutSpecialUse()

    with mock.patch("components.provider_ops.imap_connection", fake_connection):
        ok, issues = provider_preflight(config, max_workers=1)

    assert not ok
    assert any("Gmail target All Mail is not visible" in issue for issue in issues)


def test_provider_preflight_rejects_gmail_target_unselectable_all_mail(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="imap-secret"),
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="target@gmail.com", password="gmail-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )

    @contextlib.contextmanager
    def fake_connection(endpoint, *_args, **_kwargs):
        yield FakeIcloudInboxSourceImap() if endpoint.provider == "imap" else FakePreflightTargetAllMailNotSelectable()

    with mock.patch("components.provider_ops.imap_connection", fake_connection):
        ok, issues = provider_preflight(config, max_workers=1)

    assert not ok
    assert any("Gmail target All Mail is not selectable" in issue for issue in issues)


def test_provider_preflight_requires_gmail_all_mail_visibility(tmp_path: Path) -> None:
    config = _provider_config()

    @contextlib.contextmanager
    def fake_connection(endpoint, *_args, **_kwargs):
        yield FakePreflightSourceNoAllMail() if endpoint.provider == "gmail" else FakePreflightTarget()

    with mock.patch("components.provider_ops.imap_connection", fake_connection):
        ok, issues = provider_preflight(config, max_workers=1)

    assert not ok
    assert any("All Mail is not visible" in issue for issue in issues)


def test_provider_preflight_requires_gmail_selectable_all_mail(tmp_path: Path) -> None:
    config = _provider_config()

    @contextlib.contextmanager
    def fake_connection(endpoint, *_args, **_kwargs):
        yield FakeGmailSourceAllMailNotSelectable() if endpoint.provider == "gmail" else FakePreflightTarget()

    with mock.patch("components.provider_ops.imap_connection", fake_connection):
        ok, issues = provider_preflight(config, max_workers=1)

    assert not ok
    assert any("Gmail source All Mail is not selectable" in issue for issue in issues)


def test_provider_preflight_requires_gmail_full_visibility_attestation(tmp_path: Path) -> None:
    config = _provider_config()
    config.source.gmail_full_visibility_verified = False

    @contextlib.contextmanager
    def fake_connection(endpoint, *_args, **_kwargs):
        yield FakeSourceImap() if endpoint.provider == "gmail" else FakePreflightTarget()

    with mock.patch("components.provider_ops.imap_connection", fake_connection):
        ok, issues = provider_preflight(config, max_workers=1)

    assert not ok
    assert any("full IMAP visibility is not attested" in issue for issue in issues)


def test_provider_preflight_accepts_attested_gmail_full_visibility(tmp_path: Path) -> None:
    config = _provider_config()
    config.source.gmail_full_visibility_verified = True

    @contextlib.contextmanager
    def fake_connection(endpoint, *_args, **_kwargs):
        yield FakeSourceImap() if endpoint.provider == "gmail" else FakePreflightTarget()

    with mock.patch("components.provider_ops.imap_connection", fake_connection):
        ok, issues = provider_preflight(config, max_workers=1)

    assert ok
    assert issues == []


def _write_provider_config_file(tmp_path: Path) -> Path:
    path = tmp_path / "migration.config.json"
    path.write_text(json.dumps({
        "source": {
            "provider": "gmail",
            "host": "imap.gmail.com",
            "auth": {"method": "xoauth2", "password": "token"},
        },
        "target": {
            "provider": "icloud",
            "host": "imap.mail.me.com",
            "auth": {"method": "app_password", "password": "secret"},
        },
        "accounts": [{"source_email": "source@example.com", "target_email": "target@icloud.com"}],
    }))
    return path


def _write_provider_gmail_target_config_file(tmp_path: Path) -> Path:
    path = tmp_path / "migration.gmail-target.config.json"
    path.write_text(json.dumps({
        "source": {
            "provider": "gmail",
            "host": "imap.gmail.com",
            "auth": {"method": "xoauth2", "password": "token"},
            "gmail_full_visibility_verified": True,
        },
        "target": {
            "provider": "gmail",
            "host": "imap.gmail.com",
            "auth": {"method": "xoauth2", "password": "target-token"},
            "gmail_full_visibility_verified": True,
        },
        "accounts": [{"source_email": "source@example.com", "target_email": "target@gmail.com"}],
        "migration": {"target_mode": "merge"},
    }))
    return path


@pytest.mark.parametrize(
    ("mode", "expected_roles"),
    [
        ("export", ("source",)),
        ("import", ("target",)),
        ("validate", ("target",)),
        ("test", ("source", "target")),
    ],
)
def test_main_routes_provider_modes_with_expected_connectivity_roles(
    tmp_path: Path,
    mode: str,
    expected_roles: tuple[str, ...],
) -> None:
    from components.main import main

    config_path = _write_provider_config_file(tmp_path)
    output_dir = tmp_path / "exported"
    input_dir = tmp_path / "exported"
    input_dir.mkdir()
    if mode in {"import", "validate"}:
        account_dir = _write_manifest_fixture(input_dir)
        if mode == "validate":
            config = load_config_file(config_path)
            assert isinstance(config, ProviderMigrationConfig)
            append_journal(account_dir, config.accounts[0], _journal_fixture(config, {
                "canonical_id": "gmail-123",
                "target_account": config.accounts[0].target_email,
                "target_mailbox": "Archive",
                "status": "committed",
            }))
    roles_seen: List[tuple[str, ...]] = []

    def record_test_accounts(*_args, **kwargs):
        roles_seen.append(tuple(kwargs["roles"]))

    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.check_free_space_for_path"), \
        mock.patch("components.main.provider_test_accounts", record_test_accounts), \
        mock.patch("components.main.provider_export_all"), \
        mock.patch("components.main.provider_import_all"), \
        mock.patch("components.main.provider_validate_all", return_value=(True, [])):
        args = [
            "--mode", mode,
            "--config", str(config_path),
            "--output-dir", str(output_dir),
            "--input-dir", str(input_dir),
            "--log-dir", str(tmp_path / "logs"),
            "--min-free-gb", "0",
            "--max-workers", "1",
            "--no-audit-after-export",
        ]
        assert main(args) == 0

    assert roles_seen == [expected_roles]


@pytest.mark.parametrize("mode", ["export", "import", "validate", "audit"])
def test_main_checks_provider_free_space_before_connectivity(
    tmp_path: Path,
    mode: str,
) -> None:
    from components.main import main

    config_path = _write_provider_config_file(tmp_path)
    output_dir = tmp_path / "provider-output"
    input_dir = tmp_path / "provider-input"
    if mode in {"import", "validate", "audit"}:
        account_dir = _write_manifest_fixture(input_dir)
        if mode == "validate":
            config = load_config_file(config_path)
            assert isinstance(config, ProviderMigrationConfig)
            append_journal(account_dir, config.accounts[0], _journal_fixture(config, {
                "canonical_id": "gmail-123",
                "target_account": config.accounts[0].target_email,
                "target_mailbox": "Archive",
                "status": "committed",
            }))
    events: List[str] = []

    def fail_free_space(*_args, **_kwargs):
        events.append("free-space")
        raise RuntimeError("low disk")

    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.check_free_space_for_path", fail_free_space), \
        mock.patch("components.main.provider_test_accounts", side_effect=AssertionError("connectivity should not run")), \
        mock.patch("components.main.provider_export_all", side_effect=AssertionError("export should not run")), \
        mock.patch("components.main.provider_import_all", side_effect=AssertionError("import should not run")), \
        mock.patch("components.main.provider_validate_all", side_effect=AssertionError("validate should not run")), \
        mock.patch("components.main.provider_audit_all", side_effect=AssertionError("audit should not run")):
        rc = main([
            "--mode", mode,
            "--config", str(config_path),
            "--output-dir", str(output_dir),
            "--input-dir", str(input_dir),
            "--log-dir", str(tmp_path / f"logs-provider-free-space-{mode}"),
            "--min-free-gb", "1000",
            "--max-workers", "1",
            "--no-audit-after-export",
        ])

    assert rc == 2
    assert events == ["free-space"]


@pytest.mark.parametrize("mode", ["import", "validate"])
def test_main_rejects_provider_symlinked_input_root_before_connectivity(
    tmp_path: Path,
    mode: str,
) -> None:
    from components.main import main

    config_path = _write_provider_config_file(tmp_path)
    outside = tmp_path / "outside-input"
    outside.mkdir()
    in_root = tmp_path / "exported"
    try:
        in_root.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.provider_test_accounts", side_effect=AssertionError("connectivity should not run")):
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
def test_main_rejects_provider_symlinked_input_root_ancestor_before_connectivity(
    tmp_path: Path,
    mode: str,
) -> None:
    from components.main import main

    config_path = _write_provider_config_file(tmp_path)
    outside = tmp_path / "outside-input"
    (outside / "staged").mkdir(parents=True)
    link_root = tmp_path / "link"
    try:
        link_root.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")
    in_root = link_root / "staged"
    assert not in_root.is_symlink()

    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.provider_test_accounts", side_effect=AssertionError("connectivity should not run")):
        rc = main([
            "--mode", mode,
            "--config", str(config_path),
            "--input-dir", str(in_root),
            "--log-dir", str(tmp_path / f"logs-ancestor-{mode}"),
            "--min-free-gb", "0",
            "--max-workers", "1",
        ])

    assert rc == 2


def test_main_rejects_provider_symlinked_output_root_before_connectivity(tmp_path: Path) -> None:
    from components.main import main

    config_path = _write_provider_config_file(tmp_path)
    outside = tmp_path / "outside-output"
    outside.mkdir()
    out_root = tmp_path / "exported"
    try:
        out_root.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.provider_test_accounts", side_effect=AssertionError("connectivity should not run")):
        rc = main([
            "--mode", "export",
            "--config", str(config_path),
            "--output-dir", str(out_root),
            "--log-dir", str(tmp_path / "logs-export"),
            "--min-free-gb", "0",
            "--max-workers", "1",
        ])

    assert rc == 2


def test_main_rejects_provider_hidden_symlinked_output_root_before_preflight_side_effects(tmp_path: Path) -> None:
    from components.main import main

    config_path = _write_provider_config_file(tmp_path)
    outside = tmp_path / "outside-hidden-output"
    outside.mkdir()
    link_root = tmp_path / "provider-exported"
    try:
        link_root.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")
    out_root = tmp_path / "missing-provider-root" / ".." / "provider-exported"
    assert not out_root.exists()
    assert not out_root.is_symlink()
    events: List[str] = []

    def record_free_space(*_args, **_kwargs) -> None:
        events.append("free-space")

    def record_connectivity(*_args, **_kwargs) -> None:
        events.append("connectivity")

    def record_export(*_args, **_kwargs) -> None:
        events.append("export")

    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.check_free_space_for_path", record_free_space), \
        mock.patch("components.main.provider_test_accounts", record_connectivity), \
        mock.patch("components.main.provider_export_all", record_export):
        rc = main([
            "--mode", "export",
            "--config", str(config_path),
            "--output-dir", str(out_root),
            "--log-dir", str(tmp_path / "logs-provider-hidden-export"),
            "--min-free-gb", "0",
            "--max-workers", "1",
        ])

    assert rc == 2
    assert events == []
    assert not (tmp_path / "missing-provider-root").exists()


@pytest.mark.parametrize("mode", ["export", "import", "validate"])
def test_main_rejects_provider_symlinked_account_dir_before_connectivity(
    tmp_path: Path,
    mode: str,
) -> None:
    from components.main import main

    config_path = _write_provider_config_file(tmp_path)
    root = tmp_path / f"provider-root-{mode}"
    root.mkdir()
    outside = tmp_path / f"outside-account-{mode}"
    outside.mkdir()
    account_dir = root / "source@example.com"
    try:
        account_dir.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    args = [
        "--mode", mode,
        "--config", str(config_path),
        "--output-dir", str(root if mode == "export" else tmp_path / f"unused-output-{mode}"),
        "--input-dir", str(root if mode != "export" else tmp_path / f"unused-input-{mode}"),
        "--log-dir", str(tmp_path / f"logs-account-{mode}"),
        "--min-free-gb", "0",
        "--max-workers", "1",
        "--no-audit-after-export",
    ]
    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.provider_test_accounts", side_effect=AssertionError("connectivity should not run")):
        rc = main(args)

    assert rc == 2


@pytest.mark.parametrize("mode", ["export", "import", "validate"])
def test_main_rejects_provider_file_root_before_connectivity(
    tmp_path: Path,
    mode: str,
) -> None:
    from components.main import main

    config_path = _write_provider_config_file(tmp_path)
    root = tmp_path / f"provider-root-{mode}"
    root.write_text("not a directory\n", encoding="utf-8")

    args = [
        "--mode", mode,
        "--config", str(config_path),
        "--output-dir", str(root if mode == "export" else tmp_path / f"unused-output-file-{mode}"),
        "--input-dir", str(root if mode != "export" else tmp_path / f"unused-input-file-{mode}"),
        "--log-dir", str(tmp_path / f"logs-file-{mode}"),
        "--min-free-gb", "0",
        "--max-workers", "1",
        "--no-audit-after-export",
    ]
    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.provider_test_accounts", side_effect=AssertionError("connectivity should not run")):
        rc = main(args)

    assert rc == 2


@pytest.mark.parametrize("mode", ["export", "import", "validate"])
def test_main_rejects_provider_symlinked_manifest_before_connectivity(
    tmp_path: Path,
    mode: str,
) -> None:
    from components.main import main

    config_path = _write_provider_config_file(tmp_path)
    root = tmp_path / f"provider-root-manifest-{mode}"
    account_dir = root / "source@example.com"
    account_dir.mkdir(parents=True)
    outside_manifest = tmp_path / f"outside-manifest-{mode}.jsonl"
    outside_manifest.write_text("", encoding="utf-8")
    try:
        (account_dir / "manifest.jsonl").symlink_to(outside_manifest)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    args = [
        "--mode", mode,
        "--config", str(config_path),
        "--output-dir", str(root if mode == "export" else tmp_path / f"unused-output-manifest-{mode}"),
        "--input-dir", str(root if mode != "export" else tmp_path / f"unused-input-manifest-{mode}"),
        "--log-dir", str(tmp_path / f"logs-manifest-{mode}"),
        "--min-free-gb", "0",
        "--max-workers", "1",
        "--no-audit-after-export",
    ]
    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.provider_test_accounts", side_effect=AssertionError("connectivity should not run")):
        rc = main(args)

    assert rc == 2


@pytest.mark.parametrize("mode", ["import", "validate"])
def test_main_rejects_provider_corrupt_payload_before_connectivity(
    tmp_path: Path,
    mode: str,
) -> None:
    from components.main import main

    config_path = _write_provider_config_file(tmp_path)
    root = tmp_path / f"provider-root-corrupt-{mode}"
    account_dir = _write_manifest_fixture(root)
    (account_dir / "messages" / "gmail-123.eml").write_bytes(b"corrupt payload")

    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.provider_test_accounts", side_effect=AssertionError("connectivity should not run")), \
        mock.patch("components.main.provider_import_all", side_effect=AssertionError("import should not run")), \
        mock.patch("components.main.provider_validate_all", side_effect=AssertionError("validate should not run")):
        rc = main([
            "--mode", mode,
            "--config", str(config_path),
            "--input-dir", str(root),
            "--log-dir", str(tmp_path / f"logs-corrupt-{mode}"),
            "--min-free-gb", "0",
            "--max-workers", "1",
        ])

    assert rc == 4
    assert not (account_dir / "validation-target@icloud.com.json").exists()


def test_main_rejects_provider_validate_missing_commit_before_connectivity(tmp_path: Path) -> None:
    from components.main import main

    config_path = _write_provider_config_file(tmp_path)
    root = tmp_path / "provider-root-missing-commit"
    account_dir = _write_manifest_fixture(root)

    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.provider_test_accounts", side_effect=AssertionError("connectivity should not run")), \
        mock.patch("components.main.provider_validate_all", side_effect=AssertionError("validate should not run")):
        rc = main([
            "--mode", "validate",
            "--config", str(config_path),
            "--input-dir", str(root),
            "--log-dir", str(tmp_path / "logs-missing-commit"),
            "--min-free-gb", "0",
            "--max-workers", "1",
        ])

    assert rc == 4
    assert not (account_dir / "validation-target@icloud.com.json").exists()


def test_main_allows_provider_import_pending_journal_to_recovery_path(tmp_path: Path) -> None:
    from components.main import main

    config_path = _write_provider_config_file(tmp_path)
    root = tmp_path / "provider-root-pending-import"
    account_dir = _write_manifest_fixture(root)
    config = load_config_file(config_path)
    assert isinstance(config, ProviderMigrationConfig)
    append_journal(account_dir, config.accounts[0], _journal_fixture(config, {
        "canonical_id": "gmail-123",
        "target_account": config.accounts[0].target_email,
        "target_mailbox": "Archive",
        "status": "pending",
    }))
    events: List[str] = []

    def record_connectivity(*_args, **_kwargs) -> None:
        events.append("connectivity")

    def record_import(*_args, **_kwargs) -> None:
        events.append("import")

    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.check_free_space_for_path"), \
        mock.patch("components.main.provider_test_accounts", record_connectivity), \
        mock.patch("components.main.provider_import_all", record_import):
        rc = main([
            "--mode", "import",
            "--config", str(config_path),
            "--input-dir", str(root),
            "--log-dir", str(tmp_path / "logs-pending-import"),
            "--min-free-gb", "0",
            "--max-workers", "1",
        ])

    assert rc == 0
    assert events == ["connectivity", "import"]


def test_main_allows_provider_import_missing_gmail_msgid_to_repair_path(tmp_path: Path) -> None:
    from components.main import main

    config_path = _write_provider_gmail_target_config_file(tmp_path)
    config = load_config_file(config_path)
    assert isinstance(config, ProviderMigrationConfig)
    root = tmp_path / "provider-root-gmail-msgid-import"
    account_dir = _write_manifest_fixture(root)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["target_account"] = "target@gmail.com"
    row["primary_mailbox"] = "INBOX"
    row["gmail_labels"] = ["\\Inbox"]
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(account_dir, target="target@gmail.com", target_endpoint=config.target)
    (account_dir / "import-target@gmail.com.journal.jsonl").write_text(json.dumps(_journal_fixture_for_manifest_row(config, row, {
        "canonical_id": "gmail-123",
        "target_account": "target@gmail.com",
        "target_mailbox": "INBOX",
        "status": "committed",
    })) + "\n")
    events: List[str] = []

    def record_connectivity(*_args, **_kwargs) -> None:
        events.append("connectivity")

    def record_import(*_args, **_kwargs) -> None:
        events.append("import")

    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.check_free_space_for_path"), \
        mock.patch("components.main.provider_test_accounts", record_connectivity), \
        mock.patch("components.main.provider_import_all", record_import):
        rc = main([
            "--mode", "import",
            "--config", str(config_path),
            "--input-dir", str(root),
            "--log-dir", str(tmp_path / "logs-gmail-msgid-import"),
            "--min-free-gb", "0",
            "--max-workers", "1",
        ])

    assert rc == 0
    assert events == ["connectivity", "import"]


def test_main_allows_provider_import_trailing_journal_repair_path(tmp_path: Path) -> None:
    from components.main import main

    config_path = _write_provider_config_file(tmp_path)
    config = load_config_file(config_path)
    assert isinstance(config, ProviderMigrationConfig)
    root = tmp_path / "provider-root-trailing-import"
    account_dir = _write_manifest_fixture(root)
    journal = account_dir / "import-target@icloud.com.journal.jsonl"
    valid = _journal_fixture(config, {
        "canonical_id": "gmail-123",
        "target_account": config.accounts[0].target_email,
        "target_mailbox": "Archive",
        "status": "pending",
    })
    journal.write_text(json.dumps(valid) + "\n" + '{"canonical_id": ')
    events: List[str] = []

    def record_connectivity(*_args, **_kwargs) -> None:
        events.append("connectivity")

    def record_import(*_args, **_kwargs) -> None:
        events.append("import")

    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.check_free_space_for_path"), \
        mock.patch("components.main.provider_test_accounts", record_connectivity), \
        mock.patch("components.main.provider_import_all", record_import):
        rc = main([
            "--mode", "import",
            "--config", str(config_path),
            "--input-dir", str(root),
            "--log-dir", str(tmp_path / "logs-provider-trailing-import"),
            "--min-free-gb", "0",
            "--max-workers", "1",
        ])

    assert rc == 0
    assert events == ["connectivity", "import"]
    assert json.loads(journal.read_text()) == valid


def test_main_provider_import_low_disk_does_not_repair_trailing_journal(tmp_path: Path) -> None:
    from components.main import main

    config_path = _write_provider_config_file(tmp_path)
    config = load_config_file(config_path)
    assert isinstance(config, ProviderMigrationConfig)
    root = tmp_path / "provider-root-trailing-low-disk"
    account_dir = _write_manifest_fixture(root)
    journal = account_dir / "import-target@icloud.com.journal.jsonl"
    original = '{"canonical_id": '
    journal.write_text(original)

    def fail_free_space(*_args, **_kwargs) -> None:
        raise RuntimeError("low disk")

    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.check_free_space_for_path", fail_free_space), \
        mock.patch("components.main.provider_test_accounts", side_effect=AssertionError("connectivity should not run")), \
        mock.patch("components.main.provider_import_all", side_effect=AssertionError("import should not run")):
        rc = main([
            "--mode", "import",
            "--config", str(config_path),
            "--input-dir", str(root),
            "--log-dir", str(tmp_path / "logs-provider-trailing-low-disk"),
            "--min-free-gb", "1000",
            "--max-workers", "1",
        ])

    assert rc == 2
    assert journal.read_text() == original


def test_main_routes_provider_preflight(tmp_path: Path) -> None:
    from components.main import main

    config_path = _write_provider_config_file(tmp_path)

    with mock.patch("components.main.check_environment"), \
        mock.patch("components.main.provider_preflight", return_value=(True, [])) as preflight:
        rc = main([
            "--mode", "preflight",
            "--config", str(config_path),
            "--log-dir", str(tmp_path / "logs"),
            "--max-workers", "1",
            "--min-free-gb", "0",
        ])

    assert rc == 0
    preflight.assert_called_once()
