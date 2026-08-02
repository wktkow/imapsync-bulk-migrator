from __future__ import annotations

import contextlib
import dataclasses
import json
import os
import random
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import components.provider_ops as provider_ops
from components.content_binding import CONTENT_BINDING_FIELD
from components.models import (
    AuthConfig,
    MigrationAccount,
    MigrationSettings,
    ProviderEndpoint,
    ProviderMigrationConfig,
)
from components.provider_ops import (
    MailboxInfo,
    build_provider_routing_report,
    gmail_labels_for_restore,
    provider_export_state_contract_issues,
    provider_audit_account,
    provider_import_account,
    provider_validate_account,
    routed_manifest_rows,
    save_provider_routing_plan,
    translated_target_mailboxes_for_rows,
)
from components.routing import (
    CUSTOM_LABEL,
    GENERIC_MAILBOX,
    GMAIL_SYSTEM,
    RoutingConfig,
    SourceFolder,
    TargetLabel,
    resolve_routing_plan,
)
from tests.test_provider_migration import (
    FakeGmailTargetImap,
    OverlapStoredGmailTarget,
    _append_identical_provider_fixture_row,
    _journal_fixture_for_manifest_row,
    _many_to_one_gmail_config,
    _write_provider_account_fixture,
    _write_provider_export_state,
    _write_single_manifest_row,
)


def _routing_config() -> RoutingConfig:
    return RoutingConfig.from_dict(
        {
            "enabled": True,
            "accounts": {"source@example.com": {"default_label": "Imported"}},
        }
    )


def _provider_config(routing: RoutingConfig | None = None) -> ProviderMigrationConfig:
    return ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", password="source-token"),
            gmail_full_visibility_verified=True,
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", password="target-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[
            MigrationAccount(
                source_email="source@example.com",
                target_email="target@example.com",
            )
        ],
        migration=MigrationSettings(
            target_mode="merge",
            routing=routing or _routing_config(),
        ),
    )


def _plan(*, existing: bool = False):
    labels = (
        [TargetLabel("Imported", CUSTOM_LABEL, target_id="Label_1")]
        if existing
        else []
    )
    return resolve_routing_plan(
        _routing_config(),
        [SourceFolder("source@example.com", "INBOX", attributes=("\\Inbox",))],
        labels,
    )


def _manifest_row(identity: str = "m1") -> dict:
    return {
        "canonical_id": identity,
        "primary_mailbox": "INBOX",
        "source_mailboxes": ["INBOX"],
        "source_mailbox_paths": {"INBOX": ["INBOX"]},
        "gmail_labels": ["Source/Private", "\\Important"],
        "flags": "\\Seen",
    }


def _duplicate_routing_row(
    identity: str,
    *,
    primary_mailbox: str = "Archive",
    systems: tuple[str, ...] = (),
    labels: tuple[str, ...] = (),
    flags: str = "",
    internaldate: str = "01-Jan-2024 00:00:00 +0000",
) -> dict:
    return {
        "canonical_id": identity,
        "primary_mailbox": primary_mailbox,
        "routing_active": True,
        "routing_system_destinations": list(systems),
        "routing_target_labels": list(labels),
        "flags": flags,
        "internaldate": internaldate,
    }


def _duplicate_stage(
    source: str,
    rows: list[dict],
    journal: list[dict] | None = None,
) -> tuple[MigrationAccount, Path, list[dict], list[dict]]:
    return (
        MigrationAccount(source, "target@gmail.com"),
        Path(f"/{source}"),
        rows,
        journal or [],
    )


def _recursive_candidate_assignment_reference(
    candidates_by_row: dict[str, list[dict]],
    *,
    required_row_keys: set[str] | None = None,
    unavailable_physical_keys: set[tuple] | None = None,
) -> dict[str, dict]:
    required = required_row_keys or set()
    unavailable = unavailable_physical_keys or set()
    candidate_by_row_and_key = {
        (row_key, candidate["physical_key"]): candidate
        for row_key, candidates in candidates_by_row.items()
        for candidate in candidates
        if candidate["physical_key"] not in unavailable
    }
    keys_by_row = {
        row_key: sorted(
            {
                candidate["physical_key"]
                for candidate in candidates
                if candidate["physical_key"] not in unavailable
            },
            key=repr,
        )
        for row_key, candidates in candidates_by_row.items()
    }
    row_by_candidate: dict[tuple, str] = {}

    def assign(row_key: str, seen: set[tuple]) -> bool:
        for candidate_key in keys_by_row[row_key]:
            if candidate_key in seen:
                continue
            seen.add(candidate_key)
            previous_row = row_by_candidate.get(candidate_key)
            if previous_row is None or assign(previous_row, seen):
                row_by_candidate[candidate_key] = row_key
                return True
        return False

    for row_key in sorted(
        keys_by_row,
        key=lambda value: (
            0 if value in required else 1,
            len(keys_by_row[value]),
            value,
        ),
    ):
        assign(row_key, set())
    return {
        row_key: candidate_by_row_and_key[(row_key, candidate_key)]
        for candidate_key, row_key in row_by_candidate.items()
    }


class _GenericRoutedVirtualSource:
    def __init__(
        self,
        mailboxes: list[MailboxInfo],
        deliveries: dict[str, list[tuple[bytes, str, str]]],
        *,
        fail_body_mailbox: str = "",
    ) -> None:
        self.mailboxes = mailboxes
        self.deliveries = deliveries
        self.fail_body_mailbox = fail_body_mailbox
        self.selected = ""

    def capability(self):
        return "OK", [b"IMAP4rev1 SPECIAL-USE"]

    def list(self, *_args):
        return (
            "OK",
            [
                (
                    f"({' '.join(mailbox.attributes)}) "
                    f'"{mailbox.delimiter}" "{mailbox.name}"'
                ).encode("ascii")
                for mailbox in self.mailboxes
            ],
        )

    def select(self, mailbox: str, readonly: bool = False):
        del readonly
        self.selected = mailbox.strip('"').replace(r'\"', '"')
        return "OK", [str(len(self.deliveries[self.selected])).encode("ascii")]

    def response(self, name: str):
        assert name == "UIDVALIDITY"
        mailbox_index = next(
            index
            for index, mailbox in enumerate(self.mailboxes, 1)
            if mailbox.name == self.selected
        )
        return "OK", [str(1000 + mailbox_index).encode("ascii")]

    def uid(self, command: str, *args):
        if command == "search":
            return "OK", [
                " ".join(
                    str(index)
                    for index in range(1, len(self.deliveries[self.selected]) + 1)
                ).encode("ascii")
            ]
        if command != "fetch":
            raise AssertionError(command)
        uid = int(args[0])
        query = str(args[-1])
        body, flags, internaldate = self.deliveries[self.selected][uid - 1]
        meta = (
            f"{uid} (UID {uid} RFC822.SIZE {len(body)} FLAGS ({flags}) "
            f'INTERNALDATE "{internaldate}")'
        ).encode("ascii")
        if "BODY.PEEK[]" not in query:
            return "OK", [meta]
        if self.selected == self.fail_body_mailbox:
            return "NO", [b"injected interruption"]
        return "OK", [
            (meta + f" BODY[] {{{len(body)}}}".encode("ascii"), body)
        ]

    def logout(self):
        return "OK", []


class _GenericPreflightTarget:
    def capability(self):
        return "OK", [b"IMAP4rev1"]

    def list(self, *_args):
        return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

    def logout(self):
        return "OK", []


def _generic_routed_virtual_setup(
    mailboxes: list[MailboxInfo],
) -> tuple[ProviderMigrationConfig, MigrationAccount, object, dict[str, str]]:
    label_by_mailbox = {
        mailbox.name: f"Route {index}"
        for index, mailbox in enumerate(mailboxes, 1)
    }
    routing = RoutingConfig.from_dict(
        {
            "enabled": True,
            "global_rules": [
                {
                    "match": {"folder": mailbox.name},
                    "destinations": [
                        {
                            "type": CUSTOM_LABEL,
                            "name": label_by_mailbox[mailbox.name],
                        }
                    ],
                }
                for mailbox in mailboxes
            ],
        }
    )
    account = MigrationAccount("source@example.com", "target@gmail.com")
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="source.example.com",
            auth=AuthConfig(method="password", password="source-secret"),
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", password="target-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=[account],
        migration=MigrationSettings(target_mode="merge", routing=routing),
    )
    plan = resolve_routing_plan(
        routing,
        [
            SourceFolder(
                account.source_email,
                mailbox.name,
                delimiter=mailbox.delimiter,
                attributes=mailbox.attributes,
            )
            for mailbox in mailboxes
        ],
        [],
    )
    return config, account, plan, label_by_mailbox


def test_plan_persistence_retains_reviewed_create_snapshot_on_status_only_rerun(
    tmp_path: Path,
) -> None:
    create_plan = _plan(existing=False)
    existing_plan = _plan(existing=True)
    assert create_plan.mapping_digest == existing_plan.mapping_digest

    path = save_provider_routing_plan(tmp_path, create_plan)
    save_provider_routing_plan(tmp_path, existing_plan)

    assert json.loads(path.read_text(encoding="utf-8")) == create_plan.to_dict()
    assert json.loads(path.read_text(encoding="utf-8")) != existing_plan.to_dict()


def test_plan_persistence_digest_binds_changed_source_discovery(
    tmp_path: Path,
) -> None:
    original = _plan()
    changed = resolve_routing_plan(
        _routing_config(),
        [SourceFolder("source@example.com", "INBOX", delimiter="/", attributes=("\\Inbox",))],
        [],
    )
    assert original.mapping_digest != changed.mapping_digest
    save_provider_routing_plan(tmp_path, original)

    with pytest.raises(RuntimeError, match="source discovery"):
        save_provider_routing_plan(tmp_path, changed)


def test_plan_persistence_allows_only_one_of_two_distinct_concurrent_creators(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    original = _plan()
    changed = resolve_routing_plan(
        _routing_config(),
        [SourceFolder("source@example.com", "INBOX", delimiter="/", attributes=("\\Inbox",))],
        [],
    )
    barrier = threading.Barrier(2)
    real_create_once = provider_ops._atomic_json_create_once

    def synchronized_create_once(path: Path, payload: dict) -> bool:
        barrier.wait(timeout=5)
        return real_create_once(path, payload)

    monkeypatch.setattr(provider_ops, "_atomic_json_create_once", synchronized_create_once)

    def attempt(plan):
        try:
            save_provider_routing_plan(tmp_path, plan)
        except RuntimeError as exc:
            return "error", str(exc), plan
        return "ok", "", plan

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(attempt, (original, changed)))

    successes = [item for item in outcomes if item[0] == "ok"]
    failures = [item for item in outcomes if item[0] == "error"]
    assert len(successes) == 1
    assert len(failures) == 1
    path = provider_ops.provider_routing_plan_path(tmp_path)
    assert json.loads(path.read_text(encoding="utf-8")) == successes[0][2].to_dict()
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.stat().st_nlink == 1


def test_plan_persistence_same_plan_race_never_publishes_with_a_hard_link(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    plan = _plan()
    barrier = threading.Barrier(2)
    real_create_once = provider_ops._atomic_json_create_once

    def synchronized_create_once(path: Path, payload: dict) -> bool:
        barrier.wait(timeout=5)
        return real_create_once(path, payload)

    def forbidden_hard_link(*_args, **_kwargs):
        raise AssertionError("create-once publication must not expose a hard-linked final file")

    monkeypatch.setattr(provider_ops, "_atomic_json_create_once", synchronized_create_once)
    monkeypatch.setattr(provider_ops.os, "link", forbidden_hard_link)

    with ThreadPoolExecutor(max_workers=2) as executor:
        paths = list(executor.map(lambda _index: save_provider_routing_plan(tmp_path, plan), range(2)))

    expected = provider_ops.provider_routing_plan_path(tmp_path)
    assert paths == [expected, expected]
    assert json.loads(expected.read_text(encoding="utf-8")) == plan.to_dict()
    assert expected.stat().st_mode & 0o777 == 0o600
    assert expected.stat().st_nlink == 1
    assert not list(tmp_path.glob(".routing-plan.json.*.tmp"))


def test_create_once_interruption_before_rename_does_not_expose_final_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / "routing-plan.json"

    def interrupted_rename(parent_fd: int, src: str, dst: str) -> bool:
        source_stat = provider_ops.os.stat(src, dir_fd=parent_fd, follow_symlinks=False)
        assert source_stat.st_nlink == 1
        with pytest.raises(FileNotFoundError):
            provider_ops.os.stat(dst, dir_fd=parent_fd, follow_symlinks=False)
        raise RuntimeError("simulated interruption before publication")

    monkeypatch.setattr(provider_ops, "_rename_provider_entry_create_once", interrupted_rename)

    with pytest.raises(RuntimeError, match="simulated interruption"):
        provider_ops._atomic_bytes_create_once(path, b"complete payload\n")

    assert not path.exists()
    assert not list(tmp_path.glob(".routing-plan.json.*.tmp"))


def test_create_once_does_not_replace_a_noncooperating_race_winner(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / "routing-plan.json"
    competitor_payload = b"competitor payload\n"
    real_rename_create_once = provider_ops._rename_provider_entry_create_once

    def race_with_competitor(parent_fd: int, src: str, dst: str) -> bool:
        fd = provider_ops.os.open(
            dst,
            provider_ops.os.O_WRONLY | provider_ops.os.O_CREAT | provider_ops.os.O_EXCL,
            0o600,
            dir_fd=parent_fd,
        )
        with provider_ops.os.fdopen(fd, "wb") as f:
            f.write(competitor_payload)
            f.flush()
            provider_ops.os.fsync(f.fileno())
        return real_rename_create_once(parent_fd, src, dst)

    monkeypatch.setattr(
        provider_ops,
        "_rename_provider_entry_create_once",
        race_with_competitor,
    )

    assert not provider_ops._atomic_bytes_create_once(path, b"our payload\n")
    assert path.read_bytes() == competitor_payload
    assert path.stat().st_nlink == 1
    assert not list(tmp_path.glob(".routing-plan.json.*.tmp"))


def test_plan_persistence_refuses_existing_symlink_without_touching_target(
    tmp_path: Path,
) -> None:
    plan = _plan()
    outside = tmp_path.parent / f"{tmp_path.name}-outside-plan.json"
    payload = json.dumps(plan.to_dict())
    outside.write_text(payload, encoding="utf-8")
    path = provider_ops.provider_routing_plan_path(tmp_path)
    path.symlink_to(outside)

    with pytest.raises(RuntimeError, match="symlinked provider file"):
        save_provider_routing_plan(tmp_path, plan)

    assert outside.read_text(encoding="utf-8") == payload
    assert not list(tmp_path.glob(".routing-plan.json.*.tmp"))


def test_plan_persistence_refuses_existing_hard_link_without_touching_target(
    tmp_path: Path,
) -> None:
    plan = _plan()
    outside = tmp_path.parent / f"{tmp_path.name}-outside-hard-plan.json"
    payload = json.dumps(plan.to_dict())
    outside.write_text(payload, encoding="utf-8")
    path = provider_ops.provider_routing_plan_path(tmp_path)
    try:
        path.hardlink_to(outside)
    except OSError as exc:
        pytest.skip(f"hard links unavailable: {exc}")

    with pytest.raises(RuntimeError, match="hard-linked provider file"):
        save_provider_routing_plan(tmp_path, plan)

    assert outside.read_text(encoding="utf-8") == payload
    assert not list(tmp_path.glob(".routing-plan.json.*.tmp"))


def test_custom_label_routing_anchors_in_all_mail_and_does_not_leak_source_labels() -> None:
    config = _provider_config()
    rows, excluded = routed_manifest_rows(config, config.accounts[0], [_manifest_row()], _plan())

    assert excluded == []
    assert rows[0]["primary_mailbox"] == "Archive"
    assert rows[0]["routing_target_labels"] == ["Imported"]
    assert gmail_labels_for_restore(rows[0], "[Gmail]/All Mail") == ["Imported"]


def test_virtual_and_regular_memberships_both_contribute_persisted_destinations() -> None:
    routing = RoutingConfig.from_dict(
        {
            "enabled": True,
            "global_rules": [
                {
                    "match": {"folder": "INBOX"},
                    "destinations": [{"type": CUSTOM_LABEL, "name": "InboxRoute"}],
                },
                {
                    "match": {"folder": "[Gmail]/All Mail"},
                    "destinations": [{"type": CUSTOM_LABEL, "name": "AllRoute"}],
                },
            ],
        }
    )
    plan = resolve_routing_plan(
        routing,
        [
            SourceFolder("source@example.com", "INBOX", attributes=("\\Inbox",)),
            SourceFolder(
                "source@example.com",
                "[Gmail]/All Mail",
                delimiter="/",
                attributes=("\\All",),
            ),
        ],
        [],
    )
    row = _manifest_row()
    row["source_mailboxes"] = ["INBOX", "[Gmail]/All Mail"]
    row["source_mailbox_paths"] = {
        "INBOX": ["INBOX"],
        "[Gmail]/All Mail": ["[Gmail]", "All Mail"],
    }

    routed, excluded = routed_manifest_rows(
        _provider_config(routing),
        _provider_config(routing).accounts[0],
        [row],
        plan,
    )

    assert excluded == []
    assert routed[0]["routing_target_labels"] == ["AllRoute", "InboxRoute"]
    assert routed[0]["routing_source_folders"] == ["[Gmail]/All Mail", "INBOX"]


def test_routed_generic_export_folds_all_starred_and_important_memberships(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    mailboxes = [
        MailboxInfo("Starred", "/", ("\\HasNoChildren", "\\Starred")),
        MailboxInfo("All One", "/", ("\\HasNoChildren", "\\All")),
        MailboxInfo("Important", ".", ("\\HasNoChildren", "\\Important")),
        MailboxInfo("All Two", "/", ("\\HasNoChildren", "\\All")),
        MailboxInfo("INBOX", "/", ("\\HasNoChildren", "\\Inbox")),
    ]
    config, account, plan, label_by_mailbox = _generic_routed_virtual_setup(
        mailboxes
    )
    body = b"Message-ID: <virtual@example.com>\r\n\r\nbody"
    internaldate = "01-Jan-2024 00:00:00 +0000"
    source = _GenericRoutedVirtualSource(
        mailboxes,
        {
            "INBOX": [(body, "\\Seen", internaldate)],
            "All One": [(body, "\\Seen", internaldate)],
            "All Two": [(body, "\\Seen", internaldate)],
            "Starred": [(body, "\\Seen \\Flagged", internaldate)],
            "Important": [(body, "\\Seen \\Answered", internaldate)],
        },
    )
    monkeypatch.setattr(
        provider_ops,
        "imap_connection",
        lambda *_args, **_kwargs: contextlib.nullcontext(source),
    )

    provider_ops.provider_export_account(
        config,
        account,
        tmp_path,
        routing_plan=plan,
    )

    account_dir = provider_ops.account_export_dir(tmp_path, account)
    rows = provider_ops.load_manifest(account_dir)
    assert len(rows) == 1
    row = rows[0]
    assert set(row["source_mailboxes"]) == {
        "INBOX",
        "All One",
        "All Two",
        "Starred",
        "Important",
    }
    assert row["source_mailbox_delimiters"]["Important"] == "."
    assert row["source_mailbox_attributes"]["All Two"] == [
        "\\All",
        "\\HasNoChildren",
    ]
    assert row["source_mailbox_paths"]["Important"] == ["Important"]
    assert row["uid_by_mailbox"] == {
        mailbox.name: 1 for mailbox in mailboxes
    }
    assert "\\Flagged" in row["flags"].split()
    assert "\\Answered" not in row["flags"].split()
    assert len(list((account_dir / "messages").glob("*.eml"))) == 1

    routed, excluded = routed_manifest_rows(config, account, rows, plan)
    assert excluded == []
    assert routed[0]["routing_target_labels"] == sorted(
        label_by_mailbox.values(),
        key=lambda value: (value.casefold(), value),
    )
    assert set(routed[0]["routing_source_folders"]) == set(
        label_by_mailbox
    )


def test_routed_generic_export_preserves_duplicate_multiplicity_and_subset_ambiguity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    mailboxes = [
        MailboxInfo("INBOX", "/", ("\\Inbox",)),
        MailboxInfo("All Mail", "/", ("\\All",)),
        MailboxInfo("Starred", "/", ("\\Starred",)),
    ]
    config, account, plan, _labels = _generic_routed_virtual_setup(mailboxes)
    body = b"Message-ID: <duplicate@example.com>\r\n\r\nsame"
    internaldate = "01-Jan-2024 00:00:00 +0000"
    source = _GenericRoutedVirtualSource(
        mailboxes,
        {
            "INBOX": [
                (body, "\\Seen", internaldate),
                (body, "\\Seen", internaldate),
            ],
            "All Mail": [
                (body, "\\Seen", internaldate),
                (body, "\\Seen", internaldate),
            ],
            "Starred": [(body, "\\Seen \\Flagged", internaldate)],
        },
    )
    monkeypatch.setattr(
        provider_ops,
        "imap_connection",
        lambda *_args, **_kwargs: contextlib.nullcontext(source),
    )

    provider_ops.provider_export_account(
        config,
        account,
        tmp_path,
        routing_plan=plan,
    )

    rows = provider_ops.load_manifest(
        provider_ops.account_export_dir(tmp_path, account)
    )
    assert len(rows) == 3
    ordinary_rows = [
        row for row in rows if "INBOX" in row["source_mailboxes"]
    ]
    assert len(ordinary_rows) == 2
    assert {
        (
            row["uid_by_mailbox"]["INBOX"],
            row["uid_by_mailbox"]["All Mail"],
        )
        for row in ordinary_rows
    } == {(1, 1), (2, 2)}
    assert all("Starred" not in row["source_mailboxes"] for row in ordinary_rows)
    starred_only = [
        row for row in rows if row["source_mailboxes"] == ["Starred"]
    ]
    assert len(starred_only) == 1


def test_routed_generic_export_limits_each_subset_view_to_one_anchor_occurrence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    mailboxes = [
        MailboxInfo("INBOX", "/", ("\\Inbox",)),
        MailboxInfo("Important", "/", ("\\Important",)),
    ]
    config, account, plan, _labels = _generic_routed_virtual_setup(mailboxes)
    body = b"Message-ID: <subset@example.com>\r\n\r\nsame"
    internaldate = "01-Jan-2024 00:00:00 +0000"
    source = _GenericRoutedVirtualSource(
        mailboxes,
        {
            "INBOX": [(body, "\\Seen", internaldate)],
            "Important": [
                (body, "\\Seen", internaldate),
                (body, "\\Seen", internaldate),
            ],
        },
    )
    monkeypatch.setattr(
        provider_ops,
        "imap_connection",
        lambda *_args, **_kwargs: contextlib.nullcontext(source),
    )

    provider_ops.provider_export_account(
        config,
        account,
        tmp_path,
        routing_plan=plan,
    )

    rows = provider_ops.load_manifest(
        provider_ops.account_export_dir(tmp_path, account)
    )
    assert len(rows) == 2
    assert sorted(
        row["source_mailboxes"] for row in rows
    ) == [["INBOX", "Important"], ["Important"]]


def test_routed_generic_export_reuses_completed_all_view_anchors_by_multiplicity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    mailboxes = [
        MailboxInfo("All One", "/", ("\\All",)),
        MailboxInfo("All Two", "/", ("\\All",)),
    ]
    config, account, plan, _labels = _generic_routed_virtual_setup(mailboxes)
    body = b"Message-ID: <all-only@example.com>\r\n\r\nsame"
    delivery = (body, "\\Seen", "01-Jan-2024 00:00:00 +0000")
    source = _GenericRoutedVirtualSource(
        mailboxes,
        {"All One": [delivery, delivery], "All Two": [delivery]},
    )
    monkeypatch.setattr(
        provider_ops,
        "imap_connection",
        lambda *_args, **_kwargs: contextlib.nullcontext(source),
    )

    provider_ops.provider_export_account(
        config,
        account,
        tmp_path,
        routing_plan=plan,
    )

    rows = provider_ops.load_manifest(
        provider_ops.account_export_dir(tmp_path, account)
    )
    assert len(rows) == 2
    assert sorted(row["source_mailboxes"] for row in rows) == [
        ["All One"],
        ["All One", "All Two"],
    ]
    combined = next(row for row in rows if "All Two" in row["source_mailboxes"])
    assert combined["uid_by_mailbox"] == {"All One": 1, "All Two": 1}


def test_routed_generic_export_and_preflight_share_partial_all_view_coverage(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    mailboxes = [
        MailboxInfo("INBOX", "/", ("\\Inbox",)),
        MailboxInfo("All One", "/", ("\\All",)),
        MailboxInfo("All Two", "/", ("\\All",)),
    ]
    config, account, plan, _labels = _generic_routed_virtual_setup(mailboxes)
    internaldate = "01-Jan-2024 00:00:00 +0000"
    delivery_a = (b"A", "\\Seen", internaldate)
    delivery_b = (b"B", "\\Seen", internaldate)
    deliveries = {
        "INBOX": [delivery_a],
        "All One": [delivery_a, delivery_b],
        "All Two": [delivery_a, delivery_b],
    }
    source = _GenericRoutedVirtualSource(mailboxes, deliveries)
    monkeypatch.setattr(
        provider_ops,
        "imap_connection",
        lambda *_args, **_kwargs: contextlib.nullcontext(source),
    )

    provider_ops.provider_export_account(
        config,
        account,
        tmp_path,
        routing_plan=plan,
    )

    rows = provider_ops.load_manifest(
        provider_ops.account_export_dir(tmp_path, account)
    )
    assert len(rows) == 2
    inbox_row = next(row for row in rows if "INBOX" in row["source_mailboxes"])
    all_only_row = next(row for row in rows if "INBOX" not in row["source_mailboxes"])
    assert set(inbox_row["source_mailboxes"]) == {
        "INBOX",
        "All One",
        "All Two",
    }
    assert set(all_only_row["source_mailboxes"]) == {"All One", "All Two"}

    config.target = ProviderEndpoint(
        provider="imap",
        host="target.example.com",
        auth=AuthConfig(method="password", password="target-secret"),
        available_bytes=len(delivery_a[0]) + len(delivery_b[0]),
    )

    @contextlib.contextmanager
    def connection(_endpoint, _account, *, role: str):
        assert _account == account
        if role == "source":
            yield _GenericRoutedVirtualSource(mailboxes, deliveries)
        else:
            yield _GenericPreflightTarget()

    monkeypatch.setattr(provider_ops, "imap_connection", connection)
    ok, issues = provider_ops.provider_preflight(config, max_workers=1)
    assert ok is True
    assert issues == []


def test_routed_generic_export_rebuilds_virtual_membership_after_interruption(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    mailboxes = [
        MailboxInfo("INBOX", "/", ("\\Inbox",)),
        MailboxInfo("All Mail", "/", ("\\All",)),
    ]
    config, account, plan, _labels = _generic_routed_virtual_setup(mailboxes)
    body = b"Message-ID: <resume@example.com>\r\n\r\nbody"
    delivery = [(body, "\\Seen", "01-Jan-2024 00:00:00 +0000")]
    interrupted = _GenericRoutedVirtualSource(
        mailboxes,
        {"INBOX": delivery, "All Mail": delivery},
        fail_body_mailbox="All Mail",
    )
    monkeypatch.setattr(
        provider_ops,
        "imap_connection",
        lambda *_args, **_kwargs: contextlib.nullcontext(interrupted),
    )
    with pytest.raises(RuntimeError, match="fetch failed in All Mail"):
        provider_ops.provider_export_account(
            config,
            account,
            tmp_path,
            routing_plan=plan,
        )

    account_dir = provider_ops.account_export_dir(tmp_path, account)
    assert provider_ops.load_manifest(account_dir)[0]["source_mailboxes"] == [
        "INBOX"
    ]
    resumed = _GenericRoutedVirtualSource(
        mailboxes,
        {"INBOX": delivery, "All Mail": delivery},
    )
    monkeypatch.setattr(
        provider_ops,
        "imap_connection",
        lambda *_args, **_kwargs: contextlib.nullcontext(resumed),
    )
    provider_ops.provider_export_account(
        config,
        account,
        tmp_path,
        routing_plan=plan,
    )

    rows = provider_ops.load_manifest(account_dir)
    assert len(rows) == 1
    assert rows[0]["source_mailboxes"] == ["All Mail", "INBOX"]
    assert len(list((account_dir / "messages").glob("*.eml"))) == 1


def test_routed_generic_export_preserves_journal_bound_virtual_snapshot(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    mailboxes = [
        MailboxInfo("INBOX", "/", ("\\Inbox",)),
        MailboxInfo("All Mail", "/", ("\\All",)),
    ]
    config, account, plan, labels = _generic_routed_virtual_setup(mailboxes)
    body = b"Message-ID: <frozen@example.com>\r\n\r\nbody"
    delivery = [(body, "\\Seen", "01-Jan-2024 00:00:00 +0000")]

    def install_source() -> _GenericRoutedVirtualSource:
        source = _GenericRoutedVirtualSource(
            mailboxes,
            {"INBOX": delivery, "All Mail": delivery},
        )
        monkeypatch.setattr(
            provider_ops,
            "imap_connection",
            lambda *_args, **_kwargs: contextlib.nullcontext(source),
        )
        return source

    install_source()
    provider_ops.provider_export_account(
        config,
        account,
        tmp_path,
        routing_plan=plan,
    )
    account_dir = provider_ops.account_export_dir(tmp_path, account)
    staged_row = provider_ops.load_manifest(account_dir)[0]
    routed_row = routed_manifest_rows(
        config,
        account,
        [staged_row],
        plan,
    )[0][0]
    committed = provider_ops._journal_row(
        routed_row,
        "[Gmail]/All Mail",
        "committed",
        "appended",
        target_binding=provider_ops.provider_target_journal_binding(
            config,
            account,
        ),
        target_gmail_msgid="9001",
        labels_applied=labels.values(),
    )
    provider_ops.append_journal(account_dir, account, committed)
    manifest_before = (account_dir / "manifest.jsonl").read_bytes()
    metadata_path = account_dir / staged_row["metadata_path"]
    metadata_before = metadata_path.read_bytes()
    journal_path = provider_ops._journal_path(account_dir, account)
    journal_before = journal_path.read_bytes()
    binding_before = staged_row[CONTENT_BINDING_FIELD]

    install_source()
    provider_ops.provider_export_account(
        config,
        account,
        tmp_path,
        routing_plan=plan,
    )

    rerun_row = provider_ops.load_manifest(account_dir)[0]
    assert (account_dir / "manifest.jsonl").read_bytes() == manifest_before
    assert metadata_path.read_bytes() == metadata_before
    assert journal_path.read_bytes() == journal_before
    assert rerun_row[CONTENT_BINDING_FIELD] == binding_before
    assert rerun_row["source_mailboxes"] == ["All Mail", "INBOX"]
    assert len(list((account_dir / "messages").glob("*.eml"))) == 1


def test_routed_preflight_counts_unique_subset_views_as_one_physical_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mailboxes = [
        MailboxInfo("INBOX", "/", ("\\Inbox",)),
        MailboxInfo("Starred", "/", ("\\Starred",)),
        MailboxInfo("Important", "/", ("\\Important",)),
    ]
    config, account, _plan, _labels = _generic_routed_virtual_setup(mailboxes)
    body = b"Message-ID: <preflight-unique@example.com>\r\n\r\nbody"
    internaldate = "01-Jan-2024 00:00:00 +0000"
    source = _GenericRoutedVirtualSource(
        mailboxes,
        {
            "INBOX": [(body, "\\Seen", internaldate)],
            "Starred": [(body, "\\Seen \\Flagged", internaldate)],
            "Important": [(body, "\\Seen", internaldate)],
        },
    )
    config.target = ProviderEndpoint(
        provider="imap",
        host="target.example.com",
        auth=AuthConfig(method="password", password="target-secret"),
        available_bytes=len(body),
    )

    @contextlib.contextmanager
    def connection(_endpoint, _account, *, role: str):
        assert _account == account
        yield source if role == "source" else _GenericPreflightTarget()

    monkeypatch.setattr(provider_ops, "imap_connection", connection)

    ok, issues = provider_ops.provider_preflight(config, max_workers=1)
    assert ok is True
    assert issues == []


def test_routed_preflight_counts_ambiguous_subset_occurrence_as_extra_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mailboxes = [
        MailboxInfo("Folder A", "/", ("\\HasNoChildren",)),
        MailboxInfo("Folder B", "/", ("\\HasNoChildren",)),
        MailboxInfo("Important", "/", ("\\Important",)),
    ]
    config, account, _plan, _labels = _generic_routed_virtual_setup(mailboxes)
    body = b"Message-ID: <preflight-ambiguous@example.com>\r\n\r\nbody"
    internaldate = "01-Jan-2024 00:00:00 +0000"
    source = _GenericRoutedVirtualSource(
        mailboxes,
        {
            "Folder A": [(body, "\\Seen", internaldate)],
            "Folder B": [(body, "\\Seen", internaldate)],
            "Important": [(body, "\\Seen", internaldate)],
        },
    )
    config.target = ProviderEndpoint(
        provider="imap",
        host="target.example.com",
        auth=AuthConfig(method="password", password="target-secret"),
        available_bytes=len(body) * 2,
    )

    @contextlib.contextmanager
    def connection(_endpoint, _account, *, role: str):
        assert _account == account
        yield source if role == "source" else _GenericPreflightTarget()

    monkeypatch.setattr(provider_ops, "imap_connection", connection)

    ok, issues = provider_ops.provider_preflight(config, max_workers=1)
    assert ok is False
    assert any(
        f"estimated source bytes {len(body) * 3}" in issue
        and f"target.available_bytes {len(body) * 2}" in issue
        for issue in issues
    )


def test_routed_preflight_counts_subset_with_missing_date_as_extra_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mailboxes = [
        MailboxInfo("INBOX", "/", ("\\Inbox",)),
        MailboxInfo("Starred", "/", ("\\Starred",)),
    ]
    config, account, _plan, _labels = _generic_routed_virtual_setup(mailboxes)
    body = b"Message-ID: <preflight-missing-date@example.com>\r\n\r\nbody"
    source = _GenericRoutedVirtualSource(
        mailboxes,
        {
            "INBOX": [(body, "\\Seen", "")],
            "Starred": [(body, "\\Seen \\Flagged", "")],
        },
    )
    config.target = ProviderEndpoint(
        provider="imap",
        host="target.example.com",
        auth=AuthConfig(method="password", password="target-secret"),
        available_bytes=len(body),
    )

    @contextlib.contextmanager
    def connection(_endpoint, _account, *, role: str):
        assert _account == account
        yield source if role == "source" else _GenericPreflightTarget()

    monkeypatch.setattr(provider_ops, "imap_connection", connection)

    ok, issues = provider_ops.provider_preflight(config, max_workers=1)
    assert ok is False
    assert any(
        f"estimated source bytes {len(body) * 2}" in issue
        and f"target.available_bytes {len(body)}" in issue
        for issue in issues
    )


def test_routed_preflight_counts_subset_with_malformed_date_as_extra_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mailboxes = [
        MailboxInfo("INBOX", "/", ("\\Inbox",)),
        MailboxInfo("Starred", "/", ("\\Starred",)),
    ]
    config, account, _plan, _labels = _generic_routed_virtual_setup(mailboxes)
    body = b"Message-ID: <preflight-malformed-date@example.com>\r\n\r\nbody"
    source = _GenericRoutedVirtualSource(
        mailboxes,
        {
            "INBOX": [(body, "\\Seen", "bogus")],
            "Starred": [(body, "\\Seen \\Flagged", "bogus")],
        },
    )
    config.target = ProviderEndpoint(
        provider="imap",
        host="target.example.com",
        auth=AuthConfig(method="password", password="target-secret"),
        available_bytes=len(body),
    )

    @contextlib.contextmanager
    def connection(_endpoint, _account, *, role: str):
        assert _account == account
        yield source if role == "source" else _GenericPreflightTarget()

    monkeypatch.setattr(provider_ops, "imap_connection", connection)

    ok, issues = provider_ops.provider_preflight(config, max_workers=1)
    assert ok is False
    assert any(
        f"estimated source bytes {len(body) * 2}" in issue
        and f"target.available_bytes {len(body)}" in issue
        for issue in issues
    )


@pytest.mark.parametrize(
    ("mailboxes", "deliveries", "physical_payloads"),
    [
        pytest.param(
            [
                MailboxInfo("INBOX", "/", ("\\Inbox",)),
                MailboxInfo("Flagged", "/", ("\\Flagged",)),
            ],
            {
                "INBOX": [("\\Seen", "01-Jan-2024 00:00:00 +0000")],
                "Flagged": [
                    ("\\Seen \\Flagged", "01-Jan-2024 00:00:00 +0000")
                ],
            },
            1,
            id="ordinary-plus-flagged",
        ),
        pytest.param(
            [MailboxInfo("Flagged", "/", ("\\Flagged",))],
            {
                "Flagged": [
                    ("\\Seen \\Flagged", "01-Jan-2024 00:00:00 +0000")
                ]
            },
            1,
            id="flagged-only",
        ),
        pytest.param(
            [
                MailboxInfo("Folder A", "/", ("\\HasNoChildren",)),
                MailboxInfo("Folder B", "/", ("\\HasNoChildren",)),
                MailboxInfo("Flagged", "/", ("\\Flagged",)),
            ],
            {
                "Folder A": [("\\Seen", "01-Jan-2024 00:00:00 +0000")],
                "Folder B": [("\\Seen", "01-Jan-2024 00:00:00 +0000")],
                "Flagged": [
                    ("\\Seen \\Flagged", "01-Jan-2024 00:00:00 +0000")
                ],
            },
            3,
            id="ambiguous-ordinary-anchors",
        ),
        pytest.param(
            [
                MailboxInfo("INBOX", "/", ("\\Inbox",)),
                MailboxInfo("Flagged", "/", ("\\Flagged",)),
            ],
            {"INBOX": [("\\Seen", "")], "Flagged": [("\\Flagged", "")]},
            2,
            id="missing-date",
        ),
        pytest.param(
            [
                MailboxInfo("INBOX", "/", ("\\Inbox",)),
                MailboxInfo("Flagged", "/", ("\\Flagged",)),
            ],
            {
                "INBOX": [("\\Seen", "bogus")],
                "Flagged": [("\\Flagged", "bogus")],
            },
            2,
            id="malformed-date",
        ),
        pytest.param(
            [
                MailboxInfo("INBOX", "/", ("\\Inbox",)),
                MailboxInfo("Flagged", "/", ("\\Flagged",)),
            ],
            {
                "INBOX": [("\\Seen", "01-Jan-2024 00:00:00 +0000")],
                "Flagged": [
                    ("\\Flagged", "01-Jan-2024 00:00:00 +0000"),
                    ("\\Flagged", "01-Jan-2024 00:00:00 +0000"),
                ],
            },
            1,
            id="same-view-multiplicity",
        ),
        pytest.param(
            [
                MailboxInfo("INBOX", "/", ("\\Inbox",)),
                MailboxInfo("Flagged A", "/", ("\\Flagged",)),
                MailboxInfo("Flagged B", "/", ("\\Flagged",)),
            ],
            {
                "INBOX": [("\\Seen", "01-Jan-2024 00:00:00 +0000")],
                "Flagged A": [
                    ("\\Flagged", "01-Jan-2024 00:00:00 +0000")
                ],
                "Flagged B": [
                    ("\\Flagged", "01-Jan-2024 00:00:00 +0000")
                ],
            },
            1,
            id="multiple-flagged-views",
        ),
        pytest.param(
            [
                MailboxInfo("All Mail", "/", ("\\All",)),
                MailboxInfo("Flagged", "/", ("\\Flagged",)),
            ],
            {
                "All Mail": [
                    ("\\Seen \\Flagged", "01-Jan-2024 00:00:00 +0000")
                ],
                "Flagged": [
                    ("\\Seen \\Flagged", "01-Jan-2024 00:00:00 +0000")
                ],
            },
            1,
            id="all-only-plus-flagged",
        ),
        pytest.param(
            [
                MailboxInfo("INBOX", "/", ("\\Inbox",)),
                MailboxInfo("All Mail", "/", ("\\All",)),
                MailboxInfo("Flagged", "/", ("\\Flagged",)),
            ],
            {
                "INBOX": [("\\Seen", "01-Jan-2024 00:00:00 +0000")],
                "All Mail": [("\\Seen", "01-Jan-2024 00:00:00 +0000")],
                "Flagged": [
                    ("\\Seen \\Flagged", "01-Jan-2024 00:00:00 +0000")
                ],
            },
            1,
            id="ordinary-all-and-flagged",
        ),
        pytest.param(
            [
                MailboxInfo("INBOX", "/", ("\\Inbox",)),
                MailboxInfo("Flagged", "/", ("\\Flagged",)),
            ],
            {
                "INBOX": [("\\Seen", "01-Jan-2024 00:00:00 +0000")],
                "Flagged": [
                    ("\\Flagged", "31-Dec-2023 19:00:00 -0500")
                ],
            },
            1,
            id="timezone-equivalent-and-different-flags",
        ),
        pytest.param(
            [
                MailboxInfo("INBOX", "/", ("\\Inbox",)),
                MailboxInfo("Flagged", "/", ("\\Flagged",)),
            ],
            {
                "INBOX": [("\\Seen", "01-Jan-2024 00:00:00 +0000")],
                "Flagged": [("\\Flagged", "02-Jan-2024 00:00:00 +0000")],
            },
            2,
            id="different-date",
        ),
    ],
)
def test_legacy_preflight_matches_export_flagged_view_physical_payload_count(
    monkeypatch: pytest.MonkeyPatch,
    mailboxes: list[MailboxInfo],
    deliveries: dict[str, list[tuple[str, str]]],
    physical_payloads: int,
) -> None:
    body = b"Message-ID: <legacy-preflight-flagged@example.com>\r\n\r\nbody"
    source = _GenericRoutedVirtualSource(
        mailboxes,
        {
            mailbox: [(body, flags, internaldate) for flags, internaldate in rows]
            for mailbox, rows in deliveries.items()
        },
    )
    account = MigrationAccount("source@example.com", "target@example.com")
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="source.example.com",
            auth=AuthConfig(method="password", password="source-secret"),
        ),
        target=ProviderEndpoint(
            provider="imap",
            host="target.example.com",
            auth=AuthConfig(method="password", password="target-secret"),
            available_bytes=len(body) * physical_payloads,
        ),
        accounts=[account],
        migration=MigrationSettings(target_mode="empty"),
    )

    @contextlib.contextmanager
    def connection(_endpoint, _account, *, role: str):
        assert _account == account
        yield source if role == "source" else _GenericPreflightTarget()

    monkeypatch.setattr(provider_ops, "imap_connection", connection)

    ok, issues = provider_ops.provider_preflight(config, max_workers=1)
    assert ok is True
    assert issues == []

    config.target.available_bytes -= 1
    ok, issues = provider_ops.provider_preflight(config, max_workers=1)
    assert ok is False
    assert any(
        f"estimated source bytes {len(body) * physical_payloads}" in issue
        for issue in issues
    )


def test_routed_source_folder_order_is_hash_seed_independent() -> None:
    script = r'''
import json
from components.provider_ops import routed_manifest_rows
from components.routing import RoutingConfig, SourceFolder, resolve_routing_plan
from tests.test_provider_routing import _manifest_row, _provider_config

routing = RoutingConfig.from_dict({
    "enabled": True,
    "accounts": {"source@example.com": {"default_label": "Imported"}},
})
plan = resolve_routing_plan(
    routing,
    [
        SourceFolder("source@example.com", "Foo"),
        SourceFolder("source@example.com", "foo"),
    ],
    [],
)
row = _manifest_row()
row["source_mailboxes"] = ["Foo", "foo"]
row["source_mailbox_paths"] = {"Foo": ["Foo"], "foo": ["foo"]}
config = _provider_config(routing)
routed, _excluded = routed_manifest_rows(
    config,
    config.accounts[0],
    [row],
    plan,
)
print(json.dumps(routed[0]["routing_source_folders"]))
'''
    outputs = []
    for seed in ("1", "3", "17"):
        environment = os.environ.copy()
        environment["PYTHONHASHSEED"] = seed
        outputs.append(
            subprocess.check_output(
                [sys.executable, "-c", script],
                cwd=Path(__file__).resolve().parents[1],
                env=environment,
                text=True,
            ).strip()
        )

    assert outputs == ['["Foo", "foo"]'] * 3


def test_explicit_exclusion_is_the_only_virtual_membership_suppression() -> None:
    routing = RoutingConfig.from_dict(
        {
            "enabled": True,
            "global_rules": [
                {
                    "match": {"folder": "INBOX"},
                    "destinations": [{"type": CUSTOM_LABEL, "name": "InboxRoute"}],
                },
                {"match": {"folder": "[Gmail]/All Mail"}, "exclude": True},
            ],
        }
    )
    plan = resolve_routing_plan(
        routing,
        [
            SourceFolder("source@example.com", "INBOX", attributes=("\\Inbox",)),
            SourceFolder(
                "source@example.com",
                "[Gmail]/All Mail",
                attributes=("\\All",),
            ),
        ],
        [],
    )
    row = _manifest_row()
    row["source_mailboxes"] = ["INBOX", "[Gmail]/All Mail"]

    routed, excluded = routed_manifest_rows(
        _provider_config(routing),
        _provider_config(routing).accounts[0],
        [row],
        plan,
    )

    assert excluded == []
    assert routed[0]["routing_target_labels"] == ["InboxRoute"]
    assert routed[0]["routing_source_folders"] == ["INBOX"]
    assert routed[0]["routing_excluded_source_folders"] == ["[Gmail]/All Mail"]


def test_explicit_gmail_system_route_selects_system_primary() -> None:
    routing = RoutingConfig.from_dict(
        {
            "enabled": True,
            "global_rules": [
                {
                    "match": {"folder": "Sent"},
                    "destinations": [{"type": GMAIL_SYSTEM, "name": "sent"}],
                }
            ],
        }
    )
    plan = resolve_routing_plan(
        routing,
        [SourceFolder("source@example.com", "Sent", attributes=("\\Sent",))],
        [TargetLabel("[Gmail]/Sent Mail", GMAIL_SYSTEM, system_role="sent")],
    )
    config = _provider_config(routing)
    row = _manifest_row()
    row["source_mailboxes"] = ["Sent"]
    row["source_mailbox_paths"] = {"Sent": ["Sent"]}

    rows, _excluded = routed_manifest_rows(config, config.accounts[0], [row], plan)

    assert rows[0]["primary_mailbox"] == "Sent"
    assert rows[0]["routing_system_destinations"] == ["sent"]
    assert rows[0]["routing_target_labels"] == []


@pytest.mark.parametrize("exact_mailbox_exists", [True, False])
def test_routed_generic_target_preserves_exact_special_like_mailbox(
    exact_mailbox_exists: bool,
) -> None:
    routing = RoutingConfig.from_dict(
        {
            "enabled": True,
            "global_rules": [
                {
                    "match": {"folder": "Source Sent"},
                    "destinations": [
                        {"type": GENERIC_MAILBOX, "name": "Sent"}
                    ],
                }
            ],
        }
    )
    account = MigrationAccount("source@example.com", "target@example.com")
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="source.example.com",
            auth=AuthConfig(method="password", password="source-secret"),
        ),
        target=ProviderEndpoint(
            provider="imap",
            host="target.example.com",
            auth=AuthConfig(method="password", password="target-secret"),
        ),
        accounts=[account],
        migration=MigrationSettings(target_mode="merge", routing=routing),
    )
    target_labels = [TargetLabel("Sent Items", GENERIC_MAILBOX)]
    if exact_mailbox_exists:
        target_labels.append(TargetLabel("Sent", GENERIC_MAILBOX))
    plan = resolve_routing_plan(
        routing,
        [SourceFolder(account.source_email, "Source Sent")],
        target_labels,
    )
    row = _manifest_row()
    row["source_mailboxes"] = ["Source Sent"]
    row["source_mailbox_paths"] = {"Source Sent": ["Source Sent"]}

    routed, excluded = routed_manifest_rows(config, account, [row], plan)
    target_mailboxes = [
        MailboxInfo("Sent Items", "/", ("\\Sent",)),
        *(
            [MailboxInfo("Sent", "/", ())]
            if exact_mailbox_exists
            else []
        ),
    ]

    assert plan.ok
    assert plan.entries[0].destinations[0].status == (
        "existing" if exact_mailbox_exists else "create"
    )
    assert excluded == []
    assert routed[0]["routing_exact_target_mailbox"] == "Sent"
    assert translated_target_mailboxes_for_rows(
        routed,
        target_mailboxes,
        target_provider="imap",
    ) == {"m1": "Sent"}

    legacy_row = {"canonical_id": "legacy", "primary_mailbox": "Sent"}
    assert translated_target_mailboxes_for_rows(
        [legacy_row],
        target_mailboxes,
        target_provider="imap",
    ) == {"legacy": "Sent Items"}

    wrong_journal = [
        {
            "canonical_id": "m1",
            "target_mailbox": "Sent Items",
            "status": "committed",
        }
    ]
    assert any(
        "wrong target mailbox" in issue
        for issue in provider_ops.offline_journal_target_mailbox_issues(
            wrong_journal,
            routed,
            target_provider="imap",
        )
    )


def test_routed_generic_exact_target_bypasses_source_hierarchy_translation() -> None:
    routing = RoutingConfig.from_dict(
        {
            "enabled": True,
            "global_rules": [
                {
                    "match": {"folder": "Projects.Shared"},
                    "destinations": [
                        {
                            "type": GENERIC_MAILBOX,
                            "name": "Projects.Shared",
                        }
                    ],
                }
            ],
        }
    )
    account = MigrationAccount("source@example.com", "target@example.com")
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="source.example.com",
            auth=AuthConfig(method="password", password="source-secret"),
        ),
        target=ProviderEndpoint(
            provider="imap",
            host="target.example.com",
            auth=AuthConfig(method="password", password="target-secret"),
        ),
        accounts=[account],
        migration=MigrationSettings(target_mode="merge", routing=routing),
    )
    plan = resolve_routing_plan(
        routing,
        [SourceFolder(account.source_email, "Projects.Shared", delimiter=".")],
        [TargetLabel("Projects.Shared", GENERIC_MAILBOX, delimiter="/")],
    )
    row = _manifest_row()
    row["source_mailboxes"] = ["Projects.Shared"]
    row["source_mailbox_paths"] = {
        "Projects.Shared": ["Projects", "Shared"]
    }
    routed, _excluded = routed_manifest_rows(config, account, [row], plan)
    target_mailboxes = [MailboxInfo("Projects.Shared", "/", ())]

    assert provider_ops.translate_source_mailbox_for_target(
        row,
        "Projects.Shared",
        target_mailboxes,
        target_provider="imap",
    ) == "Projects/Shared"
    assert translated_target_mailboxes_for_rows(
        routed,
        target_mailboxes,
        target_provider="imap",
    ) == {"m1": "Projects.Shared"}


def test_offline_exact_generic_inbox_journal_is_case_insensitive() -> None:
    routed = {
        "canonical_id": "m1",
        "primary_mailbox": "INBOX",
        "routing_active": True,
        "routing_exact_target_mailbox": "INBOX",
    }
    journal = [
        {
            "canonical_id": "m1",
            "target_mailbox": "inbox",
            "status": "committed",
        }
    ]

    assert provider_ops.offline_journal_target_mailbox_issues(
        journal,
        [routed],
        target_provider="imap",
    ) == []


def test_only_rows_from_same_frozen_gmail_plan_bypass_legacy_translation_collision() -> None:
    config = _provider_config()
    plan = resolve_routing_plan(
        RoutingConfig.from_dict(
            {
                "enabled": True,
                "global_rules": [
                    {
                        "match": {"folder": "One"},
                        "destinations": [{"type": CUSTOM_LABEL, "name": "One"}],
                    },
                    {
                        "match": {"folder": "Two"},
                        "destinations": [{"type": CUSTOM_LABEL, "name": "Two"}],
                    },
                ],
            }
        ),
        [
            SourceFolder("source@example.com", "One"),
            SourceFolder("source@example.com", "Two"),
        ],
        [],
    )
    config.migration.routing = RoutingConfig.from_dict(
        {
            "enabled": True,
            "global_rules": [
                {
                    "match": {"folder": "One"},
                    "destinations": [{"type": CUSTOM_LABEL, "name": "One"}],
                },
                {
                    "match": {"folder": "Two"},
                    "destinations": [{"type": CUSTOM_LABEL, "name": "Two"}],
                },
            ],
        }
    )
    rows = []
    for identity, folder in (("m1", "One"), ("m2", "Two")):
        row = _manifest_row(identity)
        row["source_mailboxes"] = [folder]
        row["source_mailbox_paths"] = {folder: [folder]}
        rows.append(row)
    routed, _ = routed_manifest_rows(config, config.accounts[0], rows, plan)
    target_mailboxes = [
        MailboxInfo("[Gmail]/All Mail", "/", ("\\All",)),
    ]

    assert translated_target_mailboxes_for_rows(
        routed,
        target_mailboxes,
        target_provider="gmail",
    ) == {"m1": "[Gmail]/All Mail", "m2": "[Gmail]/All Mail"}

    mixed = [routed[0], {**routed[1], "routing_active": False}]
    with pytest.raises(RuntimeError, match="translation collision"):
        translated_target_mailboxes_for_rows(
            mixed,
            target_mailboxes,
            target_provider="gmail",
        )


def test_export_state_contract_requires_exact_routing_digest() -> None:
    digest = "a" * 64
    assert provider_export_state_contract_issues(
        {"routing_plan_sha256": digest},
        routing_plan_sha256=digest,
    ) == []
    assert any(
        "routing_plan_sha256" in issue
        for issue in provider_export_state_contract_issues(
            {},
            routing_plan_sha256=digest,
        )
    )
    assert any(
        "routing is disabled" in issue
        for issue in provider_export_state_contract_issues(
            {"routing_plan_sha256": digest},
            routing_enabled=False,
        )
    )


def test_export_resume_requires_existing_stage_to_bind_exact_routing_plan(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config = _provider_config()
    account = config.accounts[0]
    plan = _plan()
    account_dir = _write_provider_account_fixture(
        tmp_path,
        source=account.source_email,
        target=account.target_email,
        canonical_id="m1",
        message_id="<m1@example.com>",
        body=b"Message-ID: <m1@example.com>\r\n\r\nbody",
        source_provider=config.source.provider,
        source_host=config.source.host,
        primary_mailbox="INBOX",
    )
    _write_provider_export_state(
        account_dir,
        source=account.source_email,
        target=account.target_email,
        source_endpoint=config.source,
        source_username=account.source_email,
        target_endpoint=config.target,
        target_username=account.target_email,
    )

    def unexpected_connection(*_args, **_kwargs):
        raise AssertionError("routing binding must be rejected before source IMAP connection")

    monkeypatch.setattr(provider_ops, "imap_connection", unexpected_connection)

    with pytest.raises(RuntimeError, match="routing_plan_sha256 does not match"):
        provider_ops.provider_export_account(
            config,
            account,
            tmp_path,
            routing_plan=plan,
        )


def test_export_rerun_retains_exact_committed_route_bound_evidence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config = _provider_config()
    config.source = ProviderEndpoint(
        provider="imap",
        host="mail.source.example.com",
        auth=AuthConfig(method="password", password="source-secret"),
    )
    account = config.accounts[0]
    plan = _plan()
    account_dir = _write_provider_account_fixture(
        tmp_path,
        source=account.source_email,
        target=account.target_email,
        canonical_id="m1",
        message_id="<m1@example.com>",
        body=b"Message-ID: <m1@example.com>\r\n\r\nbody",
        source_provider=config.source.provider,
        source_host=config.source.host,
        primary_mailbox="INBOX",
    )
    row = json.loads((account_dir / "manifest.jsonl").read_text(encoding="utf-8"))
    row.update({
        "source_mailboxes": ["INBOX"],
        "source_mailbox_paths": {"INBOX": ["INBOX"]},
        "source_mailbox_attributes": {"INBOX": ["\\Inbox"]},
        "source_mailbox_delimiters": {"INBOX": ""},
    })
    _write_single_manifest_row(account_dir, row)
    _write_provider_export_state(
        account_dir,
        source=account.source_email,
        target=account.target_email,
        source_endpoint=config.source,
        source_username=account.source_email,
        target_endpoint=config.target,
        target_username=account.target_email,
    )
    state_path = account_dir / "export-state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["target_provider"] = config.target.provider
    state["routing_plan_sha256"] = plan.mapping_digest
    state_path.write_text(json.dumps(state), encoding="utf-8")
    row = provider_ops.load_manifest(account_dir)[0]
    routed_row = routed_manifest_rows(config, account, [row], plan)[0][0]
    journal_row = provider_ops._journal_row(
        routed_row,
        "[Gmail]/All Mail",
        "committed",
        "appended",
        target_binding=provider_ops.provider_target_journal_binding(config, account),
        target_gmail_msgid="9001",
        labels_applied=["Imported"],
    )
    journal_path = account_dir / "import-target@example.com.journal.jsonl"
    journal_path.write_text(json.dumps(journal_row) + "\n", encoding="utf-8")
    metadata_before = (account_dir / row["metadata_path"]).read_bytes()
    journal_before = journal_path.read_bytes()

    class EmptyRoutedSource:
        selected = ""

        def capability(self):
            return "OK", [b"IMAP4rev1"]

        def list(self):
            return "OK", [b'(\\Inbox) NIL "INBOX"']

        def select(self, mailbox: str, readonly: bool = False):
            self.selected = mailbox.strip('"')
            return "OK", [b"0"]

        def response(self, name: str):
            return "OK", [b"777"]

        def uid(self, command: str, *_args):
            assert command == "search"
            return "OK", [b""]

        def logout(self):
            return "OK", []

    monkeypatch.setattr(
        provider_ops,
        "imap_connection",
        lambda *_args, **_kwargs: contextlib.nullcontext(EmptyRoutedSource()),
    )

    provider_ops.provider_export_account(
        config,
        account,
        tmp_path,
        routing_plan=plan,
    )

    assert provider_ops.load_manifest(account_dir) == [row]
    assert (account_dir / row["metadata_path"]).read_bytes() == metadata_before
    assert journal_path.read_bytes() == journal_before
    retained_row = provider_ops.load_manifest(account_dir)[0]
    retained_routed = routed_manifest_rows(config, account, [retained_row], plan)[0][0]
    retained_journal = provider_ops.load_import_journal(account_dir, account)[-1]
    assert provider_ops.routing_journal_membership_complete(
        retained_journal,
        retained_routed,
    )


def test_export_resume_rejects_route_bound_stage_when_routing_is_disabled(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config = _provider_config(RoutingConfig.from_dict({"enabled": False}))
    account = config.accounts[0]
    account_dir = _write_provider_account_fixture(
        tmp_path,
        source=account.source_email,
        target=account.target_email,
        canonical_id="m1",
        message_id="<m1@example.com>",
        body=b"Message-ID: <m1@example.com>\r\n\r\nbody",
        source_provider=config.source.provider,
        source_host=config.source.host,
        primary_mailbox="INBOX",
    )
    _write_provider_export_state(
        account_dir,
        source=account.source_email,
        target=account.target_email,
        source_endpoint=config.source,
        source_username=account.source_email,
        target_endpoint=config.target,
        target_username=account.target_email,
    )
    state_path = account_dir / "export-state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["routing_plan_sha256"] = "a" * 64
    state_path.write_text(json.dumps(state), encoding="utf-8")

    def unexpected_connection(*_args, **_kwargs):
        raise AssertionError("routing binding must be rejected before source IMAP connection")

    monkeypatch.setattr(provider_ops, "imap_connection", unexpected_connection)

    with pytest.raises(RuntimeError, match="routing is disabled"):
        provider_ops.provider_export_account(config, account, tmp_path)


def test_route_bound_stage_is_rejected_by_import_audit_and_validate_when_routing_disabled(
    tmp_path: Path,
) -> None:
    config = _provider_config(RoutingConfig.from_dict({"enabled": False}))
    account = config.accounts[0]
    account_dir = provider_ops.account_export_dir(tmp_path, account)
    account_dir.mkdir(parents=True)
    (account_dir / "manifest.jsonl").write_text("", encoding="utf-8")
    state = {
        "source_account": account.source_email,
        "target_account": account.target_email,
        "source_provider": config.source.provider,
        "target_provider": config.target.provider,
        "source_endpoint": provider_ops.provider_account_endpoint_state(
            config.source, account, role="source"
        ),
        "source_endpoint_sha256": provider_ops.provider_account_endpoint_state_digest(
            config.source, account, role="source"
        ),
        "target_endpoint": provider_ops.provider_account_endpoint_state(
            config.target, account, role="target"
        ),
        "target_endpoint_sha256": provider_ops.provider_account_endpoint_state_digest(
            config.target, account, role="target"
        ),
        "gmail_full_visibility_verified": True,
        "complete": True,
        "canonical_messages": 0,
        "manifest_sha256": provider_ops.provider_manifest_digest([]),
        "routing_plan_sha256": "a" * 64,
    }
    (account_dir / "export-state.json").write_text(json.dumps(state), encoding="utf-8")

    with pytest.raises(RuntimeError, match="routing is disabled"):
        provider_import_account(config, account, tmp_path)

    _account, audit_issues = provider_audit_account(config, account, tmp_path)
    assert any("routing is disabled" in issue for issue in audit_issues)

    _account, report = provider_validate_account(
        config,
        account,
        tmp_path,
        check_target=False,
        write_report=False,
    )
    assert any("routing is disabled" in issue for issue in report["failed"])


def test_custom_label_routing_requires_gmail_api_oauth_but_system_only_does_not() -> None:
    custom_config = _provider_config()
    custom_config.target.auth = AuthConfig(method="app_password", password="app-secret")
    with pytest.raises(ValueError, match="gmail.labels.*app passwords"):
        custom_config.validate_routing()

    system_routing = RoutingConfig.from_dict(
        {
            "enabled": True,
            "global_rules": [
                {
                    "match": {"folder": "INBOX"},
                    "destinations": [{"type": GMAIL_SYSTEM, "name": "inbox"}],
                }
            ],
        }
    )
    system_config = _provider_config(system_routing)
    system_config.target.auth = AuthConfig(method="app_password", password="app-secret")
    system_config.validate_routing()


def test_gmail_api_system_labels_only_enrich_imap_discovery_but_user_labels_merge() -> None:
    merged = provider_ops._routing_merge_gmail_api_labels(
        [
            TargetLabel("INBOX", GMAIL_SYSTEM, system_role="inbox"),
            TargetLabel("[Gmail]/All Mail", GMAIL_SYSTEM, system_role="all"),
        ],
        [
            {"id": "INBOX", "name": "INBOX", "type": "system"},
            {"id": "SENT", "name": "SENT", "type": "system"},
            {"id": "STARRED", "name": "STARRED", "type": "system"},
            {"id": "Label_42", "name": "Review", "type": "user"},
        ],
    )

    assert {(label.kind, label.name) for label in merged} == {
        (GMAIL_SYSTEM, "INBOX"),
        (GMAIL_SYSTEM, "[Gmail]/All Mail"),
        (GMAIL_SYSTEM, "STARRED"),
        (CUSTOM_LABEL, "Review"),
    }
    assert next(label for label in merged if label.system_role == "inbox").target_id == "INBOX"
    assert next(label for label in merged if label.system_role == "starred").target_id == "STARRED"
    assert next(label for label in merged if label.name == "Review").target_id == "Label_42"

    routing = RoutingConfig.from_dict(
        {
            "enabled": True,
            "global_rules": [
                {
                    "match": {"folder": "Sent"},
                    "destinations": [{"type": GMAIL_SYSTEM, "name": "sent"}],
                }
            ],
        }
    )
    plan = resolve_routing_plan(
        routing,
        [SourceFolder("source@example.com", "Sent", attributes=("\\Sent",))],
        merged,
    )
    assert not plan.ok
    assert plan.entries[0].destinations[0].status == "missing_system"


def test_cross_folder_exclusive_gmail_membership_is_rejected_after_export() -> None:
    routing = RoutingConfig.from_dict(
        {
            "enabled": True,
            "global_rules": [
                {
                    "match": {"folder": "Sent"},
                    "destinations": [{"type": GMAIL_SYSTEM, "name": "sent"}],
                },
                {
                    "match": {"folder": "Trash"},
                    "destinations": [
                        {"type": GMAIL_SYSTEM, "name": "trash", "allow_unsafe": True}
                    ],
                },
            ],
        }
    )
    plan = resolve_routing_plan(
        routing,
        [
            SourceFolder("source@example.com", "Sent", attributes=("\\Sent",)),
            SourceFolder("source@example.com", "Trash", attributes=("\\Trash",)),
        ],
        [
            TargetLabel("[Gmail]/Sent Mail", GMAIL_SYSTEM, system_role="sent"),
            TargetLabel("[Gmail]/Trash", GMAIL_SYSTEM, system_role="trash"),
        ],
    )
    row = _manifest_row()
    row["source_mailboxes"] = ["Sent", "Trash"]
    row["source_mailbox_paths"] = {"Sent": ["Sent"], "Trash": ["Trash"]}

    assert plan.ok
    assert any("mutually exclusive" in warning for warning in plan.warnings)
    with pytest.raises(RuntimeError, match="incompatible Gmail system locations"):
        routed_manifest_rows(_provider_config(routing), _provider_config(routing).accounts[0], [row], plan)


@pytest.mark.parametrize(
    (
        "anchor_folder",
        "anchor_role",
        "anchor_target_name",
        "anchor_attributes",
        "unsafe_folder",
        "unsafe_role",
        "unsafe_target_name",
        "unsafe_attributes",
    ),
    [
        ("Archive", "all", "[Gmail]/All Mail", (), "Spam", "spam", "[Gmail]/Spam", ("\\Junk",)),
        ("Archive", "all", "[Gmail]/All Mail", (), "Trash", "trash", "[Gmail]/Trash", ("\\Trash",)),
        ("INBOX", "inbox", "INBOX", ("\\Inbox",), "Spam", "spam", "[Gmail]/Spam", ("\\Junk",)),
        ("INBOX", "inbox", "INBOX", ("\\Inbox",), "Trash", "trash", "[Gmail]/Trash", ("\\Trash",)),
    ],
)
def test_cross_folder_all_mail_or_inbox_with_spam_or_trash_is_rejected_after_export(
    anchor_folder: str,
    anchor_role: str,
    anchor_target_name: str,
    anchor_attributes: tuple[str, ...],
    unsafe_folder: str,
    unsafe_role: str,
    unsafe_target_name: str,
    unsafe_attributes: tuple[str, ...],
) -> None:
    routing = RoutingConfig.from_dict(
        {
            "enabled": True,
            "global_rules": [
                {
                    "match": {"folder": anchor_folder},
                    "destinations": [{"type": GMAIL_SYSTEM, "name": anchor_role}],
                },
                {
                    "match": {"folder": unsafe_folder},
                    "destinations": [
                        {
                            "type": GMAIL_SYSTEM,
                            "name": unsafe_role,
                            "allow_unsafe": True,
                        }
                    ],
                },
            ],
        }
    )
    plan = resolve_routing_plan(
        routing,
        [
            SourceFolder("source@example.com", anchor_folder, attributes=anchor_attributes),
            SourceFolder("source@example.com", unsafe_folder, attributes=unsafe_attributes),
        ],
        [
            TargetLabel(anchor_target_name, GMAIL_SYSTEM, system_role=anchor_role),
            TargetLabel(unsafe_target_name, GMAIL_SYSTEM, system_role=unsafe_role),
        ],
    )
    config = _provider_config(routing)
    row = _manifest_row()
    row["source_mailboxes"] = [anchor_folder, unsafe_folder]
    row["source_mailbox_paths"] = {
        anchor_folder: [anchor_folder],
        unsafe_folder: [unsafe_folder],
    }

    assert plan.ok
    assert any(
        "mutually exclusive" in warning
        and anchor_role in warning
        and unsafe_role in warning
        for warning in plan.warnings
    )
    with pytest.raises(RuntimeError, match="incompatible Gmail system locations"):
        routed_manifest_rows(config, config.accounts[0], [row], plan)


def test_cross_folder_inbox_and_sent_membership_remains_representable() -> None:
    routing = RoutingConfig.from_dict(
        {
            "enabled": True,
            "global_rules": [
                {
                    "match": {"folder": "INBOX"},
                    "destinations": [{"type": GMAIL_SYSTEM, "name": "inbox"}],
                },
                {
                    "match": {"folder": "Sent"},
                    "destinations": [{"type": GMAIL_SYSTEM, "name": "sent"}],
                },
            ],
        }
    )
    plan = resolve_routing_plan(
        routing,
        [
            SourceFolder("source@example.com", "INBOX", attributes=("\\Inbox",)),
            SourceFolder("source@example.com", "Sent", attributes=("\\Sent",)),
        ],
        [
            TargetLabel("INBOX", GMAIL_SYSTEM, system_role="inbox"),
            TargetLabel("[Gmail]/Sent Mail", GMAIL_SYSTEM, system_role="sent"),
        ],
    )
    config = _provider_config(routing)
    row = _manifest_row()
    row["source_mailboxes"] = ["INBOX", "Sent"]
    row["source_mailbox_paths"] = {"INBOX": ["INBOX"], "Sent": ["Sent"]}

    routed, excluded = routed_manifest_rows(config, config.accounts[0], [row], plan)

    assert plan.ok
    assert excluded == []
    assert routed[0]["primary_mailbox"] == "Sent"
    assert routed[0]["routing_system_destinations"] == ["inbox", "sent"]


def test_cross_folder_draft_and_custom_label_membership_is_rejected_after_export() -> None:
    routing = RoutingConfig.from_dict(
        {
            "enabled": True,
            "global_rules": [
                {
                    "match": {"folder": "Drafts"},
                    "destinations": [{"type": GMAIL_SYSTEM, "name": "drafts"}],
                },
                {
                    "match": {"folder": "Review"},
                    "destinations": [{"type": CUSTOM_LABEL, "name": "Review"}],
                },
            ],
        }
    )
    plan = resolve_routing_plan(
        routing,
        [
            SourceFolder("source@example.com", "Drafts", attributes=("\\Drafts",)),
            SourceFolder("source@example.com", "Review"),
        ],
        [TargetLabel("[Gmail]/Drafts", GMAIL_SYSTEM, system_role="drafts")],
    )
    config = _provider_config(routing)
    row = _manifest_row()
    row["source_mailboxes"] = ["Drafts", "Review"]
    row["source_mailbox_paths"] = {"Drafts": ["Drafts"], "Review": ["Review"]}

    assert plan.ok
    assert any("Gmail Drafts and other" in warning for warning in plan.warnings)
    with pytest.raises(RuntimeError, match="Gmail Drafts plus incompatible"):
        routed_manifest_rows(config, config.accounts[0], [row], plan)


def test_draft_and_all_mail_membership_is_accepted_at_runtime() -> None:
    routing = RoutingConfig.from_dict(
        {
            "enabled": True,
            "global_rules": [
                {
                    "match": {"folder": "Drafts"},
                    "destinations": [
                        {"type": GMAIL_SYSTEM, "name": "drafts"},
                        {"type": GMAIL_SYSTEM, "name": "all"},
                    ],
                }
            ],
        }
    )
    plan = resolve_routing_plan(
        routing,
        [SourceFolder("source@example.com", "Drafts", attributes=("\\Drafts",))],
        [
            TargetLabel("[Gmail]/Drafts", GMAIL_SYSTEM, system_role="drafts"),
            TargetLabel("[Gmail]/All Mail", GMAIL_SYSTEM, system_role="all"),
        ],
    )
    row = _manifest_row()
    row["source_mailboxes"] = ["Drafts"]
    row["source_mailbox_paths"] = {"Drafts": ["Drafts"]}

    routed, excluded = routed_manifest_rows(
        _provider_config(routing),
        _provider_config(routing).accounts[0],
        [row],
        plan,
    )

    assert excluded == []
    assert routed[0]["primary_mailbox"] == "Drafts"
    assert routed[0]["routing_system_destinations"] == ["all", "drafts"]
    assert provider_ops.gmail_draft_combination_issues(routed) == []


def test_nonrouting_draft_plus_custom_label_is_rejected_before_target_connection(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config = _provider_config(RoutingConfig.from_dict({"enabled": False}))
    account = config.accounts[0]
    account_dir = provider_ops.account_export_dir(tmp_path, account)
    (account_dir / "messages").mkdir(parents=True)
    eml = account_dir / "messages" / "draft.eml"
    eml.write_bytes(b"From: source@example.com\r\n\r\ndraft\r\n")
    row = {
        **_manifest_row(),
        "primary_mailbox": "Drafts",
        "source_mailboxes": ["Drafts"],
        "source_mailbox_paths": {"Drafts": ["Drafts"]},
        "gmail_labels": ["\\Drafts", "Review"],
        "eml_path": "messages/draft.eml",
    }
    monkeypatch.setattr(provider_ops, "load_manifest", lambda _path: [row])
    for name in (
        "require_manifest_schema",
        "require_unique_manifest_identities",
        "require_manifest_accounts",
        "require_manifest_source_provider",
        "require_manifest_integrity_metadata",
        "require_provider_delivery_metadata",
        "require_complete_export_state",
        "require_manifest_payload_matches",
    ):
        monkeypatch.setattr(provider_ops, name, lambda *_args, **_kwargs: None)
    for name in (
        "metadata_manifest_issues",
        "_provider_artifact_orphan_issues",
        "provider_mixed_legacy_layout_issues",
    ):
        monkeypatch.setattr(provider_ops, name, lambda *_args, **_kwargs: [])

    def unexpected_connection(*_args, **_kwargs):
        raise AssertionError("target connection must not open for an invalid Draft label set")

    monkeypatch.setattr(provider_ops, "imap_connection", unexpected_connection)

    with pytest.raises(RuntimeError, match="Gmail Drafts.*Review"):
        provider_import_account(config, account, tmp_path)


def test_nonrouting_draft_membership_is_rejected_even_when_another_system_wins_primary() -> None:
    row = {
        **_manifest_row(),
        "primary_mailbox": "Sent",
        "source_mailboxes": ["[Gmail]/Drafts", "[Gmail]/Sent Mail"],
        "gmail_labels": ["\\Drafts", "\\Sent"],
    }

    issues = provider_ops.gmail_draft_combination_issues([row])

    assert len(issues) == 1
    assert "sent" in issues[0]


def test_filter_routing_api_error_names_both_required_scope_families() -> None:
    routing = RoutingConfig.from_dict(
        {
            "enabled": True,
            "filters": [
                {"delivered_to": "source@example.com", "label": "Imported"}
            ],
        }
    )
    config = _provider_config(routing)
    config.target.auth = AuthConfig(method="app_password", password="app-secret")

    with pytest.raises(ValueError) as excinfo:
        config.validate_routing()

    message = str(excinfo.value)
    assert "gmail.labels" in message
    assert "gmail.settings.basic" in message
    assert "app passwords" in message


def _routing_report_commit(
    plan,
    action: str,
    *,
    target_gmail_msgid: str | None = "101",
    routing_plan_sha256: str | None = None,
    membership_complete: bool = True,
    target_account: str = "target@example.com",
) -> dict:
    row = {
        "canonical_id": "m1",
        "target_account": target_account,
        "target_mailbox": "[Gmail]/All Mail",
        "status": "committed",
        "action": action,
        "routing_plan_sha256": (
            plan.mapping_digest
            if routing_plan_sha256 is None
            else routing_plan_sha256
        ),
        "labels_applied": ["Imported"] if action == "appended" else [],
    }
    if target_gmail_msgid is not None:
        row["target_gmail_msgid"] = target_gmail_msgid
    if membership_complete:
        row.update(
            {
                "required_gmail_labels": ["Imported"],
                "required_gmail_system_destinations": [],
                "label_membership_verified": True,
            }
        )
    return row


def _install_routing_report_fixture(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    config: ProviderMigrationConfig,
    plan,
    manifests_by_source: dict[str, list[dict]],
    journals_by_source: dict[str, list[dict]],
) -> None:
    manifests_by_path = {
        provider_ops.account_export_dir(tmp_path, account): manifests_by_source[
            account.source_email
        ]
        for account in config.accounts
    }
    monkeypatch.setattr(
        provider_ops,
        "load_manifest",
        lambda account_dir: manifests_by_path[account_dir],
    )
    monkeypatch.setattr(
        provider_ops,
        "load_import_journal",
        lambda _account_dir, account: journals_by_source[account.source_email],
    )
    for name in (
        "require_manifest_schema",
        "require_unique_manifest_identities",
        "require_manifest_accounts",
        "require_manifest_source_provider",
        "require_manifest_integrity_metadata",
        "require_complete_export_state",
        "require_valid_import_journal",
    ):
        monkeypatch.setattr(provider_ops, name, lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        provider_ops,
        "committed_journal_manifest_content_issues",
        lambda *_args, **_kwargs: [],
    )
    monkeypatch.setattr(
        provider_ops,
        "pending_journal_manifest_content_issues",
        lambda *_args, **_kwargs: [],
    )
    monkeypatch.setattr(
        provider_ops,
        "_effective_provider_routing_plan",
        lambda *_args, **_kwargs: plan,
    )


def test_report_rejects_multiple_gmail_ids_committed_to_one_manifest_identity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    plan = _plan()
    config = _provider_config()
    journal = [
        _routing_report_commit(plan, "appended", target_gmail_msgid="101"),
        _routing_report_commit(plan, "route-verified", target_gmail_msgid="202"),
    ]
    _install_routing_report_fixture(
        monkeypatch,
        tmp_path,
        config,
        plan,
        {"source@example.com": [_manifest_row()]},
        {"source@example.com": journal},
    )

    with pytest.raises(RuntimeError, match="committed to multiple target_gmail_msgid"):
        build_provider_routing_report(config, tmp_path, routing_plan=plan)


@pytest.mark.parametrize("missing_value", [None, ""])
def test_report_rejects_missing_or_empty_committed_gmail_id(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    missing_value: str | None,
) -> None:
    plan = _plan()
    config = _provider_config()
    journal = [
        _routing_report_commit(
            plan,
            "appended",
            target_gmail_msgid=missing_value,
        )
    ]
    _install_routing_report_fixture(
        monkeypatch,
        tmp_path,
        config,
        plan,
        {"source@example.com": [_manifest_row()]},
        {"source@example.com": journal},
    )

    with pytest.raises(RuntimeError, match="missing target_gmail_msgid"):
        build_provider_routing_report(config, tmp_path, routing_plan=plan)


@pytest.mark.parametrize("later_kind", ["foreign-plan", "incomplete-membership"])
def test_report_physical_id_comes_only_from_latest_accepted_route_commit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    later_kind: str,
) -> None:
    plan = _plan()
    config = _provider_config()
    later = _routing_report_commit(
        plan,
        "route-verified",
        target_gmail_msgid="202",
        routing_plan_sha256=("f" * 64 if later_kind == "foreign-plan" else None),
        membership_complete=later_kind != "incomplete-membership",
    )
    journal = [
        _routing_report_commit(plan, "appended", target_gmail_msgid="101"),
        later,
    ]
    _install_routing_report_fixture(
        monkeypatch,
        tmp_path,
        config,
        plan,
        {"source@example.com": [_manifest_row()]},
        {"source@example.com": journal},
    )
    monkeypatch.setattr(
        provider_ops,
        "duplicate_journal_target_gmail_msgid_issues",
        lambda *_args, **_kwargs: [],
    )

    report = build_provider_routing_report(config, tmp_path, routing_plan=plan)

    account = report["accounts"][0]
    assert account["committed_records"][0]["target_gmail_msgid"] == "101"
    assert account["gmail_physical_messages"][0]["target_gmail_msgid"] == "101"
    assert report["totals"]["appended_gmail_physical_message_ids"] == ["101"]


@pytest.mark.parametrize(
    ("foreign_action", "accepted_action"),
    [("existing", "appended"), ("appended", "existing")],
)
def test_report_origin_ignores_foreign_plan_commits(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    foreign_action: str,
    accepted_action: str,
) -> None:
    plan = _plan()
    config = _provider_config()
    journal = [
        _routing_report_commit(
            plan,
            foreign_action,
            routing_plan_sha256="f" * 64,
        ),
        _routing_report_commit(plan, accepted_action),
        _routing_report_commit(plan, "labels-reconciled"),
    ]
    _install_routing_report_fixture(
        monkeypatch,
        tmp_path,
        config,
        plan,
        {"source@example.com": [_manifest_row()]},
        {"source@example.com": journal},
    )

    report = build_provider_routing_report(config, tmp_path, routing_plan=plan)

    account = report["accounts"][0]
    assert account["committed_records"][0]["origin_action"] == accepted_action
    assert account["appended_source_records"] == (accepted_action == "appended")
    assert account["matched_existing_source_records"] == (
        accepted_action == "existing"
    )


def test_report_origin_ignores_incomplete_current_plan_commit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    plan = _plan()
    config = _provider_config()
    journal = [
        _routing_report_commit(
            plan,
            "existing",
            membership_complete=False,
        ),
        _routing_report_commit(plan, "appended"),
        _routing_report_commit(plan, "route-verified"),
        _routing_report_commit(plan, "labels-reconciled"),
    ]
    _install_routing_report_fixture(
        monkeypatch,
        tmp_path,
        config,
        plan,
        {"source@example.com": [_manifest_row()]},
        {"source@example.com": journal},
    )

    report = build_provider_routing_report(config, tmp_path, routing_plan=plan)

    assert report["accounts"][0]["committed_records"][0][
        "origin_action"
    ] == "appended"
    assert report["totals"]["appended_source_records"] == 1
    assert report["totals"]["appended_gmail_physical_messages"] == 1


@pytest.mark.parametrize("same_target", [False, True])
def test_report_scopes_gmail_physical_ids_to_target_merge_group(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    same_target: bool,
) -> None:
    routing = RoutingConfig.from_dict(
        {
            "enabled": True,
            "global_rules": [
                {
                    "match": {"folder": "INBOX"},
                    "destinations": [
                        {"type": CUSTOM_LABEL, "name": "Imported"}
                    ],
                }
            ],
        }
    )
    accounts = [
        MigrationAccount("source1@example.com", "target@example.com"),
        MigrationAccount(
            "source2@example.com",
            "target@example.com" if same_target else "other@example.com",
        ),
    ]
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", password="source-token"),
            gmail_full_visibility_verified=True,
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", password="target-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=accounts,
        migration=MigrationSettings(
            target_mode="merge",
            account_merge_mode="many_to_one" if same_target else "one_to_one",
            routing=routing,
        ),
    )
    plan = resolve_routing_plan(
        routing,
        [
            SourceFolder(account.source_email, "INBOX", attributes=("\\Inbox",))
            for account in accounts
        ],
        [],
    )
    manifests = {
        account.source_email: [_manifest_row(f"m{index}")]
        for index, account in enumerate(accounts, 1)
    }
    journals = {}
    for index, account in enumerate(accounts, 1):
        commit = _routing_report_commit(
            plan,
            "appended",
            target_account=account.target_email,
        )
        commit["canonical_id"] = f"m{index}"
        journals[account.source_email] = [commit]
    _install_routing_report_fixture(
        monkeypatch,
        tmp_path,
        config,
        plan,
        manifests,
        journals,
    )

    report = build_provider_routing_report(config, tmp_path, routing_plan=plan)

    expected_physical = 1 if same_target else 2
    assert report["totals"]["appended_gmail_physical_messages"] == expected_physical
    assert report["totals"]["appended_gmail_physical_message_ids"] == (
        ["101"] if same_target else ["101", "101"]
    )
    assert len(report["totals"]["appended_gmail_physical_message_refs"]) == (
        expected_physical
    )
    assert report["totals"]["gmail_physical_messages"] == expected_physical
    assert report["totals"]["gmail_physical_message_merges"] == (
        1 if same_target else 0
    )
    assert len(report["gmail_physical_messages"]) == expected_physical
    assert all(record["target_account"] for record in report["gmail_physical_messages"])
    assert sorted(
        record["source_records"] for record in report["gmail_physical_messages"]
    ) == ([2] if same_target else [1, 1])


def test_report_keeps_historical_labels_but_attributes_repair_to_true_origin(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    plan = _plan()
    config = _provider_config()
    staged = [_manifest_row("appended"), _manifest_row("existing")]

    def committed(
        identity: str,
        action: str,
        labels: list[str],
        target_gmail_msgid: str,
    ) -> dict:
        return {
            "canonical_id": identity,
            "status": "committed",
            "action": action,
            "routing_plan_sha256": plan.mapping_digest,
            "required_gmail_labels": ["Imported"],
            "required_gmail_system_destinations": [],
            "label_membership_verified": True,
            "labels_applied": labels,
            "target_gmail_msgid": target_gmail_msgid,
        }

    journal = [
        {"canonical_id": "appended", "status": "pending", "action": "append-started"},
        committed("appended", "appended", ["Imported"], "101"),
        committed("appended", "labels-reconciled", ["Repair"], "101"),
        committed("existing", "existing", [], "202"),
        committed("existing", "route-verified", [], "202"),
        committed("existing", "labels-reconciled", ["Repair"], "202"),
    ]
    monkeypatch.setattr(provider_ops, "load_manifest", lambda _path: staged)
    monkeypatch.setattr(provider_ops, "load_import_journal", lambda *_args, **_kwargs: journal)
    for name in (
        "require_manifest_schema",
        "require_unique_manifest_identities",
        "require_manifest_accounts",
        "require_manifest_source_provider",
        "require_manifest_integrity_metadata",
        "require_complete_export_state",
        "require_valid_import_journal",
    ):
        monkeypatch.setattr(provider_ops, name, lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        provider_ops,
        "_effective_provider_routing_plan",
        lambda *_args, **_kwargs: plan,
    )
    report = build_provider_routing_report(config, tmp_path, routing_plan=plan)
    applications = {
        item["canonical_id"]: item for item in report["accounts"][0]["labels_applied"]
    }

    assert applications["appended"]["labels"] == ["Imported", "Repair"]
    assert applications["appended"]["labels_applied_to_existing_match"] == []
    assert applications["existing"]["labels_applied_to_existing_match"] == [
        "Repair",
    ]
    assert report["totals"]["committed_messages"] == 2
    assert report["totals"]["messages_with_labels_applied_to_existing_matches"] == 1
    assert report["totals"]["appended_source_records"] == 1
    assert report["totals"]["imported_source_records"] == 1
    assert report["totals"]["appended_gmail_physical_messages"] == 1
    assert report["totals"]["appended_gmail_physical_message_ids"] == ["101"]
    assert report["totals"]["matched_existing_source_records"] == 1
    account_report = report["accounts"][0]
    assert account_report["appended_canonical_ids"] == ["appended"]
    assert account_report["matched_existing_canonical_ids"] == ["existing"]
    assert account_report["origin_unclassified_source_records"] == 0
    folder = account_report["folders"][0]
    assert folder["appended_source_records"] == 1
    assert folder["imported_source_records"] == 1
    assert folder["matched_existing_source_records"] == 1


def test_report_uses_the_same_virtual_membership_union_as_execution(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    routing = RoutingConfig.from_dict(
        {
            "enabled": True,
            "global_rules": [
                {
                    "match": {"folder": "INBOX"},
                    "destinations": [{"type": CUSTOM_LABEL, "name": "InboxRoute"}],
                },
                {
                    "match": {"folder": "[Gmail]/All Mail"},
                    "destinations": [{"type": CUSTOM_LABEL, "name": "AllRoute"}],
                },
            ],
        }
    )
    plan = resolve_routing_plan(
        routing,
        [
            SourceFolder("source@example.com", "INBOX", attributes=("\\Inbox",)),
            SourceFolder(
                "source@example.com",
                "[Gmail]/All Mail",
                attributes=("\\All",),
            ),
        ],
        [],
    )
    config = _provider_config(routing)
    staged = _manifest_row()
    staged["source_mailboxes"] = ["INBOX", "[Gmail]/All Mail"]
    monkeypatch.setattr(provider_ops, "load_manifest", lambda _path: [staged])
    monkeypatch.setattr(provider_ops, "load_import_journal", lambda *_args, **_kwargs: [])
    for name in (
        "require_manifest_schema",
        "require_unique_manifest_identities",
        "require_manifest_accounts",
        "require_manifest_source_provider",
        "require_manifest_integrity_metadata",
        "require_complete_export_state",
        "require_valid_import_journal",
    ):
        monkeypatch.setattr(provider_ops, name, lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        provider_ops,
        "_effective_provider_routing_plan",
        lambda *_args, **_kwargs: plan,
    )

    report = build_provider_routing_report(config, tmp_path, routing_plan=plan)
    folders = {
        folder["source_folder"]: folder
        for folder in report["accounts"][0]["folders"]
    }

    assert folders["INBOX"]["routed_messages"] == 1
    assert folders["[Gmail]/All Mail"]["routed_messages"] == 1


def test_routed_report_aggregates_and_deduplicates_internaldate_evidence_warnings(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    plan = dataclasses.replace(
        _plan(),
        warnings=("routing plan warning", "routing plan warning"),
    )
    config = _provider_config()
    staged = _manifest_row()
    staged["internaldate"] = "01-Jan-2024 00:00:00 +0000"
    staged["content_sha256"] = "a" * 64
    staged["rfc822_size"] = 1
    staged[CONTENT_BINDING_FIELD] = provider_ops.provider_content_binding_sha256(staged)
    evidence = {
        "content_sha256": staged["content_sha256"],
        "rfc822_size": staged["rfc822_size"],
        CONTENT_BINDING_FIELD: staged[CONTENT_BINDING_FIELD],
        "target_gmail_msgid": "101",
        "source_internaldate": "01-Jan-2024 00:00:00 +0000",
        "target_internaldate": "02-Jan-2024 00:00:00 +0000",
        "internaldate_provenance": "existing-content-reuse",
        "internaldate_origin_action": "existing",
    }
    journal = [
        {
            "canonical_id": "m1",
            "target_account": "target@example.com",
            "target_mailbox": "Archive",
            "status": "committed",
            "action": "existing",
            "internaldate": staged["internaldate"],
            **evidence,
        },
        {
            "canonical_id": "m1",
            "target_account": "target@example.com",
            "target_mailbox": "Archive",
            "status": "committed",
            "action": "route-verified",
            "internaldate": staged["internaldate"],
            "routing_plan_sha256": plan.mapping_digest,
            "required_gmail_labels": ["Imported"],
            "required_gmail_system_destinations": [],
            "label_membership_verified": True,
            "labels_applied": [],
            **evidence,
        },
    ]
    monkeypatch.setattr(provider_ops, "load_manifest", lambda _path: [staged])
    monkeypatch.setattr(
        provider_ops,
        "load_import_journal",
        lambda *_args, **_kwargs: journal,
    )
    for name in (
        "require_manifest_schema",
        "require_unique_manifest_identities",
        "require_manifest_accounts",
        "require_manifest_source_provider",
        "require_manifest_integrity_metadata",
        "require_complete_export_state",
        "require_valid_import_journal",
    ):
        monkeypatch.setattr(provider_ops, name, lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        provider_ops,
        "_effective_provider_routing_plan",
        lambda *_args, **_kwargs: plan,
    )
    monkeypatch.setattr(
        provider_ops,
        "validate_provider_routing_plan",
        lambda *_args, **_kwargs: None,
    )

    report = build_provider_routing_report(config, tmp_path, routing_plan=plan)

    account_warnings = report["accounts"][0]["warnings"]
    assert len(account_warnings) == 1
    warning = account_warnings[0]
    assert warning["code"] == "existing-target-internaldate-differs"
    assert warning["source_account"] == "source@example.com"
    assert warning["target_account"] == "target@example.com"
    assert report["warnings"] == ["routing plan warning", warning]
    assert report["totals"]["warnings"] == 1


def test_staged_audit_allows_incomplete_route_commit_for_import_reconciliation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    plan = _plan()
    config = _provider_config()
    account = config.accounts[0]
    account_dir = provider_ops.account_export_dir(tmp_path, account)
    (account_dir / "messages").mkdir(parents=True)
    (account_dir / "metadata").mkdir()
    eml_path = account_dir / "messages" / "message.eml"
    metadata_path = account_dir / "metadata" / "message.json"
    eml_path.write_bytes(b"From: source@example.com\r\n\r\nbody\r\n")
    metadata_path.write_text("{}\n", encoding="utf-8")
    eml_path.chmod(0o600)
    metadata_path.chmod(0o600)
    row = {
        **_manifest_row(),
        "eml_path": "messages/message.eml",
        "metadata_path": "metadata/message.json",
    }
    incomplete_commit = {
        "canonical_id": "m1",
        "status": "committed",
        "action": "existing",
        # Deliberately no routing digest/required-label verification yet.
    }
    monkeypatch.setattr(
        provider_ops,
        "_effective_provider_routing_plan",
        lambda *_args, **_kwargs: plan,
    )
    monkeypatch.setattr(provider_ops, "load_manifest", lambda _path: [row])
    monkeypatch.setattr(
        provider_ops,
        "load_import_journal",
        lambda *_args, **_kwargs: [incomplete_commit],
    )
    for name in (
        "provider_export_state_issues",
        "manifest_schema_issues",
        "manifest_account_issues",
        "manifest_source_provider_issues",
        "manifest_integrity_issues",
        "provider_delivery_metadata_issues",
        "metadata_manifest_issues",
        "_provider_artifact_orphan_issues",
        "provider_mixed_legacy_layout_issues",
        "gmail_target_decommission_issues",
        "journal_row_issues",
        "journal_target_endpoint_issues",
        "committed_journal_manifest_content_issues",
        "offline_journal_target_mailbox_issues",
        "invalid_journal_target_gmail_msgid_issues",
        "missing_journal_target_gmail_msgid_issues",
        "duplicate_journal_target_gmail_msgid_issues",
    ):
        monkeypatch.setattr(provider_ops, name, lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        provider_ops,
        "require_manifest_payload_matches",
        lambda *_args, **_kwargs: None,
    )

    _name, issues = provider_audit_account(
        config,
        account,
        tmp_path,
        routing_plan=plan,
    )

    assert issues == []
    routed, _ = routed_manifest_rows(config, account, [row], plan)
    assert not provider_ops.routing_journal_membership_complete(
        incomplete_commit,
        routed[0],
    )


def test_import_reconciles_incomplete_committed_route_membership(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    plan = _plan()
    config = _provider_config()
    account = config.accounts[0]
    account_dir = provider_ops.account_export_dir(tmp_path, account)
    (account_dir / "messages").mkdir(parents=True)
    eml_path = account_dir / "messages" / "message.eml"
    eml_path.write_bytes(b"From: source@example.com\r\n\r\nbody\r\n")
    eml_path.chmod(0o600)
    row = {
        **_manifest_row(),
        "target_account": account.target_email,
        "content_sha256": "a" * 64,
        "rfc822_size": eml_path.stat().st_size,
        "internaldate": "01-Jan-2024 00:00:00 +0000",
        "eml_path": "messages/message.eml",
    }
    incomplete_commit = {
        "canonical_id": "m1",
        "target_mailbox": "[Gmail]/All Mail",
        "target_gmail_msgid": "123",
        "status": "committed",
        "action": "existing",
    }
    appended_journal_rows: list[dict] = []
    monkeypatch.setattr(
        provider_ops,
        "_effective_provider_routing_plan",
        lambda *_args, **_kwargs: plan,
    )
    monkeypatch.setattr(provider_ops, "load_manifest", lambda _path: [row])
    monkeypatch.setattr(
        provider_ops,
        "load_import_journal",
        lambda *_args, **_kwargs: [incomplete_commit],
    )
    for name in (
        "require_manifest_schema",
        "require_unique_manifest_identities",
        "require_manifest_accounts",
        "require_manifest_source_provider",
        "require_manifest_integrity_metadata",
        "require_provider_delivery_metadata",
        "require_complete_export_state",
        "require_manifest_payload_matches",
        "require_valid_import_journal",
    ):
        monkeypatch.setattr(provider_ops, name, lambda *_args, **_kwargs: None)
    for name in (
        "metadata_manifest_issues",
        "_provider_artifact_orphan_issues",
        "provider_mixed_legacy_layout_issues",
        "journal_target_endpoint_issues",
        "committed_journal_manifest_content_issues",
        "invalid_journal_target_gmail_msgid_issues",
        "duplicate_journal_target_gmail_msgid_issues",
        "committed_journal_target_mailbox_issues",
        "pending_journal_target_mailbox_issues",
        "gmail_target_readiness_issues",
        "gmail_all_mail_select_issues",
        "gmail_target_decommission_issues",
        "gmail_target_system_mailbox_issues",
        "missing_journal_target_gmail_msgid_issues",
    ):
        monkeypatch.setattr(provider_ops, name, lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        provider_ops,
        "repair_missing_journal_target_gmail_msgids",
        lambda _imap, _dir, _account, rows, *_args, **_kwargs: rows,
    )
    monkeypatch.setattr(
        provider_ops,
        "imap_connection",
        lambda *_args, **_kwargs: contextlib.nullcontext(object()),
    )
    monkeypatch.setattr(provider_ops, "get_capabilities", lambda _imap: ["X-GM-EXT-1"])
    target_mailboxes = [MailboxInfo("[Gmail]/All Mail", "/", ("\\All",))]
    monkeypatch.setattr(provider_ops, "list_mailboxes", lambda _imap: target_mailboxes)
    monkeypatch.setattr(
        provider_ops,
        "_target_physical_occurrences_for_row",
        lambda *_args, **_kwargs: [
            {
                "physical_key": ("gmail", "123"),
                "mailbox": "[Gmail]/All Mail",
                "num": b"1",
                "gmail_msgid": "123",
                "internaldate": "01-Jan-2024 00:00:00 +0000",
                "gmail_label_keys": {"all"},
                "gmail_flags": set(),
            }
        ],
    )
    monkeypatch.setattr(provider_ops, "subscribe_mailbox", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        provider_ops,
        "target_message_internaldate",
        lambda *_args, **_kwargs: "01-Jan-2024 00:00:00 +0000",
    )
    monkeypatch.setattr(
        provider_ops,
        "restore_gmail_labels",
        lambda *_args, **_kwargs: ["Imported"],
    )
    monkeypatch.setattr(provider_ops, "restore_gmail_starred_flag", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(provider_ops, "restore_imap_flags", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        provider_ops,
        "append_journal",
        lambda _dir, _account, journal_row: appended_journal_rows.append(journal_row),
    )

    provider_import_account(config, account, tmp_path, routing_plan=plan)

    assert len(appended_journal_rows) == 1
    reconciled = appended_journal_rows[0]
    assert reconciled["action"] == "labels-reconciled"
    assert reconciled["labels_applied"] == ["Imported"]
    routed, _ = routed_manifest_rows(config, account, [row], plan)
    assert provider_ops.routing_journal_membership_complete(reconciled, routed[0])


def test_import_prevalidation_defers_incomplete_route_membership_to_reconciliation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    plan = _plan()
    config = _provider_config()
    account = config.accounts[0]
    row = _manifest_row()
    incomplete_commit = {
        "canonical_id": "m1",
        "target_mailbox": "[Gmail]/All Mail",
        "status": "committed",
        "action": "existing",
    }
    monkeypatch.setattr(
        provider_ops,
        "_effective_provider_routing_plan",
        lambda *_args, **_kwargs: plan,
    )
    monkeypatch.setattr(provider_ops, "load_manifest", lambda _path: [row])
    monkeypatch.setattr(
        provider_ops,
        "load_import_journal",
        lambda *_args, **_kwargs: [incomplete_commit],
    )
    for name in (
        "provider_export_state_issues",
        "manifest_schema_issues",
        "manifest_source_provider_issues",
        "manifest_integrity_issues",
        "provider_delivery_metadata_issues",
        "metadata_manifest_issues",
        "manifest_payload_issues",
        "_provider_artifact_orphan_issues",
        "provider_mixed_legacy_layout_issues",
        "gmail_target_decommission_issues",
        "journal_row_issues",
        "journal_target_endpoint_issues",
        "committed_journal_manifest_content_issues",
        "offline_journal_target_mailbox_issues",
        "invalid_journal_target_gmail_msgid_issues",
        "duplicate_journal_target_gmail_msgid_entries",
    ):
        monkeypatch.setattr(provider_ops, name, lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        provider_ops,
        "require_manifest_accounts",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        provider_ops,
        "manifest_payload_content_identities",
        lambda *_args, **_kwargs: {},
    )
    route_check_called = False

    def route_check(*_args, **_kwargs):
        nonlocal route_check_called
        route_check_called = True
        return ["route membership sentinel"]

    monkeypatch.setattr(provider_ops, "routing_committed_journal_issues", route_check)

    _name, report = provider_validate_account(
        config,
        account,
        tmp_path,
        check_target=False,
        write_report=False,
        allow_unresolved_pending=True,
        allow_missing_gmail_target_msgid=True,
        routing_plan=plan,
    )

    assert not route_check_called
    assert "route membership sentinel" not in report["failed"]


@pytest.mark.parametrize(
    ("left", "right", "needle"),
    [
        (
            _duplicate_routing_row(
                "draft",
                primary_mailbox="Drafts",
                systems=("drafts",),
            ),
            _duplicate_routing_row("custom", labels=("Review",)),
            "label:review",
        ),
        (
            _duplicate_routing_row(
                "draft",
                primary_mailbox="Drafts",
                systems=("drafts",),
            ),
            _duplicate_routing_row("important", systems=("important",)),
            "important",
        ),
        (
            _duplicate_routing_row(
                "draft",
                primary_mailbox="Drafts",
                systems=("drafts",),
            ),
            _duplicate_routing_row("starred", flags="\\Flagged"),
            "starred",
        ),
        (
            _duplicate_routing_row(
                "inbox",
                primary_mailbox="INBOX",
                systems=("inbox",),
            ),
            _duplicate_routing_row(
                "spam",
                primary_mailbox="Spam",
                systems=("spam",),
            ),
            "inbox",
        ),
        (
            _duplicate_routing_row(
                "inbox",
                primary_mailbox="INBOX",
                systems=("inbox",),
            ),
            _duplicate_routing_row(
                "trash",
                primary_mailbox="Trash",
                systems=("trash",),
            ),
            "inbox",
        ),
        (
            _duplicate_routing_row("all", systems=("all",)),
            _duplicate_routing_row(
                "spam",
                primary_mailbox="Spam",
                systems=("spam",),
            ),
            "all",
        ),
    ],
)
def test_cross_source_one_slot_duplicate_rejects_incompatible_gmail_destinations(
    left: dict,
    right: dict,
    needle: str,
) -> None:
    content_identity = (123, "a" * 64)
    stages = [
        _duplicate_stage("a@example.com", [left]),
        _duplicate_stage("b@example.com", [right]),
    ]

    with pytest.raises(
        provider_ops.ProviderImportIntegrityGateError,
        match="incompatible Gmail destinations",
    ) as excinfo:
        provider_ops.require_merge_group_gmail_destination_allocations_compatible(
            stages,
            expected_content_identities_by_id={
                left["canonical_id"]: {content_identity},
                right["canonical_id"]: {content_identity},
            },
        )

    assert needle in str(excinfo.value).casefold()


@pytest.mark.parametrize(
    ("left", "right"),
    [
        (
            _duplicate_routing_row(
                "inbox",
                primary_mailbox="INBOX",
                systems=("inbox",),
            ),
            _duplicate_routing_row(
                "sent",
                primary_mailbox="Sent",
                systems=("sent",),
            ),
        ),
        (
            _duplicate_routing_row("mail-b", labels=("MailB",)),
            _duplicate_routing_row("mail-c", labels=("MailC",)),
        ),
    ],
)
def test_cross_source_one_slot_duplicate_accepts_representable_unions(
    left: dict,
    right: dict,
) -> None:
    content_identity = (123, "b" * 64)

    classes = provider_ops.require_merge_group_gmail_destination_allocations_compatible(
        [
            _duplicate_stage("a@example.com", [left]),
            _duplicate_stage("b@example.com", [right]),
        ],
        expected_content_identities_by_id={
            left["canonical_id"]: {content_identity},
            right["canonical_id"]: {content_identity},
        },
    )

    assert len(classes) == 1
    assert classes[0]["capacity"] == 1


def test_cross_source_duplicate_allocation_uses_distinct_capacity_when_feasible() -> None:
    content_identity = (123, "c" * 64)
    a_draft = _duplicate_routing_row(
        "a-draft",
        primary_mailbox="Drafts",
        systems=("drafts",),
    )
    a_custom = _duplicate_routing_row("a-custom", labels=("Review",))
    b_custom = _duplicate_routing_row("b-custom", labels=("Review",))
    b_draft = _duplicate_routing_row(
        "b-draft",
        primary_mailbox="Drafts",
        systems=("drafts",),
    )
    rows = [a_draft, a_custom, b_custom, b_draft]

    classes = provider_ops.require_merge_group_gmail_destination_allocations_compatible(
        [
            _duplicate_stage("a@example.com", [a_draft, a_custom]),
            _duplicate_stage("b@example.com", [b_custom, b_draft]),
        ],
        expected_content_identities_by_id={
            row["canonical_id"]: {content_identity} for row in rows
        },
    )

    assert len(classes) == 1
    assert classes[0]["capacity"] == 2
    allocation = classes[0]["allocations"]
    assert allocation[("a@example.com", "a-draft")] == allocation[
        ("b@example.com", "b-draft")
    ]
    assert allocation[("a@example.com", "a-custom")] == allocation[
        ("b@example.com", "b-custom")
    ]
    assert allocation[("a@example.com", "a-draft")] != allocation[
        ("a@example.com", "a-custom")
    ]


def test_duplicate_allocator_groups_five_family_symmetries_and_is_cancellable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content_identity = (456, "9" * 64)
    profile_specs = [
        (("drafts",), (), "Drafts"),
        (("sent",), (), "Sent"),
        (("spam", "important"), (), "Spam"),
        (("trash",), (), "Trash"),
        (("important",), ("Unique",), "Archive"),
        (("inbox",), ("Unique",), "INBOX"),
        (("starred",), ("Unique",), "Archive"),
        (("all",), ("Unique",), "Archive"),
    ]
    stages = []
    expected: dict[str, set[tuple[int, str]]] = {}
    for source_index in range(5):
        source = f"source-{source_index}@example.com"
        rows = []
        journal = []
        for row_index, (systems, labels, primary_mailbox) in enumerate(
            profile_specs
        ):
            identity = f"source-{source_index}-row-{row_index}"
            row = _duplicate_routing_row(
                identity,
                primary_mailbox=primary_mailbox,
                systems=systems,
                labels=tuple(
                    f"{label}-{source_index}-{row_index}"
                    for label in labels
                ),
            )
            rows.append(row)
            expected[identity] = {content_identity}
            if source_index == 0:
                journal.append(
                    {
                        "canonical_id": identity,
                        "status": "committed",
                        "action": "appended",
                        "target_gmail_msgid": str(1000 + row_index),
                    }
                )
        stages.append(_duplicate_stage(source, rows, journal))

    classes = provider_ops.require_merge_group_gmail_destination_allocations_compatible(
        stages,
        expected_content_identities_by_id=expected,
    )
    reversed_classes = (
        provider_ops.require_merge_group_gmail_destination_allocations_compatible(
            list(reversed(stages)),
            expected_content_identities_by_id=expected,
        )
    )

    assert len(classes) == 1
    assert classes[0]["capacity"] == 8
    assert len(classes[0]["allocations"]) == 40
    assert classes[0]["allocation_search_states"] <= 100
    assert classes[0]["allocations"] == reversed_classes[0]["allocations"]
    assert classes[0]["slot_profiles"] == reversed_classes[0]["slot_profiles"]

    stop_event = threading.Event()
    stop_event.set()
    with pytest.raises(RuntimeError, match="stop requested"):
        provider_ops.require_merge_group_gmail_destination_allocations_compatible(
            stages,
            expected_content_identities_by_id=expected,
            stop_event=stop_event,
        )

    monkeypatch.setattr(
        provider_ops,
        "GMAIL_DUPLICATE_ALLOCATION_MAX_SEARCH_STATES",
        0,
    )
    with pytest.raises(
        provider_ops.ProviderImportIntegrityGateError,
        match="indeterminate: search-state resource bound exceeded",
    ):
        provider_ops.require_merge_group_gmail_destination_allocations_compatible(
            stages,
            expected_content_identities_by_id=expected,
        )

    monkeypatch.setattr(
        provider_ops,
        "GMAIL_DUPLICATE_ALLOCATION_MAX_SEARCH_STATES",
        1_000_000,
    )
    monkeypatch.setattr(
        provider_ops,
        "GMAIL_DUPLICATE_ALLOCATION_MAX_FAMILY_GROUPS",
        0,
    )
    with pytest.raises(
        provider_ops.ProviderImportIntegrityGateError,
        match="indeterminate: family-group resource bound exceeded",
    ):
        provider_ops.require_merge_group_gmail_destination_allocations_compatible(
            stages,
            expected_content_identities_by_id=expected,
        )


def test_runtime_matching_honors_full_feasible_slot_profile_not_candidate_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content_identity = (123, "f" * 64)
    a_spam = _duplicate_routing_row(
        "a-spam",
        primary_mailbox="Spam",
        systems=("spam",),
    )
    a_sent = _duplicate_routing_row(
        "a-sent",
        primary_mailbox="Sent",
        systems=("sent",),
    )
    b_important = _duplicate_routing_row(
        "b-important",
        systems=("important",),
    )
    b_sent = _duplicate_routing_row(
        "b-sent",
        primary_mailbox="Sent",
        systems=("sent",),
    )
    rows = [a_spam, a_sent, b_important, b_sent]
    allocation_class = (
        provider_ops.require_merge_group_gmail_destination_allocations_compatible(
            [
                _duplicate_stage("a@example.com", [a_spam, a_sent]),
                _duplicate_stage("b@example.com", [b_important, b_sent]),
            ],
            expected_content_identities_by_id={
                row["canonical_id"]: {content_identity} for row in rows
            },
        )[0]
    )
    allocation = allocation_class["allocations"]

    assert allocation[("b@example.com", "b-important")] == allocation[
        ("a@example.com", "a-spam")
    ]
    assert allocation[("b@example.com", "b-sent")] == allocation[
        ("a@example.com", "a-sent")
    ]

    for row in (b_important, b_sent):
        slot = allocation[("b@example.com", row["canonical_id"])]
        profile = allocation_class["slot_profiles"][slot]
        row["_gmail_duplicate_allocation"] = {
            "class": 0,
            "slot": slot,
            "systems": profile["systems"],
            "custom_labels": profile["custom_labels"],
        }

    search_mailboxes = provider_ops.gmail_expected_target_mailboxes_for_row(
        b_important,
        "[Gmail]/All Mail",
        [
            MailboxInfo("[Gmail]/All Mail", "/", ("\\All",)),
            MailboxInfo("[Gmail]/Sent Mail", "/", ("\\Sent",)),
            MailboxInfo("[Gmail]/Spam", "/", ("\\Junk",)),
            MailboxInfo("[Gmail]/Important", "/", ("\\Important",)),
        ],
    )
    assert "[Gmail]/Spam" in search_mailboxes

    sent_occurrence = {
        "physical_key": ("gmail", "sent-id"),
        "mailbox": "[Gmail]/Sent Mail",
        "num": b"2",
        "gmail_msgid": "sent-id",
        "internaldate": "01-Jan-2024 00:00:00 +0000",
        "gmail_label_keys": {"sent"},
        "gmail_flags": set(),
    }
    spam_occurrence = {
        "physical_key": ("gmail", "spam-id"),
        "mailbox": "[Gmail]/Spam",
        "num": b"1",
        "gmail_msgid": "spam-id",
        "internaldate": "01-Jan-2024 00:00:00 +0000",
        "gmail_label_keys": {"spam"},
        "gmail_flags": set(),
    }
    monkeypatch.setattr(
        provider_ops,
        "_target_physical_occurrences_for_row",
        lambda *_args, **_kwargs: [sent_occurrence, spam_occurrence],
    )

    assignments = provider_ops._target_row_assignments(
        object(),
        [],
        {
            "b-important": {
                "manifest_row": b_important,
                "target_mailbox": "Archive",
            },
            "b-sent": {
                "manifest_row": b_sent,
                "target_mailbox": "Sent",
            },
        },
        target_provider="gmail",
    )

    assert assignments["b-important"]["gmail_msgid"] == "spam-id"
    assert assignments["b-sent"]["gmail_msgid"] == "sent-id"

    b_journal = [
        {
            "canonical_id": "b-important",
            "status": "committed",
            "action": "appended",
            "target_gmail_msgid": "important-id",
        },
        {
            "canonical_id": "b-sent",
            "status": "committed",
            "action": "appended",
            "target_gmail_msgid": "sent-id",
        },
    ]
    reverse_class = (
        provider_ops.require_merge_group_gmail_destination_allocations_compatible(
            [
                _duplicate_stage("a@example.com", [a_spam, a_sent]),
                _duplicate_stage(
                    "b@example.com",
                    [b_important, b_sent],
                    b_journal,
                ),
            ],
            expected_content_identities_by_id={
                row["canonical_id"]: {content_identity} for row in rows
            },
        )[0]
    )
    reverse_allocation = reverse_class["allocations"]
    for row in (a_spam, a_sent):
        slot = reverse_allocation[("a@example.com", row["canonical_id"])]
        profile = reverse_class["slot_profiles"][slot]
        row["_gmail_duplicate_allocation"] = {
            "class": 0,
            "slot": slot,
            "systems": profile["systems"],
            "custom_labels": profile["custom_labels"],
            "target_gmail_msgids": profile["target_gmail_msgids"],
        }

    important_occurrence = {
        "physical_key": ("gmail", "important-id"),
        "mailbox": "[Gmail]/All Mail",
        "num": b"3",
        "gmail_msgid": "important-id",
        "internaldate": "01-Jan-2024 00:00:00 +0000",
        "gmail_label_keys": {"important"},
        "gmail_flags": set(),
    }
    monkeypatch.setattr(
        provider_ops,
        "_target_physical_occurrences_for_row",
        lambda *_args, **_kwargs: [sent_occurrence, important_occurrence],
    )
    reverse_assignments = provider_ops._target_row_assignments(
        object(),
        [],
        {
            "a-spam": {
                "manifest_row": a_spam,
                "target_mailbox": "Spam",
            },
            "a-sent": {
                "manifest_row": a_sent,
                "target_mailbox": "Sent",
            },
        },
        target_provider="gmail",
    )

    assert reverse_assignments["a-spam"]["gmail_msgid"] == "important-id"
    assert reverse_assignments["a-sent"]["gmail_msgid"] == "sent-id"

    unrelated_important = {
        **important_occurrence,
        "physical_key": ("gmail", "unrelated-id"),
        "gmail_msgid": "unrelated-id",
    }
    monkeypatch.setattr(
        provider_ops,
        "_target_physical_occurrences_for_row",
        lambda *_args, **_kwargs: [unrelated_important],
    )
    assert provider_ops._target_row_assignments(
        object(),
        [],
        {
            "a-spam": {
                "manifest_row": a_spam,
                "target_mailbox": "Spam",
            }
        },
        target_provider="gmail",
    ) == {}


def test_fresh_neutral_anchor_uses_durable_post_append_identity_and_fails_ambiguous(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    important = _duplicate_routing_row(
        "important-first",
        systems=("important",),
    )
    important["_gmail_duplicate_allocation"] = {
        "class": 0,
        "slot": 0,
        "systems": ["important", "spam"],
        "custom_labels": [],
        "target_gmail_msgids": [],
    }
    old_anchor = {
        "physical_key": ("gmail", "100"),
        "mailbox": "[Gmail]/All Mail",
        "num": b"1",
        "gmail_msgid": "100",
        "internaldate": "01-Jan-2024 00:00:00 +0000",
        "gmail_label_keys": {"all"},
        "gmail_flags": set(),
    }
    fresh_anchor = {
        **old_anchor,
        "physical_key": ("gmail", "101"),
        "num": b"2",
        "gmail_msgid": "101",
    }
    monkeypatch.setattr(
        provider_ops,
        "_target_physical_occurrences_for_row",
        lambda *_args, **_kwargs: [old_anchor, fresh_anchor],
    )

    confirmed = provider_ops._gmail_confirmed_fresh_append_occurrence(
        object(),
        [],
        important,
        "[Gmail]/All Mail",
        ["100"],
        expected_content_identities=None,
    )
    pending_assignment = provider_ops._target_row_assignments(
        object(),
        [],
        {
            "important-first": {
                "manifest_row": important,
                "target_mailbox": "[Gmail]/All Mail",
                "pre_append_gmail_msgids": ["100"],
                "require_unique_fresh_append": True,
                "require_internaldate_match": True,
            }
        },
        target_provider="gmail",
        required_row_keys={"important-first"},
    )

    assert confirmed is not None
    assert confirmed["gmail_msgid"] == "101"
    assert pending_assignment["important-first"]["gmail_msgid"] == "101"

    second_fresh = {
        **fresh_anchor,
        "physical_key": ("gmail", "102"),
        "num": b"3",
        "gmail_msgid": "102",
    }
    monkeypatch.setattr(
        provider_ops,
        "_target_physical_occurrences_for_row",
        lambda *_args, **_kwargs: [old_anchor, fresh_anchor, second_fresh],
    )
    with pytest.raises(
        provider_ops.ProviderImportIntegrityGateError,
        match="cannot uniquely confirm fresh Gmail APPEND",
    ):
        provider_ops._gmail_confirmed_fresh_append_occurrence(
            object(),
            [],
            important,
            "[Gmail]/All Mail",
            ["100"],
            expected_content_identities=None,
        )

    explicit_all = dict(important)
    explicit_all["_gmail_duplicate_allocation"] = {
        **important["_gmail_duplicate_allocation"],
        "systems": ["all", "important", "spam"],
    }
    monkeypatch.setattr(
        provider_ops,
        "_target_physical_occurrences_for_row",
        lambda *_args, **_kwargs: [fresh_anchor],
    )
    assert provider_ops._gmail_confirmed_fresh_append_occurrence(
        object(),
        [],
        explicit_all,
        "[Gmail]/All Mail",
        [],
        expected_content_identities=None,
    ) is None


def test_gmail_candidate_flags_do_not_become_custom_labels_and_seen_draft_matches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FlagImap:
        def fetch(self, _num: bytes, _query: str):
            return (
                "OK",
                [
                    b'1 (X-GM-LABELS ("Review") FLAGS (\\Seen \\Answered \\Draft))'
                ],
            )

    label_keys, flags = provider_ops._target_gmail_label_and_flag_keys(
        FlagImap(),
        b"1",
    )

    assert label_keys == {"label:review", "drafts"}
    assert flags == {"\\SEEN", "\\ANSWERED", "\\DRAFT"}

    draft = _duplicate_routing_row(
        "seen-draft",
        primary_mailbox="Drafts",
        systems=("drafts",),
        flags="\\Seen \\Draft",
    )
    draft["_gmail_duplicate_allocation"] = {
        "systems": ["drafts"],
        "custom_labels": [],
        "target_gmail_msgids": [],
    }
    draft_occurrence = {
        "physical_key": ("gmail", "501"),
        "mailbox": "[Gmail]/Drafts",
        "num": b"1",
        "gmail_msgid": "501",
        "internaldate": "01-Jan-2024 00:00:00 +0000",
        "gmail_label_keys": {"drafts"},
        "gmail_flags": {"\\SEEN", "\\DRAFT"},
    }
    monkeypatch.setattr(
        provider_ops,
        "_target_physical_occurrences_for_row",
        lambda *_args, **_kwargs: [draft_occurrence],
    )

    assignment = provider_ops._target_row_assignments(
        object(),
        [],
        {"seen-draft": {"manifest_row": draft, "target_mailbox": "Drafts"}},
        target_provider="gmail",
    )

    assert assignment["seen-draft"]["gmail_msgid"] == "501"


def test_pending_fresh_append_batch_uses_unique_global_nested_baseline_matching(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    broad = _duplicate_routing_row("broad", labels=("Broad",))
    narrow = _duplicate_routing_row("narrow", labels=("Narrow",))
    for row in (broad, narrow):
        row["_gmail_duplicate_allocation"] = {
            "systems": ["all"],
            "custom_labels": ["Broad", "Narrow"],
            "target_gmail_msgids": [],
        }
    occurrence_a = {
        "physical_key": ("gmail", "601"),
        "mailbox": "[Gmail]/All Mail",
        "num": b"1",
        "gmail_msgid": "601",
        "internaldate": "01-Jan-2024 00:00:00 +0000",
        "gmail_label_keys": {"all"},
        "gmail_flags": set(),
    }
    occurrence_b = {
        **occurrence_a,
        "physical_key": ("gmail", "602"),
        "num": b"2",
        "gmail_msgid": "602",
    }
    monkeypatch.setattr(
        provider_ops,
        "_target_physical_occurrences_for_row",
        lambda *_args, **_kwargs: [occurrence_a, occurrence_b],
    )
    specs = {
        "broad": {
            "manifest_row": broad,
            "target_mailbox": "[Gmail]/All Mail",
            "pre_append_gmail_msgids": [],
            "require_unique_fresh_append": True,
            "require_internaldate_match": True,
        },
        "narrow": {
            "manifest_row": narrow,
            "target_mailbox": "[Gmail]/All Mail",
            "pre_append_gmail_msgids": ["601"],
            "require_unique_fresh_append": True,
            "require_internaldate_match": True,
        },
    }

    assignments = provider_ops._target_row_assignments(
        object(),
        [],
        specs,
        target_provider="gmail",
    )

    assert assignments["broad"]["gmail_msgid"] == "601"
    assert assignments["narrow"]["gmail_msgid"] == "602"

    specs["narrow"]["pre_append_gmail_msgids"] = []
    with pytest.raises(
        provider_ops.ProviderImportIntegrityGateError,
        match="multiple one-to-one post-APPEND physical allocations remain",
    ):
        provider_ops._target_row_assignments(
            object(),
            [],
            specs,
            target_provider="gmail",
        )


def test_exact_committed_gmail_id_must_match_full_allocated_slot_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent = _duplicate_routing_row(
        "sent-bound-to-spam",
        primary_mailbox="Sent",
        systems=("sent",),
    )
    sent["_gmail_duplicate_allocation"] = {
        "class": 0,
        "slot": 0,
        "systems": ["spam"],
        "custom_labels": [],
        "target_gmail_msgids": ["777"],
    }
    sent_occurrence = {
        "physical_key": ("gmail", "777"),
        "mailbox": "[Gmail]/Sent Mail",
        "num": b"7",
        "gmail_msgid": "777",
        "internaldate": "01-Jan-2024 00:00:00 +0000",
        "gmail_label_keys": {"sent"},
        "gmail_flags": set(),
    }
    monkeypatch.setattr(
        provider_ops,
        "_target_physical_occurrences_for_row",
        lambda *_args, **_kwargs: [sent_occurrence],
    )

    assert provider_ops._target_row_assignments(
        object(),
        [],
        {
            "sent-bound-to-spam": {
                "manifest_row": sent,
                "target_mailbox": "Sent",
                "target_gmail_msgid": "777",
                "require_internaldate_match": True,
            }
        },
        target_provider="gmail",
        required_row_keys={"sent-bound-to-spam"},
    ) == {}


def test_missing_gmail_id_repair_searches_allocation_expanded_mailboxes_before_write(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    account = MigrationAccount("important@example.com", "target@gmail.com")
    row = _duplicate_routing_row(
        "important-anchor",
        systems=("important",),
    )
    row.update(
        {
            "target_account": account.target_email,
            "content_sha256": "a" * 64,
            "rfc822_size": 10,
            CONTENT_BINDING_FIELD: "b" * 64,
        }
    )
    row["_gmail_duplicate_allocation"] = {
        "class": 0,
        "slot": 0,
        "systems": ["important", "spam"],
        "custom_labels": [],
        "target_gmail_msgids": [],
    }
    journal_row = {
        "canonical_id": "important-anchor",
        "target_mailbox": "[Gmail]/All Mail",
        "status": "committed",
        "action": "appended",
        "internaldate": row["internaldate"],
    }
    target_mailboxes = [
        MailboxInfo("[Gmail]/All Mail", "/", ("\\All",)),
        MailboxInfo("[Gmail]/Important", "/", ("\\Important",)),
        MailboxInfo("[Gmail]/Spam", "/", ("\\Junk",)),
    ]
    searched: list[str] = []

    def matching_nums(_imap, mailbox, *_args, **_kwargs):
        searched.append(mailbox)
        return [b"1"] if mailbox == "[Gmail]/Spam" else []

    monkeypatch.setattr(
        provider_ops,
        "target_matching_message_nums",
        matching_nums,
    )
    monkeypatch.setattr(provider_ops, "_target_gmail_msgid", lambda *_args: "901")
    monkeypatch.setattr(
        provider_ops,
        "_target_gmail_label_flag_internaldate",
        lambda *_args: (
            {"important", "spam"},
            {"\\SEEN"},
            "01-Jan-2024 00:00:00 +0000",
        ),
    )
    written: list[dict] = []
    monkeypatch.setattr(
        provider_ops,
        "append_journal",
        lambda _dir, _account, repaired: written.append(repaired),
    )

    repaired = provider_ops.repair_missing_journal_target_gmail_msgids(
        object(),
        tmp_path,
        account,
        [journal_row],
        [row],
        {"important-anchor": "[Gmail]/All Mail"},
        {
            "target_endpoint": {"provider": "gmail"},
            "target_endpoint_sha256": "c" * 64,
        },
        target_mailboxes=target_mailboxes,
    )

    assert "[Gmail]/Spam" in searched
    assert len(written) == 1
    assert written[0]["target_gmail_msgid"] == "901"
    assert written[0]["target_mailbox"] == "[Gmail]/All Mail"
    assert repaired[-1] == written[0]


def test_iterative_target_matching_is_recursive_equivalent_and_handles_deep_chain() -> None:
    rng = random.Random(20260802)
    for size in range(1, 12):
        for _case in range(75):
            candidates = {
                f"row-{row_index:02d}": [
                    {"physical_key": ("candidate", candidate_index)}
                    for candidate_index in range(size)
                    if rng.random() < 0.35
                ]
                for row_index in range(size)
            }
            required = {
                row_key for row_key in candidates if rng.random() < 0.3
            }
            unavailable = {
                ("candidate", candidate_index)
                for candidate_index in range(size)
                if rng.random() < 0.15
            }
            expected = _recursive_candidate_assignment_reference(
                candidates,
                required_row_keys=required,
                unavailable_physical_keys=unavailable,
            )
            actual = provider_ops._maximum_target_candidate_assignments(
                candidates,
                required_row_keys=required,
                unavailable_physical_keys=unavailable,
            )
            assert {
                row_key: candidate["physical_key"]
                for row_key, candidate in actual.items()
            } == {
                row_key: candidate["physical_key"]
                for row_key, candidate in expected.items()
            }

    chain_size = 1_100
    deep_chain = {
        f"row-{row_index:04d}": [
            {"physical_key": ("candidate", candidate_index)}
            for candidate_index in range(
                max(0, row_index - 1),
                min(chain_size, row_index + 1),
            )
        ]
        for row_index in range(chain_size)
    }
    assignments = provider_ops._maximum_target_candidate_assignments(
        deep_chain,
        required_row_keys={"row-1099"},
    )
    assert len(assignments) == chain_size


@pytest.mark.parametrize(
    ("value", "valid"),
    [
        ("1", True),
        (str((1 << 64) - 1), True),
        ("", False),
        ("0", False),
        ("00", False),
        ("01", False),
        ("+1", False),
        ("-1", False),
        (" 1", False),
        ("1 ", False),
        ("١", False),
        (str(1 << 64), False),
        (1, False),
        (0, False),
        (True, False),
        (False, False),
    ],
)
def test_gmail_message_ids_are_canonical_positive_uint64_strings(
    value: object,
    valid: bool,
) -> None:
    assert provider_ops.is_valid_gmail_msgid(value) is valid
    assert provider_ops._valid_gmail_uint64(value) == (value if valid else "")


def test_gmail_id_writer_and_matcher_reject_coercible_noncanonical_values_before_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = _duplicate_routing_row("strict-id", labels=("Imported",))
    row.update(
        {
            "target_account": "target@gmail.com",
            "content_sha256": "a" * 64,
            "rfc822_size": 1,
            CONTENT_BINDING_FIELD: "b" * 64,
        }
    )
    binding = {
        "target_endpoint": {"provider": "gmail"},
        "target_endpoint_sha256": "c" * 64,
    }
    with pytest.raises(RuntimeError, match="invalid canonical Gmail"):
        provider_ops._journal_row(
            row,
            "[Gmail]/All Mail",
            "committed",
            "appended",
            target_binding=binding,
            target_gmail_msgid=1,
        )
    with pytest.raises(RuntimeError, match="invalid pre-APPEND Gmail-ID"):
        provider_ops._journal_row(
            row,
            "[Gmail]/All Mail",
            "pending",
            "append-started",
            target_binding=binding,
            pre_append_gmail_msgids=[1],
        )
    with pytest.raises(RuntimeError, match="invalid pre-APPEND Gmail-ID"):
        provider_ops._journal_row(
            row,
            "[Gmail]/All Mail",
            "pending",
            "append-started",
            target_binding=binding,
            pre_append_gmail_msgids=[""],
        )

    monkeypatch.setattr(
        provider_ops,
        "_target_physical_occurrences_for_row",
        lambda *_args, **_kwargs: pytest.fail(
            "invalid baseline must reject before target matching"
        ),
    )
    for persisted_baseline in (["001"], [""]):
        with pytest.raises(
            provider_ops.ProviderImportIntegrityGateError,
            match="canonical pre-APPEND",
        ):
            provider_ops._target_row_assignments(
                object(),
                [],
                {
                    "strict-id": {
                        "manifest_row": row,
                        "target_mailbox": "[Gmail]/All Mail",
                        "pre_append_gmail_msgids": persisted_baseline,
                        "require_unique_fresh_append": True,
                    }
                },
                target_provider="gmail",
            )


def test_global_pending_gmail_evidence_gate_proves_nested_rows_and_rejects_ambiguity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _duplicate_routing_row("first", labels=("Imported",))
    second = _duplicate_routing_row("second", labels=("Imported",))
    for row in (first, second):
        row["_gmail_duplicate_allocation"] = {
            "systems": ["all"],
            "custom_labels": ["Imported"],
            "target_gmail_msgids": [],
        }
    stage = (
        MigrationAccount("source@example.com", "target@gmail.com"),
        Path("/source@example.com"),
        [first, second],
        [
            {
                "canonical_id": "first",
                "target_mailbox": "[Gmail]/All Mail",
                "status": "pending",
                "pre_append_gmail_msgids": [],
            },
            {
                "canonical_id": "second",
                "target_mailbox": "[Gmail]/All Mail",
                "status": "pending",
                "pre_append_gmail_msgids": ["701"],
            },
        ],
    )
    occurrences = [
        {
            "physical_key": ("gmail", gmail_id),
            "mailbox": "[Gmail]/All Mail",
            "num": str(index).encode("ascii"),
            "gmail_msgid": gmail_id,
            "internaldate": "01-Jan-2024 00:00:00 +0000",
            "gmail_label_keys": {"all"},
            "gmail_flags": set(),
        }
        for index, gmail_id in enumerate(("701", "702"), 1)
    ]
    monkeypatch.setattr(
        provider_ops,
        "translated_target_mailboxes_for_rows",
        lambda rows, *_args, **_kwargs: {
            str(row["canonical_id"]): "[Gmail]/All Mail" for row in rows
        },
    )
    monkeypatch.setattr(
        provider_ops,
        "_target_physical_occurrences_for_row",
        lambda *_args, **_kwargs: occurrences,
    )

    provider_ops.require_pending_gmail_append_evidence_safe(
        object(),
        [],
        [stage],
        expected_content_identities_by_id={},
    )

    stage[3][1]["pre_append_gmail_msgids"] = []
    with pytest.raises(
        provider_ops.ProviderImportIntegrityGateError,
        match="multiple one-to-one post-APPEND physical allocations remain",
    ):
        provider_ops.require_pending_gmail_append_evidence_safe(
            object(),
            [],
            [stage],
            expected_content_identities_by_id={},
        )


def test_global_pending_gmail_evidence_gate_rejects_legacy_neutral_anchor_before_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = _duplicate_routing_row("legacy-neutral", systems=("important",))
    row["_gmail_duplicate_allocation"] = {
        "systems": ["important", "spam"],
        "custom_labels": [],
        "target_gmail_msgids": [],
    }
    stage = (
        MigrationAccount("source@example.com", "target@gmail.com"),
        Path("/source@example.com"),
        [row],
        [
            {
                "canonical_id": "legacy-neutral",
                "target_mailbox": "[Gmail]/All Mail",
                "status": "pending",
            }
        ],
    )
    monkeypatch.setattr(
        provider_ops,
        "translated_target_mailboxes_for_rows",
        lambda *_args, **_kwargs: {
            "legacy-neutral": "[Gmail]/All Mail"
        },
    )
    monkeypatch.setattr(
        provider_ops,
        "_target_physical_occurrences_for_row",
        lambda *_args, **_kwargs: pytest.fail(
            "legacy neutral evidence must reject before target matching"
        ),
    )

    with pytest.raises(
        provider_ops.ProviderImportIntegrityGateError,
        match="predates durable pre-APPEND",
    ):
        provider_ops.require_pending_gmail_append_evidence_safe(
            object(),
            [],
            [stage],
            expected_content_identities_by_id={},
        )


@pytest.mark.parametrize("many_to_one", [False, True])
def test_pending_gmail_ambiguity_preserves_all_torn_journal_bytes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    many_to_one: bool,
) -> None:
    config = _many_to_one_gmail_config(target_mode="merge")
    account, peer_account = config.accounts
    if not many_to_one:
        config.accounts = [account]
        config.migration.account_merge_mode = "one_to_one"
    body = b"Message-ID: <deferred-ambiguous@example.com>\r\n\r\nsame"
    account_dir = _write_provider_account_fixture(
        tmp_path,
        source=account.source_email,
        target=account.target_email,
        canonical_id="pending-a",
        message_id="<deferred-ambiguous@example.com>",
        body=body,
    )
    _append_identical_provider_fixture_row(account_dir, "pending-b")
    manifest_rows = provider_ops.load_manifest(account_dir)
    pending_rows = [
        _journal_fixture_for_manifest_row(
            config,
            manifest_row,
            {
                "canonical_id": manifest_row["canonical_id"],
                "target_account": account.target_email,
                "target_mailbox": "[Gmail]/All Mail",
                "status": "pending",
                "action": "append-started",
                "pre_append_gmail_msgids": [],
            },
            account=account,
        )
        for manifest_row in manifest_rows
    ]
    journal_path = provider_ops._journal_path(account_dir, account)
    journal_path.write_bytes(
        b"".join(
            json.dumps(row).encode("utf-8") + b"\n" for row in pending_rows
        )
        + b'{"incomplete-current":'
    )
    journal_paths = [journal_path]
    if many_to_one:
        peer_dir = _write_provider_account_fixture(
            tmp_path,
            source=peer_account.source_email,
            target=peer_account.target_email,
            canonical_id="peer-distinct",
            message_id="<peer-distinct@example.com>",
            body=b"Message-ID: <peer-distinct@example.com>\r\n\r\npeer",
        )
        peer_journal = provider_ops._journal_path(peer_dir, peer_account)
        peer_journal.write_bytes(b'{"incomplete-peer":')
        journal_paths.append(peer_journal)
    original_journals = {
        path: path.read_bytes() for path in journal_paths
    }
    target = OverlapStoredGmailTarget([body, body])

    monkeypatch.setattr(
        provider_ops,
        "imap_connection",
        lambda *_args, **_kwargs: contextlib.nullcontext(target),
    )

    with pytest.raises(
        provider_ops.ProviderImportIntegrityGateError,
        match="multiple one-to-one post-APPEND physical allocations remain",
    ):
        provider_import_account(config, account, tmp_path)

    assert target.appended == []
    assert target.stored_labels == []
    assert all(
        path.read_bytes() == original_bytes
        for path, original_bytes in original_journals.items()
    )


@pytest.mark.parametrize("many_to_one", [False, True])
def test_successful_pending_gmail_proof_repairs_all_tails_then_resumes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    many_to_one: bool,
) -> None:
    config = _many_to_one_gmail_config(target_mode="merge")
    account, peer_account = config.accounts
    if not many_to_one:
        config.accounts = [account]
        config.migration.account_merge_mode = "one_to_one"
    body = b"Message-ID: <deferred-success@example.com>\r\n\r\nbody"
    account_dir = _write_provider_account_fixture(
        tmp_path,
        source=account.source_email,
        target=account.target_email,
        canonical_id="pending-success",
        message_id="<deferred-success@example.com>",
        body=body,
    )
    manifest_row = provider_ops.load_manifest(account_dir)[0]
    pending_row = _journal_fixture_for_manifest_row(
        config,
        manifest_row,
        {
            "canonical_id": manifest_row["canonical_id"],
            "target_account": account.target_email,
            "target_mailbox": "[Gmail]/All Mail",
            "status": "pending",
            "action": "append-started",
            "pre_append_gmail_msgids": [],
        },
        account=account,
    )
    journal_path = provider_ops._journal_path(account_dir, account)
    journal_path.write_bytes(
        json.dumps(pending_row).encode("utf-8")
        + b"\n"
        + b'{"incomplete-current":'
    )
    peer_journal: Path | None = None
    if many_to_one:
        peer_dir = _write_provider_account_fixture(
            tmp_path,
            source=peer_account.source_email,
            target=peer_account.target_email,
            canonical_id="peer-distinct",
            message_id="<peer-distinct@example.com>",
            body=b"Message-ID: <peer-distinct@example.com>\r\n\r\npeer",
        )
        peer_journal = provider_ops._journal_path(peer_dir, peer_account)
        peer_journal.write_bytes(b'{"incomplete-peer":')
    target = OverlapStoredGmailTarget([body])

    monkeypatch.setattr(
        provider_ops,
        "imap_connection",
        lambda *_args, **_kwargs: contextlib.nullcontext(target),
    )

    provider_import_account(config, account, tmp_path)

    journal_rows = provider_ops.load_import_journal(account_dir, account)
    assert [row["status"] for row in journal_rows] == ["pending", "committed"]
    assert journal_rows[-1]["target_gmail_msgid"] == "9001"
    assert target.appended == []
    assert b"incomplete-current" not in journal_path.read_bytes()
    if peer_journal is not None:
        assert peer_journal.read_bytes() == b""


def test_recovery_uses_global_cross_stage_nested_baseline_assignment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    accounts = [
        MigrationAccount("a@example.com", "target@gmail.com"),
        MigrationAccount("b@example.com", "target@gmail.com"),
    ]
    rows = [
        {
            "canonical_id": "a-row",
            "primary_mailbox": "Archive",
            "internaldate": "01-Jan-2024 00:00:00 +0000",
            "target_account": "target@gmail.com",
            "flags": "",
        },
        {
            "canonical_id": "b-row",
            "primary_mailbox": "Archive",
            "internaldate": "01-Jan-2024 00:00:00 +0000",
            "target_account": "target@gmail.com",
            "flags": "",
        },
    ]
    stages = [
        (
            accounts[0],
            Path("/a@example.com"),
            [rows[0]],
            [
                {
                    "canonical_id": "a-row",
                    "target_mailbox": "[Gmail]/All Mail",
                    "status": "pending",
                    "pre_append_gmail_msgids": [],
                }
            ],
        ),
        (
            accounts[1],
            Path("/b@example.com"),
            [rows[1]],
            [
                {
                    "canonical_id": "b-row",
                    "target_mailbox": "[Gmail]/All Mail",
                    "status": "pending",
                    "pre_append_gmail_msgids": ["601"],
                }
            ],
        ),
    ]
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="source.example.com",
            auth=AuthConfig(method="password", password="source-secret"),
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", password="target-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=accounts,
        migration=MigrationSettings(
            target_mode="merge",
            account_merge_mode="many_to_one",
        ),
    )
    occurrences = [
        {
            "physical_key": ("gmail", gmail_id),
            "mailbox": "[Gmail]/All Mail",
            "num": str(index).encode("ascii"),
            "gmail_msgid": gmail_id,
            "internaldate": "01-Jan-2024 00:00:00 +0000",
            "gmail_label_keys": {"all"},
            "gmail_flags": set(),
        }
        for index, gmail_id in enumerate(("601", "602"), 1)
    ]
    monkeypatch.setattr(
        provider_ops,
        "translated_target_mailboxes_for_rows",
        lambda manifest_rows, *_args, **_kwargs: {
            str(row["canonical_id"]): "[Gmail]/All Mail"
            for row in manifest_rows
        },
    )
    monkeypatch.setattr(
        provider_ops,
        "_target_physical_occurrences_for_row",
        lambda *_args, **_kwargs: occurrences,
    )
    content_class = {
        "capacity": 2,
        "entries": [
            {
                "source_email": account.source_email,
                "identity": row["canonical_id"],
            }
            for account, row in zip(accounts, rows)
        ],
    }
    monkeypatch.setattr(
        provider_ops,
        "require_merge_group_pending_internaldates_compatible",
        lambda *_args, **_kwargs: [content_class],
    )
    monkeypatch.setattr(
        provider_ops,
        "pending_journal_target_mailbox_issues",
        lambda *_args, **_kwargs: [],
    )
    monkeypatch.setattr(provider_ops, "subscribe_mailbox", lambda *_args: None)
    monkeypatch.setattr(
        provider_ops,
        "restore_gmail_labels",
        lambda *_args, **_kwargs: [],
    )
    monkeypatch.setattr(
        provider_ops,
        "restore_gmail_starred_flag",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        provider_ops,
        "restore_imap_flags",
        lambda *_args, **_kwargs: None,
    )
    committed: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        provider_ops,
        "append_journal",
        lambda _dir, account, journal_row: committed.append(
            (account.source_email, journal_row)
        ),
    )

    provider_ops.recover_merge_group_pending_appends(
        config,
        object(),
        [],
        stages,
        expected_content_identities_by_id={},
        limiter=provider_ops.RateLimiter(0),
    )

    assert [
        (source, row["canonical_id"], row["target_gmail_msgid"])
        for source, row in committed
    ] == [
        ("a@example.com", "a-row", "601"),
        ("b@example.com", "b-row", "602"),
    ]


def test_cross_source_strong_duplicates_with_different_dates_do_not_false_conflict() -> None:
    content_identity = (123, "d" * 64)
    draft = _duplicate_routing_row(
        "draft",
        primary_mailbox="Drafts",
        systems=("drafts",),
        internaldate="01-Jan-2024 00:00:00 +0000",
    )
    custom = _duplicate_routing_row(
        "custom",
        labels=("Review",),
        internaldate="02-Jan-2024 00:00:00 +0000",
    )

    classes = provider_ops.require_merge_group_gmail_destination_allocations_compatible(
        [
            _duplicate_stage("a@example.com", [draft]),
            _duplicate_stage("b@example.com", [custom]),
        ],
        expected_content_identities_by_id={
            "draft": {content_identity},
            "custom": {content_identity},
        },
    )

    assert len(classes) == 2


def test_cross_source_duplicate_gate_honors_pending_and_committed_physical_evidence() -> None:
    content_identity = (123, "e" * 64)
    draft = _duplicate_routing_row(
        "draft",
        primary_mailbox="Drafts",
        systems=("drafts",),
    )
    custom = _duplicate_routing_row("custom", labels=("Review",))
    pending = [{"canonical_id": "draft", "status": "pending"}]
    committed_draft = [
        {
            "canonical_id": "draft",
            "status": "committed",
            "action": "appended",
            "target_gmail_msgid": "123",
        }
    ]
    committed_custom = [
        {
            "canonical_id": "custom",
            "status": "committed",
            "action": "existing",
            "target_gmail_msgid": "123",
        }
    ]

    with pytest.raises(provider_ops.ProviderImportIntegrityGateError):
        provider_ops.require_merge_group_gmail_destination_allocations_compatible(
            [
                _duplicate_stage("a@example.com", [draft], pending),
                _duplicate_stage("b@example.com", [custom]),
            ],
            expected_content_identities_by_id={
                "draft": {content_identity},
                "custom": {content_identity},
            },
        )

    with pytest.raises(
        provider_ops.ProviderImportIntegrityGateError,
        match="committed Gmail physical ID 123",
    ):
        provider_ops.require_merge_group_gmail_destination_allocations_compatible(
            [
                _duplicate_stage("a@example.com", [draft], committed_draft),
                _duplicate_stage("b@example.com", [custom], committed_custom),
            ],
            expected_content_identities_by_id={
                "draft": {content_identity},
                "custom": {content_identity},
            },
        )


def test_cross_source_duplicate_gate_precedes_target_connection_and_journal_repair(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    routing = RoutingConfig.from_dict(
        {
            "enabled": True,
            "global_rules": [
                {
                    "match": {"folder": "DraftA"},
                    "destinations": [{"type": GMAIL_SYSTEM, "name": "drafts"}],
                },
                {
                    "match": {"folder": "CustomB"},
                    "destinations": [{"type": CUSTOM_LABEL, "name": "Review"}],
                },
            ],
        }
    )
    accounts = [
        MigrationAccount("a@example.com", "target@gmail.com"),
        MigrationAccount("b@example.com", "target@gmail.com"),
    ]
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="source.example.com",
            auth=AuthConfig(method="password", password="source-secret"),
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", password="target-token"),
            gmail_full_visibility_verified=True,
        ),
        accounts=accounts,
        migration=MigrationSettings(
            target_mode="merge",
            account_merge_mode="many_to_one",
            routing=routing,
        ),
    )
    plan = resolve_routing_plan(
        routing,
        [
            SourceFolder("a@example.com", "DraftA"),
            SourceFolder("b@example.com", "CustomB"),
        ],
        [TargetLabel("[Gmail]/Drafts", GMAIL_SYSTEM, system_role="drafts")],
    )
    body = b"Message-ID: <same@example.com>\r\n\r\nbody"
    rows = {
        "a@example.com": {
            **_manifest_row("a-row"),
            "source_mailboxes": ["DraftA"],
            "primary_mailbox": "DraftA",
            "internaldate": "01-Jan-2024 00:00:00 +0000",
            "eml_path": "messages/a.eml",
        },
        "b@example.com": {
            **_manifest_row("b-row"),
            "source_mailboxes": ["CustomB"],
            "primary_mailbox": "CustomB",
            "internaldate": "01-Jan-2024 00:00:00 +0000",
            "eml_path": "messages/b.eml",
        },
    }
    account_dirs = {
        account.source_email: provider_ops.account_export_dir(tmp_path, account)
        for account in accounts
    }
    for account in accounts:
        account_dir = account_dirs[account.source_email]
        (account_dir / "messages").mkdir(parents=True)
        if account is accounts[0]:
            (account_dir / "messages" / "a.eml").write_bytes(body)
        journal_path = provider_ops._journal_path(account_dir, account)
        journal_path.write_bytes(b'{"incomplete":')

    monkeypatch.setattr(
        provider_ops,
        "_effective_provider_routing_plan",
        lambda *_args, **_kwargs: plan,
    )
    monkeypatch.setattr(
        provider_ops,
        "load_manifest",
        lambda account_dir: [
            rows[
                next(
                    source
                    for source, expected_dir in account_dirs.items()
                    if expected_dir == account_dir
                )
            ]
        ],
    )
    for name in (
        "require_manifest_schema",
        "require_unique_manifest_identities",
        "require_manifest_accounts",
        "require_manifest_source_provider",
        "require_manifest_integrity_metadata",
        "require_provider_delivery_metadata",
        "require_complete_export_state",
        "require_manifest_payload_matches",
        "require_valid_import_journal",
    ):
        monkeypatch.setattr(provider_ops, name, lambda *_args, **_kwargs: None)
    for name in (
        "metadata_manifest_issues",
        "manifest_payload_issues",
        "_provider_artifact_orphan_issues",
        "provider_mixed_legacy_layout_issues",
        "journal_target_endpoint_issues",
        "committed_journal_manifest_content_issues",
        "pending_journal_manifest_content_issues",
        "offline_journal_target_mailbox_issues",
        "invalid_journal_target_gmail_msgid_issues",
        "missing_journal_target_gmail_msgid_issues",
        "duplicate_journal_target_gmail_msgid_issues",
    ):
        monkeypatch.setattr(provider_ops, name, lambda *_args, **_kwargs: [])
    content_identities = provider_ops.provider_payload_content_identities(body)
    monkeypatch.setattr(
        provider_ops,
        "merge_group_payload_content_identities",
        lambda _stages: {
            "a-row": content_identities,
            "b-row": content_identities,
        },
    )

    def unexpected_connection(*_args, **_kwargs):
        raise AssertionError("target connection must not open before duplicate gate")

    monkeypatch.setattr(provider_ops, "imap_connection", unexpected_connection)
    journal_bytes_before = {
        account.source_email: provider_ops._journal_path(
            account_dirs[account.source_email],
            account,
        ).read_bytes()
        for account in accounts
    }

    with pytest.raises(
        provider_ops.ProviderImportIntegrityGateError,
        match="incompatible Gmail destinations",
    ):
        provider_import_account(config, accounts[0], tmp_path, routing_plan=plan)

    for account in accounts:
        assert provider_ops._journal_path(
            account_dirs[account.source_email],
            account,
        ).read_bytes() == journal_bytes_before[account.source_email]

def test_two_routed_accounts_union_custom_labels_on_one_strong_duplicate(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    routing = RoutingConfig.from_dict(
        {
            "enabled": True,
            "accounts": {
                "mailb@example.com": {"default_label": "MailB"},
                "mailc@example.com": {"default_label": "MailC"},
            },
        }
    )
    accounts = [
        MigrationAccount("mailb@example.com", "target@gmail.com"),
        MigrationAccount("mailc@example.com", "target@gmail.com"),
    ]
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="mail.source.example.com",
            auth=AuthConfig(method="password", password="source-secret"),
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(
                method="xoauth2",
                username="target@gmail.com",
                password="target-token",
            ),
            gmail_full_visibility_verified=True,
        ),
        accounts=accounts,
        migration=MigrationSettings(
            target_mode="merge",
            account_merge_mode="many_to_one",
            routing=routing,
        ),
    )
    plan = resolve_routing_plan(
        routing,
        [
            SourceFolder("mailb@example.com", "INBOX", attributes=("\\Inbox",)),
            SourceFolder("mailc@example.com", "INBOX", attributes=("\\Inbox",)),
        ],
        [],
    )
    save_provider_routing_plan(tmp_path, plan)
    body = b"Message-ID: <m1@example.com>\r\n\r\nbody"
    for index, account in enumerate(accounts, 1):
        account_dir = _write_provider_account_fixture(
            tmp_path,
            source=account.source_email,
            target=account.target_email,
            canonical_id=f"source-{index}",
            message_id="<m1@example.com>",
            body=body,
            source_provider="imap",
            source_host=config.source.host,
            primary_mailbox="INBOX",
        )
        row = json.loads((account_dir / "manifest.jsonl").read_text(encoding="utf-8"))
        row["source_mailboxes"] = ["INBOX"]
        row["source_mailbox_paths"] = {"INBOX": ["INBOX"]}
        row["source_mailbox_attributes"] = {"INBOX": ["\\Inbox"]}
        _write_single_manifest_row(account_dir, row)
        _write_provider_export_state(
            account_dir,
            source=account.source_email,
            target=account.target_email,
            source_endpoint=config.source,
            source_username=account.source_email,
            target_endpoint=config.target,
            target_username=account.target_email,
        )
        state_path = account_dir / "export-state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["routing_plan_sha256"] = plan.mapping_digest
        state_path.write_text(json.dumps(state), encoding="utf-8")

    fake = FakeGmailTargetImap(
        has_existing=False,
        existing_message_id="<m1@example.com>",
        existing_body=body,
        existing_mailbox="[Gmail]/All Mail",
        gmail_labels=["Unrelated", "MailC"],
    )

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs):
        yield fake

    monkeypatch.setattr(provider_ops, "imap_connection", fake_target_connection)

    provider_ops.provider_import_all(
        config,
        tmp_path,
        max_workers=1,
        ignore_errors=False,
        routing_plan=plan,
    )
    first_label_stores = [
        item for item in fake.stored_labels if item[1] == "+X-GM-LABELS"
    ]

    assert fake.appended == ["[Gmail]/All Mail"]
    assert set(fake.gmail_labels) == {"Unrelated", "MailB", "MailC"}
    assert len(first_label_stores) == 1
    assert any('"MailB"' in value for _num, _command, value in first_label_stores)
    assert not any('"MailC"' in value for _num, _command, value in first_label_stores)
    first_journal = provider_ops.load_import_journal(
        provider_ops.account_export_dir(tmp_path, accounts[0]),
        accounts[0],
    )
    second_journal = provider_ops.load_import_journal(
        provider_ops.account_export_dir(tmp_path, accounts[1]),
        accounts[1],
    )
    assert first_journal[-1]["label_membership_verified"] is True
    assert second_journal[-1]["label_membership_verified"] is True
    assert second_journal[-1]["action"] == "existing"
    assert second_journal[-1]["labels_applied"] == []

    provider_ops.provider_import_all(
        config,
        tmp_path,
        max_workers=1,
        ignore_errors=False,
        routing_plan=plan,
    )
    rerun_label_stores = [
        item for item in fake.stored_labels if item[1] == "+X-GM-LABELS"
    ]

    assert fake.appended == ["[Gmail]/All Mail"]
    assert rerun_label_stores == first_label_stores
    assert set(fake.gmail_labels) == {"Unrelated", "MailB", "MailC"}

    report = build_provider_routing_report(config, tmp_path, routing_plan=plan)

    assert report["ok"] is True
    assert "_gmail_duplicate_allocation" not in json.dumps(report)
    assert report["totals"]["appended_source_records"] == 1
    assert report["totals"]["imported_source_records"] == 1
    assert report["totals"]["matched_existing_source_records"] == 1
    assert report["totals"]["appended_gmail_physical_messages"] == 1
    assert len(report["totals"]["appended_gmail_physical_message_ids"]) == 1
    assert report["totals"]["gmail_physical_messages"] == 1
    assert report["totals"]["gmail_physical_message_merges"] == 1
    assert len(report["gmail_physical_messages"]) == 1
    physical_record = report["gmail_physical_messages"][0]
    assert physical_record["target_gmail_msgid"] == report["totals"][
        "appended_gmail_physical_message_ids"
    ][0]
    assert physical_record["source_accounts"] == [
        "mailb@example.com",
        "mailc@example.com",
    ]
    assert physical_record["appended_source_records"] == 1
    assert physical_record["matched_existing_source_records"] == 1
    assert physical_record["required_custom_labels"] == ["MailB", "MailC"]
    assert physical_record["labels_applied"] == ["MailB"]
    assert [
        (item["source_account"], item["canonical_id"], item["origin_action"])
        for item in physical_record["contributors"]
    ] == [
        ("mailb@example.com", "source-1", "appended"),
        ("mailc@example.com", "source-2", "existing"),
    ]
    accounts_by_source = {
        item["source_account"]: item for item in report["accounts"]
    }
    assert accounts_by_source["mailb@example.com"]["appended_source_records"] == 1
    assert accounts_by_source["mailb@example.com"]["imported_source_records"] == 1
    assert (
        accounts_by_source["mailc@example.com"]["matched_existing_source_records"]
        == 1
    )
    assert accounts_by_source["mailb@example.com"]["folders"][0][
        "appended_source_records"
    ] == 1
    assert accounts_by_source["mailc@example.com"]["folders"][0][
        "matched_existing_source_records"
    ] == 1
    mailc_commit = accounts_by_source["mailc@example.com"]["committed_records"][0]
    assert mailc_commit["origin_action"] == "existing"
    assert mailc_commit["target_gmail_msgid"] == physical_record[
        "target_gmail_msgid"
    ]
    assert mailc_commit["labels_applied"] == []
    assert build_provider_routing_report(
        config,
        tmp_path,
        routing_plan=plan,
    ) == report
