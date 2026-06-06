from __future__ import annotations

import contextlib
import hashlib
import json
from pathlib import Path
from typing import Iterator, List, Optional
from unittest import mock

import pytest

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
    build_xoauth2_payload,
    effective_auth,
    fetch_all_uids_and_uidvalidity,
    gmail_labels_for_restore,
    list_mailboxes,
    load_import_journal,
    parse_list_line,
    parse_provider_fetch_response,
    provider_audit_account,
    provider_export_account,
    provider_import_account,
    provider_manifest_digest,
    provider_preflight,
    provider_validate_account,
    quote_mailbox_name,
    resolve_secret,
    resolve_primary_mailbox,
    resolve_target_mailbox,
    restore_gmail_labels,
    restore_gmail_starred_flag,
    target_has_message,
    translate_source_mailbox_for_target,
    xoauth2_authenticator,
)
from components.utils import encode_imap_utf7


def _provider_config(*, target_mode: str = "empty") -> ProviderMigrationConfig:
    return ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="source@example.com", password="token"),
        ),
        target=ProviderEndpoint(
            provider="icloud",
            host="imap.mail.me.com",
            auth=AuthConfig(method="app_password", username="target", password="secret"),
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@icloud.com")],
        migration=MigrationSettings(target_mode=target_mode),
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

    icloud_xoauth = tmp_path / "icloud-xoauth.json"
    icloud_xoauth.write_text(json.dumps({
        "source": {"provider": "gmail", "host": "imap.gmail.com", "auth": {"method": "xoauth2", "password": "x"}},
        "target": {"provider": "icloud", "host": "imap.mail.me.com", "auth": {"method": "xoauth2", "password": "x"}},
        "accounts": [{"source_email": "source@example.com", "target_email": "target@icloud.com"}],
    }))
    with pytest.raises(ValueError, match="target.auth.method"):
        load_config_file(icloud_xoauth)

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
            "target": {"provider": "icloud", "host": "imap.mail.me.com", "auth": {"method": "app_password", "username": "icloud-login", "password": "icloud-secret"}},
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
            "auth": {"method": "app_password", "username": "icloud-user", "password": "icloud-secret"},
        },
        "accounts": [{"source_email": "user@example.com", "target_email": "user@icloud.com"}],
    }))

    parsed = load_config_file(path)

    assert isinstance(parsed, ProviderMigrationConfig)
    assert parsed.source.provider == "imap"
    assert parsed.target.provider == "icloud"


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
    assert literal_label["rfc822_size"] == 35


def test_list_parser_accepts_literal_mailbox_names() -> None:
    class LiteralListImap:
        def list(self):
            return "OK", [(b'(\\HasNoChildren) "/" {13}', encode_imap_utf7("Föld & Team").encode("ascii"))]

    mailboxes = list_mailboxes(LiteralListImap())

    assert len(mailboxes) == 1
    assert mailboxes[0].name == "Föld & Team"


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
            b'(\\HasNoChildren) "/" "[Gmail]/All Mail"',
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
            meta = b'1 (UID 1 RFC822.SIZE 42 FLAGS (\\Seen) INTERNALDATE "01-Jan-2024 00:00:00 +0000")'
            if "BODY.PEEK[]" not in query:
                return "OK", [meta]
            return "OK", [(meta + b" BODY[] {42}", b"Message-ID: <copy@example.com>\r\n\r\nsame body")]
        raise AssertionError(command)

    def logout(self):
        return "OK", []


class FakeGenericVirtualViewsSourceImap(FakeNonGmailDuplicateSourceImap):
    def list(self):
        return "OK", [
            b'(\\HasNoChildren) "/" "INBOX"',
            b'(\\HasNoChildren \\All) "/" "All Mail"',
            b'(\\HasNoChildren \\Flagged) "/" "Flagged"',
        ]

    def uid(self, command: str, *args):
        if self.selected in {"All Mail", "Flagged"}:
            raise AssertionError(f"virtual mailbox should be skipped: {self.selected}")
        return super().uid(command, *args)


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


@pytest.mark.parametrize(
    ("fake_cls", "needle"),
    [
        (FakeGmailSourceNoExtensions, "X-GM-EXT-1"),
        (FakeGmailSourceNoAllMail, "All Mail"),
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


def test_provider_export_skips_generic_virtual_all_and_flagged_views(tmp_path: Path) -> None:
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
        existing_mailbox: str = "Archive",
        messages_by_mailbox: Optional[dict[str, int]] = None,
    ) -> None:
        self.appended: List[str] = []
        self.has_existing = has_existing
        self.existing_message_id = existing_message_id
        self.existing_mailbox = existing_mailbox
        self.messages = 0
        self.messages_by_mailbox = dict(messages_by_mailbox or {})
        self.selected_mailbox = ""
        self.fetch_queries: List[str] = []
        self.search_queries: List[tuple] = []
        self.select_readonly: List[bool] = []

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

    def append(self, mailbox: str, flags: str, date_time: str, data: bytes):
        target = self._normalize_mailbox(mailbox)
        self.appended.append(target)
        self.messages_by_mailbox[target] = self._message_count(target) + 1
        self.messages += 1
        self.has_existing = True
        self.existing_mailbox = target
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
        return "OK", [(b"99 (RFC822.SIZE 36 BODY[] {36}", b"Message-ID: <m1@example.com>\r\n\r\nbody")]

    def logout(self):
        return "OK", []


class FakeGmailTargetImap(FakeTargetImap):
    def __init__(self, **kwargs) -> None:
        self.gmail_labels = list(kwargs.pop("gmail_labels", []))
        self.gmail_flags = str(kwargs.pop("gmail_flags", ""))
        super().__init__(**kwargs)
        self.stored_labels: List[tuple[bytes, str, str]] = []

    def list(self):
        return "OK", [
            b'(\\HasNoChildren) "/" "INBOX"',
            b'(\\HasNoChildren \\All) "/" "[Gmail]/All Mail"',
            b'(\\HasNoChildren \\Sent) "/" "[Gmail]/Sent Mail"',
        ]

    def store(self, num: bytes, command: str, labels: str):
        self.stored_labels.append((num, command, labels))
        return "OK", [b""]

    def fetch(self, num: bytes, query: str):
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


class StoredMessageTarget(FakeTargetImap):
    def __init__(self, bodies_by_mailbox: Optional[dict[str, List[bytes]]] = None) -> None:
        super().__init__(has_existing=False, messages_by_mailbox={})
        self.bodies_by_mailbox = {
            mailbox: list(bodies)
            for mailbox, bodies in (bodies_by_mailbox or {}).items()
        }

    def _message_count(self, mailbox: str) -> int:
        return len(self.bodies_by_mailbox.get(mailbox, []))

    def create(self, mailbox: str):
        self.bodies_by_mailbox.setdefault(self._normalize_mailbox(mailbox), [])
        return "OK", [b""]

    def append(self, mailbox: str, flags: str, date_time: str, data: bytes):
        target = self._normalize_mailbox(mailbox)
        self.appended.append(target)
        self.bodies_by_mailbox.setdefault(target, []).append(bytes(data))
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
        return "OK", [(num + f" (RFC822.SIZE {len(body)} BODY[] {{{len(body)}}}".encode("ascii"), body)]


def _write_manifest_fixture(root: Path) -> Path:
    account_dir = root / "source@example.com"
    (account_dir / "messages").mkdir(parents=True)
    (account_dir / "metadata").mkdir()
    eml = account_dir / "messages" / "gmail-123.eml"
    eml.write_bytes(b"Message-ID: <m1@example.com>\r\n\r\nbody")
    row = {
        "canonical_id": "gmail-123",
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
    (account_dir / "metadata" / "gmail-123.json").write_text(json.dumps(row))
    (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")
    _write_provider_export_state(account_dir)
    return account_dir


def _write_provider_export_state(
    account_dir: Path,
    *,
    source: str = "source@example.com",
    target: str = "target@icloud.com",
    canonical_messages: Optional[int] = None,
    complete: bool = True,
) -> None:
    manifest_rows = [
        json.loads(line)
        for line in account_dir.joinpath("manifest.jsonl").read_text().splitlines()
        if line.strip()
    ]
    account_dir.joinpath("export-state.json").write_text(json.dumps({
        "source_account": source,
        "target_account": target,
        "complete": complete,
        "canonical_messages": len(manifest_rows) if canonical_messages is None else canonical_messages,
        "manifest_sha256": provider_manifest_digest(manifest_rows),
    }))


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
    row["target_account"] = "target@example.com"
    row["primary_mailbox"] = "INBOX"
    (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")
    _write_provider_export_state(account_dir, target="target@example.com")
    fake = FakeTargetImap()

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        provider_import_account(config, account, tmp_path)

    assert fake.appended == ["INBOX"]


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
    row["target_account"] = "target@example.com"
    row["primary_mailbox"] = "Projects/2024"
    row["source_mailboxes"] = ["Projects/2024"]
    row["source_mailbox_delimiters"] = {"Projects/2024": "/"}
    row["source_mailbox_paths"] = {"Projects/2024": ["Projects", "2024"]}
    (account_dir / "metadata" / "gmail-123.json").write_text(json.dumps(row))
    (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")
    _write_provider_export_state(account_dir, target="target@example.com")
    fake = DotDelimiterTarget()

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[DotDelimiterTarget]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        provider_import_account(config, account, tmp_path)

    assert fake.appended == ["Projects.2024"]


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
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    first = json.loads((account_dir / "manifest.jsonl").read_text())
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
    (account_dir / "messages" / "first.eml").write_bytes(body)
    (account_dir / "messages" / "second.eml").write_bytes(body)
    (account_dir / "metadata" / "first.json").write_text(json.dumps(first))
    (account_dir / "metadata" / "second.json").write_text(json.dumps(second))
    (account_dir / "manifest.jsonl").write_text(json.dumps(first) + "\n" + json.dumps(second) + "\n")
    _write_provider_export_state(account_dir, target="target@example.com", canonical_messages=2)
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
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["target_account"] = "target@gmail.com"
    row["primary_mailbox"] = "Archive"
    (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")
    _write_provider_export_state(account_dir, target="target@gmail.com")
    fake = FakeGmailTargetImap()

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeGmailTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        provider_import_account(config, account, tmp_path)

    assert fake.appended == ["[Gmail]/All Mail"]


def test_gmail_label_restore_filters_system_labels() -> None:
    row = {
        "gmail_labels": ["\\Inbox", "\\AllMail", "Project A", "[Gmail]/All Mail", "Team Blue", "\\Important", "Important", "Starred", "Project A"],
    }

    assert gmail_labels_for_restore(row, "INBOX") == ["Important", "Project A", "Team Blue"]


def test_provider_import_to_gmail_restores_custom_labels(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="source@gmail.com", password="gmail-token"),
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
            auth=AuthConfig(method="xoauth2", username="source@gmail.com", password="gmail-token"),
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


def test_provider_import_to_gmail_restores_starred_as_flag_not_plain_label(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="source@gmail.com", password="gmail-token"),
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
    row["target_account"] = "target@gmail.com"
    row["primary_mailbox"] = "INBOX"
    row["gmail_labels"] = ["\\Inbox", "\\Starred", "Starred", "Project A"]
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
    (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")
    _write_provider_export_state(account_dir)
    fake = FakeTargetImap()

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        with pytest.raises(RuntimeError, match="unsafe eml_path"):
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
    (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")
    with mock.patch("components.provider_ops.imap_connection", side_effect=AssertionError("target should not be contacted")):
        with pytest.raises(RuntimeError, match="export-state manifest_sha256"):
            provider_import_account(config, account, tmp_path)


def test_provider_import_rejects_corrupt_staged_payload_before_append(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    (account_dir / "messages" / "gmail-123.eml").write_bytes(b"Message-ID: <m1@example.com>\r\n\r\ncorrupted")
    fake = FakeTargetImap()

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        with pytest.raises(RuntimeError, match="content_sha256 mismatch|rfc822_size mismatch"):
            provider_import_account(config, account, tmp_path)

    assert fake.appended == []
    journal = account_dir / "import-target@icloud.com.journal.jsonl"
    assert not journal.exists()


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
    (account_dir / "import-target@icloud.com.journal.jsonl").write_text(json.dumps({
        "canonical_id": "gmail-123",
        "target_account": "target@icloud.com",
        "target_mailbox": "Archive",
        "status": "committed",
    }) + "\n")
    fake = StoredMessageTarget({"Archive": [(account_dir / "messages" / "gmail-123.eml").read_bytes()]})

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[StoredMessageTarget]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        provider_import_account(config, account, tmp_path)

    assert fake.appended == ["Archive"]


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
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["target_account"] = "target@gmail.com"
    row["primary_mailbox"] = "Archive"
    (account_dir / "metadata" / "gmail-123.json").write_text(json.dumps(row))
    (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")
    _write_provider_export_state(account_dir, target="target@gmail.com")
    (account_dir / "import-target@gmail.com.journal.jsonl").write_text(json.dumps({
        "canonical_id": "gmail-123",
        "target_account": "target@gmail.com",
        "target_mailbox": "[Gmail]/All Mail",
        "status": "committed",
    }) + "\n")
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
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["target_account"] = "target@gmail.com"
    row["primary_mailbox"] = "INBOX"
    row["flags"] = "\\Seen \\Flagged"
    (account_dir / "metadata" / "gmail-123.json").write_text(json.dumps(row))
    (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")
    _write_provider_export_state(account_dir, target="target@gmail.com")
    (account_dir / "import-target@gmail.com.journal.jsonl").write_text(json.dumps({
        "canonical_id": "gmail-123",
        "target_account": "target@gmail.com",
        "target_mailbox": "INBOX",
        "status": "committed",
    }) + "\n")
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
        ),
        accounts=[MigrationAccount(source_email="source@example.com", target_email="target@gmail.com")],
        migration=MigrationSettings(target_mode="empty"),
    )
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["target_account"] = "target@gmail.com"
    row["primary_mailbox"] = "INBOX"
    row["gmail_labels"] = ["Important"]
    (account_dir / "metadata" / "gmail-123.json").write_text(json.dumps(row))
    (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")
    _write_provider_export_state(account_dir, target="target@gmail.com")
    (account_dir / "import-target@gmail.com.journal.jsonl").write_text(json.dumps({
        "canonical_id": "gmail-123",
        "target_account": "target@gmail.com",
        "target_mailbox": "INBOX",
        "status": "committed",
    }) + "\n")
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
    (account_dir / "import-target@icloud.com.journal.jsonl").write_text(json.dumps({
        "canonical_id": "gmail-123",
        "target_account": "target@icloud.com",
        "target_mailbox": "Archive",
        "status": "pending",
    }) + "\n")
    fake = FakeTargetImap(has_existing=False)
    fake.messages = 1

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        with pytest.raises(RuntimeError, match="target_mode=empty"):
            provider_import_account(config, account, tmp_path)


def test_provider_import_rejects_committed_journal_missing_target_message(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    (account_dir / "import-target@icloud.com.journal.jsonl").write_text(json.dumps({
        "canonical_id": "gmail-123",
        "target_account": "target@icloud.com",
        "target_mailbox": "Archive",
        "status": "committed",
    }) + "\n")
    fake = FakeTargetImap(has_existing=False)

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        with pytest.raises(RuntimeError, match="journal says gmail-123 is committed"):
            provider_import_account(config, account, tmp_path)


def test_provider_validation_is_manifest_exact(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    _name, report = provider_validate_account(config, account, tmp_path)
    assert not report["ok"]
    assert report["missing"] == ["gmail-123"]

    (account_dir / "import-target@icloud.com.journal.jsonl").write_text(json.dumps({
        "canonical_id": "gmail-123",
        "target_account": "target@icloud.com",
        "target_mailbox": "Archive",
        "status": "committed",
    }) + "\n")
    _name, report = provider_validate_account(config, account, tmp_path)
    assert report["ok"]
    assert report["committed"] == 1


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


def test_provider_validation_rejects_incomplete_export_state(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    (account_dir / "export-state.json").write_text(json.dumps({"complete": False}))

    _name, report = provider_validate_account(config, account, tmp_path)

    assert not report["ok"]
    assert any("export-state is not complete" in item for item in report["failed"])


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


def test_provider_import_and_validation_reject_journal_target_account_mismatch(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    (account_dir / "import-target@icloud.com.journal.jsonl").write_text(json.dumps({
        "canonical_id": "gmail-123",
        "target_account": "other@icloud.com",
        "target_mailbox": "Archive",
        "status": "committed",
    }) + "\n")

    with pytest.raises(RuntimeError, match="invalid import journal"):
        provider_import_account(config, account, tmp_path)

    _name, report = provider_validate_account(config, account, tmp_path)
    assert not report["ok"]
    assert any("journal gmail-123 target_account" in item for item in report["failed"])


def test_provider_validation_rejects_journal_missing_target_mailbox(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    (account_dir / "import-target@icloud.com.journal.jsonl").write_text(json.dumps({
        "canonical_id": "gmail-123",
        "target_account": "target@icloud.com",
        "status": "committed",
    }) + "\n")

    _name, report = provider_validate_account(config, account, tmp_path)

    assert not report["ok"]
    assert any("missing target_mailbox" in item for item in report["failed"])


def test_provider_validation_rejects_unresolved_pending_journal_row(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    (account_dir / "import-target@icloud.com.journal.jsonl").write_text(json.dumps({
        "canonical_id": "gmail-123",
        "target_account": "target@icloud.com",
        "target_mailbox": "Archive",
        "status": "pending",
    }) + "\n")

    _name, report = provider_validate_account(config, account, tmp_path)

    assert not report["ok"]
    assert any("pending identity has no committed resolution" in item for item in report["failed"])


def test_provider_validation_rejects_wrong_target_mailbox_commit(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    (account_dir / "import-target@icloud.com.journal.jsonl").write_text(json.dumps({
        "canonical_id": "gmail-123",
        "target_account": "target@icloud.com",
        "target_mailbox": "INBOX",
        "status": "committed",
    }) + "\n")
    fake = FakeTargetImap()

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        _name, report = provider_validate_account(config, account, tmp_path, check_target=True)

    assert not report["ok"]
    assert report["missing"] == ["gmail-123"]
    assert any("wrong target mailbox" in item for item in report["failed"])


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
        json.dumps({
            "canonical_id": "first",
            "target_account": "target@example.com",
            "target_mailbox": "A/B/C",
            "status": "committed",
        }) + "\n" + json.dumps({
            "canonical_id": "second",
            "target_account": "target@example.com",
            "target_mailbox": "A/B/C",
            "status": "committed",
        }) + "\n"
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
        json.dumps({
            "canonical_id": "gmail-123",
            "target_account": "target@icloud.com",
            "target_mailbox": "Archive",
            "status": "committed",
        }) + "\n" + json.dumps({
            "canonical_id": "physical-duplicate",
            "target_account": "target@icloud.com",
            "target_mailbox": "Archive",
            "status": "committed",
        }) + "\n"
    )
    fake = FakeTargetImap(has_existing=True)

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        _name, report = provider_validate_account(config, account, tmp_path, check_target=True)

    assert not report["ok"]
    assert report["remote_missing"] == ["physical-duplicate"]


def test_provider_validation_checks_gmail_target_labels(tmp_path: Path) -> None:
    config = ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(method="xoauth2", username="source@gmail.com", password="gmail-token"),
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
    row["target_account"] = "target@gmail.com"
    row["primary_mailbox"] = "INBOX"
    row["gmail_labels"] = ["\\Inbox", "Important", "Project A"]
    (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")
    (account_dir / "metadata" / "gmail-123.json").write_text(json.dumps(row))
    _write_provider_export_state(account_dir, target="target@gmail.com")
    (account_dir / "import-target@gmail.com.journal.jsonl").write_text(json.dumps({
        "canonical_id": "gmail-123",
        "target_account": "target@gmail.com",
        "target_mailbox": "INBOX",
        "status": "committed",
    }) + "\n")
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

    rows = load_import_journal(account_dir, account)

    assert rows == [valid]
    assert journal.read_text().strip() == json.dumps(valid, sort_keys=True)


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


class FakePreflightTarget:
    def list(self):
        return "OK", [b'(\\HasNoChildren) "/" "INBOX"']


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


def test_provider_preflight_reports_metadata_fetch_failures(tmp_path: Path) -> None:
    config = _provider_config()

    @contextlib.contextmanager
    def fake_connection(endpoint, *_args, **_kwargs):
        yield FakePreflightSourceFailure() if endpoint.provider == "gmail" else FakePreflightTarget()

    with mock.patch("components.provider_ops.imap_connection", fake_connection):
        ok, issues = provider_preflight(config, max_workers=1)

    assert not ok
    assert any("metadata fetch failed" in issue for issue in issues)


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


def test_provider_preflight_requires_gmail_all_mail_visibility(tmp_path: Path) -> None:
    config = _provider_config()

    @contextlib.contextmanager
    def fake_connection(endpoint, *_args, **_kwargs):
        yield FakePreflightSourceNoAllMail() if endpoint.provider == "gmail" else FakePreflightTarget()

    with mock.patch("components.provider_ops.imap_connection", fake_connection):
        ok, issues = provider_preflight(config, max_workers=1)

    assert not ok
    assert any("All Mail is not visible" in issue for issue in issues)


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
