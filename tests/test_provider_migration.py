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
    build_xoauth2_payload,
    list_mailboxes,
    load_import_journal,
    parse_list_line,
    parse_provider_fetch_response,
    provider_audit_account,
    provider_export_account,
    provider_import_account,
    provider_preflight,
    provider_validate_account,
    quote_mailbox_name,
    resolve_secret,
    resolve_primary_mailbox,
    target_has_message,
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
        "source": {"provider": "imap", "host": "example.com", "auth": {"method": "password", "password": "x"}},
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
    assert resolve_primary_mailbox(["[Gmail]/All Mail"], [], {}) == "Archive"
    assert resolve_primary_mailbox(["Project A", "[Gmail]/All Mail"], [], {}) == "Project A"
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
    assert row["source_mailboxes"] == ["INBOX", "[Gmail]/All Mail"]
    assert row["gmail_labels"] == ["Project A", "\\Inbox"]
    assert (account_dir / row["eml_path"]).exists()
    assert (account_dir / row["metadata_path"]).exists()
    assert fake.body_fetches == 1


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
        return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

    def response(self, name: str):
        self.response_calls += 1
        value = b"777" if self.response_calls == 1 else b"888"
        return "OK", [value]


class FakeSourceUidSetChangedImap(FakeSourceImap):
    def __init__(self) -> None:
        super().__init__()
        self.search_calls = 0

    def list(self):
        return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

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
    def __init__(self, *, has_existing: bool = False, existing_message_id: str = "<m1@example.com>") -> None:
        self.appended: List[str] = []
        self.has_existing = has_existing
        self.existing_message_id = existing_message_id
        self.messages = 0
        self.fetch_queries: List[str] = []
        self.search_queries: List[tuple] = []
        self.select_readonly: List[bool] = []

    def list(self):
        return "OK", [
            b'(\\HasNoChildren) "/" "INBOX"',
            b'(\\HasNoChildren \\Archive) "/" "Archive"',
        ]

    def select(self, mailbox: str, readonly: bool = False):
        self.select_readonly.append(readonly)
        return "OK", [b"0"]

    def create(self, mailbox: str):
        return "OK", [b""]

    def append(self, mailbox: str, flags: str, date_time: str, data: bytes):
        self.appended.append(mailbox.strip('"'))
        self.messages += 1
        self.has_existing = True
        return "OK", [b""]

    def search(self, charset: Optional[str], *criteria):
        self.search_queries.append(criteria)
        if criteria == ("ALL",):
            return "OK", [b" ".join(str(i).encode("ascii") for i in range(1, self.messages + 1))]
        if criteria == ("HEADER", "Message-ID", self.existing_message_id) and self.has_existing:
            return "OK", [b"99"]
        return "OK", [b""]

    def fetch(self, num: bytes, query: str):
        self.fetch_queries.append(query)
        return "OK", [(b"99 (RFC822.SIZE 36 BODY[] {36}", b"Message-ID: <m1@example.com>\r\n\r\nbody")]

    def logout(self):
        return "OK", []


def _write_manifest_fixture(root: Path) -> Path:
    account_dir = root / "source@example.com"
    (account_dir / "messages").mkdir(parents=True)
    (account_dir / "metadata").mkdir()
    eml = account_dir / "messages" / "gmail-123.eml"
    eml.write_bytes(b"Message-ID: <m1@example.com>\r\n\r\nbody")
    row = {
        "canonical_id": "gmail-123",
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
    return account_dir


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


def test_provider_import_rejects_manifest_paths_outside_export_dir(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    row = json.loads((account_dir / "manifest.jsonl").read_text())
    row["eml_path"] = "../secret.eml"
    (tmp_path / "secret.eml").write_bytes(b"Message-ID: <leak@example.com>\r\n\r\nsecret")
    (account_dir / "manifest.jsonl").write_text(json.dumps(row) + "\n")
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
    (account_dir / "import-target@icloud.com.journal.jsonl").write_text(json.dumps({
        "canonical_id": "gmail-123",
        "target_account": "target@icloud.com",
        "target_mailbox": "Archive",
        "status": "committed",
    }) + "\n")
    fake = FakeTargetImap(has_existing=True)
    fake.messages = 1

    @contextlib.contextmanager
    def fake_target_connection(*_args, **_kwargs) -> Iterator[FakeTargetImap]:
        yield fake

    with mock.patch("components.provider_ops.imap_connection", fake_target_connection):
        provider_import_account(config, account, tmp_path)

    assert fake.appended == ["Archive"]


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

    with pytest.raises(RuntimeError, match="target_account"):
        provider_import_account(config, account, tmp_path)

    _name, report = provider_validate_account(config, account, tmp_path)
    assert not report["ok"]
    assert any("target_account" in item for item in report["failed"])


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


def test_provider_audit_detects_corrupted_message(tmp_path: Path) -> None:
    config = _provider_config()
    account = config.accounts[0]
    account_dir = _write_manifest_fixture(tmp_path)
    (account_dir / "messages" / "gmail-123.eml").write_bytes(b"corrupted")

    _name, issues = provider_audit_account(config, account, tmp_path)
    assert any("content_sha256 mismatch" in issue for issue in issues)


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
        return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

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
