"""
Tests for Pylance type-error fixes.

Validates that the type fixes are correct at runtime and don't alter behavior.
"""
from __future__ import annotations

import contextlib
import json
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Iterator
from unittest import mock

import imaplib
import pytest

from components.models import Account, ServerConfig


# ---------------------------------------------------------------------------
# RC1: list_all_mailboxes handles non-bytes items in imap.list() response
# ---------------------------------------------------------------------------


class TestListAllMailboxesTypeGuard:
    """list_all_mailboxes must skip non-bytes items gracefully."""

    def test_tuple_item_in_list_response_is_skipped(self) -> None:
        """If imap.list() returns a tuple[bytes,bytes] entry, it should be skipped."""
        from components.imap_ops import list_all_mailboxes

        fake_imap = mock.MagicMock(spec=imaplib.IMAP4)
        # Simulate a response with a normal bytes entry and a tuple entry
        fake_imap.list.return_value = (
            "OK",
            [
                b'(\\HasNoChildren) "/" "INBOX"',
                (b"extra", b"data"),  # tuple item — should be skipped
                b'(\\HasNoChildren) "/" "Sent"',
            ],
        )

        result = list_all_mailboxes(fake_imap)

        assert "INBOX" in result
        assert "Sent" in result
        assert len(result) == 2

    def test_none_item_in_list_response_is_skipped(self) -> None:
        from components.imap_ops import list_all_mailboxes

        fake_imap = mock.MagicMock(spec=imaplib.IMAP4)
        fake_imap.list.return_value = (
            "OK",
            [None, b'(\\HasNoChildren) "/" "INBOX"'],
        )

        result = list_all_mailboxes(fake_imap)
        assert result == ["INBOX"]

    def test_normal_bytes_still_work(self) -> None:
        from components.imap_ops import list_all_mailboxes

        fake_imap = mock.MagicMock(spec=imaplib.IMAP4)
        fake_imap.list.return_value = (
            "OK",
            [
                b'(\\HasNoChildren) "/" "INBOX"',
                b'(\\HasNoChildren) "/" "Drafts"',
                b'(\\HasNoChildren) "/" "Sent"',
            ],
        )

        result = list_all_mailboxes(fake_imap)
        assert result == ["INBOX", "Drafts", "Sent"]


# ---------------------------------------------------------------------------
# RC2: uid("search", "ALL") without None charset
# ---------------------------------------------------------------------------


class TestUidSearchNoNone:
    """fetch_all_uids must call uid('search', 'ALL') without None."""

    def test_fetch_all_uids_call_signature(self) -> None:
        from components.imap_ops import fetch_all_uids

        fake_imap = mock.MagicMock(spec=imaplib.IMAP4)
        fake_imap.select.return_value = ("OK", [b"3"])
        fake_imap.uid.return_value = ("OK", [b"1 2 3"])

        result = fetch_all_uids(fake_imap, "INBOX")

        assert result == [1, 2, 3]
        # Verify uid was called with ("search", "ALL") — no None
        fake_imap.uid.assert_called_once_with("search", "ALL")

    def test_audit_uid_search_no_none(self) -> None:
        """audit_account's remote check must also call uid('search', 'ALL')."""
        import inspect
        from components.audit import audit_account

        source = inspect.getsource(audit_account)
        # The old pattern: uid("search", None, "ALL") should be gone
        assert 'uid("search", None,' not in source
        assert 'uid("search", "ALL")' in source


# ---------------------------------------------------------------------------
# RC3: _imap_ctx return type and imap_factory type annotation
# ---------------------------------------------------------------------------


class TestImapFactoryTyping:
    """import_account imap_factory parameter must be properly typed."""

    def test_imap_factory_accepts_typed_callable(self, tmp_path: Path) -> None:
        """A properly typed imap_factory callable should work with import_account."""
        from components.imap_ops import import_account

        server = ServerConfig(host="dummy", port=993, ssl=True)
        account = Account(email="user@example.com", password="pass")

        # Set up minimal export structure
        acc_dir = tmp_path / "user@example.com" / "INBOX"
        acc_dir.mkdir(parents=True)
        eml = acc_dir / "u0000000001.eml"
        eml.write_bytes(b"From: a@b.com\n\nbody")
        meta = acc_dir / "u0000000001.json"
        meta.write_text(json.dumps({"mailbox": "INBOX", "uid": 1, "flags": "", "internaldate": ""}))

        fake_imap = mock.MagicMock(spec=imaplib.IMAP4)
        fake_imap.select.return_value = ("OK", [b"0"])
        fake_imap.append.return_value = ("OK", [b""])

        @contextlib.contextmanager
        def typed_factory(srv: ServerConfig, acc: Account) -> Iterator[imaplib.IMAP4]:
            yield fake_imap

        # Should work without type errors
        import_account(
            account, server, tmp_path, ignore_errors=False,
            imap_factory=typed_factory,
        )

        assert fake_imap.append.called

    def test_import_account_signature_has_typed_factory(self) -> None:
        import inspect
        from components.imap_ops import import_account

        sig = inspect.signature(import_account)
        param = sig.parameters["imap_factory"]
        annotation_str = str(param.annotation)
        # Should contain Callable and AbstractContextManager, not be empty/None
        assert "Callable" in annotation_str or "callable" in annotation_str.lower()


# ---------------------------------------------------------------------------
# RC4: flags_str is always str (never None) for imap.append
# ---------------------------------------------------------------------------


class TestFlagsAlwaysStr:
    """flags passed to imap.append must always be str, never None."""

    def test_empty_flags_passes_empty_string(self, tmp_path: Path) -> None:
        from components.imap_ops import import_account

        server = ServerConfig(host="dummy", port=993, ssl=True)
        account = Account(email="user@example.com", password="pass")

        acc_dir = tmp_path / "user@example.com" / "INBOX"
        acc_dir.mkdir(parents=True)
        eml = acc_dir / "u0000000001.eml"
        eml.write_bytes(b"From: a@b.com\n\nbody")
        meta = acc_dir / "u0000000001.json"
        # Empty flags and no internaldate
        meta.write_text(json.dumps({"mailbox": "INBOX", "uid": 1, "flags": "", "internaldate": ""}))

        fake_imap = mock.MagicMock(spec=imaplib.IMAP4)
        fake_imap.select.return_value = ("OK", [b"0"])
        fake_imap.append.return_value = ("OK", [b""])

        @contextlib.contextmanager
        def factory(srv: ServerConfig, acc: Account) -> Iterator[imaplib.IMAP4]:
            yield fake_imap

        import_account(account, server, tmp_path, ignore_errors=False, imap_factory=factory)

        # Verify append was called with a str for flags, not None
        call_args = fake_imap.append.call_args
        flags_arg = call_args[0][1]  # second positional arg
        assert isinstance(flags_arg, str), f"flags should be str, got {type(flags_arg)}"

    def test_recent_only_flags_passes_empty_string(self, tmp_path: Path) -> None:
        """When the only flag is \\Recent (filtered out), flags should be empty string."""
        from components.imap_ops import import_account

        server = ServerConfig(host="dummy", port=993, ssl=True)
        account = Account(email="user@example.com", password="pass")

        acc_dir = tmp_path / "user@example.com" / "INBOX"
        acc_dir.mkdir(parents=True)
        eml = acc_dir / "u0000000001.eml"
        eml.write_bytes(b"From: a@b.com\n\nbody")
        meta = acc_dir / "u0000000001.json"
        meta.write_text(json.dumps({"mailbox": "INBOX", "uid": 1, "flags": "\\Recent", "internaldate": ""}))

        fake_imap = mock.MagicMock(spec=imaplib.IMAP4)
        fake_imap.select.return_value = ("OK", [b"0"])
        fake_imap.append.return_value = ("OK", [b""])

        @contextlib.contextmanager
        def factory(srv: ServerConfig, acc: Account) -> Iterator[imaplib.IMAP4]:
            yield fake_imap

        import_account(account, server, tmp_path, ignore_errors=False, imap_factory=factory)

        call_args = fake_imap.append.call_args
        flags_arg = call_args[0][1]
        assert isinstance(flags_arg, str)
        assert flags_arg == "", f"Expected empty string after \\Recent filtered, got '{flags_arg}'"


# ---------------------------------------------------------------------------
# RC5: build_config return type is Dict[str, Any]
# ---------------------------------------------------------------------------


class TestBuildConfigReturnType:
    """build_config must return Dict[str, Any] so len() works on nested values."""

    def test_build_config_accounts_is_list(self) -> None:
        from directadmin_indexer import build_config, ServerSettings

        server = ServerSettings(host="imap.example.com")
        result = build_config(server, ["a@example.com", "b@example.com"], "pass")

        accounts = result.get("accounts", [])
        # This must not raise TypeError — proves the type is compatible with len()
        assert len(accounts) == 2

    def test_build_config_return_annotation(self) -> None:
        import inspect
        from directadmin_indexer import build_config

        sig = inspect.signature(build_config)
        ret_str = str(sig.return_annotation)
        assert "Any" in ret_str, f"Expected Dict[str, Any], got: {ret_str}"
