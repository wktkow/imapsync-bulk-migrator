from __future__ import annotations

import argparse
import os
from pathlib import Path

import pytest

from components.models import AuthConfig
from components.main import _read_required_secret_file, _resolve_cpanel_auth, _resolve_da_password
from components.provider_ops import resolve_secret
from cpanel_indexer import resolve_cpanel_auth as resolve_cpanel_indexer_auth
from directadmin_indexer import read_secret_file, resolve_default_password, resolve_password


def _symlink_or_skip(target: Path, link: Path) -> None:
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")


def _hardlink_or_skip(target: Path, link: Path) -> None:
    try:
        os.link(target, link)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"hardlink creation unavailable: {exc}")


def _mkfifo_or_skip(path: Path) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO creation unavailable")
    try:
        os.mkfifo(path)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"FIFO creation unavailable: {exc}")


def _assert_file_secret_readers_reject(path: Path) -> None:
    with pytest.raises(RuntimeError, match="secret|file|regular|linked|open"):
        resolve_secret(AuthConfig(method="password", password_file=str(path)))
    with pytest.raises(RuntimeError, match="secret|file|regular|linked|open"):
        resolve_secret(AuthConfig(method="xoauth2", token_file=str(path)))
    with pytest.raises(RuntimeError, match="secret|file|regular|linked|open"):
        _read_required_secret_file(str(path), label="panel secret")
    with pytest.raises(RuntimeError, match="secret|file|regular|linked|open"):
        read_secret_file(str(path), label="panel secret")

    cpanel_args = argparse.Namespace(
        password=None,
        password_file=str(path),
        password_env=None,
        token=None,
        token_file=None,
        token_env=None,
    )
    with pytest.raises(RuntimeError, match="secret|file|regular|linked|open"):
        resolve_cpanel_indexer_auth(cpanel_args)


def test_main_panel_secret_sources_preserve_boundary_spaces(tmp_path, monkeypatch):
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("  file secret  \n", encoding="utf-8")

    assert _read_required_secret_file(str(secret_file), label="panel secret") == "  file secret  "

    monkeypatch.setenv("DA_SECRET", "  login key  ")
    da_args = argparse.Namespace(da_password=None, da_password_file=None, da_password_env="DA_SECRET")
    assert _resolve_da_password(da_args) == "  login key  "

    monkeypatch.setenv("CPANEL_TOKEN", "  api token  ")
    cpanel_args = argparse.Namespace(
        cpanel_password=None,
        cpanel_password_file=None,
        cpanel_password_env=None,
        cpanel_token=None,
        cpanel_token_file=None,
        cpanel_token_env="CPANEL_TOKEN",
    )
    assert _resolve_cpanel_auth(cpanel_args) == (None, "  api token  ")


def test_standalone_indexers_preserve_boundary_spaces(tmp_path, monkeypatch):
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("  panel secret  \r\n", encoding="utf-8")

    assert read_secret_file(str(secret_file), label="panel secret") == "  panel secret  "

    monkeypatch.setenv("DA_PASSWORD", "  da password  ")
    da_args = argparse.Namespace(password=None, password_file=None, password_env="DA_PASSWORD")
    assert resolve_password(da_args) == "  da password  "

    monkeypatch.setenv("DEFAULT_PASSWORD", "  mailbox password  ")
    default_args = argparse.Namespace(
        default_password="",
        default_password_file=None,
        default_password_env="DEFAULT_PASSWORD",
    )
    assert resolve_default_password(default_args) == "  mailbox password  "

    monkeypatch.setenv("CPANEL_PASSWORD", "  cpanel password  ")
    cpanel_args = argparse.Namespace(
        password=None,
        password_file=None,
        password_env="CPANEL_PASSWORD",
        token=None,
        token_file=None,
        token_env=None,
    )
    assert resolve_cpanel_indexer_auth(cpanel_args) == ("  cpanel password  ", None)


def test_secret_file_readers_reject_symlinks(tmp_path):
    real_secret = tmp_path / "real-secret.txt"
    real_secret.write_text("redirected\n", encoding="utf-8")
    linked_secret = tmp_path / "linked-secret.txt"
    _symlink_or_skip(real_secret, linked_secret)

    _assert_file_secret_readers_reject(linked_secret)


def test_secret_file_readers_reject_symlinked_parent(tmp_path):
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    (real_dir / "secret.txt").write_text("redirected\n", encoding="utf-8")
    linked_dir = tmp_path / "linked"
    _symlink_or_skip(real_dir, linked_dir)

    _assert_file_secret_readers_reject(linked_dir / "secret.txt")


def test_secret_file_readers_reject_fifo(tmp_path):
    fifo = tmp_path / "secret-fifo"
    _mkfifo_or_skip(fifo)

    _assert_file_secret_readers_reject(fifo)


def test_secret_file_readers_reject_hardlinks(tmp_path):
    real_secret = tmp_path / "real-secret.txt"
    real_secret.write_text("redirected\n", encoding="utf-8")
    linked_secret = tmp_path / "hardlinked-secret.txt"
    _hardlink_or_skip(real_secret, linked_secret)

    _assert_file_secret_readers_reject(linked_secret)
