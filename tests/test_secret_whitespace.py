from __future__ import annotations

import argparse

from components.main import _read_required_secret_file, _resolve_cpanel_auth, _resolve_da_password
from cpanel_indexer import resolve_cpanel_auth as resolve_cpanel_indexer_auth
from directadmin_indexer import read_secret_file, resolve_default_password, resolve_password


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
