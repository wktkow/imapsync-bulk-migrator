from __future__ import annotations

import copy
from pathlib import Path

import pytest

from components.models import ProviderMigrationConfig


def _raw_alias_config() -> dict:
    return {
        "source": {
            "provider": "imap",
            "host": "source.example.com",
            "auth": {"method": "password", "password": "source-default"},
        },
        "target": {
            "provider": "gmail",
            "host": "imap.gmail.com",
            "gmail_full_visibility_verified": True,
            "auth": {
                "method": "app_password",
                "username": "merged@example.com",
                "password": "target-secret",
            },
            "gmail_api_auth": {
                "method": "xoauth2",
                "username": "merged@example.com",
                "env_var": "GMAIL_API_TOKEN",
            },
            "workspace_aliases": {
                "enabled": True,
                "target_user": "Merged@Example.com",
                "from_source_accounts": True,
                "aliases": ["Explicit@Example.com", "OLD1@example.com"],
                "exclusions": ["skip@example.com"],
                "conflict_policy": "create_only",
                "admin_auth": {
                    "method": "xoauth2",
                    "admin_email": "admin@example.com",
                    "env_var": "WORKSPACE_ADMIN_TOKEN",
                },
            },
        },
        "accounts": [
            {
                "source_email": "old1@example.com",
                "target_email": "merged@example.com",
                "source_auth": {
                    "method": "password",
                    "username": "old1@example.com",
                    "password": "old1-secret",
                },
            },
            {
                "source_email": "skip@example.com",
                "target_email": "merged@example.com",
                "source_auth": {
                    "method": "password",
                    "username": "skip@example.com",
                    "password": "skip-secret",
                },
            },
        ],
        "migration": {
            "target_mode": "merge",
            "account_merge_mode": "many_to_one",
            "routing": {
                "enabled": True,
                "filters": [
                    {"delivered_to": "old1@example.com", "label": "Imported/old1"},
                    {
                        "delivered_to": "explicit@example.com",
                        "label": "Imported/explicit",
                    },
                ],
            },
        },
    }


def test_workspace_alias_config_is_opt_in_and_disabled_form_is_strict() -> None:
    raw = _raw_alias_config()
    raw["target"].pop("workspace_aliases")
    parsed = ProviderMigrationConfig.from_dict(raw)
    assert not parsed.target.workspace_aliases.enabled
    assert parsed.workspace_alias_candidates() == ()

    raw["target"]["workspace_aliases"] = {"enabled": False}
    assert not ProviderMigrationConfig.from_dict(raw).target.workspace_aliases.enabled

    raw["target"]["workspace_aliases"]["aliases"] = ["old@example.com"]
    with pytest.raises(ValueError, match="settings require .*enabled=true"):
        ProviderMigrationConfig.from_dict(raw)


@pytest.mark.parametrize("endpoint", ["source", "target"])
def test_provider_endpoints_reject_unknown_fields_including_alias_typo(
    endpoint: str,
) -> None:
    raw = _raw_alias_config()
    raw[endpoint]["workspace_aliasses"] = {"enabled": True}

    with pytest.raises(ValueError, match=rf"{endpoint} contains unknown field.*workspace_aliasses"):
        ProviderMigrationConfig.from_dict(raw)


@pytest.mark.parametrize(
    ("mutate", "context", "field"),
    [
        (
            lambda raw: raw.update(limts={"retry_max_attempts": 3}),
            "provider config",
            "limts",
        ),
        (
            lambda raw: raw["migration"].update(routng={"enabled": False}),
            "migration",
            "routng",
        ),
        (
            lambda raw: raw["migration"].update(target_mod="merge"),
            "migration",
            "target_mod",
        ),
        (
            lambda raw: raw.update(
                limits={"retry_max_attempts": 3, "retry_max_atempts": 4}
            ),
            "limits",
            "retry_max_atempts",
        ),
        (
            lambda raw: raw.update(
                limits={
                    "throttle": {
                        "max_bytes_per_second": 1024,
                        "max_bytes_per_secnd": 512,
                    }
                }
            ),
            "limits.throttle",
            "max_bytes_per_secnd",
        ),
        (
            lambda raw: raw["accounts"][0].update(
                gmail_full_visiblity_verified=True
            ),
            "accounts[0]",
            "gmail_full_visiblity_verified",
        ),
        (
            lambda raw: raw["accounts"][0]["source_auth"].update(
                usernme="old1@example.com"
            ),
            "accounts[0].source_auth",
            "usernme",
        ),
    ],
)
def test_provider_config_rejects_unknown_fields_at_every_owned_level(
    mutate,
    context: str,
    field: str,
) -> None:
    raw = _raw_alias_config()
    mutate(raw)

    with pytest.raises(ValueError) as error:
        ProviderMigrationConfig.from_dict(raw)

    message = str(error.value)
    assert context in message
    assert field in message
    assert "unknown field" in message
    assert "allowed fields" in message


def test_provider_config_accepts_documented_optional_account_auth_and_limit_fields() -> None:
    raw = _raw_alias_config()
    raw["limits"] = {
        "retry_max_attempts": 3,
        "throttle": {"max_bytes_per_second": 1024},
    }
    raw["accounts"][0].update(
        gmail_full_visibility_verified=False,
        target_gmail_full_visibility_verified=True,
        target_gmail_api_auth={
            "method": "xoauth2",
            "username": "merged@example.com",
            "env_var": "ACCOUNT_GMAIL_API_TOKEN",
        },
    )

    parsed = ProviderMigrationConfig.from_dict(raw)

    assert parsed.limits.retry_max_attempts == 3
    assert parsed.limits.throttle.max_bytes_per_second == 1024
    assert parsed.accounts[0].target_gmail_full_visibility_verified is True
    assert parsed.accounts[0].target_gmail_api_auth is not None
    assert parsed.accounts[0].target_gmail_api_auth.env_var == "ACCOUNT_GMAIL_API_TOKEN"


@pytest.mark.parametrize(
    "alias",
    [
        "sales+tag@example.com",
        "ümlaut@example.com",
        "abuse@example.com",
        "POSTMASTER@example.com",
    ],
)
def test_workspace_alias_preflight_rejects_invalid_or_reserved_local_parts(
    alias: str,
) -> None:
    raw = _raw_alias_config()
    raw["target"]["workspace_aliases"]["aliases"] = [alias]
    raw["migration"]["routing"]["filters"].append(
        {"delivered_to": alias, "label": "Imported/rejected"}
    )

    with pytest.raises(ValueError, match="local part|reserved"):
        ProviderMigrationConfig.from_dict(raw)


def test_workspace_alias_candidates_union_sources_and_explicit_then_exclude() -> None:
    parsed = ProviderMigrationConfig.from_dict(_raw_alias_config())

    assert parsed.target.workspace_aliases.target_user == "merged@example.com"
    assert parsed.workspace_alias_candidates() == (
        "explicit@example.com",
        "old1@example.com",
    )


def test_workspace_alias_config_uses_nontransitional_idna_and_rejects_joiners() -> None:
    raw = _raw_alias_config()
    settings = raw["target"]["workspace_aliases"]
    settings["from_source_accounts"] = False
    settings["aliases"] = ["Alias@faß.de"]
    settings["exclusions"] = []
    raw["migration"]["routing"]["filters"] = [
        {"delivered_to": "alias@xn--fa-hia.de", "label": "Imported/idna"}
    ]

    parsed = ProviderMigrationConfig.from_dict(raw)
    assert parsed.workspace_alias_candidates() == ("alias@xn--fa-hia.de",)
    assert parsed.migration.routing.filters[0].delivered_to == "alias@xn--fa-hia.de"

    raw["target"]["workspace_aliases"]["aliases"] = ["alias@fa\u200c.de"]
    with pytest.raises(ValueError, match="email address"):
        ProviderMigrationConfig.from_dict(raw)


def test_workspace_alias_config_rejects_idna_equivalent_filter_duplicates() -> None:
    raw = _raw_alias_config()
    settings = raw["target"]["workspace_aliases"]
    settings["from_source_accounts"] = False
    settings["aliases"] = ["alias@faß.de"]
    settings["exclusions"] = []
    raw["migration"]["routing"]["filters"] = [
        {"delivered_to": "alias@faß.de", "label": "Imported/unicode"},
        {
            "delivered_to": "alias@xn--fa-hia.de",
            "label": "Imported/punycode",
        },
    ]

    with pytest.raises(
        ValueError,
        match=r"same Gmail delivered-to condition .*xn--fa-hia",
    ):
        ProviderMigrationConfig.from_dict(raw)


def test_routing_only_filter_preserves_one_configured_spelling() -> None:
    raw = _raw_alias_config()
    raw["target"].pop("workspace_aliases")
    raw["migration"]["routing"]["filters"] = [
        {"delivered_to": "alias@faß.de", "label": "Imported/unicode"},
    ]

    parsed = ProviderMigrationConfig.from_dict(raw)

    assert parsed.migration.routing.filters[0].delivered_to == "alias@faß.de"


def test_routing_only_filters_reject_idna_equivalent_gmail_conditions() -> None:
    raw = _raw_alias_config()
    raw["target"].pop("workspace_aliases")
    raw["migration"]["routing"]["filters"] = [
        {"delivered_to": "alias@faß.de", "label": "Imported/unicode"},
        {
            "delivered_to": "alias@xn--fa-hia.de",
            "label": "Imported/punycode",
        },
    ]

    with pytest.raises(
        ValueError,
        match=r"same Gmail delivered-to condition .*xn--fa-hia.*filters 0 and 1",
    ):
        ProviderMigrationConfig.from_dict(raw)


def test_workspace_alias_email_accepts_254_ascii_octet_boundary() -> None:
    raw = _raw_alias_config()
    domain = ".".join(("a" * 63, "b" * 63, "c" * 61))
    alias = f"{'z' * 64}@{domain}"
    assert len(alias.encode("ascii")) == 254
    raw["target"]["workspace_aliases"].update(
        from_source_accounts=False,
        aliases=[alias],
        exclusions=[],
    )
    raw["migration"]["routing"]["filters"] = [
        {"delivered_to": alias, "label": "Imported/boundary"}
    ]

    parsed = ProviderMigrationConfig.from_dict(raw)

    assert parsed.workspace_alias_candidates() == (alias,)


def test_workspace_alias_email_length_is_measured_after_idna_canonicalization() -> None:
    raw = _raw_alias_config()
    unicode_domain = ".".join(["e\u0301" * 30] * 5 + ["com"])
    alias = f"a@{unicode_domain}"
    assert len(alias) > 254
    raw["target"]["workspace_aliases"].update(
        from_source_accounts=False,
        aliases=[alias],
        exclusions=[],
    )
    raw["migration"]["routing"]["filters"] = [
        {"delivered_to": alias, "label": "Imported/canonical-length"}
    ]

    parsed = ProviderMigrationConfig.from_dict(raw)
    candidate = parsed.workspace_alias_candidates()[0]

    assert candidate.startswith("a@xn--")
    assert len(candidate.encode("ascii")) < 254
    assert parsed.migration.routing.filters[0].delivered_to == candidate


def test_workspace_alias_email_rejects_overlong_ascii_form_after_idna() -> None:
    raw = _raw_alias_config()
    unicode_domain = ".".join(["ü" * 40] * 4 + ["com"])
    alias = f"{'z' * 64}@{unicode_domain}"
    assert len(alias) < 254
    raw["target"]["workspace_aliases"].update(
        from_source_accounts=False,
        aliases=[alias],
        exclusions=[],
    )
    raw["migration"]["routing"]["filters"] = [
        {"delivered_to": alias, "label": "Imported/overlong"}
    ]

    with pytest.raises(ValueError, match="email address"):
        ProviderMigrationConfig.from_dict(raw)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (
            lambda raw: raw["target"]["workspace_aliases"].update(
                target_user="someone-else@example.com"
            ),
            "target_user must match the shared target_email",
        ),
        (
            lambda raw: raw["migration"]["routing"].update(filters=[]),
            "matching migration.routing.filters.* missing",
        ),
    ],
)
def test_workspace_alias_config_rejects_unsafe_binding_or_missing_filters(
    change,
    message: str,
) -> None:
    raw = _raw_alias_config()
    change(raw)
    with pytest.raises(ValueError, match=message):
        ProviderMigrationConfig.from_dict(raw)


def test_workspace_alias_admin_xoauth2_rejects_inline_or_ambiguous_secrets() -> None:
    raw = _raw_alias_config()
    auth = raw["target"]["workspace_aliases"]["admin_auth"]
    auth["token"] = "do-not-leak-this-token"
    with pytest.raises(ValueError) as error:
        ProviderMigrationConfig.from_dict(raw)
    assert "unknown field" in str(error.value)
    assert "do-not-leak-this-token" not in str(error.value)

    raw = _raw_alias_config()
    auth = raw["target"]["workspace_aliases"]["admin_auth"]
    auth["token_file"] = "admin.token"
    with pytest.raises(ValueError, match="exactly one of token_file or env_var"):
        ProviderMigrationConfig.from_dict(raw)


def test_workspace_alias_service_account_paths_bind_to_config_directory(
    tmp_path: Path,
) -> None:
    raw = copy.deepcopy(_raw_alias_config())
    raw["target"]["workspace_aliases"]["admin_auth"] = {
        "method": "service_account",
        "credentials_file": "secrets/workspace.json",
        "delegated_admin": "Admin@Example.com",
    }

    parsed = ProviderMigrationConfig.from_dict(raw, base_dir=tmp_path)
    auth = parsed.target.workspace_aliases.admin_auth
    assert auth is not None
    assert auth.credentials_file == str(tmp_path / "secrets" / "workspace.json")
    assert auth.delegated_admin == "admin@example.com"
