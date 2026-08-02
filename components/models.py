from __future__ import annotations

import dataclasses
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import idna

from .routing import CUSTOM_LABEL, GENERIC_MAILBOX, GMAIL_SYSTEM, RoutingConfig
from .utils import sanitize_for_path, sanitized_path_key


@dataclasses.dataclass
class Account:
    email: str
    password: str


def _reject_sanitized_path_collisions(values: List[str], *, context: str) -> None:
    seen: Dict[str, Tuple[str, str]] = {}
    for value in values:
        path = sanitize_for_path(value)
        key = sanitized_path_key(value)
        previous = seen.get(key)
        if previous is not None and previous[0] != value:
            raise ValueError(
                f"{context} path collision after sanitizing: "
                f"{previous[0]!r} -> {previous[1]!r} and {value!r} -> {path!r} "
                "alias on case-insensitive filesystems"
            )
        seen[key] = (value, path)


@dataclasses.dataclass
class ServerConfig:
    host: str
    port: int = 993
    ssl: bool = True
    starttls: bool = False


@dataclasses.dataclass
class AuthConfig:
    method: str
    username: Optional[str] = None
    password: Optional[str] = None
    password_file: Optional[str] = None
    token_file: Optional[str] = None
    env_var: Optional[str] = None

    @staticmethod
    def from_dict(raw: Optional[Dict[str, Any]], *, context: str, required: bool = True, base_dir: Optional[Path] = None) -> Optional["AuthConfig"]:
        if raw is None:
            if required:
                raise ValueError(f"{context} must be an object")
            return None
        if not isinstance(raw, dict):
            raise ValueError(f"{context} must be an object")
        _strict_config_keys(
            raw,
            {
                "method",
                "username",
                "password",
                "password_file",
                "token_file",
                "env_var",
            },
            context,
        )
        method = raw.get("method")
        if not method or not isinstance(method, str):
            raise ValueError(f"{context}.method must be a non-empty string")
        method = method.strip().lower()
        if method not in {"password", "app_password", "xoauth2"}:
            raise ValueError(f"{context}.method must be one of: password, app_password, xoauth2")
        auth = AuthConfig(
            method=method,
            username=_optional_str(raw, "username", context),
            password=_optional_secret_str(raw, "password", context),
            password_file=_optional_path_str(raw, "password_file", context, base_dir),
            token_file=_optional_path_str(raw, "token_file", context, base_dir),
            env_var=_optional_str(raw, "env_var", context),
        )
        auth.validate(context=context)
        return auth

    def secret_source_count(self) -> int:
        return sum(1 for value in (self.password, self.password_file, self.token_file, self.env_var) if value)

    def validate(self, *, context: str) -> None:
        if self.secret_source_count() > 1:
            raise ValueError(f"{context} must specify at most one secret source")
        if self.method == "xoauth2" and self.password_file is not None:
            raise ValueError(f"{context}.password_file is not valid for xoauth2; use token_file, env_var, or password")
        if self.method in {"password", "app_password"} and self.token_file is not None:
            raise ValueError(f"{context}.token_file is not valid for {self.method}; use password_file, env_var, or password")


def _strict_config_keys(raw: Dict[str, Any], allowed: set[str], context: str) -> None:
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise ValueError(
            f"{context} contains unknown field(s): {', '.join(unknown)}; "
            f"allowed fields: {', '.join(sorted(allowed))}"
        )


def _workspace_email(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{context} must be a non-empty email address")
    address = value.strip()
    if (
        address.count("@") != 1
        or any(char.isspace() for char in address)
    ):
        raise ValueError(f"{context} must be an email address")
    local, domain = address.split("@", 1)
    if (
        not local
        or len(local) > 64
        or local.startswith(".")
        or local.endswith(".")
        or ".." in local
        or not domain
    ):
        raise ValueError(f"{context} must be an email address")
    try:
        domain = idna.encode(
            domain,
            uts46=True,
            transitional=False,
            std3_rules=True,
        ).decode("ascii").casefold()
    except (idna.IDNAError, UnicodeError, ValueError):
        raise ValueError(f"{context} must be an email address") from None
    if len(domain) > 253 or "." not in domain:
        raise ValueError(f"{context} must be an email address")
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or not all(char.isalnum() or char == "-" for char in label)
        for label in domain.split(".")
    ):
        raise ValueError(f"{context} must be an email address")
    canonical = f"{local.casefold()}@{domain}"
    try:
        canonical_octets = canonical.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError(f"{context} local part must contain only ASCII characters") from None
    if len(canonical_octets) > 254:
        raise ValueError(f"{context} must be an email address")
    return canonical


_WORKSPACE_ALIAS_LOCAL_RE = re.compile(r"^[a-z0-9._'-]+$", flags=re.ASCII)
_WORKSPACE_RESERVED_ALIAS_LOCALS = frozenset({"abuse", "postmaster"})


def _workspace_alias_email(value: Any, context: str) -> str:
    """Canonicalize an address and enforce Workspace alias username rules."""

    address = _workspace_email(value, context)
    local = address.rsplit("@", 1)[0]
    if _WORKSPACE_ALIAS_LOCAL_RE.fullmatch(local) is None:
        raise ValueError(
            f"{context} local part may contain only ASCII letters, numbers, periods, "
            "dashes, underscores, and apostrophes for a Workspace alias"
        )
    if local in _WORKSPACE_RESERVED_ALIAS_LOCALS:
        raise ValueError(
            f"{context} uses reserved Workspace alias local part {local!r}"
        )
    return address


def _workspace_email_list(raw: Dict[str, Any], key: str, context: str) -> Tuple[str, ...]:
    value = raw.get(key, [])
    if not isinstance(value, list):
        raise ValueError(f"{context}.{key} must be an array")
    addresses = {
        _workspace_email(item, f"{context}.{key}[{index}]")
        for index, item in enumerate(value)
    }
    return tuple(sorted(addresses))


def _workspace_alias_email_list(
    raw: Dict[str, Any],
    key: str,
    context: str,
) -> Tuple[str, ...]:
    value = raw.get(key, [])
    if not isinstance(value, list):
        raise ValueError(f"{context}.{key} must be an array")
    addresses = {
        _workspace_alias_email(item, f"{context}.{key}[{index}]")
        for index, item in enumerate(value)
    }
    return tuple(sorted(addresses))


@dataclasses.dataclass(frozen=True)
class WorkspaceAliasAdminAuthConfig:
    """Separate Directory API administrator authorization.

    Only preissued bearer-token sources and service-account domain-wide
    delegation are accepted.  Secret values are never stored inline.
    """

    method: str
    admin_email: Optional[str] = None
    token_file: Optional[str] = None
    env_var: Optional[str] = None
    credentials_file: Optional[str] = None
    delegated_admin: Optional[str] = None

    @staticmethod
    def from_dict(
        raw: Any,
        *,
        context: str,
        base_dir: Optional[Path] = None,
    ) -> "WorkspaceAliasAdminAuthConfig":
        if not isinstance(raw, dict):
            raise ValueError(f"{context} must be an object")
        method = raw.get("method")
        if not isinstance(method, str) or not method.strip():
            raise ValueError(f"{context}.method must be a non-empty string")
        method = method.strip().lower()
        if method == "xoauth2":
            _strict_config_keys(
                raw,
                {"method", "admin_email", "token_file", "env_var"},
                context,
            )
            admin_email = _workspace_email(raw.get("admin_email"), f"{context}.admin_email")
            token_file = _optional_path_str(raw, "token_file", context, base_dir)
            env_var = _optional_str(raw, "env_var", context)
            if sum(item is not None for item in (token_file, env_var)) != 1:
                raise ValueError(
                    f"{context} must configure exactly one of token_file or env_var"
                )
            return WorkspaceAliasAdminAuthConfig(
                method=method,
                admin_email=admin_email,
                token_file=token_file,
                env_var=env_var,
            )
        if method == "service_account":
            _strict_config_keys(
                raw,
                {"method", "credentials_file", "delegated_admin"},
                context,
            )
            credentials_file = _optional_path_str(raw, "credentials_file", context, base_dir)
            if credentials_file is None:
                raise ValueError(f"{context}.credentials_file must be a non-empty string")
            delegated_admin = _workspace_email(
                raw.get("delegated_admin"),
                f"{context}.delegated_admin",
            )
            return WorkspaceAliasAdminAuthConfig(
                method=method,
                credentials_file=credentials_file,
                delegated_admin=delegated_admin,
            )
        raise ValueError(f"{context}.method must be one of: service_account, xoauth2")

    def validate(self, *, context: str) -> None:
        if self.method == "xoauth2":
            if self.admin_email is None:
                raise ValueError(f"{context}.admin_email must be set for xoauth2")
            _workspace_email(self.admin_email, f"{context}.admin_email")
            if sum(item is not None for item in (self.token_file, self.env_var)) != 1:
                raise ValueError(
                    f"{context} must configure exactly one of token_file or env_var"
                )
            if self.credentials_file is not None or self.delegated_admin is not None:
                raise ValueError(
                    f"{context} service-account settings are not valid for xoauth2"
                )
            return
        if self.method == "service_account":
            if self.credentials_file is None:
                raise ValueError(f"{context}.credentials_file must be set for service_account")
            if self.delegated_admin is None:
                raise ValueError(f"{context}.delegated_admin must be set for service_account")
            _workspace_email(self.delegated_admin, f"{context}.delegated_admin")
            if self.admin_email is not None or self.token_file is not None or self.env_var is not None:
                raise ValueError(
                    f"{context} XOAUTH2 settings are not valid for service_account"
                )
            return
        raise ValueError(f"{context}.method must be one of: service_account, xoauth2")


@dataclasses.dataclass(frozen=True)
class WorkspaceAliasesConfig:
    enabled: bool = False
    target_user: Optional[str] = None
    from_source_accounts: bool = True
    aliases: Tuple[str, ...] = ()
    exclusions: Tuple[str, ...] = ()
    conflict_policy: Optional[str] = None
    admin_auth: Optional[WorkspaceAliasAdminAuthConfig] = None

    @staticmethod
    def from_dict(
        raw: Any,
        *,
        context: str,
        base_dir: Optional[Path] = None,
    ) -> "WorkspaceAliasesConfig":
        if raw is None:
            return WorkspaceAliasesConfig()
        if not isinstance(raw, dict):
            raise ValueError(f"{context} must be an object")
        _strict_config_keys(
            raw,
            {
                "enabled",
                "target_user",
                "from_source_accounts",
                "aliases",
                "exclusions",
                "conflict_policy",
                "admin_auth",
            },
            context,
        )
        if "enabled" not in raw:
            raise ValueError(f"{context}.enabled must be explicitly set")
        enabled = _bool_value(raw["enabled"], f"{context}.enabled")
        if not enabled:
            if set(raw) != {"enabled"}:
                raise ValueError(f"{context} settings require {context}.enabled=true")
            return WorkspaceAliasesConfig()
        target_user = _workspace_email(raw.get("target_user"), f"{context}.target_user")
        from_source_accounts = _bool_value(
            raw.get("from_source_accounts", True),
            f"{context}.from_source_accounts",
        )
        aliases = _workspace_alias_email_list(raw, "aliases", context)
        exclusions = _workspace_email_list(raw, "exclusions", context)
        conflict_policy = raw.get("conflict_policy")
        if conflict_policy != "create_only":
            raise ValueError(f"{context}.conflict_policy must be 'create_only'")
        admin_auth = WorkspaceAliasAdminAuthConfig.from_dict(
            raw.get("admin_auth"),
            context=f"{context}.admin_auth",
            base_dir=base_dir,
        )
        if not from_source_accounts and not aliases:
            raise ValueError(
                f"{context} must enable from_source_accounts or configure aliases"
            )
        return WorkspaceAliasesConfig(
            enabled=True,
            target_user=target_user,
            from_source_accounts=from_source_accounts,
            aliases=aliases,
            exclusions=exclusions,
            conflict_policy=conflict_policy,
            admin_auth=admin_auth,
        )


@dataclasses.dataclass
class ProviderEndpoint:
    provider: str
    host: str
    port: int = 993
    ssl: bool = True
    starttls: bool = False
    auth: AuthConfig = dataclasses.field(default_factory=lambda: AuthConfig(method="password"))
    gmail_api_auth: Optional[AuthConfig] = None
    available_bytes: Optional[int] = None
    gmail_full_visibility_verified: bool = False
    workspace_aliases: WorkspaceAliasesConfig = dataclasses.field(default_factory=WorkspaceAliasesConfig)

    @staticmethod
    def from_dict(raw: Dict[str, Any], *, context: str, base_dir: Optional[Path] = None) -> "ProviderEndpoint":
        if not isinstance(raw, dict):
            raise ValueError(f"{context} must be an object")
        _strict_config_keys(
            raw,
            {
                "provider",
                "host",
                "port",
                "ssl",
                "starttls",
                "auth",
                "gmail_api_auth",
                "available_bytes",
                "gmail_full_visibility_verified",
                "workspace_aliases",
            },
            context,
        )
        provider = raw.get("provider")
        if not provider or not isinstance(provider, str):
            raise ValueError(f"{context}.provider must be a non-empty string")
        provider = provider.strip().lower()
        if provider not in {"gmail", "icloud", "imap"}:
            raise ValueError(f"{context}.provider must be one of: gmail, icloud, imap")
        host = raw.get("host")
        if not isinstance(host, str) or not host.strip():
            raise ValueError(f"{context}.host must be a non-empty string")
        host = host.strip()
        port = _int_value(raw.get("port", 993), f"{context}.port", min_value=1, max_value=65535)
        use_ssl = _bool_value(raw.get("ssl", True), f"{context}.ssl")
        starttls = _bool_value(raw.get("starttls", False), f"{context}.starttls")
        auth = AuthConfig.from_dict(
            raw.get("auth"),
            context=f"{context}.auth",
            required=True,
            base_dir=base_dir,
        )
        assert auth is not None
        gmail_api_auth = AuthConfig.from_dict(
            raw.get("gmail_api_auth"),
            context=f"{context}.gmail_api_auth",
            required=False,
            base_dir=base_dir,
        )
        available_bytes = raw.get("available_bytes")
        if available_bytes is not None:
            available_bytes = _int_value(available_bytes, f"{context}.available_bytes", min_value=0)
        gmail_full_visibility_verified = _bool_value(
            raw.get("gmail_full_visibility_verified", False),
            f"{context}.gmail_full_visibility_verified",
        )
        if context != "target" and "workspace_aliases" in raw:
            raise ValueError("workspace_aliases is valid only under target")
        workspace_aliases = WorkspaceAliasesConfig.from_dict(
            raw.get("workspace_aliases"),
            context=f"{context}.workspace_aliases",
            base_dir=base_dir,
        )
        endpoint = ProviderEndpoint(
            provider=provider,
            host=host,
            port=port,
            ssl=use_ssl,
            starttls=starttls,
            auth=auth,
            gmail_api_auth=gmail_api_auth,
            available_bytes=available_bytes,
            gmail_full_visibility_verified=gmail_full_visibility_verified,
            workspace_aliases=workspace_aliases,
        )
        endpoint.validate_provider_contract(context=context)
        return endpoint

    def validate_provider_contract(self, *, context: str) -> None:
        expected_hosts = {"gmail": "imap.gmail.com", "icloud": "imap.mail.me.com"}
        host_key = self.host.strip().lower().rstrip(".")
        if self.provider != "gmail" and self.gmail_full_visibility_verified:
            raise ValueError(f"{context}.gmail_full_visibility_verified is only valid for provider 'gmail'")
        if self.workspace_aliases.enabled and self.provider != "gmail":
            raise ValueError(f"{context}.workspace_aliases requires provider 'gmail'")
        if self.workspace_aliases.enabled:
            if context != "target":
                raise ValueError("workspace_aliases is valid only under target")
            if self.workspace_aliases.admin_auth is None:
                raise ValueError(f"{context}.workspace_aliases.admin_auth must be configured")
            self.workspace_aliases.admin_auth.validate(
                context=f"{context}.workspace_aliases.admin_auth"
            )
        if self.gmail_api_auth is not None:
            if self.provider != "gmail":
                raise ValueError(f"{context}.gmail_api_auth is only valid for provider 'gmail'")
            if self.gmail_api_auth.method != "xoauth2":
                raise ValueError(f"{context}.gmail_api_auth.method must be 'xoauth2'")
            self.gmail_api_auth.validate(context=f"{context}.gmail_api_auth")
            if self.gmail_api_auth.secret_source_count() == 0:
                raise ValueError(f"{context}.gmail_api_auth must provide a bearer token source")
        if self.provider == "imap":
            known_provider = {
                host: provider
                for provider, host in expected_hosts.items()
            }.get(host_key)
            if known_provider:
                raise ValueError(
                    f"{context}.host {self.host!r} is the known {known_provider} IMAP host; "
                    f"use provider {known_provider!r} so provider-specific safeguards run"
                )
            if self.ssl and self.starttls:
                raise ValueError(f"{context}.ssl and {context}.starttls cannot both be true")
            if not self.ssl and not self.starttls:
                raise ValueError(
                    f"{context}.ssl or {context}.starttls must be true; "
                    "cleartext IMAP authentication is not allowed"
                )
            self.validate_auth_method(self.auth, context=f"{context}.auth")
            return
        if host_key != expected_hosts[self.provider]:
            raise ValueError(f"{context}.host must be {expected_hosts[self.provider]!r} for provider {self.provider!r}")
        if self.port != 993:
            raise ValueError(f"{context}.port must be 993 for provider {self.provider!r}")
        if not self.ssl:
            raise ValueError(f"{context}.ssl must be true for provider {self.provider!r}")
        if self.starttls:
            raise ValueError(f"{context}.starttls must be false; provider IMAP uses implicit SSL on port 993")
        self.host = expected_hosts[self.provider]
        self.validate_auth_method(self.auth, context=f"{context}.auth")

    def validate_auth_method(self, auth: AuthConfig, *, context: str) -> None:
        allowed_methods = {
            "gmail": {"xoauth2", "app_password"},
            "icloud": {"app_password"},
            "imap": {"password", "app_password", "xoauth2"},
        }[self.provider]
        if auth.method not in allowed_methods:
            methods = ", ".join(sorted(allowed_methods))
            raise ValueError(f"{context}.method must be one of: {methods}")


@dataclasses.dataclass
class MigrationAccount:
    source_email: str
    target_email: str
    source_auth: Optional[AuthConfig] = None
    target_auth: Optional[AuthConfig] = None
    target_gmail_api_auth: Optional[AuthConfig] = None
    gmail_full_visibility_verified: bool = False
    target_gmail_full_visibility_verified: bool = False

    @property
    def email(self) -> str:
        return f"{self.source_email}->{self.target_email}"

    @staticmethod
    def from_dict(raw: Dict[str, Any], *, index: int, base_dir: Optional[Path] = None) -> "MigrationAccount":
        if not isinstance(raw, dict):
            raise ValueError(f"accounts[{index}] must be an object")
        _strict_config_keys(
            raw,
            {
                "source_email",
                "target_email",
                "source_auth",
                "target_auth",
                "target_gmail_api_auth",
                "gmail_full_visibility_verified",
                "target_gmail_full_visibility_verified",
            },
            f"accounts[{index}]",
        )
        source_email = raw.get("source_email")
        target_email = raw.get("target_email")
        if not isinstance(source_email, str) or not source_email.strip():
            raise ValueError(f"accounts[{index}].source_email must be a non-empty string")
        if not isinstance(target_email, str) or not target_email.strip():
            raise ValueError(f"accounts[{index}].target_email must be a non-empty string")
        source_email = source_email.strip()
        target_email = target_email.strip()
        return MigrationAccount(
            source_email=source_email,
            target_email=target_email,
            source_auth=AuthConfig.from_dict(raw.get("source_auth"), context=f"accounts[{index}].source_auth", required=False, base_dir=base_dir),
            target_auth=AuthConfig.from_dict(raw.get("target_auth"), context=f"accounts[{index}].target_auth", required=False, base_dir=base_dir),
            target_gmail_api_auth=AuthConfig.from_dict(
                raw.get("target_gmail_api_auth"),
                context=f"accounts[{index}].target_gmail_api_auth",
                required=False,
                base_dir=base_dir,
            ),
            gmail_full_visibility_verified=_bool_value(
                raw.get("gmail_full_visibility_verified", False),
                f"accounts[{index}].gmail_full_visibility_verified",
            ),
            target_gmail_full_visibility_verified=_bool_value(
                raw.get("target_gmail_full_visibility_verified", False),
                f"accounts[{index}].target_gmail_full_visibility_verified",
            ),
        )


@dataclasses.dataclass
class MigrationSettings:
    label_policy: str = "single_copy_preserve_metadata"
    target_mode: str = "empty"
    account_merge_mode: str = "one_to_one"
    folder_map: Dict[str, str] = dataclasses.field(default_factory=dict)
    validation: str = "manifest_exact"
    routing: RoutingConfig = dataclasses.field(default_factory=RoutingConfig)

    @staticmethod
    def from_dict(raw: Optional[Dict[str, Any]]) -> "MigrationSettings":
        if raw is None:
            return MigrationSettings()
        if not isinstance(raw, dict):
            raise ValueError("migration must be an object")
        _strict_config_keys(
            raw,
            {
                "label_policy",
                "target_mode",
                "account_merge_mode",
                "folder_map",
                "validation",
                "routing",
            },
            "migration",
        )
        label_policy = str(raw.get("label_policy", "single_copy_preserve_metadata"))
        if label_policy != "single_copy_preserve_metadata":
            raise ValueError("migration.label_policy must be 'single_copy_preserve_metadata'")
        target_mode = str(raw.get("target_mode", "empty")).lower()
        if target_mode not in {"empty", "merge"}:
            raise ValueError("migration.target_mode must be one of: empty, merge")
        account_merge_mode = str(raw.get("account_merge_mode", "one_to_one")).lower()
        if account_merge_mode not in {"one_to_one", "many_to_one"}:
            raise ValueError("migration.account_merge_mode must be one of: one_to_one, many_to_one")
        folder_map_raw = raw.get("folder_map", {})
        if not isinstance(folder_map_raw, dict):
            raise ValueError("migration.folder_map must be an object")
        folder_map: Dict[str, str] = {}
        for key, value in folder_map_raw.items():
            if not isinstance(key, str) or not key.strip():
                raise ValueError("migration.folder_map keys must be non-empty strings")
            if not isinstance(value, str) or not value.strip():
                raise ValueError("migration.folder_map values must be non-empty strings")
            folder_map[key] = value
        validation = str(raw.get("validation", "manifest_exact"))
        if validation != "manifest_exact":
            raise ValueError("migration.validation must be 'manifest_exact'")
        return MigrationSettings(
            label_policy=label_policy,
            target_mode=target_mode,
            account_merge_mode=account_merge_mode,
            folder_map=folder_map,
            validation=validation,
            routing=RoutingConfig.from_dict(raw.get("routing")),
        )


@dataclasses.dataclass
class ThrottleSettings:
    max_bytes_per_second: int = 0

    @staticmethod
    def from_dict(raw: Optional[Dict[str, Any]]) -> "ThrottleSettings":
        if raw is None:
            return ThrottleSettings()
        if not isinstance(raw, dict):
            raise ValueError("limits.throttle must be an object")
        _strict_config_keys(
            raw,
            {"max_bytes_per_second"},
            "limits.throttle",
        )
        max_bps = _int_value(raw.get("max_bytes_per_second", 0), "limits.throttle.max_bytes_per_second", min_value=0)
        return ThrottleSettings(max_bytes_per_second=max_bps)


@dataclasses.dataclass
class LimitsSettings:
    throttle: ThrottleSettings = dataclasses.field(default_factory=ThrottleSettings)
    retry_max_attempts: int = 5

    @staticmethod
    def from_dict(raw: Optional[Dict[str, Any]]) -> "LimitsSettings":
        if raw is None:
            return LimitsSettings()
        if not isinstance(raw, dict):
            raise ValueError("limits must be an object")
        _strict_config_keys(
            raw,
            {"throttle", "retry_max_attempts"},
            "limits",
        )
        retry_max_attempts = _int_value(raw.get("retry_max_attempts", 5), "limits.retry_max_attempts", min_value=1)
        return LimitsSettings(
            throttle=ThrottleSettings.from_dict(raw.get("throttle")),
            retry_max_attempts=retry_max_attempts,
        )


def _effective_auth_username(endpoint: ProviderEndpoint, account: MigrationAccount, *, role: str) -> str:
    override = account.source_auth if role == "source" else account.target_auth
    auth = override or endpoint.auth
    fallback_email = account.source_email if role == "source" else account.target_email
    username = auth.username or endpoint.auth.username
    if not username and endpoint.provider == "icloud" and "@" in fallback_email:
        username = fallback_email.split("@", 1)[0]
    if not username:
        username = fallback_email
    return username.strip()


def effective_gmail_api_auth(
    endpoint: ProviderEndpoint,
    account: MigrationAccount,
) -> Optional[AuthConfig]:
    """Return the bearer-token source used for Gmail label/filter APIs.

    A dedicated API token wins.  For convenience, an existing target XOAUTH2
    token is reused when it was minted with the additional Gmail API scopes.
    App passwords can never authorize the Gmail REST API.
    """

    auth = account.target_gmail_api_auth or endpoint.gmail_api_auth
    if auth is not None:
        return auth
    target_auth = account.target_auth or endpoint.auth
    return target_auth if target_auth.method == "xoauth2" else None


def auth_username_identity(endpoint: ProviderEndpoint, username: str) -> str:
    username = username.strip()
    if endpoint.provider == "gmail":
        identity = username.lower()
        local, sep, domain = identity.partition("@")
        if sep and domain in {"gmail.com", "googlemail.com"}:
            return f"{local.replace('.', '')}@gmail.com"
        return identity
    if endpoint.provider == "icloud":
        local, sep, domain = username.partition("@")
        if sep and domain.lower() in {"icloud.com", "me.com", "mac.com"}:
            return local
    return username


@dataclasses.dataclass
class ProviderMigrationConfig:
    source: ProviderEndpoint
    target: ProviderEndpoint
    accounts: List[MigrationAccount]
    migration: MigrationSettings = dataclasses.field(default_factory=MigrationSettings)
    limits: LimitsSettings = dataclasses.field(default_factory=LimitsSettings)

    @staticmethod
    def from_json_file(path: Path) -> "ProviderMigrationConfig":
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("Config root must be an object")
        return ProviderMigrationConfig.from_dict(data, base_dir=path.parent)

    @staticmethod
    def from_dict(data: Dict[str, Any], *, base_dir: Optional[Path] = None) -> "ProviderMigrationConfig":
        if not isinstance(data, dict):
            raise ValueError("Config root must be an object")
        _strict_config_keys(
            data,
            {"source", "target", "accounts", "migration", "limits"},
            "provider config",
        )
        source_raw = data.get("source")
        target_raw = data.get("target")
        if source_raw is None or target_raw is None:
            raise ValueError("Provider config must include 'source' and 'target' objects")
        accounts_raw = data.get("accounts")
        if not isinstance(accounts_raw, list) or not accounts_raw:
            raise ValueError("Config must include non-empty 'accounts' array")
        config = ProviderMigrationConfig(
            source=ProviderEndpoint.from_dict(source_raw, context="source", base_dir=base_dir),
            target=ProviderEndpoint.from_dict(target_raw, context="target", base_dir=base_dir),
            accounts=[MigrationAccount.from_dict(item, index=idx, base_dir=base_dir) for idx, item in enumerate(accounts_raw)],
            migration=MigrationSettings.from_dict(data.get("migration")),
            limits=LimitsSettings.from_dict(data.get("limits")),
        )
        config.validate_auth()
        return config

    def validate_auth(self) -> None:
        self.source.validate_provider_contract(context="source")
        self.target.validate_provider_contract(context="target")
        seen_sources: Dict[str, int] = {}
        seen_targets: Dict[str, int] = {}
        allow_target_duplicates = self.migration.account_merge_mode == "many_to_one"
        unique_target_keys = {auth_username_identity(self.target, account.target_email) for account in self.accounts}
        shared_single_target = allow_target_duplicates and len(unique_target_keys) == 1
        source_labels_by_username: Dict[str, Dict[str, int]] = {}
        target_usernames_by_target: Dict[str, Dict[str, int]] = {}
        target_labels_by_username: Dict[str, Dict[str, int]] = {}
        for idx, account in enumerate(self.accounts):
            source_key = auth_username_identity(self.source, account.source_email)
            target_key = auth_username_identity(self.target, account.target_email)
            if source_key in seen_sources:
                raise ValueError(f"accounts[{idx}].source_email duplicates accounts[{seen_sources[source_key]}].source_email")
            if target_key in seen_targets and not allow_target_duplicates:
                raise ValueError(f"accounts[{idx}].target_email duplicates accounts[{seen_targets[target_key]}].target_email")
            seen_sources[source_key] = idx
            seen_targets[target_key] = idx
            source_username_key = auth_username_identity(
                self.source,
                _effective_auth_username(self.source, account, role="source"),
            )
            target_username_key = auth_username_identity(
                self.target,
                _effective_auth_username(self.target, account, role="target"),
            )
            source_labels_by_username.setdefault(source_username_key, {}).setdefault(source_key, idx)
            target_usernames_by_target.setdefault(target_key, {}).setdefault(target_username_key, idx)
            target_labels_by_username.setdefault(target_username_key, {}).setdefault(target_key, idx)
        for username_key, source_indexes in sorted(source_labels_by_username.items()):
            if len(source_indexes) > 1:
                details = ", ".join(
                    f"accounts[{idx}]={source!r}"
                    for source, idx in sorted(source_indexes.items(), key=lambda item: item[1])
                )
                raise ValueError(
                    f"effective source_auth.username {username_key!r} is reused by multiple source_email labels "
                    f"({details})"
                )
        for username_key, target_indexes in sorted(target_labels_by_username.items()):
            if len(target_indexes) > 1:
                details = ", ".join(
                    f"accounts[{idx}]={target!r}"
                    for target, idx in sorted(target_indexes.items(), key=lambda item: item[1])
                )
                if allow_target_duplicates:
                    raise ValueError(
                        f"migration.account_merge_mode=many_to_one cannot reuse effective target_auth.username "
                        f"{username_key!r} across different target_email labels ({details}); use the same "
                        "target_email for accounts intentionally merging into that login"
                    )
                raise ValueError(
                    f"effective target_auth.username {username_key!r} is reused by multiple target_email labels "
                    f"({details}); set migration.account_merge_mode=many_to_one for intentional account merges"
                )
        if allow_target_duplicates:
            for target_key, username_indexes in sorted(target_usernames_by_target.items()):
                if len(username_indexes) > 1:
                    details = ", ".join(
                        f"accounts[{idx}]={username!r}"
                        for username, idx in sorted(username_indexes.items(), key=lambda item: item[1])
                    )
                    raise ValueError(
                        f"migration.account_merge_mode=many_to_one requires the same effective target_auth.username "
                        f"for every account targeting {target_key}: {details}"
                    )
        _reject_sanitized_path_collisions([account.source_email for account in self.accounts], context="accounts.source_email")
        _reject_sanitized_path_collisions([account.target_email for account in self.accounts], context="accounts.target_email")
        multi_account = len(self.accounts) > 1
        for idx, account in enumerate(self.accounts):
            for role, endpoint, override in (
                ("source", self.source, account.source_auth),
                ("target", self.target, account.target_auth),
            ):
                shared_target_login = role == "target" and shared_single_target
                auth = override or endpoint.auth
                endpoint.validate_auth_method(auth, context=f"accounts[{idx}].{role}_auth" if override else f"{role}.auth")
                if auth.secret_source_count() == 0:
                    raise ValueError(f"accounts[{idx}].{role}_auth must provide a secret source or {role}.auth must provide one")
                if multi_account and override is None and endpoint.auth.secret_source_count() > 0 and not shared_target_login:
                    raise ValueError(
                        f"accounts[{idx}].{role}_auth must be set in multi-account provider configs; "
                        f"endpoint-level provider secrets would be reused for every account"
                    )
                if multi_account and override is not None and endpoint.auth.username and not override.username and not shared_target_login:
                    raise ValueError(
                        f"accounts[{idx}].{role}_auth.username must be set in multi-account provider configs; "
                        f"endpoint-level provider username would be reused for every account"
                    )
                expected_email = account.source_email if role == "source" else account.target_email
                auth_username = auth.username or endpoint.auth.username
                if (
                    endpoint.provider in {"gmail", "icloud"}
                    and auth_username
                    and auth_username_identity(endpoint, auth_username) != auth_username_identity(endpoint, expected_email)
                ):
                    raise ValueError(
                        f"accounts[{idx}].{role}_auth.username must match {role}_email for {endpoint.provider} "
                        f"({expected_email})"
                    )
            if self.source.provider == "gmail" and multi_account and not account.gmail_full_visibility_verified:
                raise ValueError(
                    f"accounts[{idx}].gmail_full_visibility_verified must be true for multi-account Gmail source configs"
                )
            if self.source.provider != "gmail" and account.gmail_full_visibility_verified:
                raise ValueError(
                    f"accounts[{idx}].gmail_full_visibility_verified is only valid when source.provider is 'gmail'"
                )
            if (
                self.target.provider == "gmail"
                and multi_account
                and not account.target_gmail_full_visibility_verified
                and not (shared_single_target and self.target.gmail_full_visibility_verified)
            ):
                raise ValueError(
                    f"accounts[{idx}].target_gmail_full_visibility_verified must be true for multi-account Gmail target configs"
                )
            if self.target.provider != "gmail" and account.target_gmail_full_visibility_verified:
                raise ValueError(
                    f"accounts[{idx}].target_gmail_full_visibility_verified is only valid when target.provider is 'gmail'"
                )
            api_auth = account.target_gmail_api_auth
            if api_auth is not None:
                if self.target.provider != "gmail":
                    raise ValueError(
                        f"accounts[{idx}].target_gmail_api_auth is only valid when target.provider is 'gmail'"
                    )
                if api_auth.method != "xoauth2":
                    raise ValueError(f"accounts[{idx}].target_gmail_api_auth.method must be 'xoauth2'")
                if api_auth.secret_source_count() == 0:
                    raise ValueError(f"accounts[{idx}].target_gmail_api_auth must provide a bearer token source")
                if (
                    api_auth.username
                    and auth_username_identity(self.target, api_auth.username)
                    != auth_username_identity(self.target, account.target_email)
                ):
                    raise ValueError(
                        f"accounts[{idx}].target_gmail_api_auth.username must match target_email "
                        f"({account.target_email})"
                    )
        self.validate_routing()
        self.validate_workspace_aliases()

    def validate_routing(self) -> None:
        routing = self.migration.routing
        if not routing.enabled:
            return

        configured_sources = {
            account.source_email.casefold(): account for account in self.accounts
        }
        for configured_name in routing.accounts:
            key = configured_name.casefold()
            if key not in configured_sources:
                raise ValueError(
                    f"migration.routing.accounts contains unknown source account {configured_name!r}"
                )

        target_keys = {
            auth_username_identity(self.target, account.target_email)
            for account in self.accounts
        }
        if len(target_keys) != 1:
            raise ValueError(
                "migration.routing currently requires all configured accounts to share one target mailbox"
            )

        destinations: List[Any] = []
        for rule in routing.global_rules:
            destinations.extend(rule.destinations)
        has_custom_default = False
        for account_routing in routing.accounts.values():
            if account_routing.default_label or account_routing.default_namespace:
                has_custom_default = True
            for rule in account_routing.rules:
                destinations.extend(rule.destinations)

        has_custom = has_custom_default or any(destination.kind == CUSTOM_LABEL for destination in destinations)
        has_gmail_system = any(destination.kind == GMAIL_SYSTEM for destination in destinations)
        has_mailbox = any(destination.kind == GENERIC_MAILBOX for destination in destinations)

        if self.target.provider == "gmail":
            if has_mailbox:
                raise ValueError(
                    "migration.routing generic mailbox destinations are not valid for Gmail; "
                    "use custom_label or gmail_system"
                )
        else:
            if has_custom or has_gmail_system or routing.filters:
                raise ValueError(
                    "migration.routing custom labels, Gmail system destinations, and filters require target.provider='gmail'"
                )
            for rule in list(routing.global_rules) + [
                item
                for account_routing in routing.accounts.values()
                for item in account_routing.rules
            ]:
                if not rule.exclude and len(rule.destinations) != 1:
                    raise ValueError(
                        "non-Gmail routing rules must select exactly one generic mailbox destination"
                    )

        if self.target.provider == "gmail" and routing.filters:
            # Import locally so the low-level Gmail module remains independent
            # of provider configuration and routing modules.
            from .gmail_api import canonical_filter_email

            filter_condition_indexes: Dict[str, int] = {}
            for index, rule in enumerate(routing.filters):
                condition = canonical_filter_email(
                    rule.delivered_to,
                    f"migration.routing.filters[{index}].delivered_to",
                )
                previous_index = filter_condition_indexes.get(condition)
                if previous_index is not None:
                    raise ValueError(
                        "multiple migration.routing.filters resolve to the same Gmail "
                        f"delivered-to condition {condition!r} after case/IDNA "
                        f"canonicalization: filters {previous_index} and {index}; "
                        "configure one deterministic action"
                    )
                filter_condition_indexes[condition] = index

        if self.target.provider == "gmail" and (has_custom or routing.filters):
            representative = self.accounts[0]
            api_auth = effective_gmail_api_auth(self.target, representative)
            if api_auth is None:
                required_scopes = [
                    "https://www.googleapis.com/auth/gmail.labels (or gmail.modify/mail.google.com)"
                ]
                if routing.filters:
                    required_scopes.append(
                        "https://www.googleapis.com/auth/gmail.settings.basic"
                    )
                raise ValueError(
                    "migration.routing custom labels/filters require Gmail API OAuth authorization; configure "
                    "target.gmail_api_auth or accounts[].target_gmail_api_auth with a bearer token that grants "
                    + " and ".join(required_scopes)
                    + "; app passwords cannot authorize the Gmail REST API"
                )
            if (
                api_auth.username
                and auth_username_identity(self.target, api_auth.username)
                != auth_username_identity(self.target, representative.target_email)
            ):
                raise ValueError(
                    "effective Gmail API authorization username must match the shared target_email "
                    f"({representative.target_email})"
                )

    def workspace_alias_candidates(self) -> Tuple[str, ...]:
        """Return the canonical, deterministic alias intent from configuration."""

        settings = self.target.workspace_aliases
        if not settings.enabled:
            return ()
        if settings.target_user is None:
            raise ValueError("target.workspace_aliases.target_user must be configured")
        candidates = set(settings.aliases)
        if settings.from_source_accounts:
            for index, account in enumerate(self.accounts):
                source = _workspace_email(
                    account.source_email,
                    f"accounts[{index}].source_email",
                )
                if source != settings.target_user:
                    candidates.add(source)
        candidates.difference_update(settings.exclusions)
        return tuple(
            sorted(
                _workspace_alias_email(alias, "target.workspace_aliases candidate")
                for alias in candidates
            )
        )

    def validate_workspace_aliases(self) -> None:
        settings = self.target.workspace_aliases
        if not settings.enabled:
            return
        if self.target.provider != "gmail":
            raise ValueError("target.workspace_aliases requires target.provider='gmail'")
        if settings.target_user is None:
            raise ValueError("target.workspace_aliases.target_user must be configured")
        if settings.conflict_policy != "create_only":
            raise ValueError(
                "target.workspace_aliases.conflict_policy must be 'create_only'"
            )
        if settings.admin_auth is None:
            raise ValueError("target.workspace_aliases.admin_auth must be configured")
        settings.admin_auth.validate(context="target.workspace_aliases.admin_auth")

        target_users = {
            _workspace_email(account.target_email, f"accounts[{index}].target_email")
            for index, account in enumerate(self.accounts)
        }
        if len(target_users) != 1:
            raise ValueError(
                "target.workspace_aliases requires all configured accounts to share one target mailbox"
            )
        configured_target = next(iter(target_users))
        if settings.target_user != configured_target:
            raise ValueError(
                "target.workspace_aliases.target_user must match the shared target_email "
                f"({self.accounts[0].target_email})"
            )

        aliases = self.workspace_alias_candidates()
        if not aliases:
            raise ValueError(
                "target.workspace_aliases resolves to no aliases after exclusions"
            )
        if configured_target in aliases:
            raise ValueError(
                "target.workspace_aliases cannot activate the target user as its own alias"
            )
        if not self.migration.routing.enabled:
            raise ValueError(
                "target.workspace_aliases requires migration.routing.enabled=true and one "
                "delivered_to filter per alias"
            )
        canonical_filters = []
        delivered_to_indexes: Dict[str, int] = {}
        for index, rule in enumerate(self.migration.routing.filters):
            canonical_delivered_to = _workspace_email(
                rule.delivered_to,
                f"migration.routing.filters[{index}].delivered_to",
            )
            previous_index = delivered_to_indexes.get(canonical_delivered_to)
            if previous_index is not None:
                raise ValueError(
                    "multiple migration.routing.filters normalize to the same "
                    f"delivered_to {canonical_delivered_to!r}: filters "
                    f"{previous_index} and {index}; configure one deterministic action"
                )
            delivered_to_indexes[canonical_delivered_to] = index
            canonical_filters.append(
                dataclasses.replace(rule, delivered_to=canonical_delivered_to)
            )
        if tuple(canonical_filters) != self.migration.routing.filters:
            self.migration.routing = dataclasses.replace(
                self.migration.routing,
                filters=tuple(canonical_filters),
            )
        delivered_to = set(delivered_to_indexes)
        missing_filters = [alias for alias in aliases if alias not in delivered_to]
        if missing_filters:
            raise ValueError(
                "target.workspace_aliases requires a matching "
                "migration.routing.filters[].delivered_to for every alias; missing: "
                + ", ".join(missing_filters)
            )


@dataclasses.dataclass
class Config:
    server: ServerConfig
    accounts: List[Account]
    source_server: Optional[ServerConfig] = None

    @staticmethod
    def from_json_file(path: Path) -> "Config":
        """Load `Config` from a JSON file with keys: server, accounts[]."""
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, dict):
            raise ValueError("Config root must be an object")

        server = _server_config_from_dict(data.get("server"), context="server")
        source_server = None
        if "source_server" in data and data.get("source_server") is not None:
            source_server = _server_config_from_dict(
                data.get("source_server"),
                context="source_server",
                require_encrypted=False,
            )

        accounts_raw = data.get("accounts")
        if not isinstance(accounts_raw, list) or not accounts_raw:
            raise ValueError("Config must include non-empty 'accounts' array")
        accounts: List[Account] = []
        seen_accounts: Dict[str, int] = {}
        for idx, item in enumerate(accounts_raw):
            if not isinstance(item, dict):
                raise ValueError(f"accounts[{idx}] must be an object")
            email = item.get("email")
            password = item.get("password")
            if not isinstance(email, str) or not email.strip():
                raise ValueError(f"accounts[{idx}].email must be a non-empty string")
            email = email.strip()
            if not isinstance(password, str):
                raise ValueError(f"accounts[{idx}].password must be a string (can be empty)")
            email_key = email.strip()
            if email_key in seen_accounts:
                raise ValueError(f"accounts[{idx}].email duplicates accounts[{seen_accounts[email_key]}].email")
            seen_accounts[email_key] = idx
            accounts.append(Account(email=email, password=password))
        _reject_sanitized_path_collisions([account.email for account in accounts], context="accounts.email")

        return Config(server=server, accounts=accounts, source_server=source_server)


def _server_config_from_dict(
    raw: Any,
    *,
    context: str,
    require_encrypted: bool = True,
) -> ServerConfig:
    if not isinstance(raw, dict):
        raise ValueError(f"Config must include '{context}' object" if context == "server" else f"{context} must be an object")
    host = raw.get("host")
    if not isinstance(host, str) or not host.strip():
        raise ValueError(f"{context}.host must be a non-empty string")
    host = host.strip()
    host_key = host.strip().lower().rstrip(".")
    known_provider_hosts = {"imap.gmail.com": "gmail", "imap.mail.me.com": "icloud"}
    if host_key in known_provider_hosts:
        provider = known_provider_hosts[host_key]
        raise ValueError(
            f"{context}.host {host!r} is the known {provider} IMAP host; "
            "use provider config mode so provider-specific safeguards run"
        )
    port = _int_value(raw.get("port", 993), f"{context}.port", min_value=1, max_value=65535)
    use_ssl = _bool_value(raw.get("ssl", True), f"{context}.ssl")
    starttls = _bool_value(raw.get("starttls", False), f"{context}.starttls")
    if use_ssl and starttls:
        raise ValueError(f"{context}.ssl and {context}.starttls cannot both be true")
    if require_encrypted and not use_ssl and not starttls:
        raise ValueError(
            f"{context}.ssl or {context}.starttls must be true; "
            "cleartext IMAP authentication is not allowed"
        )
    return ServerConfig(host=host, port=port, ssl=use_ssl, starttls=starttls)


def is_provider_config_file(path: Path) -> bool:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    return isinstance(data, dict) and "source" in data and "target" in data


def load_config_file(path: Path) -> Union[Config, ProviderMigrationConfig]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict) and "source" in data and "target" in data:
        return ProviderMigrationConfig.from_dict(data, base_dir=path.parent)
    return Config.from_json_file(path)


def _optional_str(raw: Dict[str, Any], key: str, context: str) -> Optional[str]:
    value = raw.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{context}.{key} must be a string")
    value = value.strip()
    if not value:
        raise ValueError(f"{context}.{key} must be a non-empty string")
    return value


def _optional_secret_str(raw: Dict[str, Any], key: str, context: str) -> Optional[str]:
    value = raw.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{context}.{key} must be a string")
    if value == "":
        raise ValueError(f"{context}.{key} must be a non-empty string")
    return value


def _optional_path_str(raw: Dict[str, Any], key: str, context: str, base_dir: Optional[Path]) -> Optional[str]:
    value = _optional_str(raw, key, context)
    if value is None:
        return None
    path = Path(value)
    if not path.is_absolute() and base_dir is not None:
        path = base_dir / path
    return str(path)


def _bool_value(value: Any, context: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{context} must be a boolean")
    return value


def _int_value(value: Any, context: str, *, min_value: Optional[int] = None, max_value: Optional[int] = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{context} must be an integer")
    if min_value is not None and value < min_value:
        raise ValueError(f"{context} must be >= {min_value}")
    if max_value is not None and value > max_value:
        raise ValueError(f"{context} must be <= {max_value}")
    return value
