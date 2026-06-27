from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

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
                raise ValueError(f"{context}.auth must be an object")
            return None
        if not isinstance(raw, dict):
            raise ValueError(f"{context}.auth must be an object")
        method = raw.get("method")
        if not method or not isinstance(method, str):
            raise ValueError(f"{context}.auth.method must be a non-empty string")
        method = method.strip().lower()
        if method not in {"password", "app_password", "xoauth2"}:
            raise ValueError(f"{context}.auth.method must be one of: password, app_password, xoauth2")
        auth = AuthConfig(
            method=method,
            username=_optional_str(raw, "username", f"{context}.auth"),
            password=_optional_secret_str(raw, "password", f"{context}.auth"),
            password_file=_optional_path_str(raw, "password_file", f"{context}.auth", base_dir),
            token_file=_optional_path_str(raw, "token_file", f"{context}.auth", base_dir),
            env_var=_optional_str(raw, "env_var", f"{context}.auth"),
        )
        auth.validate(context=f"{context}.auth")
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


@dataclasses.dataclass
class ProviderEndpoint:
    provider: str
    host: str
    port: int = 993
    ssl: bool = True
    starttls: bool = False
    auth: AuthConfig = dataclasses.field(default_factory=lambda: AuthConfig(method="password"))
    available_bytes: Optional[int] = None
    gmail_full_visibility_verified: bool = False

    @staticmethod
    def from_dict(raw: Dict[str, Any], *, context: str, base_dir: Optional[Path] = None) -> "ProviderEndpoint":
        if not isinstance(raw, dict):
            raise ValueError(f"{context} must be an object")
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
        auth = AuthConfig.from_dict(raw.get("auth"), context=context, required=True, base_dir=base_dir)
        assert auth is not None
        available_bytes = raw.get("available_bytes")
        if available_bytes is not None:
            available_bytes = _int_value(available_bytes, f"{context}.available_bytes", min_value=0)
        gmail_full_visibility_verified = _bool_value(
            raw.get("gmail_full_visibility_verified", False),
            f"{context}.gmail_full_visibility_verified",
        )
        endpoint = ProviderEndpoint(
            provider=provider,
            host=host,
            port=port,
            ssl=use_ssl,
            starttls=starttls,
            auth=auth,
            available_bytes=available_bytes,
            gmail_full_visibility_verified=gmail_full_visibility_verified,
        )
        endpoint.validate_provider_contract(context=context)
        return endpoint

    def validate_provider_contract(self, *, context: str) -> None:
        expected_hosts = {"gmail": "imap.gmail.com", "icloud": "imap.mail.me.com"}
        host_key = self.host.strip().lower().rstrip(".")
        if self.provider != "gmail" and self.gmail_full_visibility_verified:
            raise ValueError(f"{context}.gmail_full_visibility_verified is only valid for provider 'gmail'")
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
    gmail_full_visibility_verified: bool = False
    target_gmail_full_visibility_verified: bool = False

    @property
    def email(self) -> str:
        return f"{self.source_email}->{self.target_email}"

    @staticmethod
    def from_dict(raw: Dict[str, Any], *, index: int, base_dir: Optional[Path] = None) -> "MigrationAccount":
        if not isinstance(raw, dict):
            raise ValueError(f"accounts[{index}] must be an object")
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

    @staticmethod
    def from_dict(raw: Optional[Dict[str, Any]]) -> "MigrationSettings":
        if raw is None:
            return MigrationSettings()
        if not isinstance(raw, dict):
            raise ValueError("migration must be an object")
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
            target_username_key = auth_username_identity(
                self.target,
                _effective_auth_username(self.target, account, role="target"),
            )
            target_usernames_by_target.setdefault(target_key, {}).setdefault(target_username_key, idx)
            target_labels_by_username.setdefault(target_username_key, {}).setdefault(target_key, idx)
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
            source_server = _server_config_from_dict(data.get("source_server"), context="source_server")

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


def _server_config_from_dict(raw: Any, *, context: str) -> ServerConfig:
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
