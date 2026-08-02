"""Safe Google Workspace user-alias discovery and create-only provisioning.

This module is intentionally independent of migration configuration models.
Callers must opt in explicitly by supplying one target user and the complete
requested alias set.  Planning performs only Directory API reads; execution
re-discovers before the first write, creates missing aliases in deterministic
order, and verifies ownership afterward.  It never deletes or reassigns an
identity.
"""

from __future__ import annotations

import copy
import dataclasses
import email.utils
import hashlib
import json
import math
import random
import re
import time
import urllib.parse
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Mapping, Optional, Sequence, Tuple

import idna

from .secret_files import read_secret_file_no_links

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover - broken installations only
    requests = None  # type: ignore

try:  # Optional at import time; required only for service-account auth.
    from google.auth.transport.requests import Request as GoogleAuthRequest  # type: ignore
    from google.oauth2 import service_account as google_service_account  # type: ignore
except Exception:  # pragma: no cover - exercised when optional dependency is absent
    GoogleAuthRequest = None  # type: ignore
    google_service_account = None  # type: ignore


WORKSPACE_ALIAS_PLAN_FILENAME = "workspace-alias-plan.json"
DEFAULT_DIRECTORY_API_BASE_URL = "https://admin.googleapis.com/admin/directory/v1"
MAX_WORKSPACE_USER_ALIASES = 30

WORKSPACE_USER_ALIAS_SCOPE = (
    "https://www.googleapis.com/auth/admin.directory.user.alias"
)
WORKSPACE_USER_READONLY_SCOPE = (
    "https://www.googleapis.com/auth/admin.directory.user.readonly"
)
WORKSPACE_GROUP_READONLY_SCOPE = (
    "https://www.googleapis.com/auth/admin.directory.group.readonly"
)
WORKSPACE_DOMAIN_READONLY_SCOPE = (
    "https://www.googleapis.com/auth/admin.directory.domain.readonly"
)
WORKSPACE_DIRECTORY_SCOPES = (
    WORKSPACE_USER_ALIAS_SCOPE,
    WORKSPACE_USER_READONLY_SCOPE,
    WORKSPACE_GROUP_READONLY_SCOPE,
    WORKSPACE_DOMAIN_READONLY_SCOPE,
)

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_SAFE_GOOGLE_REASON_RE = re.compile(r"^[A-Za-z0-9_.-]{1,80}$", flags=re.ASCII)
_WORKSPACE_ALIAS_LOCAL_RE = re.compile(r"^[a-z0-9._'-]+$", flags=re.ASCII)
_WORKSPACE_RESERVED_ALIAS_LOCALS = frozenset({"abuse", "postmaster"})
_RETRYABLE_GOOGLE_REASONS = frozenset(
    {
        "backend_error",
        "backenderror",
        "quota_exceeded",
        "quotaexceeded",
        "rate_limit_exceeded",
        "ratelimitexceeded",
        "resource_exhausted",
        "user_rate_limit_exceeded",
        "userratelimitexceeded",
    }
)
_QUOTA_RATE_GOOGLE_REASONS = frozenset(
    {
        "daily_limit_exceeded",
        "dailylimitexceeded",
        "dailylimitexceededunreg",
        "mail_rate_limit_exceeded",
        "mailratelimitexceeded",
        "quota_exceeded",
        "quotaexceeded",
        "rate_limit_exceeded",
        "ratelimitexceeded",
        "resource_exhausted",
        "user_rate_limit_exceeded",
        "userratelimitexceeded",
    }
)
_SAFE_GOOGLE_REASON_KEYS = frozenset(
    set(_RETRYABLE_GOOGLE_REASONS)
    | set(_QUOTA_RATE_GOOGLE_REASONS)
    | {
        "access_token_scope_insufficient",
        "autherror",
        "deadline_exceeded",
        "forbidden",
        "insufficientpermissions",
        "internal",
        "invalidcredentials",
        "permission_denied",
        "service_disabled",
        "unauthenticated",
        "unavailable",
    }
)
_RETRYABLE_HTTP_STATUSES = frozenset({408, 429, 500, 502, 503, 504})
_SAFE_RETRY_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "DELETE"})


def _text(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{context} must be a non-empty string")
    if value != value.strip():
        raise ValueError(f"{context} must not have leading or trailing whitespace")
    if _CONTROL_RE.search(value):
        raise ValueError(f"{context} must not contain control characters")
    return value


def canonical_workspace_email(value: Any, context: str = "email") -> str:
    """Return the exact case-insensitive Workspace identity key."""

    address = _text(value, context)
    if address.count("@") != 1:
        raise ValueError(f"{context} must be a valid email address")
    local, domain = address.rsplit("@", 1)
    if not local or len(local) > 64 or not domain or any(char.isspace() for char in address):
        raise ValueError(f"{context} must be a valid email address")
    if local.startswith(".") or local.endswith(".") or ".." in local:
        raise ValueError(f"{context} has an invalid local part")
    try:
        ascii_domain = idna.encode(
            domain,
            uts46=True,
            transitional=False,
            std3_rules=True,
        ).decode("ascii").casefold()
    except (idna.IDNAError, UnicodeError, ValueError):
        raise ValueError(f"{context} has an invalid domain") from None
    if len(ascii_domain) > 253 or "." not in ascii_domain:
        raise ValueError(f"{context} has an invalid domain")
    for label in ascii_domain.split("."):
        if (
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not all(char.isalnum() or char == "-" for char in label)
        ):
            raise ValueError(f"{context} has an invalid domain")
    canonical = f"{local.casefold()}@{ascii_domain}"
    try:
        canonical_octets = canonical.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError(f"{context} must contain an ASCII local part") from None
    if len(canonical_octets) > 254:
        raise ValueError(f"{context} must be at most 254 ASCII octets after IDNA canonicalization")
    return canonical


def canonical_workspace_alias_email(value: Any, context: str = "alias") -> str:
    """Return a canonical address valid for a Workspace user alias."""

    address = canonical_workspace_email(value, context)
    local = address.rsplit("@", 1)[0]
    if _WORKSPACE_ALIAS_LOCAL_RE.fullmatch(local) is None:
        raise ValueError(
            f"{context} local part may contain only ASCII letters, numbers, periods, "
            "dashes, underscores, and apostrophes for a Workspace alias"
        )
    if local in _WORKSPACE_RESERVED_ALIAS_LOCALS:
        raise ValueError(f"{context} uses reserved Workspace alias local part {local!r}")
    return address


def _canonical_domain(value: Any, context: str = "domain") -> str:
    text = _text(value, context)
    try:
        result = idna.encode(
            text,
            uts46=True,
            transitional=False,
            std3_rules=True,
        ).decode("ascii").casefold()
    except (idna.IDNAError, UnicodeError, ValueError):
        raise ValueError(f"{context} is invalid") from None
    if len(result) > 253 or "." not in result:
        raise ValueError(f"{context} is invalid")
    for label in result.split("."):
        if (
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not all(char.isalnum() or char == "-" for char in label)
        ):
            raise ValueError(f"{context} is invalid")
    return result


def _email_tuple(values: Iterable[Any], context: str) -> Tuple[str, ...]:
    return tuple(
        sorted(
            {canonical_workspace_email(value, context) for value in values},
            key=lambda value: (value.casefold(), value),
        )
    )


def _alias_email_tuple(values: Iterable[Any], context: str) -> Tuple[str, ...]:
    return tuple(
        sorted(
            {canonical_workspace_alias_email(value, context) for value in values},
            key=lambda value: (value.casefold(), value),
        )
    )


def _directory_user_key(value: Any, context: str) -> str:
    key = _text(value, context)
    if "@" in key:
        return canonical_workspace_email(key, context)
    if len(key) > 256 or any(char.isspace() for char in key):
        raise ValueError(f"{context} must be a valid Directory user key")
    return key


def _safe_google_error_reasons(response: Any) -> Tuple[str, ...]:
    """Extract only bounded machine-readable reason codes, never error messages."""

    try:
        payload = response.json()
    except Exception:
        return ()
    if not isinstance(payload, Mapping):
        return ()
    error = payload.get("error")
    if not isinstance(error, Mapping):
        return ()
    candidates = []
    status = error.get("status")
    if isinstance(status, str):
        candidates.append(status)
    errors = error.get("errors")
    if isinstance(errors, list):
        for item in errors:
            if isinstance(item, Mapping) and isinstance(item.get("reason"), str):
                candidates.append(item["reason"])
    details = error.get("details")
    if isinstance(details, list):
        for item in details:
            if isinstance(item, Mapping) and isinstance(item.get("reason"), str):
                candidates.append(item["reason"])
    return tuple(
        dict.fromkeys(
            item
            for item in candidates
            if _SAFE_GOOGLE_REASON_RE.fullmatch(item)
            and item.casefold() in _SAFE_GOOGLE_REASON_KEYS
        )
    )


def _has_retryable_google_reason(reasons: Iterable[str]) -> bool:
    return any(reason.casefold() in _RETRYABLE_GOOGLE_REASONS for reason in reasons)


def _has_quota_rate_google_reason(reasons: Iterable[str]) -> bool:
    return any(reason.casefold() in _QUOTA_RATE_GOOGLE_REASONS for reason in reasons)


def _retry_after_seconds(response: Any, *, now: Optional[float] = None) -> Optional[float]:
    headers = getattr(response, "headers", None)
    if not isinstance(headers, Mapping):
        return None
    raw = next(
        (value for key, value in headers.items() if str(key).casefold() == "retry-after"),
        None,
    )
    if not isinstance(raw, str):
        return None
    value = raw.strip()
    if re.fullmatch(r"[0-9]+", value):
        return float(value)
    try:
        parsed = email.utils.parsedate_to_datetime(value)
        if parsed is None:
            return None
        return max(0.0, parsed.timestamp() - (time.time() if now is None else now))
    except (TypeError, ValueError, OverflowError):
        return None


def _mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{context} must be an object")
    return value


def _sequence(value: Any, context: str) -> Sequence[Any]:
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"{context} must be an array")
    return value


def _require_keys(value: Mapping[str, Any], keys: set[str], context: str) -> None:
    unknown = sorted(set(value) - keys)
    missing = sorted(keys - set(value))
    if unknown:
        raise ValueError(f"{context} has unknown field(s): {', '.join(unknown)}")
    if missing:
        raise ValueError(f"{context} is missing field(s): {', '.join(missing)}")


def _digest(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _optional_email(value: Any, context: str) -> Optional[str]:
    return None if value is None else canonical_workspace_email(value, context)


@dataclasses.dataclass(frozen=True)
class WorkspaceAuthorizationIdentity:
    method: str
    admin_email: str
    service_account_email: Optional[str] = None
    scopes: Tuple[str, ...] = WORKSPACE_DIRECTORY_SCOPES

    def __post_init__(self) -> None:
        method = _text(self.method, "authorization method").casefold()
        if method not in {"xoauth2", "service_account"}:
            raise ValueError("authorization method must be xoauth2 or service_account")
        object.__setattr__(self, "method", method)
        object.__setattr__(
            self,
            "admin_email",
            canonical_workspace_email(self.admin_email, "admin email"),
        )
        object.__setattr__(
            self,
            "service_account_email",
            _optional_email(self.service_account_email, "service account email"),
        )
        scopes = tuple(sorted({_text(item, "OAuth scope") for item in self.scopes}))
        object.__setattr__(self, "scopes", scopes)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "method": self.method,
            "admin_email": self.admin_email,
            "service_account_email": self.service_account_email,
            "scopes": list(self.scopes),
        }

    @staticmethod
    def from_dict(raw: Mapping[str, Any]) -> "WorkspaceAuthorizationIdentity":
        raw = _mapping(raw, "authorization identity")
        _require_keys(
            raw,
            {"method", "admin_email", "service_account_email", "scopes"},
            "authorization identity",
        )
        return WorkspaceAuthorizationIdentity(
            method=raw["method"],
            admin_email=raw["admin_email"],
            service_account_email=raw["service_account_email"],
            scopes=tuple(_sequence(raw["scopes"], "authorization scopes")),
        )


@dataclasses.dataclass(frozen=True)
class WorkspaceUserAlias:
    alias: str
    primary_email: str
    user_id: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "alias",
            canonical_workspace_alias_email(self.alias, "user alias"),
        )
        object.__setattr__(
            self,
            "primary_email",
            canonical_workspace_email(self.primary_email, "alias primary email"),
        )
        object.__setattr__(self, "user_id", _text(self.user_id, "alias user id"))

    @staticmethod
    def from_api(raw: Mapping[str, Any]) -> "WorkspaceUserAlias":
        raw = _mapping(raw, "Directory user alias")
        return WorkspaceUserAlias(
            alias=_text(raw.get("alias"), "Directory user alias address"),
            primary_email=_text(
                raw.get("primaryEmail"),
                "Directory user alias primary email",
            ),
            user_id=_text(raw.get("id"), "Directory user alias id"),
        )

    def to_dict(self) -> Dict[str, str]:
        return {
            "alias": self.alias,
            "primary_email": self.primary_email,
            "user_id": self.user_id,
        }

    @staticmethod
    def from_dict(raw: Mapping[str, Any]) -> "WorkspaceUserAlias":
        raw = _mapping(raw, "user alias")
        _require_keys(raw, {"alias", "primary_email", "user_id"}, "user alias")
        return WorkspaceUserAlias(raw["alias"], raw["primary_email"], raw["user_id"])


@dataclasses.dataclass(frozen=True)
class WorkspaceDirectoryUser:
    user_id: str
    primary_email: str
    customer_id: str
    aliases: Tuple[str, ...] = ()
    non_editable_aliases: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "user_id", _text(self.user_id, "user id"))
        object.__setattr__(
            self,
            "primary_email",
            canonical_workspace_email(self.primary_email, "user primary email"),
        )
        object.__setattr__(self, "customer_id", _text(self.customer_id, "customer id"))
        object.__setattr__(self, "aliases", _email_tuple(self.aliases, "user alias"))
        object.__setattr__(
            self,
            "non_editable_aliases",
            _email_tuple(self.non_editable_aliases, "non-editable user alias"),
        )

    @staticmethod
    def from_api(raw: Mapping[str, Any]) -> "WorkspaceDirectoryUser":
        raw = _mapping(raw, "Directory user")
        return WorkspaceDirectoryUser(
            user_id=_text(raw.get("id"), "Directory user id"),
            primary_email=_text(raw.get("primaryEmail"), "Directory user primary email"),
            customer_id=_text(raw.get("customerId"), "Directory user customer id"),
            aliases=_api_alias_values(
                raw.get("aliases", _API_ALIAS_FIELD_MISSING),
                "user aliases",
            ),
            non_editable_aliases=_api_alias_values(
                raw.get("nonEditableAliases", _API_ALIAS_FIELD_MISSING),
                "non-editable user aliases",
            ),
        )

    def alias_kind(self, email: str) -> Optional[str]:
        email = canonical_workspace_email(email)
        if email == self.primary_email:
            return "user"
        if email in self.aliases:
            return "user_alias"
        if email in self.non_editable_aliases:
            return "non_editable_user_alias"
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "primary_email": self.primary_email,
            "customer_id": self.customer_id,
            "aliases": list(self.aliases),
            "non_editable_aliases": list(self.non_editable_aliases),
        }

    @staticmethod
    def from_dict(raw: Mapping[str, Any]) -> "WorkspaceDirectoryUser":
        raw = _mapping(raw, "user")
        _require_keys(
            raw,
            {"user_id", "primary_email", "customer_id", "aliases", "non_editable_aliases"},
            "user",
        )
        return WorkspaceDirectoryUser(
            raw["user_id"],
            raw["primary_email"],
            raw["customer_id"],
            tuple(_sequence(raw["aliases"], "user aliases")),
            tuple(_sequence(raw["non_editable_aliases"], "non-editable user aliases")),
        )


_API_ALIAS_FIELD_MISSING = object()


def _api_alias_values(value: Any, context: str) -> Tuple[str, ...]:
    if value is _API_ALIAS_FIELD_MISSING:
        return ()
    if not isinstance(value, list):
        raise ValueError(f"{context} must be an array")
    return tuple(_text(item, context) for item in value)


@dataclasses.dataclass(frozen=True)
class WorkspaceDirectoryGroup:
    group_id: str
    primary_email: str
    aliases: Tuple[str, ...] = ()
    non_editable_aliases: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "group_id", _text(self.group_id, "group id"))
        object.__setattr__(
            self,
            "primary_email",
            canonical_workspace_email(self.primary_email, "group primary email"),
        )
        object.__setattr__(self, "aliases", _email_tuple(self.aliases, "group alias"))
        object.__setattr__(
            self,
            "non_editable_aliases",
            _email_tuple(self.non_editable_aliases, "non-editable group alias"),
        )

    @staticmethod
    def from_api(raw: Mapping[str, Any]) -> "WorkspaceDirectoryGroup":
        raw = _mapping(raw, "Directory group")
        return WorkspaceDirectoryGroup(
            group_id=_text(raw.get("id"), "Directory group id"),
            primary_email=_text(raw.get("email"), "Directory group primary email"),
            aliases=_api_alias_values(
                raw.get("aliases", _API_ALIAS_FIELD_MISSING),
                "group aliases",
            ),
            non_editable_aliases=_api_alias_values(
                raw.get("nonEditableAliases", _API_ALIAS_FIELD_MISSING),
                "non-editable group aliases",
            ),
        )

    def alias_kind(self, email: str) -> Optional[str]:
        email = canonical_workspace_email(email)
        if email == self.primary_email:
            return "group"
        if email in self.aliases:
            return "group_alias"
        if email in self.non_editable_aliases:
            return "non_editable_group_alias"
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "group_id": self.group_id,
            "primary_email": self.primary_email,
            "aliases": list(self.aliases),
            "non_editable_aliases": list(self.non_editable_aliases),
        }

    @staticmethod
    def from_dict(raw: Mapping[str, Any]) -> "WorkspaceDirectoryGroup":
        raw = _mapping(raw, "group")
        _require_keys(
            raw,
            {"group_id", "primary_email", "aliases", "non_editable_aliases"},
            "group",
        )
        return WorkspaceDirectoryGroup(
            raw["group_id"],
            raw["primary_email"],
            tuple(_sequence(raw["aliases"], "group aliases")),
            tuple(_sequence(raw["non_editable_aliases"], "non-editable group aliases")),
        )


@dataclasses.dataclass(frozen=True)
class WorkspaceDomain:
    name: str
    kind: str
    verified: bool
    parent_domain: Optional[str] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _canonical_domain(self.name))
        kind = _text(self.kind, "domain kind").casefold()
        if kind not in {"primary", "secondary", "domain_alias"}:
            raise ValueError("domain kind must be primary, secondary, or domain_alias")
        object.__setattr__(self, "kind", kind)
        if type(self.verified) is not bool:
            raise ValueError("domain verified must be a boolean")
        parent = self.parent_domain
        object.__setattr__(
            self,
            "parent_domain",
            None if parent is None else _canonical_domain(parent, "parent domain"),
        )

    @staticmethod
    def from_domain_api(raw: Mapping[str, Any]) -> "WorkspaceDomain":
        raw = _mapping(raw, "Directory domain")
        is_primary = raw.get("isPrimary")
        if type(is_primary) is not bool or type(raw.get("verified")) is not bool:
            raise ValueError("Directory domain flags must be booleans")
        return WorkspaceDomain(
            name=_text(raw.get("domainName"), "Directory domain name"),
            kind="primary" if is_primary else "secondary",
            verified=raw["verified"],
        )

    @staticmethod
    def from_domain_alias_api(raw: Mapping[str, Any]) -> "WorkspaceDomain":
        raw = _mapping(raw, "Directory domain alias")
        if type(raw.get("verified")) is not bool:
            raise ValueError("Directory domain alias verified must be a boolean")
        return WorkspaceDomain(
            name=_text(raw.get("domainAliasName"), "Directory domain alias name"),
            kind="domain_alias",
            verified=raw["verified"],
            parent_domain=raw.get("parentDomainName"),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "verified": self.verified,
            "parent_domain": self.parent_domain,
        }

    @staticmethod
    def from_dict(raw: Mapping[str, Any]) -> "WorkspaceDomain":
        raw = _mapping(raw, "domain")
        _require_keys(raw, {"name", "kind", "verified", "parent_domain"}, "domain")
        return WorkspaceDomain(raw["name"], raw["kind"], raw["verified"], raw["parent_domain"])


class WorkspaceDirectoryApiError(RuntimeError):
    """A Directory API failure whose message never includes response content."""

    def __init__(
        self,
        message: str,
        *,
        operation: str,
        status_code: Optional[int] = None,
        required_scopes: Iterable[str] = (),
        reasons: Iterable[str] = (),
        retryable: bool = False,
        mutation_outcome_uncertain: bool = False,
    ) -> None:
        super().__init__(message)
        self.operation = operation
        self.status_code = status_code
        self.required_scopes = tuple(required_scopes)
        self.reasons = tuple(
            dict.fromkeys(
                reason
                for reason in reasons
                if isinstance(reason, str)
                and _SAFE_GOOGLE_REASON_RE.fullmatch(reason)
                and reason.casefold() in _SAFE_GOOGLE_REASON_KEYS
            )
        )
        self.retryable = bool(retryable)
        self.mutation_outcome_uncertain = bool(mutation_outcome_uncertain)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "error": "workspace_directory_api",
            "operation": self.operation,
            "status_code": self.status_code,
            "required_scopes": list(self.required_scopes),
            "reasons": list(self.reasons),
            "retryable": self.retryable,
            "mutation_outcome_uncertain": self.mutation_outcome_uncertain,
            "message": str(self),
        }


class WorkspaceDirectoryCancelledError(InterruptedError):
    """Raised when cooperative cancellation stops a Directory API operation."""

    def __init__(self, operation: str, *, result: Optional[Any] = None) -> None:
        self.operation = operation
        self.result = result
        super().__init__(
            f"Workspace Directory {operation} cancelled: stop requested"
        )

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "error": "workspace_directory_cancelled",
            "operation": self.operation,
            "message": str(self),
        }
        if self.result is not None and hasattr(self.result, "to_dict"):
            payload["result"] = self.result.to_dict()
        return payload


class WorkspaceAuthenticationError(RuntimeError):
    """A redacted bearer/service-account credential error."""


class _StaticTokenProvider:
    def __init__(self, token: str) -> None:
        self._token = _text(token, "Workspace admin bearer token")

    def __call__(self) -> str:
        return self._token

    def __repr__(self) -> str:
        return "<_StaticTokenProvider redacted>"


class _GoogleCredentialsTokenProvider:
    def __init__(self, credentials: Any, auth_request: Optional[Any] = None) -> None:
        self._credentials = credentials
        self._auth_request = auth_request

    def __call__(self) -> str:
        try:
            token = getattr(self._credentials, "token", None)
            valid = bool(getattr(self._credentials, "valid", False))
            if not valid or not token:
                request = self._auth_request
                if request is None:
                    if GoogleAuthRequest is None:
                        raise RuntimeError("google-auth transport is unavailable")
                    request = GoogleAuthRequest()
                self._credentials.refresh(request)
                token = getattr(self._credentials, "token", None)
        except Exception as exc:
            raise WorkspaceAuthenticationError(
                "Workspace service-account token refresh failed "
                f"({type(exc).__name__}); verify domain-wide delegation and scopes"
            ) from None
        if not isinstance(token, str) or not token:
            raise WorkspaceAuthenticationError(
                "Workspace service-account token refresh returned no bearer token"
            )
        return token

    def __repr__(self) -> str:
        return "<_GoogleCredentialsTokenProvider redacted>"


class WorkspaceDirectoryClient:
    """Minimal Directory API v1 client with injectable HTTP/token providers."""

    def __init__(
        self,
        token_provider: Callable[[], str],
        *,
        authorization_identity: WorkspaceAuthorizationIdentity,
        session: Optional[Any] = None,
        base_url: str = DEFAULT_DIRECTORY_API_BASE_URL,
        timeout_sec: float = 20,
        retry_max_attempts: int = 5,
        retry_base_delay_sec: float = 0.5,
        retry_max_delay_sec: float = 30,
        sleep_fn: Optional[Callable[[float], None]] = None,
        random_fn: Optional[Callable[[], float]] = None,
        stop_event: Optional[object] = None,
    ) -> None:
        if requests is None:  # type: ignore
            raise RuntimeError("Workspace alias provisioning requires the requests package")
        if not callable(token_provider):
            raise ValueError("Workspace token provider must be callable")
        if (
            not isinstance(timeout_sec, (int, float))
            or isinstance(timeout_sec, bool)
            or not math.isfinite(float(timeout_sec))
            or timeout_sec <= 0
        ):
            raise ValueError("Workspace Directory timeout_sec must be positive and finite")
        if type(retry_max_attempts) is not int or retry_max_attempts < 1:
            raise ValueError("Workspace Directory retry_max_attempts must be a positive integer")
        for value, name in (
            (retry_base_delay_sec, "retry_base_delay_sec"),
            (retry_max_delay_sec, "retry_max_delay_sec"),
        ):
            if (
                not isinstance(value, (int, float))
                or isinstance(value, bool)
                or not math.isfinite(float(value))
                or value < 0
            ):
                raise ValueError(f"Workspace Directory {name} must be finite and non-negative")
        if retry_max_delay_sec < retry_base_delay_sec:
            raise ValueError(
                "Workspace Directory retry_max_delay_sec must be at least retry_base_delay_sec"
            )
        if sleep_fn is not None and not callable(sleep_fn):
            raise ValueError("Workspace Directory sleep_fn must be callable")
        if random_fn is not None and not callable(random_fn):
            raise ValueError("Workspace Directory random_fn must be callable")
        if stop_event is not None and not callable(
            getattr(stop_event, "is_set", None)
        ) and not callable(stop_event):
            raise ValueError(
                "Workspace Directory stop_event must expose is_set() or be callable"
            )
        self._token_provider = token_provider
        self.authorization_identity = authorization_identity
        self.session = session if session is not None else requests.Session()  # type: ignore
        self.base_url = _text(base_url, "Directory API base URL").rstrip("/")
        self.timeout_sec = float(timeout_sec)
        self.retry_max_attempts = retry_max_attempts
        self.retry_base_delay_sec = float(retry_base_delay_sec)
        self.retry_max_delay_sec = float(retry_max_delay_sec)
        self._sleep = time.sleep if sleep_fn is None else sleep_fn
        self._random = random.random if random_fn is None else random_fn
        self._stop_event = stop_event

    def __repr__(self) -> str:
        return (
            f"WorkspaceDirectoryClient(authorization_identity={self.authorization_identity!r}, "
            f"base_url={self.base_url!r}, timeout_sec={self.timeout_sec!r}, "
            f"retry_max_attempts={self.retry_max_attempts!r})"
        )

    @staticmethod
    def _quote(value: str) -> str:
        return urllib.parse.quote(value, safe="")

    def _stop_requested(self) -> bool:
        if self._stop_event is None:
            return False
        is_set = getattr(self._stop_event, "is_set", None)
        if callable(is_set):
            return bool(is_set())
        return bool(self._stop_event())  # type: ignore[operator]

    def _raise_if_cancelled(self, operation: str) -> None:
        if self._stop_requested():
            raise WorkspaceDirectoryCancelledError(operation)

    def _sleep_for_retry(
        self,
        attempt: int,
        response: Optional[Any] = None,
        *,
        operation: str,
    ) -> None:
        retry_after = None if response is None else _retry_after_seconds(response)
        if retry_after is None:
            exponent = min(max(attempt - 1, 0), 30)
            base = min(
                self.retry_max_delay_sec,
                self.retry_base_delay_sec * (2**exponent),
            )
            try:
                random_value = float(self._random())
            except Exception:
                random_value = 0.5
            random_value = min(1.0, max(0.0, random_value))
            delay = base * (0.5 + 0.5 * random_value)
        else:
            delay = retry_after
        delay = min(self.retry_max_delay_sec, max(0.0, delay))
        self._raise_if_cancelled(operation)
        wait = getattr(self._stop_event, "wait", None)
        if callable(wait):
            if wait(delay):
                raise WorkspaceDirectoryCancelledError(operation)
        else:
            self._sleep(delay)
        self._raise_if_cancelled(operation)

    def _request(
        self,
        method: str,
        suffix: str,
        *,
        operation: str,
        required_scopes: Tuple[str, ...],
        expected_statuses: Tuple[int, ...] = (200,),
        body: Optional[Mapping[str, Any]] = None,
        allow_not_found: bool = False,
    ) -> Optional[Dict[str, Any]]:
        method = method.upper()
        url = f"{self.base_url}/{suffix.lstrip('/')}"
        for attempt in range(1, self.retry_max_attempts + 1):
            self._raise_if_cancelled(operation)
            try:
                token = self._token_provider()
            except WorkspaceAuthenticationError:
                raise
            except Exception as exc:
                raise WorkspaceAuthenticationError(
                    f"Workspace bearer-token resolution failed ({type(exc).__name__})"
                ) from None
            token = _text(token, "Workspace bearer token")
            self._raise_if_cancelled(operation)
            kwargs: Dict[str, Any] = {
                "headers": {
                    "Accept": "application/json",
                    "Authorization": f"Bearer {token}",
                },
                "timeout": self.timeout_sec,
                "allow_redirects": False,
            }
            if body is not None:
                kwargs["json"] = copy.deepcopy(dict(body))
            try:
                response = self.session.request(method, url, **kwargs)
            except Exception as exc:
                if method in _SAFE_RETRY_METHODS and attempt < self.retry_max_attempts:
                    self._sleep_for_retry(attempt, operation=operation)
                    continue
                raise WorkspaceDirectoryApiError(
                    f"Workspace Directory {operation} failed: transport error ({type(exc).__name__})",
                    operation=operation,
                    required_scopes=required_scopes,
                    retryable=method in _SAFE_RETRY_METHODS,
                    mutation_outcome_uncertain=method not in _SAFE_RETRY_METHODS,
                ) from None
            status = getattr(response, "status_code", None)
            if type(status) is not int:
                raise WorkspaceDirectoryApiError(
                    f"Workspace Directory {operation} failed: invalid HTTP response",
                    operation=operation,
                    required_scopes=required_scopes,
                    mutation_outcome_uncertain=method not in _SAFE_RETRY_METHODS,
                )
            if allow_not_found and status == 404:
                return None
            if status not in expected_statuses:
                reasons = _safe_google_error_reasons(response)
                reason_retryable = _has_retryable_google_reason(reasons)
                quota_or_rate_limited = _has_quota_rate_google_reason(reasons)
                retryable = status in _RETRYABLE_HTTP_STATUSES or (
                    status == 403 and reason_retryable
                )
                safe_to_repeat = method in _SAFE_RETRY_METHODS or (
                    method == "POST"
                    and (status == 429 or (status == 403 and reason_retryable))
                )
                if retryable and safe_to_repeat and attempt < self.retry_max_attempts:
                    self._sleep_for_retry(attempt, response, operation=operation)
                    continue
                reason_text = (
                    f"; reason(s): {', '.join(reasons)}" if reasons else ""
                )
                if status == 401:
                    message = (
                        f"Workspace Directory {operation} failed: HTTP 401 "
                        f"(invalid or expired token); required scope(s): {', '.join(required_scopes)}"
                    )
                elif (
                    status == 403
                    and not quota_or_rate_limited
                    and not reason_retryable
                ):
                    message = (
                        f"Workspace Directory {operation} failed: HTTP 403 "
                        f"(permission denied){reason_text}; required scope(s): "
                        f"{', '.join(required_scopes)}"
                    )
                elif status == 429 or quota_or_rate_limited:
                    message = (
                        f"Workspace Directory {operation} failed: HTTP {status} "
                        f"(rate or quota limited){reason_text}"
                    )
                elif retryable:
                    message = (
                        f"Workspace Directory {operation} failed: HTTP {status} "
                        f"(transient service failure){reason_text}"
                    )
                else:
                    message = (
                        f"Workspace Directory {operation} failed: HTTP {status}{reason_text}"
                    )
                raise WorkspaceDirectoryApiError(
                    message,
                    operation=operation,
                    status_code=status,
                    required_scopes=required_scopes,
                    reasons=reasons,
                    retryable=retryable,
                    mutation_outcome_uncertain=(
                        method not in _SAFE_RETRY_METHODS and status >= 500
                    ),
                )
            try:
                payload = response.json()
            except Exception:
                raise WorkspaceDirectoryApiError(
                    f"Workspace Directory {operation} returned invalid JSON",
                    operation=operation,
                    status_code=status,
                    required_scopes=required_scopes,
                    mutation_outcome_uncertain=method not in _SAFE_RETRY_METHODS,
                ) from None
            if not isinstance(payload, dict):
                raise WorkspaceDirectoryApiError(
                    f"Workspace Directory {operation} returned a non-object response",
                    operation=operation,
                    status_code=status,
                    required_scopes=required_scopes,
                    mutation_outcome_uncertain=method not in _SAFE_RETRY_METHODS,
                )
            return payload
        raise AssertionError("unreachable Workspace Directory retry loop")

    def get_user(self, user_key: str) -> Optional[WorkspaceDirectoryUser]:
        key = _directory_user_key(user_key, "user lookup key")
        payload = self._request(
            "GET",
            f"users/{self._quote(key)}",
            operation="get user identity",
            required_scopes=(WORKSPACE_USER_READONLY_SCOPE,),
            allow_not_found=True,
        )
        if payload is None:
            return None
        try:
            return WorkspaceDirectoryUser.from_api(payload)
        except (TypeError, ValueError) as exc:
            raise WorkspaceDirectoryApiError(
                f"Workspace Directory get user identity returned an invalid resource ({type(exc).__name__})",
                operation="get user identity",
                required_scopes=(WORKSPACE_USER_READONLY_SCOPE,),
            ) from None

    def list_user_aliases(self, target_user_key: str) -> Tuple[WorkspaceUserAlias, ...]:
        key = _directory_user_key(target_user_key, "target user key")
        payload = self._request(
            "GET",
            f"users/{self._quote(key)}/aliases",
            operation="list target user aliases",
            required_scopes=(WORKSPACE_USER_ALIAS_SCOPE,),
        )
        assert payload is not None
        raw = payload.get("aliases", [])
        if not isinstance(raw, list):
            raise WorkspaceDirectoryApiError(
                "Workspace Directory list target user aliases returned an invalid aliases array",
                operation="list target user aliases",
                required_scopes=(WORKSPACE_USER_ALIAS_SCOPE,),
            )
        try:
            aliases = tuple(WorkspaceUserAlias.from_api(item) for item in raw)
        except (TypeError, ValueError) as exc:
            raise WorkspaceDirectoryApiError(
                f"Workspace Directory list target user aliases returned an invalid resource ({type(exc).__name__})",
                operation="list target user aliases",
                required_scopes=(WORKSPACE_USER_ALIAS_SCOPE,),
            ) from None
        names = [item.alias for item in aliases]
        if len(names) != len(set(names)):
            raise WorkspaceDirectoryApiError(
                "Workspace Directory returned duplicate target user aliases",
                operation="list target user aliases",
                required_scopes=(WORKSPACE_USER_ALIAS_SCOPE,),
            )
        return tuple(sorted(aliases, key=lambda item: item.alias))

    def get_group(self, email: str) -> Optional[WorkspaceDirectoryGroup]:
        key = canonical_workspace_email(email, "group lookup email")
        payload = self._request(
            "GET",
            f"groups/{self._quote(key)}",
            operation="get group identity",
            required_scopes=(WORKSPACE_GROUP_READONLY_SCOPE,),
            allow_not_found=True,
        )
        if payload is None:
            return None
        try:
            return WorkspaceDirectoryGroup.from_api(payload)
        except (TypeError, ValueError) as exc:
            raise WorkspaceDirectoryApiError(
                f"Workspace Directory get group identity returned an invalid resource ({type(exc).__name__})",
                operation="get group identity",
                required_scopes=(WORKSPACE_GROUP_READONLY_SCOPE,),
            ) from None

    def get_domain(self, customer: str, domain: str) -> Optional[WorkspaceDomain]:
        customer = _text(customer, "Workspace customer")
        domain = _canonical_domain(domain)
        payload = self._request(
            "GET",
            f"customer/{self._quote(customer)}/domains/{self._quote(domain)}",
            operation="get Workspace domain",
            required_scopes=(WORKSPACE_DOMAIN_READONLY_SCOPE,),
            allow_not_found=True,
        )
        if payload is None:
            return None
        try:
            result = WorkspaceDomain.from_domain_api(payload)
        except (TypeError, ValueError) as exc:
            raise WorkspaceDirectoryApiError(
                f"Workspace Directory get domain returned an invalid resource ({type(exc).__name__})",
                operation="get Workspace domain",
                required_scopes=(WORKSPACE_DOMAIN_READONLY_SCOPE,),
            ) from None
        if result.name != domain:
            raise WorkspaceDirectoryApiError(
                "Workspace Directory get domain returned a different domain",
                operation="get Workspace domain",
                required_scopes=(WORKSPACE_DOMAIN_READONLY_SCOPE,),
            )
        return result

    def get_domain_alias(self, customer: str, domain: str) -> Optional[WorkspaceDomain]:
        customer = _text(customer, "Workspace customer")
        domain = _canonical_domain(domain)
        payload = self._request(
            "GET",
            f"customer/{self._quote(customer)}/domainaliases/{self._quote(domain)}",
            operation="get Workspace domain alias",
            required_scopes=(WORKSPACE_DOMAIN_READONLY_SCOPE,),
            allow_not_found=True,
        )
        if payload is None:
            return None
        try:
            result = WorkspaceDomain.from_domain_alias_api(payload)
        except (TypeError, ValueError) as exc:
            raise WorkspaceDirectoryApiError(
                f"Workspace Directory get domain alias returned an invalid resource ({type(exc).__name__})",
                operation="get Workspace domain alias",
                required_scopes=(WORKSPACE_DOMAIN_READONLY_SCOPE,),
            ) from None
        if result.name != domain:
            raise WorkspaceDirectoryApiError(
                "Workspace Directory get domain alias returned a different domain",
                operation="get Workspace domain alias",
                required_scopes=(WORKSPACE_DOMAIN_READONLY_SCOPE,),
            )
        return result

    def insert_user_alias(
        self,
        target_user_key: str,
        alias: str,
        *,
        expected_user_id: Optional[str] = None,
        expected_primary_email: Optional[str] = None,
    ) -> WorkspaceUserAlias:
        target = _directory_user_key(target_user_key, "target user key")
        alias = canonical_workspace_alias_email(alias, "user alias")
        expected_id = (
            None
            if expected_user_id is None
            else _directory_user_key(expected_user_id, "expected target user ID")
        )
        expected_primary = (
            None
            if expected_primary_email is None
            else canonical_workspace_email(
                expected_primary_email,
                "expected target primary email",
            )
        )
        payload = self._request(
            "POST",
            f"users/{self._quote(target)}/aliases",
            operation="create user alias",
            required_scopes=(WORKSPACE_USER_ALIAS_SCOPE,),
            expected_statuses=(200, 201),
            body={"alias": alias},
        )
        assert payload is not None
        try:
            result = WorkspaceUserAlias.from_api(payload)
        except (TypeError, ValueError) as exc:
            raise WorkspaceDirectoryApiError(
                f"Workspace Directory create user alias returned an invalid resource ({type(exc).__name__})",
                operation="create user alias",
                required_scopes=(WORKSPACE_USER_ALIAS_SCOPE,),
                mutation_outcome_uncertain=True,
            ) from None
        if (
            result.alias != alias
            or (expected_id is not None and result.user_id != expected_id)
            or (
                expected_primary is not None
                and result.primary_email != expected_primary
            )
        ):
            raise WorkspaceDirectoryApiError(
                "Workspace Directory create user alias returned an unexpected identity binding",
                operation="create user alias",
                required_scopes=(WORKSPACE_USER_ALIAS_SCOPE,),
                mutation_outcome_uncertain=True,
            )
        return result


def build_workspace_directory_client_from_token(
    access_token: str,
    *,
    admin_email: str,
    session: Optional[Any] = None,
    base_url: str = DEFAULT_DIRECTORY_API_BASE_URL,
    timeout_sec: float = 20,
    retry_max_attempts: int = 5,
    retry_base_delay_sec: float = 0.5,
    retry_max_delay_sec: float = 30,
    sleep_fn: Optional[Callable[[float], None]] = None,
    random_fn: Optional[Callable[[], float]] = None,
    stop_event: Optional[object] = None,
) -> WorkspaceDirectoryClient:
    identity = WorkspaceAuthorizationIdentity("xoauth2", admin_email)
    return WorkspaceDirectoryClient(
        _StaticTokenProvider(access_token),
        authorization_identity=identity,
        session=session,
        base_url=base_url,
        timeout_sec=timeout_sec,
        retry_max_attempts=retry_max_attempts,
        retry_base_delay_sec=retry_base_delay_sec,
        retry_max_delay_sec=retry_max_delay_sec,
        sleep_fn=sleep_fn,
        random_fn=random_fn,
        stop_event=stop_event,
    )


def build_workspace_directory_client_from_service_account(
    credentials_file: str | Path,
    *,
    delegated_admin: str,
    session: Optional[Any] = None,
    base_url: str = DEFAULT_DIRECTORY_API_BASE_URL,
    timeout_sec: float = 20,
    auth_request: Optional[Any] = None,
    retry_max_attempts: int = 5,
    retry_base_delay_sec: float = 0.5,
    retry_max_delay_sec: float = 30,
    sleep_fn: Optional[Callable[[float], None]] = None,
    random_fn: Optional[Callable[[], float]] = None,
    stop_event: Optional[object] = None,
) -> WorkspaceDirectoryClient:
    """Build DWD credentials from a securely read service-account JSON file."""

    delegated_admin = canonical_workspace_email(delegated_admin, "delegated admin")
    if google_service_account is None:
        raise WorkspaceAuthenticationError(
            "Workspace service-account authorization requires google-auth; "
            "install project requirements"
        )
    try:
        serialized = read_secret_file_no_links(
            str(credentials_file),
            label="Workspace service-account credentials file",
        )
        info = json.loads(serialized)
        if not isinstance(info, dict):
            raise ValueError("credentials JSON is not an object")
        service_account_email = canonical_workspace_email(
            info.get("client_email"),
            "service account client_email",
        )
        credentials = google_service_account.Credentials.from_service_account_info(
            info,
            scopes=WORKSPACE_DIRECTORY_SCOPES,
        ).with_subject(delegated_admin)
    except WorkspaceAuthenticationError:
        raise
    except Exception as exc:
        raise WorkspaceAuthenticationError(
            "Workspace service-account credentials are invalid or unsafe "
            f"({type(exc).__name__})"
        ) from None
    identity = WorkspaceAuthorizationIdentity(
        "service_account",
        delegated_admin,
        service_account_email,
    )
    return WorkspaceDirectoryClient(
        _GoogleCredentialsTokenProvider(credentials, auth_request),
        authorization_identity=identity,
        session=session,
        base_url=base_url,
        timeout_sec=timeout_sec,
        retry_max_attempts=retry_max_attempts,
        retry_base_delay_sec=retry_base_delay_sec,
        retry_max_delay_sec=retry_max_delay_sec,
        sleep_fn=sleep_fn,
        random_fn=random_fn,
        stop_event=stop_event,
    )


def workspace_alias_plan_path(root: Path) -> Path:
    return Path(root) / WORKSPACE_ALIAS_PLAN_FILENAME


@dataclasses.dataclass(frozen=True)
class WorkspaceAliasCandidateDiscovery:
    alias: str
    user_owner: Optional[WorkspaceDirectoryUser]
    group_owner: Optional[WorkspaceDirectoryGroup]
    domain: Optional[WorkspaceDomain]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "alias",
            canonical_workspace_alias_email(self.alias, "candidate alias"),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alias": self.alias,
            "user_owner": None if self.user_owner is None else self.user_owner.to_dict(),
            "group_owner": None if self.group_owner is None else self.group_owner.to_dict(),
            "domain": None if self.domain is None else self.domain.to_dict(),
        }

    @staticmethod
    def from_dict(raw: Mapping[str, Any]) -> "WorkspaceAliasCandidateDiscovery":
        raw = _mapping(raw, "alias candidate discovery")
        _require_keys(raw, {"alias", "user_owner", "group_owner", "domain"}, "alias candidate discovery")
        return WorkspaceAliasCandidateDiscovery(
            alias=raw["alias"],
            user_owner=(
                None
                if raw["user_owner"] is None
                else WorkspaceDirectoryUser.from_dict(_mapping(raw["user_owner"], "user owner"))
            ),
            group_owner=(
                None
                if raw["group_owner"] is None
                else WorkspaceDirectoryGroup.from_dict(_mapping(raw["group_owner"], "group owner"))
            ),
            domain=(
                None
                if raw["domain"] is None
                else WorkspaceDomain.from_dict(_mapping(raw["domain"], "candidate domain"))
            ),
        )


@dataclasses.dataclass(frozen=True)
class WorkspaceAliasDiscovery:
    target_user: str
    customer_id: str
    requested_aliases: Tuple[str, ...]
    authorization: WorkspaceAuthorizationIdentity
    target: Optional[WorkspaceDirectoryUser]
    listed_target_aliases: Tuple[WorkspaceUserAlias, ...]
    domains: Tuple[WorkspaceDomain, ...]
    candidates: Tuple[WorkspaceAliasCandidateDiscovery, ...]
    issues: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "target_user", canonical_workspace_email(self.target_user, "target user"))
        object.__setattr__(self, "customer_id", _text(self.customer_id, "customer id"))
        requested = _alias_email_tuple(self.requested_aliases, "requested alias")
        object.__setattr__(self, "requested_aliases", requested)
        listed = tuple(sorted(self.listed_target_aliases, key=lambda item: item.alias))
        if len({item.alias for item in listed}) != len(listed):
            raise ValueError("listed target aliases contain duplicate addresses")
        object.__setattr__(self, "listed_target_aliases", listed)
        domains = tuple(sorted(self.domains, key=lambda item: item.name))
        if len({item.name for item in domains}) != len(domains):
            raise ValueError("domain discovery contains duplicate domains")
        object.__setattr__(self, "domains", domains)
        candidates = tuple(sorted(self.candidates, key=lambda item: item.alias))
        if tuple(item.alias for item in candidates) != requested:
            raise ValueError("candidate discovery must exactly cover requested aliases")
        object.__setattr__(self, "candidates", candidates)
        object.__setattr__(self, "issues", tuple(dict.fromkeys(_text(item, "discovery issue") for item in self.issues)))

    def _payload(self) -> Dict[str, Any]:
        return {
            "version": 1,
            "target_user": self.target_user,
            "customer_id": self.customer_id,
            "requested_aliases": list(self.requested_aliases),
            "authorization": self.authorization.to_dict(),
            "target": None if self.target is None else self.target.to_dict(),
            "listed_target_aliases": [item.to_dict() for item in self.listed_target_aliases],
            "domains": [item.to_dict() for item in self.domains],
            "candidates": [item.to_dict() for item in self.candidates],
            "issues": list(self.issues),
        }

    @property
    def discovery_sha256(self) -> str:
        return _digest(self._payload())

    def to_dict(self) -> Dict[str, Any]:
        result = self._payload()
        result["discovery_sha256"] = self.discovery_sha256
        return result

    @staticmethod
    def from_dict(raw: Mapping[str, Any]) -> "WorkspaceAliasDiscovery":
        raw = _mapping(raw, "Workspace alias discovery")
        keys = {
            "version",
            "target_user",
            "customer_id",
            "requested_aliases",
            "authorization",
            "target",
            "listed_target_aliases",
            "domains",
            "candidates",
            "issues",
            "discovery_sha256",
        }
        _require_keys(raw, keys, "Workspace alias discovery")
        if raw["version"] != 1:
            raise ValueError("unsupported Workspace alias discovery version")
        result = WorkspaceAliasDiscovery(
            target_user=raw["target_user"],
            customer_id=raw["customer_id"],
            requested_aliases=tuple(_sequence(raw["requested_aliases"], "requested aliases")),
            authorization=WorkspaceAuthorizationIdentity.from_dict(
                _mapping(raw["authorization"], "authorization")
            ),
            target=(
                None
                if raw["target"] is None
                else WorkspaceDirectoryUser.from_dict(_mapping(raw["target"], "target user"))
            ),
            listed_target_aliases=tuple(
                WorkspaceUserAlias.from_dict(_mapping(item, "listed target alias"))
                for item in _sequence(raw["listed_target_aliases"], "listed target aliases")
            ),
            domains=tuple(
                WorkspaceDomain.from_dict(_mapping(item, "domain"))
                for item in _sequence(raw["domains"], "domains")
            ),
            candidates=tuple(
                WorkspaceAliasCandidateDiscovery.from_dict(_mapping(item, "candidate"))
                for item in _sequence(raw["candidates"], "candidates")
            ),
            issues=tuple(_sequence(raw["issues"], "discovery issues")),
        )
        if raw["discovery_sha256"] != result.discovery_sha256:
            raise ValueError("Workspace alias discovery digest mismatch")
        return result


@dataclasses.dataclass(frozen=True)
class WorkspaceAliasPlanEntry:
    alias: str
    status: str
    owner_kind: Optional[str]
    owner_primary_email: Optional[str]
    domain_kind: Optional[str]
    conflicts: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "alias",
            canonical_workspace_alias_email(self.alias, "planned alias"),
        )
        status = _text(self.status, "alias plan status").casefold()
        if status not in {"create", "reuse", "conflict"}:
            raise ValueError("alias plan status must be create, reuse, or conflict")
        object.__setattr__(self, "status", status)
        allowed_owners = {
            None,
            "target_user_alias",
            "target_non_editable_alias",
            "target_resolved_alias",
            "user",
            "user_alias",
            "non_editable_user_alias",
            "group",
            "group_alias",
            "non_editable_group_alias",
        }
        if self.owner_kind not in allowed_owners:
            raise ValueError("invalid alias plan owner kind")
        object.__setattr__(
            self,
            "owner_primary_email",
            _optional_email(self.owner_primary_email, "owner primary email"),
        )
        if self.domain_kind not in {None, "primary", "secondary", "domain_alias"}:
            raise ValueError("invalid alias plan domain kind")
        conflicts = tuple(dict.fromkeys(_text(item, "alias conflict") for item in self.conflicts))
        if status == "conflict" and not conflicts:
            raise ValueError("conflict plan entry must include a conflict")
        if status != "conflict" and conflicts:
            raise ValueError("non-conflict plan entry cannot include conflicts")
        object.__setattr__(self, "conflicts", conflicts)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alias": self.alias,
            "status": self.status,
            "owner_kind": self.owner_kind,
            "owner_primary_email": self.owner_primary_email,
            "domain_kind": self.domain_kind,
            "conflicts": list(self.conflicts),
        }

    @staticmethod
    def from_dict(raw: Mapping[str, Any]) -> "WorkspaceAliasPlanEntry":
        raw = _mapping(raw, "Workspace alias plan entry")
        _require_keys(
            raw,
            {"alias", "status", "owner_kind", "owner_primary_email", "domain_kind", "conflicts"},
            "Workspace alias plan entry",
        )
        return WorkspaceAliasPlanEntry(
            raw["alias"],
            raw["status"],
            raw["owner_kind"],
            raw["owner_primary_email"],
            raw["domain_kind"],
            tuple(_sequence(raw["conflicts"], "entry conflicts")),
        )


@dataclasses.dataclass(frozen=True)
class WorkspaceAliasPlan:
    discovery: WorkspaceAliasDiscovery
    entries: Tuple[WorkspaceAliasPlanEntry, ...]
    conflicts: Tuple[str, ...] = ()
    actions_required: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        entries = tuple(sorted(self.entries, key=lambda item: item.alias))
        if tuple(item.alias for item in entries) != self.discovery.requested_aliases:
            raise ValueError("Workspace alias plan entries must exactly cover requested aliases")
        object.__setattr__(self, "entries", entries)
        derived_conflicts = tuple(
            dict.fromkeys(
                tuple(self.discovery.issues)
                + tuple(conflict for entry in entries for conflict in entry.conflicts)
            )
        )
        supplied = tuple(dict.fromkeys(_text(item, "plan conflict") for item in self.conflicts))
        if supplied != derived_conflicts:
            raise ValueError("Workspace alias plan conflicts do not match discovery/entries")
        object.__setattr__(self, "conflicts", supplied)
        object.__setattr__(
            self,
            "actions_required",
            tuple(dict.fromkeys(_text(item, "required action") for item in self.actions_required)),
        )

    @property
    def target_user(self) -> str:
        return self.discovery.target_user

    @property
    def customer_id(self) -> str:
        return self.discovery.customer_id

    @property
    def target_user_id(self) -> Optional[str]:
        target = self.discovery.target
        return None if target is None else target.user_id

    @property
    def requested_aliases(self) -> Tuple[str, ...]:
        return self.discovery.requested_aliases

    @property
    def existing_target_aliases(self) -> Tuple[str, ...]:
        values = {item.alias for item in self.discovery.listed_target_aliases}
        if self.discovery.target is not None:
            values.update(self.discovery.target.aliases)
            values.update(self.discovery.target.non_editable_aliases)
        return tuple(sorted(values))

    @property
    def ok(self) -> bool:
        return not self.conflicts and all(entry.status != "conflict" for entry in self.entries)

    @property
    def intent_sha256(self) -> str:
        return _digest(
            {
                "version": 2,
                "target_user": self.target_user,
                "target_user_id": self.target_user_id,
                "customer_id": self.customer_id,
                "requested_aliases": list(self.requested_aliases),
                "conflict_policy": "create_only",
            }
        )

    @property
    def discovery_sha256(self) -> str:
        return self.discovery.discovery_sha256

    @property
    def counts(self) -> Dict[str, int]:
        return {
            "create": sum(entry.status == "create" for entry in self.entries),
            "reuse": sum(entry.status == "reuse" for entry in self.entries),
            "conflict": sum(entry.status == "conflict" for entry in self.entries),
            "existing_target_aliases": len(self.existing_target_aliases),
        }

    def _payload(self) -> Dict[str, Any]:
        return {
            "version": 2,
            "target_user": self.target_user,
            "target_user_id": self.target_user_id,
            "customer_id": self.customer_id,
            "requested_aliases": list(self.requested_aliases),
            "existing_target_aliases": list(self.existing_target_aliases),
            "discovery": self.discovery.to_dict(),
            "entries": [entry.to_dict() for entry in self.entries],
            "counts": self.counts,
            "conflicts": list(self.conflicts),
            "actions_required": list(self.actions_required),
            "intent_sha256": self.intent_sha256,
            "discovery_sha256": self.discovery_sha256,
        }

    @property
    def plan_sha256(self) -> str:
        return _digest(self._payload())

    def to_dict(self) -> Dict[str, Any]:
        result = self._payload()
        result["plan_sha256"] = self.plan_sha256
        result["ok"] = self.ok
        return result

    @staticmethod
    def from_dict(raw: Mapping[str, Any]) -> "WorkspaceAliasPlan":
        raw = _mapping(raw, "Workspace alias plan")
        version = raw.get("version")
        if version == 1:
            raise ValueError(
                "Workspace alias plan version 1 is not bound to an immutable target user ID; "
                "run preflight with a new staging directory"
            )
        if version != 2:
            raise ValueError("unsupported Workspace alias plan version")
        keys = {
            "version",
            "target_user",
            "target_user_id",
            "customer_id",
            "requested_aliases",
            "existing_target_aliases",
            "discovery",
            "entries",
            "counts",
            "conflicts",
            "actions_required",
            "intent_sha256",
            "discovery_sha256",
            "plan_sha256",
            "ok",
        }
        _require_keys(raw, keys, "Workspace alias plan")
        result = WorkspaceAliasPlan(
            discovery=WorkspaceAliasDiscovery.from_dict(_mapping(raw["discovery"], "discovery")),
            entries=tuple(
                WorkspaceAliasPlanEntry.from_dict(_mapping(item, "plan entry"))
                for item in _sequence(raw["entries"], "plan entries")
            ),
            conflicts=tuple(_sequence(raw["conflicts"], "plan conflicts")),
            actions_required=tuple(_sequence(raw["actions_required"], "required actions")),
        )
        expected = result.to_dict()
        if dict(raw) != expected:
            raise ValueError("Workspace alias plan fields or digest do not match canonical plan")
        return result


def discover_workspace_aliases(
    client: WorkspaceDirectoryClient,
    target_user: str,
    requested_aliases: Iterable[str],
    *,
    customer: str = "my_customer",
) -> WorkspaceAliasDiscovery:
    """Read all identity/domain state needed for an alias decision."""

    target_user = canonical_workspace_email(target_user, "target user")
    requested = _alias_email_tuple(requested_aliases, "requested alias")
    customer = _text(customer, "Workspace customer")
    target = client.get_user(target_user)
    issues = []
    if target is None:
        issues.append(f"Workspace target user {target_user!r} does not exist")
        customer_id = customer
        listed: Tuple[WorkspaceUserAlias, ...] = ()
    else:
        customer_id = target.customer_id
        if target.primary_email != target_user:
            issues.append(
                f"configured target_user {target_user!r} resolves to different primary user "
                f"{target.primary_email!r}; configure the primary address"
            )
        if customer != "my_customer" and customer != target.customer_id:
            issues.append(
                f"configured Workspace customer {customer!r} does not match target user customer "
                f"{target.customer_id!r}"
            )
        # Directory user IDs are immutable even if an address is renamed or
        # later reassigned.  Bind every subsequent alias read to that ID.
        listed = client.list_user_aliases(target.user_id)

    domain_names = {target_user.rsplit("@", 1)[1]}
    domain_names.update(alias.rsplit("@", 1)[1] for alias in requested)
    domains_by_name: Dict[str, WorkspaceDomain] = {}
    for domain_name in sorted(domain_names):
        domain = client.get_domain(customer_id, domain_name)
        if domain is None:
            domain = client.get_domain_alias(customer_id, domain_name)
        if domain is not None:
            domains_by_name[domain_name] = domain

    candidates = []
    for alias in requested:
        candidates.append(
            WorkspaceAliasCandidateDiscovery(
                alias=alias,
                user_owner=client.get_user(alias),
                group_owner=client.get_group(alias),
                domain=domains_by_name.get(alias.rsplit("@", 1)[1]),
            )
        )
    authorization = getattr(client, "authorization_identity", None)
    if not isinstance(authorization, WorkspaceAuthorizationIdentity):
        authorization = WorkspaceAuthorizationIdentity("xoauth2", target_user)
    return WorkspaceAliasDiscovery(
        target_user=target_user,
        customer_id=customer_id,
        requested_aliases=requested,
        authorization=authorization,
        target=target,
        listed_target_aliases=listed,
        domains=tuple(domains_by_name.values()),
        candidates=tuple(candidates),
        issues=tuple(issues),
    )


def _owner_kind_for_user(user: WorkspaceDirectoryUser, alias: str) -> str:
    return user.alias_kind(alias) or "user_alias"


def _owner_kind_for_group(group: WorkspaceDirectoryGroup, alias: str) -> str:
    return group.alias_kind(alias) or "group_alias"


def plan_workspace_aliases(discovery: WorkspaceAliasDiscovery) -> WorkspaceAliasPlan:
    """Resolve create/reuse/conflict decisions from an immutable snapshot."""

    target = discovery.target
    target_primary = target.primary_email if target is not None else discovery.target_user
    listed = {item.alias: item for item in discovery.listed_target_aliases}
    editable_target_aliases = set(listed)
    non_editable_target_aliases: set[str] = set()
    global_conflicts = list(discovery.issues)
    if target is not None:
        editable_target_aliases.update(target.aliases)
        non_editable_target_aliases.update(target.non_editable_aliases)
        for item in discovery.listed_target_aliases:
            if item.primary_email != target.primary_email or item.user_id != target.user_id:
                global_conflicts.append(
                    f"listed target alias {item.alias!r} is bound to an unexpected user"
                )
        target_domain = next(
            (
                item
                for item in discovery.domains
                if item.name == target.primary_email.rsplit("@", 1)[1]
            ),
            None,
        )
        if target_domain is None:
            global_conflicts.append("target user's domain is not registered in this Workspace customer")
        elif not target_domain.verified:
            global_conflicts.append("target user's Workspace domain is not verified")

    entries = []
    for candidate in discovery.candidates:
        alias = candidate.alias
        conflicts = list(global_conflicts)
        owner_kind: Optional[str] = None
        owner_primary: Optional[str] = None
        reuse = False
        if alias == target_primary:
            conflicts.append(f"requested alias {alias!r} is the target user's primary address")

        user_owner = candidate.user_owner
        if user_owner is not None:
            owner_primary = user_owner.primary_email
            raw_kind = _owner_kind_for_user(user_owner, alias)
            if user_owner.primary_email == target_primary and alias != target_primary:
                reuse = True
                if alias in editable_target_aliases:
                    owner_kind = "target_user_alias"
                elif alias in non_editable_target_aliases:
                    owner_kind = "target_non_editable_alias"
                else:
                    owner_kind = "target_resolved_alias"
            elif alias != target_primary:
                owner_kind = raw_kind
                conflicts.append(
                    f"requested alias {alias!r} is already owned by Workspace user "
                    f"{user_owner.primary_email!r} ({raw_kind})"
                )
        elif alias in editable_target_aliases:
            reuse = True
            owner_kind = "target_user_alias"
            owner_primary = target_primary
        elif alias in non_editable_target_aliases:
            reuse = True
            owner_kind = "target_non_editable_alias"
            owner_primary = target_primary

        group_owner = candidate.group_owner
        if group_owner is not None:
            group_kind = _owner_kind_for_group(group_owner, alias)
            if owner_kind is None:
                owner_kind = group_kind
                owner_primary = group_owner.primary_email
            conflicts.append(
                f"requested alias {alias!r} is already owned by Workspace group "
                f"{group_owner.primary_email!r} ({group_kind})"
            )

        domain = candidate.domain
        if domain is None:
            conflicts.append(
                f"requested alias domain {alias.rsplit('@', 1)[1]!r} is not registered "
                "in the target Workspace customer"
            )
        elif not domain.verified:
            conflicts.append(f"requested alias domain {domain.name!r} is not verified")
        elif domain.kind == "domain_alias" and not reuse:
            conflicts.append(
                f"requested alias domain {domain.name!r} is a Workspace domain alias; "
                "those aliases are automatically managed and cannot be explicitly created"
            )

        conflicts = list(dict.fromkeys(conflicts))
        status = "conflict" if conflicts else ("reuse" if reuse else "create")
        entries.append(
            WorkspaceAliasPlanEntry(
                alias=alias,
                status=status,
                owner_kind=owner_kind,
                owner_primary_email=owner_primary,
                domain_kind=None if domain is None else domain.kind,
                conflicts=tuple(conflicts),
            )
        )

    create_entries = [entry for entry in entries if entry.status == "create"]
    projected_count = len(editable_target_aliases) + len(create_entries)
    if projected_count > MAX_WORKSPACE_USER_ALIASES:
        limit_conflict = (
            f"Workspace user alias limit would be exceeded: existing "
            f"{len(editable_target_aliases)} + create {len(create_entries)} = "
            f"{projected_count}, maximum {MAX_WORKSPACE_USER_ALIASES}"
        )
        entries = [
            dataclasses.replace(
                entry,
                status="conflict",
                conflicts=(limit_conflict,),
            )
            if entry.status == "create"
            else entry
            for entry in entries
        ]

    all_conflicts = tuple(
        dict.fromkeys(
            tuple(discovery.issues)
            + tuple(conflict for entry in entries for conflict in entry.conflicts)
        )
    )
    conflicted_aliases = [entry.alias for entry in entries if entry.status == "conflict"]
    actions = tuple(
        f"Resolve the Workspace identity/domain conflict for {alias!r} before provisioning."
        for alias in conflicted_aliases
    )
    return WorkspaceAliasPlan(
        discovery=discovery,
        entries=tuple(entries),
        conflicts=all_conflicts,
        actions_required=actions,
    )


def discover_workspace_alias_plan(
    client: WorkspaceDirectoryClient,
    target_user: str,
    requested_aliases: Iterable[str],
    *,
    customer: str = "my_customer",
) -> WorkspaceAliasPlan:
    return plan_workspace_aliases(
        discover_workspace_aliases(
            client,
            target_user,
            requested_aliases,
            customer=customer,
        )
    )


@dataclasses.dataclass(frozen=True)
class WorkspaceAliasOutcome:
    alias: str
    action: str
    owner_primary_email: Optional[str] = None
    conflicts: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "alias",
            canonical_workspace_alias_email(self.alias, "alias outcome"),
        )
        action = _text(self.action, "alias outcome action").casefold()
        if action not in {"created", "reused", "would_create", "conflict"}:
            raise ValueError("alias outcome action is invalid")
        object.__setattr__(self, "action", action)
        object.__setattr__(
            self,
            "owner_primary_email",
            _optional_email(self.owner_primary_email, "outcome owner primary email"),
        )
        conflicts = tuple(dict.fromkeys(_text(item, "outcome conflict") for item in self.conflicts))
        if action == "conflict" and not conflicts:
            raise ValueError("conflict outcome must include a conflict")
        if action != "conflict" and conflicts:
            raise ValueError("non-conflict outcome cannot include conflicts")
        object.__setattr__(self, "conflicts", conflicts)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alias": self.alias,
            "action": self.action,
            "owner_primary_email": self.owner_primary_email,
            "conflicts": list(self.conflicts),
        }


@dataclasses.dataclass(frozen=True)
class WorkspaceAliasProvisionResult:
    dry_run: bool
    target_user: str
    plan_sha256: str
    verified: bool
    aliases: Tuple[WorkspaceAliasOutcome, ...]
    issues: Tuple[str, ...] = ()
    actions_required: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if type(self.dry_run) is not bool or type(self.verified) is not bool:
            raise ValueError("provision result dry_run/verified must be booleans")
        object.__setattr__(self, "target_user", canonical_workspace_email(self.target_user, "target user"))
        digest = _text(self.plan_sha256, "Workspace alias plan digest")
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("Workspace alias plan digest must be lowercase SHA-256")
        aliases = tuple(sorted(self.aliases, key=lambda item: item.alias))
        if len({item.alias for item in aliases}) != len(aliases):
            raise ValueError("provision result contains duplicate aliases")
        object.__setattr__(self, "aliases", aliases)
        object.__setattr__(
            self,
            "issues",
            tuple(dict.fromkeys(_text(item, "provision issue") for item in self.issues)),
        )
        object.__setattr__(
            self,
            "actions_required",
            tuple(dict.fromkeys(_text(item, "provision action") for item in self.actions_required)),
        )

    @property
    def created(self) -> Tuple[str, ...]:
        return tuple(item.alias for item in self.aliases if item.action == "created")

    @property
    def reused(self) -> Tuple[str, ...]:
        return tuple(item.alias for item in self.aliases if item.action == "reused")

    @property
    def would_create(self) -> Tuple[str, ...]:
        return tuple(item.alias for item in self.aliases if item.action == "would_create")

    @property
    def conflicted(self) -> Tuple[str, ...]:
        return tuple(item.alias for item in self.aliases if item.action == "conflict")

    @property
    def ok(self) -> bool:
        return not self.issues and not self.conflicted and (self.dry_run or self.verified)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": 1,
            "ok": self.ok,
            "dry_run": self.dry_run,
            "target_user": self.target_user,
            "plan_sha256": self.plan_sha256,
            "verified": self.verified,
            "aliases": [item.to_dict() for item in self.aliases],
            "created": list(self.created),
            "reused": list(self.reused),
            "would_create": list(self.would_create),
            "conflicted": list(self.conflicted),
            "issues": list(self.issues),
            "actions_required": list(self.actions_required),
        }


@dataclasses.dataclass(frozen=True)
class WorkspaceAliasVerificationResult:
    target_user: str
    plan_sha256: str
    aliases: Tuple[WorkspaceAliasOutcome, ...]
    missing: Tuple[str, ...]
    conflicted: Tuple[str, ...]
    issues: Tuple[str, ...] = ()
    actions_required: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "target_user", canonical_workspace_email(self.target_user, "target user"))
        digest = _text(self.plan_sha256, "Workspace alias plan digest")
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("Workspace alias plan digest must be lowercase SHA-256")
        object.__setattr__(self, "aliases", tuple(sorted(self.aliases, key=lambda item: item.alias)))
        object.__setattr__(self, "missing", _email_tuple(self.missing, "missing alias"))
        object.__setattr__(self, "conflicted", _email_tuple(self.conflicted, "conflicted alias"))
        object.__setattr__(
            self,
            "issues",
            tuple(dict.fromkeys(_text(item, "verification issue") for item in self.issues)),
        )
        object.__setattr__(
            self,
            "actions_required",
            tuple(dict.fromkeys(_text(item, "verification action") for item in self.actions_required)),
        )

    @property
    def ok(self) -> bool:
        return not self.missing and not self.conflicted and not self.issues

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": 1,
            "ok": self.ok,
            "target_user": self.target_user,
            "plan_sha256": self.plan_sha256,
            "aliases": [item.to_dict() for item in self.aliases],
            "missing": list(self.missing),
            "conflicted": list(self.conflicted),
            "issues": list(self.issues),
            "actions_required": list(self.actions_required),
        }


class WorkspaceAliasProvisionError(RuntimeError):
    """A redacted provisioning failure carrying safe partial outcomes."""

    def __init__(self, message: str, result: WorkspaceAliasProvisionResult) -> None:
        super().__init__(message)
        self.result = result
        self.conflicts = result.issues


def _result_from_plan(
    plan: WorkspaceAliasPlan,
    *,
    dry_run: bool,
) -> WorkspaceAliasProvisionResult:
    outcomes = []
    for entry in plan.entries:
        if entry.status == "reuse":
            action = "reused"
            conflicts: Tuple[str, ...] = ()
        elif entry.status == "create" and dry_run:
            action = "would_create"
            conflicts = ()
        elif entry.status == "create":
            action = "conflict"
            conflicts = (f"Workspace alias {entry.alias!r} has not been created",)
        else:
            action = "conflict"
            conflicts = entry.conflicts
        outcomes.append(
            WorkspaceAliasOutcome(
                entry.alias,
                action,
                entry.owner_primary_email,
                conflicts,
            )
        )
    return WorkspaceAliasProvisionResult(
        dry_run=dry_run,
        target_user=plan.target_user,
        plan_sha256=plan.plan_sha256,
        verified=False,
        aliases=tuple(outcomes),
        issues=plan.conflicts,
        actions_required=plan.actions_required,
    )


def verify_workspace_aliases(
    client: WorkspaceDirectoryClient,
    plan: WorkspaceAliasPlan,
) -> WorkspaceAliasVerificationResult:
    """Verify every requested alias currently resolves to the target user."""

    live = discover_workspace_alias_plan(
        client,
        plan.target_user,
        plan.requested_aliases,
        customer=plan.customer_id,
    )
    issues = []
    if plan.target_user_id is None:
        issues.append("persisted Workspace alias plan has no immutable target user ID")
    elif live.target_user_id != plan.target_user_id:
        issues.append(
            "live Workspace target address resolves to a different immutable user ID than "
            "the persisted alias plan"
        )
    elif live.intent_sha256 != plan.intent_sha256:
        issues.append(
            "live Workspace target/customer binding no longer matches the persisted alias plan"
        )
    outcomes = []
    missing = []
    conflicted = []
    for entry in live.entries:
        if entry.status == "reuse" and entry.owner_primary_email == plan.target_user:
            outcomes.append(
                WorkspaceAliasOutcome(
                    entry.alias,
                    "reused",
                    entry.owner_primary_email,
                )
            )
        elif entry.status == "create":
            message = f"required Workspace alias {entry.alias!r} is missing"
            missing.append(entry.alias)
            issues.append(message)
            outcomes.append(WorkspaceAliasOutcome(entry.alias, "conflict", conflicts=(message,)))
        else:
            conflicts = entry.conflicts or (
                f"required Workspace alias {entry.alias!r} is not owned by the target user",
            )
            conflicted.append(entry.alias)
            issues.extend(conflicts)
            outcomes.append(
                WorkspaceAliasOutcome(
                    entry.alias,
                    "conflict",
                    entry.owner_primary_email,
                    conflicts,
                )
            )
    issues = list(dict.fromkeys(issues))
    actions = tuple(
        f"Ensure Workspace alias {alias!r} is owned by {plan.target_user!r}, then rerun verification."
        for alias in sorted(set(missing + conflicted))
    )
    return WorkspaceAliasVerificationResult(
        target_user=plan.target_user,
        plan_sha256=plan.plan_sha256,
        aliases=tuple(outcomes),
        missing=tuple(missing),
        conflicted=tuple(conflicted),
        issues=tuple(issues),
        actions_required=actions,
    )


def _partial_failure_result(
    plan: WorkspaceAliasPlan,
    outcomes: Sequence[WorkspaceAliasOutcome],
    failed_alias: str,
    issue: str,
) -> WorkspaceAliasProvisionResult:
    completed = {item.alias for item in outcomes}
    rows = list(outcomes)
    for entry in plan.entries:
        if entry.alias in completed:
            continue
        if entry.alias == failed_alias:
            conflict = issue
        else:
            conflict = (
                f"Workspace alias {entry.alias!r} was not attempted after an earlier provisioning failure"
            )
        rows.append(
            WorkspaceAliasOutcome(
                entry.alias,
                "conflict",
                entry.owner_primary_email,
                (conflict,),
            )
        )
    action = (
        "Resolve Workspace alias authorization or identity conflicts and rerun; "
        "aliases already created will be safely reused."
    )
    return WorkspaceAliasProvisionResult(
        dry_run=False,
        target_user=plan.target_user,
        plan_sha256=plan.plan_sha256,
        verified=False,
        aliases=tuple(rows),
        issues=(issue,),
        actions_required=(action,),
    )


def _attach_workspace_cancellation_result(
    exc: WorkspaceDirectoryCancelledError,
    result: WorkspaceAliasProvisionResult,
) -> None:
    exc.result = result


def provision_workspace_aliases(
    client: WorkspaceDirectoryClient,
    plan: WorkspaceAliasPlan,
    *,
    dry_run: bool = False,
) -> WorkspaceAliasProvisionResult:
    """Create only missing aliases, safely handling reruns and create races."""

    try:
        live = discover_workspace_alias_plan(
            client,
            plan.target_user,
            plan.requested_aliases,
            customer=plan.customer_id,
        )
    except WorkspaceDirectoryCancelledError as exc:
        issue = str(exc) or type(exc).__name__
        result = _result_from_plan(plan, dry_run=False)
        result = dataclasses.replace(
            result,
            issues=tuple(dict.fromkeys(result.issues + (issue,))),
            actions_required=tuple(
                dict.fromkeys(
                    result.actions_required
                    + ("Rerun Workspace alias provisioning; no new alias write was started.",)
                )
            ),
        )
        _attach_workspace_cancellation_result(exc, result)
        raise
    if plan.target_user_id is None:
        issue = "persisted Workspace alias plan has no immutable target user ID"
        result = _result_from_plan(live, dry_run=dry_run)
        return dataclasses.replace(
            result,
            plan_sha256=plan.plan_sha256,
            issues=tuple(dict.fromkeys(result.issues + (issue,))),
            actions_required=result.actions_required
            + ("Run preflight with a new staging directory.",),
        )
    if live.target_user_id != plan.target_user_id:
        issue = (
            "live Workspace target address resolves to a different immutable user ID than "
            "the persisted alias plan"
        )
        result = _result_from_plan(live, dry_run=dry_run)
        return dataclasses.replace(
            result,
            plan_sha256=plan.plan_sha256,
            issues=tuple(dict.fromkeys(result.issues + (issue,))),
            actions_required=result.actions_required
            + ("Use a new staging directory after reviewing the changed Workspace binding.",),
        )
    if live.intent_sha256 != plan.intent_sha256:
        issue = "live Workspace target/customer binding does not match the persisted alias plan"
        result = _result_from_plan(live, dry_run=dry_run)
        return dataclasses.replace(
            result,
            plan_sha256=plan.plan_sha256,
            issues=tuple(dict.fromkeys(result.issues + (issue,))),
            actions_required=result.actions_required
            + ("Use a new staging directory after reviewing the changed Workspace binding.",),
        )
    if not live.ok:
        result = _result_from_plan(live, dry_run=dry_run)
        return dataclasses.replace(result, plan_sha256=plan.plan_sha256)
    if dry_run:
        result = _result_from_plan(live, dry_run=True)
        return dataclasses.replace(result, plan_sha256=plan.plan_sha256)

    outcomes = [
        WorkspaceAliasOutcome(entry.alias, "reused", entry.owner_primary_email)
        for entry in live.entries
        if entry.status == "reuse"
    ]
    for entry in (item for item in live.entries if item.status == "create"):
        try:
            created = client.insert_user_alias(
                plan.target_user_id,
                entry.alias,
                expected_user_id=plan.target_user_id,
                expected_primary_email=plan.target_user,
            )
            if (
                created.user_id != plan.target_user_id
                or created.primary_email != plan.target_user
            ):
                raise WorkspaceDirectoryApiError(
                    "Workspace Directory create user alias returned an unexpected identity binding",
                    operation="create user alias",
                    required_scopes=(WORKSPACE_USER_ALIAS_SCOPE,),
                    mutation_outcome_uncertain=True,
                )
        except WorkspaceDirectoryApiError as exc:
            # A failed POST response can be ambiguous (the server may have
            # committed it).  Never repeat it blindly: re-read ownership first.
            try:
                race = discover_workspace_alias_plan(
                    client,
                    plan.target_user,
                    plan.requested_aliases,
                    customer=plan.customer_id,
                )
            except WorkspaceDirectoryCancelledError as cancel_error:
                issue = str(cancel_error) or type(cancel_error).__name__
                result = _partial_failure_result(plan, outcomes, entry.alias, issue)
                _attach_workspace_cancellation_result(cancel_error, result)
                raise
            except Exception as rediscovery_exc:
                if isinstance(rediscovery_exc, WorkspaceDirectoryApiError):
                    detail = str(rediscovery_exc)
                else:
                    detail = type(rediscovery_exc).__name__
                issue = (
                    f"Workspace alias {entry.alias!r} create outcome ownership "
                    f"rediscovery failed ({detail})"
                )
                result = _partial_failure_result(plan, outcomes, entry.alias, issue)
                raise WorkspaceAliasProvisionError(issue, result) from None
            race_entry = next(item for item in race.entries if item.alias == entry.alias)
            if (
                race.target_user_id == plan.target_user_id
                and race_entry.status == "reuse"
                and race_entry.owner_primary_email == plan.target_user
            ):
                outcomes.append(
                    WorkspaceAliasOutcome(
                        entry.alias,
                        "reused",
                        race_entry.owner_primary_email,
                    )
                )
                continue
            if exc.status_code == 409 and race_entry.conflicts:
                issue = race_entry.conflicts[0]
            else:
                issue = str(exc)
            result = _partial_failure_result(plan, outcomes, entry.alias, issue)
            raise WorkspaceAliasProvisionError(
                f"Workspace alias provisioning failed for {entry.alias!r}: {issue}",
                result,
            ) from None
        except WorkspaceDirectoryCancelledError as cancel_error:
            issue = str(cancel_error) or type(cancel_error).__name__
            result = _partial_failure_result(plan, outcomes, entry.alias, issue)
            _attach_workspace_cancellation_result(cancel_error, result)
            raise
        except Exception as exc:
            issue = (
                f"Workspace alias {entry.alias!r} provisioning failed "
                f"({type(exc).__name__})"
            )
            result = _partial_failure_result(plan, outcomes, entry.alias, issue)
            raise WorkspaceAliasProvisionError(issue, result) from None
        outcomes.append(
            WorkspaceAliasOutcome(
                entry.alias,
                "created",
                created.primary_email,
            )
        )

    try:
        verification = verify_workspace_aliases(client, plan)
    except WorkspaceDirectoryCancelledError as cancel_error:
        issue = str(cancel_error) or type(cancel_error).__name__
        result = WorkspaceAliasProvisionResult(
            dry_run=False,
            target_user=plan.target_user,
            plan_sha256=plan.plan_sha256,
            verified=False,
            aliases=tuple(outcomes),
            issues=(issue,),
            actions_required=(
                "Rerun Workspace alias provisioning; completed aliases will be safely reused and verified.",
            ),
        )
        _attach_workspace_cancellation_result(cancel_error, result)
        raise
    except Exception as exc:
        detail = str(exc) if isinstance(exc, WorkspaceDirectoryApiError) else type(exc).__name__
        issue = f"Workspace alias post-write verification failed ({detail})"
        result = WorkspaceAliasProvisionResult(
            dry_run=False,
            target_user=plan.target_user,
            plan_sha256=plan.plan_sha256,
            verified=False,
            aliases=tuple(outcomes),
            issues=(issue,),
            actions_required=(
                "Rerun alias provisioning; completed aliases will be safely reused and verified.",
            ),
        )
        raise WorkspaceAliasProvisionError(issue, result) from None
    if not verification.ok:
        result = WorkspaceAliasProvisionResult(
            dry_run=False,
            target_user=plan.target_user,
            plan_sha256=plan.plan_sha256,
            verified=False,
            aliases=tuple(outcomes),
            issues=verification.issues,
            actions_required=verification.actions_required,
        )
        raise WorkspaceAliasProvisionError(
            "Workspace alias verification failed after provisioning",
            result,
        )
    return WorkspaceAliasProvisionResult(
        dry_run=False,
        target_user=plan.target_user,
        plan_sha256=plan.plan_sha256,
        verified=True,
        aliases=tuple(outcomes),
    )


__all__ = [
    "DEFAULT_DIRECTORY_API_BASE_URL",
    "MAX_WORKSPACE_USER_ALIASES",
    "WORKSPACE_ALIAS_PLAN_FILENAME",
    "WORKSPACE_DIRECTORY_SCOPES",
    "WORKSPACE_DOMAIN_READONLY_SCOPE",
    "WORKSPACE_GROUP_READONLY_SCOPE",
    "WORKSPACE_USER_ALIAS_SCOPE",
    "WORKSPACE_USER_READONLY_SCOPE",
    "WorkspaceAliasCandidateDiscovery",
    "WorkspaceAliasDiscovery",
    "WorkspaceAliasOutcome",
    "WorkspaceAliasPlan",
    "WorkspaceAliasPlanEntry",
    "WorkspaceAliasProvisionError",
    "WorkspaceAliasProvisionResult",
    "WorkspaceAliasVerificationResult",
    "WorkspaceAuthenticationError",
    "WorkspaceAuthorizationIdentity",
    "WorkspaceDirectoryApiError",
    "WorkspaceDirectoryCancelledError",
    "WorkspaceDirectoryClient",
    "WorkspaceDirectoryGroup",
    "WorkspaceDirectoryUser",
    "WorkspaceDomain",
    "WorkspaceUserAlias",
    "build_workspace_directory_client_from_service_account",
    "build_workspace_directory_client_from_token",
    "canonical_workspace_alias_email",
    "canonical_workspace_email",
    "discover_workspace_alias_plan",
    "discover_workspace_aliases",
    "plan_workspace_aliases",
    "provision_workspace_aliases",
    "verify_workspace_aliases",
    "workspace_alias_plan_path",
]
