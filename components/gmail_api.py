"""Small, safe Gmail REST client and idempotent routing reconciliation.

This module intentionally does not import provider or routing modules.  It can
therefore be used by preflight/planning code as well as by the migration
executor without introducing an import cycle.

The planning functions are pure: callers supply snapshots returned by the
Gmail API and receive immutable plans.  The reconciliation functions perform
the writes, then re-list and verify the resulting state before reporting
success.
"""

from __future__ import annotations

import copy
import dataclasses
import email.utils
import math
import random
import re
import time
import urllib.parse
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple

import idna

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover - exercised only in broken installations
    requests = None  # type: ignore


GMAIL_LABELS_SCOPE = "https://www.googleapis.com/auth/gmail.labels"
GMAIL_MODIFY_SCOPE = "https://www.googleapis.com/auth/gmail.modify"
GMAIL_FULL_MAIL_SCOPE = "https://mail.google.com/"
GMAIL_SETTINGS_BASIC_SCOPE = "https://www.googleapis.com/auth/gmail.settings.basic"

LABEL_SCOPE_HINT = (
    f"{GMAIL_LABELS_SCOPE} (or compatible {GMAIL_MODIFY_SCOPE} or "
    f"{GMAIL_FULL_MAIL_SCOPE} label-write scope)"
)
FILTER_SCOPE_HINT = GMAIL_SETTINGS_BASIC_SCOPE

DEFAULT_GMAIL_API_BASE_URL = "https://gmail.googleapis.com/gmail/v1"
GMAIL_FILTER_LIMIT = 1000
GMAIL_LABEL_LIMIT = 10_000
GMAIL_LABEL_NAME_MAX_LENGTH = 225

_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+$")
_SIMPLE_DELIVERED_TO_RE = re.compile(
    r'^\s*deliveredto:\s*(?:"([^"\s]+)"|([^\s"]+))\s*$',
    flags=re.IGNORECASE,
)
_SAFE_GOOGLE_REASON_RE = re.compile(r"^[A-Za-z0-9_.-]{1,80}$", flags=re.ASCII)
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


def _canonical_filter_email(value: Any, context: str) -> str:
    address = _nonempty_text(value, context)
    if address.count("@") != 1 or not _EMAIL_RE.fullmatch(address):
        raise ValueError(f"{context} must be an email address without whitespace")
    local, domain = address.rsplit("@", 1)
    if not local or len(local) > 64 or not domain:
        raise ValueError(f"{context} must be an email address without whitespace")
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
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or not all(char.isalnum() or char == "-" for char in label)
        for label in ascii_domain.split(".")
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


def canonical_filter_email(
    value: Any,
    context: str = "filter delivered_to",
) -> str:
    """Return the exact address form used by Gmail filter conditions."""

    return _canonical_filter_email(value, context)


def _safe_google_error_reasons(response: Any) -> Tuple[str, ...]:
    """Extract bounded machine codes without ever surfacing API error messages."""

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


class GmailApiError(RuntimeError):
    """A redacted Gmail API transport, authorization, or response error."""

    def __init__(
        self,
        message: str,
        *,
        operation: str,
        status_code: Optional[int] = None,
        required_scope: Optional[str] = None,
        reasons: Iterable[str] = (),
        retryable: bool = False,
        mutation_outcome_uncertain: bool = False,
        result: Optional[Any] = None,
    ) -> None:
        super().__init__(message)
        self.operation = operation
        self.status_code = status_code
        self.required_scope = required_scope
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
        self.result = result
        self.context: Dict[str, Any] = {}

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "error": "gmail_api",
            "operation": self.operation,
            "message": str(self),
        }
        if self.status_code is not None:
            result["status_code"] = self.status_code
        if self.required_scope is not None:
            result["required_scope"] = self.required_scope
        result["reasons"] = list(self.reasons)
        result["retryable"] = self.retryable
        result["mutation_outcome_uncertain"] = self.mutation_outcome_uncertain
        if self.context:
            result["context"] = copy.deepcopy(self.context)
        if self.result is not None and hasattr(self.result, "to_dict"):
            result["result"] = self.result.to_dict()
        return result


class _GmailApiResourceError(GmailApiError):
    """An API response was syntactically valid JSON but not a valid resource."""


def _attach_label_collision_context(
    rediscovery_error: GmailApiError,
    create_error: GmailApiError,
) -> None:
    """Retain a redacted, structured summary of the collision that prompted a relist."""

    collision: Dict[str, Any] = {
        "operation": create_error.operation,
        "reasons": list(create_error.reasons),
        "retryable": create_error.retryable,
        "mutation_outcome_uncertain": create_error.mutation_outcome_uncertain,
    }
    if create_error.status_code is not None:
        collision["status_code"] = create_error.status_code
    if create_error.required_scope is not None:
        collision["required_scope"] = create_error.required_scope
    rediscovery_error.context["label_create_collision"] = collision


class GmailApiCancelledError(InterruptedError):
    """Raised when cooperative cancellation stops a Gmail API operation."""

    def __init__(self, operation: str, *, result: Optional[Any] = None) -> None:
        self.operation = operation
        self.result = result
        super().__init__(f"Gmail API {operation} cancelled: stop requested")

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "error": "gmail_api_cancelled",
            "operation": self.operation,
            "message": str(self),
        }
        if self.result is not None and hasattr(self.result, "to_dict"):
            payload["result"] = self.result.to_dict()
        return payload


class GmailReconciliationError(RuntimeError):
    """Raised before mutation for conflicts, or after failed verification."""

    def __init__(
        self,
        message: str,
        conflicts: Iterable[str],
        *,
        result: Optional[Any] = None,
    ) -> None:
        ordered = tuple(dict.fromkeys(str(item) for item in conflicts if str(item)))
        super().__init__(message + (f": {'; '.join(ordered)}" if ordered else ""))
        self.conflicts = ordered
        self.result = result

    def to_dict(self) -> Dict[str, Any]:
        payload = {
            "error": "gmail_reconciliation",
            "message": str(self),
            "conflicts": list(self.conflicts),
        }
        if self.result is not None and hasattr(self.result, "to_dict"):
            payload["result"] = self.result.to_dict()
        return payload


def _nonempty_text(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{context} must be a non-empty string")
    if value != value.strip():
        raise ValueError(f"{context} must not have leading or trailing whitespace")
    if _CONTROL_CHAR_RE.search(value):
        raise ValueError(f"{context} must not contain control characters")
    return value


def _label_name(value: Any, context: str = "label name") -> str:
    name = _nonempty_text(value, context)
    if name.startswith("/") or name.endswith("/") or "//" in name:
        raise ValueError(f"{context} has an invalid hierarchy")
    return name


def _label_name_length_conflict(name: str) -> Optional[str]:
    """Describe an unsupported full Gmail label path without rejecting discovery.

    Gmail can return pre-existing resources that no longer satisfy the limits we
    enforce for new configuration. Keep parsing those resources, but reject a
    requested full label/path deterministically before any reconciliation write.
    """

    if len(name) <= GMAIL_LABEL_NAME_MAX_LENGTH:
        return None
    return (
        f"label {name!r} has full path length {len(name)}, exceeding Gmail's "
        f"maximum of {GMAIL_LABEL_NAME_MAX_LENGTH} characters"
    )


def _filter_id(value: Any) -> str:
    return _nonempty_text(value, "filter id")


def _mapping_copy(value: Any, context: str) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{context} must be an object")
    result: Dict[str, Any] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise ValueError(f"{context} keys must be strings")
        result[key] = copy.deepcopy(item)
    return result


def _filter_action_resource(value: Any) -> Dict[str, Any]:
    """Validate the typed fields in a Gmail API filter action resource."""

    action = _mapping_copy(value, "filter action")
    for key in ("addLabelIds", "removeLabelIds"):
        if key not in action:
            continue
        raw_ids = action[key]
        if not isinstance(raw_ids, list):
            raise ValueError(f"filter action {key} must be an array")
        action[key] = [
            _nonempty_text(item, f"filter action {key} item") for item in raw_ids
        ]
    return action


@dataclasses.dataclass(frozen=True)
class GmailLabel:
    id: str
    name: str
    type: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _nonempty_text(self.id, "label id"))
        object.__setattr__(self, "name", _nonempty_text(self.name, "label name"))
        label_type = _nonempty_text(self.type, "label type").casefold()
        if label_type not in {"user", "system"}:
            raise ValueError("label type must be 'user' or 'system'")
        object.__setattr__(self, "type", label_type)

    @staticmethod
    def from_api(raw: Mapping[str, Any]) -> "GmailLabel":
        if not isinstance(raw, Mapping):
            raise ValueError("Gmail label resource must be an object")
        return GmailLabel(
            id=_nonempty_text(raw.get("id"), "label id"),
            name=_nonempty_text(raw.get("name"), "label name"),
            type=_nonempty_text(raw.get("type"), "label type"),
        )

    def to_dict(self) -> Dict[str, str]:
        return {"id": self.id, "name": self.name, "type": self.type}


@dataclasses.dataclass(frozen=True)
class GmailFilter:
    id: str
    criteria: Mapping[str, Any]
    action: Mapping[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _filter_id(self.id))
        object.__setattr__(self, "criteria", _mapping_copy(self.criteria, "filter criteria"))
        object.__setattr__(self, "action", _filter_action_resource(self.action))

    @staticmethod
    def from_api(raw: Mapping[str, Any]) -> "GmailFilter":
        if not isinstance(raw, Mapping):
            raise ValueError("Gmail filter resource must be an object")
        return GmailFilter(
            id=_filter_id(raw.get("id")),
            criteria=_mapping_copy(raw.get("criteria"), "filter criteria"),
            action=_mapping_copy(raw.get("action"), "filter action"),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "criteria": copy.deepcopy(dict(self.criteria)),
            "action": copy.deepcopy(dict(self.action)),
        }


@dataclasses.dataclass(frozen=True)
class GmailFilterSpec:
    """A narrowly scoped ``deliveredto:`` Gmail filter declaration."""

    delivered_to: str
    label: str
    inbox: str = "keep"
    mark_read: bool = False
    conflict_policy: str = "error"

    def __post_init__(self) -> None:
        address = canonical_filter_email(self.delivered_to)
        object.__setattr__(self, "delivered_to", address)
        object.__setattr__(self, "label", _label_name(self.label, "filter label"))
        inbox = _nonempty_text(self.inbox, "filter inbox").casefold()
        if inbox not in {"keep", "archive"}:
            raise ValueError("filter inbox must be one of: keep, archive")
        object.__setattr__(self, "inbox", inbox)
        if type(self.mark_read) is not bool:
            raise ValueError("filter mark_read must be a boolean")
        policy = _nonempty_text(self.conflict_policy, "filter conflict_policy").casefold()
        if policy not in {"error", "replace"}:
            raise ValueError("filter conflict_policy must be one of: error, replace")
        object.__setattr__(self, "conflict_policy", policy)

    @property
    def query(self) -> str:
        return f"deliveredto:{self.delivered_to}"

    @property
    def criteria(self) -> Dict[str, str]:
        return {"query": self.query}

    def action_for_label_id(self, label_id: str) -> Dict[str, List[str]]:
        label_id = _nonempty_text(label_id, "filter label id")
        remove: List[str] = []
        if self.inbox == "archive":
            remove.append("INBOX")
        if self.mark_read:
            remove.append("UNREAD")
        action: Dict[str, List[str]] = {"addLabelIds": [label_id]}
        if remove:
            action["removeLabelIds"] = remove
        return action

    def to_dict(self) -> Dict[str, Any]:
        return {
            "delivered_to": self.delivered_to,
            "query": self.query,
            "label": self.label,
            "inbox": self.inbox,
            "mark_read": self.mark_read,
            "conflict_policy": self.conflict_policy,
        }


# A shorter public spelling for callers that do not need the Gmail qualifier.
FilterSpec = GmailFilterSpec
DeliveredToFilterSpec = GmailFilterSpec


class GmailApiClient:
    """Minimal Gmail API client with an injectable ``requests.Session``."""

    def __init__(
        self,
        access_token: str,
        *,
        session: Optional[Any] = None,
        user_id: str = "me",
        base_url: str = DEFAULT_GMAIL_API_BASE_URL,
        timeout_sec: float = 20,
        retry_max_attempts: int = 5,
        retry_base_delay_sec: float = 0.5,
        retry_max_delay_sec: float = 30,
        sleep_fn: Optional[Callable[[float], None]] = None,
        random_fn: Optional[Callable[[], float]] = None,
        stop_event: Optional[object] = None,
    ) -> None:
        if requests is None:  # type: ignore
            raise RuntimeError(
                "Gmail API provisioning requires the 'requests' package. "
                "Install it via: pip install -r requirements.txt"
            )
        self._access_token = _nonempty_text(access_token, "Gmail API access token")
        self.user_id = _nonempty_text(user_id, "Gmail API user id")
        self.base_url = _nonempty_text(base_url, "Gmail API base URL").rstrip("/")
        if (
            not isinstance(timeout_sec, (int, float))
            or isinstance(timeout_sec, bool)
            or not math.isfinite(float(timeout_sec))
            or timeout_sec <= 0
        ):
            raise ValueError("Gmail API timeout_sec must be positive")
        if type(retry_max_attempts) is not int or retry_max_attempts < 1:
            raise ValueError("Gmail API retry_max_attempts must be a positive integer")
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
                raise ValueError(f"Gmail API {name} must be finite and non-negative")
        if retry_max_delay_sec < retry_base_delay_sec:
            raise ValueError("Gmail API retry_max_delay_sec must be at least retry_base_delay_sec")
        if sleep_fn is not None and not callable(sleep_fn):
            raise ValueError("Gmail API sleep_fn must be callable")
        if random_fn is not None and not callable(random_fn):
            raise ValueError("Gmail API random_fn must be callable")
        if stop_event is not None and not callable(
            getattr(stop_event, "is_set", None)
        ) and not callable(stop_event):
            raise ValueError("Gmail API stop_event must expose is_set() or be callable")
        self.timeout_sec = float(timeout_sec)
        self.retry_max_attempts = retry_max_attempts
        self.retry_base_delay_sec = float(retry_base_delay_sec)
        self.retry_max_delay_sec = float(retry_max_delay_sec)
        self._sleep = time.sleep if sleep_fn is None else sleep_fn
        self._random = random.random if random_fn is None else random_fn
        self._stop_event = stop_event
        self.session = session if session is not None else requests.Session()  # type: ignore

    def _url(self, suffix: str) -> str:
        quoted_user = urllib.parse.quote(self.user_id, safe="")
        return f"{self.base_url}/users/{quoted_user}/{suffix.lstrip('/')}"

    def _stop_requested(self) -> bool:
        if self._stop_event is None:
            return False
        is_set = getattr(self._stop_event, "is_set", None)
        if callable(is_set):
            return bool(is_set())
        return bool(self._stop_event())  # type: ignore[operator]

    def _raise_if_cancelled(self, operation: str) -> None:
        if self._stop_requested():
            raise GmailApiCancelledError(operation)

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
                raise GmailApiCancelledError(operation)
        else:
            self._sleep(delay)
        self._raise_if_cancelled(operation)

    def _request(
        self,
        method: str,
        suffix: str,
        *,
        operation: str,
        scope_hint: str,
        expected_statuses: Tuple[int, ...],
        json_body: Optional[Mapping[str, Any]] = None,
        expect_json: bool = True,
    ) -> Optional[Dict[str, Any]]:
        method = method.upper()
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self._access_token}",
        }
        kwargs: Dict[str, Any] = {
            "headers": headers,
            "timeout": self.timeout_sec,
            "allow_redirects": False,
        }
        if json_body is not None:
            kwargs["json"] = copy.deepcopy(dict(json_body))
        url = self._url(suffix)
        for attempt in range(1, self.retry_max_attempts + 1):
            self._raise_if_cancelled(operation)
            try:
                response = self.session.request(method, url, **kwargs)
            except Exception as exc:
                # Exception text may include request headers or URLs.  Report
                # only its class so bearer tokens and user IDs stay redacted.
                if method in _SAFE_RETRY_METHODS and attempt < self.retry_max_attempts:
                    self._sleep_for_retry(attempt, operation=operation)
                    continue
                raise GmailApiError(
                    f"Gmail API {operation} failed: transport error ({type(exc).__name__})",
                    operation=operation,
                    required_scope=scope_hint,
                    retryable=method in _SAFE_RETRY_METHODS,
                    mutation_outcome_uncertain=method not in _SAFE_RETRY_METHODS,
                ) from None

            status_code = getattr(response, "status_code", None)
            if type(status_code) is not int:
                raise GmailApiError(
                    f"Gmail API {operation} failed: response has no valid HTTP status",
                    operation=operation,
                    required_scope=scope_hint,
                    mutation_outcome_uncertain=method not in _SAFE_RETRY_METHODS,
                )
            if status_code not in expected_statuses:
                reasons = _safe_google_error_reasons(response)
                reason_retryable = _has_retryable_google_reason(reasons)
                quota_or_rate_limited = _has_quota_rate_google_reason(reasons)
                retryable = status_code in _RETRYABLE_HTTP_STATUSES or (
                    status_code == 403 and reason_retryable
                )
                safe_to_repeat = method in _SAFE_RETRY_METHODS or (
                    method == "POST"
                    and (
                        status_code == 429
                        or (status_code == 403 and reason_retryable)
                    )
                )
                if retryable and safe_to_repeat and attempt < self.retry_max_attempts:
                    self._sleep_for_retry(attempt, response, operation=operation)
                    continue
                reason_text = (
                    f"; reason(s): {', '.join(reasons)}" if reasons else ""
                )
                if status_code == 401:
                    message = (
                        f"Gmail API {operation} failed: HTTP 401 "
                        f"(access token is invalid or expired); required scope: {scope_hint}"
                    )
                elif (
                    status_code == 403
                    and not quota_or_rate_limited
                    and not reason_retryable
                ):
                    message = (
                        f"Gmail API {operation} failed: HTTP 403 "
                        f"(permission denied){reason_text}; required scope: {scope_hint}"
                    )
                elif status_code == 429 or quota_or_rate_limited:
                    message = (
                        f"Gmail API {operation} failed: HTTP {status_code} "
                        f"(rate or quota limited){reason_text}"
                    )
                elif retryable:
                    message = (
                        f"Gmail API {operation} failed: HTTP {status_code} "
                        f"(transient service failure){reason_text}"
                    )
                else:
                    message = f"Gmail API {operation} failed: HTTP {status_code}{reason_text}"
                raise GmailApiError(
                    message,
                    operation=operation,
                    status_code=status_code,
                    required_scope=scope_hint,
                    reasons=reasons,
                    retryable=retryable,
                    mutation_outcome_uncertain=(
                        method not in _SAFE_RETRY_METHODS and status_code >= 500
                    ),
                )
            if not expect_json:
                return None
            try:
                payload = response.json()
            except Exception:
                raise GmailApiError(
                    f"Gmail API {operation} returned invalid JSON",
                    operation=operation,
                    status_code=status_code,
                    required_scope=scope_hint,
                    mutation_outcome_uncertain=method not in _SAFE_RETRY_METHODS,
                ) from None
            if not isinstance(payload, dict):
                raise GmailApiError(
                    f"Gmail API {operation} returned an invalid response object",
                    operation=operation,
                    status_code=status_code,
                    required_scope=scope_hint,
                    mutation_outcome_uncertain=method not in _SAFE_RETRY_METHODS,
                )
            return payload
        raise AssertionError("unreachable Gmail API retry loop")

    @staticmethod
    def _parse_label(
        raw: Mapping[str, Any],
        operation: str,
        *,
        mutation_outcome_uncertain: bool = False,
    ) -> GmailLabel:
        try:
            return GmailLabel.from_api(raw)
        except (TypeError, ValueError) as exc:
            raise _GmailApiResourceError(
                f"Gmail API {operation} returned an invalid label resource ({type(exc).__name__})",
                operation=operation,
                required_scope=LABEL_SCOPE_HINT,
                mutation_outcome_uncertain=mutation_outcome_uncertain,
            ) from None

    @staticmethod
    def _parse_filter(
        raw: Mapping[str, Any],
        operation: str,
        *,
        mutation_outcome_uncertain: bool = False,
    ) -> GmailFilter:
        try:
            return GmailFilter.from_api(raw)
        except (TypeError, ValueError) as exc:
            raise _GmailApiResourceError(
                f"Gmail API {operation} returned an invalid filter resource ({type(exc).__name__})",
                operation=operation,
                required_scope=FILTER_SCOPE_HINT,
                mutation_outcome_uncertain=mutation_outcome_uncertain,
            ) from None

    def list_labels(self) -> Tuple[GmailLabel, ...]:
        payload = self._request(
            "GET",
            "labels",
            operation="list labels",
            scope_hint=LABEL_SCOPE_HINT,
            expected_statuses=(200,),
        )
        assert payload is not None
        raw_labels = payload.get("labels", [])
        if not isinstance(raw_labels, list):
            raise GmailApiError(
                "Gmail API list labels returned an invalid labels array",
                operation="list labels",
                required_scope=LABEL_SCOPE_HINT,
            )
        labels = tuple(self._parse_label(item, "list labels") for item in raw_labels)
        ids = [label.id for label in labels]
        if len(ids) != len(set(ids)):
            raise GmailApiError(
                "Gmail API list labels returned duplicate label IDs",
                operation="list labels",
                required_scope=LABEL_SCOPE_HINT,
            )
        return tuple(sorted(labels, key=lambda item: (item.name.casefold(), item.name, item.id)))

    def create_label(self, name: str) -> GmailLabel:
        name = _label_name(name)
        length_conflict = _label_name_length_conflict(name)
        if length_conflict is not None:
            raise ValueError(length_conflict)
        payload = self._request(
            "POST",
            "labels",
            operation="create label",
            scope_hint=LABEL_SCOPE_HINT,
            expected_statuses=(200,),
            json_body={"name": name},
        )
        assert payload is not None
        return self._parse_label(
            payload,
            "create label",
            mutation_outcome_uncertain=True,
        )

    def list_filters(self) -> Tuple[GmailFilter, ...]:
        payload = self._request(
            "GET",
            "settings/filters",
            operation="list filters",
            scope_hint=FILTER_SCOPE_HINT,
            expected_statuses=(200,),
        )
        assert payload is not None
        raw_filters = payload.get("filter", [])
        if not isinstance(raw_filters, list):
            raise GmailApiError(
                "Gmail API list filters returned an invalid filter array",
                operation="list filters",
                required_scope=FILTER_SCOPE_HINT,
            )
        filters = tuple(self._parse_filter(item, "list filters") for item in raw_filters)
        ids = [item.id for item in filters]
        if len(ids) != len(set(ids)):
            raise GmailApiError(
                "Gmail API list filters returned duplicate filter IDs",
                operation="list filters",
                required_scope=FILTER_SCOPE_HINT,
            )
        return tuple(sorted(filters, key=lambda item: item.id))

    def create_filter(
        self,
        criteria: Mapping[str, Any],
        action: Mapping[str, Any],
    ) -> GmailFilter:
        criteria_copy = _mapping_copy(criteria, "filter criteria")
        action_copy = _mapping_copy(action, "filter action")
        payload = self._request(
            "POST",
            "settings/filters",
            operation="create filter",
            scope_hint=FILTER_SCOPE_HINT,
            expected_statuses=(200,),
            json_body={"criteria": criteria_copy, "action": action_copy},
        )
        assert payload is not None
        return self._parse_filter(
            payload,
            "create filter",
            mutation_outcome_uncertain=True,
        )

    def delete_filter(self, filter_id: str) -> None:
        filter_id = _filter_id(filter_id)
        quoted_id = urllib.parse.quote(filter_id, safe="")
        self._request(
            "DELETE",
            f"settings/filters/{quoted_id}",
            operation="delete filter",
            scope_hint=FILTER_SCOPE_HINT,
            # Deletion is idempotent: a concurrent/ambiguous prior deletion
            # already achieved the required absent state.
            expected_statuses=(200, 204, 404),
            expect_json=False,
        )


def _coerce_label(value: Any) -> GmailLabel:
    if isinstance(value, GmailLabel):
        return value
    if isinstance(value, Mapping):
        return GmailLabel.from_api(value)
    raise ValueError("existing label must be a GmailLabel or API object")


def _coerce_filter(value: Any) -> GmailFilter:
    if isinstance(value, GmailFilter):
        return value
    if isinstance(value, Mapping):
        return GmailFilter.from_api(value)
    raise ValueError("existing filter must be a GmailFilter or API object")


def _coerce_filter_spec(value: Any) -> GmailFilterSpec:
    if isinstance(value, GmailFilterSpec):
        return value
    if not isinstance(value, Mapping):
        raise ValueError("filter spec must be a GmailFilterSpec or object")
    allowed = {"delivered_to", "label", "inbox", "mark_read", "conflict_policy"}
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ValueError(f"filter spec has unknown field(s): {', '.join(unknown)}")
    return GmailFilterSpec(
        delivered_to=_nonempty_text(value.get("delivered_to"), "filter delivered_to"),
        label=_label_name(value.get("label"), "filter label"),
        inbox=_nonempty_text(value.get("inbox", "keep"), "filter inbox"),
        mark_read=value.get("mark_read", False),
        conflict_policy=_nonempty_text(
            value.get("conflict_policy", "error"),
            "filter conflict_policy",
        ),
    )


def _stable_freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        items = []
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("Gmail filter objects must use string keys")
            items.append((key, _stable_freeze(item)))
        return tuple(sorted(items))
    if isinstance(value, (list, tuple)):
        return tuple(_stable_freeze(item) for item in value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise ValueError(f"unsupported Gmail filter value type: {type(value).__name__}")


def _normalized_query(value: str) -> str:
    match = _SIMPLE_DELIVERED_TO_RE.fullmatch(value)
    if match is None:
        return value.strip()
    address = match.group(1) or match.group(2)
    try:
        address = _canonical_filter_email(address, "deliveredto query address")
    except ValueError:
        address = address.casefold()
    return f"deliveredto:{address}"


def canonical_filter_criteria(criteria: Mapping[str, Any]) -> Tuple[Tuple[str, Any], ...]:
    """Return a deterministic semantic key for Gmail filter criteria."""

    raw = _mapping_copy(criteria, "filter criteria")
    canonical: List[Tuple[str, Any]] = []
    for key in sorted(raw):
        value = raw[key]
        if value is None or value == "" or value == [] or value == {}:
            continue
        if key in {"hasAttachment", "excludeChats"} and value is False:
            continue
        if key == "query":
            if not isinstance(value, str):
                raise ValueError("filter criteria query must be a string")
            value = _normalized_query(value)
        canonical.append((key, _stable_freeze(value)))
    return tuple(canonical)


def _canonical_id_list(value: Any, context: str) -> Tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"{context} must be an array")
    values = tuple(_nonempty_text(item, context) for item in value)
    return tuple(sorted(set(values)))


def canonical_filter_action(action: Mapping[str, Any]) -> Tuple[Tuple[str, Any], ...]:
    """Return a deterministic action key; label-ID array order is ignored."""

    raw = _mapping_copy(action, "filter action")
    canonical: List[Tuple[str, Any]] = []
    for key in sorted(raw):
        value = raw[key]
        if key in {"addLabelIds", "removeLabelIds"}:
            ids = _canonical_id_list(value, f"filter action {key}")
            if ids:
                canonical.append((key, ids))
            continue
        if value is None or value == "" or value == [] or value == {}:
            continue
        canonical.append((key, _stable_freeze(value)))
    return tuple(canonical)


def _label_prefixes(name: str) -> Tuple[str, ...]:
    parts = name.split("/")
    return tuple("/".join(parts[:index]) for index in range(1, len(parts) + 1))


@dataclasses.dataclass(frozen=True)
class LabelPlanEntry:
    name: str
    action: str
    label_id: Optional[str] = None
    conflicts: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "name": self.name,
            "action": self.action,
            "conflicts": list(self.conflicts),
        }
        if self.label_id is not None:
            result["label_id"] = self.label_id
        return result


@dataclasses.dataclass(frozen=True)
class LabelReconciliationPlan:
    entries: Tuple[LabelPlanEntry, ...]
    conflicts: Tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return not self.conflicts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "entries": [entry.to_dict() for entry in self.entries],
            "conflicts": list(self.conflicts),
        }


def plan_label_reconciliation(
    required_names: Iterable[str],
    existing_labels: Iterable[Any],
) -> LabelReconciliationPlan:
    """Plan exact-name reuse/creation and detect all naming conflicts."""

    desired_names = tuple(
        sorted(
            {_label_name(name) for name in required_names},
            key=lambda name: (name.casefold(), name),
        )
    )
    labels = tuple(
        sorted(
            (_coerce_label(item) for item in existing_labels),
            key=lambda item: (item.name.casefold(), item.name, item.id),
        )
    )

    existing_exact: Dict[str, List[GmailLabel]] = {}
    existing_folded: Dict[str, List[GmailLabel]] = {}
    existing_prefixes: Dict[str, set[str]] = {}
    system_names: Dict[str, List[str]] = {}
    for label in labels:
        existing_exact.setdefault(label.name, []).append(label)
        existing_folded.setdefault(label.name.casefold(), []).append(label)
        for prefix in _label_prefixes(label.name):
            existing_prefixes.setdefault(prefix.casefold(), set()).add(prefix)
        if label.type == "system":
            system_names.setdefault(label.name.casefold(), []).append(label.name)

    desired_folded: Dict[str, set[str]] = {}
    desired_prefixes: Dict[str, set[str]] = {}
    for name in desired_names:
        desired_folded.setdefault(name.casefold(), set()).add(name)
        for prefix in _label_prefixes(name):
            desired_prefixes.setdefault(prefix.casefold(), set()).add(prefix)

    all_conflicts: List[str] = []
    entries: List[LabelPlanEntry] = []
    for name in desired_names:
        conflicts: List[str] = []
        length_conflict = _label_name_length_conflict(name)
        if length_conflict is not None:
            conflicts.append(length_conflict)
        folded_variants = desired_folded[name.casefold()]
        if len(folded_variants) > 1:
            conflicts.append(
                f"required labels differ only by case: {', '.join(repr(item) for item in sorted(folded_variants))}"
            )

        exact = existing_exact.get(name, [])
        folded = existing_folded.get(name.casefold(), [])
        if len(exact) > 1:
            conflicts.append(
                f"label {name!r} has duplicate exact-name resources: "
                + ", ".join(sorted(label.id for label in exact))
            )
        if any(label.type == "system" for label in exact):
            conflicts.append(f"label {name!r} conflicts with a Gmail system label")
        elif not exact and folded:
            variants = sorted({label.name for label in folded})
            if any(label.type == "system" for label in folded):
                conflicts.append(
                    f"label {name!r} conflicts case-insensitively with Gmail system label "
                    + ", ".join(repr(item) for item in variants)
                )
            else:
                conflicts.append(
                    f"label {name!r} conflicts case-insensitively with existing label "
                    + ", ".join(repr(item) for item in variants)
                )

        for prefix in _label_prefixes(name):
            prefix_key = prefix.casefold()
            desired_variants = desired_prefixes.get(prefix_key, set())
            if any(item != prefix for item in desired_variants):
                conflicts.append(
                    f"label {name!r} has a hierarchy casing conflict at {prefix!r}: "
                    + ", ".join(repr(item) for item in sorted(desired_variants))
                )
            existing_variants = existing_prefixes.get(prefix_key, set())
            if existing_variants and prefix not in existing_variants:
                conflicts.append(
                    f"label {name!r} has a hierarchy casing conflict at {prefix!r} with "
                    + ", ".join(repr(item) for item in sorted(existing_variants))
                )
            system_variants = system_names.get(prefix_key, [])
            if system_variants and prefix != name:
                conflicts.append(
                    f"label {name!r} has Gmail system label in its hierarchy at {prefix!r}"
                )

        conflicts = list(dict.fromkeys(conflicts))
        all_conflicts.extend(conflicts)
        if conflicts:
            entries.append(LabelPlanEntry(name=name, action="conflict", conflicts=tuple(conflicts)))
        elif exact:
            entries.append(LabelPlanEntry(name=name, action="reuse", label_id=exact[0].id))
        else:
            entries.append(LabelPlanEntry(name=name, action="create"))

    missing_creates = sum(entry.action == "create" for entry in entries)
    required_count = len(labels) + missing_creates
    if required_count > GMAIL_LABEL_LIMIT:
        message = (
            "Gmail label limit would be exceeded: "
            f"{len(labels)} existing label(s) plus {missing_creates} required create(s) "
            f"would require {required_count}, maximum {GMAIL_LABEL_LIMIT}"
        )
        all_conflicts.append(message)
        entries = [
            dataclasses.replace(
                entry,
                action="conflict",
                conflicts=tuple(dict.fromkeys(entry.conflicts + (message,))),
            )
            if entry.action == "create"
            else entry
            for entry in entries
        ]

    return LabelReconciliationPlan(
        entries=tuple(entries),
        conflicts=tuple(dict.fromkeys(all_conflicts)),
    )


@dataclasses.dataclass(frozen=True)
class FilterPlanEntry:
    spec: GmailFilterSpec
    action: str
    label_id: Optional[str] = None
    filter_id: Optional[str] = None
    equivalent_filter_ids: Tuple[str, ...] = ()
    incompatible_filter_ids: Tuple[str, ...] = ()
    delete_filter_ids: Tuple[str, ...] = ()
    conflicts: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        result = self.spec.to_dict()
        result.update(
            {
                "action": self.action,
                "equivalent_filter_ids": list(self.equivalent_filter_ids),
                "incompatible_filter_ids": list(self.incompatible_filter_ids),
                "delete_filter_ids": list(self.delete_filter_ids),
                "conflicts": list(self.conflicts),
            }
        )
        if self.label_id is not None:
            result["label_id"] = self.label_id
        if self.filter_id is not None:
            result["filter_id"] = self.filter_id
        return result


@dataclasses.dataclass(frozen=True)
class FilterReconciliationPlan:
    entries: Tuple[FilterPlanEntry, ...]
    conflicts: Tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return not self.conflicts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "entries": [entry.to_dict() for entry in self.entries],
            "conflicts": list(self.conflicts),
        }


def _filter_mutation_schedule(
    entries: Iterable[FilterPlanEntry],
) -> Tuple[FilterPlanEntry, ...]:
    """Return a deterministic, capacity-safe global mutation order.

    Duplicate or incompatible filters can be removed before any create only
    when an exact desired filter is already present for that condition.  A
    replacement that still needs its desired filter is created and confirmed
    before its predecessors are removed.  Pure creates run last so they cannot
    consume capacity that a replacement would safely release.
    """

    entries = tuple(entries)
    safe_cleanups = tuple(
        entry
        for entry in entries
        if entry.action == "replace" and entry.filter_id is not None
    )
    create_then_delete = tuple(
        entry
        for entry in entries
        if entry.action == "replace" and entry.filter_id is None
    )
    creates = tuple(entry for entry in entries if entry.action == "create")
    return safe_cleanups + create_then_delete + creates


def plan_filter_reconciliation(
    specs: Iterable[Any],
    existing_filters: Iterable[Any],
    existing_labels: Iterable[Any],
    *,
    allow_missing_labels: bool = False,
) -> FilterReconciliationPlan:
    """Plan delivered-to filters without mutating any supplied snapshot."""

    normalized_specs = tuple(
        sorted(
            (_coerce_filter_spec(item) for item in specs),
            key=lambda item: (
                canonical_filter_criteria(item.criteria),
                item.label.casefold(),
                item.label,
            ),
        )
    )
    filters = tuple(sorted((_coerce_filter(item) for item in existing_filters), key=lambda item: item.id))
    labels = tuple(_coerce_label(item) for item in existing_labels)

    label_plan = plan_label_reconciliation((spec.label for spec in normalized_specs), labels)
    label_entries = {entry.name: entry for entry in label_plan.entries}

    conditions: Dict[Tuple[Tuple[str, Any], ...], List[GmailFilter]] = {}
    for item in filters:
        key = canonical_filter_criteria(item.criteria)
        conditions.setdefault(key, []).append(item)

    requested_conditions: Dict[Tuple[Tuple[str, Any], ...], List[GmailFilterSpec]] = {}
    for spec in normalized_specs:
        requested_conditions.setdefault(canonical_filter_criteria(spec.criteria), []).append(spec)

    entries: List[FilterPlanEntry] = []
    all_conflicts: List[str] = []
    for spec in normalized_specs:
        condition_key = canonical_filter_criteria(spec.criteria)
        same_condition = tuple(sorted(conditions.get(condition_key, []), key=lambda item: item.id))
        label_entry = label_entries[spec.label]
        conflicts: List[str] = list(label_entry.conflicts)
        label_id = label_entry.label_id
        if label_entry.action == "create" and not allow_missing_labels:
            conflicts.append(f"filter {spec.query!r} requires missing user label {spec.label!r}")

        duplicate_requested = requested_conditions.get(condition_key, [])
        if len(duplicate_requested) > 1:
            conflicts.append(
                f"multiple requested filters have the same condition {spec.query!r}; configure one deterministic action"
            )

        expected_action = (
            canonical_filter_action(spec.action_for_label_id(label_id))
            if label_id is not None
            else None
        )
        equivalent = tuple(
            item.id
            for item in same_condition
            if expected_action is not None and canonical_filter_action(item.action) == expected_action
        )
        incompatible = tuple(item.id for item in same_condition if item.id not in equivalent)
        same_ids = tuple(item.id for item in same_condition)

        duplicate_remote = len(same_condition) > 1
        if spec.conflict_policy == "error":
            if duplicate_remote:
                conflicts.append(
                    f"filter {spec.query!r} has duplicate same-condition filters: {', '.join(same_ids)}"
                )
            if incompatible:
                conflicts.append(
                    f"filter {spec.query!r} has incompatible same-condition filter(s): "
                    + ", ".join(incompatible)
                )

        conflicts = list(dict.fromkeys(conflicts))
        all_conflicts.extend(conflicts)
        if conflicts:
            action = "conflict"
            filter_id = None
            delete_ids: Tuple[str, ...] = ()
        elif not same_condition:
            action = "create"
            filter_id = None
            delete_ids = ()
        elif len(same_condition) == 1 and equivalent:
            action = "reuse"
            filter_id = equivalent[0]
            delete_ids = ()
        elif spec.conflict_policy == "replace":
            keep_id = min(equivalent) if equivalent else None
            delete_ids = tuple(item for item in same_ids if item != keep_id)
            action = "replace"
            filter_id = keep_id
        else:
            # All non-replace same-condition incompatibilities were converted
            # to conflicts above.  Keep this defensive branch deterministic.
            action = "conflict"
            filter_id = None
            delete_ids = ()
            message = f"filter {spec.query!r} cannot be reconciled safely"
            conflicts.append(message)
            all_conflicts.append(message)

        entries.append(
            FilterPlanEntry(
                spec=spec,
                action=action,
                label_id=label_id,
                filter_id=filter_id,
                equivalent_filter_ids=equivalent,
                incompatible_filter_ids=incompatible,
                delete_filter_ids=delete_ids,
                conflicts=tuple(conflicts),
            )
        )

    # Globally schedule mutations rather than letting condition sort order
    # decide whether an equivalent plan fits.  Exact-filter cleanup is safe to
    # run first; create-before-delete replacements can then release capacity;
    # pure creates consume the remaining slots last.
    running_count = len(filters)
    peak_count = running_count
    for entry in _filter_mutation_schedule(entries):
        if entry.action == "replace" and entry.filter_id is not None:
            running_count -= len(entry.delete_filter_ids)
            continue
        if entry.action in {"create", "replace"}:
            running_count += 1
            peak_count = max(peak_count, running_count)
        if entry.action == "replace":
            running_count -= len(entry.delete_filter_ids)
    if peak_count > GMAIL_FILTER_LIMIT:
        message = (
            f"Gmail filter limit would be exceeded during safe create-before-delete replacement: "
            f"required peak {peak_count}, "
            f"maximum {GMAIL_FILTER_LIMIT}"
        )
        all_conflicts.append(message)
        entries = [
            dataclasses.replace(
                entry,
                action="conflict",
                conflicts=tuple(dict.fromkeys(entry.conflicts + (message,))),
                delete_filter_ids=(),
            )
            if entry.action in {"create", "replace"}
            else entry
            for entry in entries
        ]

    return FilterReconciliationPlan(
        entries=tuple(entries),
        conflicts=tuple(dict.fromkeys(all_conflicts)),
    )


@dataclasses.dataclass(frozen=True)
class LabelOutcome:
    name: str
    action: str
    label_id: Optional[str] = None
    conflicts: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "name": self.name,
            "action": self.action,
            "conflicts": list(self.conflicts),
        }
        if self.label_id is not None:
            result["label_id"] = self.label_id
        return result


@dataclasses.dataclass(frozen=True)
class LabelReconciliationResult:
    dry_run: bool
    labels: Tuple[LabelOutcome, ...]
    verified: bool
    conflicts: Tuple[str, ...] = ()
    created: Tuple[str, ...] = ()
    reused: Tuple[str, ...] = ()
    unresolved: Tuple[str, ...] = ()
    issues: Tuple[str, ...] = ()
    actions_required: Tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return (
            not self.conflicts
            and not self.issues
            and not self.unresolved
            and (self.dry_run or self.verified)
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "dry_run": self.dry_run,
            "verified": self.verified,
            "labels": [item.to_dict() for item in self.labels],
            "conflicts": list(self.conflicts),
            "created": list(self.created),
            "reused": list(self.reused),
            "unresolved": list(self.unresolved),
            "issues": list(self.issues),
            "actions_required": list(self.actions_required),
        }


@dataclasses.dataclass(frozen=True)
class FilterOutcome:
    spec: GmailFilterSpec
    action: str
    filter_id: Optional[str] = None
    label_id: Optional[str] = None
    deleted_filter_ids: Tuple[str, ...] = ()
    equivalent_filter_ids: Tuple[str, ...] = ()
    incompatible_filter_ids: Tuple[str, ...] = ()
    conflicts: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        result = self.spec.to_dict()
        result.update(
            {
                "action": self.action,
                "deleted_filter_ids": list(self.deleted_filter_ids),
                "equivalent_filter_ids": list(self.equivalent_filter_ids),
                "incompatible_filter_ids": list(self.incompatible_filter_ids),
                "conflicts": list(self.conflicts),
            }
        )
        if self.filter_id is not None:
            result["filter_id"] = self.filter_id
        if self.label_id is not None:
            result["label_id"] = self.label_id
        return result


@dataclasses.dataclass(frozen=True)
class FilterReconciliationResult:
    dry_run: bool
    filters: Tuple[FilterOutcome, ...]
    verified: bool
    conflicts: Tuple[str, ...] = ()
    created_filter_ids: Tuple[str, ...] = ()
    deleted_filter_ids: Tuple[str, ...] = ()
    reused_filter_ids: Tuple[str, ...] = ()
    unresolved: Tuple[str, ...] = ()
    issues: Tuple[str, ...] = ()
    actions_required: Tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return (
            not self.conflicts
            and not self.issues
            and not self.unresolved
            and (self.dry_run or self.verified)
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "dry_run": self.dry_run,
            "verified": self.verified,
            "filters": [item.to_dict() for item in self.filters],
            "conflicts": list(self.conflicts),
            "created_filter_ids": list(self.created_filter_ids),
            "deleted_filter_ids": list(self.deleted_filter_ids),
            "reused_filter_ids": list(self.reused_filter_ids),
            "unresolved": list(self.unresolved),
            "issues": list(self.issues),
            "actions_required": list(self.actions_required),
        }


@dataclasses.dataclass(frozen=True)
class GmailProvisionPlan:
    labels: LabelReconciliationPlan
    filters: FilterReconciliationPlan
    conflicts: Tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return not self.conflicts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "labels": self.labels.to_dict(),
            "filters": self.filters.to_dict(),
            "conflicts": list(self.conflicts),
        }


@dataclasses.dataclass(frozen=True)
class GmailProvisionResult:
    dry_run: bool
    labels: LabelReconciliationResult
    filters: FilterReconciliationResult
    conflicts: Tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return not self.conflicts and self.labels.ok and self.filters.ok

    @property
    def verified(self) -> bool:
        return not self.dry_run and self.labels.verified and self.filters.verified

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "dry_run": self.dry_run,
            "verified": self.verified,
            "labels": self.labels.to_dict(),
            "filters": self.filters.to_dict(),
            "conflicts": list(self.conflicts),
        }


def plan_gmail_configuration(
    required_labels: Iterable[str],
    filter_specs: Iterable[Any],
    existing_labels: Iterable[Any],
    existing_filters: Iterable[Any],
) -> GmailProvisionPlan:
    specs = tuple(_coerce_filter_spec(item) for item in filter_specs)
    names = tuple(required_labels) + tuple(spec.label for spec in specs)
    labels = tuple(_coerce_label(item) for item in existing_labels)
    filters = tuple(_coerce_filter(item) for item in existing_filters)
    label_plan = plan_label_reconciliation(names, labels)
    filter_plan = plan_filter_reconciliation(
        specs,
        filters,
        labels,
        allow_missing_labels=True,
    )
    conflicts = tuple(dict.fromkeys(label_plan.conflicts + filter_plan.conflicts))
    return GmailProvisionPlan(labels=label_plan, filters=filter_plan, conflicts=conflicts)


def _label_result_from_plan(
    plan: LabelReconciliationPlan,
    *,
    dry_run: bool,
) -> LabelReconciliationResult:
    outcomes = []
    for entry in plan.entries:
        if entry.action == "create":
            action = "would_create" if dry_run else "create"
        elif entry.action == "reuse":
            action = "reused"
        else:
            action = "conflict"
        outcomes.append(
            LabelOutcome(
                name=entry.name,
                action=action,
                label_id=entry.label_id,
                conflicts=entry.conflicts,
            )
        )
    return LabelReconciliationResult(
        dry_run=dry_run,
        labels=tuple(outcomes),
        verified=False,
        conflicts=plan.conflicts,
    )


def _filter_result_from_plan(
    plan: FilterReconciliationPlan,
    *,
    dry_run: bool,
) -> FilterReconciliationResult:
    outcomes = []
    for entry in plan.entries:
        action = entry.action
        if dry_run and action in {"create", "replace"}:
            action = f"would_{action}"
        elif action == "reuse":
            action = "reused"
        outcomes.append(
            FilterOutcome(
                spec=entry.spec,
                action=action,
                filter_id=entry.filter_id,
                label_id=entry.label_id,
                deleted_filter_ids=entry.delete_filter_ids,
                equivalent_filter_ids=entry.equivalent_filter_ids,
                incompatible_filter_ids=entry.incompatible_filter_ids,
                conflicts=entry.conflicts,
            )
        )
    return FilterReconciliationResult(
        dry_run=dry_run,
        filters=tuple(outcomes),
        verified=False,
        conflicts=plan.conflicts,
    )


def _attach_reconciliation_result(exc: BaseException, result: Any) -> None:
    """Attach reportable progress without changing the original exception type."""

    try:
        setattr(exc, "result", result)
    except Exception:  # pragma: no cover - built-in exceptions used here are mutable
        pass


def _label_reconciliation_issue(exc: BaseException) -> str:
    if isinstance(exc, GmailApiError):
        collision = exc.context.get("label_create_collision")
        if isinstance(collision, Mapping):
            status = collision.get("status_code")
            status_text = f"HTTP {status}" if type(status) is int else "API error"
            return (
                f"Gmail label create collision candidate ({status_text}) could not be "
                f"verified because label rediscovery failed: {exc}"
            )
    return str(exc) or type(exc).__name__


def _label_partial_result(
    plan: LabelReconciliationPlan,
    created_by_name: Mapping[str, GmailLabel],
    reused_by_name: Mapping[str, GmailLabel],
    issue: str,
    *,
    verification_pending: bool = False,
) -> LabelReconciliationResult:
    outcomes = []
    reused = []
    unresolved = []
    for entry in plan.entries:
        created = created_by_name.get(entry.name)
        recovered_reuse = reused_by_name.get(entry.name)
        if created is not None:
            outcomes.append(LabelOutcome(entry.name, "created", created.id))
        elif recovered_reuse is not None:
            outcomes.append(LabelOutcome(entry.name, "reused", recovered_reuse.id))
            reused.append(entry.name)
        elif entry.action == "reuse":
            outcomes.append(LabelOutcome(entry.name, "reused", entry.label_id))
            reused.append(entry.name)
        else:
            outcomes.append(LabelOutcome(entry.name, "unresolved", conflicts=(issue,)))
            unresolved.append(entry.name)
    if verification_pending:
        unresolved.append("post-write label verification")
    return LabelReconciliationResult(
        dry_run=False,
        labels=tuple(outcomes),
        verified=False,
        created=tuple(sorted(created_by_name)),
        reused=tuple(reused),
        unresolved=tuple(unresolved),
        issues=(issue,),
        actions_required=(
            "Rerun Gmail label reconciliation; committed labels will be safely reused and verified.",
        ),
    )


def _filter_partial_result(
    plan: FilterReconciliationPlan,
    completed: Mapping[Tuple[Tuple[str, Any], ...], FilterOutcome],
    created_by_condition: Mapping[Tuple[Tuple[str, Any], ...], GmailFilter],
    deleted_by_condition: Mapping[Tuple[Tuple[str, Any], ...], Iterable[str]],
    issue: str,
    *,
    verification_pending: bool = False,
) -> FilterReconciliationResult:
    outcomes = []
    unresolved = []
    reused_ids = []
    for entry in plan.entries:
        condition_key = canonical_filter_criteria(entry.spec.criteria)
        completed_outcome = completed.get(condition_key)
        if completed_outcome is not None:
            outcomes.append(completed_outcome)
            if completed_outcome.action == "reused" and completed_outcome.filter_id:
                reused_ids.append(completed_outcome.filter_id)
            elif entry.filter_id is not None:
                reused_ids.append(entry.filter_id)
            continue
        created = created_by_condition.get(condition_key)
        outcomes.append(
            FilterOutcome(
                spec=entry.spec,
                action="unresolved",
                filter_id=created.id if created is not None else entry.filter_id,
                label_id=entry.label_id,
                deleted_filter_ids=tuple(deleted_by_condition.get(condition_key, ())),
                equivalent_filter_ids=entry.equivalent_filter_ids,
                incompatible_filter_ids=entry.incompatible_filter_ids,
                conflicts=(issue,),
            )
        )
        unresolved.append(entry.spec.query)
    if verification_pending:
        unresolved.append("post-write filter verification")
    return FilterReconciliationResult(
        dry_run=False,
        filters=tuple(outcomes),
        verified=False,
        created_filter_ids=tuple(
            sorted(item.id for item in created_by_condition.values())
        ),
        deleted_filter_ids=tuple(
            filter_id
            for entry in plan.entries
            for filter_id in deleted_by_condition.get(
                canonical_filter_criteria(entry.spec.criteria),
                (),
            )
        ),
        reused_filter_ids=tuple(dict.fromkeys(reused_ids)),
        unresolved=tuple(unresolved),
        issues=(issue,),
        actions_required=(
            "Rerun Gmail filter reconciliation; committed creates and deletes will be rediscovered and verified.",
        ),
    )


def reconcile_labels(
    client: GmailApiClient,
    required_names: Iterable[str],
    *,
    dry_run: bool = False,
    existing_labels: Optional[Iterable[Any]] = None,
) -> LabelReconciliationResult:
    snapshot = tuple(existing_labels) if existing_labels is not None else client.list_labels()
    plan = plan_label_reconciliation(required_names, snapshot)
    if dry_run:
        return _label_result_from_plan(plan, dry_run=True)
    if not plan.ok:
        raise GmailReconciliationError("Gmail label reconciliation conflicts", plan.conflicts)

    created_by_name: Dict[str, GmailLabel] = {}
    reused_by_name: Dict[str, GmailLabel] = {}
    for entry in plan.entries:
        if entry.action != "create":
            continue
        try:
            try:
                created = client.create_label(entry.name)
            except GmailApiError as create_error:
                if isinstance(create_error, _GmailApiResourceError):
                    raise
                collision_candidate = create_error.status_code in {400, 409}
                if not (
                    create_error.mutation_outcome_uncertain or collision_candidate
                ):
                    raise
                try:
                    refreshed = client.list_labels()
                except GmailApiError as rediscovery_error:
                    if collision_candidate:
                        _attach_label_collision_context(
                            rediscovery_error,
                            create_error,
                        )
                        raise rediscovery_error from create_error
                    raise create_error from None
                matches = tuple(
                    label for label in refreshed if label.name == entry.name
                )
                if len(matches) != 1 or matches[0].type != "user":
                    raise create_error from None
                created = matches[0]
                if collision_candidate:
                    reused_by_name[entry.name] = created
            if created.name != entry.name or created.type != "user":
                raise GmailReconciliationError(
                    "Gmail label creation returned an unexpected resource",
                    (f"expected user label {entry.name!r}, received {created.name!r} ({created.type})",),
                )
            if entry.name not in reused_by_name:
                created_by_name[entry.name] = created
        except Exception as exc:
            issue = _label_reconciliation_issue(exc)
            partial = _label_partial_result(
                plan,
                created_by_name,
                reused_by_name,
                issue,
            )
            _attach_reconciliation_result(exc, partial)
            raise

    try:
        final_labels = client.list_labels()
    except Exception as exc:
        partial = _label_partial_result(
            plan,
            created_by_name,
            reused_by_name,
            str(exc) or type(exc).__name__,
            verification_pending=True,
        )
        _attach_reconciliation_result(exc, partial)
        raise
    verification = plan_label_reconciliation(
        (entry.name for entry in plan.entries),
        final_labels,
    )
    incomplete = tuple(
        f"label {entry.name!r} was not present as one exact user label after reconciliation"
        for entry in verification.entries
        if entry.action != "reuse"
    )
    verification_conflicts = tuple(dict.fromkeys(verification.conflicts + incomplete))
    if verification_conflicts:
        issue = "Gmail label verification failed: " + "; ".join(verification_conflicts)
        partial = _label_partial_result(
            plan,
            created_by_name,
            reused_by_name,
            issue,
            verification_pending=True,
        )
        raise GmailReconciliationError(
            "Gmail label verification failed",
            verification_conflicts,
            result=partial,
        )

    final_by_name = {label.name: label for label in final_labels if label.type == "user"}
    outcomes = tuple(
        LabelOutcome(
            name=entry.name,
            action="created" if entry.name in created_by_name else "reused",
            label_id=final_by_name[entry.name].id,
        )
        for entry in plan.entries
    )
    return LabelReconciliationResult(
        dry_run=False,
        labels=outcomes,
        verified=True,
        created=tuple(sorted(created_by_name)),
        reused=tuple(
            entry.name for entry in plan.entries if entry.name not in created_by_name
        ),
    )


def reconcile_filters(
    client: GmailApiClient,
    specs: Iterable[Any],
    *,
    dry_run: bool = False,
    existing_labels: Optional[Iterable[Any]] = None,
    existing_filters: Optional[Iterable[Any]] = None,
) -> FilterReconciliationResult:
    normalized_specs = tuple(_coerce_filter_spec(item) for item in specs)
    if not normalized_specs:
        return FilterReconciliationResult(
            dry_run=dry_run,
            filters=(),
            verified=not dry_run,
        )
    label_snapshot = tuple(existing_labels) if existing_labels is not None else client.list_labels()
    filter_snapshot = tuple(existing_filters) if existing_filters is not None else client.list_filters()
    plan = plan_filter_reconciliation(normalized_specs, filter_snapshot, label_snapshot)
    if dry_run:
        return _filter_result_from_plan(plan, dry_run=True)
    if not plan.ok:
        raise GmailReconciliationError("Gmail filter reconciliation conflicts", plan.conflicts)

    created_by_condition: Dict[Tuple[Tuple[str, Any], ...], GmailFilter] = {}
    deleted_by_condition: Dict[Tuple[Tuple[str, Any], ...], List[str]] = {
        canonical_filter_criteria(entry.spec.criteria): [] for entry in plan.entries
    }
    completed: Dict[Tuple[Tuple[str, Any], ...], FilterOutcome] = {}
    # Reuse requires no remote mutation, so it is already complete even if a
    # later scheduled mutation fails.  This keeps partial reports exact when
    # execution order intentionally differs from presentation order.
    for entry in plan.entries:
        if entry.action != "reuse":
            continue
        condition_key = canonical_filter_criteria(entry.spec.criteria)
        completed[condition_key] = FilterOutcome(
            spec=entry.spec,
            action="reused",
            filter_id=entry.filter_id,
            label_id=entry.label_id,
            equivalent_filter_ids=entry.equivalent_filter_ids,
            incompatible_filter_ids=entry.incompatible_filter_ids,
        )

    for entry in _filter_mutation_schedule(plan.entries):
        condition_key = canonical_filter_criteria(entry.spec.criteria)
        try:
            must_create = entry.action == "create" or (
                entry.action == "replace" and entry.filter_id is None
            )
            created: Optional[GmailFilter] = None
            if must_create:
                assert entry.label_id is not None
                required_action = entry.spec.action_for_label_id(entry.label_id)
                try:
                    created = client.create_filter(
                        entry.spec.criteria,
                        required_action,
                    )
                except GmailApiError as create_error:
                    if not create_error.mutation_outcome_uncertain:
                        raise
                    try:
                        refreshed = client.list_filters()
                    except GmailApiError:
                        raise create_error from None
                    matches = tuple(
                        item
                        for item in refreshed
                        if canonical_filter_criteria(item.criteria) == condition_key
                        and canonical_filter_action(item.action)
                        == canonical_filter_action(required_action)
                    )
                    if len(matches) != 1:
                        raise create_error from None
                    created = matches[0]
                if (
                    canonical_filter_criteria(created.criteria) != condition_key
                    or canonical_filter_action(created.action)
                    != canonical_filter_action(required_action)
                ):
                    raise GmailReconciliationError(
                        "Gmail filter creation returned an unexpected resource",
                        (f"created filter {created.id!r} does not match {entry.spec.query!r}",),
                    )
                created_by_condition[condition_key] = created

                # A successful POST response alone is not enough reason to
                # remove a functioning predecessor.  Confirm the new filter is
                # visible with the exact expected condition/action first.
                post_create = client.list_filters()
                confirmed = tuple(
                    item
                    for item in post_create
                    if item.id == created.id
                    and canonical_filter_criteria(item.criteria) == condition_key
                    and canonical_filter_action(item.action)
                    == canonical_filter_action(required_action)
                )
                if len(confirmed) != 1:
                    raise GmailReconciliationError(
                        "Gmail filter creation could not be confirmed before replacement",
                        (
                            f"created filter {created.id!r} was not visible with the expected action; "
                            "existing filter protection was preserved",
                        ),
                    )

            elif entry.action == "replace":
                # Capacity may depend on deleting these redundant resources
                # before unrelated creates.  Reconfirm the exact desired
                # filter immediately before cleanup so the deletion phase
                # never relies only on a stale planning snapshot.
                assert entry.filter_id is not None
                assert entry.label_id is not None
                required_action = entry.spec.action_for_label_id(entry.label_id)
                pre_cleanup = client.list_filters()
                kept = tuple(
                    item
                    for item in pre_cleanup
                    if item.id == entry.filter_id
                    and canonical_filter_criteria(item.criteria) == condition_key
                    and canonical_filter_action(item.action)
                    == canonical_filter_action(required_action)
                )
                if len(kept) != 1:
                    raise GmailReconciliationError(
                        "Gmail filter cleanup could not confirm the desired filter",
                        (
                            f"kept filter {entry.filter_id!r} was not visible with the expected action; "
                            "redundant filters were preserved",
                        ),
                    )

            for filter_id in entry.delete_filter_ids:
                client.delete_filter(filter_id)
                deleted_by_condition[condition_key].append(filter_id)

            if entry.action == "replace":
                action = "replaced"
            elif created is not None:
                action = "created"
            else:
                action = "reused"
            completed[condition_key] = FilterOutcome(
                spec=entry.spec,
                action=action,
                filter_id=created.id if created is not None else entry.filter_id,
                label_id=entry.label_id,
                deleted_filter_ids=tuple(deleted_by_condition[condition_key]),
                equivalent_filter_ids=entry.equivalent_filter_ids,
                incompatible_filter_ids=entry.incompatible_filter_ids,
            )
        except Exception as exc:
            partial = _filter_partial_result(
                plan,
                completed,
                created_by_condition,
                deleted_by_condition,
                str(exc) or type(exc).__name__,
            )
            _attach_reconciliation_result(exc, partial)
            raise

    try:
        final_filters = client.list_filters()
    except Exception as exc:
        partial = _filter_partial_result(
            plan,
            completed,
            created_by_condition,
            deleted_by_condition,
            str(exc) or type(exc).__name__,
            verification_pending=True,
        )
        _attach_reconciliation_result(exc, partial)
        raise
    # Labels are immutable for this operation, but re-use the snapshot so this
    # verifier cannot accidentally require an additional label-list scope call.
    verification = plan_filter_reconciliation(
        normalized_specs,
        final_filters,
        label_snapshot,
    )
    incomplete = tuple(
        f"filter {entry.spec.query!r} was not present exactly once with the required action"
        for entry in verification.entries
        if entry.action != "reuse"
    )
    verification_conflicts = tuple(dict.fromkeys(verification.conflicts + incomplete))
    if verification_conflicts:
        issue = "Gmail filter verification failed: " + "; ".join(verification_conflicts)
        partial = _filter_partial_result(
            plan,
            completed,
            created_by_condition,
            deleted_by_condition,
            issue,
            verification_pending=True,
        )
        raise GmailReconciliationError(
            "Gmail filter verification failed",
            verification_conflicts,
            result=partial,
        )

    verified_by_condition = {
        canonical_filter_criteria(entry.spec.criteria): entry
        for entry in verification.entries
    }
    outcomes: List[FilterOutcome] = []
    for original in plan.entries:
        condition_key = canonical_filter_criteria(original.spec.criteria)
        verified = verified_by_condition[condition_key]
        if original.action == "replace":
            action = "replaced"
        elif condition_key in created_by_condition:
            action = "created"
        else:
            action = "reused"
        outcomes.append(
            FilterOutcome(
                spec=original.spec,
                action=action,
                filter_id=verified.filter_id,
                label_id=verified.label_id,
                deleted_filter_ids=tuple(deleted_by_condition.get(condition_key, ())),
                equivalent_filter_ids=verified.equivalent_filter_ids,
                incompatible_filter_ids=original.incompatible_filter_ids,
            )
        )
    return FilterReconciliationResult(
        dry_run=False,
        filters=tuple(outcomes),
        verified=True,
        created_filter_ids=tuple(
            sorted(item.id for item in created_by_condition.values())
        ),
        deleted_filter_ids=tuple(
            filter_id
            for original in plan.entries
            for filter_id in deleted_by_condition.get(
                canonical_filter_criteria(original.spec.criteria),
                (),
            )
        ),
        reused_filter_ids=tuple(
            dict.fromkeys(
                verified_by_condition[canonical_filter_criteria(original.spec.criteria)].filter_id
                for original in plan.entries
                if canonical_filter_criteria(original.spec.criteria)
                not in created_by_condition
                and verified_by_condition[
                    canonical_filter_criteria(original.spec.criteria)
                ].filter_id
                is not None
            )
        ),
    )


def provision_gmail_configuration(
    client: GmailApiClient,
    required_labels: Iterable[str],
    filter_specs: Iterable[Any] = (),
    *,
    dry_run: bool = False,
) -> GmailProvisionResult:
    """Reconcile labels and delivered-to filters as one reportable operation.

    All conflicts visible in the initial snapshots are evaluated before the
    first write.  Label and filter writes are individually idempotent, so a
    transport or verification failure can be handled by rerunning this method.
    """

    specs = tuple(_coerce_filter_spec(item) for item in filter_specs)
    names = tuple(required_labels) + tuple(spec.label for spec in specs)
    initial_labels = client.list_labels()
    initial_filters = client.list_filters() if specs else ()
    plan = plan_gmail_configuration(names, specs, initial_labels, initial_filters)

    if dry_run:
        label_result = _label_result_from_plan(plan.labels, dry_run=True)
        filter_result = _filter_result_from_plan(plan.filters, dry_run=True)
        return GmailProvisionResult(
            dry_run=True,
            labels=label_result,
            filters=filter_result,
            conflicts=plan.conflicts,
        )

    if not plan.ok:
        raise GmailReconciliationError("Gmail configuration reconciliation conflicts", plan.conflicts)

    label_result = reconcile_labels(
        client,
        names,
        existing_labels=initial_labels,
    )
    if specs:
        # Re-list both snapshots immediately before the filter mutation.  This
        # catches concurrent changes; any labels already created remain safe
        # and will be reused on a rerun.
        current_labels = client.list_labels()
        current_filters = client.list_filters()
        filter_result = reconcile_filters(
            client,
            specs,
            existing_labels=current_labels,
            existing_filters=current_filters,
        )
    else:
        filter_result = FilterReconciliationResult(
            dry_run=False,
            filters=(),
            verified=True,
        )

    return GmailProvisionResult(
        dry_run=False,
        labels=label_result,
        filters=filter_result,
    )


# Natural aliases for integration sites that refer to routing or settings.
provision_gmail_routing = provision_gmail_configuration
reconcile_gmail_configuration = provision_gmail_configuration


__all__ = [
    "DEFAULT_GMAIL_API_BASE_URL",
    "DeliveredToFilterSpec",
    "FILTER_SCOPE_HINT",
    "FilterOutcome",
    "FilterPlanEntry",
    "FilterReconciliationPlan",
    "FilterReconciliationResult",
    "FilterSpec",
    "GMAIL_FULL_MAIL_SCOPE",
    "GMAIL_FILTER_LIMIT",
    "GMAIL_LABEL_LIMIT",
    "GMAIL_LABEL_NAME_MAX_LENGTH",
    "GMAIL_LABELS_SCOPE",
    "GMAIL_MODIFY_SCOPE",
    "GMAIL_SETTINGS_BASIC_SCOPE",
    "GmailApiClient",
    "GmailApiCancelledError",
    "GmailApiError",
    "GmailFilter",
    "GmailFilterSpec",
    "GmailLabel",
    "GmailProvisionPlan",
    "GmailProvisionResult",
    "GmailReconciliationError",
    "LABEL_SCOPE_HINT",
    "LabelOutcome",
    "LabelPlanEntry",
    "LabelReconciliationPlan",
    "LabelReconciliationResult",
    "canonical_filter_action",
    "canonical_filter_criteria",
    "canonical_filter_email",
    "plan_filter_reconciliation",
    "plan_gmail_configuration",
    "plan_label_reconciliation",
    "provision_gmail_configuration",
    "provision_gmail_routing",
    "reconcile_filters",
    "reconcile_gmail_configuration",
    "reconcile_labels",
]
