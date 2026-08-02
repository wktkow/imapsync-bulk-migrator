"""Pure configuration parsing and planning for opt-in folder routing.

The module deliberately has no IMAP, Gmail API, filesystem, or logging
dependencies.  Callers discover source folders and target labels, pass those
snapshots to :func:`resolve_routing_plan`, and may then persist or execute the
returned immutable plan themselves.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import re
from collections import defaultdict
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple


CUSTOM_LABEL = "custom_label"
GMAIL_SYSTEM = "gmail_system"
GENERIC_MAILBOX = "mailbox"
DESTINATION_KINDS = frozenset({CUSTOM_LABEL, GMAIL_SYSTEM, GENERIC_MAILBOX})

ROUTING_PLAN_VERSION = 2
ROUTING_MAPPING_SEMANTICS = "all-selectable-memberships-v2"
GMAIL_CUSTOM_LABEL_MAX_LENGTH = 225

INBOX = "inbox"
SENT = "sent"
DRAFTS = "drafts"
TRASH = "trash"
ARCHIVE = "archive"
JUNK = "junk"
SPECIAL_USE_ROLES = (INBOX, SENT, DRAFTS, TRASH, ARCHIVE, JUNK)
_ROLE_ORDER = {role: index for index, role in enumerate(SPECIAL_USE_ROLES)}

_ROLE_ALIASES = {
    "inbox": INBOX,
    "sent": SENT,
    "draft": DRAFTS,
    "drafts": DRAFTS,
    "trash": TRASH,
    "deleted": TRASH,
    "deleted messages": TRASH,
    "archive": ARCHIVE,
    "archives": ARCHIVE,
    "all": ARCHIVE,
    "all mail": ARCHIVE,
    "junk": JUNK,
    "spam": JUNK,
}

_ATTRIBUTE_ROLES = {
    "\\inbox": INBOX,
    "\\sent": SENT,
    "\\drafts": DRAFTS,
    "\\trash": TRASH,
    "\\archive": ARCHIVE,
    "\\all": ARCHIVE,
    "\\allmail": ARCHIVE,
    "\\junk": JUNK,
    "\\spam": JUNK,
}

_COMMON_NAME_ROLES = {
    "inbox": INBOX,
    "sent": SENT,
    "sent mail": SENT,
    "sent message": SENT,
    "sent messages": SENT,
    "sent item": SENT,
    "sent items": SENT,
    "draft": DRAFTS,
    "drafts": DRAFTS,
    "trash": TRASH,
    "bin": TRASH,
    "deleted": TRASH,
    "deleted mail": TRASH,
    "deleted message": TRASH,
    "deleted messages": TRASH,
    "deleted item": TRASH,
    "deleted items": TRASH,
    "archive": ARCHIVE,
    "archives": ARCHIVE,
    "all mail": ARCHIVE,
    "junk": JUNK,
    "junk mail": JUNK,
    "junk email": JUNK,
    "junk e mail": JUNK,
    "spam": JUNK,
    "spam mail": JUNK,
    "bulk mail": JUNK,
}

_GMAIL_SYSTEM_ALIASES = {
    "inbox": "inbox",
    "sent": "sent",
    "sent mail": "sent",
    "draft": "drafts",
    "drafts": "drafts",
    "trash": "trash",
    "deleted messages": "trash",
    "spam": "spam",
    "junk": "spam",
    "all": "all",
    "all mail": "all",
    "archive": "all",
    "important": "important",
    "starred": "starred",
}
_GMAIL_SYSTEM_ROLES = frozenset(_GMAIL_SYSTEM_ALIASES.values())
_UNSAFE_GMAIL_SYSTEM_ROLES = frozenset({"spam", "trash"})
GMAIL_EXCLUSIVE_PRIMARY_ROLES = frozenset({"sent", "drafts", "trash", "spam"})
GMAIL_INCOMPATIBLE_SYSTEM_ROLE_PAIRS = (
    frozenset({"all", "spam"}),
    frozenset({"all", "trash"}),
    frozenset({"inbox", "spam"}),
    frozenset({"inbox", "trash"}),
)
_RESERVED_GMAIL_NAMES = frozenset(
    {
        "inbox",
        "sent",
        "sent mail",
        "drafts",
        "trash",
        "spam",
        "all mail",
        "important",
        "starred",
    }
)
_GMAIL_RESTORE_SYSTEM_LABEL_ALIASES = frozenset(
    {
        "\\inbox",
        "[gmail]/inbox",
        "[googlemail]/inbox",
        "\\sent",
        "[gmail]/sent mail",
        "[googlemail]/sent mail",
        "\\drafts",
        "[gmail]/drafts",
        "[googlemail]/drafts",
        "\\trash",
        "[gmail]/trash",
        "[googlemail]/trash",
        "\\junk",
        "\\spam",
        "[gmail]/spam",
        "[googlemail]/spam",
        "\\all",
        "\\allmail",
        "[gmail]/all mail",
        "[googlemail]/all mail",
        "\\important",
        "[gmail]/important",
        "[googlemail]/important",
        "\\starred",
        "\\flagged",
        "[gmail]/starred",
        "[googlemail]/starred",
    }
)


def gmail_incompatible_system_roles(destinations: Iterable[str]) -> Tuple[str, ...]:
    """Return Gmail location roles that cannot represent one message together."""

    roles = set(destinations)
    incompatible = roles & GMAIL_EXCLUSIVE_PRIMARY_ROLES
    result = set(incompatible) if len(incompatible) > 1 else set()
    for pair in GMAIL_INCOMPATIBLE_SYSTEM_ROLE_PAIRS:
        if pair <= roles:
            result.update(pair)
    return tuple(sorted(result))

_ROLE_DISPLAY_NAMES = {
    SENT: "Sent",
    DRAFTS: "Drafts",
    TRASH: "Trash",
    ARCHIVE: "Archive",
    JUNK: "Junk",
}


def _strict_keys(raw: Mapping[str, Any], allowed: set[str], context: str) -> None:
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise ValueError(f"{context} has unknown field(s): {', '.join(unknown)}")


def _required_keys(raw: Mapping[str, Any], required: set[str], context: str) -> None:
    missing = sorted(required - set(raw))
    if missing:
        raise ValueError(f"{context} is missing required field(s): {', '.join(missing)}")


def _text(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{context} must be a non-empty string")
    if value != value.strip():
        raise ValueError(f"{context} must not have leading or trailing whitespace")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError(f"{context} must not contain control characters")
    return value


def _bool(value: Any, context: str) -> bool:
    if type(value) is not bool:
        raise ValueError(f"{context} must be a boolean")
    return value


def _destination_name(value: Any, context: str) -> str:
    name = _text(value, context)
    if name.startswith("/") or name.endswith("/") or "//" in name:
        raise ValueError(f"{context} has an invalid hierarchy")
    return name


def _role(value: Any, context: str) -> str:
    text = _text(value, context).casefold()
    role = _ROLE_ALIASES.get(text)
    if role is None:
        raise ValueError(f"{context} must be one of: {', '.join(SPECIAL_USE_ROLES)}")
    return role


def _gmail_system_role(value: Any, context: str) -> str:
    text = _text(value, context).casefold()
    role = _GMAIL_SYSTEM_ALIASES.get(text)
    if role is None or role not in _GMAIL_SYSTEM_ROLES:
        raise ValueError(
            f"{context} must identify one of: "
            + ", ".join(sorted(_GMAIL_SYSTEM_ROLES))
        )
    return role


@dataclasses.dataclass(frozen=True)
class Destination:
    """A typed routing destination.

    ``name`` is preserved exactly for custom labels and generic mailboxes other
    than protocol-defined ``INBOX``.  Generic INBOX is canonicalized because
    IMAP requires every case variant to identify the same mailbox.  For Gmail
    system destinations it is the canonical system role.
    """

    kind: str
    name: str
    unsafe_acknowledged: bool = False

    def __post_init__(self) -> None:
        if self.kind not in DESTINATION_KINDS:
            raise ValueError(f"destination kind must be one of: {', '.join(sorted(DESTINATION_KINDS))}")
        if self.kind == GMAIL_SYSTEM:
            canonical = _gmail_system_role(self.name, "destination.name")
            object.__setattr__(self, "name", canonical)
            if canonical in _UNSAFE_GMAIL_SYSTEM_ROLES and not self.unsafe_acknowledged:
                raise ValueError(
                    f"Gmail system {canonical} is unsafe for historical mail; "
                    "set allow_unsafe=true to acknowledge retention/deletion behavior"
                )
        else:
            name = _destination_name(self.name, "destination.name")
            if self.kind == GENERIC_MAILBOX and name.casefold() == INBOX:
                name = "INBOX"
            object.__setattr__(self, "name", name)
            if self.unsafe_acknowledged:
                raise ValueError("allow_unsafe is valid only for Gmail system destinations")

    @staticmethod
    def from_dict(raw: Mapping[str, Any], *, context: str = "destination") -> "Destination":
        if not isinstance(raw, Mapping):
            raise ValueError(f"{context} must be an object")
        _strict_keys(raw, {"type", "name", "allow_unsafe"}, context)
        kind = _text(raw.get("type"), f"{context}.type")
        allow_unsafe = _bool(raw.get("allow_unsafe", False), f"{context}.allow_unsafe")
        if kind != GMAIL_SYSTEM and "allow_unsafe" in raw:
            raise ValueError(f"{context}.allow_unsafe is valid only for type {GMAIL_SYSTEM!r}")
        return Destination(kind=kind, name=_text(raw.get("name"), f"{context}.name"), unsafe_acknowledged=allow_unsafe)

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {"type": self.kind, "name": self.name}
        if self.kind == GMAIL_SYSTEM:
            result["allow_unsafe"] = self.unsafe_acknowledged
        return result


@dataclasses.dataclass(frozen=True)
class RoutingRule:
    folder: Optional[str]
    role: Optional[str]
    destinations: Tuple[Destination, ...]
    exclude: bool = False
    include_default: bool = False

    def __post_init__(self) -> None:
        if (self.folder is None) == (self.role is None):
            raise ValueError("routing rule must match exactly one of folder or role")
        if self.folder is not None:
            object.__setattr__(self, "folder", _text(self.folder, "routing rule folder"))
        if self.role is not None:
            object.__setattr__(self, "role", _role(self.role, "routing rule role"))
        object.__setattr__(self, "destinations", tuple(self.destinations))
        if self.exclude:
            if self.destinations:
                raise ValueError("excluded routing rule cannot have destinations")
            if self.include_default:
                raise ValueError("excluded routing rule cannot include the account default")
        elif not self.destinations:
            raise ValueError("routing rule must have at least one destination or set exclude=true")
        keys = [(destination.kind, destination.name) for destination in self.destinations]
        if len(keys) != len(set(keys)):
            raise ValueError("routing rule has duplicate destinations")

    @staticmethod
    def from_dict(raw: Mapping[str, Any], *, context: str) -> "RoutingRule":
        if not isinstance(raw, Mapping):
            raise ValueError(f"{context} must be an object")
        _strict_keys(raw, {"match", "destinations", "exclude", "include_default"}, context)
        match = raw.get("match")
        if not isinstance(match, Mapping):
            raise ValueError(f"{context}.match must be an object")
        _strict_keys(match, {"folder", "role"}, f"{context}.match")
        if set(match) not in ({"folder"}, {"role"}):
            raise ValueError(f"{context}.match must contain exactly one of folder or role")
        destinations_raw = raw.get("destinations", [])
        if not isinstance(destinations_raw, list):
            raise ValueError(f"{context}.destinations must be an array")
        destinations = tuple(
            Destination.from_dict(item, context=f"{context}.destinations[{index}]")
            for index, item in enumerate(destinations_raw)
        )
        return RoutingRule(
            folder=_text(match["folder"], f"{context}.match.folder") if "folder" in match else None,
            role=_role(match["role"], f"{context}.match.role") if "role" in match else None,
            destinations=destinations,
            exclude=_bool(raw.get("exclude", False), f"{context}.exclude"),
            include_default=_bool(raw.get("include_default", False), f"{context}.include_default"),
        )

    def canonical(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "destinations": [destination.to_dict() for destination in self.destinations],
            "exclude": self.exclude,
            "include_default": self.include_default,
        }
        result["match"] = {"folder": self.folder} if self.folder is not None else {"role": self.role}
        return result


@dataclasses.dataclass(frozen=True)
class AccountRouting:
    default_label: Optional[str] = None
    default_namespace: Optional[str] = None
    rules: Tuple[RoutingRule, ...] = ()

    def __post_init__(self) -> None:
        if self.default_label is not None:
            object.__setattr__(self, "default_label", _destination_name(self.default_label, "default_label"))
        if self.default_namespace is not None:
            object.__setattr__(self, "default_namespace", _destination_name(self.default_namespace, "default_namespace"))
        object.__setattr__(self, "rules", tuple(self.rules))

    @staticmethod
    def from_dict(raw: Mapping[str, Any], *, context: str) -> "AccountRouting":
        if not isinstance(raw, Mapping):
            raise ValueError(f"{context} must be an object")
        _strict_keys(raw, {"default_label", "default_namespace", "rules"}, context)
        rules_raw = raw.get("rules", [])
        if not isinstance(rules_raw, list):
            raise ValueError(f"{context}.rules must be an array")
        return AccountRouting(
            default_label=(
                _destination_name(raw["default_label"], f"{context}.default_label")
                if "default_label" in raw
                else None
            ),
            default_namespace=(
                _destination_name(raw["default_namespace"], f"{context}.default_namespace")
                if "default_namespace" in raw
                else None
            ),
            rules=tuple(
                RoutingRule.from_dict(item, context=f"{context}.rules[{index}]")
                for index, item in enumerate(rules_raw)
            ),
        )


@dataclasses.dataclass(frozen=True)
class FilterRule:
    delivered_to: str
    label: str
    inbox: str = "keep"
    mark_read: bool = False
    conflict_policy: str = "error"

    def __post_init__(self) -> None:
        address = _text(self.delivered_to, "filter delivered_to")
        if address.count("@") != 1 or any(char.isspace() for char in address):
            raise ValueError("filter delivered_to must be an email address")
        object.__setattr__(self, "delivered_to", address)
        object.__setattr__(self, "label", _destination_name(self.label, "filter label"))
        if self.inbox not in {"keep", "archive"}:
            raise ValueError("filter inbox must be one of: keep, archive")
        if self.conflict_policy not in {"error", "replace"}:
            raise ValueError("filter conflict_policy must be one of: error, replace")
        if type(self.mark_read) is not bool:
            raise ValueError("filter mark_read must be a boolean")

    @staticmethod
    def from_dict(raw: Mapping[str, Any], *, context: str) -> "FilterRule":
        if not isinstance(raw, Mapping):
            raise ValueError(f"{context} must be an object")
        _strict_keys(raw, {"delivered_to", "label", "inbox", "mark_read", "conflict_policy"}, context)
        return FilterRule(
            delivered_to=_text(raw.get("delivered_to"), f"{context}.delivered_to"),
            label=_destination_name(raw.get("label"), f"{context}.label"),
            inbox=_text(raw.get("inbox", "keep"), f"{context}.inbox"),
            mark_read=_bool(raw.get("mark_read", False), f"{context}.mark_read"),
            conflict_policy=_text(raw.get("conflict_policy", "error"), f"{context}.conflict_policy"),
        )

    @property
    def query(self) -> str:
        return f"deliveredto:{self.delivered_to}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "delivered_to": self.delivered_to,
            "query": self.query,
            "label": self.label,
            "inbox": self.inbox,
            "mark_read": self.mark_read,
            "conflict_policy": self.conflict_policy,
        }


@dataclasses.dataclass(frozen=True)
class RoutingConfig:
    enabled: bool = False
    accounts: Mapping[str, AccountRouting] = dataclasses.field(default_factory=dict)
    global_rules: Tuple[RoutingRule, ...] = ()
    filters: Tuple[FilterRule, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "accounts", dict(self.accounts))
        object.__setattr__(self, "global_rules", tuple(self.global_rules))
        object.__setattr__(self, "filters", tuple(self.filters))
        seen_accounts: Dict[str, str] = {}
        for account in self.accounts:
            _text(account, "routing account")
            key = account.casefold()
            previous = seen_accounts.get(key)
            if previous is not None and previous != account:
                raise ValueError(f"routing accounts differ only by case: {previous!r} and {account!r}")
            seen_accounts[key] = account
        seen_filters: Dict[str, FilterRule] = {}
        for rule in self.filters:
            key = rule.delivered_to.casefold()
            previous_filter = seen_filters.get(key)
            if previous_filter is not None:
                raise ValueError(
                    f"duplicate filter delivered_to {rule.delivered_to!r}; configure one deterministic action"
                )
            seen_filters[key] = rule
        if not self.enabled and (self.accounts or self.global_rules or self.filters):
            raise ValueError("disabled routing config cannot contain accounts, rules, or filters")

    @staticmethod
    def from_dict(raw: Optional[Mapping[str, Any]]) -> "RoutingConfig":
        """Parse the optional routing block.

        Absence is backward-compatible and disabled.  Any present block must
        explicitly set ``enabled``; settings are accepted only with
        ``enabled=true``.
        """

        if raw is None:
            return RoutingConfig()
        if not isinstance(raw, Mapping):
            raise ValueError("routing must be an object")
        _strict_keys(raw, {"enabled", "accounts", "global_rules", "filters"}, "routing")
        if "enabled" not in raw:
            raise ValueError("routing.enabled must be explicitly set")
        enabled = _bool(raw["enabled"], "routing.enabled")
        if not enabled:
            if set(raw) != {"enabled"}:
                raise ValueError("routing settings require routing.enabled=true")
            return RoutingConfig()
        accounts_raw = raw.get("accounts", {})
        if not isinstance(accounts_raw, Mapping):
            raise ValueError("routing.accounts must be an object keyed by source account")
        accounts: Dict[str, AccountRouting] = {}
        for raw_account, value in accounts_raw.items():
            account = _text(raw_account, "routing.accounts key")
            accounts[account] = AccountRouting.from_dict(value, context=f"routing.accounts[{account!r}]")
        global_rules_raw = raw.get("global_rules", [])
        if not isinstance(global_rules_raw, list):
            raise ValueError("routing.global_rules must be an array")
        filters_raw = raw.get("filters", [])
        if not isinstance(filters_raw, list):
            raise ValueError("routing.filters must be an array")
        return RoutingConfig(
            enabled=True,
            accounts=accounts,
            global_rules=tuple(
                RoutingRule.from_dict(item, context=f"routing.global_rules[{index}]")
                for index, item in enumerate(global_rules_raw)
            ),
            filters=tuple(
                FilterRule.from_dict(item, context=f"routing.filters[{index}]")
                for index, item in enumerate(filters_raw)
            ),
        )


@dataclasses.dataclass(frozen=True)
class SourceFolder:
    source_account: str
    name: str
    delimiter: str = ""
    attributes: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "source_account", _text(self.source_account, "source folder account"))
        object.__setattr__(self, "name", _text(self.name, "source folder name"))
        if not isinstance(self.delimiter, str):
            raise ValueError("source folder delimiter must be a string")
        attributes = tuple(self.attributes)
        if any(not isinstance(attribute, str) or not attribute for attribute in attributes):
            raise ValueError("source folder attributes must be non-empty strings")
        object.__setattr__(
            self,
            "attributes",
            tuple(sorted({attribute.casefold() for attribute in attributes})),
        )

    @property
    def detected_roles(self) -> Tuple[str, ...]:
        return detect_special_use_roles(self)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_account": self.source_account,
            "name": self.name,
            "delimiter": self.delimiter,
            "attributes": list(self.attributes),
        }


@dataclasses.dataclass(frozen=True)
class TargetLabel:
    name: str
    kind: str
    system_role: Optional[str] = None
    target_id: Optional[str] = None
    delimiter: str = "/"

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _text(self.name, "target label name"))
        if self.kind not in DESTINATION_KINDS:
            raise ValueError(f"target label kind must be one of: {', '.join(sorted(DESTINATION_KINDS))}")
        if self.kind == GMAIL_SYSTEM:
            if self.system_role is None:
                raise ValueError("Gmail system target label requires system_role")
            object.__setattr__(self, "system_role", _gmail_system_role(self.system_role, "target label system_role"))
        elif self.system_role is not None:
            raise ValueError("system_role is valid only for Gmail system target labels")
        if self.target_id is not None:
            object.__setattr__(self, "target_id", _text(self.target_id, "target label id"))
        if not isinstance(self.delimiter, str):
            raise ValueError("target label delimiter must be a string")

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "name": self.name,
            "type": self.kind,
            "delimiter": self.delimiter,
        }
        if self.system_role is not None:
            result["system_role"] = self.system_role
        if self.target_id is not None:
            result["id"] = self.target_id
        return result


def _normalized_common_name(value: str) -> str:
    normalized = value.casefold().strip()
    normalized = re.sub(r"^\[(?:gmail|googlemail)\][./\\]", "", normalized)
    normalized = normalized.replace("-", " ").replace("_", " ")
    normalized = re.sub(r"\s+", " ", normalized)
    return normalized


def detect_special_use_roles(folder: SourceFolder) -> Tuple[str, ...]:
    """Return deterministic role candidates from SPECIAL-USE and common names."""

    attribute_roles = {
        _ATTRIBUTE_ROLES[attribute.casefold()]
        for attribute in folder.attributes
        if attribute.casefold() in _ATTRIBUTE_ROLES
    }
    if attribute_roles:
        return tuple(sorted(attribute_roles, key=lambda role: _ROLE_ORDER[role]))

    name = folder.name
    basename = name
    if folder.delimiter and folder.delimiter in name:
        basename = name.rsplit(folder.delimiter, 1)[-1]
    else:
        gmail_match = re.match(r"^\[(?:gmail|googlemail)\][./\\](.+)$", name, flags=re.IGNORECASE)
        inbox_child_match = re.match(r"^inbox[./\\](.+)$", name, flags=re.IGNORECASE)
        if gmail_match:
            basename = gmail_match.group(1).rsplit("/", 1)[-1]
        elif inbox_child_match:
            basename = inbox_child_match.group(1).rsplit(".", 1)[-1]
    normalized = _normalized_common_name(basename)
    role = _COMMON_NAME_ROLES.get(normalized)
    return (role,) if role is not None else ()


@dataclasses.dataclass(frozen=True)
class Contributor:
    source_account: str
    source_folder: str

    def to_dict(self) -> Dict[str, str]:
        return {"source_account": self.source_account, "source_folder": self.source_folder}


@dataclasses.dataclass(frozen=True)
class PlannedDestination:
    kind: str
    name: str
    status: str
    existing_name: Optional[str] = None
    target_id: Optional[str] = None
    contributors: Tuple[Contributor, ...] = ()

    @property
    def exists(self) -> bool:
        return self.status == "existing"

    @property
    def will_create(self) -> bool:
        return self.status == "create"

    @property
    def merged(self) -> bool:
        return len(self.contributors) > 1

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "type": self.kind,
            "name": self.name,
            "status": self.status,
            "exists": self.exists,
            "will_create": self.will_create,
            "merged": self.merged,
            "contributors": [contributor.to_dict() for contributor in self.contributors],
        }
        if self.existing_name is not None:
            result["existing_name"] = self.existing_name
        if self.target_id is not None:
            result["id"] = self.target_id
        return result


@dataclasses.dataclass(frozen=True)
class PlanEntry:
    source: SourceFolder
    detected_role: Optional[str]
    role_candidates: Tuple[str, ...]
    destinations: Tuple[PlannedDestination, ...]
    excluded: bool
    assignment_source: str
    ambiguities: Tuple[str, ...] = ()
    warnings: Tuple[str, ...] = ()

    @property
    def ambiguous(self) -> bool:
        return bool(self.ambiguities)

    @property
    def appears_in_inbox(self) -> bool:
        return any(
            (destination.kind == GMAIL_SYSTEM and destination.name == "inbox")
            or (destination.kind == GENERIC_MAILBOX and destination.name.casefold() == "inbox")
            for destination in self.destinations
        )

    @property
    def merged_contributors(self) -> Tuple[Contributor, ...]:
        contributors = {
            (contributor.source_account, contributor.source_folder): contributor
            for destination in self.destinations
            if destination.merged
            for contributor in destination.contributors
        }
        return tuple(contributors[key] for key in sorted(contributors, key=lambda item: (item[0].casefold(), item[0], item[1].casefold(), item[1])))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_account": self.source.source_account,
            "source_folder": self.source.name,
            "delimiter": self.source.delimiter,
            "attributes": list(self.source.attributes),
            "detected_role": self.detected_role,
            "role_candidates": list(self.role_candidates),
            "destinations": [destination.to_dict() for destination in self.destinations],
            "merged_contributors": [contributor.to_dict() for contributor in self.merged_contributors],
            "appears_in_inbox": self.appears_in_inbox,
            "excluded": self.excluded,
            "ambiguous": self.ambiguous,
            "ambiguities": list(self.ambiguities),
            "assignment_source": self.assignment_source,
            "warnings": list(self.warnings),
        }


@dataclasses.dataclass(frozen=True)
class PlannedFilter:
    rule: FilterRule
    label_status: str
    existing_label_name: Optional[str] = None
    target_label_id: Optional[str] = None
    conflicts: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        result = self.rule.to_dict()
        result.update(
            {
                "label_status": self.label_status,
                "label_exists": self.label_status == "existing",
                "label_will_create": self.label_status == "create",
                "conflicts": list(self.conflicts),
            }
        )
        if self.existing_label_name is not None:
            result["existing_label_name"] = self.existing_label_name
        if self.target_label_id is not None:
            result["label_id"] = self.target_label_id
        return result


@dataclasses.dataclass(frozen=True)
class RoutingPlan:
    entries: Tuple[PlanEntry, ...]
    discovered_target_labels: Tuple[TargetLabel, ...]
    filters: Tuple[PlannedFilter, ...]
    labels_to_create: Tuple[str, ...]
    labels_reused: Tuple[str, ...]
    conflicts: Tuple[str, ...]
    warnings: Tuple[str, ...]
    mapping_digest: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "entries", tuple(self.entries))
        object.__setattr__(self, "discovered_target_labels", tuple(self.discovered_target_labels))
        object.__setattr__(self, "filters", tuple(self.filters))
        object.__setattr__(self, "labels_to_create", tuple(self.labels_to_create))
        object.__setattr__(self, "labels_reused", tuple(self.labels_reused))
        object.__setattr__(self, "conflicts", tuple(self.conflicts))
        object.__setattr__(self, "warnings", tuple(self.warnings))

    @property
    def ok(self) -> bool:
        return not self.conflicts and all(not entry.ambiguous for entry in self.entries) and all(not item.conflicts for item in self.filters)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": ROUTING_PLAN_VERSION,
            "mapping_semantics": ROUTING_MAPPING_SEMANTICS,
            "ok": self.ok,
            "mapping_digest": self.mapping_digest,
            "entries": [entry.to_dict() for entry in self.entries],
            "discovered_target_labels": [label.to_dict() for label in self.discovered_target_labels],
            "labels_to_create": list(self.labels_to_create),
            "labels_reused": list(self.labels_reused),
            "filters": [item.to_dict() for item in self.filters],
            "conflicts": list(self.conflicts),
            "warnings": list(self.warnings),
        }

    @staticmethod
    def from_dict(raw: Mapping[str, Any]) -> "RoutingPlan":
        """Load and integrity-check a persisted routing plan artifact."""

        if not isinstance(raw, Mapping):
            raise ValueError("routing plan must be an object")
        raw_version = raw.get("version")
        if type(raw_version) is int and raw_version == 1:
            raise ValueError(
                "routing plan version 1 uses obsolete folder-membership semantics; "
                "run a fresh routing preflight and re-export before importing"
            )
        if type(raw_version) is not int or raw_version != ROUTING_PLAN_VERSION:
            raise ValueError(
                f"routing plan version must be {ROUTING_PLAN_VERSION}; run a fresh routing "
                "preflight and re-export before importing"
            )
        _strict_keys(
            raw,
            {
                "version",
                "mapping_semantics",
                "ok",
                "mapping_digest",
                "entries",
                "discovered_target_labels",
                "labels_to_create",
                "labels_reused",
                "filters",
                "conflicts",
                "warnings",
            },
            "routing plan",
        )
        _required_keys(
            raw,
            {
                "version",
                "mapping_semantics",
                "ok",
                "mapping_digest",
                "entries",
                "discovered_target_labels",
                "labels_to_create",
                "labels_reused",
                "filters",
                "conflicts",
                "warnings",
            },
            "routing plan",
        )
        mapping_semantics = _text(
            raw.get("mapping_semantics"),
            "routing plan mapping_semantics",
        )
        if mapping_semantics != ROUTING_MAPPING_SEMANTICS:
            raise ValueError(
                "routing plan mapping_semantics is obsolete or unsupported; run a fresh "
                "routing preflight and re-export before importing"
            )
        _bool(raw.get("ok"), "routing plan ok")

        def text_list(value: Any, context: str) -> Tuple[str, ...]:
            if not isinstance(value, list):
                raise ValueError(f"{context} must be an array of strings")
            return tuple(_text(item, f"{context}[{index}]") for index, item in enumerate(value))

        def optional_text(value: Any, context: str) -> Optional[str]:
            return None if value is None else _text(value, context)

        target_labels_raw = raw.get("discovered_target_labels")
        if not isinstance(target_labels_raw, list):
            raise ValueError("routing plan discovered_target_labels must be an array")
        target_labels: list[TargetLabel] = []
        for index, item in enumerate(target_labels_raw):
            context = f"routing plan discovered_target_labels[{index}]"
            if not isinstance(item, Mapping):
                raise ValueError(f"{context} must be an object")
            _strict_keys(item, {"name", "type", "system_role", "id", "delimiter"}, context)
            _required_keys(item, {"name", "type", "delimiter"}, context)
            target_delimiter = item.get("delimiter")
            if not isinstance(target_delimiter, str):
                raise ValueError("target label delimiter must be a string")
            target_labels.append(
                TargetLabel(
                    name=_text(item.get("name"), f"{context}.name"),
                    kind=_text(item.get("type"), f"{context}.type"),
                    system_role=optional_text(item.get("system_role"), f"{context}.system_role"),
                    target_id=optional_text(item.get("id"), f"{context}.id"),
                    delimiter=target_delimiter,
                )
            )

        entries_raw = raw.get("entries")
        if not isinstance(entries_raw, list):
            raise ValueError("routing plan entries must be an array")
        entries: list[PlanEntry] = []
        for index, item in enumerate(entries_raw):
            context = f"routing plan entries[{index}]"
            if not isinstance(item, Mapping):
                raise ValueError(f"{context} must be an object")
            _strict_keys(
                item,
                {
                    "source_account",
                    "source_folder",
                    "delimiter",
                    "attributes",
                    "detected_role",
                    "role_candidates",
                    "destinations",
                    "merged_contributors",
                    "appears_in_inbox",
                    "excluded",
                    "ambiguous",
                    "ambiguities",
                    "assignment_source",
                    "warnings",
                },
                context,
            )
            _required_keys(
                item,
                {
                    "source_account",
                    "source_folder",
                    "delimiter",
                    "attributes",
                    "detected_role",
                    "role_candidates",
                    "destinations",
                    "merged_contributors",
                    "appears_in_inbox",
                    "excluded",
                    "ambiguous",
                    "ambiguities",
                    "assignment_source",
                    "warnings",
                },
                context,
            )
            destinations_raw = item.get("destinations")
            if not isinstance(destinations_raw, list):
                raise ValueError(f"{context}.destinations must be an array")
            destinations: list[PlannedDestination] = []
            for destination_index, destination_raw in enumerate(destinations_raw):
                destination_context = f"{context}.destinations[{destination_index}]"
                if not isinstance(destination_raw, Mapping):
                    raise ValueError(f"{destination_context} must be an object")
                _strict_keys(
                    destination_raw,
                    {
                        "type",
                        "name",
                        "status",
                        "exists",
                        "will_create",
                        "merged",
                        "contributors",
                        "existing_name",
                        "id",
                    },
                    destination_context,
                )
                _required_keys(
                    destination_raw,
                    {"type", "name", "status", "exists", "will_create", "merged", "contributors"},
                    destination_context,
                )
                _bool(destination_raw.get("exists"), f"{destination_context}.exists")
                _bool(destination_raw.get("will_create"), f"{destination_context}.will_create")
                _bool(destination_raw.get("merged"), f"{destination_context}.merged")
                contributors_raw = destination_raw.get("contributors")
                if not isinstance(contributors_raw, list):
                    raise ValueError(f"{destination_context}.contributors must be an array")
                contributors: list[Contributor] = []
                for contributor_index, contributor_raw in enumerate(contributors_raw):
                    contributor_context = (
                        f"{destination_context}.contributors[{contributor_index}]"
                    )
                    if not isinstance(contributor_raw, Mapping):
                        raise ValueError(f"{contributor_context} must be an object")
                    _strict_keys(
                        contributor_raw,
                        {"source_account", "source_folder"},
                        contributor_context,
                    )
                    _required_keys(
                        contributor_raw,
                        {"source_account", "source_folder"},
                        contributor_context,
                    )
                    contributors.append(
                        Contributor(
                            _text(
                                contributor_raw.get("source_account"),
                                f"{contributor_context}.source_account",
                            ),
                            _text(
                                contributor_raw.get("source_folder"),
                                f"{contributor_context}.source_folder",
                            ),
                        )
                    )
                status = _text(destination_raw.get("status"), f"{destination_context}.status")
                if status not in {"existing", "create", "conflict", "missing_system"}:
                    raise ValueError(f"{destination_context}.status is invalid")
                kind = _text(destination_raw.get("type"), f"{destination_context}.type")
                if kind not in DESTINATION_KINDS:
                    raise ValueError(
                        f"{destination_context}.type must be one of: "
                        + ", ".join(sorted(DESTINATION_KINDS))
                    )
                raw_name = destination_raw.get("name")
                name = (
                    _gmail_system_role(raw_name, f"{destination_context}.name")
                    if kind == GMAIL_SYSTEM
                    else _destination_name(raw_name, f"{destination_context}.name")
                )
                destinations.append(
                    PlannedDestination(
                        kind=kind,
                        name=name,
                        status=status,
                        existing_name=optional_text(
                            destination_raw.get("existing_name"),
                            f"{destination_context}.existing_name",
                        ),
                        target_id=optional_text(
                            destination_raw.get("id"),
                            f"{destination_context}.id",
                        ),
                        contributors=tuple(contributors),
                    )
                )
            detected_role = item.get("detected_role")
            if detected_role is not None:
                detected_role = _role(detected_role, f"{context}.detected_role")
            source_delimiter = item.get("delimiter")
            if not isinstance(source_delimiter, str):
                raise ValueError("source folder delimiter must be a string")
            entry = PlanEntry(
                source=SourceFolder(
                    source_account=_text(item.get("source_account"), f"{context}.source_account"),
                    name=_text(item.get("source_folder"), f"{context}.source_folder"),
                    delimiter=source_delimiter,
                    attributes=text_list(item.get("attributes"), f"{context}.attributes"),
                ),
                detected_role=detected_role,
                role_candidates=tuple(
                    _role(role, f"{context}.role_candidates")
                    for role in text_list(item.get("role_candidates"), f"{context}.role_candidates")
                ),
                destinations=tuple(destinations),
                excluded=_bool(item.get("excluded"), f"{context}.excluded"),
                assignment_source=_text(
                    item.get("assignment_source"), f"{context}.assignment_source"
                ),
                ambiguities=text_list(item.get("ambiguities"), f"{context}.ambiguities"),
                warnings=text_list(item.get("warnings"), f"{context}.warnings"),
            )
            if entry.assignment_source not in {
                "account_exact",
                "account_role",
                "global_exact",
                "global_role",
                "account_default",
                "unassigned",
            }:
                raise ValueError(f"{context}.assignment_source is invalid")
            expected_detected_role = (
                entry.role_candidates[0] if len(entry.role_candidates) == 1 else None
            )
            if entry.detected_role != expected_detected_role:
                raise ValueError(
                    f"{context}.detected_role does not match role_candidates"
                )
            if entry.excluded and entry.destinations:
                raise ValueError(f"{context} is excluded but still has destinations")
            _bool(item.get("ambiguous"), f"{context}.ambiguous")
            _bool(item.get("appears_in_inbox"), f"{context}.appears_in_inbox")
            if item.get("ambiguous") is not entry.ambiguous:
                raise ValueError(f"{context}.ambiguous does not match ambiguities")
            if item.get("appears_in_inbox") is not entry.appears_in_inbox:
                raise ValueError(f"{context}.appears_in_inbox does not match destinations")
            entries.append(entry)

        filters_raw = raw.get("filters")
        if not isinstance(filters_raw, list):
            raise ValueError("routing plan filters must be an array")
        filters: list[PlannedFilter] = []
        for index, item in enumerate(filters_raw):
            context = f"routing plan filters[{index}]"
            if not isinstance(item, Mapping):
                raise ValueError(f"{context} must be an object")
            allowed = {
                "delivered_to",
                "query",
                "label",
                "inbox",
                "mark_read",
                "conflict_policy",
                "label_status",
                "label_exists",
                "label_will_create",
                "conflicts",
                "existing_label_name",
                "label_id",
            }
            _strict_keys(item, allowed, context)
            _required_keys(
                item,
                {
                    "delivered_to",
                    "query",
                    "label",
                    "inbox",
                    "mark_read",
                    "conflict_policy",
                    "label_status",
                    "label_exists",
                    "label_will_create",
                    "conflicts",
                },
                context,
            )
            _bool(item.get("label_exists"), f"{context}.label_exists")
            _bool(item.get("label_will_create"), f"{context}.label_will_create")
            rule = FilterRule.from_dict(
                {
                    key: item[key]
                    for key in ("delivered_to", "label", "inbox", "mark_read", "conflict_policy")
                    if key in item
                },
                context=context,
            )
            if item.get("query") != rule.query:
                raise ValueError(f"{context}.query does not match delivered_to")
            label_status = _text(item.get("label_status"), f"{context}.label_status")
            if label_status not in {"existing", "create", "conflict", "missing_system"}:
                raise ValueError(f"{context}.label_status is invalid")
            filters.append(
                PlannedFilter(
                    rule=rule,
                    label_status=label_status,
                    existing_label_name=optional_text(
                        item.get("existing_label_name"),
                        f"{context}.existing_label_name",
                    ),
                    target_label_id=optional_text(item.get("label_id"), f"{context}.label_id"),
                    conflicts=text_list(item.get("conflicts"), f"{context}.conflicts"),
                )
            )

        plan = RoutingPlan(
            entries=tuple(entries),
            discovered_target_labels=tuple(target_labels),
            filters=tuple(filters),
            labels_to_create=text_list(raw.get("labels_to_create"), "routing plan labels_to_create"),
            labels_reused=text_list(raw.get("labels_reused"), "routing plan labels_reused"),
            conflicts=text_list(raw.get("conflicts"), "routing plan conflicts"),
            warnings=text_list(raw.get("warnings"), "routing plan warnings"),
            mapping_digest=_text(raw.get("mapping_digest"), "routing plan mapping_digest"),
        )
        if not re.fullmatch(r"[0-9a-f]{64}", plan.mapping_digest):
            raise ValueError("routing plan mapping_digest must be a lowercase SHA-256 digest")
        expected_digest = _mapping_digest(plan.entries, plan.filters)
        if plan.mapping_digest != expected_digest:
            raise ValueError("routing plan mapping_digest does not match its resolved mapping")
        expected_created = {
            destination.name
            for entry in plan.entries
            for destination in entry.destinations
            if destination.kind == CUSTOM_LABEL and destination.status == "create"
        }
        expected_created.update(
            item.rule.label for item in plan.filters if item.label_status == "create"
        )
        expected_reused = {
            destination.name
            for entry in plan.entries
            for destination in entry.destinations
            if destination.kind == CUSTOM_LABEL and destination.status == "existing"
        }
        expected_reused.update(
            item.rule.label for item in plan.filters if item.label_status == "existing"
        )
        if plan.labels_to_create != tuple(
            sorted(expected_created, key=lambda value: (value.casefold(), value))
        ):
            raise ValueError("routing plan labels_to_create does not match destination statuses")
        if plan.labels_reused != tuple(
            sorted(expected_reused, key=lambda value: (value.casefold(), value))
        ):
            raise ValueError("routing plan labels_reused does not match destination statuses")
        expected_warnings = tuple(
            sorted({warning for entry in plan.entries for warning in entry.warnings})
        )
        if plan.warnings != expected_warnings:
            raise ValueError("routing plan warnings do not match entry warnings")
        if raw.get("ok") is not plan.ok:
            raise ValueError("routing plan ok flag does not match plan conflicts")
        if plan.to_dict() != dict(raw):
            raise ValueError("routing plan is not in canonical serialized form")
        return plan


def _folder_matches(rule: RoutingRule, folder: SourceFolder, roles: Tuple[str, ...]) -> bool:
    if rule.folder is not None:
        if rule.folder.upper() == "INBOX" and folder.name.upper() == "INBOX":
            return True
        return rule.folder == folder.name
    return bool(rule.role is not None and rule.role in roles)


def _matching_rule(
    folder: SourceFolder,
    roles: Tuple[str, ...],
    account: Optional[AccountRouting],
    global_rules: Sequence[RoutingRule],
) -> Tuple[Optional[RoutingRule], str, Tuple[str, ...]]:
    levels = (
        ("account_exact", tuple(rule for rule in (account.rules if account else ()) if rule.folder is not None)),
        ("account_role", tuple(rule for rule in (account.rules if account else ()) if rule.role is not None)),
        ("global_exact", tuple(rule for rule in global_rules if rule.folder is not None)),
        ("global_role", tuple(rule for rule in global_rules if rule.role is not None)),
    )
    for source, rules in levels:
        matches = [rule for rule in rules if _folder_matches(rule, folder, roles)]
        if not matches:
            continue
        canonical = {json.dumps(rule.canonical(), sort_keys=True, separators=(",", ":")) for rule in matches}
        if len(canonical) > 1:
            return None, source, (f"multiple conflicting {source.replace('_', ' ')} rules match",)
        return matches[0], source, ()
    return None, "unassigned", ()


def _namespace_suffix(folder: SourceFolder, detected_role: Optional[str]) -> str:
    if detected_role in _ROLE_DISPLAY_NAMES:
        return _ROLE_DISPLAY_NAMES[detected_role]
    if folder.delimiter and folder.delimiter in folder.name:
        return "/".join(segment for segment in folder.name.split(folder.delimiter) if segment)
    return folder.name


def _default_destinations(
    folder: SourceFolder,
    detected_role: Optional[str],
    account: Optional[AccountRouting],
) -> Tuple[Destination, ...]:
    if account is None:
        return ()
    if detected_role == INBOX:
        root = account.default_label or account.default_namespace
        return (Destination(CUSTOM_LABEL, root),) if root else ()
    if account.default_namespace:
        suffix = _namespace_suffix(folder, detected_role)
        return (Destination(CUSTOM_LABEL, f"{account.default_namespace}/{suffix}"),)
    if account.default_label:
        return (Destination(CUSTOM_LABEL, account.default_label),)
    return ()


def _dedupe_destinations(destinations: Iterable[Destination]) -> Tuple[Destination, ...]:
    result: list[Destination] = []
    seen: set[Tuple[str, str]] = set()
    for destination in destinations:
        key = (destination.kind, destination.name)
        if key in seen:
            continue
        seen.add(key)
        result.append(destination)
    return tuple(result)


def _hierarchy_key(label: TargetLabel) -> Tuple[str, ...]:
    delimiter = label.delimiter
    segments = label.name.split(delimiter) if delimiter and delimiter in label.name else [label.name]
    return tuple(segment.casefold() for segment in segments)


def _target_inventory_conflicts(labels: Sequence[TargetLabel]) -> Tuple[str, ...]:
    conflicts: list[str] = []
    by_casefold: Dict[str, list[TargetLabel]] = defaultdict(list)
    by_hierarchy: Dict[Tuple[str, ...], list[TargetLabel]] = defaultdict(list)
    for label in labels:
        by_casefold[label.name.casefold()].append(label)
        by_hierarchy[_hierarchy_key(label)].append(label)
    for values in by_casefold.values():
        identities = {(label.name, label.kind, label.system_role) for label in values}
        if len(values) > 1 and len(identities) > 1:
            shown = ", ".join(sorted(f"{label.name!r} ({label.kind})" for label in values))
            conflicts.append(f"target label name/casefold conflict: {shown}")
        elif len(values) > 1:
            shown = values[0].name
            conflicts.append(f"target label is duplicated: {shown!r}")
    for values in by_hierarchy.values():
        spellings = {(label.name, label.delimiter) for label in values}
        if len(spellings) > 1:
            shown = ", ".join(sorted(repr(label.name) for label in values))
            conflicts.append(f"target label hierarchy conflict: {shown}")
    return tuple(sorted(set(conflicts)))


def _custom_label_hierarchy_case_conflicts(
    names: Iterable[str],
    *,
    context: str = "requested custom label",
) -> Tuple[str, ...]:
    """Reject casing disagreements at any desired Gmail hierarchy node."""

    spellings_by_node: Dict[Tuple[str, ...], set[Tuple[str, ...]]] = defaultdict(set)
    descendant_nodes: set[Tuple[str, ...]] = set()
    for name in set(names):
        segments = tuple(name.split("/"))
        for end in range(1, len(segments) + 1):
            folded = tuple(segment.casefold() for segment in segments[:end])
            spellings_by_node[folded].add(segments[:end])
            if end < len(segments):
                descendant_nodes.add(folded)
    conflicts: list[str] = []
    for folded, spellings in spellings_by_node.items():
        if len(spellings) < 2 or folded not in descendant_nodes:
            continue
        shown = ", ".join(sorted(repr("/".join(parts)) for parts in spellings))
        conflicts.append(f"{context} hierarchy conflicts by casing: {shown}")
    return tuple(sorted(conflicts))


def _planned_destination(
    destination: Destination,
    labels: Sequence[TargetLabel],
) -> Tuple[PlannedDestination, Tuple[str, ...]]:
    conflicts: list[str] = []
    if (
        destination.kind == CUSTOM_LABEL
        and len(destination.name) > GMAIL_CUSTOM_LABEL_MAX_LENGTH
    ):
        conflicts.append(
            f"custom label {destination.name!r} exceeds Gmail's "
            f"{GMAIL_CUSTOM_LABEL_MAX_LENGTH}-character full-name limit"
        )
        return (
            PlannedDestination(destination.kind, destination.name, "conflict"),
            tuple(conflicts),
        )
    if destination.kind == GMAIL_SYSTEM:
        candidates = [
            label for label in labels if label.kind == GMAIL_SYSTEM and label.system_role == destination.name
        ]
        if len(candidates) == 1:
            label = candidates[0]
            return PlannedDestination(
                kind=destination.kind,
                name=destination.name,
                status="existing",
                existing_name=label.name,
                target_id=label.target_id,
            ), ()
        if len(candidates) > 1:
            conflicts.append(f"multiple target Gmail system labels advertise role {destination.name!r}")
            return PlannedDestination(destination.kind, destination.name, "conflict"), tuple(conflicts)
        conflicts.append(f"target Gmail system label for role {destination.name!r} is missing and cannot be created")
        return PlannedDestination(destination.kind, destination.name, "missing_system"), tuple(conflicts)

    exact = [
        label
        for label in labels
        if label.name == destination.name
        or (
            destination.kind == GENERIC_MAILBOX
            and destination.name == "INBOX"
            and label.name.casefold() == INBOX
        )
    ]
    same_kind = [label for label in exact if label.kind == destination.kind]
    if len(same_kind) == 1 and len(exact) == 1:
        label = same_kind[0]
        return PlannedDestination(
            kind=destination.kind,
            name=destination.name,
            status="existing",
            existing_name=label.name,
            target_id=label.target_id,
        ), ()
    if exact:
        kinds = ", ".join(sorted({label.kind for label in exact}))
        conflicts.append(
            f"destination {destination.name!r} is requested as {destination.kind} but exists as {kinds}"
        )
        return PlannedDestination(destination.kind, destination.name, "conflict"), tuple(conflicts)

    folded = [label for label in labels if label.name.casefold() == destination.name.casefold()]
    if folded:
        shown = ", ".join(sorted(repr(label.name) for label in folded))
        conflicts.append(
            f"destination {destination.name!r} conflicts by casefold with existing target name(s): {shown}"
        )
        return PlannedDestination(destination.kind, destination.name, "conflict"), tuple(conflicts)

    if destination.kind == CUSTOM_LABEL:
        normalized_name = destination.name.casefold()
        if (
            normalized_name in _RESERVED_GMAIL_NAMES
            or normalized_name in _GMAIL_RESTORE_SYSTEM_LABEL_ALIASES
        ):
            conflicts.append(f"custom label {destination.name!r} conflicts with a Gmail system name")
        segments = destination.name.split("/")
        for end in range(1, len(segments)):
            ancestor = "/".join(segments[:end]).casefold()
            ancestor_labels = [label for label in labels if label.name.casefold() == ancestor]
            system_ancestors = [label for label in ancestor_labels if label.kind == GMAIL_SYSTEM]
            if system_ancestors:
                conflicts.append(
                    f"custom label hierarchy {destination.name!r} has Gmail system ancestor "
                    f"{system_ancestors[0].name!r}"
                )
    if conflicts:
        return PlannedDestination(destination.kind, destination.name, "conflict"), tuple(conflicts)
    return PlannedDestination(destination.kind, destination.name, "create"), ()


def _mapping_digest(entries: Sequence[PlanEntry], filters: Sequence[PlannedFilter]) -> str:
    payload = {
        "version": ROUTING_PLAN_VERSION,
        "mapping_semantics": ROUTING_MAPPING_SEMANTICS,
        "entries": [
            {
                "source_account": entry.source.source_account,
                "source_folder": entry.source.name,
                "delimiter": entry.source.delimiter,
                "attributes": list(entry.source.attributes),
                "detected_role": entry.detected_role,
                "role_candidates": list(entry.role_candidates),
                "destinations": [
                    {"type": destination.kind, "name": destination.name}
                    for destination in entry.destinations
                ],
                "excluded": entry.excluded,
                "assignment_source": entry.assignment_source,
                "ambiguities": list(entry.ambiguities),
            }
            for entry in entries
        ],
        "filters": [item.rule.to_dict() for item in filters],
    }
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def resolve_routing_plan(
    config: RoutingConfig,
    source_folders: Iterable[SourceFolder],
    target_labels: Iterable[TargetLabel],
) -> RoutingPlan:
    """Resolve every discovered folder without mutating external state."""

    if not config.enabled:
        raise ValueError("routing plan resolution requires routing.enabled=true")
    sources = sorted(
        tuple(source_folders),
        key=lambda folder: (
            folder.source_account.casefold(),
            folder.source_account,
            folder.name.casefold(),
            folder.name,
        ),
    )
    labels = sorted(
        tuple(target_labels),
        key=lambda label: (label.name.casefold(), label.name, label.kind, label.system_role or ""),
    )
    duplicate_sources: Dict[Tuple[str, str], int] = defaultdict(int)
    for folder in sources:
        duplicate_sources[(folder.source_account, folder.name)] += 1
    source_conflicts = [
        f"source folder is duplicated in discovery: {account}/{name}"
        for (account, name), count in sorted(duplicate_sources.items())
        if count > 1
    ]
    inbox_sources: Dict[str, list[SourceFolder]] = defaultdict(list)
    for folder in sources:
        if folder.name.upper() == "INBOX":
            inbox_sources[folder.source_account.casefold()].append(folder)
    for inbox_entries in inbox_sources.values():
        if len(inbox_entries) <= 1:
            continue
        shown = ", ".join(
            f"{folder.source_account}/{folder.name}"
            for folder in sorted(
                inbox_entries,
                key=lambda item: (
                    item.source_account.casefold(),
                    item.source_account,
                    item.name.casefold(),
                    item.name,
                ),
            )
        )
        source_conflicts.append(
            "source INBOX discovery is ambiguous because Gmail/IMAP treats "
            f"INBOX case-insensitively: {shown}"
        )
    inventory_conflicts = list(_target_inventory_conflicts(labels))

    account_by_key = {name.casefold(): value for name, value in config.accounts.items()}
    raw_entries: list[PlanEntry] = []
    all_warnings: list[str] = []
    for folder in sources:
        roles = folder.detected_roles
        detected_role = roles[0] if len(roles) == 1 else None
        account = account_by_key.get(folder.source_account.casefold())
        rule, assignment_source, ambiguities = _matching_rule(folder, roles, account, config.global_rules)
        entry_ambiguities = list(ambiguities)
        entry_warnings: list[str] = []
        if len(roles) > 1 and (rule is None or rule.role is not None):
            entry_ambiguities.append(
                "source folder has conflicting special-use roles: " + ", ".join(roles)
            )

        excluded = False
        destinations: Tuple[Destination, ...]
        defaults = _default_destinations(folder, detected_role, account)
        if ambiguities:
            destinations = ()
        elif rule is not None:
            excluded = rule.exclude
            destinations = () if excluded else _dedupe_destinations(
                tuple(rule.destinations) + (defaults if rule.include_default else ())
            )
        else:
            destinations = defaults
            if destinations:
                assignment_source = "account_default"
            elif not entry_ambiguities:
                entry_ambiguities.append("no routing rule or account default assigns this source folder")

        gmail_system_destinations = {
            destination.name
            for destination in destinations
            if destination.kind == GMAIL_SYSTEM
        }
        if "drafts" in gmail_system_destinations and any(
            destination.kind != GMAIL_SYSTEM
            or destination.name not in {"all", "drafts"}
            for destination in destinations
        ):
            incompatible = sorted(
                f"{destination.kind}:{destination.name}"
                for destination in destinations
                if destination.kind != GMAIL_SYSTEM
                or destination.name not in {"all", "drafts"}
            )
            entry_ambiguities.append(
                "Gmail drafts destination cannot be combined with non-draft destination(s): "
                + ", ".join(incompatible)
            )
        else:
            incompatible_roles = gmail_incompatible_system_roles(gmail_system_destinations)
            if incompatible_roles:
                entry_ambiguities.append(
                    "routing destinations combine incompatible Gmail system locations: "
                    + ", ".join(incompatible_roles)
                )

        planned: list[PlannedDestination] = []
        for destination in destinations:
            planned_destination, destination_conflicts = _planned_destination(destination, labels)
            planned.append(planned_destination)
            entry_ambiguities.extend(destination_conflicts)
            if destination.kind == GMAIL_SYSTEM and destination.name in _UNSAFE_GMAIL_SYSTEM_ROLES:
                warning = (
                    f"historical mail from {folder.source_account}/{folder.name} is explicitly routed "
                    f"to unsafe Gmail system {destination.name}"
                )
                entry_warnings.append(warning)
                all_warnings.append(warning)

        raw_entries.append(
            PlanEntry(
                source=folder,
                detected_role=detected_role,
                role_candidates=roles,
                destinations=tuple(planned),
                excluded=excluded,
                assignment_source=assignment_source,
                ambiguities=tuple(sorted(set(entry_ambiguities))),
                warnings=tuple(sorted(set(entry_warnings))),
            )
        )

    entries_by_account: Dict[str, list[PlanEntry]] = defaultdict(list)
    for entry in raw_entries:
        if not entry.excluded and not entry.ambiguous:
            entries_by_account[entry.source.source_account].append(entry)
    routing_warnings_by_account: Dict[str, str] = {}
    for source_account, account_entries in entries_by_account.items():
        destination_pairs = {
            (destination.kind, destination.name)
            for entry in account_entries
            for destination in entry.destinations
            if destination.status not in {"conflict", "missing_system"}
        }
        system_roles = {
            name
            for kind, name in destination_pairs
            if kind == GMAIL_SYSTEM
        }
        if "drafts" in system_roles and any(
            kind != GMAIL_SYSTEM or name not in {"all", "drafts"}
            for kind, name in destination_pairs
        ):
            warning = (
                f"source account {source_account} routes folders to Gmail Drafts and other "
                "destinations; a message shared by those folders will be rejected after export"
            )
        elif incompatible_roles := gmail_incompatible_system_roles(system_roles):
            warning = (
                f"source account {source_account} routes folders to multiple mutually exclusive "
                f"Gmail system locations ({', '.join(incompatible_roles)}); a message shared by "
                "those folders will be rejected after export"
            )
        else:
            continue
        routing_warnings_by_account[source_account] = warning
        all_warnings.append(warning)
    if routing_warnings_by_account:
        raw_entries = [
            dataclasses.replace(
                entry,
                warnings=tuple(
                    sorted(
                        {
                            *entry.warnings,
                            routing_warnings_by_account[entry.source.source_account],
                        }
                    )
                ),
            )
            if (
                entry.source.source_account in routing_warnings_by_account
                and not entry.excluded
                and not entry.ambiguous
            )
            else entry
            for entry in raw_entries
        ]

    contributors_by_destination: Dict[Tuple[str, str], list[Contributor]] = defaultdict(list)
    for entry in raw_entries:
        contributor = Contributor(entry.source.source_account, entry.source.name)
        for planned_destination in entry.destinations:
            if planned_destination.status not in {"conflict", "missing_system"}:
                contributors_by_destination[
                    (planned_destination.kind, planned_destination.name)
                ].append(contributor)
    entries: list[PlanEntry] = []
    for entry in raw_entries:
        updated_destinations: list[PlannedDestination] = []
        for planned_destination in entry.destinations:
            contributors = contributors_by_destination.get(
                (planned_destination.kind, planned_destination.name),
                [],
            )
            unique = {
                (contributor.source_account, contributor.source_folder): contributor
                for contributor in contributors
            }
            ordered = tuple(
                unique[key]
                for key in sorted(unique, key=lambda item: (item[0].casefold(), item[0], item[1].casefold(), item[1]))
            )
            updated_destinations.append(
                dataclasses.replace(planned_destination, contributors=ordered)
            )
        entries.append(dataclasses.replace(entry, destinations=tuple(updated_destinations)))

    planned_filters: list[PlannedFilter] = []
    filter_conflicts: list[str] = []
    for filter_rule in sorted(
        config.filters,
        key=lambda filter_item: (
            filter_item.delivered_to.casefold(),
            filter_item.delivered_to,
        ),
    ):
        planned_label, conflicts = _planned_destination(
            Destination(CUSTOM_LABEL, filter_rule.label),
            labels,
        )
        planned_filters.append(
            PlannedFilter(
                rule=filter_rule,
                label_status=planned_label.status,
                existing_label_name=planned_label.existing_name,
                target_label_id=planned_label.target_id,
                conflicts=tuple(conflicts),
            )
        )
        filter_conflicts.extend(
            f"filter {filter_rule.delivered_to}: {conflict}"
            for conflict in conflicts
        )

    requested_labels: Dict[str, str] = {}
    requested_label_names: set[str] = set()
    created: set[str] = set()
    reused: set[str] = set()
    for entry in entries:
        for planned_destination in entry.destinations:
            if planned_destination.kind != CUSTOM_LABEL:
                continue
            previous_label = requested_labels.get(planned_destination.name.casefold())
            if previous_label is not None and previous_label != planned_destination.name:
                inventory_conflicts.append(
                    f"requested custom labels conflict by casefold: "
                    f"{previous_label!r} and {planned_destination.name!r}"
                )
            requested_labels[planned_destination.name.casefold()] = planned_destination.name
            requested_label_names.add(planned_destination.name)
            if planned_destination.status == "create":
                created.add(planned_destination.name)
            elif planned_destination.status == "existing":
                reused.add(planned_destination.name)
    for planned_filter in planned_filters:
        previous_label = requested_labels.get(planned_filter.rule.label.casefold())
        if previous_label is not None and previous_label != planned_filter.rule.label:
            inventory_conflicts.append(
                f"requested custom labels conflict by casefold: "
                f"{previous_label!r} and {planned_filter.rule.label!r}"
            )
        requested_labels[planned_filter.rule.label.casefold()] = planned_filter.rule.label
        requested_label_names.add(planned_filter.rule.label)
        if planned_filter.label_status == "create":
            created.add(planned_filter.rule.label)
        elif planned_filter.label_status == "existing":
            reused.add(planned_filter.rule.label)

    inventory_conflicts.extend(_custom_label_hierarchy_case_conflicts(requested_label_names))
    inventory_conflicts.extend(
        _custom_label_hierarchy_case_conflicts(
            [
                *(label.name for label in labels if label.kind == CUSTOM_LABEL),
                *requested_label_names,
            ],
            context="target/requested custom label",
        )
    )
    conflicts = tuple(sorted(set(source_conflicts + inventory_conflicts + filter_conflicts)))
    entries_tuple = tuple(entries)
    filters_tuple = tuple(planned_filters)
    return RoutingPlan(
        entries=entries_tuple,
        discovered_target_labels=tuple(labels),
        filters=filters_tuple,
        labels_to_create=tuple(sorted(created, key=lambda value: (value.casefold(), value))),
        labels_reused=tuple(sorted(reused, key=lambda value: (value.casefold(), value))),
        conflicts=conflicts,
        warnings=tuple(sorted(set(all_warnings))),
        mapping_digest=_mapping_digest(entries_tuple, filters_tuple),
    )


__all__ = [
    "ARCHIVE",
    "AccountRouting",
    "Contributor",
    "CUSTOM_LABEL",
    "DRAFTS",
    "Destination",
    "FilterRule",
    "GENERIC_MAILBOX",
    "GMAIL_EXCLUSIVE_PRIMARY_ROLES",
    "GMAIL_INCOMPATIBLE_SYSTEM_ROLE_PAIRS",
    "GMAIL_SYSTEM",
    "GMAIL_CUSTOM_LABEL_MAX_LENGTH",
    "INBOX",
    "JUNK",
    "PlanEntry",
    "PlannedDestination",
    "PlannedFilter",
    "RoutingConfig",
    "RoutingPlan",
    "ROUTING_MAPPING_SEMANTICS",
    "ROUTING_PLAN_VERSION",
    "RoutingRule",
    "SENT",
    "SPECIAL_USE_ROLES",
    "SourceFolder",
    "TRASH",
    "TargetLabel",
    "detect_special_use_roles",
    "gmail_incompatible_system_roles",
    "resolve_routing_plan",
]
