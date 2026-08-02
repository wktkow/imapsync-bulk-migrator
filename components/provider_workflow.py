"""Top-level, resumable provider migration orchestration."""

from __future__ import annotations

import contextlib
import copy
import errno
import hashlib
import inspect
import json
import logging
import os
import re
import stat
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, Mapping, Optional

from . import provider_ops
from .gmail_api import GmailApiClient
from .gmail_provisioning import (
    GMAIL_CONFIGURATION_PLAN_FILENAME,
    GmailConfigurationPlan,
    discover_gmail_configuration,
    gmail_api_client_if_required,
    gmail_configuration_plan_path,
    plan_live_gmail_configuration,
    provision_gmail_filters,
    provision_gmail_labels,
    require_gmail_configuration_plan,
    require_live_gmail_plan_ok,
    save_gmail_configuration_plan,
    verify_gmail_configuration,
)
from .models import (
    ProviderMigrationConfig,
    WorkspaceAliasAdminAuthConfig,
)
from .routing import RoutingPlan
from .secret_files import read_secret_file_no_links
from .workspace_aliases import (
    WORKSPACE_ALIAS_PLAN_FILENAME,
    WorkspaceAliasPlan,
    WorkspaceDirectoryClient,
    build_workspace_directory_client_from_service_account,
    build_workspace_directory_client_from_token,
    discover_workspace_alias_plan,
    provision_workspace_aliases,
    verify_workspace_aliases,
    workspace_alias_plan_path,
)


MIGRATION_REPORT_FILENAME = "migration-report.json"
_LEGACY_REPORT_QUARANTINE_FILENAME_PREFIX = ".migration-report-quarantine-"
_TERMINAL_SUCCESS_STATUSES = frozenset({"planned", "completed"})
_TERMINAL_COMMIT_FIELDS = frozenset(
    {
        "terminal_commit_id",
        "terminal_commit_spec_sha256",
        "terminal_target_status",
        "terminal_committed",
    }
)

_WORKFLOW_AUTHORIZATION_SECRET_RE = re.compile(
    r"(?i)([\"']?\bauthorization\b[\"']?\s*(?::|=|%3d|\s)\s*)"
    r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;]+(?:[ \t]+[^\s,;]+)?)"
)
_WORKFLOW_BEARER_SECRET_RE = re.compile(
    r"(?i)(\bbearer\b(?:\s+|%20))[^\s,;&]+"
)
_WORKFLOW_NAMED_SECRET_RE = re.compile(
    r"(?i)([\"']?\b(?:"
    r"password|passwd|token|secret|"
    r"(?:access|refresh|auth|authorization|oauth|id|api)[-_ ]?token|"
    r"client[-_ ]?secret|api[-_ ]?key"
    r")\b[\"']?\s*(?::|=|%3d|\bis\b)\s*)"
    r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;&]+)"
)

_RESERVED_ROOT_ARTIFACT_FILENAMES = frozenset(
    {
        provider_ops.ROUTING_PLAN_FILENAME,
        GMAIL_CONFIGURATION_PLAN_FILENAME,
        WORKSPACE_ALIAS_PLAN_FILENAME,
    }
)
_RESERVED_ACCOUNT_ARTIFACT_FILENAMES = frozenset(
    {
        "export-state.json",
        "import.journal.jsonl",
        "manifest.jsonl",
    }
)
_RESERVED_ACCOUNT_DIRECTORY_NAMES = frozenset({"messages", "metadata"})


class _WorkflowStoppedError(RuntimeError):
    """Internal control-flow signal for cooperative workflow cancellation."""


def redact_workflow_diagnostic_secrets(value: str) -> str:
    """Redact common plain and URL-encoded credential forms."""

    redacted = _WORKFLOW_AUTHORIZATION_SECRET_RE.sub(r"\1[REDACTED]", value)
    redacted = _WORKFLOW_BEARER_SECRET_RE.sub(r"\1[REDACTED]", redacted)
    return _WORKFLOW_NAMED_SECRET_RE.sub(r"\1[REDACTED]", redacted)


class _StopAwareRemoteClient:
    """Gate each remote client method call on the shared stop event."""

    def __init__(self, client: Any, stop_event: object, label: str) -> None:
        self._client = client
        self._stop_event = stop_event
        self._label = label

    def __getattr__(self, name: str) -> Any:
        value = getattr(self._client, name)
        if not callable(value):
            return value

        def guarded(*args: Any, **kwargs: Any) -> Any:
            _raise_if_workflow_stopped(
                self._stop_event,
                f"{self._label} {name}",
            )
            return value(*args, **kwargs)

        return guarded


def stop_aware_remote_client(
    client: Optional[Any],
    stop_event: Optional[object],
    *,
    label: str,
) -> Optional[Any]:
    """Return a proxy that prevents new remote calls after cancellation."""

    if client is None or stop_event is None:
        return client
    if isinstance(client, _StopAwareRemoteClient):
        return client
    return _StopAwareRemoteClient(client, stop_event, label)


def resolve_workspace_alias_access_token(auth: WorkspaceAliasAdminAuthConfig) -> str:
    """Resolve the dedicated Directory bearer token without exposing it."""

    if auth.method != "xoauth2":
        raise RuntimeError("Workspace alias bearer authorization requires method='xoauth2'")
    if sum(item is not None for item in (auth.token_file, auth.env_var)) != 1:
        raise RuntimeError(
            "Workspace alias admin auth must configure exactly one bearer-token source"
        )
    if auth.env_var is not None:
        token = os.environ.get(auth.env_var)
        if token is None:
            raise RuntimeError(
                f"Workspace alias token environment variable {auth.env_var} is not set"
            )
    elif auth.token_file is not None:
        token = read_secret_file_no_links(
            auth.token_file,
            label="Workspace alias admin token file",
        )
    else:  # pragma: no cover - guarded above and by config validation
        raise RuntimeError("Workspace alias admin auth has no bearer-token source")
    if not token:
        raise RuntimeError("Workspace alias admin bearer token is empty")
    return token


def workspace_directory_client_if_required(
    config: ProviderMigrationConfig,
    *,
    session: Optional[Any] = None,
    stop_event: Optional[object] = None,
) -> Optional[WorkspaceDirectoryClient]:
    settings = config.target.workspace_aliases
    if not settings.enabled:
        return None
    auth = settings.admin_auth
    if auth is None:
        raise RuntimeError("Workspace alias admin authorization is not configured")
    if auth.method == "xoauth2":
        if auth.admin_email is None:
            raise RuntimeError("Workspace alias XOAUTH2 admin_email is not configured")
        return build_workspace_directory_client_from_token(
            resolve_workspace_alias_access_token(auth),
            admin_email=auth.admin_email,
            retry_max_attempts=config.limits.retry_max_attempts,
            session=session,
            stop_event=stop_event,
        )
    if auth.method == "service_account":
        if auth.credentials_file is None or auth.delegated_admin is None:
            raise RuntimeError(
                "Workspace alias service-account credentials_file and delegated_admin are required"
            )
        return build_workspace_directory_client_from_service_account(
            auth.credentials_file,
            delegated_admin=auth.delegated_admin,
            retry_max_attempts=config.limits.retry_max_attempts,
            session=session,
            stop_event=stop_event,
        )
    raise RuntimeError(f"unsupported Workspace alias admin auth method: {auth.method}")


def _load_workspace_alias_plan(root: Path) -> WorkspaceAliasPlan:
    path = workspace_alias_plan_path(root)
    try:
        payload = json.loads(provider_ops._read_provider_private_file(path))
    except Exception as exc:
        raise RuntimeError(
            f"invalid persisted {path.name}: {type(exc).__name__}"
        ) from None
    try:
        return WorkspaceAliasPlan.from_dict(payload)
    except ValueError as exc:
        if isinstance(payload, Mapping) and payload.get("version") == 1:
            raise RuntimeError(f"invalid persisted {path.name}: {exc}") from None
        raise RuntimeError(
            f"invalid persisted {path.name}: {type(exc).__name__}"
        ) from None
    except Exception as exc:
        raise RuntimeError(
            f"invalid persisted {path.name}: {type(exc).__name__}"
        ) from None


def _save_workspace_alias_plan(
    root: Path,
    discovered: WorkspaceAliasPlan,
) -> WorkspaceAliasPlan:
    """Persist the first reviewed plan and retain it across resumable reruns."""

    if not discovered.ok:
        raise RuntimeError("refusing to persist an unresolved Workspace alias plan")
    path = workspace_alias_plan_path(root)
    created = provider_ops._atomic_json_create_once(path, discovered.to_dict())
    authoritative = _load_workspace_alias_plan(root)
    if created and authoritative.plan_sha256 != discovered.plan_sha256:
        raise RuntimeError(f"persisted {path.name} failed its immutable digest check")
    if authoritative.intent_sha256 != discovered.intent_sha256:
        raise RuntimeError(
            f"existing {path.name} is bound to a different target user or alias set; "
            "use a new staging directory"
        )
    return authoritative


def _reportable(value: Any) -> Any:
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if isinstance(value, tuple):
        return [_reportable(item) for item in value]
    if isinstance(value, list):
        return [_reportable(item) for item in value]
    if isinstance(value, Mapping):
        return {str(key): _reportable(item) for key, item in value.items()}
    return value


def _merge_report_actions(report: Dict[str, Any], actions: Any) -> None:
    for action in actions or ():
        if isinstance(action, str) and action and action not in report["actions_required"]:
            report["actions_required"].append(action)


def _partial_result_payload(exc: BaseException) -> Optional[Dict[str, Any]]:
    partial = getattr(exc, "result", None)
    to_dict = getattr(partial, "to_dict", None)
    if not callable(to_dict):
        return None
    payload = to_dict()
    if not isinstance(payload, Mapping):
        return None
    return {str(key): _reportable(value) for key, value in payload.items()}


def _capture_gmail_partial_result(
    report: Dict[str, Any],
    result_key: str,
    exc: BaseException,
) -> None:
    payload = _partial_result_payload(exc)
    if payload is None:
        return
    report["gmail"][result_key] = payload
    _merge_report_actions(report, payload.get("actions_required"))


def _human_join(items: list[str]) -> str:
    if len(items) == 1:
        return items[0]
    if len(items) == 2:
        return f"{items[0]} and {items[1]}"
    return ", ".join(items[:-1]) + f", and {items[-1]}"


def _dry_run_review_action(artifacts: Mapping[str, Any]) -> str:
    artifact_names = []
    for key, label in (
        ("routing_plan", "routing plan"),
        ("gmail_configuration_plan", "Gmail configuration plan"),
        ("workspace_alias_plan", "Workspace alias plan"),
        ("report", "migration report"),
    ):
        if artifacts.get(key):
            artifact_names.append(label)
    if not artifact_names:  # pragma: no cover - every workflow has a report
        artifact_names.append("dry-run results")
    return (
        f"Review the persisted {_human_join(artifact_names)}, then run migrate "
        "without --dry-run."
    )


def _workspace_alias_groups_from_plan(plan: WorkspaceAliasPlan) -> Dict[str, Any]:
    entries = plan.to_dict().get("entries", [])
    reused = [
        entry.get("alias")
        for entry in entries
        if isinstance(entry, dict) and entry.get("status") == "reuse"
    ]
    conflicted = [
        entry.get("alias")
        for entry in entries
        if isinstance(entry, dict) and entry.get("status") == "conflict"
    ]
    return {
        "created": [],
        "reused": [item for item in reused if isinstance(item, str)],
        "conflicted": [item for item in conflicted if isinstance(item, str)],
        "actions_required": list(plan.actions_required),
    }


def _workspace_alias_groups_from_result(result: Any) -> Dict[str, Any]:
    payload = result.to_dict()
    return {
        "created": list(payload.get("created") or ()),
        "reused": list(payload.get("reused") or ()),
        "conflicted": list(payload.get("conflicted") or ()),
        "actions_required": list(payload.get("actions_required") or ()),
    }


def _set_workspace_alias_groups(report: Dict[str, Any], groups: Mapping[str, Any]) -> None:
    section = report["workspace_aliases"]
    for key in ("created", "reused", "conflicted", "actions_required"):
        section[key] = _reportable(groups.get(key, []))


def _absolute_path(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _existing_migration_report_matches(path: Path, root: Path) -> bool:
    """Recognize only a report previously written for this exact root/path."""

    try:
        payload = json.loads(provider_ops._read_provider_private_file(path))
    except Exception:
        return False
    if not isinstance(payload, Mapping) or payload.get("version") != 1:
        return False
    if not isinstance(payload.get("stage_order"), list) or not isinstance(
        payload.get("stages"), list
    ):
        return False
    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, Mapping):
        return False
    recorded_root = artifacts.get("staging_root")
    recorded_report = artifacts.get("report")
    if not isinstance(recorded_root, str) or not isinstance(recorded_report, str):
        return False
    return bool(
        _absolute_path(Path(recorded_root)) == _absolute_path(root)
        and _absolute_path(Path(recorded_report)) == _absolute_path(path)
    )


def _existing_account_artifact_ancestor(
    root_absolute: Path,
    candidate_absolute: Path,
) -> Optional[Path]:
    current = candidate_absolute.parent
    while current != root_absolute:
        if current == current.parent:
            break
        if current.exists() and current.is_dir():
            if any((current / name).exists() for name in _RESERVED_ACCOUNT_ARTIFACT_FILENAMES):
                return current
            if any((current / name).is_dir() for name in _RESERVED_ACCOUNT_DIRECTORY_NAMES):
                return current
        current = current.parent
    return None


def migration_report_path(
    root: Path,
    report_path: Optional[Path] = None,
    *,
    config: Optional[ProviderMigrationConfig] = None,
) -> Path:
    """Resolve a report path without allowing it to replace staged evidence."""

    root = Path(root)
    candidate = Path(report_path) if report_path is not None else root / MIGRATION_REPORT_FILENAME
    root_absolute = _absolute_path(root)
    candidate_absolute = _absolute_path(candidate)
    try:
        relative = candidate_absolute.relative_to(root_absolute)
    except ValueError:
        raise ValueError(
            f"migration report path must be inside the staging directory {root}"
        ) from None
    if relative == Path("."):
        raise ValueError("migration report path must name a file inside the staging directory")

    relative_name = relative.name.casefold()
    if (
        relative.parts[0].casefold() == provider_ops.IMPORT_LOCK_DIRNAME.casefold()
        or relative_name.startswith(_LEGACY_REPORT_QUARANTINE_FILENAME_PREFIX.casefold())
    ):
        raise ValueError(
            f"migration report path collides with reserved internal staging namespace: {candidate}"
        )
    if (
        len(relative.parts) == 1
        and relative_name in _RESERVED_ROOT_ARTIFACT_FILENAMES
    ):
        raise ValueError(
            f"migration report path collides with reserved staged artifact {relative.name!r}"
        )
    if (
        relative_name in _RESERVED_ACCOUNT_ARTIFACT_FILENAMES
        or relative.suffix.casefold() in {".eml", ".jsonl"}
        or (relative_name.startswith("validation-") and relative.suffix.casefold() == ".json")
        or any(part.casefold() in _RESERVED_ACCOUNT_DIRECTORY_NAMES for part in relative.parts[:-1])
    ):
        raise ValueError(
            f"migration report path collides with a reserved account artifact location: {candidate}"
        )

    if config is not None:
        for account in getattr(config, "accounts", ()):
            account_absolute = _absolute_path(provider_ops.account_export_dir(root, account))
            account_parts = tuple(part.casefold() for part in account_absolute.parts)
            candidate_parts = tuple(part.casefold() for part in candidate_absolute.parts)
            if candidate_parts[: len(account_parts)] != account_parts:
                continue
            raise ValueError(
                f"migration report path must not be inside provider account directory {account_absolute}"
            )

    account_ancestor = _existing_account_artifact_ancestor(root_absolute, candidate_absolute)
    if account_ancestor is not None:
        raise ValueError(
            f"migration report path must not be inside staged account directory {account_ancestor}"
        )

    symlink_component = provider_ops._provider_symlink_component(candidate)
    if symlink_component is not None:
        raise ValueError(
            f"migration report path contains a symlinked component: {symlink_component}"
        )

    current = root_absolute
    for part in relative.parts[:-1]:
        current = current / part
        if not os.path.lexists(current):
            continue
        current_stat = os.lstat(current)
        if not stat.S_ISDIR(current_stat.st_mode):
            raise ValueError(
                f"migration report parent is not a safe directory: {current}"
            )

    if os.path.lexists(candidate_absolute):
        target_stat = os.lstat(candidate_absolute)
        if not stat.S_ISREG(target_stat.st_mode) or target_stat.st_nlink > 1:
            raise ValueError(
                f"migration report target is not a safe regular file: {candidate}"
            )
        if not _existing_migration_report_matches(candidate, root):
            raise ValueError(
                f"migration report path would overwrite an existing non-report artifact: {candidate}"
            )
    return candidate_absolute


def _stage(report: Dict[str, Any], name: str, status: str, **details: Any) -> None:
    report["stage_order"].append(name)
    item: Dict[str, Any] = {"name": name, "status": status}
    item.update(details)
    report["stages"].append(item)


def _raise_if_workflow_stopped(stop_event: Optional[object], label: str) -> None:
    if _workflow_stop_requested(stop_event):
        raise _WorkflowStoppedError(
            f"{label}: stop requested before starting the next stage"
        )


def _workflow_stop_requested(stop_event: Optional[object]) -> bool:
    if stop_event is None:
        return False
    is_set = getattr(stop_event, "is_set", None)
    return bool(callable(is_set) and is_set())


def _write_report(
    root: Path,
    report: Dict[str, Any],
    report_path: Optional[Path],
    *,
    config: Optional[ProviderMigrationConfig] = None,
    before_publish: Optional[Callable[[], None]] = None,
) -> Path:
    path = migration_report_path(root, report_path, config=config)
    # Reports may be the first local artifact for routing-disabled dry runs and
    # early preflight failures.  Establish both locations with the provider
    # code's descriptor-relative, symlink-safe private-directory handling.
    provider_ops.ensure_private_dir(root)
    provider_ops.ensure_private_dir(path.parent)
    _atomic_report_json(path, report, before_publish=before_publish)
    return path


def _atomic_report_json(
    path: Path,
    payload: Mapping[str, Any],
    *,
    before_publish: Optional[Callable[[], None]] = None,
) -> None:
    """Atomically publish a private report without post-publication cleanup.

    The callback is the caller's linearization check: it runs after the temporary
    file is fully synced, with the atomic replace as the next operation. Once
    replacement occurs, any uncertain error leaves the visible path untouched
    for exact-payload recovery by the caller.
    """

    provider_ops.ensure_private_dir(path.parent)
    parent_fd, name, parent_path = provider_ops._open_provider_parent_dir(
        path,
        "migration report",
    )
    tmp_name = f".{name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    tmp_stat: Optional[os.stat_result] = None
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_NONBLOCK"):
            flags |= os.O_NONBLOCK
        try:
            fd = os.open(
                tmp_name,
                flags,
                provider_ops.PRIVATE_FILE_MODE,
                dir_fd=parent_fd,
            )
        except OSError as exc:
            if exc.errno == errno.EEXIST:
                raise RuntimeError(
                    f"refusing to use unsafe migration report temporary file: "
                    f"{path.with_name(tmp_name)}"
                ) from exc
            if exc.errno in {errno.ELOOP, errno.EMLINK}:
                raise RuntimeError(
                    f"refusing to use symlinked migration report temporary file: "
                    f"{path.with_name(tmp_name)}"
                ) from exc
            if exc.errno == errno.ENXIO:
                raise RuntimeError(
                    f"refusing to use non-regular migration report temporary file: "
                    f"{path.with_name(tmp_name)}"
                ) from exc
            raise
        try:
            encoded = (
                json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n"
            ).encode("utf-8")
            with os.fdopen(fd, "wb") as stream:
                os.fchmod(stream.fileno(), provider_ops.PRIVATE_FILE_MODE)
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
                tmp_stat = os.fstat(stream.fileno())
            if (
                tmp_stat is None
                or not stat.S_ISREG(tmp_stat.st_mode)
                or getattr(tmp_stat, "st_nlink", 1) != 1
            ):
                raise RuntimeError(
                    f"refusing to publish unsafe migration report file: {path}"
                )
            provider_ops._raise_if_provider_parent_replaced(
                parent_path,
                parent_fd,
                "migration report",
            )
            if before_publish is not None:
                before_publish()
            os.rename(tmp_name, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            tmp_name = ""
            final_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(final_stat.st_mode)
                or final_stat.st_dev != tmp_stat.st_dev
                or final_stat.st_ino != tmp_stat.st_ino
                or getattr(final_stat, "st_nlink", 1) != 1
                or stat.S_IMODE(final_stat.st_mode) != provider_ops.PRIVATE_FILE_MODE
            ):
                raise RuntimeError(
                    f"migration report changed during atomic publication: {path}"
                )
            provider_ops._raise_if_provider_parent_replaced(
                parent_path,
                parent_fd,
                "migration report",
            )
            provider_ops._fsync_provider_directory_fd(
                parent_fd,
                parent_path,
                "migration report",
            )
            provider_ops._raise_if_provider_parent_replaced(
                parent_path,
                parent_fd,
                "migration report",
            )
        except Exception:
            if tmp_name:
                with contextlib.suppress(OSError, RuntimeError):
                    provider_ops._unlink_provider_entry_and_fsync(
                        parent_fd,
                        tmp_name,
                        parent_path,
                        "migration report temporary file",
                    )
            raise
    finally:
        os.close(parent_fd)


def _terminal_commit_spec_sha256(report: Mapping[str, Any]) -> str:
    """Bind a terminal commit to the complete intended success payload."""

    spec = copy.deepcopy(dict(report))
    for field in _TERMINAL_COMMIT_FIELDS:
        spec.pop(field, None)
    encoded = json.dumps(
        spec,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _read_report_payload(path: Path) -> Optional[Dict[str, Any]]:
    """Read one report through the private-file checks, returning no guess on error."""

    try:
        payload = json.loads(provider_ops._read_provider_private_file(path))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def _report_payload_matches(path: Path, expected: Mapping[str, Any]) -> bool:
    payload = _read_report_payload(path)
    return bool(
        payload is not None
        and provider_ops._json_values_match(payload, dict(expected))
    )


def _terminal_success_payload_matches(
    path: Path,
    expected: Mapping[str, Any],
) -> bool:
    """Accept an uncertain write only when the exact intended commit is visible."""

    payload = _read_report_payload(path)
    if payload is None:
        return False
    commit_id = expected.get("terminal_commit_id")
    spec_sha256 = expected.get("terminal_commit_spec_sha256")
    target_status = expected.get("terminal_target_status")
    return bool(
        isinstance(commit_id, str)
        and commit_id
        and payload.get("terminal_commit_id") == commit_id
        and payload.get("terminal_commit_spec_sha256") == spec_sha256
        and payload.get("terminal_target_status") == target_status
        and payload.get("status") == target_status
        and payload.get("ok") is True
        and payload.get("terminal_committed") is True
        and provider_ops._json_values_match(payload, dict(expected))
    )


def provider_workflow_terminal_success_committed(report: Mapping[str, Any]) -> bool:
    """Return whether a workflow result crossed its explicit success commit point."""

    status = report.get("status")
    return bool(
        report.get("ok") is True
        and status in _TERMINAL_SUCCESS_STATUSES
        and report.get("terminal_target_status") == status
        and report.get("terminal_committed") is True
        and report.get("report_persisted") is True
        and isinstance(report.get("terminal_commit_id"), str)
        and bool(report.get("terminal_commit_id"))
        and isinstance(report.get("terminal_commit_spec_sha256"), str)
        and len(str(report.get("terminal_commit_spec_sha256"))) == 64
    )


def _call_provider_stage(function: Any, *args: Any, routing_plan: Optional[RoutingPlan], **kwargs: Any) -> Any:
    """Pass the routing plan to both old and finalized provider signatures."""

    parameters = inspect.signature(function).parameters
    if "routing_plan" in parameters:
        kwargs["routing_plan"] = routing_plan
    return function(*args, **kwargs)


def _provider_report(
    config: ProviderMigrationConfig,
    root: Path,
    plan: Optional[RoutingPlan],
) -> Dict[str, Any]:
    if not config.migration.routing.enabled:
        accounts = []
        totals = {
            "exported": 0,
            "committed": 0,
            "missing": 0,
            "duplicates": 0,
            "failed": 0,
            "warnings": 0,
        }
        for account in config.accounts:
            _name, validation = provider_ops.provider_validate_account(
                config,
                account,
                root,
                check_target=False,
                write_report=False,
                allow_unresolved_pending=True,
                repair_trailing_journal=False,
                allow_missing_gmail_target_msgid=True,
            )
            account_row: Dict[str, Any] = {
                "source_account": account.source_email,
                "target_account": account.target_email,
                "exported": int(validation.get("exported") or 0),
                "committed": int(validation.get("committed") or 0),
                "missing": list(validation.get("missing") or ()),
                "duplicates": list(validation.get("duplicates") or ()),
                "failed": list(validation.get("failed") or ()),
                "warnings": list(validation.get("warnings") or ()),
            }
            accounts.append(account_row)
            totals["exported"] += account_row["exported"]
            totals["committed"] += account_row["committed"]
            totals["missing"] += len(account_row["missing"])
            totals["duplicates"] += len(account_row["duplicates"])
            totals["failed"] += len(account_row["failed"])
            totals["warnings"] += len(account_row["warnings"])
        return {
            "version": 1,
            "routing_enabled": False,
            "accounts": accounts,
            "totals": totals,
        }
    builder = getattr(provider_ops, "build_provider_routing_report", None)
    if builder is None:
        raise RuntimeError(
            "provider report API is unavailable: expected "
            "build_provider_routing_report(config, in_root, routing_plan=None)"
        )
    result = _call_provider_stage(builder, config, root, routing_plan=plan)
    if not isinstance(result, dict):
        raise RuntimeError("provider routing report API returned a non-object result")
    return result


def _failure_report(
    report: Dict[str, Any],
    *,
    root: Path,
    report_path: Optional[Path],
    stage: str,
    exc: Optional[BaseException] = None,
    issues: Optional[list[str]] = None,
    plan: Optional[RoutingPlan] = None,
    config: Optional[ProviderMigrationConfig] = None,
    stop_event: Optional[object] = None,
) -> Dict[str, Any]:
    report["ok"] = False
    report["status"] = "failed"
    messages = list(issues or ())
    if exc is not None:
        messages.append(str(exc) or type(exc).__name__)
    messages = list(dict.fromkeys(messages))
    report["issues"].extend(item for item in messages if item not in report["issues"])
    action = f"Resolve the {stage} failure and rerun the same command with the same staging directory."
    if action not in report["actions_required"]:
        report["actions_required"].append(action)
    # A cancellation report is essential resumability evidence, but building a
    # fresh provider summary is later work and must not begin after the signal.
    if config is not None and root.exists() and not _workflow_stop_requested(stop_event):
        try:
            report["provider"] = _provider_report(config, root, plan)
        except Exception as report_exc:
            report["provider_report_error"] = str(report_exc) or type(report_exc).__name__
    report["report_persisted"] = True
    try:
        path = _write_report(root, report, report_path, config=config)
        report["artifacts"]["report"] = str(path)
    except Exception as write_exc:
        error = str(write_exc) or type(write_exc).__name__
        report["report_persisted"] = False
        report["report_write_error"] = error
        issue = f"Failed to write the migration failure report: {error}"
        if issue not in report["issues"]:
            report["issues"].append(issue)
        write_action = (
            "Restore writable space and access for the migration report path, then rerun "
            "the same command with the same staging directory."
        )
        if write_action not in report["actions_required"]:
            report["actions_required"].append(write_action)
    return report


def _mark_terminal_failure(
    report: Mapping[str, Any],
    *,
    error: str,
    failure_stage: str,
    write_error: bool,
) -> Dict[str, Any]:
    """Build an in-memory terminal failure without touching the report path."""

    failed = copy.deepcopy(dict(report))
    failed["ok"] = False
    failed["status"] = "failed"
    failed["terminal_committed"] = False
    failed["report_persisted"] = False
    if failed.get("stages") and failed["stages"][-1].get("name") == "final_report":
        failed["stages"][-1].update(status="failed", error=error)
    else:  # pragma: no cover - all current callers stage final_report first
        _stage(failed, "final_report", "failed", error=error)
    if write_error:
        failed["report_write_error"] = error
        issue = f"Failed to write the terminal migration report: {error}"
        action = (
            "Restore writable space and access for the migration report path, then rerun "
            "the same command with the same staging directory."
        )
    else:
        issue = error
        action = (
            f"Resolve the {failure_stage} failure and rerun the same command with the same "
            "staging directory."
        )
    if issue not in failed["issues"]:
        failed["issues"].append(issue)
    if action not in failed["actions_required"]:
        failed["actions_required"].append(action)
    return failed


def _persist_precommit_stop_failure(
    preliminary: Mapping[str, Any],
    *,
    root: Path,
    report_path: Optional[Path],
    config: ProviderMigrationConfig,
    path: Path,
    exc: _WorkflowStoppedError,
    failure_stage: str,
) -> Dict[str, Any]:
    """Replace only this run's finalizing marker with a cancellation failure."""

    failed = _mark_terminal_failure(
        preliminary,
        error=str(exc) or type(exc).__name__,
        failure_stage=failure_stage,
        write_error=False,
    )
    failed["report_persisted"] = True

    def require_preliminary() -> None:
        if not _report_payload_matches(path, preliminary):
            raise RuntimeError(
                "migration report changed before cancellation publication; "
                "refusing to overwrite the replacement"
            )

    try:
        _write_report(
            root,
            failed,
            report_path,
            config=config,
            before_publish=require_preliminary,
        )
    except Exception as write_exc:
        if _report_payload_matches(path, failed):
            return failed
        error = str(write_exc) or type(write_exc).__name__
        failed["report_persisted"] = False
        failed["report_write_error"] = error
        issue = f"Failed to write the migration failure report: {error}"
        if issue not in failed["issues"]:
            failed["issues"].append(issue)
        action = (
            "Restore writable space and access for the migration report path, then rerun "
            "the same command with the same staging directory."
        )
        if action not in failed["actions_required"]:
            failed["actions_required"].append(action)
    return failed


def _write_terminal_report(
    report: Dict[str, Any],
    *,
    root: Path,
    report_path: Optional[Path],
    config: ProviderMigrationConfig,
    plan: Optional[RoutingPlan],
    stop_event: Optional[object],
    failure_stage: str,
) -> Dict[str, Any]:
    """Persist terminal state with an explicit, cancellation-aware commit point."""

    success_requested = bool(
        report.get("ok") is True
        and report.get("status") in _TERMINAL_SUCCESS_STATUSES
    )
    if not success_requested:
        try:
            _raise_if_workflow_stopped(stop_event, failure_stage)
            report["report_persisted"] = True
            _write_report(root, report, report_path, config=config)
        except _WorkflowStoppedError as exc:
            return _failure_report(
                report,
                root=root,
                report_path=report_path,
                stage=failure_stage,
                exc=exc,
                plan=plan,
                config=config,
                stop_event=stop_event,
            )
        except Exception as exc:
            return _mark_terminal_failure(
                report,
                error=str(exc) or type(exc).__name__,
                failure_stage=failure_stage,
                write_error=True,
            )
        return report

    path = migration_report_path(root, report_path, config=config)
    success = copy.deepcopy(report)
    for field in _TERMINAL_COMMIT_FIELDS:
        success.pop(field, None)
    success["report_persisted"] = True
    success["artifacts"]["report"] = str(path)
    success["terminal_commit_id"] = uuid.uuid4().hex
    success["terminal_target_status"] = str(success["status"])
    success["terminal_committed"] = True
    success["terminal_commit_spec_sha256"] = _terminal_commit_spec_sha256(success)
    preliminary = copy.deepcopy(success)
    preliminary["ok"] = False
    preliminary["status"] = "finalizing"
    preliminary["terminal_committed"] = False
    if preliminary.get("stages") and preliminary["stages"][-1].get("name") == "final_report":
        preliminary["stages"][-1]["status"] = "finalizing"

    try:
        _raise_if_workflow_stopped(stop_event, failure_stage)
        _write_report(root, preliminary, report_path, config=config)
        _raise_if_workflow_stopped(stop_event, failure_stage)
    except _WorkflowStoppedError as exc:
        if _report_payload_matches(path, preliminary):
            return _persist_precommit_stop_failure(
                preliminary,
                root=root,
                report_path=report_path,
                config=config,
                path=path,
                exc=exc,
                failure_stage=failure_stage,
            )
        return _failure_report(
            report,
            root=root,
            report_path=report_path,
            stage=failure_stage,
            exc=exc,
            plan=plan,
            config=config,
            stop_event=stop_event,
        )
    except Exception as exc:
        return _mark_terminal_failure(
            preliminary,
            error=str(exc) or type(exc).__name__,
            failure_stage=failure_stage,
            write_error=True,
        )

    def before_success_publish() -> None:
        if not _report_payload_matches(path, preliminary):
            raise RuntimeError(
                "migration report changed before terminal success publication; "
                "refusing to overwrite the replacement"
            )
        # This is the terminal success linearization point. The root lock excludes
        # cooperating writers; after this final observation, a later signal may
        # lose to the immediately following atomic replacement.
        _raise_if_workflow_stopped(stop_event, failure_stage)

    try:
        _write_report(
            root,
            success,
            report_path,
            config=config,
            before_publish=before_success_publish,
        )
    except _WorkflowStoppedError as exc:
        return _persist_precommit_stop_failure(
            preliminary,
            root=root,
            report_path=report_path,
            config=config,
            path=path,
            exc=exc,
            failure_stage=failure_stage,
        )
    except Exception as exc:
        if _terminal_success_payload_matches(path, success):
            recovered = copy.deepcopy(success)
            recovered["report_durability_uncertain"] = (
                redact_workflow_diagnostic_secrets(
                    str(exc) or type(exc).__name__
                )
            )
            return recovered
        return _mark_terminal_failure(
            preliminary,
            error=str(exc) or type(exc).__name__,
            failure_stage=failure_stage,
            write_error=True,
        )
    return success


def run_provider_migration_workflow(
    config: ProviderMigrationConfig,
    root: Path,
    *,
    max_workers: int,
    ignore_errors: bool = False,
    dry_run: bool = False,
    stop_event: Optional[object] = None,
    gmail_client: Optional[GmailApiClient] = None,
    gmail_session: Optional[Any] = None,
    workspace_client: Optional[WorkspaceDirectoryClient] = None,
    workspace_session: Optional[Any] = None,
    report_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Run planning through final validation using one persisted route plan.

    Failures return a structured report and leave all completed artifacts and
    journals available for an idempotent rerun.  Whenever future-delivery
    filters are configured, all required Gmail labels and filters are
    reconciled before export so delivery during the long export/import window
    is protected.  Workspace alias activation also has a fresh Gmail gate
    immediately before any Directory mutation.

    One root-wide filesystem lock covers discovery through the terminal report.
    This keeps separate processes from acting on the same persisted plan at the
    same time while remaining distinct from the narrower target import locks.
    """

    root = _absolute_path(Path(root))
    # Validate the report destination before the lock creates the staging root.
    # Callers rely on invalid external/reserved paths having no filesystem side
    # effects.
    migration_report_path(root, report_path, config=config)
    with provider_ops.provider_workflow_lock(root, stop_event=stop_event):
        return _run_provider_migration_workflow_locked(
            config,
            root,
            max_workers=max_workers,
            ignore_errors=ignore_errors,
            dry_run=dry_run,
            stop_event=stop_event,
            gmail_client=gmail_client,
            gmail_session=gmail_session,
            workspace_client=workspace_client,
            workspace_session=workspace_session,
            report_path=report_path,
        )


def _run_provider_migration_workflow_locked(
    config: ProviderMigrationConfig,
    root: Path,
    *,
    max_workers: int,
    ignore_errors: bool = False,
    dry_run: bool = False,
    stop_event: Optional[object] = None,
    gmail_client: Optional[GmailApiClient] = None,
    gmail_session: Optional[Any] = None,
    workspace_client: Optional[WorkspaceDirectoryClient] = None,
    workspace_session: Optional[Any] = None,
    report_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Execute a provider workflow while the caller holds the root lock."""

    root = _absolute_path(Path(root))
    target = getattr(config, "target", None)
    workspace_settings = getattr(target, "workspace_aliases", None)
    workspace_aliases_enabled = bool(
        workspace_settings is not None
        and getattr(workspace_settings, "enabled", False)
    )
    artifacts = {
        "staging_root": str(root),
        "report": str(migration_report_path(root, report_path, config=config)),
    }
    if config.migration.routing.enabled:
        artifacts.update(
            {
                "routing_plan": str(provider_ops.provider_routing_plan_path(root)),
                "gmail_configuration_plan": str(gmail_configuration_plan_path(root)),
            }
        )
    if workspace_aliases_enabled:
        artifacts["workspace_alias_plan"] = str(workspace_alias_plan_path(root))
    report: Dict[str, Any] = {
        "version": 1,
        "ok": False,
        "dry_run": bool(dry_run),
        "status": "running",
        "terminal_committed": False,
        "report_persisted": False,
        "stage_order": [],
        "stages": [],
        "issues": [],
        "actions_required": [],
        "artifacts": artifacts,
        "planning": None,
        "gmail": {
            "labels": None,
            "filters": None,
            "pre_export_verification": None,
            "verification": None,
            "pre_alias_gate": None,
        },
        "workspace_aliases": {
            "enabled": workspace_aliases_enabled,
            "active_alias_filters_ready_before_export": False,
            "filter_protection": {
                "status": "pending" if workspace_aliases_enabled else "not_applicable",
                "verified_before_export": False,
                "verified_before_alias_activation": False,
                # Gmail filters do not act retroactively.  Even after this run
                # establishes the pre-export boundary, the report must not
                # imply that delivery before that boundary was reconciled.
                "delivery_before_verification_proven": False,
            },
            "planning": None,
            "provisioning": None,
            "verification": None,
            "created": [],
            "reused": [],
            "conflicted": [],
            "actions_required": [],
        },
        "validation": None,
        "provider": None,
    }
    plan: Optional[RoutingPlan] = None
    discovered: Optional[GmailConfigurationPlan] = None
    workspace_discovered: Optional[WorkspaceAliasPlan] = None
    workspace_plan: Optional[WorkspaceAliasPlan] = None
    workspace_alias_resume_action = (
        "Historical imports and journals are preserved; any Workspace aliases already "
        "created are also preserved. Resolve Workspace alias authorization/conflicts and "
        "rerun with the same staging directory."
    )

    try:
        _raise_if_workflow_stopped(stop_event, "provider migration discovery")
        if gmail_client is None:
            gmail_client = gmail_api_client_if_required(
                config,
                session=gmail_session,
                stop_event=stop_event,
            )
        gmail_client = stop_aware_remote_client(
            gmail_client,
            stop_event,
            label="Gmail API",
        )
        _raise_if_workflow_stopped(stop_event, "provider preflight")
        preflight_ok, preflight_issues = provider_ops.provider_preflight(
            config,
            max_workers=max_workers,
            stop_event=stop_event,
        )
        _raise_if_workflow_stopped(stop_event, "provider routing discovery")
        if config.migration.routing.enabled:
            discovered = discover_gmail_configuration(
                config,
                max_workers=max_workers,
                stop_event=stop_event,
                client=gmail_client,
            )
            _raise_if_workflow_stopped(stop_event, "provider routing discovery")
            report["planning"] = discovered.to_dict()
            plan_issues = list(discovered.conflicts)
        else:
            plan_issues = []
            report["planning"] = {
                "version": 1,
                "ok": True,
                "routing_enabled": False,
            }
        discovery_issues = list(preflight_issues) + plan_issues
        discovery_ok = preflight_ok and not discovery_issues
        _stage(
            report,
            "discover_plan",
            "completed" if discovery_ok else "failed",
            preflight_ok=preflight_ok,
            issues=discovery_issues,
        )
        if not discovery_ok:
            return _failure_report(
                report,
                root=root,
                report_path=report_path,
                stage="discover/plan",
                issues=discovery_issues,
                config=config,
                stop_event=stop_event,
            )
    except Exception as exc:
        _stage(report, "discover_plan", "failed", error=str(exc) or type(exc).__name__)
        return _failure_report(
            report,
            root=root,
            report_path=report_path,
            stage="discover/plan",
            exc=exc,
            config=config,
            stop_event=stop_event,
        )

    if workspace_aliases_enabled:
        try:
            _raise_if_workflow_stopped(stop_event, "Workspace alias discovery")
            if workspace_client is None:
                workspace_client = workspace_directory_client_if_required(
                    config,
                    session=workspace_session,
                    stop_event=stop_event,
                )
            workspace_client = stop_aware_remote_client(
                workspace_client,
                stop_event,
                label="Workspace Directory API",
            )
            if workspace_client is None:  # pragma: no cover - defensive
                raise RuntimeError("Workspace Directory client is unavailable")
            target_user = getattr(workspace_settings, "target_user", None)
            if not isinstance(target_user, str):
                raise RuntimeError("Workspace alias target_user is unavailable")
            workspace_discovered = discover_workspace_alias_plan(
                workspace_client,
                target_user,
                config.workspace_alias_candidates(),
            )
            _raise_if_workflow_stopped(stop_event, "Workspace alias discovery")
            report["workspace_aliases"]["planning"] = workspace_discovered.to_dict()
            _set_workspace_alias_groups(
                report,
                _workspace_alias_groups_from_plan(workspace_discovered),
            )
            alias_issues = list(workspace_discovered.conflicts)
            alias_actions = list(workspace_discovered.actions_required)
            report["actions_required"].extend(
                action
                for action in alias_actions
                if action not in report["actions_required"]
            )
            _stage(
                report,
                "discover_aliases",
                "completed" if workspace_discovered.ok else "failed",
                issues=alias_issues,
            )
            if not workspace_discovered.ok:
                return _failure_report(
                    report,
                    root=root,
                    report_path=report_path,
                    stage="Workspace alias discovery/conflict gate",
                    issues=alias_issues,
                    config=config,
                    stop_event=stop_event,
                )
        except Exception as exc:
            _stage(
                report,
                "discover_aliases",
                "failed",
                error=str(exc) or type(exc).__name__,
            )
            return _failure_report(
                report,
                root=root,
                report_path=report_path,
                stage="Workspace alias discovery/conflict gate",
                exc=exc,
                config=config,
                stop_event=stop_event,
            )

    try:
        _raise_if_workflow_stopped(stop_event, "routing plan persistence")
        if discovered is not None:
            plan = save_gmail_configuration_plan(root, config, discovered)
            require_gmail_configuration_plan(root, config, plan)
        _raise_if_workflow_stopped(stop_event, "routing plan persistence")
        _stage(
            report,
            "persist_plan",
            "completed",
            routing_plan_sha256=plan.mapping_digest if plan is not None else None,
        )
    except Exception as exc:
        _stage(report, "persist_plan", "failed", error=str(exc) or type(exc).__name__)
        return _failure_report(
            report,
            root=root,
            report_path=report_path,
            stage="plan persistence",
            exc=exc,
            plan=plan,
            config=config,
            stop_event=stop_event,
        )

    if workspace_aliases_enabled:
        try:
            _raise_if_workflow_stopped(stop_event, "Workspace alias plan persistence")
            if workspace_discovered is None:  # pragma: no cover - defensive
                raise RuntimeError("Workspace alias discovery plan is unavailable")
            workspace_plan = _save_workspace_alias_plan(root, workspace_discovered)
            _raise_if_workflow_stopped(stop_event, "Workspace alias plan persistence")
            report["workspace_aliases"]["persisted_plan_sha256"] = (
                workspace_plan.plan_sha256
            )
            _stage(
                report,
                "persist_alias_plan",
                "completed",
                workspace_alias_plan_sha256=workspace_plan.plan_sha256,
            )
        except Exception as exc:
            _stage(
                report,
                "persist_alias_plan",
                "failed",
                error=str(exc) or type(exc).__name__,
            )
            return _failure_report(
                report,
                root=root,
                report_path=report_path,
                stage="Workspace alias plan persistence",
                exc=exc,
                plan=plan,
                config=config,
                stop_event=stop_event,
            )

    if dry_run:
        report["ok"] = True
        report["status"] = "planned"
        review_action = _dry_run_review_action(report["artifacts"])
        report["actions_required"] = [review_action]
        if workspace_aliases_enabled:
            report["workspace_aliases"]["actions_required"] = [review_action]
        _stage(report, "final_report", "completed")
        return _write_terminal_report(
            report,
            root=root,
            report_path=report_path,
            config=config,
            plan=plan,
            stop_event=stop_event,
            failure_stage="dry-run final report",
        )

    # Gmail filters are not retroactive.  Reconcile every requested
    # future-delivery filter before the long export/import window even when
    # aliases are provisioned outside this tool.  Directory access remains
    # strictly opt-in through workspace_aliases.enabled.
    protect_future_delivery = bool(
        plan is not None and getattr(plan, "filters", ())
    )

    if protect_future_delivery:
        try:
            _raise_if_workflow_stopped(
                stop_event,
                "early Gmail label provisioning for future-delivery filters",
            )
            if plan is None:  # pragma: no cover - guarded by protect_future_delivery
                raise RuntimeError("future-delivery protection requires a routing plan")
            live_plan = plan_live_gmail_configuration(plan, gmail_client)
            require_live_gmail_plan_ok(live_plan)
            _raise_if_workflow_stopped(
                stop_event,
                "early Gmail label provisioning for future-delivery filters",
            )
            label_result = provision_gmail_labels(plan, gmail_client)
            report["gmail"]["labels"] = label_result.to_dict()
            if not label_result.ok:
                details = "; ".join(
                    getattr(label_result, "issues", ())
                    or getattr(label_result, "conflicts", ())
                )
                raise RuntimeError(
                    "Gmail label reconciliation did not verify"
                    + (f": {details}" if details else "")
                )
            _raise_if_workflow_stopped(
                stop_event,
                "early Gmail label provisioning for future-delivery filters",
            )
            _stage(report, "provision_labels", "completed", timing="before_export")
        except Exception as exc:
            _capture_gmail_partial_result(report, "labels", exc)
            _stage(
                report,
                "provision_labels",
                "failed",
                timing="before_export",
                error=str(exc) or type(exc).__name__,
            )
            if workspace_aliases_enabled:
                report["actions_required"].append(
                    "Export has not started and no new Workspace aliases were created. "
                    "Fix Gmail label authorization/conflicts and rerun before continuing."
                )
            else:
                report["actions_required"].append(
                    "Export has not started. Fix Gmail label authorization/conflicts "
                    "and rerun before continuing the migration."
                )
            return _failure_report(
                report,
                root=root,
                report_path=report_path,
                stage="early Gmail label provisioning for future-delivery filters",
                exc=exc,
                plan=plan,
                config=config,
                stop_event=stop_event,
            )

        try:
            _raise_if_workflow_stopped(
                stop_event,
                "early Gmail filter provisioning for future delivery",
            )
            filter_result = provision_gmail_filters(plan, gmail_client)
            report["gmail"]["filters"] = filter_result.to_dict()
            if not filter_result.ok:
                details = "; ".join(
                    getattr(filter_result, "issues", ())
                    or getattr(filter_result, "conflicts", ())
                )
                raise RuntimeError(
                    "Gmail filter reconciliation did not verify"
                    + (f": {details}" if details else "")
                )
            _raise_if_workflow_stopped(
                stop_event,
                "early Gmail filter provisioning for future delivery",
            )
            pre_export_verification = verify_gmail_configuration(plan, gmail_client)
            report["gmail"]["pre_export_verification"] = (
                pre_export_verification.to_dict()
            )
            if not pre_export_verification.ok:
                details = "; ".join(pre_export_verification.issues)
                raise RuntimeError(
                    "Gmail configuration did not verify before export"
                    + (f": {details}" if details else "")
                )
            _raise_if_workflow_stopped(
                stop_event,
                "early Gmail verification for future delivery",
            )
            if workspace_aliases_enabled:
                report["workspace_aliases"][
                    "active_alias_filters_ready_before_export"
                ] = True
                report["workspace_aliases"]["filter_protection"].update(
                    status="verified_before_export",
                    verified_before_export=True,
                )
            _stage(report, "provision_filters", "completed", timing="before_export")
        except Exception as exc:
            _capture_gmail_partial_result(report, "filters", exc)
            _stage(
                report,
                "provision_filters",
                "failed",
                timing="before_export",
                error=str(exc) or type(exc).__name__,
            )
            if workspace_aliases_enabled:
                report["actions_required"].append(
                    "No new Workspace aliases were created. Fix Gmail filter authorization/conflicts "
                    "for every configured alias, then rerun before continuing the migration."
                )
            else:
                report["actions_required"].append(
                    "Export has not started. Fix Gmail filter authorization/conflicts "
                    "and rerun before continuing the migration."
                )
            return _failure_report(
                report,
                root=root,
                report_path=report_path,
                stage="early Gmail filter provisioning for future delivery",
                exc=exc,
                plan=plan,
                config=config,
                stop_event=stop_event,
            )

    try:
        _raise_if_workflow_stopped(stop_event, "export")
        provider_ops.provider_export_all(
            config,
            root,
            max_workers=max_workers,
            ignore_errors=ignore_errors,
            stop_event=stop_event,
            routing_plan=plan,
        )
        _raise_if_workflow_stopped(stop_event, "export")
        _stage(report, "export", "completed")
    except Exception as exc:
        _stage(report, "export", "failed", error=str(exc) or type(exc).__name__)
        return _failure_report(
            report,
            root=root,
            report_path=report_path,
            stage="export",
            exc=exc,
            plan=plan,
            config=config,
            stop_event=stop_event,
        )

    try:
        _raise_if_workflow_stopped(stop_event, "audit")
        audit_ok, audit_issues = _call_provider_stage(
            provider_ops.provider_audit_all,
            config,
            root,
            routing_plan=plan,
            max_workers=max_workers,
            stop_event=stop_event,
        )
        _raise_if_workflow_stopped(stop_event, "audit")
        _stage(
            report,
            "audit",
            "completed" if audit_ok else "failed",
            issues=list(audit_issues),
        )
        if not audit_ok:
            return _failure_report(
                report,
                root=root,
                report_path=report_path,
                stage="audit",
                issues=list(audit_issues),
                plan=plan,
                config=config,
                stop_event=stop_event,
            )
    except Exception as exc:
        _stage(report, "audit", "failed", error=str(exc) or type(exc).__name__)
        return _failure_report(
            report,
            root=root,
            report_path=report_path,
            stage="audit",
            exc=exc,
            plan=plan,
            config=config,
            stop_event=stop_event,
        )

    if not protect_future_delivery:
        try:
            _raise_if_workflow_stopped(stop_event, "Gmail label provisioning")
            if plan is not None:
                live_plan = plan_live_gmail_configuration(plan, gmail_client)
                require_live_gmail_plan_ok(live_plan)
                _raise_if_workflow_stopped(stop_event, "Gmail label provisioning")
                label_result = provision_gmail_labels(plan, gmail_client)
                report["gmail"]["labels"] = label_result.to_dict()
                _raise_if_workflow_stopped(stop_event, "Gmail label provisioning")
            _stage(report, "provision_labels", "completed")
        except Exception as exc:
            _capture_gmail_partial_result(report, "labels", exc)
            _stage(report, "provision_labels", "failed", error=str(exc) or type(exc).__name__)
            return _failure_report(
                report,
                root=root,
                report_path=report_path,
                stage="Gmail label provisioning",
                exc=exc,
                plan=plan,
                config=config,
                stop_event=stop_event,
            )

    try:
        _raise_if_workflow_stopped(stop_event, "import")
        provider_ops.provider_import_all(
            config,
            root,
            max_workers=max_workers,
            ignore_errors=ignore_errors,
            stop_event=stop_event,
            routing_plan=plan,
        )
        _raise_if_workflow_stopped(stop_event, "import")
        _stage(report, "import", "completed")
    except Exception as exc:
        _stage(report, "import", "failed", error=str(exc) or type(exc).__name__)
        return _failure_report(
            report,
            root=root,
            report_path=report_path,
            stage="import",
            exc=exc,
            plan=plan,
            config=config,
            stop_event=stop_event,
        )

    if not protect_future_delivery:
        try:
            _raise_if_workflow_stopped(stop_event, "Gmail filter provisioning")
            if plan is not None:
                filter_result = provision_gmail_filters(plan, gmail_client)
                report["gmail"]["filters"] = filter_result.to_dict()
                _raise_if_workflow_stopped(stop_event, "Gmail filter provisioning")
            _stage(report, "provision_filters", "completed")
        except Exception as exc:
            _capture_gmail_partial_result(report, "filters", exc)
            _stage(report, "provision_filters", "failed", error=str(exc) or type(exc).__name__)
            report["actions_required"].append(
                "Imported messages and journals are preserved; fix Gmail filter authorization/conflicts and rerun."
            )
            return _failure_report(
                report,
                root=root,
                report_path=report_path,
                stage="Gmail filter provisioning",
                exc=exc,
                plan=plan,
                config=config,
                stop_event=stop_event,
            )

    if workspace_aliases_enabled:
        gate = {
            "timing": "immediately_before_alias_activation",
            "status": "running",
            "ok": False,
            "live_plan": "pending",
            "labels": None,
            "filters": None,
            "verification": None,
        }
        report["gmail"]["pre_alias_gate"] = gate
        gate_phase = "live_plan"
        try:
            _raise_if_workflow_stopped(
                stop_event,
                "Gmail reconciliation immediately before Workspace alias activation",
            )
            if plan is None:  # pragma: no cover - validated alias config requires routing
                raise RuntimeError("Workspace alias protection requires a routing plan")
            live_plan = plan_live_gmail_configuration(plan, gmail_client)
            to_dict = getattr(live_plan, "to_dict", None)
            gate["live_plan"] = to_dict() if callable(to_dict) else "checked"
            require_live_gmail_plan_ok(live_plan)
            _raise_if_workflow_stopped(
                stop_event,
                "Gmail reconciliation immediately before Workspace alias activation",
            )

            gate_phase = "labels"
            label_result = provision_gmail_labels(plan, gmail_client)
            gate["labels"] = label_result.to_dict()
            if not label_result.ok:
                details = "; ".join(
                    getattr(label_result, "issues", ())
                    or getattr(label_result, "conflicts", ())
                )
                raise RuntimeError(
                    "Gmail label reconciliation did not verify before Workspace alias activation"
                    + (f": {details}" if details else "")
                )
            _raise_if_workflow_stopped(
                stop_event,
                "Gmail reconciliation immediately before Workspace alias activation",
            )

            gate_phase = "filters"
            filter_result = provision_gmail_filters(plan, gmail_client)
            gate["filters"] = filter_result.to_dict()
            if not filter_result.ok:
                details = "; ".join(
                    getattr(filter_result, "issues", ())
                    or getattr(filter_result, "conflicts", ())
                )
                raise RuntimeError(
                    "Gmail filter reconciliation did not verify before Workspace alias activation"
                    + (f": {details}" if details else "")
                )
            _raise_if_workflow_stopped(
                stop_event,
                "Gmail verification immediately before Workspace alias activation",
            )

            gate_phase = "verification"
            gmail_gate_verification = verify_gmail_configuration(plan, gmail_client)
            gate["verification"] = gmail_gate_verification.to_dict()
            if not gmail_gate_verification.ok:
                details = "; ".join(gmail_gate_verification.issues)
                raise RuntimeError(
                    "Gmail configuration is not ready for Workspace alias activation"
                    + (f": {details}" if details else "")
                )
            _raise_if_workflow_stopped(
                stop_event,
                "Gmail verification immediately before Workspace alias activation",
            )
            gate.update(status="verified", ok=True)
            report["workspace_aliases"]["filter_protection"].update(
                status="verified_before_alias_activation",
                verified_before_alias_activation=True,
            )
            _stage(
                report,
                "reconcile_gmail_before_aliases",
                "completed",
                timing="immediately_before_alias_activation",
            )
        except Exception as exc:
            partial_payload = _partial_result_payload(exc)
            if partial_payload is not None and gate_phase in {"labels", "filters"}:
                gate[gate_phase] = partial_payload
                _merge_report_actions(report, partial_payload.get("actions_required"))
            gate.update(
                status="failed",
                ok=False,
                failed_phase=gate_phase,
                error=str(exc) or type(exc).__name__,
            )
            report["workspace_aliases"]["filter_protection"]["status"] = (
                "unresolved_before_alias_activation"
            )
            _stage(
                report,
                "reconcile_gmail_before_aliases",
                "failed",
                timing="immediately_before_alias_activation",
                error=str(exc) or type(exc).__name__,
            )
            gate_action = (
                "Historical imports and journals are preserved. No new Workspace alias "
                "insertions were attempted after the Gmail protection gate failed. "
                "Repair Gmail labels, filters, authorization, or conflicts and rerun "
                "with the same staging directory."
            )
            if gate_action not in report["actions_required"]:
                report["actions_required"].append(gate_action)
            if gate_action not in report["workspace_aliases"]["actions_required"]:
                report["workspace_aliases"]["actions_required"].append(gate_action)
            return _failure_report(
                report,
                root=root,
                report_path=report_path,
                stage="Gmail reconciliation immediately before Workspace alias activation",
                exc=exc,
                plan=plan,
                config=config,
                stop_event=stop_event,
            )

        try:
            _raise_if_workflow_stopped(stop_event, "Workspace alias provisioning")
            if workspace_plan is None or workspace_client is None:  # pragma: no cover - defensive
                raise RuntimeError("persisted Workspace alias plan or client is unavailable")
            alias_result = provision_workspace_aliases(
                workspace_client,
                workspace_plan,
                dry_run=False,
            )
            report["workspace_aliases"]["provisioning"] = alias_result.to_dict()
            _set_workspace_alias_groups(
                report,
                _workspace_alias_groups_from_result(alias_result),
            )
            _raise_if_workflow_stopped(stop_event, "Workspace alias provisioning")
            if not alias_result.ok:
                alias_issues = list(alias_result.issues)
                _stage(
                    report,
                    "provision_aliases",
                    "failed",
                    issues=alias_issues,
                )
                for action in list(alias_result.actions_required) + [workspace_alias_resume_action]:
                    if action not in report["actions_required"]:
                        report["actions_required"].append(action)
                    if action not in report["workspace_aliases"]["actions_required"]:
                        report["workspace_aliases"]["actions_required"].append(action)
                return _failure_report(
                    report,
                    root=root,
                    report_path=report_path,
                    stage="Workspace alias provisioning",
                    issues=alias_issues,
                    plan=plan,
                    config=config,
                    stop_event=stop_event,
                )
            _stage(report, "provision_aliases", "completed")
        except Exception as exc:
            partial = getattr(exc, "result", None)
            partial_payload = _partial_result_payload(exc)
            if partial is not None and partial_payload is not None:
                report["workspace_aliases"]["provisioning"] = partial_payload
                groups = _workspace_alias_groups_from_result(partial)
                _set_workspace_alias_groups(
                    report,
                    groups,
                )
                _merge_report_actions(report, groups.get("actions_required"))
            _stage(
                report,
                "provision_aliases",
                "failed",
                error=str(exc) or type(exc).__name__,
            )
            if workspace_alias_resume_action not in report["actions_required"]:
                report["actions_required"].append(workspace_alias_resume_action)
            if workspace_alias_resume_action not in report["workspace_aliases"]["actions_required"]:
                report["workspace_aliases"]["actions_required"].append(
                    workspace_alias_resume_action
                )
            return _failure_report(
                report,
                root=root,
                report_path=report_path,
                stage="Workspace alias provisioning",
                exc=exc,
                plan=plan,
                config=config,
                stop_event=stop_event,
            )

    try:
        _raise_if_workflow_stopped(stop_event, "validation/verification")
        validation_ok, validation_issues = provider_ops.provider_validate_all(
            config,
            root,
            max_workers=max_workers,
            stop_event=stop_event,
            routing_plan=plan,
        )
        _raise_if_workflow_stopped(stop_event, "Gmail configuration verification")
        if plan is not None:
            gmail_verification = verify_gmail_configuration(plan, gmail_client)
            report["gmail"]["verification"] = gmail_verification.to_dict()
            _raise_if_workflow_stopped(stop_event, "Gmail configuration verification")
        else:
            gmail_verification = None
        validation_issues = list(validation_issues)
        if gmail_verification is not None:
            validation_issues.extend(gmail_verification.issues)
        combined_ok = validation_ok and (
            gmail_verification is None or gmail_verification.ok
        )
        report["validation"] = {
            "ok": combined_ok,
            "provider_ok": validation_ok,
            "issues": list(dict.fromkeys(validation_issues)),
        }
        _stage(
            report,
            "validate_verify",
            "completed" if combined_ok else "failed",
            issues=report["validation"]["issues"],
        )
        _raise_if_workflow_stopped(stop_event, "provider report generation")
        report["provider"] = _provider_report(config, root, plan)
        _raise_if_workflow_stopped(stop_event, "provider report generation")
    except Exception as exc:
        _stage(report, "validate_verify", "failed", error=str(exc) or type(exc).__name__)
        return _failure_report(
            report,
            root=root,
            report_path=report_path,
            stage="validation/verification",
            exc=exc,
            plan=plan,
            config=config,
            stop_event=stop_event,
        )

    if workspace_aliases_enabled:
        try:
            _raise_if_workflow_stopped(stop_event, "Workspace alias verification")
            if workspace_plan is None or workspace_client is None:  # pragma: no cover - defensive
                raise RuntimeError("persisted Workspace alias plan or client is unavailable")
            alias_verification = verify_workspace_aliases(
                workspace_client,
                workspace_plan,
            )
            _raise_if_workflow_stopped(stop_event, "Workspace alias verification")
            alias_verification_payload = alias_verification.to_dict()
            report["workspace_aliases"]["verification"] = alias_verification_payload
            report["workspace_aliases"]["conflicted"] = list(
                alias_verification_payload.get("conflicted") or ()
            )
            alias_actions = list(alias_verification.actions_required)
            report["workspace_aliases"]["actions_required"] = alias_actions
            alias_issues = list(alias_verification.issues)
            if not alias_verification.ok:
                if workspace_alias_resume_action not in report["workspace_aliases"]["actions_required"]:
                    report["workspace_aliases"]["actions_required"].append(
                        workspace_alias_resume_action
                    )
                if workspace_alias_resume_action not in report["actions_required"]:
                    report["actions_required"].append(workspace_alias_resume_action)
            report["validation"]["workspace_aliases_ok"] = alias_verification.ok
            report["validation"]["issues"] = list(
                dict.fromkeys(report["validation"]["issues"] + alias_issues)
            )
            report["validation"]["ok"] = bool(
                report["validation"]["ok"] and alias_verification.ok
            )
            _stage(
                report,
                "verify_aliases",
                "completed" if alias_verification.ok else "failed",
                issues=alias_issues,
            )
            for action in alias_actions:
                if action not in report["actions_required"]:
                    report["actions_required"].append(action)
        except Exception as exc:
            _stage(
                report,
                "verify_aliases",
                "failed",
                error=str(exc) or type(exc).__name__,
            )
            if workspace_alias_resume_action not in report["actions_required"]:
                report["actions_required"].append(workspace_alias_resume_action)
            if workspace_alias_resume_action not in report["workspace_aliases"]["actions_required"]:
                report["workspace_aliases"]["actions_required"].append(
                    workspace_alias_resume_action
                )
            return _failure_report(
                report,
                root=root,
                report_path=report_path,
                stage="Workspace alias verification",
                exc=exc,
                plan=plan,
                config=config,
                stop_event=stop_event,
            )

    report["ok"] = bool(report["validation"]["ok"])
    report["status"] = "completed" if report["ok"] else "failed"
    if not report["ok"]:
        report["issues"].extend(report["validation"]["issues"])
        report["actions_required"].append(
            "Resolve validation findings and rerun with the same staging directory."
        )
    _stage(report, "final_report", "completed")
    report = _write_terminal_report(
        report,
        root=root,
        report_path=report_path,
        config=config,
        plan=plan,
        stop_event=stop_event,
        failure_stage="final report",
    )
    if report["status"] == "completed":
        logging.info(
            "Provider migration workflow report written to %s",
            report["artifacts"]["report"],
        )
    return report


__all__ = [
    "MIGRATION_REPORT_FILENAME",
    "migration_report_path",
    "provider_workflow_terminal_success_committed",
    "resolve_workspace_alias_access_token",
    "run_provider_migration_workflow",
    "stop_aware_remote_client",
    "workspace_directory_client_if_required",
]
