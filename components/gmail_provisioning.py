"""Gmail API integration for provider routing plans.

The low-level REST and reconciliation implementation lives in
``components.gmail_api``.  This module binds it to provider configuration,
resolves OAuth bearer-token sources without logging their contents, and keeps
the immutable provider routing plan separate from changing live Gmail IDs and
create/reuse actions.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Tuple

from .gmail_api import (
    FILTER_SCOPE_HINT,
    LABEL_SCOPE_HINT,
    FilterReconciliationResult,
    GmailApiClient,
    GmailFilterSpec,
    GmailProvisionPlan,
    GmailReconciliationError,
    LabelReconciliationResult,
    plan_filter_reconciliation,
    plan_gmail_configuration,
    plan_label_reconciliation,
    reconcile_filters,
    reconcile_labels,
)
from .models import (
    AuthConfig,
    ProviderMigrationConfig,
    auth_username_identity,
    effective_gmail_api_auth,
)
from . import provider_ops
from .routing import CUSTOM_LABEL, RoutingPlan
from .secret_files import read_secret_file_no_links


GMAIL_CONFIGURATION_PLAN_FILENAME = "gmail-configuration-plan.json"


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _target_account(config: ProviderMigrationConfig) -> str:
    if not config.accounts:
        raise ValueError("Gmail API provisioning requires at least one migration account")
    identities = {
        auth_username_identity(config.target, account.target_email)
        for account in config.accounts
    }
    if len(identities) != 1:
        raise ValueError("Gmail API provisioning requires one shared target account")
    return config.accounts[0].target_email


def gmail_api_required(config: ProviderMigrationConfig) -> bool:
    """Return whether the opt-in route requires label/filter REST APIs."""

    if config.target.provider != "gmail" or not config.migration.routing.enabled:
        return False
    routing = config.migration.routing
    if routing.filters:
        return True
    for account in routing.accounts.values():
        if account.default_label or account.default_namespace:
            return True
        if any(
            destination.kind == CUSTOM_LABEL
            for rule in account.rules
            for destination in rule.destinations
        ):
            return True
    return any(
        destination.kind == CUSTOM_LABEL
        for rule in routing.global_rules
        for destination in rule.destinations
    )


def _required_scope_text(config: ProviderMigrationConfig) -> str:
    scopes = [LABEL_SCOPE_HINT]
    if config.migration.routing.filters:
        scopes.append(FILTER_SCOPE_HINT)
    return "; ".join(scopes)


def resolve_gmail_api_access_token(auth: AuthConfig) -> str:
    """Resolve one configured XOAUTH2 token without exposing it in errors."""

    if auth.method != "xoauth2":
        raise RuntimeError(
            "Gmail REST provisioning requires XOAUTH2 bearer authorization; "
            "an IMAP app password cannot manage Gmail labels or filters"
        )
    if auth.secret_source_count() != 1:
        raise RuntimeError("Gmail API auth must configure exactly one bearer-token source")
    if auth.env_var:
        token = os.environ.get(auth.env_var)
        if token is None:
            raise RuntimeError(
                f"Gmail API token environment variable {auth.env_var} is not set"
            )
    elif auth.token_file:
        token = read_secret_file_no_links(auth.token_file, label="Gmail API token file")
    elif auth.password is not None:
        # AuthConfig uses the legacy ``password`` field as the inline XOAUTH2
        # bearer source.  It is deliberately never included in reports/logs.
        token = auth.password
    else:
        raise RuntimeError("Gmail API auth has no supported bearer-token source")
    if not token:
        raise RuntimeError("Gmail API bearer token is empty")
    return token


def build_gmail_api_client(
    config: ProviderMigrationConfig,
    *,
    session: Optional[Any] = None,
    timeout_sec: float = 20,
    retry_max_attempts: Optional[int] = None,
    stop_event: Optional[object] = None,
) -> GmailApiClient:
    """Build a client bound to the configured target email, never just ``me``."""

    if config.target.provider != "gmail":
        raise ValueError("Gmail API provisioning requires target.provider='gmail'")
    target_account = _target_account(config)
    representative = config.accounts[0]
    auth = effective_gmail_api_auth(config.target, representative)
    if auth is None:
        raise RuntimeError(
            "Gmail routing requires OAuth API authorization. Configure "
            "target.gmail_api_auth or accounts[].target_gmail_api_auth with a bearer token; "
            f"required scope(s): {_required_scope_text(config)}. "
            "An IMAP app password cannot manage Gmail labels or filters."
        )
    if auth.username and (
        auth_username_identity(config.target, auth.username)
        != auth_username_identity(config.target, target_account)
    ):
        raise RuntimeError(
            "Gmail API authorization username does not match the configured target account"
        )
    token = resolve_gmail_api_access_token(auth)
    attempts = (
        config.limits.retry_max_attempts
        if retry_max_attempts is None
        else retry_max_attempts
    )
    return GmailApiClient(
        token,
        session=session,
        user_id=target_account,
        timeout_sec=timeout_sec,
        retry_max_attempts=attempts,
        stop_event=stop_event,
    )


def gmail_api_client_if_required(
    config: ProviderMigrationConfig,
    *,
    session: Optional[Any] = None,
    timeout_sec: float = 20,
    retry_max_attempts: Optional[int] = None,
    stop_event: Optional[object] = None,
) -> Optional[GmailApiClient]:
    if not gmail_api_required(config):
        return None
    return build_gmail_api_client(
        config,
        session=session,
        timeout_sec=timeout_sec,
        retry_max_attempts=retry_max_attempts,
        stop_event=stop_event,
    )


def required_custom_labels(plan: RoutingPlan) -> Tuple[str, ...]:
    names = {
        destination.name
        for entry in plan.entries
        for destination in entry.destinations
        if destination.kind == CUSTOM_LABEL
    }
    names.update(item.rule.label for item in plan.filters)
    return tuple(sorted(names, key=lambda value: (value.casefold(), value)))


def gmail_filter_specs(plan: RoutingPlan) -> Tuple[GmailFilterSpec, ...]:
    return tuple(
        GmailFilterSpec(
            delivered_to=item.rule.delivered_to,
            label=item.rule.label,
            inbox=item.rule.inbox,
            mark_read=item.rule.mark_read,
            conflict_policy=item.rule.conflict_policy,
        )
        for item in sorted(
            plan.filters,
            key=lambda value: (
                value.rule.delivered_to.casefold(),
                value.rule.delivered_to,
            ),
        )
    )


@dataclasses.dataclass(frozen=True)
class GmailConfigurationPlan:
    target_account: str
    routing: RoutingPlan
    gmail: GmailProvisionPlan
    api_required: bool

    @property
    def conflicts(self) -> Tuple[str, ...]:
        values = list(self.routing.conflicts)
        values.extend(
            f"{entry.source.source_account}/{entry.source.name}: {ambiguity}"
            for entry in self.routing.entries
            for ambiguity in entry.ambiguities
        )
        values.extend(self.gmail.conflicts)
        return tuple(dict.fromkeys(values))

    @property
    def ok(self) -> bool:
        return self.routing.ok and self.gmail.ok

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": 1,
            "ok": self.ok,
            "target_account": self.target_account,
            "routing_plan_sha256": self.routing.mapping_digest,
            "gmail_api_required": self.api_required,
            "routing": self.routing.to_dict(),
            "gmail": self.gmail.to_dict(),
            "conflicts": list(self.conflicts),
        }


def discover_gmail_configuration(
    config: ProviderMigrationConfig,
    *,
    max_workers: int,
    stop_event: Optional[object] = None,
    client: Optional[GmailApiClient] = None,
) -> GmailConfigurationPlan:
    """Perform read-only source, target-label, and target-filter discovery."""

    if not config.migration.routing.enabled:
        raise ValueError("Gmail configuration discovery requires migration.routing.enabled=true")
    api_required = gmail_api_required(config)
    if api_required and client is None:
        client = build_gmail_api_client(config, stop_event=stop_event)
    api_labels = client.list_labels() if client is not None else ()
    routing_plan = provider_ops.provider_discover_routing_plan(
        config,
        max_workers=max_workers,
        stop_event=stop_event,
        gmail_api_labels=api_labels if client is not None else None,
    )
    specs = gmail_filter_specs(routing_plan)
    api_filters = client.list_filters() if client is not None and specs else ()
    gmail_plan = plan_gmail_configuration(
        required_custom_labels(routing_plan),
        specs,
        api_labels,
        api_filters,
    )
    return GmailConfigurationPlan(
        target_account=_target_account(config),
        routing=routing_plan,
        gmail=gmail_plan,
        api_required=api_required,
    )


def plan_live_gmail_configuration(
    plan: RoutingPlan,
    client: Optional[GmailApiClient],
) -> GmailProvisionPlan:
    """Reconcile persisted requested names/specs against a fresh live snapshot."""

    labels = required_custom_labels(plan)
    specs = gmail_filter_specs(plan)
    if not labels and not specs:
        return plan_gmail_configuration((), (), (), ())
    if client is None:
        raise RuntimeError(
            "Gmail custom-label routing requires OAuth API authorization; "
            f"required scope(s): {LABEL_SCOPE_HINT}"
        )
    live_labels = client.list_labels()
    live_filters = client.list_filters() if specs else ()
    return plan_gmail_configuration(labels, specs, live_labels, live_filters)


def require_live_gmail_plan_ok(plan: GmailProvisionPlan) -> None:
    if not plan.ok:
        raise GmailReconciliationError(
            "Live Gmail label/filter reconciliation conflicts",
            plan.conflicts,
        )


def _configuration_spec(
    config: ProviderMigrationConfig,
    plan: RoutingPlan,
) -> Dict[str, Any]:
    target = _target_account(config)
    representative = config.accounts[0]
    return {
        "version": 1,
        "target_account": target,
        "target_endpoint_sha256": provider_ops.provider_account_endpoint_state_digest(
            config.target,
            representative,
            role="target",
        ),
        "routing_plan_sha256": plan.mapping_digest,
        "required_custom_labels": list(required_custom_labels(plan)),
        "filters": [spec.to_dict() for spec in gmail_filter_specs(plan)],
    }


def gmail_configuration_plan_path(root: Path) -> Path:
    return root / GMAIL_CONFIGURATION_PLAN_FILENAME


def save_gmail_configuration_plan(
    root: Path,
    config: ProviderMigrationConfig,
    discovered: GmailConfigurationPlan,
) -> RoutingPlan:
    """Persist immutable requested specs and retain the first reviewed live plan.

    The provider saver decides whether an existing source snapshot/mapping is
    the same run.  Its returned artifact is immediately reloaded and is the
    authoritative plan used by every later stage.
    """

    if not discovered.ok:
        raise GmailReconciliationError(
            "Refusing to persist an unresolved Gmail routing plan",
            discovered.conflicts,
        )
    provider_ops.save_provider_routing_plan(root, discovered.routing)
    authoritative = provider_ops.load_provider_routing_plan(root, config)
    spec = _configuration_spec(config, authoritative)
    spec_digest = _sha256(spec)
    path = gmail_configuration_plan_path(root)
    payload = {
        "version": 1,
        "spec_sha256": spec_digest,
        "spec": spec,
        "initial_dry_run": discovered.to_dict(),
    }
    # Publish exactly once.  Concurrent preflights may observe different live
    # create/reuse snapshots for the same immutable request; neither may
    # overwrite the other's reviewed artifact.
    provider_ops._atomic_json_create_once(path, payload)
    try:
        existing = json.loads(provider_ops._read_provider_private_file(path))
    except Exception as exc:
        raise RuntimeError(
            f"invalid persisted {GMAIL_CONFIGURATION_PLAN_FILENAME}: {type(exc).__name__}"
        ) from None
    existing_spec = existing.get("spec") if isinstance(existing, dict) else None
    existing_digest = existing.get("spec_sha256") if isinstance(existing, dict) else None
    if (
        not isinstance(existing, dict)
        or existing.get("version") != 1
        or not isinstance(existing.get("initial_dry_run"), Mapping)
        or not isinstance(existing_spec, Mapping)
        or existing_digest != _sha256(existing_spec)
        or existing_digest != spec_digest
        or existing_spec != spec
    ):
        raise RuntimeError(
            f"existing {GMAIL_CONFIGURATION_PLAN_FILENAME} is bound to a different "
            "target, routing mapping, label set, or filter specification; use a new staging directory"
        )
    return authoritative


def require_gmail_configuration_plan(
    root: Path,
    config: ProviderMigrationConfig,
    plan: RoutingPlan,
) -> Path:
    """Validate the immutable Gmail configuration artifact for a stage run."""

    path = gmail_configuration_plan_path(root)
    try:
        payload = json.loads(provider_ops._read_provider_private_file(path))
    except Exception as exc:
        raise RuntimeError(
            f"routing-enabled Gmail migration requires a valid "
            f"{GMAIL_CONFIGURATION_PLAN_FILENAME}; run provider preflight first: "
            f"{type(exc).__name__}"
        ) from None
    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise RuntimeError(f"invalid persisted {GMAIL_CONFIGURATION_PLAN_FILENAME}")
    spec = _configuration_spec(config, plan)
    expected = _sha256(spec)
    if payload.get("spec_sha256") != expected or payload.get("spec") != spec:
        raise RuntimeError(
            f"persisted {GMAIL_CONFIGURATION_PLAN_FILENAME} does not match the current "
            "target, routing mapping, label set, or filter specification"
        )
    return path


def provision_gmail_labels(
    plan: RoutingPlan,
    client: Optional[GmailApiClient],
) -> LabelReconciliationResult:
    names = required_custom_labels(plan)
    if not names:
        return LabelReconciliationResult(
            dry_run=False,
            labels=(),
            verified=True,
        )
    if client is None:
        raise RuntimeError(
            "Gmail custom-label provisioning requires OAuth API authorization; "
            f"required scope(s): {LABEL_SCOPE_HINT}"
        )
    return reconcile_labels(client, names)


def provision_gmail_filters(
    plan: RoutingPlan,
    client: Optional[GmailApiClient],
) -> FilterReconciliationResult:
    specs = gmail_filter_specs(plan)
    if not specs:
        return FilterReconciliationResult(
            dry_run=False,
            filters=(),
            verified=True,
        )
    if client is None:
        raise RuntimeError(
            "Gmail filter provisioning requires OAuth API authorization; "
            f"required scope(s): {FILTER_SCOPE_HINT} and {LABEL_SCOPE_HINT}"
        )
    return reconcile_filters(client, specs)


@dataclasses.dataclass(frozen=True)
class GmailVerificationResult:
    ok: bool
    labels: Tuple[Dict[str, Any], ...]
    filters: Tuple[Dict[str, Any], ...]
    issues: Tuple[str, ...]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "labels": [dict(item) for item in self.labels],
            "filters": [dict(item) for item in self.filters],
            "issues": list(self.issues),
        }


def verify_gmail_configuration(
    plan: RoutingPlan,
    client: Optional[GmailApiClient],
) -> GmailVerificationResult:
    """Read and verify exact required label/filter state without mutating it."""

    names = required_custom_labels(plan)
    specs = gmail_filter_specs(plan)
    if not names and not specs:
        return GmailVerificationResult(True, (), (), ())
    if client is None:
        return GmailVerificationResult(
            False,
            (),
            (),
            ("Gmail API authorization is unavailable for live verification",),
        )
    live_labels = client.list_labels()
    label_plan = plan_label_reconciliation(names, live_labels)
    label_rows = tuple(entry.to_dict() for entry in label_plan.entries)
    issues = list(label_plan.conflicts)
    issues.extend(
        f"required Gmail user label {entry.name!r} is missing"
        for entry in label_plan.entries
        if entry.action == "create"
    )

    if specs:
        live_filters = client.list_filters()
        filter_plan = plan_filter_reconciliation(specs, live_filters, live_labels)
        filter_rows = tuple(entry.to_dict() for entry in filter_plan.entries)
        issues.extend(filter_plan.conflicts)
        issues.extend(
            f"required Gmail filter {entry.spec.query!r} is not present exactly once with the expected action"
            for entry in filter_plan.entries
            if entry.action != "reuse" and not entry.conflicts
        )
    else:
        filter_rows = ()
    ordered_issues = tuple(dict.fromkeys(issues))
    return GmailVerificationResult(
        not ordered_issues,
        label_rows,
        filter_rows,
        ordered_issues,
    )


__all__ = [
    "GMAIL_CONFIGURATION_PLAN_FILENAME",
    "GmailConfigurationPlan",
    "GmailVerificationResult",
    "build_gmail_api_client",
    "discover_gmail_configuration",
    "gmail_api_client_if_required",
    "gmail_api_required",
    "gmail_configuration_plan_path",
    "gmail_filter_specs",
    "plan_live_gmail_configuration",
    "provision_gmail_filters",
    "provision_gmail_labels",
    "require_gmail_configuration_plan",
    "require_live_gmail_plan_ok",
    "required_custom_labels",
    "resolve_gmail_api_access_token",
    "save_gmail_configuration_plan",
    "verify_gmail_configuration",
]
