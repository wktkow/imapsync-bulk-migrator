from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from components.gmail_api import GmailFilter, GmailLabel, plan_gmail_configuration
from components.gmail_provisioning import (
    GmailConfigurationPlan,
    gmail_filter_specs,
    required_custom_labels,
)
from components.models import ProviderMigrationConfig
from components.provider_workflow import (
    MIGRATION_REPORT_FILENAME,
    run_provider_migration_workflow,
)
from components.routing import (
    CUSTOM_LABEL,
    GMAIL_SYSTEM,
    SourceFolder,
    TargetLabel,
    resolve_routing_plan,
)
from components.workspace_aliases import (
    WORKSPACE_USER_ALIAS_SCOPE,
    WorkspaceAuthorizationIdentity,
    WorkspaceDirectoryApiError,
    WorkspaceDirectoryGroup,
    WorkspaceDirectoryUser,
    WorkspaceDomain,
    WorkspaceUserAlias,
)


def _maila_config(*, workspace_aliases: bool | None = None) -> ProviderMigrationConfig:
    accounts = []
    for name in ("mailA", "mailB", "mailC", "mailD", "mailE"):
        address = f"{name}@example.com"
        accounts.append(
            {
                "source_email": address,
                "target_email": "mailA@example.com",
                "source_auth": {
                    "method": "password",
                    "username": address,
                    "password": f"{name}-source-secret",
                },
            }
        )
    raw = {
        "source": {
            "provider": "imap",
            "host": "imap.old.example.com",
            "auth": {"method": "password"},
        },
        "target": {
            "provider": "gmail",
            "host": "imap.gmail.com",
            "gmail_full_visibility_verified": True,
            "auth": {
                "method": "xoauth2",
                "username": "mailA@example.com",
                "password": "target-imap-token",
            },
            "gmail_api_auth": {
                "method": "xoauth2",
                "username": "mailA@example.com",
                "password": "target-api-token",
            },
        },
        "migration": {
            "target_mode": "merge",
            "account_merge_mode": "many_to_one",
            "routing": {
                "enabled": True,
                "accounts": {
                    "mailA@example.com": {
                        "rules": [
                            {
                                "match": {"role": "inbox"},
                                "destinations": [
                                    {"type": "gmail_system", "name": "inbox"}
                                ],
                            },
                            {
                                "match": {"role": "sent"},
                                "destinations": [
                                    {"type": "gmail_system", "name": "sent"}
                                ],
                            },
                            {
                                "match": {"role": "drafts"},
                                "destinations": [
                                    {"type": "gmail_system", "name": "drafts"}
                                ],
                            },
                            {
                                "match": {"role": "archive"},
                                "destinations": [
                                    {"type": "gmail_system", "name": "all"}
                                ],
                            },
                            {"match": {"role": "trash"}, "exclude": True},
                        ]
                    },
                    "mailB@example.com": {"default_namespace": "MailB"},
                    "mailC@example.com": {"default_namespace": "MailC"},
                    "mailD@example.com": {"default_namespace": "MailD"},
                    "mailE@example.com": {"default_namespace": "MailE"},
                },
                "global_rules": [
                    {
                        "match": {"role": "junk"},
                        "destinations": [
                            {"type": "custom_label", "name": "Imported/Junk"}
                        ],
                    }
                ],
                "filters": [
                    {
                        "delivered_to": f"mail{name}@example.com",
                        "label": f"Mail{name}",
                        "inbox": "keep",
                        "mark_read": False,
                        "conflict_policy": "error",
                    }
                    for name in ("B", "C", "D", "E")
                ],
            },
        },
        "accounts": accounts,
    }
    if workspace_aliases is not None:
        raw["target"]["workspace_aliases"] = (
            {
                "enabled": True,
                "target_user": "mailA@example.com",
                "from_source_accounts": True,
                "aliases": [],
                "exclusions": [],
                "conflict_policy": "create_only",
                "admin_auth": {
                    "method": "xoauth2",
                    "admin_email": "workspace-admin@example.com",
                    "env_var": "WORKSPACE_DIRECTORY_ACCESS_TOKEN",
                },
            }
            if workspace_aliases
            else {"enabled": False}
        )
    return ProviderMigrationConfig.from_dict(raw)


def _source_folders() -> list[SourceFolder]:
    return [
        SourceFolder("mailA@example.com", "INBOX", "/", ("\\Inbox",)),
        SourceFolder("mailA@example.com", "Sent", "/", ("\\Sent",)),
        SourceFolder("mailA@example.com", "Drafts", "/", ("\\Drafts",)),
        SourceFolder("mailA@example.com", "Archive", "/", ("\\Archive",)),
        SourceFolder("mailA@example.com", "Trash", "/", ("\\Trash",)),
        SourceFolder("mailA@example.com", "Junk", "/", ("\\Junk",)),
        SourceFolder("mailB@example.com", "INBOX", "/", ("\\Inbox",)),
        SourceFolder("mailB@example.com", "Junk", "/"),
        SourceFolder("mailC@example.com", "INBOX", "/", ("\\Inbox",)),
        SourceFolder("mailC@example.com", "Spam", "/"),
        SourceFolder("mailD@example.com", "INBOX", ".", ("\\Inbox",)),
        SourceFolder("mailD@example.com", "INBOX.Spam", "."),
        SourceFolder("mailE@example.com", "INBOX", "/", ("\\Inbox",)),
        SourceFolder("mailE@example.com", "Junk E-mail", "/"),
    ]


def _target_labels() -> list[TargetLabel]:
    return [
        TargetLabel("INBOX", GMAIL_SYSTEM, system_role="inbox", target_id="INBOX"),
        TargetLabel(
            "[Gmail]/Sent Mail",
            GMAIL_SYSTEM,
            system_role="sent",
            target_id="SENT",
        ),
        TargetLabel(
            "[Gmail]/Drafts",
            GMAIL_SYSTEM,
            system_role="drafts",
            target_id="DRAFT",
        ),
        TargetLabel(
            "[Gmail]/All Mail",
            GMAIL_SYSTEM,
            system_role="all",
            target_id="ALL",
        ),
        TargetLabel("MailB", CUSTOM_LABEL, target_id="Label_MailB"),
        TargetLabel("Unrelated", CUSTOM_LABEL, target_id="Label_Unrelated"),
    ]


def _resolved_acceptance_plan(config: ProviderMigrationConfig):
    return resolve_routing_plan(
        config.migration.routing,
        _source_folders(),
        _target_labels(),
    )


def test_maila_to_maile_plan_reuses_creates_and_suppresses_namespaced_junk() -> None:
    config = _maila_config()
    plan = _resolved_acceptance_plan(config)

    assert plan.ok
    assert plan.labels_reused == ("MailB",)
    assert plan.labels_to_create == (
        "Imported/Junk",
        "MailC",
        "MailD",
        "MailE",
    )

    entries = {
        (entry.source.source_account, entry.source.name): entry
        for entry in plan.entries
    }
    for letter in "BCDE":
        entry = entries[(f"mail{letter}@example.com", "INBOX")]
        assert [destination.name for destination in entry.destinations] == [
            f"Mail{letter}"
        ]
        assert not entry.appears_in_inbox

    primary_roles = {
        entries[("mailA@example.com", folder)].detected_role: [
            destination.name
            for destination in entries[("mailA@example.com", folder)].destinations
        ]
        for folder in ("INBOX", "Sent", "Drafts", "Archive")
    }
    assert primary_roles == {
        "inbox": ["inbox"],
        "sent": ["sent"],
        "drafts": ["drafts"],
        "archive": ["all"],
    }

    junk_entries = [entry for entry in plan.entries if entry.detected_role == "junk"]
    assert len(junk_entries) == 5
    assert {
        (entry.source.source_account, entry.source.name) for entry in junk_entries
    } == {
        ("mailA@example.com", "Junk"),
        ("mailB@example.com", "Junk"),
        ("mailC@example.com", "Spam"),
        ("mailD@example.com", "INBOX.Spam"),
        ("mailE@example.com", "Junk E-mail"),
    }
    for entry in junk_entries:
        assert [destination.name for destination in entry.destinations] == [
            "Imported/Junk"
        ]
        assert entry.destinations[0].merged
        assert len(entry.destinations[0].contributors) == 5

    requested_custom_labels = {
        destination.name
        for entry in plan.entries
        for destination in entry.destinations
        if destination.kind == CUSTOM_LABEL
    }
    assert not (
        requested_custom_labels
        & {"MailB/Junk", "MailC/Spam", "MailD/Junk", "MailE/Junk"}
    )

    assert [item.rule.query for item in plan.filters] == [
        "deliveredto:mailB@example.com",
        "deliveredto:mailC@example.com",
        "deliveredto:mailD@example.com",
        "deliveredto:mailE@example.com",
    ]
    assert all(item.rule.inbox == "keep" for item in plan.filters)


class _StatefulGmail:
    def __init__(
        self,
        *,
        fail_filter_attempt: int | None = None,
        events: list[str] | None = None,
    ) -> None:
        self.labels = [
            GmailLabel("Label_MailB", "MailB", "user"),
            GmailLabel("Label_Unrelated", "Unrelated", "user"),
        ]
        self.filters = [
            GmailFilter(
                "filter-unrelated",
                {"from": "friend@example.net"},
                {"addLabelIds": ["Label_Unrelated"]},
            )
        ]
        self.label_create_calls: list[str] = []
        self.filter_create_attempts = 0
        self.filter_create_calls: list[str] = []
        self.filter_delete_calls: list[str] = []
        self.fail_filter_attempt = fail_filter_attempt
        self.failed_once = False
        self.events = events if events is not None else []

    def list_labels(self):
        return tuple(self.labels)

    def create_label(self, name: str):
        self.events.append(f"label:{name}")
        self.label_create_calls.append(name)
        label = GmailLabel(f"Label_{len(self.labels) + 1}", name, "user")
        self.labels.append(label)
        return label

    def list_filters(self):
        return tuple(self.filters)

    def create_filter(self, criteria, action):
        self.filter_create_attempts += 1
        if (
            self.fail_filter_attempt == self.filter_create_attempts
            and not self.failed_once
        ):
            self.failed_once = True
            raise RuntimeError(
                "filter permission denied; required scope: gmail.settings.basic"
            )
        query = str(criteria.get("query") or "")
        self.events.append(f"filter:{query}")
        self.filter_create_calls.append(query)
        item = GmailFilter(
            f"filter-{len(self.filters) + 1}",
            dict(criteria),
            dict(action),
        )
        self.filters.append(item)
        return item

    def delete_filter(self, filter_id: str) -> None:
        self.filter_delete_calls.append(filter_id)
        self.filters = [item for item in self.filters if item.id != filter_id]


def _install_acceptance_workflow_fakes(
    monkeypatch: pytest.MonkeyPatch,
    config: ProviderMigrationConfig,
    plan,
    gmail: _StatefulGmail,
) -> dict[str, Any]:
    from components import provider_workflow as workflow

    discovered = GmailConfigurationPlan(
        target_account="mailA@example.com",
        routing=plan,
        gmail=plan_gmail_configuration(
            required_custom_labels(plan),
            gmail_filter_specs(plan),
            gmail.list_labels(),
            gmail.list_filters(),
        ),
        api_required=True,
    )
    state: dict[str, Any] = {
        "export_runs": 0,
        "import_runs": 0,
        "append_count": 0,
        "messages": {"unrelated": {"Unrelated"}},
    }

    def export(*_args, **_kwargs) -> None:
        gmail.events.append("messages:export")
        state["export_runs"] += 1

    def import_messages(*_args, **_kwargs) -> None:
        gmail.events.append("messages:import")
        state["import_runs"] += 1
        desired = {
            "primary-inbox": {"INBOX"},
            "shared-mailb-mailc": {"MailB", "MailC"},
            "maild-inbox": {"MailD"},
            "maile-inbox": {"MailE"},
            "maila-junk": {"Imported/Junk"},
            "mailb-junk": {"Imported/Junk"},
            "mailc-junk": {"Imported/Junk"},
            "maild-junk": {"Imported/Junk"},
            "maile-junk": {"Imported/Junk"},
        }
        for identity, labels in desired.items():
            if identity not in state["messages"]:
                state["append_count"] += 1
                state["messages"][identity] = set()
            state["messages"][identity].update(labels)

    def provider_report(*_args, routing_plan=None, **_kwargs):
        assert routing_plan is not None
        accounts = []
        for account in config.accounts:
            folders = []
            for entry in routing_plan.entries:
                if entry.source.source_account != account.source_email:
                    continue
                folders.append(
                    {
                        "source_folder": entry.source.name,
                        "detected_role": entry.detected_role,
                        "excluded": entry.excluded,
                        "destinations": [
                            destination.to_dict() for destination in entry.destinations
                        ],
                        "shared_destinations": [
                            destination.name
                            for destination in entry.destinations
                            if destination.merged
                        ],
                        "appears_in_inbox": entry.appears_in_inbox,
                        "exported_messages": 1,
                        "committed_messages": 0 if entry.excluded else 1,
                    }
                )
            accounts.append(
                {
                    "source_account": account.source_email,
                    "target_account": account.target_email,
                    "ok": True,
                    "folders": folders,
                }
            )
        return {
            "version": 1,
            "ok": True,
            "routing_plan_sha256": routing_plan.mapping_digest,
            "labels": {
                "planned_create": list(routing_plan.labels_to_create),
                "planned_reuse": list(routing_plan.labels_reused),
            },
            "totals": {
                "accounts": 5,
                "appended_messages": state["append_count"],
                "messages_with_labels_applied_to_existing_matches": 1,
            },
            "accounts": accounts,
            "duplicate_label_union": {
                "canonical_id": "shared-mailb-mailc",
                "labels": sorted(state["messages"].get("shared-mailb-mailc", set())),
            },
        }

    monkeypatch.setattr(
        workflow.provider_ops,
        "provider_preflight",
        lambda *_args, **_kwargs: (True, []),
    )
    monkeypatch.setattr(
        workflow,
        "discover_gmail_configuration",
        lambda *_args, **_kwargs: discovered,
    )
    monkeypatch.setattr(workflow.provider_ops, "provider_export_all", export)
    monkeypatch.setattr(
        workflow.provider_ops,
        "provider_audit_all",
        lambda *_args, **_kwargs: (True, []),
    )
    monkeypatch.setattr(
        workflow.provider_ops,
        "provider_import_all",
        import_messages,
    )
    monkeypatch.setattr(
        workflow.provider_ops,
        "provider_validate_all",
        lambda *_args, **_kwargs: (True, []),
    )
    monkeypatch.setattr(
        workflow.provider_ops,
        "build_provider_routing_report",
        provider_report,
    )
    return state


def test_maila_workflow_resumes_filter_failure_and_completed_rerun_is_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # macOS exposes /var as a symlink to /private/var; the production artifact
    # guards correctly reject symlinked path components, so exercise them with
    # the fixture's canonical path.
    tmp_path = tmp_path.resolve()
    config = _maila_config()
    plan = _resolved_acceptance_plan(config)
    gmail = _StatefulGmail(fail_filter_attempt=2)
    state = _install_acceptance_workflow_fakes(
        monkeypatch,
        config,
        plan,
        gmail,
    )

    first = run_provider_migration_workflow(
        config,
        tmp_path,
        max_workers=2,
        gmail_client=gmail,  # type: ignore[arg-type]
    )
    assert not first["ok"]
    assert first["stage_order"][-1] == "provision_filters"
    assert any("Export has not started" in action for action in first["actions_required"])
    assert "gmail.settings.basic" in " ".join(first["issues"])

    append_count_after_failure = state["append_count"]
    assert append_count_after_failure == 0
    assert state["export_runs"] == 0
    assert state["import_runs"] == 0
    label_creates_after_failure = list(gmail.label_create_calls)
    assert set(label_creates_after_failure) == {
        "Imported/Junk",
        "MailC",
        "MailD",
        "MailE",
    }
    assert state["messages"]["unrelated"] == {"Unrelated"}

    second = run_provider_migration_workflow(
        config,
        tmp_path,
        max_workers=2,
        gmail_client=gmail,  # type: ignore[arg-type]
    )
    assert second["ok"]
    assert second["status"] == "completed"
    assert state["append_count"] > append_count_after_failure
    assert gmail.label_create_calls == label_creates_after_failure
    assert {item["query"] for item in second["gmail"]["filters"]["filters"]} == {
        "deliveredto:mailb@example.com",
        "deliveredto:mailc@example.com",
        "deliveredto:maild@example.com",
        "deliveredto:maile@example.com",
    }

    creates_before_completed_rerun = (
        list(gmail.label_create_calls),
        list(gmail.filter_create_calls),
        state["append_count"],
    )
    third = run_provider_migration_workflow(
        config,
        tmp_path,
        max_workers=2,
        gmail_client=gmail,  # type: ignore[arg-type]
    )
    assert third["ok"]
    assert all(
        item["action"] == "reused" for item in third["gmail"]["labels"]["labels"]
    )
    assert all(
        item["action"] == "reused" for item in third["gmail"]["filters"]["filters"]
    )
    assert (
        gmail.label_create_calls,
        gmail.filter_create_calls,
        state["append_count"],
    ) == creates_before_completed_rerun
    assert gmail.filter_delete_calls == []
    assert [item.name for item in gmail.labels].count("MailB") == 1
    assert len({item.id for item in gmail.filters}) == len(gmail.filters)
    assert any(item.id == "filter-unrelated" for item in gmail.filters)
    assert state["messages"]["unrelated"] == {"Unrelated"}

    provider_report = third["provider"]
    assert provider_report["labels"] == {
        "planned_create": ["Imported/Junk", "MailC", "MailD", "MailE"],
        "planned_reuse": ["MailB"],
    }
    assert provider_report["duplicate_label_union"] == {
        "canonical_id": "shared-mailb-mailc",
        "labels": ["MailB", "MailC"],
    }
    junk_folders = [
        folder
        for account in provider_report["accounts"]
        for folder in account["folders"]
        if folder["detected_role"] == "junk"
    ]
    assert len(junk_folders) == 5
    assert {
        destination["name"]
        for folder in junk_folders
        for destination in folder["destinations"]
    } == {"Imported/Junk"}

    persisted = json.loads(
        (tmp_path / MIGRATION_REPORT_FILENAME).read_text(encoding="utf-8")
    )
    assert persisted["ok"]
    assert persisted["status"] == "completed"
    assert persisted["provider"] == provider_report


class _StatefulWorkspace:
    def __init__(
        self,
        *,
        collision_kind: str | None = None,
        fail_alias_attempt: int | None = None,
        events: list[str] | None = None,
    ) -> None:
        self.authorization_identity = WorkspaceAuthorizationIdentity(
            "xoauth2",
            "workspace-admin@example.com",
        )
        self.target_user = "maila@example.com"
        self.customer_id = "customer-acceptance"
        self.target_aliases = {
            "mailb@example.com",
            "unrelated@example.com",
        }
        self.collision_kind = collision_kind
        self.fail_alias_attempt = fail_alias_attempt
        self.failed_once = False
        self.events = events if events is not None else []
        self.read_calls: list[tuple[str, str]] = []
        self.insert_attempts: list[str] = []
        self.insert_successes: list[str] = []

    def _target(self) -> WorkspaceDirectoryUser:
        return WorkspaceDirectoryUser(
            "user-maila",
            self.target_user,
            self.customer_id,
            aliases=tuple(sorted(self.target_aliases)),
        )

    def get_user(self, email: str) -> WorkspaceDirectoryUser | None:
        email = email.casefold()
        self.read_calls.append(("user", email))
        if email == self.target_user or email in self.target_aliases:
            return self._target()
        if email != "mailc@example.com":
            return None
        if self.collision_kind == "user":
            return WorkspaceDirectoryUser(
                "user-mailc",
                "mailc@example.com",
                self.customer_id,
            )
        if self.collision_kind == "other_owner":
            return WorkspaceDirectoryUser(
                "user-other",
                "other@example.com",
                self.customer_id,
                aliases=("mailc@example.com",),
            )
        return None

    def list_user_aliases(self, target_user: str) -> tuple[WorkspaceUserAlias, ...]:
        target_user = target_user.casefold()
        self.read_calls.append(("aliases", target_user))
        assert target_user == "user-maila"
        return tuple(
            WorkspaceUserAlias(alias, self.target_user, "user-maila")
            for alias in sorted(self.target_aliases)
        )

    def get_group(self, email: str) -> WorkspaceDirectoryGroup | None:
        email = email.casefold()
        self.read_calls.append(("group", email))
        if self.collision_kind == "group" and email == "mailc@example.com":
            return WorkspaceDirectoryGroup(
                "group-mailc",
                "mailc@example.com",
            )
        return None

    def get_domain(self, customer: str, domain: str) -> WorkspaceDomain | None:
        self.read_calls.append(("domain", domain.casefold()))
        assert customer == self.customer_id
        if domain.casefold() == "example.com":
            return WorkspaceDomain("example.com", "primary", True)
        return None

    def get_domain_alias(self, customer: str, domain: str) -> WorkspaceDomain | None:
        self.read_calls.append(("domain_alias", domain.casefold()))
        assert customer == self.customer_id
        return None

    def insert_user_alias(
        self,
        target_user: str,
        alias: str,
        *,
        expected_user_id: str | None = None,
        expected_primary_email: str | None = None,
    ) -> WorkspaceUserAlias:
        target_user = target_user.casefold()
        alias = alias.casefold()
        assert target_user == "user-maila"
        assert expected_user_id == "user-maila"
        assert expected_primary_email == self.target_user
        self.insert_attempts.append(alias)
        self.events.append(f"alias-attempt:{alias}")
        if (
            self.fail_alias_attempt == len(self.insert_attempts)
            and not self.failed_once
        ):
            self.failed_once = True
            raise WorkspaceDirectoryApiError(
                "Workspace Directory create user alias failed: HTTP 403 "
                f"(permission denied); required scope(s): {WORKSPACE_USER_ALIAS_SCOPE}",
                operation="create user alias",
                status_code=403,
                required_scopes=(WORKSPACE_USER_ALIAS_SCOPE,),
            )
        self.target_aliases.add(alias)
        self.insert_successes.append(alias)
        self.events.append(f"alias-created:{alias}")
        return WorkspaceUserAlias(alias, self.target_user, "user-maila")


def _workspace_plan_statuses(report: dict[str, Any]) -> dict[str, str]:
    return {
        entry["alias"]: entry["status"]
        for entry in report["workspace_aliases"]["planning"]["entries"]
    }


def test_workspace_alias_maila_preflight_failure_resume_and_rerun(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tmp_path = tmp_path.resolve()
    events: list[str] = []
    config = _maila_config(workspace_aliases=True)
    plan = _resolved_acceptance_plan(config)
    gmail = _StatefulGmail(events=events)
    workspace = _StatefulWorkspace(fail_alias_attempt=2, events=events)
    state = _install_acceptance_workflow_fakes(
        monkeypatch,
        config,
        plan,
        gmail,
    )

    preflight = run_provider_migration_workflow(
        config,
        tmp_path,
        max_workers=2,
        dry_run=True,
        gmail_client=gmail,  # type: ignore[arg-type]
        workspace_client=workspace,  # type: ignore[arg-type]
    )
    assert preflight["ok"]
    assert preflight["status"] == "planned"
    assert preflight["stage_order"] == [
        "discover_plan",
        "discover_aliases",
        "persist_plan",
        "persist_alias_plan",
        "final_report",
    ]
    assert _workspace_plan_statuses(preflight) == {
        "mailb@example.com": "reuse",
        "mailc@example.com": "create",
        "maild@example.com": "create",
        "maile@example.com": "create",
    }
    assert preflight["workspace_aliases"]["conflicted"] == []
    assert Path(preflight["artifacts"]["workspace_alias_plan"]).exists()
    assert gmail.label_create_calls == []
    assert gmail.filter_create_calls == []
    assert workspace.insert_attempts == []
    assert state["append_count"] == 0
    assert state["export_runs"] == 0
    assert state["import_runs"] == 0

    first_event = len(events)
    first = run_provider_migration_workflow(
        config,
        tmp_path,
        max_workers=2,
        gmail_client=gmail,  # type: ignore[arg-type]
        workspace_client=workspace,  # type: ignore[arg-type]
    )
    assert not first["ok"]
    assert first["stage_order"][-1] == "provision_aliases"
    assert "mailc@example.com" in first["workspace_aliases"]["created"]
    assert set(first["workspace_aliases"]["conflicted"]) == {
        "maild@example.com",
        "maile@example.com",
    }
    assert any(
        "Historical imports and journals are preserved" in action
        and "aliases already created are also preserved" in action
        for action in first["actions_required"]
    )
    assert WORKSPACE_USER_ALIAS_SCOPE in " ".join(first["issues"])

    first_run_events = events[first_event:]
    filter_positions = [
        index
        for index, event in enumerate(first_run_events)
        if event.startswith("filter:")
    ]
    alias_positions = [
        index
        for index, event in enumerate(first_run_events)
        if event.startswith("alias-attempt:")
    ]
    assert len(filter_positions) == 4
    assert alias_positions
    assert max(filter_positions) < min(alias_positions)

    appended_after_failure = state["append_count"]
    label_creates_after_failure = list(gmail.label_create_calls)
    filter_creates_after_failure = list(gmail.filter_create_calls)
    assert appended_after_failure > 0
    assert workspace.insert_successes == ["mailc@example.com"]
    assert workspace.target_aliases == {
        "mailb@example.com",
        "mailc@example.com",
        "unrelated@example.com",
    }

    second = run_provider_migration_workflow(
        config,
        tmp_path,
        max_workers=2,
        gmail_client=gmail,  # type: ignore[arg-type]
        workspace_client=workspace,  # type: ignore[arg-type]
    )
    assert second["ok"]
    assert second["stage_order"] == [
        "discover_plan",
        "discover_aliases",
        "persist_plan",
        "persist_alias_plan",
        "provision_labels",
        "provision_filters",
        "export",
        "audit",
        "import",
        "reconcile_gmail_before_aliases",
        "provision_aliases",
        "validate_verify",
        "verify_aliases",
        "final_report",
    ]
    assert second["workspace_aliases"][
        "active_alias_filters_ready_before_export"
    ] is True
    assert state["append_count"] == appended_after_failure
    assert state["import_runs"] == 2
    assert gmail.label_create_calls == label_creates_after_failure
    assert gmail.filter_create_calls == filter_creates_after_failure
    assert workspace.insert_successes == [
        "mailc@example.com",
        "maild@example.com",
        "maile@example.com",
    ]
    assert workspace.target_aliases == {
        "mailb@example.com",
        "mailc@example.com",
        "maild@example.com",
        "maile@example.com",
        "unrelated@example.com",
    }
    assert second["workspace_aliases"]["created"] == [
        "maild@example.com",
        "maile@example.com",
    ]
    assert set(second["workspace_aliases"]["reused"]) == {
        "mailb@example.com",
        "mailc@example.com",
    }
    assert second["workspace_aliases"]["verification"]["ok"]

    before_completed_rerun = (
        state["append_count"],
        list(gmail.label_create_calls),
        list(gmail.filter_create_calls),
        list(workspace.insert_attempts),
        list(workspace.insert_successes),
    )
    third = run_provider_migration_workflow(
        config,
        tmp_path,
        max_workers=2,
        gmail_client=gmail,  # type: ignore[arg-type]
        workspace_client=workspace,  # type: ignore[arg-type]
    )
    assert third["ok"]
    assert (
        state["append_count"],
        gmail.label_create_calls,
        gmail.filter_create_calls,
        workspace.insert_attempts,
        workspace.insert_successes,
    ) == before_completed_rerun
    assert third["workspace_aliases"]["created"] == []
    assert set(third["workspace_aliases"]["reused"]) == {
        "mailb@example.com",
        "mailc@example.com",
        "maild@example.com",
        "maile@example.com",
    }
    assert state["messages"]["shared-mailb-mailc"] == {"MailB", "MailC"}
    assert state["messages"]["unrelated"] == {"Unrelated"}
    assert "unrelated@example.com" in workspace.target_aliases

    persisted = json.loads(
        (tmp_path / MIGRATION_REPORT_FILENAME).read_text(encoding="utf-8")
    )
    assert persisted["ok"]
    assert persisted["workspace_aliases"] == third["workspace_aliases"]


@pytest.mark.parametrize(
    "mutation",
    ["delete_filter", "delete_label_and_filter"],
)
def test_workspace_alias_jit_gate_repairs_safe_gmail_deletion_before_insert(
    mutation: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from components import provider_workflow as workflow

    tmp_path = tmp_path.resolve()
    events: list[str] = []
    config = _maila_config(workspace_aliases=True)
    plan = _resolved_acceptance_plan(config)
    gmail = _StatefulGmail(events=events)
    workspace = _StatefulWorkspace(events=events)
    state = _install_acceptance_workflow_fakes(
        monkeypatch,
        config,
        plan,
        gmail,
    )
    import_messages = workflow.provider_ops.provider_import_all

    def import_then_delete_gmail_state(*args, **kwargs) -> None:
        import_messages(*args, **kwargs)
        gmail.filters = [
            item
            for item in gmail.filters
            if str(item.criteria.get("query") or "").casefold()
            != "deliveredto:mailc@example.com"
        ]
        if mutation == "delete_label_and_filter":
            gmail.labels = [item for item in gmail.labels if item.name != "MailC"]
        events.append(f"mutation:{mutation}")

    monkeypatch.setattr(
        workflow.provider_ops,
        "provider_import_all",
        import_then_delete_gmail_state,
    )

    report = run_provider_migration_workflow(
        config,
        tmp_path,
        max_workers=2,
        gmail_client=gmail,  # type: ignore[arg-type]
        workspace_client=workspace,  # type: ignore[arg-type]
    )

    assert report["ok"]
    gate = report["gmail"]["pre_alias_gate"]
    assert gate["status"] == "verified"
    assert gate["ok"] is True
    assert gate["verification"]["ok"] is True
    assert any(
        row["delivered_to"].casefold() == "mailc@example.com"
        and row["action"] == "created"
        for row in gate["filters"]["filters"]
    )
    if mutation == "delete_label_and_filter":
        assert any(
            row["name"] == "MailC" and row["action"] == "created"
            for row in gate["labels"]["labels"]
        )
    assert state["import_runs"] == 1
    assert workspace.insert_attempts == [
        "mailc@example.com",
        "maild@example.com",
        "maile@example.com",
    ]
    mutation_position = events.index(f"mutation:{mutation}")
    repaired_filter_position = max(
        index
        for index, event in enumerate(events)
        if event == "filter:deliveredto:mailc@example.com"
    )
    first_alias_position = min(
        index for index, event in enumerate(events) if event.startswith("alias-attempt:")
    )
    assert mutation_position < repaired_filter_position < first_alias_position


def test_workspace_alias_jit_gate_rejects_changed_filter_then_reruns_safely(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from components import provider_workflow as workflow

    tmp_path = tmp_path.resolve()
    events: list[str] = []
    config = _maila_config(workspace_aliases=True)
    plan = _resolved_acceptance_plan(config)
    gmail = _StatefulGmail(events=events)
    workspace = _StatefulWorkspace(events=events)
    state = _install_acceptance_workflow_fakes(
        monkeypatch,
        config,
        plan,
        gmail,
    )
    import_messages = workflow.provider_ops.provider_import_all
    mutate_filter = True

    def import_then_change_filter_action(*args, **kwargs) -> None:
        import_messages(*args, **kwargs)
        if not mutate_filter:
            return
        for index, item in enumerate(gmail.filters):
            if (
                str(item.criteria.get("query") or "").casefold()
                == "deliveredto:mailc@example.com"
            ):
                gmail.filters[index] = GmailFilter(
                    item.id,
                    dict(item.criteria),
                    {
                        "addLabelIds": list(item.action.get("addLabelIds") or ()),
                        "removeLabelIds": ["INBOX"],
                    },
                )
                break
        else:  # pragma: no cover - assertion aid
            raise AssertionError("pre-export MailC filter was not installed")
        events.append("mutation:change-filter-action")

    monkeypatch.setattr(
        workflow.provider_ops,
        "provider_import_all",
        import_then_change_filter_action,
    )

    report = run_provider_migration_workflow(
        config,
        tmp_path,
        max_workers=2,
        gmail_client=gmail,  # type: ignore[arg-type]
        workspace_client=workspace,  # type: ignore[arg-type]
    )

    assert not report["ok"]
    assert report["stage_order"][-1] == "reconcile_gmail_before_aliases"
    assert report["gmail"]["pre_alias_gate"]["failed_phase"] == "live_plan"
    assert "same-condition" in " ".join(report["issues"])
    assert state["import_runs"] == 1
    assert workspace.insert_attempts == []
    assert workspace.insert_successes == []
    assert not any(event.startswith("alias-attempt:") for event in events)

    gmail.filters = [
        item
        for item in gmail.filters
        if str(item.criteria.get("query") or "").casefold()
        != "deliveredto:mailc@example.com"
    ]
    mutate_filter = False
    second = run_provider_migration_workflow(
        config,
        tmp_path,
        max_workers=2,
        gmail_client=gmail,  # type: ignore[arg-type]
        workspace_client=workspace,  # type: ignore[arg-type]
    )

    assert second["ok"]
    assert state["import_runs"] == 2
    assert workspace.insert_attempts == [
        "mailc@example.com",
        "maild@example.com",
        "maile@example.com",
    ]
    assert second["gmail"]["pre_alias_gate"]["ok"] is True


@pytest.mark.parametrize("collision_kind", ["user", "group", "other_owner"])
def test_workspace_alias_preflight_conflicts_block_every_remote_mutation(
    collision_kind: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tmp_path = tmp_path.resolve()
    config = _maila_config(workspace_aliases=True)
    plan = _resolved_acceptance_plan(config)
    gmail = _StatefulGmail()
    workspace = _StatefulWorkspace(collision_kind=collision_kind)
    state = _install_acceptance_workflow_fakes(
        monkeypatch,
        config,
        plan,
        gmail,
    )

    report = run_provider_migration_workflow(
        config,
        tmp_path,
        max_workers=2,
        dry_run=True,
        gmail_client=gmail,  # type: ignore[arg-type]
        workspace_client=workspace,  # type: ignore[arg-type]
    )

    assert not report["ok"]
    assert report["stage_order"] == ["discover_plan", "discover_aliases"]
    assert _workspace_plan_statuses(report)["mailc@example.com"] == "conflict"
    assert report["workspace_aliases"]["conflicted"] == ["mailc@example.com"]
    assert any(collision_kind.split("_")[0] in issue for issue in report["issues"])
    assert gmail.label_create_calls == []
    assert gmail.filter_create_calls == []
    assert workspace.insert_attempts == []
    assert workspace.insert_successes == []
    assert workspace.target_aliases == {
        "mailb@example.com",
        "unrelated@example.com",
    }
    assert state["append_count"] == 0
    assert state["export_runs"] == 0
    assert state["import_runs"] == 0
    assert (
        "workspace_alias_plan" not in report["artifacts"]
        or not Path(report["artifacts"]["workspace_alias_plan"]).exists()
    )


def test_workspace_alias_explicit_off_preserves_routing_only_workflow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tmp_path = tmp_path.resolve()
    config = _maila_config(workspace_aliases=False)
    plan = _resolved_acceptance_plan(config)
    gmail = _StatefulGmail()
    workspace = _StatefulWorkspace()
    state = _install_acceptance_workflow_fakes(
        monkeypatch,
        config,
        plan,
        gmail,
    )

    report = run_provider_migration_workflow(
        config,
        tmp_path,
        max_workers=2,
        gmail_client=gmail,  # type: ignore[arg-type]
        workspace_client=workspace,  # type: ignore[arg-type]
    )

    assert report["ok"]
    assert report["stage_order"] == [
        "discover_plan",
        "persist_plan",
        "provision_labels",
        "provision_filters",
        "export",
        "audit",
        "import",
        "validate_verify",
        "final_report",
    ]
    assert report["workspace_aliases"]["enabled"] is False
    assert "workspace_alias_plan" not in report["artifacts"]
    assert not (tmp_path / "workspace-alias-plan.json").exists()
    assert workspace.read_calls == []
    assert workspace.insert_attempts == []
    filter_positions = [
        index for index, event in enumerate(gmail.events) if event.startswith("filter:")
    ]
    assert filter_positions
    assert max(filter_positions) < gmail.events.index("messages:export")
    assert gmail.events.index("messages:export") < gmail.events.index("messages:import")
    assert state["append_count"] > 0
