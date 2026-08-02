from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import stat
import threading
from unittest import mock

import pytest

from components.gmail_api import (
    GmailApiCancelledError,
    GmailFilter,
    GmailLabel,
    plan_gmail_configuration,
)
from components.gmail_provisioning import (
    GMAIL_CONFIGURATION_PLAN_FILENAME,
    GmailConfigurationPlan,
    build_gmail_api_client,
    discover_gmail_configuration,
    gmail_api_required,
    gmail_filter_specs,
    required_custom_labels,
    save_gmail_configuration_plan,
    verify_gmail_configuration,
)
from components.models import (
    AuthConfig,
    MigrationAccount,
    MigrationSettings,
    ProviderEndpoint,
    ProviderMigrationConfig,
)
from components.routing import (
    CUSTOM_LABEL,
    GMAIL_SYSTEM,
    RoutingConfig,
    SourceFolder,
    TargetLabel,
    resolve_routing_plan,
)


def _config(*, api_auth: AuthConfig | None, filters: bool = True) -> ProviderMigrationConfig:
    routing = RoutingConfig.from_dict(
        {
            "enabled": True,
            "accounts": {
                "source@example.com": {
                    "default_label": "MailB",
                }
            },
            "filters": (
                [
                    {
                        "delivered_to": "alias@example.com",
                        "label": "MailB",
                        "inbox": "archive",
                        "mark_read": True,
                    }
                ]
                if filters
                else []
            ),
        }
    )
    return ProviderMigrationConfig(
        source=ProviderEndpoint(
            provider="imap",
            host="source.example.com",
            auth=AuthConfig(method="password", username="source@example.com", password="pw"),
        ),
        target=ProviderEndpoint(
            provider="gmail",
            host="imap.gmail.com",
            auth=AuthConfig(
                method="app_password",
                username="target@example.com",
                password="imap-secret",
            ),
            gmail_api_auth=api_auth,
        ),
        accounts=[
            MigrationAccount(
                source_email="source@example.com",
                target_email="target@example.com",
            )
        ],
        migration=MigrationSettings(
            target_mode="merge",
            account_merge_mode="many_to_one",
            routing=routing,
        ),
    )


def _routing_plan(config: ProviderMigrationConfig, *, existing: bool = False):
    labels = [
        TargetLabel(
            name="INBOX",
            kind=GMAIL_SYSTEM,
            system_role="inbox",
            target_id="INBOX",
        )
    ]
    if existing:
        labels.append(TargetLabel(name="MailB", kind=CUSTOM_LABEL, target_id="Label_B"))
    return resolve_routing_plan(
        config.migration.routing,
        [SourceFolder("source@example.com", "INBOX", "/", ("\\Inbox",))],
        labels,
    )


def test_custom_label_routing_without_filters_still_requires_api_auth() -> None:
    config = _config(api_auth=None, filters=False)
    assert gmail_api_required(config)
    with pytest.raises(RuntimeError) as exc_info:
        build_gmail_api_client(config)
    message = str(exc_info.value)
    assert "gmail.labels" in message
    assert "app password" in message.lower()
    assert "imap-secret" not in message


def test_api_token_resolves_from_environment_without_appearing_in_client_repr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "environment-secret-token"
    monkeypatch.setenv("MIGRATION_GMAIL_TOKEN", token)
    config = _config(
        api_auth=AuthConfig(
            method="xoauth2",
            username="target@example.com",
            env_var="MIGRATION_GMAIL_TOKEN",
        )
    )
    config.limits.retry_max_attempts = 9
    session = mock.Mock()
    client = build_gmail_api_client(config, session=session)

    assert client.user_id == "target@example.com"
    assert token not in repr(client)
    assert client.session is session
    assert client.retry_max_attempts == 9


def test_gmail_client_factory_threads_stop_event_to_low_level_requests() -> None:
    config = _config(api_auth=AuthConfig(method="xoauth2", password="token"))
    session = mock.Mock()
    stop_event = mock.Mock()
    stop_event.is_set.return_value = True
    client = build_gmail_api_client(
        config,
        session=session,
        stop_event=stop_event,
    )

    with pytest.raises(GmailApiCancelledError, match="list labels cancelled"):
        client.list_labels()
    session.request.assert_not_called()


def test_system_only_routing_does_not_require_gmail_api() -> None:
    routing = RoutingConfig.from_dict(
        {
            "enabled": True,
            "global_rules": [
                {
                    "match": {"role": "inbox"},
                    "destinations": [{"type": "gmail_system", "name": "inbox"}],
                }
            ],
        }
    )
    config = _config(api_auth=None)
    config.migration.routing = routing
    assert not gmail_api_required(config)


def test_discovery_combines_provider_routing_with_live_labels_and_filters() -> None:
    config = _config(api_auth=AuthConfig(method="xoauth2", password="token"))
    discovered_plan = _routing_plan(config, existing=True)

    class Client:
        def list_labels(self):
            return (
                GmailLabel("INBOX", "INBOX", "system"),
                GmailLabel("Label_B", "MailB", "user"),
            )

        def list_filters(self):
            return (
                GmailFilter(
                    "filter-1",
                    {"query": "deliveredto:alias@example.com"},
                    {
                        "addLabelIds": ["Label_B"],
                        "removeLabelIds": ["INBOX", "UNREAD"],
                    },
                ),
            )

    with mock.patch(
        "components.gmail_provisioning.provider_ops.provider_discover_routing_plan",
        return_value=discovered_plan,
    ) as provider_discovery:
        result = discover_gmail_configuration(
            config,
            max_workers=3,
            client=Client(),  # type: ignore[arg-type]
        )

    assert result.ok
    assert result.target_account == "target@example.com"
    assert result.gmail.labels.entries[0].action == "reuse"
    assert result.gmail.filters.entries[0].action == "reuse"
    api_labels = provider_discovery.call_args.kwargs["gmail_api_labels"]
    assert [item.name for item in api_labels] == ["INBOX", "MailB"]


def test_discovery_forwards_stop_event_when_building_its_gmail_client() -> None:
    config = _config(
        api_auth=AuthConfig(method="xoauth2", password="token"),
        filters=False,
    )
    discovered_plan = _routing_plan(config, existing=True)
    stop_event = object()

    class Client:
        def list_labels(self):
            return (
                GmailLabel("INBOX", "INBOX", "system"),
                GmailLabel("Label_B", "MailB", "user"),
            )

    with mock.patch(
        "components.gmail_provisioning.build_gmail_api_client",
        return_value=Client(),
    ) as factory, mock.patch(
        "components.gmail_provisioning.provider_ops.provider_discover_routing_plan",
        return_value=discovered_plan,
    ):
        result = discover_gmail_configuration(
            config,
            max_workers=1,
            stop_event=stop_event,
        )

    assert result.ok
    factory.assert_called_once_with(config, stop_event=stop_event)


def test_required_names_and_filters_come_from_resolved_plan() -> None:
    config = _config(api_auth=AuthConfig(method="xoauth2", password="token"))
    plan = _routing_plan(config)
    assert required_custom_labels(plan) == ("MailB",)
    specs = gmail_filter_specs(plan)
    assert len(specs) == 1
    assert specs[0].query == "deliveredto:alias@example.com"
    assert specs[0].inbox == "archive"
    assert specs[0].mark_read


def test_gmail_filter_specs_execute_one_unicode_domain_as_canonical_idna() -> None:
    config = _config(api_auth=AuthConfig(method="xoauth2", password="token"))
    config.migration.routing = RoutingConfig.from_dict(
        {
            "enabled": True,
            "accounts": {
                "source@example.com": {"default_label": "MailB"}
            },
            "filters": [
                {"delivered_to": "alias@faß.de", "label": "MailB"}
            ],
        }
    )
    plan = _routing_plan(config, existing=True)

    specs = gmail_filter_specs(plan)
    reconciliation = plan_gmail_configuration(
        required_custom_labels(plan),
        specs,
        [
            GmailLabel("INBOX", "INBOX", "system"),
            GmailLabel("Label_B", "MailB", "user"),
        ],
        [],
    )

    assert len(specs) == 1
    assert specs[0].delivered_to == "alias@xn--fa-hia.de"
    assert reconciliation.ok
    assert reconciliation.filters.entries[0].action == "create"


def test_gmail_filter_reconciliation_rejects_idna_equivalent_plan_conditions() -> None:
    routing = RoutingConfig.from_dict(
        {
            "enabled": True,
            "accounts": {
                "source@example.com": {"default_label": "MailB"}
            },
            "filters": [
                {"delivered_to": "alias@faß.de", "label": "MailB"},
                {
                    "delivered_to": "alias@xn--fa-hia.de",
                    "label": "MailC",
                },
            ],
        }
    )
    plan = resolve_routing_plan(
        routing,
        [SourceFolder("source@example.com", "INBOX", "/", ("\\Inbox",))],
        [
            TargetLabel("INBOX", GMAIL_SYSTEM, system_role="inbox", target_id="INBOX"),
            TargetLabel("MailB", CUSTOM_LABEL, target_id="Label_B"),
            TargetLabel("MailC", CUSTOM_LABEL, target_id="Label_C"),
        ],
    )

    specs = gmail_filter_specs(plan)
    reconciliation = plan_gmail_configuration(
        required_custom_labels(plan),
        specs,
        [
            GmailLabel("INBOX", "INBOX", "system"),
            GmailLabel("Label_B", "MailB", "user"),
            GmailLabel("Label_C", "MailC", "user"),
        ],
        [],
    )

    assert [spec.delivered_to for spec in specs] == [
        "alias@xn--fa-hia.de",
        "alias@xn--fa-hia.de",
    ]
    assert not reconciliation.ok
    assert any(
        "multiple requested filters have the same condition" in conflict
        for conflict in reconciliation.filters.conflicts
    )


def test_second_plan_artifact_is_stable_across_create_to_reuse_transition(
    tmp_path: Path,
) -> None:
    config = _config(api_auth=AuthConfig(method="xoauth2", password="token"))
    create_plan = _routing_plan(config, existing=False)
    create_gmail = plan_gmail_configuration(
        ["MailB"],
        gmail_filter_specs(create_plan),
        [GmailLabel("INBOX", "INBOX", "system")],
        [],
    )
    first = GmailConfigurationPlan(
        "target@example.com",
        create_plan,
        create_gmail,
        True,
    )
    authoritative = save_gmail_configuration_plan(tmp_path, config, first)
    artifact = tmp_path / GMAIL_CONFIGURATION_PLAN_FILENAME
    original = artifact.read_bytes()

    # Live Gmail state has changed, but requested mapping/spec identity has not.
    reuse_plan = _routing_plan(config, existing=True)
    reuse_gmail = plan_gmail_configuration(
        ["MailB"],
        gmail_filter_specs(reuse_plan),
        [GmailLabel("INBOX", "INBOX", "system"), GmailLabel("Label_B", "MailB", "user")],
        [],
    )
    second = GmailConfigurationPlan(
        "target@example.com",
        reuse_plan,
        reuse_gmail,
        True,
    )
    authoritative_again = save_gmail_configuration_plan(tmp_path, config, second)

    assert authoritative.mapping_digest == authoritative_again.mapping_digest
    assert artifact.read_bytes() == original


def test_same_spec_different_snapshot_race_keeps_one_authoritative_gmail_plan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from components import gmail_provisioning as module

    config = _config(api_auth=AuthConfig(method="xoauth2", password="token"))
    create_route = _routing_plan(config, existing=False)
    reuse_route = _routing_plan(config, existing=True)
    create_snapshot = GmailConfigurationPlan(
        "target@example.com",
        create_route,
        plan_gmail_configuration(
            ["MailB"],
            gmail_filter_specs(create_route),
            [GmailLabel("INBOX", "INBOX", "system")],
            [],
        ),
        True,
    )
    reuse_snapshot = GmailConfigurationPlan(
        "target@example.com",
        reuse_route,
        plan_gmail_configuration(
            ["MailB"],
            gmail_filter_specs(reuse_route),
            [
                GmailLabel("INBOX", "INBOX", "system"),
                GmailLabel("Label_B", "MailB", "user"),
            ],
            [],
        ),
        True,
    )
    assert create_route.mapping_digest == reuse_route.mapping_digest
    assert create_snapshot.to_dict() != reuse_snapshot.to_dict()

    barrier = threading.Barrier(2)
    real_create_once = module.provider_ops._atomic_json_create_once

    def synchronized_create_once(path: Path, payload: dict) -> bool:
        if path.name == GMAIL_CONFIGURATION_PLAN_FILENAME:
            barrier.wait(timeout=5)
        return real_create_once(path, payload)

    monkeypatch.setattr(
        module.provider_ops,
        "_atomic_json_create_once",
        synchronized_create_once,
    )
    with ThreadPoolExecutor(max_workers=2) as executor:
        returned = list(
            executor.map(
                lambda discovered: save_gmail_configuration_plan(
                    tmp_path,
                    config,
                    discovered,
                ),
                (create_snapshot, reuse_snapshot),
            )
        )

    artifact = tmp_path / GMAIL_CONFIGURATION_PLAN_FILENAME
    persisted = json.loads(artifact.read_text(encoding="utf-8"))
    persisted_snapshot = json.dumps(persisted["initial_dry_run"], sort_keys=True)
    assert {item.mapping_digest for item in returned} == {create_route.mapping_digest}
    assert persisted_snapshot in {
        json.dumps(create_snapshot.to_dict(), sort_keys=True),
        json.dumps(reuse_snapshot.to_dict(), sort_keys=True),
    }
    assert stat.S_IMODE(artifact.stat().st_mode) == 0o600
    assert artifact.stat().st_nlink == 1


def test_tampered_second_plan_spec_is_rejected_even_with_original_digest(
    tmp_path: Path,
) -> None:
    config = _config(api_auth=AuthConfig(method="xoauth2", password="token"))
    route = _routing_plan(config)
    discovered = GmailConfigurationPlan(
        "target@example.com",
        route,
        plan_gmail_configuration(
            ["MailB"],
            gmail_filter_specs(route),
            [GmailLabel("INBOX", "INBOX", "system")],
            [],
        ),
        True,
    )
    save_gmail_configuration_plan(tmp_path, config, discovered)
    path = tmp_path / GMAIL_CONFIGURATION_PLAN_FILENAME
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["spec"]["required_custom_labels"] = ["Attacker"]
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(RuntimeError, match="different target, routing mapping"):
        save_gmail_configuration_plan(tmp_path, config, discovered)


def test_live_verification_requires_labels_and_exact_filters() -> None:
    config = _config(api_auth=AuthConfig(method="xoauth2", password="token"))
    plan = _routing_plan(config, existing=True)

    class MissingClient:
        def list_labels(self):
            return (GmailLabel("INBOX", "INBOX", "system"),)

        def list_filters(self):
            return ()

    missing = verify_gmail_configuration(plan, MissingClient())  # type: ignore[arg-type]
    assert not missing.ok
    assert any("MailB" in issue for issue in missing.issues)

    class CompleteClient:
        def list_labels(self):
            return (
                GmailLabel("INBOX", "INBOX", "system"),
                GmailLabel("Label_B", "MailB", "user"),
            )

        def list_filters(self):
            return (
                GmailFilter(
                    "filter-1",
                    {"query": "deliveredto:alias@example.com"},
                    {
                        "addLabelIds": ["Label_B"],
                        "removeLabelIds": ["INBOX", "UNREAD"],
                    },
                ),
            )

    complete = verify_gmail_configuration(plan, CompleteClient())  # type: ignore[arg-type]
    assert complete.ok
    assert complete.issues == ()
