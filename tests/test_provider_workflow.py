from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import errno
import json
import stat
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from components.gmail_api import GmailApiClient
from components.models import WorkspaceAliasAdminAuthConfig
from components.provider_workflow import (
    MIGRATION_REPORT_FILENAME,
    _dry_run_review_action,
    _load_workspace_alias_plan,
    _save_workspace_alias_plan,
    migration_report_path,
    run_provider_migration_workflow,
    workspace_directory_client_if_required,
)
from components.workspace_aliases import (
    WorkspaceAuthorizationIdentity,
    WorkspaceDirectoryUser,
    WorkspaceDomain,
    WorkspaceUserAlias,
    discover_workspace_alias_plan,
)


class Result:
    def __init__(self, name: str, *, ok: bool = True, issues=()) -> None:
        self.name = name
        self.ok = ok
        self.issues = tuple(issues)

    def to_dict(self):
        return {"ok": self.ok, "name": self.name, "issues": list(self.issues)}


class Discovered:
    ok = True
    conflicts = ()

    def __init__(self, plan) -> None:
        self.routing = plan

    def to_dict(self):
        return {
            "version": 1,
            "ok": True,
            "routing_plan_sha256": self.routing.mapping_digest,
        }


class AliasPlan:
    def __init__(
        self,
        *,
        ok: bool = True,
        conflicts=(),
        actions_required=(),
        status: str | None = None,
        entries=None,
    ) -> None:
        self.ok = ok
        self.conflicts = tuple(conflicts)
        self.actions_required = tuple(actions_required)
        self.status = status
        self.entries = entries
        self.intent_sha256 = "b" * 64
        self.plan_sha256 = "c" * 64

    def to_dict(self):
        status = self.status or ("conflict" if self.conflicts else "create")
        entries = (
            self.entries
            if self.entries is not None
            else [{"alias": "old@example.com", "status": status}]
        )
        return {
            "version": 1,
            "ok": self.ok,
            "entries": entries,
            "conflicts": list(self.conflicts),
            "actions_required": list(self.actions_required),
            "intent_sha256": self.intent_sha256,
            "plan_sha256": self.plan_sha256,
        }


class AliasResult:
    def __init__(
        self,
        *,
        ok: bool = True,
        created=(),
        reused=(),
        conflicted=(),
        issues=(),
        actions_required=(),
    ) -> None:
        self.ok = ok
        self.created = tuple(created)
        self.reused = tuple(reused)
        self.conflicted = tuple(conflicted)
        self.issues = tuple(issues)
        self.actions_required = tuple(actions_required)

    def to_dict(self):
        return {
            "version": 1,
            "ok": self.ok,
            "created": list(self.created),
            "reused": list(self.reused),
            "conflicted": list(self.conflicted),
            "issues": list(self.issues),
            "actions_required": list(self.actions_required),
        }


class AliasProvisionFailure(RuntimeError):
    def __init__(self, message: str, result: AliasResult) -> None:
        super().__init__(message)
        self.result = result


class PartialCancellation(InterruptedError):
    def __init__(self, message: str, result) -> None:
        super().__init__(message)
        self.result = result


class PartialGmailResult:
    def __init__(self, payload) -> None:
        self.payload = dict(payload)

    def to_dict(self):
        return dict(self.payload)


class PlanningDirectoryClient:
    authorization_identity = WorkspaceAuthorizationIdentity(
        "xoauth2",
        "admin@example.com",
    )

    def __init__(self) -> None:
        self.alias_active = False

    def get_user(self, email: str):
        aliases = ("old@example.com",) if self.alias_active else ()
        if email in {"merged@example.com", "old@example.com"} and (
            email == "merged@example.com" or self.alias_active
        ):
            return WorkspaceDirectoryUser(
                "target-id",
                "merged@example.com",
                "customer-id",
                aliases=aliases,
            )
        return None

    def list_user_aliases(self, _target_user: str):
        if not self.alias_active:
            return ()
        return (
            WorkspaceUserAlias(
                "old@example.com",
                "merged@example.com",
                "target-id",
            ),
        )

    def get_group(self, _email: str):
        return None

    def get_domain(self, _customer: str, domain: str):
        return WorkspaceDomain(domain, "primary", True)

    def get_domain_alias(self, _customer: str, _domain: str):
        return None


def _config():
    return SimpleNamespace(
        migration=SimpleNamespace(routing=SimpleNamespace(enabled=True)),
    )


def _config_without_routing():
    return SimpleNamespace(
        target=SimpleNamespace(provider="imap"),
        accounts=[],
        migration=SimpleNamespace(routing=SimpleNamespace(enabled=False)),
    )


def _alias_config(*, admin_auth=None, aliases=("old@example.com",)):
    settings = SimpleNamespace(
        enabled=True,
        target_user="merged@example.com",
        admin_auth=admin_auth,
    )
    return SimpleNamespace(
        target=SimpleNamespace(provider="gmail", workspace_aliases=settings),
        accounts=[],
        limits=SimpleNamespace(retry_max_attempts=7),
        migration=SimpleNamespace(routing=SimpleNamespace(enabled=True)),
        workspace_alias_candidates=lambda: tuple(aliases),
    )


def _install_successful_workflow_mocks(monkeypatch, events, *, filter_effect=None):
    from components import provider_workflow as workflow

    plan = SimpleNamespace(mapping_digest="a" * 64, filters=(object(),))
    discovered = Discovered(plan)
    client = object()

    def record(name, value=None):
        def inner(*_args, **_kwargs):
            events.append(name)
            return value

        return inner

    monkeypatch.setattr(workflow.provider_ops, "provider_preflight", record("preflight", (True, [])))
    monkeypatch.setattr(workflow, "discover_gmail_configuration", record("discover", discovered))
    monkeypatch.setattr(workflow, "save_gmail_configuration_plan", record("save", plan))
    monkeypatch.setattr(workflow, "require_gmail_configuration_plan", record("require", Path("plan")))
    monkeypatch.setattr(workflow.provider_ops, "provider_export_all", record("export"))
    monkeypatch.setattr(workflow.provider_ops, "provider_audit_all", record("audit", (True, [])))
    monkeypatch.setattr(workflow, "plan_live_gmail_configuration", record("live-plan", object()))
    monkeypatch.setattr(workflow, "require_live_gmail_plan_ok", record("live-gate"))
    monkeypatch.setattr(workflow, "provision_gmail_labels", record("labels", Result("labels")))
    monkeypatch.setattr(workflow.provider_ops, "provider_import_all", record("import"))
    if filter_effect is None:
        monkeypatch.setattr(workflow, "provision_gmail_filters", record("filters", Result("filters")))
    else:
        monkeypatch.setattr(workflow, "provision_gmail_filters", filter_effect)
    monkeypatch.setattr(workflow.provider_ops, "provider_validate_all", record("validate", (True, [])))
    monkeypatch.setattr(workflow, "verify_gmail_configuration", record("verify", Result("verify")))
    monkeypatch.setattr(
        workflow.provider_ops,
        "build_provider_routing_report",
        record("provider-report", {"ok": True, "accounts": []}),
        raising=False,
    )
    return plan, client


def _install_alias_workflow_mocks(
    monkeypatch,
    events,
    *,
    alias_plan=None,
    provision_effect=None,
    verification=None,
):
    from components import provider_workflow as workflow

    alias_plan = alias_plan or AliasPlan()
    verification = verification or AliasResult(reused=("old@example.com",))

    def discover(*_args, **_kwargs):
        events.append("alias-discover")
        return alias_plan

    def save(*_args, **_kwargs):
        events.append("alias-save")
        return alias_plan

    def provision(*_args, **_kwargs):
        events.append("alias-provision")
        if provision_effect is not None:
            return provision_effect()
        return AliasResult(created=("old@example.com",))

    def verify(*_args, **_kwargs):
        events.append("alias-verify")
        return verification

    monkeypatch.setattr(workflow, "discover_workspace_alias_plan", discover)
    monkeypatch.setattr(workflow, "_save_workspace_alias_plan", save)
    monkeypatch.setattr(workflow, "provision_workspace_aliases", provision)
    monkeypatch.setattr(workflow, "verify_workspace_aliases", verify)
    return alias_plan


def test_workflow_dry_run_is_read_only_remotely_and_persists_plans(
    tmp_path: Path,
    monkeypatch,
) -> None:
    events = []
    _plan, client = _install_successful_workflow_mocks(monkeypatch, events)

    report = run_provider_migration_workflow(
        _config(),  # type: ignore[arg-type]
        tmp_path,
        max_workers=2,
        dry_run=True,
        gmail_client=client,  # type: ignore[arg-type]
    )

    assert report["ok"]
    assert report["status"] == "planned"
    assert report["stage_order"] == ["discover_plan", "persist_plan", "final_report"]
    assert events == ["preflight", "discover", "save", "require"]
    assert not any(name in events for name in ("export", "labels", "import", "filters"))
    persisted = json.loads((tmp_path / MIGRATION_REPORT_FILENAME).read_text())
    assert persisted["dry_run"] is True
    assert persisted["status"] == "planned"


def test_workflow_lock_serializes_same_root_remote_mutations(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from components import provider_workflow as workflow

    events: list[str] = []
    first_filter_entered = threading.Event()
    release_first_filter = threading.Event()
    second_lock_contended = threading.Event()
    mutation_guard = threading.Lock()
    active_mutations = 0
    maximum_active_mutations = 0
    filter_calls = 0

    real_flock = workflow.provider_ops.fcntl.flock

    def recording_flock(fd: int, operation: int) -> None:
        try:
            real_flock(fd, operation)
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK}:
                second_lock_contended.set()
            raise

    def filter_effect(*_args, **_kwargs):
        nonlocal active_mutations, maximum_active_mutations, filter_calls
        with mutation_guard:
            filter_calls += 1
            call_number = filter_calls
            active_mutations += 1
            maximum_active_mutations = max(
                maximum_active_mutations,
                active_mutations,
            )
        try:
            events.append(f"filters-{call_number}")
            if call_number == 1:
                first_filter_entered.set()
                assert release_first_filter.wait(5), "first workflow was not released"
            return Result("filters")
        finally:
            with mutation_guard:
                active_mutations -= 1

    _plan, client = _install_successful_workflow_mocks(
        monkeypatch,
        events,
        filter_effect=filter_effect,
    )
    monkeypatch.setattr(workflow.provider_ops.fcntl, "flock", recording_flock)

    def run_workflow():
        return run_provider_migration_workflow(
            _config(),  # type: ignore[arg-type]
            tmp_path,
            max_workers=1,
            gmail_client=client,  # type: ignore[arg-type]
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(run_workflow)
        assert first_filter_entered.wait(5), "first workflow never reached mutation"
        second = executor.submit(run_workflow)
        try:
            assert second_lock_contended.wait(5), "second workflow never contended"
            assert events.count("preflight") == 1
            assert not second.done()
        finally:
            release_first_filter.set()
        first_report = first.result(timeout=5)
        second_report = second.result(timeout=5)

    assert first_report["ok"]
    assert second_report["ok"]
    assert filter_calls == 2
    assert maximum_active_mutations == 1
    assert events.count("preflight") == 2


def test_nonrouting_dry_run_creates_private_staging_and_report_parent(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from components import provider_workflow as workflow

    root = tmp_path / "new" / "staging"
    report_path = root / "reports" / "migration-report.json"
    monkeypatch.setattr(
        workflow.provider_ops,
        "provider_preflight",
        lambda *_args, **_kwargs: (True, []),
    )

    report = run_provider_migration_workflow(
        _config_without_routing(),  # type: ignore[arg-type]
        root,
        max_workers=1,
        dry_run=True,
        report_path=report_path,
    )

    assert report["ok"]
    assert report["artifacts"] == {
        "staging_root": str(root),
        "report": str(report_path),
    }
    assert report_path.is_file()
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert stat.S_IMODE(report_path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(report_path.stat().st_mode) == 0o600
    action = report["actions_required"][0]
    assert "migration report" in action
    assert "routing plan" not in action
    assert "Gmail configuration plan" not in action
    assert "Workspace alias plan" not in action


@pytest.mark.parametrize(
    ("artifact_keys", "expected_names", "absent_names"),
    [
        (
            {"report"},
            ("migration report",),
            ("routing plan", "Gmail configuration plan", "Workspace alias plan"),
        ),
        (
            {"routing_plan", "gmail_configuration_plan", "report"},
            ("routing plan", "Gmail configuration plan", "migration report"),
            ("Workspace alias plan",),
        ),
        (
            {"workspace_alias_plan", "report"},
            ("Workspace alias plan", "migration report"),
            ("routing plan", "Gmail configuration plan"),
        ),
        (
            {
                "routing_plan",
                "gmail_configuration_plan",
                "workspace_alias_plan",
                "report",
            },
            (
                "routing plan",
                "Gmail configuration plan",
                "Workspace alias plan",
                "migration report",
            ),
            (),
        ),
    ],
)
def test_dry_run_review_action_names_only_created_artifacts(
    artifact_keys,
    expected_names,
    absent_names,
) -> None:
    action = _dry_run_review_action({key: f"/{key}.json" for key in artifact_keys})

    for name in expected_names:
        assert name in action
    for name in absent_names:
        assert name not in action
    assert action.endswith("then run migrate without --dry-run.")


def test_report_path_outside_staging_is_rejected_without_chmod(
    tmp_path: Path,
) -> None:
    root = tmp_path / "staging"
    outside = tmp_path / "unrelated"
    outside.mkdir(mode=0o755)
    report_path = outside / "migration-report.json"

    with pytest.raises(ValueError, match="must be inside the staging directory"):
        run_provider_migration_workflow(
            _config_without_routing(),  # type: ignore[arg-type]
            root,
            max_workers=1,
            dry_run=True,
            report_path=report_path,
        )

    assert not root.exists()
    assert not report_path.exists()
    assert stat.S_IMODE(outside.stat().st_mode) == 0o755


@pytest.mark.parametrize(
    "filename",
    [
        "routing-plan.json",
        "ROUTING-PLAN.JSON",
        "gmail-configuration-plan.json",
        "workspace-alias-plan.json",
    ],
)
def test_report_path_rejects_reserved_root_artifacts(
    tmp_path: Path,
    filename: str,
) -> None:
    with pytest.raises(ValueError, match="reserved staged artifact"):
        migration_report_path(tmp_path, tmp_path / filename)


@pytest.mark.parametrize(
    "relative",
    [
        ".import-locks",
        ".import-locks/provider-workflow.lock",
        ".import-locks/provider-deadbeef.lock",
        ".import-locks/nested/custom-report.json",
        ".IMPORT-LOCKS/nested/custom-report.json",
    ],
)
def test_report_path_rejects_entire_internal_lock_namespace(
    tmp_path: Path,
    relative: str,
) -> None:
    with pytest.raises(ValueError, match="reserved internal staging namespace"):
        migration_report_path(tmp_path, tmp_path / relative)


@pytest.mark.parametrize("preexisting", [False, True])
def test_workflow_rejects_lock_namespace_report_before_staging_side_effects(
    tmp_path: Path,
    monkeypatch,
    preexisting: bool,
) -> None:
    from components import provider_workflow as workflow

    root = tmp_path / "staged"
    report_path = root / ".import-locks" / "provider-workflow.lock"
    if preexisting:
        report_path.parent.mkdir(parents=True, mode=0o700)
        report_path.write_text("existing-lock-inode\n", encoding="utf-8")
        report_path.chmod(0o600)
    monkeypatch.setattr(
        workflow.provider_ops,
        "provider_preflight",
        lambda *_args, **_kwargs: pytest.fail("validation must precede workflow work"),
    )

    with pytest.raises(ValueError, match="reserved internal staging namespace"):
        run_provider_migration_workflow(
            _config_without_routing(),  # type: ignore[arg-type]
            root,
            max_workers=1,
            dry_run=True,
            report_path=report_path,
        )

    if preexisting:
        assert report_path.read_text(encoding="utf-8") == "existing-lock-inode\n"
        assert stat.S_IMODE(report_path.stat().st_mode) == 0o600
    else:
        assert not root.exists()


@pytest.mark.parametrize(
    "relative",
    [
        "source@example.com/report.json",
        "SOURCE@EXAMPLE.COM/report.json",
        "source@example.com/messages/message.eml",
        "source@example.com/metadata/message.json",
        "source@example.com/manifest.jsonl",
        "source@example.com/import.journal.jsonl",
        "source@example.com/validation-target@example.com.json",
    ],
)
def test_report_path_rejects_configured_account_artifact_locations(
    tmp_path: Path,
    relative: str,
) -> None:
    config = SimpleNamespace(
        accounts=[SimpleNamespace(source_email="source@example.com")]
    )

    with pytest.raises(ValueError, match="account artifact|account directory"):
        migration_report_path(
            tmp_path,
            tmp_path / relative,
            config=config,  # type: ignore[arg-type]
        )


def test_report_path_rejects_existing_non_report_and_unsafe_targets(
    tmp_path: Path,
) -> None:
    reports = tmp_path / "reports"
    reports.mkdir()
    ordinary = reports / "ordinary.json"
    ordinary.write_text('{"not":"a migration report"}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="existing non-report artifact"):
        migration_report_path(tmp_path, ordinary)

    directory = reports / "directory.json"
    directory.mkdir()
    with pytest.raises(ValueError, match="not a safe regular file"):
        migration_report_path(tmp_path, directory)

    victim = tmp_path / "victim.json"
    victim.write_text('{"outside":"unchanged"}\n', encoding="utf-8")
    linked = reports / "linked.json"
    linked.symlink_to(victim)
    with pytest.raises(ValueError, match="symlinked component"):
        migration_report_path(tmp_path, linked)

    hard_link = reports / "hard-linked.json"
    hard_link.hardlink_to(victim)
    with pytest.raises(ValueError, match="not a safe regular file"):
        migration_report_path(tmp_path, hard_link)
    assert victim.read_text(encoding="utf-8") == '{"outside":"unchanged"}\n'


def test_nested_custom_report_path_remains_valid_and_resumable(tmp_path: Path) -> None:
    report_path = tmp_path / "reports" / "custom.json"
    assert migration_report_path(tmp_path, report_path) == report_path
    report_path.parent.mkdir()
    report_path.write_text(
        json.dumps(
            {
                "version": 1,
                "status": "failed",
                "stage_order": [],
                "stages": [],
                "artifacts": {
                    "staging_root": str(tmp_path),
                    "report": str(report_path),
                },
            }
        ),
        encoding="utf-8",
    )
    assert migration_report_path(tmp_path, report_path) == report_path


def test_relative_report_bindings_are_persisted_absolute_and_survive_chdir(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from components import provider_workflow as workflow

    original_cwd = tmp_path / "original-cwd"
    other_cwd = tmp_path / "other-cwd"
    original_cwd.mkdir()
    other_cwd.mkdir()
    monkeypatch.chdir(original_cwd)
    monkeypatch.setattr(
        workflow.provider_ops,
        "provider_preflight",
        lambda *_args, **_kwargs: (True, []),
    )

    first = run_provider_migration_workflow(
        _config_without_routing(),  # type: ignore[arg-type]
        Path("staged"),
        max_workers=1,
        dry_run=True,
        report_path=Path("staged/reports/custom.json"),
    )
    staging_root = original_cwd / "staged"
    report_path = staging_root / "reports" / "custom.json"
    assert first["artifacts"]["staging_root"] == str(staging_root)
    assert first["artifacts"]["report"] == str(report_path)
    persisted = json.loads(report_path.read_text(encoding="utf-8"))
    assert persisted["artifacts"]["staging_root"] == str(staging_root)
    assert persisted["artifacts"]["report"] == str(report_path)

    monkeypatch.chdir(other_cwd)
    second = run_provider_migration_workflow(
        _config_without_routing(),  # type: ignore[arg-type]
        staging_root,
        max_workers=1,
        dry_run=True,
        report_path=report_path,
    )

    assert second["ok"]
    assert second["artifacts"] == first["artifacts"]


def test_workflow_runs_required_stages_in_order(tmp_path: Path, monkeypatch) -> None:
    events = []
    _plan, client = _install_successful_workflow_mocks(monkeypatch, events)

    report = run_provider_migration_workflow(
        _config(),  # type: ignore[arg-type]
        tmp_path,
        max_workers=4,
        gmail_client=client,  # type: ignore[arg-type]
    )

    assert report["ok"]
    assert report["workspace_aliases"]["enabled"] is False
    assert report["workspace_aliases"]["filter_protection"] == {
        "status": "not_applicable",
        "verified_before_export": False,
        "verified_before_alias_activation": False,
        "delivery_before_verification_proven": False,
    }
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
    assert events == [
        "preflight",
        "discover",
        "save",
        "require",
        "live-plan",
        "live-gate",
        "labels",
        "filters",
        "verify",
        "export",
        "audit",
        "import",
        "validate",
        "verify",
        "provider-report",
    ]
    persisted = json.loads((tmp_path / MIGRATION_REPORT_FILENAME).read_text())
    assert persisted["gmail"]["labels"]["name"] == "labels"
    assert persisted["gmail"]["filters"]["name"] == "filters"
    assert persisted["gmail"]["pre_export_verification"]["name"] == "verify"
    assert persisted["gmail"]["verification"]["name"] == "verify"


def test_nonrouting_aggregate_report_preserves_internaldate_warnings(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from components import provider_workflow as workflow

    account = SimpleNamespace(
        source_email="source@example.com",
        target_email="target@example.com",
    )
    config = SimpleNamespace(
        accounts=[account],
        migration=SimpleNamespace(routing=SimpleNamespace(enabled=False)),
    )
    warning = {
        "code": "existing-target-internaldate-differs",
        "canonical_id": "a" * 64,
        "target_mailbox": "Archive",
        "source_internaldate": "01-Jan-2020 00:00:00 +0000",
        "target_internaldate": "02-Jan-2020 00:00:00 +0000",
        "provenance": "existing-content-reuse",
        "message": "Existing byte-identical target message was reused.",
    }
    validation = {
        "exported": 1,
        "committed": 1,
        "missing": [],
        "duplicates": [],
        "failed": [],
        "warnings": [warning],
    }
    monkeypatch.setattr(
        workflow.provider_ops,
        "provider_validate_account",
        lambda *_args, **_kwargs: (account.source_email, validation),
    )

    report = workflow._provider_report(config, tmp_path, None)

    assert report["accounts"][0]["warnings"] == [warning]
    assert report["totals"]["warnings"] == 1
    assert report["totals"]["failed"] == 0


def test_filter_failure_before_export_writes_resumable_failure_report(
    tmp_path: Path,
    monkeypatch,
) -> None:
    events = []

    def filter_failure(*_args, **_kwargs):
        events.append("filters")
        raise RuntimeError("filter permission denied; required scope: gmail.settings.basic")

    _plan, client = _install_successful_workflow_mocks(
        monkeypatch,
        events,
        filter_effect=filter_failure,
    )
    report = run_provider_migration_workflow(
        _config(),  # type: ignore[arg-type]
        tmp_path,
        max_workers=1,
        gmail_client=client,  # type: ignore[arg-type]
    )

    assert not report["ok"]
    assert events.index("labels") < events.index("filters")
    assert "export" not in events
    assert "audit" not in events
    assert "import" not in events
    assert "validate" not in events
    assert report["stage_order"][-1] == "provision_filters"
    assert any("Export has not started" in item for item in report["actions_required"])
    persisted = json.loads((tmp_path / MIGRATION_REPORT_FILENAME).read_text())
    assert persisted["status"] == "failed"
    assert persisted["provider"] == {"ok": True, "accounts": []}
    assert "gmail.settings.basic" in " ".join(persisted["issues"])


def test_filter_mutation_cancellation_persists_partial_result_without_new_remote_work(
    tmp_path: Path,
    monkeypatch,
) -> None:
    events: list[str] = []
    stop_event = threading.Event()
    partial_payload = {
        "ok": False,
        "dry_run": False,
        "verified": False,
        "filters": [
            {
                "query": "deliveredto:old@example.com",
                "action": "unresolved",
                "deleted_filter_ids": ["old-filter"],
            }
        ],
        "created_filter_ids": [],
        "deleted_filter_ids": ["old-filter"],
        "reused_filter_ids": [],
        "unresolved": ["deliveredto:old@example.com"],
        "issues": ["Gmail filter reconciliation cancelled: stop requested"],
        "actions_required": [
            "Rerun Gmail filter reconciliation to resolve the remaining filter."
        ],
    }

    def cancel_after_filter_mutation(*_args, **_kwargs):
        events.append("filters-cancelled")
        stop_event.set()
        raise PartialCancellation(
            "Gmail filter reconciliation cancelled: stop requested",
            PartialGmailResult(partial_payload),
        )

    _plan, client = _install_successful_workflow_mocks(
        monkeypatch,
        events,
        filter_effect=cancel_after_filter_mutation,
    )
    report = run_provider_migration_workflow(
        _config(),  # type: ignore[arg-type]
        tmp_path,
        max_workers=1,
        stop_event=stop_event,
        gmail_client=client,  # type: ignore[arg-type]
    )

    assert not report["ok"]
    assert report["status"] == "failed"
    assert report["stage_order"][-1] == "provision_filters"
    assert report["gmail"]["filters"] == partial_payload
    assert partial_payload["actions_required"][0] in report["actions_required"]
    assert "validate" not in events
    assert "verify" not in events
    assert "provider-report" not in events
    persisted = json.loads((tmp_path / MIGRATION_REPORT_FILENAME).read_text())
    assert persisted["gmail"]["filters"] == partial_payload
    assert partial_payload["actions_required"][0] in persisted["actions_required"]


def test_rerun_after_filter_failure_reuses_same_root_and_completes(
    tmp_path: Path,
    monkeypatch,
) -> None:
    events = []
    attempts = 0

    def filters(*_args, **_kwargs):
        nonlocal attempts
        attempts += 1
        events.append(f"filters-{attempts}")
        if attempts == 1:
            raise RuntimeError("temporary filter failure")
        return Result("filters-reused")

    _plan, client = _install_successful_workflow_mocks(
        monkeypatch,
        events,
        filter_effect=filters,
    )
    first = run_provider_migration_workflow(
        _config(),  # type: ignore[arg-type]
        tmp_path,
        max_workers=1,
        gmail_client=client,  # type: ignore[arg-type]
    )
    second = run_provider_migration_workflow(
        _config(),  # type: ignore[arg-type]
        tmp_path,
        max_workers=1,
        gmail_client=client,  # type: ignore[arg-type]
    )

    assert not first["ok"]
    assert second["ok"]
    assert attempts == 2
    assert second["artifacts"]["staging_root"] == str(tmp_path)
    assert second["gmail"]["filters"]["name"] == "filters-reused"


def test_workflow_stops_before_label_mutation_when_live_filter_gate_conflicts(
    tmp_path: Path,
    monkeypatch,
) -> None:
    events = []
    _plan, client = _install_successful_workflow_mocks(monkeypatch, events)
    from components import provider_workflow as workflow

    def fail_gate(*_args, **_kwargs):
        events.append("live-gate-failed")
        raise RuntimeError("same-condition filter conflict")

    monkeypatch.setattr(workflow, "require_live_gmail_plan_ok", fail_gate)
    report = run_provider_migration_workflow(
        _config(),  # type: ignore[arg-type]
        tmp_path,
        max_workers=1,
        gmail_client=client,  # type: ignore[arg-type]
    )

    assert not report["ok"]
    assert "labels" not in events
    assert "export" not in events
    assert "import" not in events
    assert "filters" not in events


def test_workflow_stops_before_export_when_full_gmail_verification_fails(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from components import provider_workflow as workflow

    events: list[str] = []
    _plan, client = _install_successful_workflow_mocks(monkeypatch, events)

    def fail_verification(*_args, **_kwargs):
        events.append("verify-failed")
        return Result(
            "pre-export-verify",
            ok=False,
            issues=("required Gmail filter disappeared",),
        )

    monkeypatch.setattr(workflow, "verify_gmail_configuration", fail_verification)
    report = run_provider_migration_workflow(
        _config(),  # type: ignore[arg-type]
        tmp_path,
        max_workers=1,
        gmail_client=client,  # type: ignore[arg-type]
        workspace_client=object(),  # type: ignore[arg-type]
    )

    assert not report["ok"]
    assert report["stage_order"][-1] == "provision_filters"
    assert report["gmail"]["pre_export_verification"]["ok"] is False
    assert "export" not in events
    assert "audit" not in events
    assert "import" not in events
    assert report["workspace_aliases"]["enabled"] is False
    assert any("Export has not started" in item for item in report["actions_required"])


def test_stop_requested_as_audit_finishes_blocks_all_later_mutations(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from components import provider_workflow as workflow

    events: list[str] = []
    stop_event = threading.Event()
    _plan, client = _install_successful_workflow_mocks(monkeypatch, events)

    def audit_then_stop(*_args, **_kwargs):
        events.append("audit-stop")
        stop_event.set()
        return True, []

    monkeypatch.setattr(workflow.provider_ops, "provider_audit_all", audit_then_stop)
    report = run_provider_migration_workflow(
        _config(),  # type: ignore[arg-type]
        tmp_path,
        max_workers=1,
        stop_event=stop_event,
        gmail_client=client,  # type: ignore[arg-type]
    )

    assert not report["ok"]
    assert report["status"] == "failed"
    assert report["stage_order"][-1] == "audit"
    assert "stop requested" in " ".join(report["issues"])
    assert events.index("labels") < events.index("filters") < events.index("export")
    assert "import" not in events
    assert "provider-report" not in events


def test_stop_event_gates_each_remote_call_inside_a_reconciliation_stage(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from components import provider_workflow as workflow

    events: list[str] = []
    stop_event = threading.Event()
    _plan, _client = _install_successful_workflow_mocks(monkeypatch, events)

    class RemoteClient:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def create_label(self, name: str) -> None:
            self.calls.append(name)
            stop_event.set()

    client = RemoteClient()

    def provision_two_labels(_plan, guarded_client):
        guarded_client.create_label("first")
        guarded_client.create_label("second")
        raise AssertionError("the second remote call must be blocked")

    monkeypatch.setattr(workflow, "provision_gmail_labels", provision_two_labels)
    report = run_provider_migration_workflow(
        _config(),  # type: ignore[arg-type]
        tmp_path,
        max_workers=1,
        stop_event=stop_event,
        gmail_client=client,  # type: ignore[arg-type]
    )

    assert not report["ok"]
    assert report["status"] == "failed"
    assert client.calls == ["first"]
    assert "import" not in events
    assert "filters" not in events
    assert "provider-report" not in events


def test_workflow_cancellation_during_gmail_retry_makes_no_second_request(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from components import provider_workflow as workflow

    events: list[str] = []
    stop_event = threading.Event()
    _install_successful_workflow_mocks(monkeypatch, events)

    class RetryableResponse:
        status_code = 503
        headers = {}

        @staticmethod
        def json():
            return {"error": {"status": "UNAVAILABLE"}}

    class StopDuringRequestSession:
        def __init__(self) -> None:
            self.calls = 0

        def request(self, *_args, **_kwargs):
            self.calls += 1
            if self.calls != 1:
                raise AssertionError("cancellation must prevent a second HTTP request")
            stop_event.set()
            return RetryableResponse()

    session = StopDuringRequestSession()

    def client_factory(_config, *, session, stop_event, **_kwargs):
        return GmailApiClient(
            "test-access-token",
            session=session,
            user_id="target@example.com",
            retry_max_attempts=3,
            stop_event=stop_event,
        )

    def discover_with_retry(*_args, **kwargs):
        kwargs["client"].list_labels()
        raise AssertionError("a cancelled API call must not return to discovery")

    monkeypatch.setattr(workflow, "gmail_api_client_if_required", client_factory)
    monkeypatch.setattr(workflow, "discover_gmail_configuration", discover_with_retry)

    report = run_provider_migration_workflow(
        _config(),  # type: ignore[arg-type]
        tmp_path,
        max_workers=1,
        stop_event=stop_event,
        gmail_session=session,
    )

    assert not report["ok"]
    assert session.calls == 1
    assert "cancelled: stop requested" in " ".join(report["issues"])
    assert "export" not in events


def test_stop_after_finalizing_before_commit_persists_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from components import provider_workflow as workflow

    events: list[str] = []
    stop_event = threading.Event()
    _plan, client = _install_successful_workflow_mocks(monkeypatch, events)
    original_write = workflow._write_report

    def stop_after_finalizing(root, payload, report_path, **kwargs):
        path = original_write(root, payload, report_path, **kwargs)
        if payload.get("status") == "finalizing":
            stop_event.set()
        return path

    monkeypatch.setattr(workflow, "_write_report", stop_after_finalizing)
    report = run_provider_migration_workflow(
        _config(),  # type: ignore[arg-type]
        tmp_path,
        max_workers=1,
        dry_run=True,
        stop_event=stop_event,
        gmail_client=client,  # type: ignore[arg-type]
    )

    persisted = json.loads(
        (tmp_path / MIGRATION_REPORT_FILENAME).read_text(encoding="utf-8")
    )
    assert report["status"] == persisted["status"] == "failed"
    assert report["terminal_committed"] is False
    assert persisted["terminal_committed"] is False
    assert persisted["terminal_commit_id"] == report["terminal_commit_id"]
    assert report["report_persisted"] is True


def test_terminal_success_reuses_finalizing_commit_identity_and_spec(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from components import provider_workflow as workflow

    events: list[str] = []
    _plan, client = _install_successful_workflow_mocks(monkeypatch, events)
    original_write = workflow._write_report
    writes: list[dict] = []

    def capture_writes(root, payload, report_path, **kwargs):
        writes.append(json.loads(json.dumps(payload)))
        return original_write(root, payload, report_path, **kwargs)

    monkeypatch.setattr(workflow, "_write_report", capture_writes)
    report = run_provider_migration_workflow(
        _config(),  # type: ignore[arg-type]
        tmp_path,
        max_workers=1,
        dry_run=True,
        gmail_client=client,  # type: ignore[arg-type]
    )

    assert [payload["status"] for payload in writes] == ["finalizing", "planned"]
    preliminary, committed = writes
    assert preliminary["ok"] is False
    assert preliminary["terminal_committed"] is False
    assert committed["ok"] is True
    assert committed["terminal_committed"] is True
    assert preliminary["terminal_commit_id"] == committed["terminal_commit_id"]
    assert (
        preliminary["terminal_commit_spec_sha256"]
        == committed["terminal_commit_spec_sha256"]
    )
    assert preliminary["terminal_target_status"] == committed["status"] == "planned"
    assert report == committed


def test_stop_during_commit_is_checked_immediately_before_atomic_replace(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from components import provider_workflow as workflow

    events: list[str] = []
    stop_event = threading.Event()
    _plan, client = _install_successful_workflow_mocks(monkeypatch, events)
    original_atomic = workflow._atomic_report_json

    def stop_at_publish(path, payload, *, before_publish=None):
        if payload.get("terminal_committed") is True:
            def stopped_publish():
                stop_event.set()
                assert before_publish is not None
                before_publish()

            return original_atomic(path, payload, before_publish=stopped_publish)
        return original_atomic(path, payload, before_publish=before_publish)

    monkeypatch.setattr(workflow, "_atomic_report_json", stop_at_publish)
    report = run_provider_migration_workflow(
        _config(),  # type: ignore[arg-type]
        tmp_path,
        max_workers=1,
        dry_run=True,
        stop_event=stop_event,
        gmail_client=client,  # type: ignore[arg-type]
    )

    persisted = json.loads(
        (tmp_path / MIGRATION_REPORT_FILENAME).read_text(encoding="utf-8")
    )
    assert report["status"] == persisted["status"] == "failed"
    assert report["terminal_committed"] is False
    assert persisted["terminal_committed"] is False


def test_stop_after_final_prepublication_check_may_lose_to_terminal_commit(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from components import provider_workflow as workflow

    events: list[str] = []
    stop_event = threading.Event()
    _plan, client = _install_successful_workflow_mocks(monkeypatch, events)
    original_atomic = workflow._atomic_report_json

    def stop_after_check(path, payload, *, before_publish=None):
        if payload.get("terminal_committed") is True:
            def checked_then_stopped():
                assert before_publish is not None
                before_publish()
                stop_event.set()

            return original_atomic(
                path,
                payload,
                before_publish=checked_then_stopped,
            )
        return original_atomic(path, payload, before_publish=before_publish)

    monkeypatch.setattr(workflow, "_atomic_report_json", stop_after_check)
    report = run_provider_migration_workflow(
        _config(),  # type: ignore[arg-type]
        tmp_path,
        max_workers=1,
        dry_run=True,
        stop_event=stop_event,
        gmail_client=client,  # type: ignore[arg-type]
    )

    persisted = json.loads(
        (tmp_path / MIGRATION_REPORT_FILENAME).read_text(encoding="utf-8")
    )
    assert stop_event.is_set()
    assert report == persisted
    assert report["ok"] is True
    assert report["status"] == "planned"
    assert report["terminal_committed"] is True


def test_stop_after_exact_success_commit_returns_success(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from components import provider_workflow as workflow

    events: list[str] = []
    stop_event = threading.Event()
    _plan, client = _install_successful_workflow_mocks(monkeypatch, events)
    original_write = workflow._write_report

    def stop_after_commit(root, payload, report_path, **kwargs):
        path = original_write(root, payload, report_path, **kwargs)
        if payload.get("terminal_committed") is True:
            stop_event.set()
        return path

    monkeypatch.setattr(workflow, "_write_report", stop_after_commit)
    report = run_provider_migration_workflow(
        _config(),  # type: ignore[arg-type]
        tmp_path,
        max_workers=1,
        dry_run=True,
        stop_event=stop_event,
        gmail_client=client,  # type: ignore[arg-type]
    )

    persisted = json.loads(
        (tmp_path / MIGRATION_REPORT_FILENAME).read_text(encoding="utf-8")
    )
    assert stop_event.is_set()
    assert report == persisted
    assert report["ok"] is True
    assert report["status"] == "planned"
    assert report["terminal_committed"] is True


@pytest.mark.parametrize("custom_report", [False, True])
def test_success_write_failure_before_rename_leaves_finalizing_marker(
    tmp_path: Path,
    monkeypatch,
    custom_report: bool,
) -> None:
    from components import provider_workflow as workflow

    events: list[str] = []
    _plan, client = _install_successful_workflow_mocks(monkeypatch, events)
    original_write = workflow._write_report
    report_path = tmp_path / "reports" / "custom.json" if custom_report else None
    authoritative = report_path or tmp_path / MIGRATION_REPORT_FILENAME

    def fail_before_success(root, payload, selected_path, **kwargs):
        if payload.get("terminal_committed") is True:
            raise OSError(errno.ENOSPC, "pre-rename terminal ENOSPC")
        return original_write(root, payload, selected_path, **kwargs)

    monkeypatch.setattr(workflow, "_write_report", fail_before_success)
    report = run_provider_migration_workflow(
        _config(),  # type: ignore[arg-type]
        tmp_path,
        max_workers=1,
        dry_run=True,
        gmail_client=client,  # type: ignore[arg-type]
        report_path=report_path,
    )

    persisted = json.loads(authoritative.read_text(encoding="utf-8"))
    assert report["status"] == "failed"
    assert report["report_persisted"] is False
    assert "pre-rename terminal ENOSPC" in report["report_write_error"]
    assert persisted["status"] == "finalizing"
    assert persisted["terminal_committed"] is False
    assert persisted["terminal_commit_id"] == report["terminal_commit_id"]
    assert not list(authoritative.parent.glob(".migration-report-quarantine-*"))


@pytest.mark.parametrize("custom_report", [False, True])
def test_success_write_failure_after_rename_recovers_exact_commit(
    tmp_path: Path,
    monkeypatch,
    custom_report: bool,
) -> None:
    from components import provider_workflow as workflow

    events: list[str] = []
    _plan, client = _install_successful_workflow_mocks(monkeypatch, events)
    original_write = workflow._write_report
    report_path = tmp_path / "reports" / "custom.json" if custom_report else None
    authoritative = report_path or tmp_path / MIGRATION_REPORT_FILENAME

    def fail_after_success(root, payload, selected_path, **kwargs):
        path = original_write(root, payload, selected_path, **kwargs)
        if payload.get("terminal_committed") is True:
            raise OSError(errno.EIO, "post-rename fsync result uncertain")
        return path

    monkeypatch.setattr(workflow, "_write_report", fail_after_success)
    report = run_provider_migration_workflow(
        _config(),  # type: ignore[arg-type]
        tmp_path,
        max_workers=1,
        dry_run=True,
        gmail_client=client,  # type: ignore[arg-type]
        report_path=report_path,
    )

    persisted = json.loads(authoritative.read_text(encoding="utf-8"))
    assert report["report_durability_uncertain"] == (
        "[Errno 5] post-rename fsync result uncertain"
    )
    assert "report_durability_uncertain" not in persisted
    returned_payload = dict(report)
    returned_payload.pop("report_durability_uncertain")
    assert returned_payload == persisted
    assert report["ok"] is True
    assert report["report_persisted"] is True
    assert report["terminal_committed"] is True


def test_directory_fsync_failure_recovers_visible_commit_with_sanitized_warning(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from components import provider_workflow as workflow

    events: list[str] = []
    _plan, client = _install_successful_workflow_mocks(monkeypatch, events)
    authoritative = tmp_path / MIGRATION_REPORT_FILENAME
    original_fsync_directory = workflow.provider_ops._fsync_provider_directory_fd
    secret_values = (
        "durability-oauth-secret",
        "durability-authorization-secret",
        "durability-api-secret",
        "durability-url-secret",
    )

    def fail_committed_directory_fsync(parent_fd, parent_path, label):
        visible = (
            json.loads(authoritative.read_text(encoding="utf-8"))
            if authoritative.exists()
            else {}
        )
        if visible.get("terminal_committed") is True:
            raise OSError(
                errno.EIO,
                "directory fsync failed: OAUTH_TOKEN="
                f"{secret_values[0]} authorization_token={secret_values[1]} "
                f"API_TOKEN={secret_values[2]} "
                f"callback?token%3D{secret_values[3]}",
            )
        return original_fsync_directory(parent_fd, parent_path, label)

    monkeypatch.setattr(
        workflow.provider_ops,
        "_fsync_provider_directory_fd",
        fail_committed_directory_fsync,
    )
    report = run_provider_migration_workflow(
        _config(),  # type: ignore[arg-type]
        tmp_path,
        max_workers=1,
        dry_run=True,
        gmail_client=client,  # type: ignore[arg-type]
    )

    persisted = json.loads(authoritative.read_text(encoding="utf-8"))
    warning = report["report_durability_uncertain"]
    assert report["ok"] is True
    assert report["report_persisted"] is True
    assert report["terminal_committed"] is True
    assert "directory fsync failed" in warning
    assert warning.count("[REDACTED]") == len(secret_values)
    assert all(secret not in warning for secret in secret_values)
    assert "report_durability_uncertain" not in persisted
    returned_payload = dict(report)
    returned_payload.pop("report_durability_uncertain")
    assert returned_payload == persisted


def test_stale_prior_success_is_not_accepted_for_new_failed_commit(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from components import provider_workflow as workflow

    events: list[str] = []
    _plan, client = _install_successful_workflow_mocks(monkeypatch, events)
    first = run_provider_migration_workflow(
        _config(),  # type: ignore[arg-type]
        tmp_path,
        max_workers=1,
        dry_run=True,
        gmail_client=client,  # type: ignore[arg-type]
    )
    original_write = workflow._write_report

    def fail_new_success(root, payload, report_path, **kwargs):
        if payload.get("terminal_committed") is True:
            raise OSError(errno.ENOSPC, "new commit failed before rename")
        return original_write(root, payload, report_path, **kwargs)

    monkeypatch.setattr(workflow, "_write_report", fail_new_success)
    second = run_provider_migration_workflow(
        _config(),  # type: ignore[arg-type]
        tmp_path,
        max_workers=1,
        dry_run=True,
        gmail_client=client,  # type: ignore[arg-type]
    )
    persisted = json.loads(
        (tmp_path / MIGRATION_REPORT_FILENAME).read_text(encoding="utf-8")
    )

    assert first["terminal_commit_id"] != second["terminal_commit_id"]
    assert second["status"] == "failed"
    assert persisted["status"] == "finalizing"
    assert persisted["terminal_commit_id"] == second["terminal_commit_id"]
    assert persisted["terminal_commit_id"] != first["terminal_commit_id"]


def test_failed_success_publication_leaves_observed_replacement_untouched(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from components import provider_workflow as workflow

    events: list[str] = []
    _plan, client = _install_successful_workflow_mocks(monkeypatch, events)
    original_write = workflow._write_report
    authoritative = tmp_path / MIGRATION_REPORT_FILENAME
    replacement = b'{"replacement":"untouched","token":"replacement-secret"}\n'

    def replace_before_success(root, payload, report_path, **kwargs):
        if payload.get("terminal_committed") is True:
            authoritative.write_bytes(replacement)
            raise OSError(errno.EIO, "replacement race")
        return original_write(root, payload, report_path, **kwargs)

    monkeypatch.setattr(workflow, "_write_report", replace_before_success)
    report = run_provider_migration_workflow(
        _config(),  # type: ignore[arg-type]
        tmp_path,
        max_workers=1,
        dry_run=True,
        gmail_client=client,  # type: ignore[arg-type]
    )

    assert report["status"] == "failed"
    assert report["report_persisted"] is False
    assert authoritative.read_bytes() == replacement
    assert "report_quarantine" not in report
    assert "report_removal_error" not in report


@pytest.mark.parametrize("failure_point", ["discovery", "pre-export"])
def test_failure_report_write_errors_are_visible_before_and_after_mutation(
    tmp_path: Path,
    monkeypatch,
    failure_point: str,
) -> None:
    from components import provider_workflow as workflow

    events: list[str] = []

    def post_import_failure(*_args, **_kwargs):
        events.append("filters")
        raise RuntimeError("post-import filter failure")

    _plan, client = _install_successful_workflow_mocks(
        monkeypatch,
        events,
        filter_effect=post_import_failure if failure_point == "pre-export" else None,
    )
    if failure_point == "discovery":
        monkeypatch.setattr(
            workflow.provider_ops,
            "provider_preflight",
            lambda *_args, **_kwargs: (False, ["early preflight failure"]),
        )

    def fail_report_write(*_args, **_kwargs):
        raise OSError(errno.ENOSPC, f"{failure_point} report ENOSPC")

    monkeypatch.setattr(workflow, "_write_report", fail_report_write)
    report = run_provider_migration_workflow(
        _config(),  # type: ignore[arg-type]
        tmp_path,
        max_workers=1,
        gmail_client=client,  # type: ignore[arg-type]
    )

    assert report["status"] == "failed"
    assert report["report_persisted"] is False
    assert f"{failure_point} report ENOSPC" in report["report_write_error"]
    assert any("migration failure report" in issue for issue in report["issues"])
    assert not (tmp_path / MIGRATION_REPORT_FILENAME).exists()
    if failure_point == "discovery":
        assert "export" not in events
    else:
        assert "export" not in events
        assert "import" not in events


@pytest.mark.parametrize("dry_run", [True, False])
def test_terminal_report_write_failure_returns_structured_failure_without_retry(
    tmp_path: Path,
    monkeypatch,
    dry_run: bool,
) -> None:
    from components import provider_workflow as workflow

    events: list[str] = []
    write_attempts = 0
    _plan, client = _install_successful_workflow_mocks(monkeypatch, events)

    def fail_terminal_write(*_args, **_kwargs):
        nonlocal write_attempts
        write_attempts += 1
        raise OSError(errno.ENOSPC, "disk full")

    monkeypatch.setattr(workflow, "_write_report", fail_terminal_write)
    report = run_provider_migration_workflow(
        _config(),  # type: ignore[arg-type]
        tmp_path,
        max_workers=1,
        dry_run=dry_run,
        gmail_client=client,  # type: ignore[arg-type]
    )

    assert not report["ok"]
    assert report["status"] == "failed"
    assert "disk full" in report["report_write_error"]
    assert report["stages"][-1]["name"] == "final_report"
    assert report["stages"][-1]["status"] == "failed"
    assert "disk full" in report["stages"][-1]["error"]
    assert any("terminal migration report" in issue for issue in report["issues"])
    assert any("Restore writable space" in action for action in report["actions_required"])
    assert write_attempts == 1
    if dry_run:
        assert events == ["preflight", "discover", "save", "require"]
    else:
        assert report["validation"]["ok"]
        assert events[-1] == "provider-report"


def test_terminal_report_write_failure_racing_stop_returns_structured_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from components import provider_workflow as workflow

    events: list[str] = []
    write_attempts = 0
    stop_event = threading.Event()
    _plan, client = _install_successful_workflow_mocks(monkeypatch, events)

    def stop_then_fail_write(*_args, **_kwargs):
        nonlocal write_attempts
        write_attempts += 1
        stop_event.set()
        raise OSError(errno.ENOSPC, "disk full during stop")

    monkeypatch.setattr(workflow, "_write_report", stop_then_fail_write)
    report = run_provider_migration_workflow(
        _config(),  # type: ignore[arg-type]
        tmp_path,
        max_workers=1,
        dry_run=True,
        stop_event=stop_event,
        gmail_client=client,  # type: ignore[arg-type]
    )

    assert stop_event.is_set()
    assert not report["ok"]
    assert report["status"] == "failed"
    assert "disk full during stop" in report["report_write_error"]
    assert report["stages"][-1]["status"] == "failed"
    assert write_attempts == 1


def test_stop_requested_during_filter_stage_blocks_alias_activation(
    tmp_path: Path,
    monkeypatch,
) -> None:
    events: list[str] = []
    stop_event = threading.Event()

    def filters_then_stop(*_args, **_kwargs):
        events.append("filters-stop")
        stop_event.set()
        return Result("filters")

    _plan, gmail_client = _install_successful_workflow_mocks(
        monkeypatch,
        events,
        filter_effect=filters_then_stop,
    )
    _install_alias_workflow_mocks(monkeypatch, events)
    report = run_provider_migration_workflow(
        _alias_config(),  # type: ignore[arg-type]
        tmp_path,
        max_workers=1,
        stop_event=stop_event,
        gmail_client=gmail_client,  # type: ignore[arg-type]
        workspace_client=object(),  # type: ignore[arg-type]
    )

    assert not report["ok"]
    assert report["stage_order"][-1] == "provision_filters"
    assert "filters-stop" in events
    assert "export" not in events
    assert "alias-provision" not in events
    assert "validate" not in events
    assert report["workspace_aliases"]["filter_protection"][
        "verified_before_export"
    ] is False


def test_stop_requested_during_jit_filter_stage_blocks_alias_activation(
    tmp_path: Path,
    monkeypatch,
) -> None:
    events: list[str] = []
    stop_event = threading.Event()
    filter_calls = 0

    def stop_during_second_filter_reconcile(*_args, **_kwargs):
        nonlocal filter_calls
        filter_calls += 1
        events.append(f"filters-{filter_calls}")
        if filter_calls == 2:
            stop_event.set()
        return Result(f"filters-{filter_calls}")

    _plan, gmail_client = _install_successful_workflow_mocks(
        monkeypatch,
        events,
        filter_effect=stop_during_second_filter_reconcile,
    )
    _install_alias_workflow_mocks(monkeypatch, events)
    report = run_provider_migration_workflow(
        _alias_config(),  # type: ignore[arg-type]
        tmp_path,
        max_workers=1,
        stop_event=stop_event,
        gmail_client=gmail_client,  # type: ignore[arg-type]
        workspace_client=object(),  # type: ignore[arg-type]
    )

    assert not report["ok"]
    assert report["stage_order"][-1] == "reconcile_gmail_before_aliases"
    assert report["gmail"]["pre_alias_gate"]["failed_phase"] == "filters"
    assert report["gmail"]["pre_alias_gate"]["filters"]["name"] == "filters-2"
    assert filter_calls == 2
    assert "import" in events
    assert "alias-provision" not in events
    assert "validate" not in events
    assert report["workspace_aliases"]["filter_protection"][
        "verified_before_alias_activation"
    ] is False


def test_reused_alias_filters_are_verified_before_export(
    tmp_path: Path,
    monkeypatch,
) -> None:
    events: list[str] = []
    _plan, gmail_client = _install_successful_workflow_mocks(monkeypatch, events)
    _install_alias_workflow_mocks(
        monkeypatch,
        events,
        alias_plan=AliasPlan(status="reuse"),
    )

    report = run_provider_migration_workflow(
        _alias_config(),  # type: ignore[arg-type]
        tmp_path,
        max_workers=1,
        gmail_client=gmail_client,  # type: ignore[arg-type]
        workspace_client=object(),  # type: ignore[arg-type]
    )

    assert report["ok"]
    assert report["workspace_aliases"][
        "active_alias_filters_ready_before_export"
    ] is True
    assert report["workspace_aliases"]["filter_protection"] == {
        "status": "verified_before_alias_activation",
        "verified_before_export": True,
        "verified_before_alias_activation": True,
        "delivery_before_verification_proven": False,
    }
    assert report["stage_order"] == [
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
    assert events.index("filters") < events.index("export")
    assert events.index("filters") < events.index("alias-provision")
    assert events.count("labels") == 2
    assert events.count("filters") == 2
    assert report["gmail"]["pre_alias_gate"]["ok"] is True


def test_alias_activated_externally_during_export_was_filter_protected_first(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from components import provider_workflow as workflow

    events: list[str] = []
    _plan, gmail_client = _install_successful_workflow_mocks(monkeypatch, events)
    directory = PlanningDirectoryClient()

    def export_then_activate_alias(*_args, **_kwargs) -> None:
        assert directory.alias_active is False
        assert events.count("labels") == 1
        assert events.count("filters") == 1
        events.append("export")
        directory.alias_active = True
        events.append("alias-activated-externally")

    monkeypatch.setattr(
        workflow.provider_ops,
        "provider_export_all",
        export_then_activate_alias,
    )

    report = run_provider_migration_workflow(
        _alias_config(),  # type: ignore[arg-type]
        tmp_path,
        max_workers=1,
        gmail_client=gmail_client,  # type: ignore[arg-type]
        workspace_client=directory,  # type: ignore[arg-type]
    )

    assert report["ok"]
    assert report["workspace_aliases"]["planning"]["entries"][0][
        "status"
    ] == "create"
    assert report["workspace_aliases"]["provisioning"]["reused"] == [
        "old@example.com"
    ]
    assert report["workspace_aliases"]["created"] == []
    assert report["workspace_aliases"]["reused"] == ["old@example.com"]
    assert report["workspace_aliases"][
        "active_alias_filters_ready_before_export"
    ] is True
    assert events.index("labels") < events.index("filters") < events.index("export")
    assert events.index("export") < events.index("alias-activated-externally")
    assert events.count("labels") == 2
    assert events.count("filters") == 2


def test_mixed_create_and_reuse_aliases_share_one_pre_export_reconciliation(
    tmp_path: Path,
    monkeypatch,
) -> None:
    events: list[str] = []
    alias_plan = AliasPlan(
        entries=[
            {"alias": "old@example.com", "status": "reuse"},
            {"alias": "new@example.com", "status": "create"},
        ]
    )
    _plan, gmail_client = _install_successful_workflow_mocks(monkeypatch, events)
    _install_alias_workflow_mocks(
        monkeypatch,
        events,
        alias_plan=alias_plan,
        provision_effect=lambda: AliasResult(
            created=("new@example.com",),
            reused=("old@example.com",),
        ),
    )

    report = run_provider_migration_workflow(
        _alias_config(aliases=("old@example.com", "new@example.com")),  # type: ignore[arg-type]
        tmp_path,
        max_workers=2,
        gmail_client=gmail_client,  # type: ignore[arg-type]
        workspace_client=object(),  # type: ignore[arg-type]
    )

    assert report["ok"]
    assert report["workspace_aliases"]["created"] == ["new@example.com"]
    assert report["workspace_aliases"]["reused"] == ["old@example.com"]
    assert events.index("labels") < events.index("filters") < events.index("export")
    assert events.index("import") < events.index("alias-provision")
    assert events.count("labels") == 2
    assert events.count("filters") == 2


@pytest.mark.parametrize(
    "statuses",
    [
        ("create",),
        ("reuse",),
        ("reuse", "create"),
    ],
    ids=("create", "reuse", "mixed"),
)
def test_alias_live_gmail_gate_failure_stops_before_export(
    tmp_path: Path,
    monkeypatch,
    statuses: tuple[str, ...],
) -> None:
    from components import provider_workflow as workflow

    events: list[str] = []
    aliases = tuple(f"alias-{index}@example.com" for index in range(len(statuses)))
    alias_plan = AliasPlan(
        entries=[
            {"alias": alias, "status": status}
            for alias, status in zip(aliases, statuses)
        ]
    )
    _plan, gmail_client = _install_successful_workflow_mocks(monkeypatch, events)
    _install_alias_workflow_mocks(
        monkeypatch,
        events,
        alias_plan=alias_plan,
    )

    def reject_live_plan(*_args, **_kwargs) -> None:
        events.append("live-gate-rejected")
        raise RuntimeError("Gmail filter capacity or conflict gate failed")

    monkeypatch.setattr(workflow, "require_live_gmail_plan_ok", reject_live_plan)
    report = run_provider_migration_workflow(
        _alias_config(aliases=aliases),  # type: ignore[arg-type]
        tmp_path,
        max_workers=1,
        gmail_client=gmail_client,  # type: ignore[arg-type]
        workspace_client=object(),  # type: ignore[arg-type]
    )

    assert not report["ok"]
    assert report["stage_order"][-1] == "provision_labels"
    assert "live-gate-rejected" in events
    assert "labels" not in events
    assert "filters" not in events
    assert "export" not in events
    assert "alias-provision" not in events
    assert report["workspace_aliases"]["filter_protection"][
        "verified_before_export"
    ] is False


def test_alias_filter_partial_failure_is_reported_before_export(
    tmp_path: Path,
    monkeypatch,
) -> None:
    events: list[str] = []
    partial_payload = {
        "ok": False,
        "verified": False,
        "filters": [{"query": "deliveredto:old@example.com", "action": "unresolved"}],
        "issues": ["Gmail filter reconciliation failed"],
        "actions_required": ["Rerun Gmail filter reconciliation."],
    }

    def fail_with_partial_result(*_args, **_kwargs):
        events.append("filters-partial-failure")
        raise PartialCancellation(
            "Gmail filter reconciliation failed",
            PartialGmailResult(partial_payload),
        )

    _plan, gmail_client = _install_successful_workflow_mocks(
        monkeypatch,
        events,
        filter_effect=fail_with_partial_result,
    )
    _install_alias_workflow_mocks(monkeypatch, events)

    report = run_provider_migration_workflow(
        _alias_config(),  # type: ignore[arg-type]
        tmp_path,
        max_workers=1,
        gmail_client=gmail_client,  # type: ignore[arg-type]
        workspace_client=object(),  # type: ignore[arg-type]
    )

    assert not report["ok"]
    assert report["stage_order"][-1] == "provision_filters"
    assert report["gmail"]["filters"] == partial_payload
    assert partial_payload["actions_required"][0] in report["actions_required"]
    assert any(
        "No new Workspace aliases were created" in action
        for action in report["actions_required"]
    )
    assert "export" not in events
    assert "alias-provision" not in events


def test_alias_workflow_gates_conflicts_before_mutation_and_orders_activation_last(
    tmp_path: Path,
    monkeypatch,
) -> None:
    events = []
    _plan, gmail_client = _install_successful_workflow_mocks(monkeypatch, events)
    _install_alias_workflow_mocks(monkeypatch, events)

    report = run_provider_migration_workflow(
        _alias_config(),  # type: ignore[arg-type]
        tmp_path,
        max_workers=2,
        gmail_client=gmail_client,  # type: ignore[arg-type]
        workspace_client=object(),  # type: ignore[arg-type]
    )

    assert report["ok"]
    assert report["stage_order"] == [
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
    assert events.index("alias-discover") < events.index("save")
    assert events.index("labels") < events.index("filters") < events.index("export")
    assert events.index("filters") < events.index("alias-provision")
    assert events.index("import") < events.index("alias-provision")
    assert events[-1] == "alias-verify"
    assert report["workspace_aliases"][
        "active_alias_filters_ready_before_export"
    ] is True
    assert report["workspace_aliases"]["created"] == ["old@example.com"]
    assert report["workspace_aliases"]["reused"] == []
    assert report["artifacts"]["workspace_alias_plan"] == str(
        tmp_path / "workspace-alias-plan.json"
    )


def test_alias_discovery_conflict_stops_before_any_mutation(
    tmp_path: Path,
    monkeypatch,
) -> None:
    events = []
    _plan, gmail_client = _install_successful_workflow_mocks(monkeypatch, events)
    conflict = "old@example.com is owned by another Workspace user"
    _install_alias_workflow_mocks(
        monkeypatch,
        events,
        alias_plan=AliasPlan(
            ok=False,
            conflicts=(conflict,),
            actions_required=("Resolve the owner conflict.",),
        ),
    )

    report = run_provider_migration_workflow(
        _alias_config(),  # type: ignore[arg-type]
        tmp_path,
        max_workers=1,
        gmail_client=gmail_client,  # type: ignore[arg-type]
        workspace_client=object(),  # type: ignore[arg-type]
    )

    assert not report["ok"]
    assert report["stage_order"] == ["discover_plan", "discover_aliases"]
    assert report["workspace_aliases"]["conflicted"] == ["old@example.com"]
    assert conflict in report["issues"]
    assert "save" not in events
    assert not any(
        name in events
        for name in ("export", "labels", "import", "filters", "alias-provision")
    )


def test_alias_dry_run_persists_both_plans_without_remote_mutations(
    tmp_path: Path,
    monkeypatch,
) -> None:
    events = []
    _plan, gmail_client = _install_successful_workflow_mocks(monkeypatch, events)
    _install_alias_workflow_mocks(monkeypatch, events)

    report = run_provider_migration_workflow(
        _alias_config(),  # type: ignore[arg-type]
        tmp_path,
        max_workers=1,
        dry_run=True,
        gmail_client=gmail_client,  # type: ignore[arg-type]
        workspace_client=object(),  # type: ignore[arg-type]
    )

    assert report["ok"]
    assert report["workspace_aliases"]["filter_protection"] == {
        "status": "pending",
        "verified_before_export": False,
        "verified_before_alias_activation": False,
        "delivery_before_verification_proven": False,
    }
    assert report["stage_order"] == [
        "discover_plan",
        "discover_aliases",
        "persist_plan",
        "persist_alias_plan",
        "final_report",
    ]
    assert events == [
        "preflight",
        "discover",
        "alias-discover",
        "save",
        "require",
        "alias-save",
    ]
    assert not any(
        name in events
        for name in ("export", "labels", "import", "filters", "alias-provision")
    )


def test_workspace_alias_plan_is_immutable_but_allows_create_to_reuse_resume(
    tmp_path: Path,
) -> None:
    client = PlanningDirectoryClient()
    initial = discover_workspace_alias_plan(
        client,  # type: ignore[arg-type]
        "merged@example.com",
        ("old@example.com",),
    )
    assert initial.ok
    assert initial.entries[0].status == "create"

    persisted = _save_workspace_alias_plan(tmp_path, initial)
    plan_path = tmp_path / "workspace-alias-plan.json"
    assert plan_path.is_file()
    assert stat.S_IMODE(plan_path.stat().st_mode) == 0o600

    client.alias_active = True
    resumed = discover_workspace_alias_plan(
        client,  # type: ignore[arg-type]
        "merged@example.com",
        ("old@example.com",),
    )
    assert resumed.ok
    assert resumed.entries[0].status == "reuse"
    assert resumed.plan_sha256 != initial.plan_sha256
    authoritative = _save_workspace_alias_plan(tmp_path, resumed)
    assert authoritative.plan_sha256 == persisted.plan_sha256

    changed_intent = discover_workspace_alias_plan(
        client,  # type: ignore[arg-type]
        "merged@example.com",
        ("different@example.com",),
    )
    with pytest.raises(RuntimeError, match="different target user or alias set"):
        _save_workspace_alias_plan(tmp_path, changed_intent)


def test_workspace_alias_plan_create_vs_reuse_race_keeps_one_authoritative_plan(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from components import provider_workflow as workflow

    client = PlanningDirectoryClient()
    create_plan = discover_workspace_alias_plan(
        client,  # type: ignore[arg-type]
        "merged@example.com",
        ("old@example.com",),
    )
    client.alias_active = True
    reuse_plan = discover_workspace_alias_plan(
        client,  # type: ignore[arg-type]
        "merged@example.com",
        ("old@example.com",),
    )
    assert create_plan.intent_sha256 == reuse_plan.intent_sha256
    assert create_plan.plan_sha256 != reuse_plan.plan_sha256

    barrier = threading.Barrier(2)
    real_create_once = workflow.provider_ops._atomic_json_create_once

    def synchronized_create_once(path: Path, payload: dict) -> bool:
        barrier.wait(timeout=5)
        return real_create_once(path, payload)

    monkeypatch.setattr(
        workflow.provider_ops,
        "_atomic_json_create_once",
        synchronized_create_once,
    )
    with ThreadPoolExecutor(max_workers=2) as executor:
        returned = list(
            executor.map(
                lambda plan: _save_workspace_alias_plan(tmp_path, plan),
                (create_plan, reuse_plan),
            )
        )

    persisted = _load_workspace_alias_plan(tmp_path)
    assert {plan.plan_sha256 for plan in returned} == {persisted.plan_sha256}
    assert persisted.plan_sha256 in {
        create_plan.plan_sha256,
        reuse_plan.plan_sha256,
    }
    plan_path = tmp_path / "workspace-alias-plan.json"
    assert stat.S_IMODE(plan_path.stat().st_mode) == 0o600
    assert plan_path.stat().st_nlink == 1


def test_workspace_alias_v1_plan_preserves_actionable_migration_error(
    tmp_path: Path,
) -> None:
    path = tmp_path / "workspace-alias-plan.json"
    path.write_text('{"version": 1}\n', encoding="utf-8")
    path.chmod(0o600)

    with pytest.raises(
        RuntimeError,
        match=(
            "version 1 is not bound to an immutable target user ID; "
            "run preflight with a new staging directory"
        ),
    ):
        _load_workspace_alias_plan(tmp_path)


def test_alias_partial_failure_after_import_is_reported_and_resumable(
    tmp_path: Path,
    monkeypatch,
) -> None:
    events = []
    attempts = 0

    def provision_effect():
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            partial = AliasResult(
                ok=False,
                created=("old@example.com",),
                conflicted=("other@example.com",),
                issues=("Directory write failed",),
                actions_required=("Fix Directory authorization.",),
            )
            raise AliasProvisionFailure("redacted alias failure", partial)
        return AliasResult(
            created=("other@example.com",),
            reused=("old@example.com",),
        )

    _plan, gmail_client = _install_successful_workflow_mocks(monkeypatch, events)
    _install_alias_workflow_mocks(
        monkeypatch,
        events,
        provision_effect=provision_effect,
    )

    first = run_provider_migration_workflow(
        _alias_config(),  # type: ignore[arg-type]
        tmp_path,
        max_workers=1,
        gmail_client=gmail_client,  # type: ignore[arg-type]
        workspace_client=object(),  # type: ignore[arg-type]
    )
    second = run_provider_migration_workflow(
        _alias_config(),  # type: ignore[arg-type]
        tmp_path,
        max_workers=1,
        gmail_client=gmail_client,  # type: ignore[arg-type]
        workspace_client=object(),  # type: ignore[arg-type]
    )

    assert not first["ok"]
    assert first["stage_order"][-1] == "provision_aliases"
    assert first["workspace_aliases"]["created"] == ["old@example.com"]
    assert first["workspace_aliases"]["conflicted"] == ["other@example.com"]
    assert any(
        "Historical imports" in action and "aliases already" in action
        for action in first["actions_required"]
    )
    assert second["ok"]
    assert attempts == 2
    assert second["workspace_aliases"]["created"] == ["other@example.com"]
    assert second["workspace_aliases"]["reused"] == ["old@example.com"]


def test_first_alias_created_cancellation_persists_partial_result_without_new_remote_work(
    tmp_path: Path,
    monkeypatch,
) -> None:
    events: list[str] = []
    stop_event = threading.Event()
    partial = AliasResult(
        ok=False,
        created=("old@example.com",),
        conflicted=("other@example.com",),
        issues=("Workspace alias provisioning cancelled: stop requested",),
        actions_required=(
            "Rerun Workspace alias provisioning to resolve other@example.com.",
        ),
    )

    def cancel_after_first_alias():
        stop_event.set()
        raise PartialCancellation(
            "Workspace alias provisioning cancelled: stop requested",
            partial,
        )

    _plan, gmail_client = _install_successful_workflow_mocks(
        monkeypatch,
        events,
    )
    _install_alias_workflow_mocks(
        monkeypatch,
        events,
        provision_effect=cancel_after_first_alias,
    )

    report = run_provider_migration_workflow(
        _alias_config(),  # type: ignore[arg-type]
        tmp_path,
        max_workers=1,
        stop_event=stop_event,
        gmail_client=gmail_client,  # type: ignore[arg-type]
        workspace_client=object(),  # type: ignore[arg-type]
    )

    assert not report["ok"]
    assert report["status"] == "failed"
    assert report["stage_order"][-1] == "provision_aliases"
    assert report["workspace_aliases"]["provisioning"] == partial.to_dict()
    assert report["workspace_aliases"]["created"] == ["old@example.com"]
    assert report["workspace_aliases"]["conflicted"] == ["other@example.com"]
    assert partial.actions_required[0] in report["actions_required"]
    assert "validate" not in events
    assert "alias-verify" not in events
    assert "provider-report" not in events
    persisted = json.loads((tmp_path / MIGRATION_REPORT_FILENAME).read_text())
    assert persisted["workspace_aliases"]["provisioning"] == partial.to_dict()
    assert persisted["workspace_aliases"]["created"] == ["old@example.com"]
    assert partial.actions_required[0] in persisted["actions_required"]


def test_workspace_admin_token_is_not_serialized_to_report(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from components import provider_workflow as workflow

    secret = "workspace-admin-super-secret"
    monkeypatch.setenv("WORKSPACE_ALIAS_TOKEN", secret)
    auth = WorkspaceAliasAdminAuthConfig(
        method="xoauth2",
        admin_email="admin@example.com",
        env_var="WORKSPACE_ALIAS_TOKEN",
    )
    config = _alias_config(admin_auth=auth)
    events = []
    _plan, gmail_client = _install_successful_workflow_mocks(monkeypatch, events)
    _install_alias_workflow_mocks(monkeypatch, events)

    def factory(access_token, **kwargs):
        assert access_token == secret
        assert kwargs["retry_max_attempts"] == 7
        return object()

    monkeypatch.setattr(workflow, "build_workspace_directory_client_from_token", factory)
    report = run_provider_migration_workflow(
        config,  # type: ignore[arg-type]
        tmp_path,
        max_workers=1,
        dry_run=True,
        gmail_client=gmail_client,  # type: ignore[arg-type]
    )

    assert report["ok"]
    assert secret not in json.dumps(report)
    assert secret not in (tmp_path / MIGRATION_REPORT_FILENAME).read_text()


def test_workspace_service_account_client_uses_configured_retry_budget(
    monkeypatch,
) -> None:
    from components import provider_workflow as workflow

    auth = WorkspaceAliasAdminAuthConfig(
        method="service_account",
        credentials_file="workspace-service-account.json",
        delegated_admin="admin@example.com",
    )
    config = _alias_config(admin_auth=auth)
    expected = object()
    stop_event = threading.Event()

    def factory(credentials_file, **kwargs):
        assert credentials_file == "workspace-service-account.json"
        assert kwargs["delegated_admin"] == "admin@example.com"
        assert kwargs["retry_max_attempts"] == 7
        assert kwargs["stop_event"] is stop_event
        return expected

    monkeypatch.setattr(
        workflow,
        "build_workspace_directory_client_from_service_account",
        factory,
    )

    assert (
        workspace_directory_client_if_required(  # type: ignore[arg-type]
            config,
            stop_event=stop_event,
        )
        is expected
    )
