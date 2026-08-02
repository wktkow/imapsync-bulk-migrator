from __future__ import annotations

import copy
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from components.workspace_aliases import (
    MAX_WORKSPACE_USER_ALIASES,
    WORKSPACE_DIRECTORY_SCOPES,
    WorkspaceAliasPlan,
    WorkspaceAliasProvisionError,
    WorkspaceAuthenticationError,
    WorkspaceAuthorizationIdentity,
    WorkspaceDirectoryApiError,
    WorkspaceDirectoryCancelledError,
    WorkspaceDirectoryClient,
    WorkspaceDirectoryGroup,
    WorkspaceDirectoryUser,
    WorkspaceDomain,
    WorkspaceUserAlias,
    build_workspace_directory_client_from_service_account,
    build_workspace_directory_client_from_token,
    canonical_workspace_alias_email,
    canonical_workspace_email,
    discover_workspace_alias_plan,
    provision_workspace_aliases,
    verify_workspace_aliases,
)


TARGET = "maila@example.com"
CUSTOMER = "C012345"


class FakeDirectory:
    def __init__(self) -> None:
        self.authorization_identity = WorkspaceAuthorizationIdentity(
            "xoauth2",
            "admin@example.com",
        )
        self.target_aliases: set[str] = {"mailb@example.com", "unrelated@example.com"}
        self.target_user_id = "target-id"
        self.target_non_editable: set[str] = set()
        self.other_users: list[WorkspaceDirectoryUser] = []
        self.groups: list[WorkspaceDirectoryGroup] = []
        self.domains = {
            "example.com": WorkspaceDomain("example.com", "primary", True),
        }
        self.domain_aliases: dict[str, WorkspaceDomain] = {}
        self.insert_calls: list[str] = []
        self.fail_once: dict[str, WorkspaceDirectoryApiError] = {}
        self.race_to_target: set[str] = set()
        self.race_to_user: dict[str, WorkspaceDirectoryUser] = {}
        self.fail_get_user_once: WorkspaceDirectoryApiError | None = None

    def _target(self) -> WorkspaceDirectoryUser:
        return WorkspaceDirectoryUser(
            self.target_user_id,
            TARGET,
            CUSTOMER,
            tuple(self.target_aliases),
            tuple(self.target_non_editable),
        )

    def get_user(self, email: str):
        if self.fail_get_user_once is not None:
            failure = self.fail_get_user_once
            self.fail_get_user_once = None
            raise failure
        target = self._target()
        if email == target.user_id:
            return target
        email = canonical_workspace_email(email)
        if email == target.primary_email or email in target.aliases or email in target.non_editable_aliases:
            return target
        for user in self.other_users:
            if user.alias_kind(email) is not None:
                return user
        return None

    def list_user_aliases(self, target_user: str):
        assert target_user == self.target_user_id
        return tuple(
            WorkspaceUserAlias(alias, TARGET, self.target_user_id)
            for alias in sorted(self.target_aliases)
        )

    def get_group(self, email: str):
        email = canonical_workspace_email(email)
        for group in self.groups:
            if group.alias_kind(email) is not None:
                return group
        return None

    def get_domain(self, customer: str, domain: str):
        assert customer == CUSTOMER
        return self.domains.get(domain.casefold())

    def get_domain_alias(self, customer: str, domain: str):
        assert customer == CUSTOMER
        return self.domain_aliases.get(domain.casefold())

    def insert_user_alias(
        self,
        target_user: str,
        alias: str,
        *,
        expected_user_id: str | None = None,
        expected_primary_email: str | None = None,
    ):
        assert target_user == self.target_user_id
        assert expected_user_id == self.target_user_id
        assert canonical_workspace_email(expected_primary_email) == TARGET
        alias = canonical_workspace_email(alias)
        self.insert_calls.append(alias)
        if alias in self.race_to_target:
            self.race_to_target.remove(alias)
            self.target_aliases.add(alias)
            raise WorkspaceDirectoryApiError(
                "Workspace Directory create user alias failed: HTTP 409",
                operation="create user alias",
                status_code=409,
            )
        if alias in self.race_to_user:
            self.other_users.append(self.race_to_user.pop(alias))
            raise WorkspaceDirectoryApiError(
                "Workspace Directory create user alias failed: HTTP 409",
                operation="create user alias",
                status_code=409,
            )
        failure = self.fail_once.pop(alias, None)
        if failure is not None:
            raise failure
        self.target_aliases.add(alias)
        return WorkspaceUserAlias(alias, TARGET, self.target_user_id)


class Response:
    def __init__(
        self,
        status_code: int,
        payload: Any,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status_code = status_code
        self.payload = payload
        self.headers = dict(headers or {})

    def json(self):
        if isinstance(self.payload, Exception):
            raise self.payload
        return copy.deepcopy(self.payload)


class QueueSession:
    def __init__(self, responses: list[Response]) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def request(self, method: str, url: str, **kwargs: Any):
        self.calls.append({"method": method, "url": url, **copy.deepcopy(kwargs)})
        if not self.responses:
            raise AssertionError("unexpected Directory API request")
        return self.responses.pop(0)


def _plan(directory: FakeDirectory, *aliases: str) -> WorkspaceAliasPlan:
    return discover_workspace_alias_plan(  # type: ignore[arg-type]
        directory,
        TARGET,
        aliases,
    )


def test_email_canonicalization_is_case_insensitive_and_idna_exact() -> None:
    assert canonical_workspace_email("MailB@EXAMPLE.com") == "mailb@example.com"
    assert canonical_workspace_email("User@bücher.example") == "user@xn--bcher-kva.example"
    assert canonical_workspace_email("User@faß.de") == "user@xn--fa-hia.de"
    with pytest.raises(ValueError, match="leading or trailing"):
        canonical_workspace_email(" mailb@example.com")
    with pytest.raises(ValueError, match="invalid local"):
        canonical_workspace_email("a..b@example.com")
    with pytest.raises(ValueError, match="invalid domain"):
        canonical_workspace_email("user@fa\u200c.de")


def test_workspace_email_enforces_254_ascii_octets_after_idna() -> None:
    local = "a" * 64
    domain_189 = ".".join(("b" * 63, "c" * 63, "d" * 61))
    domain_190 = ".".join(("b" * 63, "c" * 63, "d" * 62))

    assert len(canonical_workspace_email(f"{local}@{domain_189}").encode("ascii")) == 254
    with pytest.raises(ValueError, match="254 ASCII octets"):
        canonical_workspace_email(f"{local}@{domain_190}")

    expanded_domain = ".".join(("é" * 45,) * 4)
    with pytest.raises(ValueError, match="254 ASCII octets"):
        canonical_workspace_email(f"{local}@{expanded_domain}")

    normalized_domain = ".".join((("e\u0301" * 45),) * 3)
    long_input = f"{local}@{normalized_domain}"
    assert len(long_input) > 254
    assert len(canonical_workspace_email(long_input).encode("ascii")) <= 254


@pytest.mark.parametrize(
    "address",
    [
        "sales+tag@example.com",
        "ümlaut@example.com",
        "abuse@example.com",
        "POSTMASTER@example.com",
    ],
)
def test_workspace_alias_local_parts_reject_unsupported_and_reserved_addresses(
    address: str,
) -> None:
    with pytest.raises(ValueError, match="local part|reserved"):
        canonical_workspace_alias_email(address)

    directory = FakeDirectory()
    with pytest.raises(ValueError, match="local part|reserved"):
        _plan(directory, address)
    assert directory.insert_calls == []


def test_directory_rest_client_uses_expected_resources_and_create_only_post() -> None:
    session = QueueSession(
        [
            Response(
                200,
                {
                    "id": "u1",
                    "primaryEmail": TARGET,
                    "customerId": CUSTOMER,
                    "aliases": ["mailb@example.com"],
                },
            ),
            Response(
                200,
                {
                    "aliases": [
                        {"id": "u1", "primaryEmail": TARGET, "alias": "mailb@example.com"}
                    ]
                },
            ),
            Response(
                200,
                {
                    "id": "g1",
                    "email": "team@example.com",
                    "aliases": ["sales@example.com"],
                },
            ),
            Response(
                200,
                {
                    "domainName": "example.com",
                    "isPrimary": True,
                    "verified": True,
                },
            ),
            Response(
                200,
                {
                    "domainAliasName": "alias.example.com",
                    "parentDomainName": "example.com",
                    "verified": True,
                },
            ),
            Response(
                201,
                {"id": "u1", "primaryEmail": TARGET, "alias": "mailc@example.com"},
            ),
        ]
    )
    client = build_workspace_directory_client_from_token(
        "top-secret-token",
        admin_email="admin@example.com",
        session=session,
    )

    assert client.get_user(TARGET).primary_email == TARGET  # type: ignore[union-attr]
    assert client.list_user_aliases("u1")[0].alias == "mailb@example.com"
    assert client.get_group("sales@example.com").primary_email == "team@example.com"  # type: ignore[union-attr]
    assert client.get_domain(CUSTOMER, "example.com").kind == "primary"  # type: ignore[union-attr]
    assert client.get_domain_alias(CUSTOMER, "alias.example.com").kind == "domain_alias"  # type: ignore[union-attr]
    assert (
        client.insert_user_alias(
            "u1",
            "mailc@example.com",
            expected_user_id="u1",
            expected_primary_email=TARGET,
        ).alias
        == "mailc@example.com"
    )

    assert [call["method"] for call in session.calls] == ["GET", "GET", "GET", "GET", "GET", "POST"]
    assert session.calls[-1]["json"] == {"alias": "mailc@example.com"}
    assert "/users/u1/aliases" in session.calls[1]["url"]
    assert "/users/u1/aliases" in session.calls[-1]["url"]
    assert session.calls[0]["headers"]["Authorization"] == "Bearer top-secret-token"
    assert "top-secret-token" not in repr(client)


@pytest.mark.parametrize("field", ["aliases", "nonEditableAliases"])
@pytest.mark.parametrize(
    "malformed",
    [
        "mailb@example.com",
        {"mailb@example.com": True},
        [{"alias": "mailb@example.com"}],
    ],
)
def test_directory_user_rejects_non_string_alias_arrays(
    field: str,
    malformed: Any,
) -> None:
    payload = {
        "id": "opaque-user-id",
        "primaryEmail": TARGET,
        "customerId": CUSTOMER,
        field: malformed,
    }
    client = build_workspace_directory_client_from_token(
        "token",
        admin_email="admin@example.com",
        session=QueueSession([Response(200, payload)]),
    )

    with pytest.raises(WorkspaceDirectoryApiError, match="invalid resource") as exc_info:
        client.get_user(TARGET)

    assert "mailb@example.com" not in str(exc_info.value)


@pytest.mark.parametrize(
    ("resource_kind", "field"),
    [
        ("user", "aliases"),
        ("user", "nonEditableAliases"),
        ("group", "aliases"),
        ("group", "nonEditableAliases"),
    ],
)
def test_directory_resources_reject_explicit_null_alias_arrays(
    resource_kind: str,
    field: str,
) -> None:
    if resource_kind == "user":
        payload = {
            "id": "opaque-user-id",
            "primaryEmail": TARGET,
            "customerId": CUSTOMER,
            field: None,
        }
    else:
        payload = {
            "id": "opaque-group-id",
            "email": "team@example.com",
            field: None,
        }
    client = build_workspace_directory_client_from_token(
        "token",
        admin_email="admin@example.com",
        session=QueueSession([Response(200, payload)]),
    )

    with pytest.raises(WorkspaceDirectoryApiError, match="invalid resource"):
        if resource_kind == "user":
            client.get_user(TARGET)
        else:
            client.get_group("team@example.com")


@pytest.mark.parametrize("resource_kind", ["user", "group"])
def test_directory_resources_allow_missing_alias_arrays(resource_kind: str) -> None:
    if resource_kind == "user":
        payload = {
            "id": "opaque-user-id",
            "primaryEmail": TARGET,
            "customerId": CUSTOMER,
        }
    else:
        payload = {
            "id": "opaque-group-id",
            "email": "team@example.com",
        }
    client = build_workspace_directory_client_from_token(
        "token",
        admin_email="admin@example.com",
        session=QueueSession([Response(200, payload)]),
    )

    resource = (
        client.get_user(TARGET)
        if resource_kind == "user"
        else client.get_group("team@example.com")
    )

    assert resource is not None
    assert resource.aliases == ()
    assert resource.non_editable_aliases == ()


def test_malformed_user_alias_mapping_cannot_false_verify_alias() -> None:
    directory = FakeDirectory()
    directory.target_aliases.clear()
    plan = _plan(directory, "new@example.com")
    client = build_workspace_directory_client_from_token(
        "token",
        admin_email="admin@example.com",
        session=QueueSession(
            [
                Response(
                    200,
                    {
                        "id": directory.target_user_id,
                        "primaryEmail": TARGET,
                        "customerId": CUSTOMER,
                        "aliases": {"new@example.com": True},
                    },
                )
            ]
        ),
    )

    with pytest.raises(WorkspaceDirectoryApiError, match="invalid resource"):
        verify_workspace_aliases(client, plan)


def test_null_alias_array_error_propagates_through_verification() -> None:
    directory = FakeDirectory()
    directory.target_aliases.clear()
    plan = _plan(directory, "new@example.com")
    client = build_workspace_directory_client_from_token(
        "token",
        admin_email="admin@example.com",
        session=QueueSession(
            [
                Response(
                    200,
                    {
                        "id": directory.target_user_id,
                        "primaryEmail": TARGET,
                        "customerId": CUSTOMER,
                        "aliases": None,
                    },
                )
            ]
        ),
    )

    with pytest.raises(WorkspaceDirectoryApiError, match="invalid resource"):
        verify_workspace_aliases(client, plan)


def test_directory_group_rejects_alias_object_entries() -> None:
    client = build_workspace_directory_client_from_token(
        "token",
        admin_email="admin@example.com",
        session=QueueSession(
            [
                Response(
                    200,
                    {
                        "id": "opaque-group-id",
                        "email": "team@example.com",
                        "aliases": [{"alias": "sales@example.com"}],
                    },
                )
            ]
        ),
    )

    with pytest.raises(WorkspaceDirectoryApiError, match="invalid resource"):
        client.get_group("sales@example.com")


def test_directory_errors_are_scope_specific_and_redacted() -> None:
    token = "do-not-leak-token"
    session = QueueSession(
        [
            Response(
                403,
                {
                    "error": {
                        "message": token,
                        "errors": [{"reason": token}],
                    }
                },
            )
        ]
    )
    client = build_workspace_directory_client_from_token(
        token,
        admin_email="admin@example.com",
        session=session,
    )
    with pytest.raises(WorkspaceDirectoryApiError) as exc_info:
        client.get_group("team@example.com")
    message = str(exc_info.value)
    assert "admin.directory.group.readonly" in message
    assert token not in message
    assert "error" not in message.casefold()


def test_directory_retries_structured_403_quota_with_retry_after() -> None:
    secret = "must-not-appear"
    delays: list[float] = []
    session = QueueSession(
        [
            Response(
                403,
                {
                    "error": {
                        "errors": [{"reason": "rateLimitExceeded"}],
                        "message": secret,
                    }
                },
                {"Retry-After": "2"},
            ),
            Response(200, {"id": "g1", "email": "team@example.com"}),
        ]
    )
    client = build_workspace_directory_client_from_token(
        "token",
        admin_email="admin@example.com",
        session=session,
        retry_max_attempts=2,
        sleep_fn=delays.append,
        random_fn=lambda: 0.0,
    )

    assert client.get_group("team@example.com").group_id == "g1"  # type: ignore[union-attr]
    assert len(session.calls) == 2
    assert delays == [2.0]
    assert secret not in repr(client)


def test_directory_rate_limited_post_stops_during_backoff_without_second_request() -> None:
    class StopDuringBackoff:
        def __init__(self) -> None:
            self.stopped = False
            self.waits: list[float] = []

        def is_set(self) -> bool:
            return self.stopped

        def wait(self, delay: float) -> bool:
            self.waits.append(delay)
            self.stopped = True
            return True

    stop_event = StopDuringBackoff()
    session = QueueSession(
        [Response(429, {"error": {}}, {"Retry-After": "6"})]
    )
    client = build_workspace_directory_client_from_token(
        "token",
        admin_email="admin@example.com",
        session=session,
        retry_max_attempts=5,
        stop_event=stop_event,
    )

    with pytest.raises(
        WorkspaceDirectoryCancelledError,
        match="create user alias cancelled",
    ) as exc_info:
        client.insert_user_alias(
            "u1",
            "new@example.com",
            expected_user_id="u1",
            expected_primary_email=TARGET,
        )

    assert exc_info.value.operation == "create user alias"
    assert exc_info.value.to_dict()["error"] == "workspace_directory_cancelled"
    assert [call["method"] for call in session.calls] == ["POST"]
    assert stop_event.waits == [6.0]


def test_directory_stop_during_token_resolution_blocks_http_request() -> None:
    class StopEvent:
        stopped = False

        def is_set(self) -> bool:
            return self.stopped

    stop_event = StopEvent()
    session = QueueSession([])

    def token_provider() -> str:
        stop_event.stopped = True
        return "token"

    client = WorkspaceDirectoryClient(
        token_provider,
        authorization_identity=WorkspaceAuthorizationIdentity(
            "service_account",
            "admin@example.com",
            "service@example.iam.gserviceaccount.com",
        ),
        session=session,
        stop_event=stop_event,
    )

    with pytest.raises(
        WorkspaceDirectoryCancelledError,
        match="get group identity cancelled",
    ):
        client.get_group("team@example.com")

    assert session.calls == []


def test_directory_exhausted_quota_403_is_not_mislabeled_as_scope_denial() -> None:
    secret = "response-secret"
    session = QueueSession(
        [
            Response(
                403,
                {
                    "error": {
                        "errors": [{"reason": "userRateLimitExceeded"}],
                        "message": secret,
                    }
                },
            )
        ]
    )
    client = build_workspace_directory_client_from_token(
        "token",
        admin_email="admin@example.com",
        session=session,
        retry_max_attempts=1,
    )

    with pytest.raises(WorkspaceDirectoryApiError) as exc_info:
        client.get_group("team@example.com")
    error = exc_info.value
    assert error.reasons == ("userRateLimitExceeded",)
    assert error.retryable
    assert "rate or quota limited" in str(error)
    assert "permission denied" not in str(error)
    assert secret not in str(error)


def test_directory_daily_quota_403_is_classified_but_not_retried() -> None:
    session = QueueSession(
        [
            Response(
                403,
                {"error": {"errors": [{"reason": "dailyLimitExceeded"}]}},
            )
        ]
    )
    client = build_workspace_directory_client_from_token(
        "token",
        admin_email="admin@example.com",
        session=session,
        retry_max_attempts=5,
        sleep_fn=lambda _delay: None,
    )

    with pytest.raises(WorkspaceDirectoryApiError) as exc_info:
        client.get_group("team@example.com")
    assert not exc_info.value.retryable
    assert "rate or quota limited" in str(exc_info.value)
    assert "permission denied" not in str(exc_info.value)
    assert len(session.calls) == 1


def test_directory_does_not_repeat_ambiguous_create_post() -> None:
    delays: list[float] = []
    session = QueueSession(
        [
            Response(
                503,
                {"error": {"errors": [{"reason": "backendError"}]}},
            )
        ]
    )
    client = build_workspace_directory_client_from_token(
        "token",
        admin_email="admin@example.com",
        session=session,
        retry_max_attempts=5,
        sleep_fn=delays.append,
    )

    with pytest.raises(WorkspaceDirectoryApiError) as exc_info:
        client.insert_user_alias(
            "u1",
            "new@example.com",
            expected_user_id="u1",
            expected_primary_email=TARGET,
        )
    assert exc_info.value.mutation_outcome_uncertain
    assert len(session.calls) == 1
    assert delays == []


def test_plan_classifies_reuse_create_user_and_group_conflicts_deterministically() -> None:
    directory = FakeDirectory()
    directory.other_users.append(
        WorkspaceDirectoryUser(
            "other-id",
            "person@example.com",
            CUSTOMER,
            ("former@example.com",),
        )
    )
    directory.groups.append(
        WorkspaceDirectoryGroup(
            "group-id",
            "team@example.com",
            ("sales@example.com",),
        )
    )
    plan = _plan(
        directory,
        "MAILB@example.com",
        "mailc@example.com",
        "former@example.com",
        "sales@example.com",
    )
    entries = {item.alias: item for item in plan.entries}

    assert entries["mailb@example.com"].status == "reuse"
    assert entries["mailc@example.com"].status == "create"
    assert entries["former@example.com"].status == "conflict"
    assert entries["former@example.com"].owner_kind == "user_alias"
    assert entries["sales@example.com"].status == "conflict"
    assert entries["sales@example.com"].owner_kind == "group_alias"
    assert "unrelated@example.com" in plan.existing_target_aliases
    assert plan.counts == {
        "create": 1,
        "reuse": 1,
        "conflict": 2,
        "existing_target_aliases": 2,
    }


def test_verified_domain_alias_is_reuse_only_and_unverified_or_unknown_conflicts() -> None:
    directory = FakeDirectory()
    directory.domain_aliases["brand.example"] = WorkspaceDomain(
        "brand.example",
        "domain_alias",
        True,
        "example.com",
    )
    directory.target_non_editable.add("maila@brand.example")
    directory.domains["unverified.example"] = WorkspaceDomain(
        "unverified.example",
        "secondary",
        False,
    )
    plan = _plan(
        directory,
        "maila@brand.example",
        "other@brand.example",
        "new@unverified.example",
        "new@outside.example",
    )
    entries = {item.alias: item for item in plan.entries}

    assert entries["maila@brand.example"].status == "reuse"
    assert entries["maila@brand.example"].owner_kind == "target_non_editable_alias"
    assert "automatically managed" in " ".join(entries["other@brand.example"].conflicts)
    assert "not verified" in " ".join(entries["new@unverified.example"].conflicts)
    assert "not registered" in " ".join(entries["new@outside.example"].conflicts)


def test_target_and_customer_binding_conflicts_before_create() -> None:
    directory = FakeDirectory()
    plan = discover_workspace_alias_plan(  # type: ignore[arg-type]
        directory,
        "mailb@example.com",
        ["new@example.com"],
    )
    assert not plan.ok
    assert "different primary user" in " ".join(plan.conflicts)

    plan = discover_workspace_alias_plan(  # type: ignore[arg-type]
        directory,
        TARGET,
        ["new@example.com"],
        customer="WRONG",
    )
    assert not plan.ok
    assert "does not match target user customer" in " ".join(plan.conflicts)


def test_plan_enforces_30_alias_limit_before_any_mutation() -> None:
    directory = FakeDirectory()
    directory.target_aliases = {
        f"old{index}@example.com" for index in range(MAX_WORKSPACE_USER_ALIASES - 1)
    }
    plan = _plan(directory, "new1@example.com", "new2@example.com")
    assert not plan.ok
    assert all(entry.status == "conflict" for entry in plan.entries)
    assert "maximum 30" in " ".join(plan.conflicts)
    assert directory.insert_calls == []


def test_plan_round_trip_is_canonical_and_tamper_evident() -> None:
    plan = _plan(FakeDirectory(), "mailb@example.com", "mailc@example.com")
    payload = plan.to_dict()
    assert WorkspaceAliasPlan.from_dict(payload).to_dict() == payload
    assert len(plan.intent_sha256) == len(plan.discovery_sha256) == len(plan.plan_sha256) == 64

    tampered = copy.deepcopy(payload)
    tampered["entries"][1]["status"] = "reuse"
    with pytest.raises(ValueError):
        WorkspaceAliasPlan.from_dict(tampered)

    legacy = copy.deepcopy(payload)
    legacy["version"] = 1
    legacy.pop("target_user_id")
    with pytest.raises(ValueError, match="not bound to an immutable target user ID"):
        WorkspaceAliasPlan.from_dict(legacy)


def test_plan_intent_and_writes_are_bound_to_immutable_target_user_id() -> None:
    directory = FakeDirectory()
    directory.target_aliases.clear()
    plan = _plan(directory, "new@example.com")
    assert plan.target_user_id == "target-id"
    assert plan.to_dict()["target_user_id"] == "target-id"

    directory.target_user_id = "replacement-id"
    replacement = _plan(directory, "new@example.com")
    assert replacement.intent_sha256 != plan.intent_sha256

    result = provision_workspace_aliases(directory, plan)  # type: ignore[arg-type]
    assert not result.ok
    assert "different immutable user ID" in " ".join(result.issues)
    assert directory.insert_calls == []

    verification = verify_workspace_aliases(directory, plan)  # type: ignore[arg-type]
    assert not verification.ok
    assert "different immutable user ID" in " ".join(verification.issues)


def test_dry_run_has_no_mutations_and_reports_would_create() -> None:
    directory = FakeDirectory()
    plan = _plan(directory, "mailb@example.com", "mailc@example.com")
    result = provision_workspace_aliases(  # type: ignore[arg-type]
        directory,
        plan,
        dry_run=True,
    )

    assert result.ok
    assert result.reused == ("mailb@example.com",)
    assert result.would_create == ("mailc@example.com",)
    assert result.created == ()
    assert directory.insert_calls == []
    assert "unrelated@example.com" in directory.target_aliases


def test_provision_verifies_is_idempotent_and_preserves_unrelated_aliases() -> None:
    directory = FakeDirectory()
    plan = _plan(directory, "mailb@example.com", "mailc@example.com")

    first = provision_workspace_aliases(directory, plan)  # type: ignore[arg-type]
    second = provision_workspace_aliases(directory, plan)  # type: ignore[arg-type]
    verification = verify_workspace_aliases(directory, plan)  # type: ignore[arg-type]

    assert first.ok and first.verified
    assert first.created == ("mailc@example.com",)
    assert first.reused == ("mailb@example.com",)
    assert second.ok and second.created == ()
    assert second.reused == ("mailb@example.com", "mailc@example.com")
    assert directory.insert_calls == ["mailc@example.com"]
    assert verification.ok
    assert "unrelated@example.com" in directory.target_aliases


def test_partial_failure_is_reported_and_rerun_reuses_completed_alias() -> None:
    directory = FakeDirectory()
    directory.target_aliases.clear()
    plan = _plan(directory, "a@example.com", "b@example.com")
    directory.fail_once["b@example.com"] = WorkspaceDirectoryApiError(
        "Workspace Directory create user alias failed: HTTP 503",
        operation="create user alias",
        status_code=503,
    )

    with pytest.raises(WorkspaceAliasProvisionError) as exc_info:
        provision_workspace_aliases(directory, plan)  # type: ignore[arg-type]
    partial = exc_info.value.result
    assert partial.created == ("a@example.com",)
    assert partial.conflicted == ("b@example.com",)
    assert "a@example.com" in directory.target_aliases

    rerun = provision_workspace_aliases(directory, plan)  # type: ignore[arg-type]
    assert rerun.ok
    assert rerun.reused == ("a@example.com",)
    assert rerun.created == ("b@example.com",)
    assert directory.insert_calls == ["a@example.com", "b@example.com", "b@example.com"]


def test_cancellation_after_first_alias_carries_structured_partial_result() -> None:
    directory = FakeDirectory()
    directory.target_aliases.clear()
    plan = _plan(directory, "a@example.com", "b@example.com")
    original_insert = directory.insert_user_alias

    def insert_then_cancel(target_user: str, alias: str, **kwargs: Any):
        if alias == "b@example.com":
            raise WorkspaceDirectoryCancelledError("create user alias")
        return original_insert(target_user, alias, **kwargs)

    directory.insert_user_alias = insert_then_cancel  # type: ignore[method-assign]
    with pytest.raises(WorkspaceDirectoryCancelledError) as exc_info:
        provision_workspace_aliases(directory, plan)  # type: ignore[arg-type]

    assert isinstance(exc_info.value, InterruptedError)
    partial = exc_info.value.result
    assert partial.created == ("a@example.com",)
    assert partial.reused == ()
    assert partial.conflicted == ("b@example.com",)
    assert "a@example.com" in directory.target_aliases
    assert exc_info.value.to_dict()["result"]["created"] == ["a@example.com"]


def test_create_409_becomes_reuse_only_when_race_owner_is_target() -> None:
    directory = FakeDirectory()
    directory.target_aliases.clear()
    plan = _plan(directory, "race@example.com")
    directory.race_to_target.add("race@example.com")

    result = provision_workspace_aliases(directory, plan)  # type: ignore[arg-type]
    assert result.ok
    assert result.created == ()
    assert result.reused == ("race@example.com",)

    directory = FakeDirectory()
    directory.target_aliases.clear()
    plan = _plan(directory, "race@example.com")
    directory.race_to_user["race@example.com"] = WorkspaceDirectoryUser(
        "other-id",
        "race@example.com",
        CUSTOMER,
    )
    with pytest.raises(WorkspaceAliasProvisionError) as exc_info:
        provision_workspace_aliases(directory, plan)  # type: ignore[arg-type]
    assert exc_info.value.result.conflicted == ("race@example.com",)
    assert "other-id" not in str(exc_info.value)


def test_post_write_verification_api_failure_carries_partial_result() -> None:
    directory = FakeDirectory()
    directory.target_aliases.clear()
    plan = _plan(directory, "new@example.com")

    original_insert = directory.insert_user_alias

    def insert_then_break_verification(target_user: str, alias: str, **kwargs: Any):
        result = original_insert(target_user, alias, **kwargs)
        directory.fail_get_user_once = WorkspaceDirectoryApiError(
            "Workspace Directory get user identity failed: HTTP 503",
            operation="get user identity",
            status_code=503,
        )
        return result

    directory.insert_user_alias = insert_then_break_verification  # type: ignore[method-assign]
    with pytest.raises(WorkspaceAliasProvisionError) as exc_info:
        provision_workspace_aliases(directory, plan)  # type: ignore[arg-type]

    partial = exc_info.value.result
    assert partial.created == ("new@example.com",)
    assert not partial.verified
    assert "HTTP 503" in " ".join(partial.issues)

    rerun = provision_workspace_aliases(directory, plan)  # type: ignore[arg-type]
    assert rerun.ok
    assert rerun.reused == ("new@example.com",)


def test_service_account_factory_securely_parses_and_delegates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from components import workspace_aliases as module

    credential_path = tmp_path / "service-account.json"
    private_key = "very-secret-private-key"
    payload = {
        "type": "service_account",
        "client_email": "svc@example-project.iam.gserviceaccount.com",
        "private_key": private_key,
    }
    credential_path.write_text(json.dumps(payload), encoding="utf-8")
    captured: dict[str, Any] = {}

    class Credentials:
        token = "delegated-token"
        valid = True

        @classmethod
        def from_service_account_info(cls, info, scopes):
            captured["info"] = info
            captured["scopes"] = tuple(scopes)
            return cls()

        def with_subject(self, subject):
            captured["subject"] = subject
            return self

        def refresh(self, _request):  # pragma: no cover - token starts valid
            raise AssertionError("unexpected refresh")

    monkeypatch.setattr(
        module,
        "google_service_account",
        SimpleNamespace(Credentials=Credentials),
    )
    client = build_workspace_directory_client_from_service_account(
        credential_path,
        delegated_admin="Admin@Example.com",
        session=QueueSession([]),
    )

    assert captured["info"] == payload
    assert captured["scopes"] == WORKSPACE_DIRECTORY_SCOPES
    assert captured["subject"] == "admin@example.com"
    assert client.authorization_identity.service_account_email == (
        "svc@example-project.iam.gserviceaccount.com"
    )
    assert private_key not in repr(client)
    assert str(credential_path) not in repr(client)

    symlink = tmp_path / "credentials-link.json"
    symlink.symlink_to(credential_path)
    with pytest.raises(WorkspaceAuthenticationError) as exc_info:
        build_workspace_directory_client_from_service_account(
            symlink,
            delegated_admin="admin@example.com",
            session=QueueSession([]),
        )
    assert private_key not in str(exc_info.value)
    assert str(credential_path) not in str(exc_info.value)
