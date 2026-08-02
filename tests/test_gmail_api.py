from __future__ import annotations

import copy
import threading
from typing import Any, Dict, List, Optional

import pytest

from components.gmail_api import (
    FILTER_SCOPE_HINT,
    GMAIL_LABEL_NAME_MAX_LENGTH,
    LABEL_SCOPE_HINT,
    GmailApiCancelledError,
    GmailApiClient,
    GmailApiError,
    GmailFilter,
    GmailFilterSpec,
    GmailLabel,
    GmailReconciliationError,
    canonical_filter_action,
    canonical_filter_criteria,
    plan_filter_reconciliation,
    plan_gmail_configuration,
    plan_label_reconciliation,
    provision_gmail_configuration,
    reconcile_filters,
    reconcile_labels,
)


class Response:
    def __init__(
        self,
        status_code: int,
        payload: Any = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        self.status_code = status_code
        self._payload = payload
        self.headers = dict(headers or {})

    def json(self) -> Any:
        if isinstance(self._payload, Exception):
            raise self._payload
        return copy.deepcopy(self._payload)


class GmailSession:
    """Small stateful Gmail API fake used through the real REST client."""

    def __init__(
        self,
        *,
        labels: Optional[List[Dict[str, Any]]] = None,
        filters: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        self.labels = copy.deepcopy(labels or [])
        self.filters = copy.deepcopy(filters or [])
        self.calls: List[Dict[str, Any]] = []
        self.next_label = 1
        self.next_filter = 1
        self.fail_after_label_create_once = False
        self.fail_label_create_status: Optional[int] = None
        self.labels_after_failed_label_create: Optional[List[Dict[str, Any]]] = None
        self.fail_after_filter_create_once = False
        self.fail_filter_create_status: Optional[int] = None
        self.fail_filter_delete_ids: set[str] = set()

    @property
    def mutating_calls(self) -> List[Dict[str, Any]]:
        return [call for call in self.calls if call["method"] in {"POST", "DELETE"}]

    def request(self, method: str, url: str, **kwargs: Any) -> Response:
        call = {"method": method, "url": url, **copy.deepcopy(kwargs)}
        self.calls.append(call)
        path = url.split("/users/", 1)[1].split("/", 1)[1]

        if method == "GET" and path == "labels":
            return Response(200, {"labels": self.labels})
        if method == "POST" and path == "labels":
            body = kwargs["json"]
            if self.fail_label_create_status is not None:
                status = self.fail_label_create_status
                self.fail_label_create_status = None
                if self.labels_after_failed_label_create is not None:
                    self.labels = copy.deepcopy(self.labels_after_failed_label_create)
                return Response(status, {"error": {}})
            resource = {
                "id": f"Label_{self.next_label}",
                "name": body["name"],
                "type": "user",
            }
            self.next_label += 1
            self.labels.append(resource)
            if self.fail_after_label_create_once:
                self.fail_after_label_create_once = False
                return Response(503, {"error": {"message": "contains secret"}})
            return Response(200, resource)
        if method == "GET" and path == "settings/filters":
            return Response(200, {"filter": self.filters})
        if method == "POST" and path == "settings/filters":
            if self.fail_filter_create_status is not None:
                return Response(self.fail_filter_create_status, {"error": {}})
            body = kwargs["json"]
            resource = {
                "id": f"filter-{self.next_filter}",
                "criteria": body["criteria"],
                "action": body["action"],
            }
            self.next_filter += 1
            self.filters.append(resource)
            if self.fail_after_filter_create_once:
                self.fail_after_filter_create_once = False
                return Response(503, {"error": {"message": "contains secret"}})
            return Response(200, resource)
        if method == "DELETE" and path.startswith("settings/filters/"):
            filter_id = path.rsplit("/", 1)[1]
            if filter_id in self.fail_filter_delete_ids:
                return Response(403, {"error": {"status": "PERMISSION_DENIED"}})
            self.filters = [item for item in self.filters if item["id"] != filter_id]
            return Response(204)
        raise AssertionError(f"unexpected request {method} {path}")


def _client(session: Any, token: str = "top-secret-token") -> GmailApiClient:
    return GmailApiClient(
        token,
        session=session,
        timeout_sec=7,
        retry_max_attempts=1,
    )


@pytest.mark.parametrize(
    ("method", "status", "operation", "scope"),
    [
        ("list_labels", 403, "list labels", LABEL_SCOPE_HINT),
        ("list_filters", 401, "list filters", FILTER_SCOPE_HINT),
    ],
)
def test_authorization_errors_are_precise_and_redacted(
    method: str,
    status: int,
    operation: str,
    scope: str,
) -> None:
    token = "extremely-secret-token"

    class Session:
        def request(self, *_args: Any, **_kwargs: Any) -> Response:
            return Response(
                status,
                {
                    "error": {
                        "message": f"leaked {token}",
                        "errors": [{"reason": token}],
                    }
                },
            )

    client = _client(Session(), token)
    with pytest.raises(GmailApiError) as exc_info:
        getattr(client, method)()

    error = exc_info.value
    assert error.status_code == status
    assert error.operation == operation
    assert error.required_scope == scope
    assert f"HTTP {status}" in str(error)
    assert scope in str(error)
    assert token not in str(error)
    assert "leaked" not in str(error)


def test_transport_error_does_not_echo_exception_or_token() -> None:
    token = "token-must-not-leak"

    class Session:
        def request(self, *_args: Any, **_kwargs: Any) -> Response:
            raise RuntimeError(f"request headers contained Bearer {token}")

    with pytest.raises(GmailApiError) as exc_info:
        _client(Session(), token).list_labels()

    assert "RuntimeError" in str(exc_info.value)
    assert token not in str(exc_info.value)
    assert "Bearer" not in str(exc_info.value)


def test_safe_get_retries_structured_quota_403_and_honors_retry_after() -> None:
    delays: List[float] = []

    class Session:
        def __init__(self) -> None:
            self.calls = 0

        def request(self, *_args: Any, **_kwargs: Any) -> Response:
            self.calls += 1
            if self.calls == 1:
                return Response(
                    403,
                    {
                        "error": {
                            "errors": [{"reason": "rateLimitExceeded"}],
                            "message": "response-secret",
                        }
                    },
                    {"Retry-After": "3"},
                )
            return Response(200, {"labels": []})

    session = Session()
    client = GmailApiClient(
        "token",
        session=session,
        retry_max_attempts=2,
        sleep_fn=delays.append,
        random_fn=lambda: 0.0,
    )

    assert client.list_labels() == ()
    assert session.calls == 2
    assert delays == [3.0]


def test_safe_get_uses_bounded_exponential_jitter_without_retry_after() -> None:
    delays: List[float] = []

    class Session:
        def __init__(self) -> None:
            self.responses = [
                Response(503, {"error": {"errors": [{"reason": "backendError"}]}}),
                Response(503, {"error": {"errors": [{"reason": "backendError"}]}}),
                Response(200, {"labels": []}),
            ]

        def request(self, *_args: Any, **_kwargs: Any) -> Response:
            return self.responses.pop(0)

    client = GmailApiClient(
        "token",
        session=Session(),
        retry_max_attempts=3,
        retry_base_delay_sec=2,
        retry_max_delay_sec=3,
        sleep_fn=delays.append,
        random_fn=lambda: 0.0,
    )

    assert client.list_labels() == ()
    assert delays == [1.0, 1.5]


def test_rate_limited_post_stops_during_backoff_without_a_second_request() -> None:
    class StopDuringBackoff:
        def __init__(self) -> None:
            self.stopped = False
            self.waits: List[float] = []

        def is_set(self) -> bool:
            return self.stopped

        def wait(self, delay: float) -> bool:
            self.waits.append(delay)
            self.stopped = True
            return True

    class Session:
        def __init__(self) -> None:
            self.calls = 0

        def request(self, method: str, *_args: Any, **_kwargs: Any) -> Response:
            assert method == "POST"
            self.calls += 1
            return Response(429, {"error": {}}, {"Retry-After": "7"})

    stop_event = StopDuringBackoff()
    session = Session()
    client = GmailApiClient(
        "token",
        session=session,
        retry_max_attempts=5,
        stop_event=stop_event,
    )

    with pytest.raises(GmailApiCancelledError, match="create label cancelled") as exc_info:
        client.create_label("MailB")

    assert exc_info.value.operation == "create label"
    assert exc_info.value.to_dict()["error"] == "gmail_api_cancelled"
    assert session.calls == 1
    assert stop_event.waits == [7.0]


def test_exhausted_quota_403_is_not_mislabeled_as_scope_denial() -> None:
    secret = "response-secret"

    class Session:
        def request(self, *_args: Any, **_kwargs: Any) -> Response:
            return Response(
                403,
                {
                    "error": {
                        "status": "RESOURCE_EXHAUSTED",
                        "errors": [{"reason": "userRateLimitExceeded"}],
                        "message": secret,
                    }
                },
            )

    client = GmailApiClient(
        "token",
        session=Session(),
        retry_max_attempts=1,
    )
    with pytest.raises(GmailApiError) as exc_info:
        client.list_filters()

    error = exc_info.value
    assert error.reasons == ("RESOURCE_EXHAUSTED", "userRateLimitExceeded")
    assert error.retryable
    assert "rate or quota limited" in str(error)
    assert "permission denied" not in str(error)
    assert secret not in str(error)


def test_daily_quota_403_is_classified_safely_but_not_retried() -> None:
    class Session:
        def __init__(self) -> None:
            self.calls = 0

        def request(self, *_args: Any, **_kwargs: Any) -> Response:
            self.calls += 1
            return Response(
                403,
                {"error": {"errors": [{"reason": "dailyLimitExceeded"}]}},
            )

    session = Session()
    client = GmailApiClient(
        "token",
        session=session,
        retry_max_attempts=5,
        sleep_fn=lambda _delay: None,
    )
    with pytest.raises(GmailApiError) as exc_info:
        client.list_labels()

    assert not exc_info.value.retryable
    assert "rate or quota limited" in str(exc_info.value)
    assert "permission denied" not in str(exc_info.value)
    assert session.calls == 1


def test_ambiguous_post_is_not_blindly_retried_by_rest_client() -> None:
    delays: List[float] = []

    class Session:
        def __init__(self) -> None:
            self.calls = 0

        def request(self, *_args: Any, **_kwargs: Any) -> Response:
            self.calls += 1
            return Response(
                503,
                {"error": {"errors": [{"reason": "backendError"}]}},
            )

    session = Session()
    client = GmailApiClient(
        "token",
        session=session,
        retry_max_attempts=5,
        sleep_fn=delays.append,
    )
    with pytest.raises(GmailApiError) as exc_info:
        client.create_label("MailB")

    assert exc_info.value.mutation_outcome_uncertain
    assert session.calls == 1
    assert delays == []


def test_rest_client_crud_uses_bearer_without_persisting_it_in_results() -> None:
    session = GmailSession(
        labels=[
            {"id": "INBOX", "name": "INBOX", "type": "system"},
            {"id": "Label_9", "name": "Zulu", "type": "user"},
        ]
    )
    client = _client(session)

    assert [item.name for item in client.list_labels()] == ["INBOX", "Zulu"]
    created_label = client.create_label("Mail B")
    created_filter = client.create_filter(
        {"query": "deliveredto:b@example.com"},
        {"addLabelIds": [created_label.id], "removeLabelIds": ["INBOX"]},
    )
    assert client.list_filters() == (created_filter,)
    client.delete_filter(created_filter.id)
    assert client.list_filters() == ()

    assert session.calls[0]["timeout"] == 7.0
    assert session.calls[0]["allow_redirects"] is False
    assert session.calls[0]["headers"]["Authorization"] == "Bearer top-secret-token"
    assert session.calls[1]["json"] == {"name": "Mail B"}
    assert session.calls[2]["json"]["criteria"] == {
        "query": "deliveredto:b@example.com"
    }


def test_label_plan_reuses_exact_and_detects_case_system_and_hierarchy_conflicts() -> None:
    existing = (
        GmailLabel("Label_1", "MailB", "user"),
        GmailLabel("Label_2", "root", "user"),
        GmailLabel("INBOX", "INBOX", "system"),
    )
    plan = plan_label_reconciliation(
        ["MailB", "MailC", "Root/Child", "INBOX/Imported"],
        existing,
    )
    by_name = {entry.name: entry for entry in plan.entries}

    assert by_name["MailB"].action == "reuse"
    assert by_name["MailB"].label_id == "Label_1"
    assert by_name["MailC"].action == "create"
    assert by_name["Root/Child"].action == "conflict"
    assert "hierarchy casing conflict" in " ".join(by_name["Root/Child"].conflicts)
    assert by_name["INBOX/Imported"].action == "conflict"
    assert "system label" in " ".join(by_name["INBOX/Imported"].conflicts)
    assert not plan.ok


def test_label_plan_rejects_desired_hierarchy_case_variants() -> None:
    plan = plan_label_reconciliation(["Team/One", "team/Two"], [])
    assert not plan.ok
    assert all(entry.action == "conflict" for entry in plan.entries)
    assert any("hierarchy casing conflict" in item for item in plan.conflicts)


def test_label_plan_enforces_full_nested_path_length_boundary() -> None:
    namespace = "N" * 200
    at_limit = f"{namespace}/{'f' * 24}"
    over_limit = f"{namespace}/{'f' * 25}"
    assert len(at_limit) == GMAIL_LABEL_NAME_MAX_LENGTH
    assert len(over_limit) == GMAIL_LABEL_NAME_MAX_LENGTH + 1

    accepted = plan_label_reconciliation((at_limit,), ())
    rejected = plan_label_reconciliation((over_limit,), ())

    assert accepted.ok
    assert accepted.entries[0].action == "create"
    assert not rejected.ok
    assert rejected.entries[0].action == "conflict"
    assert any("full path length 226" in item for item in rejected.conflicts)
    assert any("maximum of 225 characters" in item for item in rejected.conflicts)


def test_label_plan_keeps_unrelated_overlong_remote_label_visible_but_rejects_request() -> None:
    overlong = "R" * (GMAIL_LABEL_NAME_MAX_LENGTH + 1)
    remote = GmailLabel("Label_legacy", overlong, "user")

    unrelated = plan_label_reconciliation(("MailB",), (remote,))
    requested = plan_label_reconciliation((overlong,), (remote,))

    assert unrelated.ok
    assert unrelated.entries[0].action == "create"
    assert not requested.ok
    assert requested.entries[0].action == "conflict"
    assert "full path length 226" in " ".join(requested.entries[0].conflicts)


@pytest.mark.parametrize("operation", ["labels", "configuration"])
def test_overlong_label_conflict_blocks_all_earlier_label_writes(operation: str) -> None:
    session = GmailSession()
    client = _client(session)
    valid = "A-valid-label"
    overlong = "Z" * (GMAIL_LABEL_NAME_MAX_LENGTH + 1)

    with pytest.raises(GmailReconciliationError, match="full path length 226"):
        if operation == "labels":
            reconcile_labels(client, (valid, overlong))
        else:
            provision_gmail_configuration(client, (valid, overlong))

    assert [call["method"] for call in session.calls] == ["GET"]
    assert not session.mutating_calls


def test_direct_label_create_rejects_overlong_name_before_request() -> None:
    session = GmailSession()
    client = _client(session)

    with pytest.raises(ValueError, match="maximum of 225 characters"):
        client.create_label("X" * (GMAIL_LABEL_NAME_MAX_LENGTH + 1))

    assert not session.calls


def _label_capacity_snapshot(count: int) -> tuple[GmailLabel, ...]:
    labels = []
    if count:
        labels.append(GmailLabel("INBOX", "INBOX", "system"))
    labels.extend(
        GmailLabel(f"Label_{index}", f"Existing-{index:05d}", "user")
        for index in range(1, count)
    )
    return tuple(labels)


@pytest.mark.parametrize(
    ("existing_count", "missing_count", "reuse_at_capacity", "expected_ok"),
    [
        (9_998, 2, False, True),
        (9_999, 1, False, True),
        (9_999, 2, False, False),
        (10_000, 0, True, True),
        (10_000, 1, False, False),
    ],
    ids=[
        "9998-plus-2-allowed",
        "9999-plus-1-allowed",
        "9999-plus-2-conflict",
        "10000-exact-reuse-allowed",
        "10000-plus-1-conflict",
    ],
)
def test_label_plan_enforces_mailbox_capacity_before_create(
    existing_count: int,
    missing_count: int,
    reuse_at_capacity: bool,
    expected_ok: bool,
) -> None:
    existing = _label_capacity_snapshot(existing_count)
    required = (
        (existing[-1].name,)
        if reuse_at_capacity
        else tuple(f"Required-{index}" for index in range(missing_count))
    )

    plan = plan_label_reconciliation(required, existing)

    assert plan.ok is expected_ok
    if expected_ok:
        expected_action = "reuse" if reuse_at_capacity else "create"
        assert all(entry.action == expected_action for entry in plan.entries)
        assert not any("label limit would be exceeded" in item for item in plan.conflicts)
    else:
        assert all(entry.action == "conflict" for entry in plan.entries)
        assert any(
            f"{existing_count} existing label(s) plus {missing_count} required create(s)"
            in item
            for item in plan.conflicts
        )
        assert any("maximum 10000" in item for item in plan.conflicts)


def test_gmail_configuration_plan_propagates_label_capacity_conflict() -> None:
    existing = _label_capacity_snapshot(9_999)

    plan = plan_gmail_configuration(
        ("Required-A", "Required-B"),
        (),
        existing,
        (),
    )

    assert not plan.ok
    assert plan.conflicts == plan.labels.conflicts
    assert any("label limit would be exceeded" in item for item in plan.conflicts)


@pytest.mark.parametrize("operation", ["labels", "configuration"])
def test_label_capacity_conflict_blocks_all_provisioning_writes(operation: str) -> None:
    session = GmailSession(
        labels=[label.to_dict() for label in _label_capacity_snapshot(9_999)]
    )
    client = _client(session)

    with pytest.raises(GmailReconciliationError, match="label limit would be exceeded"):
        if operation == "labels":
            reconcile_labels(client, ("Required-A", "Required-B"))
        else:
            provision_gmail_configuration(
                client,
                ("Required-A", "Required-B"),
            )

    assert not session.mutating_calls


def test_reconcile_labels_dry_run_and_idempotent_provision() -> None:
    session = GmailSession(labels=[{"id": "Label_8", "name": "MailB", "type": "user"}])
    client = _client(session)

    dry_run = reconcile_labels(client, ["MailC", "MailB"], dry_run=True)
    assert dry_run.ok
    assert not dry_run.verified
    assert [item.action for item in dry_run.labels] == ["reused", "would_create"]
    assert not session.mutating_calls

    result = reconcile_labels(client, ["MailC", "MailB"])
    assert result.ok and result.verified
    assert [item.action for item in result.labels] == ["reused", "created"]
    assert [item["name"] for item in session.labels].count("MailC") == 1

    mutations_before = len(session.mutating_calls)
    rerun = reconcile_labels(client, ["MailC", "MailB"])
    assert rerun.ok
    assert all(item.action == "reused" for item in rerun.labels)
    assert len(session.mutating_calls) == mutations_before


@pytest.mark.parametrize("status_code", [400, 409])
def test_label_create_collision_reuses_exact_concurrent_label_and_reruns(
    status_code: int,
) -> None:
    session = GmailSession()
    session.fail_label_create_status = status_code
    session.labels_after_failed_label_create = [
        {"id": "Label_concurrent", "name": "MailA", "type": "user"}
    ]
    client = _client(session)

    result = reconcile_labels(client, ["MailA"])

    assert result.ok and result.verified
    assert result.created == ()
    assert result.reused == ("MailA",)
    assert result.labels[0].action == "reused"
    assert result.labels[0].label_id == "Label_concurrent"
    assert [call["method"] for call in session.mutating_calls] == ["POST"]

    mutations_before = len(session.mutating_calls)
    rerun = reconcile_labels(client, ["MailA"])
    assert rerun.ok and rerun.verified
    assert rerun.created == ()
    assert rerun.reused == ("MailA",)
    assert rerun.labels[0].action == "reused"
    assert len(session.mutating_calls) == mutations_before


@pytest.mark.parametrize("status_code", [400, 409])
@pytest.mark.parametrize(
    "rediscovered",
    [
        [],
        [{"id": "INBOX", "name": "MailA", "type": "system"}],
        [
            {"id": "Label_1", "name": "MailA", "type": "user"},
            {"id": "Label_2", "name": "MailA", "type": "user"},
        ],
    ],
    ids=["no-exact-match", "system-only", "multiple-exact"],
)
def test_label_create_collision_only_recovers_one_valid_exact_user_label(
    status_code: int,
    rediscovered: List[Dict[str, Any]],
) -> None:
    session = GmailSession()
    session.fail_label_create_status = status_code
    session.labels_after_failed_label_create = rediscovered

    with pytest.raises(GmailApiError) as exc_info:
        reconcile_labels(_client(session), ["MailA"])

    assert exc_info.value.status_code == status_code
    assert exc_info.value.operation == "create label"
    assert exc_info.value.result.created == ()
    assert exc_info.value.result.reused == ()
    assert exc_info.value.result.unresolved == ("MailA",)
    assert [call["method"] for call in session.mutating_calls] == ["POST"]
    assert sum(call["method"] == "GET" for call in session.calls) == 2


@pytest.mark.parametrize("create_status", [400, 409])
@pytest.mark.parametrize(
    ("failure_kind", "expected_status", "expected_retryable", "expected_text"),
    [
        ("unauthorized", 401, False, "HTTP 401"),
        ("forbidden", 403, False, "HTTP 403"),
        ("transport", None, True, "transport error (TimeoutError)"),
        ("malformed", None, False, "invalid label resource (ValueError)"),
        ("duplicate-list", None, False, "duplicate label IDs"),
    ],
)
def test_label_collision_surfaces_rediscovery_failure_with_redacted_context(
    create_status: int,
    failure_kind: str,
    expected_status: Optional[int],
    expected_retryable: bool,
    expected_text: str,
) -> None:
    secret = "top-secret-rediscovery-token"

    class RediscoveryFailureSession(GmailSession):
        def __init__(self) -> None:
            super().__init__()
            self.collision_seen = False

        def request(self, method: str, url: str, **kwargs: Any) -> Response:
            if (
                method == "GET"
                and url.endswith("/labels")
                and self.collision_seen
            ):
                self.calls.append(
                    {"method": method, "url": url, **copy.deepcopy(kwargs)}
                )
                if failure_kind == "transport":
                    raise TimeoutError(f"transport exposed {secret}")
                if failure_kind == "unauthorized":
                    return Response(
                        401,
                        {
                            "error": {
                                "status": "UNAUTHENTICATED",
                                "message": secret,
                            }
                        },
                    )
                if failure_kind == "forbidden":
                    return Response(
                        403,
                        {
                            "error": {
                                "status": "PERMISSION_DENIED",
                                "message": secret,
                            }
                        },
                    )
                if failure_kind == "malformed":
                    return Response(
                        200,
                        {"labels": [{"id": "Label_bad", "name": secret}]},
                    )
                assert failure_kind == "duplicate-list"
                return Response(
                    200,
                    {
                        "labels": [
                            {"id": "Label_dup", "name": "MailA", "type": "user"},
                            {"id": "Label_dup", "name": secret, "type": "user"},
                        ]
                    },
                )
            response = super().request(method, url, **kwargs)
            if (
                method == "POST"
                and url.endswith("/labels")
                and response.status_code == create_status
            ):
                self.collision_seen = True
            return response

    session = RediscoveryFailureSession()
    session.fail_label_create_status = create_status

    with pytest.raises(GmailApiError) as exc_info:
        reconcile_labels(_client(session, secret), ["MailA"])

    error = exc_info.value
    assert error.operation == "list labels"
    assert error.status_code == expected_status
    assert error.retryable is expected_retryable
    assert expected_text in str(error)
    assert error.result.unresolved == ("MailA",)
    assert "collision candidate" in error.result.issues[0]
    assert f"HTTP {create_status}" in error.result.issues[0]
    assert "rediscovery failed" in error.result.issues[0]

    create_error = error.__cause__
    assert isinstance(create_error, GmailApiError)
    assert create_error.operation == "create label"
    assert create_error.status_code == create_status
    assert error.to_dict()["context"]["label_create_collision"] == {
        "operation": "create label",
        "reasons": [],
        "retryable": False,
        "mutation_outcome_uncertain": False,
        "status_code": create_status,
        "required_scope": LABEL_SCOPE_HINT,
    }
    assert [call["method"] for call in session.mutating_calls] == ["POST"]
    assert [call["method"] for call in session.calls] == ["GET", "POST", "GET"]
    for surface in (
        str(error),
        str(error.to_dict()),
        str(error.result.to_dict()),
        str(create_error),
    ):
        assert secret not in surface


def test_label_create_permission_error_is_not_recovered_from_matching_state() -> None:
    session = GmailSession()
    session.fail_label_create_status = 403
    session.labels_after_failed_label_create = [
        {"id": "Label_external", "name": "MailA", "type": "user"}
    ]

    with pytest.raises(GmailApiError) as exc_info:
        reconcile_labels(_client(session), ["MailA"])

    assert exc_info.value.status_code == 403
    assert exc_info.value.result.unresolved == ("MailA",)
    assert [call["method"] for call in session.calls] == ["GET", "POST"]


def test_label_create_malformed_success_resource_is_not_masked_by_rediscovery() -> None:
    class MalformedCreateResponseSession(GmailSession):
        def request(self, method: str, url: str, **kwargs: Any) -> Response:
            response = super().request(method, url, **kwargs)
            if method == "POST" and url.endswith("/labels"):
                return Response(
                    200,
                    {"name": kwargs["json"]["name"], "type": "user"},
                )
            return response

    session = MalformedCreateResponseSession()

    with pytest.raises(GmailApiError) as exc_info:
        reconcile_labels(_client(session), ["MailA"])

    assert exc_info.value.operation == "create label"
    assert "invalid label resource" in str(exc_info.value)
    assert exc_info.value.result.unresolved == ("MailA",)
    assert [call["method"] for call in session.calls] == ["GET", "POST"]
    assert [item["name"] for item in session.labels] == ["MailA"]


def test_label_collision_recovery_preserves_partial_progress_on_later_failure() -> None:
    class CollisionThenPermissionSession(GmailSession):
        def request(self, method: str, url: str, **kwargs: Any) -> Response:
            if (
                method == "POST"
                and url.endswith("/labels")
                and kwargs["json"]["name"] == "MailB"
            ):
                self.calls.append({"method": method, "url": url, **copy.deepcopy(kwargs)})
                return Response(403, {"error": {"status": "PERMISSION_DENIED"}})
            return super().request(method, url, **kwargs)

    session = CollisionThenPermissionSession()
    session.fail_label_create_status = 409
    session.labels_after_failed_label_create = [
        {"id": "Label_external", "name": "MailA", "type": "user"}
    ]

    with pytest.raises(GmailApiError) as exc_info:
        reconcile_labels(_client(session), ["MailA", "MailB"])

    partial = exc_info.value.result
    assert exc_info.value.status_code == 403
    assert partial.created == ()
    assert partial.reused == ("MailA",)
    assert partial.unresolved == ("MailB",)
    assert [item.action for item in partial.labels] == ["reused", "unresolved"]
    assert [call["method"] for call in session.mutating_calls] == ["POST", "POST"]


def test_label_collision_recovery_cancellation_keeps_structured_partial_result() -> None:
    stop_event = threading.Event()

    class StopAfterCollisionSession(GmailSession):
        def request(self, method: str, url: str, **kwargs: Any) -> Response:
            response = super().request(method, url, **kwargs)
            if method == "POST" and url.endswith("/labels"):
                stop_event.set()
            return response

    session = StopAfterCollisionSession()
    session.fail_label_create_status = 409
    session.labels_after_failed_label_create = [
        {"id": "Label_external", "name": "MailA", "type": "user"}
    ]
    client = GmailApiClient(
        "token",
        session=session,
        retry_max_attempts=1,
        stop_event=stop_event,
    )

    with pytest.raises(GmailApiCancelledError) as exc_info:
        reconcile_labels(client, ["MailA"])

    partial = exc_info.value.result
    assert partial.created == ()
    assert partial.reused == ()
    assert partial.unresolved == ("MailA",)
    assert [call["method"] for call in session.calls] == ["GET", "POST"]


def test_label_cancellation_carries_exact_committed_progress() -> None:
    stop_event = threading.Event()

    class StopAfterFirstLabelSession(GmailSession):
        def request(self, method: str, url: str, **kwargs: Any) -> Response:
            response = super().request(method, url, **kwargs)
            if method == "POST" and url.endswith("/labels") and response.status_code == 200:
                stop_event.set()
            return response

    session = StopAfterFirstLabelSession()
    client = GmailApiClient(
        "token",
        session=session,
        retry_max_attempts=1,
        stop_event=stop_event,
    )

    with pytest.raises(GmailApiCancelledError) as exc_info:
        reconcile_labels(client, ["MailA", "MailB"])

    partial = exc_info.value.result
    assert isinstance(exc_info.value, InterruptedError)
    assert partial.created == ("MailA",)
    assert partial.reused == ()
    assert partial.unresolved == ("MailB",)
    assert [item["name"] for item in session.labels] == ["MailA"]
    assert exc_info.value.to_dict()["result"]["created"] == ["MailA"]


def test_label_conflicts_return_in_dry_run_and_raise_before_mutation() -> None:
    session = GmailSession(labels=[{"id": "Label_1", "name": "mailb", "type": "user"}])
    client = _client(session)

    dry_run = reconcile_labels(client, ["MailB"], dry_run=True)
    assert not dry_run.ok
    assert dry_run.labels[0].action == "conflict"
    assert not session.mutating_calls

    with pytest.raises(GmailReconciliationError, match="case-insensitively"):
        reconcile_labels(client, ["MailB"])
    assert not session.mutating_calls


def test_filter_spec_builds_exact_supported_actions() -> None:
    keep = GmailFilterSpec("mailb@example.com", "MailB")
    archive_read = GmailFilterSpec(
        "mailc@example.com",
        "MailC",
        inbox="archive",
        mark_read=True,
    )

    assert keep.criteria == {"query": "deliveredto:mailb@example.com"}
    assert keep.action_for_label_id("Label_1") == {"addLabelIds": ["Label_1"]}
    assert archive_read.action_for_label_id("Label_2") == {
        "addLabelIds": ["Label_2"],
        "removeLabelIds": ["INBOX", "UNREAD"],
    }
    with pytest.raises(ValueError, match="non-empty string"):
        GmailFilterSpec("mail@example.com", ["One", "Two"])  # type: ignore[arg-type]


def test_filter_spec_and_existing_query_share_workspace_idna_identity() -> None:
    spec = GmailFilterSpec("Alias@bücher.example", "Imported")
    assert spec.delivered_to == "alias@xn--bcher-kva.example"
    assert spec.query == "deliveredto:alias@xn--bcher-kva.example"
    assert canonical_filter_criteria(
        {"query": 'DELIVEREDTO:"ALIAS@BÜCHER.EXAMPLE"'}
    ) == canonical_filter_criteria(spec.criteria)


def test_filter_email_uses_nontransitional_idna_and_rejects_invalid_joiner() -> None:
    assert GmailFilterSpec("Alias@faß.de", "Imported").delivered_to == (
        "alias@xn--fa-hia.de"
    )
    with pytest.raises(ValueError, match="invalid domain"):
        GmailFilterSpec("alias@fa\u200c.de", "Imported")


def test_filter_email_enforces_254_ascii_octets_after_idna() -> None:
    local = "a" * 64
    domain_189 = ".".join(("b" * 63, "c" * 63, "d" * 61))
    domain_190 = ".".join(("b" * 63, "c" * 63, "d" * 62))

    assert len(GmailFilterSpec(f"{local}@{domain_189}", "Imported").delivered_to) == 254
    with pytest.raises(ValueError, match="254 ASCII octets"):
        GmailFilterSpec(f"{local}@{domain_190}", "Imported")

    # The Unicode input is below 254 code points, but IDNA expands it beyond
    # the mailbox limit and must be rejected after canonicalization.
    expanded_domain = ".".join(("é" * 45,) * 4)
    assert len(f"{local}@{expanded_domain}") < 254
    with pytest.raises(ValueError, match="254 ASCII octets"):
        GmailFilterSpec(f"{local}@{expanded_domain}", "Imported")

    normalized_domain = ".".join((("e\u0301" * 45),) * 3)
    long_input = f"{local}@{normalized_domain}"
    assert len(long_input) > 254
    canonical = GmailFilterSpec(long_input, "Imported").delivered_to
    assert len(canonical.encode("ascii")) <= 254


def test_filter_canonicalization_normalizes_deliveredto_and_label_array_order() -> None:
    assert canonical_filter_criteria(
        {"query": ' DELIVEREDTO:"MailB@Example.COM" ', "excludeChats": False}
    ) == canonical_filter_criteria({"query": "deliveredto:mailb@example.com"})
    assert canonical_filter_action(
        {"removeLabelIds": ["UNREAD", "INBOX"], "addLabelIds": ["Label_1"]}
    ) == canonical_filter_action(
        {"addLabelIds": ["Label_1"], "removeLabelIds": ["INBOX", "UNREAD"]}
    )


@pytest.mark.parametrize("field", ["addLabelIds", "removeLabelIds"])
@pytest.mark.parametrize(
    "bad_value",
    [None, "Label_1", False, 1, {}, [None], [False], [1], [{}], [[]]],
    ids=[
        "null",
        "string",
        "boolean",
        "number",
        "object",
        "null-item",
        "boolean-item",
        "number-item",
        "object-item",
        "array-item",
    ],
)
def test_list_filters_rejects_invalid_action_label_id_arrays(
    field: str,
    bad_value: Any,
) -> None:
    session = GmailSession(
        filters=[
            {
                "id": "filter-invalid",
                "criteria": {"query": "deliveredto:maila@example.com"},
                "action": {field: bad_value},
            }
        ]
    )

    with pytest.raises(GmailApiError) as exc_info:
        _client(session).list_filters()

    assert exc_info.value.operation == "list filters"
    assert "invalid filter resource" in str(exc_info.value)


@pytest.mark.parametrize(
    "action",
    [
        {},
        {"addLabelIds": []},
        {"removeLabelIds": []},
        {"addLabelIds": [], "removeLabelIds": []},
    ],
)
def test_list_filters_accepts_omitted_and_empty_action_label_id_arrays(
    action: Dict[str, Any],
) -> None:
    session = GmailSession(
        filters=[
            {
                "id": "filter-valid",
                "criteria": {"query": "from:sender@example.com"},
                "action": action,
            }
        ]
    )

    parsed = _client(session).list_filters()

    assert len(parsed) == 1
    assert parsed[0].action == action
    assert canonical_filter_action(parsed[0].action) == ()


@pytest.mark.parametrize("field", ["addLabelIds", "removeLabelIds"])
def test_filter_action_null_is_distinct_from_missing(field: str) -> None:
    assert canonical_filter_action({}) == ()
    with pytest.raises(ValueError, match="must be an array"):
        canonical_filter_action({field: None})


def test_invalid_existing_filter_action_cannot_false_reuse() -> None:
    session = GmailSession(
        labels=[{"id": "Label_A", "name": "MailA", "type": "user"}],
        filters=[
            {
                "id": "filter-invalid",
                "criteria": {"query": "deliveredto:maila@example.com"},
                "action": {
                    "addLabelIds": ["Label_A"],
                    "removeLabelIds": None,
                },
            }
        ],
    )

    with pytest.raises(GmailApiError) as exc_info:
        reconcile_filters(
            _client(session),
            [GmailFilterSpec("maila@example.com", "MailA")],
        )

    assert exc_info.value.operation == "list filters"
    assert not session.mutating_calls


@pytest.mark.parametrize(
    "existing_action",
    [
        {"addLabelIds": ["Label_A"]},
        {"addLabelIds": ["Label_A"], "removeLabelIds": []},
    ],
)
def test_filter_reconciliation_reuses_valid_omitted_or_empty_optional_array(
    existing_action: Dict[str, Any],
) -> None:
    session = GmailSession(
        labels=[{"id": "Label_A", "name": "MailA", "type": "user"}],
        filters=[
            {
                "id": "filter-existing",
                "criteria": {"query": "deliveredto:maila@example.com"},
                "action": existing_action,
            }
        ],
    )

    result = reconcile_filters(
        _client(session),
        [GmailFilterSpec("maila@example.com", "MailA")],
    )

    assert result.ok and result.verified
    assert result.filters[0].action == "reused"
    assert not session.mutating_calls


def test_filter_plan_reuses_one_exact_equivalent_filter() -> None:
    spec = GmailFilterSpec(
        "mailb@example.com",
        "MailB",
        inbox="archive",
        mark_read=True,
    )
    label = GmailLabel("Label_B", "MailB", "user")
    existing = GmailFilter(
        "filter-1",
        {"query": 'DELIVEREDTO:"MAILB@EXAMPLE.COM"'},
        {
            "removeLabelIds": ["UNREAD", "INBOX"],
            "addLabelIds": ["Label_B"],
        },
    )

    plan = plan_filter_reconciliation([spec], [existing], [label])
    assert plan.ok
    assert plan.entries[0].action == "reuse"
    assert plan.entries[0].filter_id == "filter-1"


@pytest.mark.parametrize("duplicate", [False, True])
def test_default_filter_conflict_never_deletes_or_creates(duplicate: bool) -> None:
    label = {"id": "Label_B", "name": "MailB", "type": "user"}
    filters = [
        {
            "id": "wrong",
            "criteria": {"query": "deliveredto:mailb@example.com"},
            "action": {"addLabelIds": ["Label_Other"]},
        }
    ]
    if duplicate:
        filters.append(
            {
                "id": "right",
                "criteria": {"query": "deliveredto:mailb@example.com"},
                "action": {"addLabelIds": ["Label_B"]},
            }
        )
    session = GmailSession(labels=[label], filters=filters)
    client = _client(session)
    spec = GmailFilterSpec("mailb@example.com", "MailB")

    dry_run = reconcile_filters(client, [spec], dry_run=True)
    assert not dry_run.ok
    assert dry_run.filters[0].action == "conflict"
    assert dry_run.filters[0].incompatible_filter_ids == ("wrong",)

    with pytest.raises(GmailReconciliationError, match="same-condition"):
        reconcile_filters(client, [spec])
    assert not session.mutating_calls


def test_replace_keeps_one_exact_filter_and_deletes_only_extras() -> None:
    labels = [
        {"id": "Label_B", "name": "MailB", "type": "user"},
        {"id": "Label_Other", "name": "Other", "type": "user"},
    ]
    filters = [
        {
            "id": "exact",
            "criteria": {"query": "deliveredto:mailb@example.com"},
            "action": {"addLabelIds": ["Label_B"]},
        },
        {
            "id": "wrong",
            "criteria": {"query": "deliveredto:mailb@example.com"},
            "action": {"addLabelIds": ["Label_Other"]},
        },
        {
            "id": "unrelated",
            "criteria": {"query": "from:somebody@example.com"},
            "action": {"addLabelIds": ["Label_Other"]},
        },
    ]
    session = GmailSession(labels=labels, filters=filters)
    result = reconcile_filters(
        _client(session),
        [GmailFilterSpec("mailb@example.com", "MailB", conflict_policy="replace")],
    )

    assert result.ok and result.verified
    assert result.filters[0].action == "replaced"
    assert result.filters[0].filter_id == "exact"
    assert result.filters[0].deleted_filter_ids == ("wrong",)
    assert {item["id"] for item in session.filters} == {"exact", "unrelated"}
    assert [call["method"] for call in session.mutating_calls] == ["DELETE"]


def test_replace_incompatible_filter_creates_then_deletes_and_verifies() -> None:
    labels = [{"id": "Label_B", "name": "MailB", "type": "user"}]
    filters = [
        {
            "id": "old",
            "criteria": {"query": "deliveredto:mailb@example.com"},
            "action": {"addLabelIds": ["Label_B"], "removeLabelIds": ["INBOX"]},
        }
    ]
    session = GmailSession(labels=labels, filters=filters)
    result = reconcile_filters(
        _client(session),
        [GmailFilterSpec("mailb@example.com", "MailB", conflict_policy="replace")],
    )

    assert result.filters[0].action == "replaced"
    assert result.filters[0].deleted_filter_ids == ("old",)
    assert len(session.filters) == 1
    assert session.filters[0]["action"] == {"addLabelIds": ["Label_B"]}
    assert [call["method"] for call in session.mutating_calls] == ["POST", "DELETE"]
    create_index = next(
        index for index, call in enumerate(session.calls) if call["method"] == "POST"
    )
    delete_index = next(
        index for index, call in enumerate(session.calls) if call["method"] == "DELETE"
    )
    assert any(
        call["method"] == "GET" and call["url"].endswith("/settings/filters")
        for call in session.calls[create_index + 1 : delete_index]
    )


def test_replace_definitive_create_failure_preserves_existing_filter() -> None:
    session = GmailSession(
        labels=[{"id": "Label_B", "name": "MailB", "type": "user"}],
        filters=[
            {
                "id": "old",
                "criteria": {"query": "deliveredto:mailb@example.com"},
                "action": {"addLabelIds": ["Label_B"], "removeLabelIds": ["INBOX"]},
            }
        ],
    )
    session.fail_filter_create_status = 400

    with pytest.raises(GmailApiError) as exc_info:
        reconcile_filters(
            _client(session),
            [GmailFilterSpec("mailb@example.com", "MailB", conflict_policy="replace")],
        )

    assert [item["id"] for item in session.filters] == ["old"]
    assert [call["method"] for call in session.mutating_calls] == ["POST"]
    assert exc_info.value.result.created_filter_ids == ()
    assert exc_info.value.result.deleted_filter_ids == ()
    assert exc_info.value.result.unresolved == ("deliveredto:mailb@example.com",)


def test_replace_at_filter_capacity_fails_before_deleting_protection() -> None:
    filters = [
        {
            "id": "old",
            "criteria": {"query": "deliveredto:mailb@example.com"},
            "action": {"addLabelIds": ["Label_B"], "removeLabelIds": ["INBOX"]},
        }
    ] + [
        {
            "id": f"unrelated-{index}",
            "criteria": {"query": f"from:person-{index}@example.com"},
            "action": {"addLabelIds": ["Label_B"]},
        }
        for index in range(999)
    ]
    session = GmailSession(
        labels=[{"id": "Label_B", "name": "MailB", "type": "user"}],
        filters=filters,
    )

    with pytest.raises(GmailReconciliationError, match="safe create-before-delete"):
        reconcile_filters(
            _client(session),
            [GmailFilterSpec("mailb@example.com", "MailB", conflict_policy="replace")],
        )

    assert len(session.filters) == 1000
    assert any(item["id"] == "old" for item in session.filters)
    assert not session.mutating_calls


def _exact_capacity_scheduling_fixture():
    labels = [
        {"id": "Label_A", "name": "Create", "type": "user"},
        {"id": "Label_B", "name": "Replace", "type": "user"},
        {"id": "Label_Z", "name": "Cleanup", "type": "user"},
        {"id": "Label_Other", "name": "Other", "type": "user"},
    ]
    filters = [
        {
            "id": "cleanup-exact",
            "criteria": {"query": "deliveredto:z-cleanup@example.com"},
            "action": {"addLabelIds": ["Label_Z"]},
        },
        {
            "id": "cleanup-extra",
            "criteria": {"query": "deliveredto:z-cleanup@example.com"},
            "action": {"addLabelIds": ["Label_Other"]},
        },
        {
            "id": "replacement-old",
            "criteria": {"query": "deliveredto:b-replace@example.com"},
            "action": {"addLabelIds": ["Label_Other"]},
        },
    ] + [
        {
            "id": f"unrelated-{index}",
            "criteria": {"query": f"from:person-{index}@example.com"},
            "action": {"addLabelIds": ["Label_Other"]},
        }
        for index in range(997)
    ]
    specs = [
        GmailFilterSpec("a-create@example.com", "Create"),
        GmailFilterSpec(
            "b-replace@example.com",
            "Replace",
            conflict_policy="replace",
        ),
        GmailFilterSpec(
            "z-cleanup@example.com",
            "Cleanup",
            conflict_policy="replace",
        ),
    ]
    assert len(filters) == 1000
    return labels, filters, specs


def test_exact_capacity_schedule_is_cleanup_then_replace_then_create_regardless_of_spec_order() -> None:
    labels, filters, specs = _exact_capacity_scheduling_fixture()
    forward_plan = plan_filter_reconciliation(specs, filters, labels)
    reverse_plan = plan_filter_reconciliation(reversed(specs), filters, labels)

    assert forward_plan.ok
    assert forward_plan.to_dict() == reverse_plan.to_dict()
    assert [entry.action for entry in forward_plan.entries] == [
        "create",
        "replace",
        "replace",
    ]

    results = []
    for requested in (specs, list(reversed(specs))):
        session = GmailSession(labels=labels, filters=filters)
        result = reconcile_filters(_client(session), requested)
        results.append(result.to_dict())

        mutations = session.mutating_calls
        assert [call["method"] for call in mutations] == [
            "DELETE",
            "POST",
            "DELETE",
            "POST",
        ]
        assert mutations[0]["url"].endswith("/cleanup-extra")
        assert mutations[1]["json"]["criteria"] == {
            "query": "deliveredto:b-replace@example.com"
        }
        assert mutations[2]["url"].endswith("/replacement-old")
        assert mutations[3]["json"]["criteria"] == {
            "query": "deliveredto:a-create@example.com"
        }
        replace_create_index = session.calls.index(mutations[1])
        replace_delete_index = session.calls.index(mutations[2])
        assert any(
            call["method"] == "GET"
            and call["url"].endswith("/settings/filters")
            for call in session.calls[replace_create_index + 1 : replace_delete_index]
        )
        assert len(session.filters) == 1000
        assert {item["id"] for item in session.filters}.isdisjoint(
            {"cleanup-extra", "replacement-old"}
        )
        assert {item["id"] for item in session.filters} >= {
            "cleanup-exact",
            "filter-1",
            "filter-2",
        }

    assert results[0] == results[1]


def test_exact_capacity_failure_reports_completed_cleanup_and_preserves_replacement() -> None:
    labels, filters, specs = _exact_capacity_scheduling_fixture()
    session = GmailSession(labels=labels, filters=filters)
    session.fail_filter_create_status = 400

    with pytest.raises(GmailApiError) as exc_info:
        reconcile_filters(_client(session), specs)

    partial = exc_info.value.result
    assert partial.created_filter_ids == ()
    assert partial.deleted_filter_ids == ("cleanup-extra",)
    assert partial.reused_filter_ids == ("cleanup-exact",)
    assert partial.unresolved == (
        "deliveredto:a-create@example.com",
        "deliveredto:b-replace@example.com",
    )
    assert [call["method"] for call in session.mutating_calls] == ["DELETE", "POST"]
    assert {item["id"] for item in session.filters} >= {
        "cleanup-exact",
        "replacement-old",
    }
    assert "cleanup-extra" not in {item["id"] for item in session.filters}

    session.fail_filter_create_status = None
    rerun = reconcile_filters(_client(session), list(reversed(specs)))
    assert rerun.ok and rerun.verified
    assert len(session.filters) == 1000
    assert {item["id"] for item in session.filters}.isdisjoint(
        {"cleanup-extra", "replacement-old"}
    )


def test_exact_capacity_cleanup_failure_stops_before_any_create() -> None:
    labels, filters, specs = _exact_capacity_scheduling_fixture()
    session = GmailSession(labels=labels, filters=filters)
    session.fail_filter_delete_ids.add("cleanup-extra")

    with pytest.raises(GmailApiError) as exc_info:
        reconcile_filters(_client(session), list(reversed(specs)))

    partial = exc_info.value.result
    assert partial.created_filter_ids == ()
    assert partial.deleted_filter_ids == ()
    assert partial.unresolved == (
        "deliveredto:a-create@example.com",
        "deliveredto:b-replace@example.com",
        "deliveredto:z-cleanup@example.com",
    )
    assert [call["method"] for call in session.mutating_calls] == ["DELETE"]
    assert len(session.filters) == 1000
    assert {item["id"] for item in session.filters} >= {
        "cleanup-exact",
        "cleanup-extra",
        "replacement-old",
    }


def test_cleanup_reconfirms_kept_filter_before_deleting_redundant_filter() -> None:
    class KeptFilterDisappearsSession(GmailSession):
        def __init__(self, **kwargs: Any) -> None:
            super().__init__(**kwargs)
            self.filter_lists = 0

        def request(self, method: str, url: str, **kwargs: Any) -> Response:
            if method == "GET" and url.endswith("/settings/filters"):
                self.filter_lists += 1
                if self.filter_lists == 2:
                    self.filters = [
                        item for item in self.filters if item["id"] != "cleanup-exact"
                    ]
            return super().request(method, url, **kwargs)

    labels = [
        {"id": "Label_Z", "name": "Cleanup", "type": "user"},
        {"id": "Label_Other", "name": "Other", "type": "user"},
    ]
    filters = [
        {
            "id": "cleanup-exact",
            "criteria": {"query": "deliveredto:z-cleanup@example.com"},
            "action": {"addLabelIds": ["Label_Z"]},
        },
        {
            "id": "cleanup-extra",
            "criteria": {"query": "deliveredto:z-cleanup@example.com"},
            "action": {"addLabelIds": ["Label_Other"]},
        },
    ]
    session = KeptFilterDisappearsSession(labels=labels, filters=filters)

    with pytest.raises(
        GmailReconciliationError,
        match="could not confirm the desired filter",
    ) as exc_info:
        reconcile_filters(
            _client(session),
            [
                GmailFilterSpec(
                    "z-cleanup@example.com",
                    "Cleanup",
                    conflict_policy="replace",
                )
            ],
        )

    assert not session.mutating_calls
    assert {item["id"] for item in session.filters} == {"cleanup-extra"}
    assert exc_info.value.result.deleted_filter_ids == ()
    assert exc_info.value.result.unresolved == (
        "deliveredto:z-cleanup@example.com",
    )


def test_replace_delete_failure_reports_created_filter_and_reruns_safely() -> None:
    session = GmailSession(
        labels=[{"id": "Label_B", "name": "MailB", "type": "user"}],
        filters=[
            {
                "id": "old",
                "criteria": {"query": "deliveredto:mailb@example.com"},
                "action": {"addLabelIds": ["Label_B"], "removeLabelIds": ["INBOX"]},
            }
        ],
    )
    session.fail_filter_delete_ids.add("old")
    spec = GmailFilterSpec("mailb@example.com", "MailB", conflict_policy="replace")

    with pytest.raises(GmailApiError) as exc_info:
        reconcile_filters(_client(session), [spec])

    partial = exc_info.value.result
    assert partial.created_filter_ids == ("filter-1",)
    assert partial.deleted_filter_ids == ()
    assert partial.unresolved == (spec.query,)
    assert {item["id"] for item in session.filters} == {"old", "filter-1"}

    session.fail_filter_delete_ids.clear()
    rerun = reconcile_filters(_client(session), [spec])
    assert rerun.ok and rerun.verified
    assert {item["id"] for item in session.filters} == {"filter-1"}


def test_replace_cancellation_between_deletes_carries_committed_progress() -> None:
    stop_event = threading.Event()

    class StopAfterFirstDeleteSession(GmailSession):
        def request(self, method: str, url: str, **kwargs: Any) -> Response:
            response = super().request(method, url, **kwargs)
            if method == "DELETE" and response.status_code == 204:
                stop_event.set()
            return response

    session = StopAfterFirstDeleteSession(
        labels=[{"id": "Label_B", "name": "MailB", "type": "user"}],
        filters=[
            {
                "id": filter_id,
                "criteria": {"query": "deliveredto:mailb@example.com"},
                "action": {"addLabelIds": ["Label_B"], "removeLabelIds": ["INBOX"]},
            }
            for filter_id in ("old-a", "old-b")
        ],
    )
    client = GmailApiClient(
        "token",
        session=session,
        retry_max_attempts=1,
        stop_event=stop_event,
    )
    spec = GmailFilterSpec("mailb@example.com", "MailB", conflict_policy="replace")

    with pytest.raises(GmailApiCancelledError) as exc_info:
        reconcile_filters(client, [spec])

    partial = exc_info.value.result
    assert isinstance(exc_info.value, InterruptedError)
    assert partial.created_filter_ids == ("filter-1",)
    assert partial.deleted_filter_ids == ("old-a",)
    assert partial.unresolved == (spec.query,)
    assert {item["id"] for item in session.filters} == {"old-b", "filter-1"}

    rerun = reconcile_filters(_client(session), [spec])
    assert rerun.ok and rerun.verified
    assert {item["id"] for item in session.filters} == {"filter-1"}


def test_combined_reconciliation_detects_filter_conflict_before_creating_label() -> None:
    session = GmailSession(
        labels=[{"id": "Other", "name": "Other", "type": "user"}],
        filters=[
            {
                "id": "existing",
                "criteria": {"query": "deliveredto:mailb@example.com"},
                "action": {"addLabelIds": ["Other"]},
            }
        ],
    )

    with pytest.raises(GmailReconciliationError, match="incompatible same-condition"):
        provision_gmail_configuration(
            _client(session),
            ["MailB"],
            [GmailFilterSpec("mailb@example.com", "MailB")],
        )

    assert not session.mutating_calls
    assert all(item["name"] != "MailB" for item in session.labels)


def test_combined_dry_run_is_structured_and_has_no_mutations() -> None:
    session = GmailSession()
    result = provision_gmail_configuration(
        _client(session),
        ["MailB"],
        [GmailFilterSpec("mailb@example.com", "MailB", inbox="archive")],
        dry_run=True,
    )

    assert result.ok
    assert result.dry_run
    assert not result.verified
    assert result.labels.labels[0].action == "would_create"
    assert result.filters.filters[0].action == "would_create"
    report = result.to_dict()
    assert report["labels"]["labels"][0]["name"] == "MailB"
    assert report["filters"]["filters"][0]["query"] == "deliveredto:mailb@example.com"
    assert not session.mutating_calls


def test_combined_provision_and_rerun_preserve_unrelated_filters() -> None:
    unrelated = {
        "id": "unrelated",
        "criteria": {"query": "from:somebody@example.com"},
        "action": {"removeLabelIds": ["UNREAD"]},
    }
    session = GmailSession(filters=[unrelated])
    spec = GmailFilterSpec(
        "mailb@example.com",
        "MailB",
        inbox="archive",
        mark_read=True,
    )
    client = _client(session)

    result = provision_gmail_configuration(client, ["MailB"], [spec])
    assert result.ok and result.verified
    assert result.labels.labels[0].action == "created"
    assert result.filters.filters[0].action == "created"
    assert len(session.labels) == 1
    assert len(session.filters) == 2
    created_filter = next(item for item in session.filters if item["id"] != "unrelated")
    assert created_filter["criteria"] == {"query": "deliveredto:mailb@example.com"}
    assert created_filter["action"] == {
        "addLabelIds": [session.labels[0]["id"]],
        "removeLabelIds": ["INBOX", "UNREAD"],
    }

    mutations_before = len(session.mutating_calls)
    rerun = provision_gmail_configuration(client, ["MailB"], [spec])
    assert rerun.ok
    assert rerun.labels.labels[0].action == "reused"
    assert rerun.filters.filters[0].action == "reused"
    assert len(session.mutating_calls) == mutations_before
    assert any(item["id"] == "unrelated" for item in session.filters)


@pytest.mark.parametrize("failure_stage", ["label", "filter"])
def test_write_response_failure_is_rerunnable_without_duplicates(failure_stage: str) -> None:
    session = GmailSession()
    if failure_stage == "label":
        session.fail_after_label_create_once = True
    else:
        session.fail_after_filter_create_once = True
    client = _client(session)
    spec = GmailFilterSpec("mailb@example.com", "MailB")

    # The fake models a server that committed the write but whose response was
    # unusable.  Reconciliation re-lists state before deciding whether another
    # POST would be safe.
    result = provision_gmail_configuration(client, ["MailB"], [spec])
    assert result.ok and result.verified
    assert [item["name"] for item in session.labels].count("MailB") == 1
    matching = [
        item
        for item in session.filters
        if canonical_filter_criteria(item["criteria"])
        == canonical_filter_criteria(spec.criteria)
    ]
    assert len(matching) == 1

    mutations_before = len(session.mutating_calls)
    rerun = provision_gmail_configuration(client, ["MailB"], [spec])
    assert rerun.ok and rerun.verified
    assert len(session.mutating_calls) == mutations_before


def test_filter_specs_with_same_condition_are_rejected_before_mutation() -> None:
    session = GmailSession(
        labels=[
            {"id": "Label_B", "name": "MailB", "type": "user"},
            {"id": "Label_C", "name": "MailC", "type": "user"},
        ]
    )
    specs = [
        GmailFilterSpec("alias@example.com", "MailB"),
        GmailFilterSpec("ALIAS@example.com", "MailC", conflict_policy="replace"),
    ]

    with pytest.raises(GmailReconciliationError, match="multiple requested filters"):
        reconcile_filters(_client(session), specs)
    assert not session.mutating_calls


def test_filter_limit_is_reported_before_mutation() -> None:
    labels = [{"id": "Label_B", "name": "MailB", "type": "user"}]
    filters = [
        {
            "id": f"existing-{index}",
            "criteria": {"query": f"from:person-{index}@example.com"},
            "action": {"addLabelIds": ["Label_B"]},
        }
        for index in range(1000)
    ]
    session = GmailSession(labels=labels, filters=filters)

    with pytest.raises(GmailReconciliationError, match="filter limit would be exceeded"):
        reconcile_filters(
            _client(session),
            [GmailFilterSpec("mailb@example.com", "MailB")],
        )
    assert not session.mutating_calls


def test_empty_filter_reconciliation_requires_no_api_scope_or_calls() -> None:
    class NoCalls:
        def request(self, *_args: Any, **_kwargs: Any) -> Response:
            raise AssertionError("empty reconciliation must not call Gmail")

    result = reconcile_filters(_client(NoCalls()), [])
    assert result.ok and result.verified
    assert result.filters == ()
