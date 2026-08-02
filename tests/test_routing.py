from __future__ import annotations

import json

import pytest

from components.routing import (
    CUSTOM_LABEL,
    GENERIC_MAILBOX,
    GMAIL_SYSTEM,
    Destination,
    RoutingConfig,
    RoutingPlan,
    SourceFolder,
    TargetLabel,
    detect_special_use_roles,
    resolve_routing_plan,
)


def _label(name: str, *, target_id: str | None = None) -> TargetLabel:
    return TargetLabel(name=name, kind=CUSTOM_LABEL, target_id=target_id)


def _destination(name: str, kind: str = CUSTOM_LABEL, **extra) -> dict:
    return {"type": kind, "name": name, **extra}


def _rule(*, folder: str | None = None, role: str | None = None, destinations=(), **extra) -> dict:
    match = {"folder": folder} if folder is not None else {"role": role}
    return {"match": match, "destinations": list(destinations), **extra}


def test_routing_config_is_strictly_opt_in_and_rejects_unknown_fields() -> None:
    assert not RoutingConfig.from_dict(None).enabled
    assert not RoutingConfig.from_dict({"enabled": False}).enabled

    with pytest.raises(ValueError, match="explicitly set"):
        RoutingConfig.from_dict({})
    with pytest.raises(ValueError, match="enabled=true"):
        RoutingConfig.from_dict({"enabled": False, "accounts": {}})
    with pytest.raises(ValueError, match="unknown field"):
        RoutingConfig.from_dict({"enabled": True, "guess": True})
    with pytest.raises(ValueError, match="unknown field"):
        RoutingConfig.from_dict(
            {
                "enabled": True,
                "global_rules": [
                    _rule(role="junk", destinations=[_destination("Imported/Junk")], priority=1)
                ],
            }
        )


@pytest.mark.parametrize(
    ("folder", "expected"),
    [
        (SourceFolder("a@example.com", "INBOX"), ("inbox",)),
        (SourceFolder("a@example.com", "INBOX.Spam", delimiter="."), ("junk",)),
        (SourceFolder("a@example.com", "Junk E-mail"), ("junk",)),
        (SourceFolder("a@example.com", "Sent Items"), ("sent",)),
        (SourceFolder("a@example.com", "Deleted Messages"), ("trash",)),
        (SourceFolder("a@example.com", "[Gmail]/All Mail", delimiter="/"), ("archive",)),
        (SourceFolder("a@example.com", "Whatever", attributes=("\\Drafts",)), ("drafts",)),
    ],
)
def test_special_use_and_common_name_role_detection(folder: SourceFolder, expected: tuple[str, ...]) -> None:
    assert detect_special_use_roles(folder) == expected


def test_preflight_rejects_case_insensitive_duplicate_inbox_discovery() -> None:
    routing = RoutingConfig.from_dict(
        {
            "enabled": True,
            "accounts": {
                "source@example.com": {"default_label": "Imported"}
            },
        }
    )

    plan = resolve_routing_plan(
        routing,
        [
            SourceFolder("source@example.com", "INBOX"),
            SourceFolder("source@example.com", "inbox"),
        ],
        [],
    )

    assert plan.ok is False
    assert any(
        "inbox discovery is ambiguous" in conflict.casefold()
        and "case-insensitively" in conflict.casefold()
        for conflict in plan.conflicts
    )


def test_conflicting_special_use_attributes_are_reported_deterministically() -> None:
    folder = SourceFolder(
        "a@example.com",
        "Odd",
        attributes=("\\Trash", "\\Junk", "\\Sent"),
    )
    assert folder.detected_roles == ("sent", "trash", "junk")

    config = RoutingConfig.from_dict(
        {
            "enabled": True,
            "global_rules": [_rule(role="junk", destinations=[_destination("Imported/Junk")])],
        }
    )
    entry = resolve_routing_plan(config, [folder], []).entries[0]
    assert entry.ambiguous
    assert entry.detected_role is None
    assert any("conflicting special-use roles" in issue for issue in entry.ambiguities)


def test_shared_junk_rule_suppresses_account_namespace_and_marks_merge() -> None:
    config = RoutingConfig.from_dict(
        {
            "enabled": True,
            "accounts": {
                "mailB@example.com": {
                    "default_label": "MailB",
                    "default_namespace": "MailB",
                },
                "mailC@example.com": {
                    "default_label": "MailC",
                    "default_namespace": "MailC",
                },
            },
            "global_rules": [
                _rule(role="junk", destinations=[_destination("Imported/Junk")])
            ],
        }
    )
    folders = [
        SourceFolder("mailB@example.com", "INBOX", attributes=("\\Inbox",)),
        SourceFolder("mailB@example.com", "Sent", attributes=("\\Sent",)),
        SourceFolder("mailB@example.com", "Junk E-mail"),
        SourceFolder("mailC@example.com", "INBOX.Spam", delimiter="."),
    ]
    plan = resolve_routing_plan(
        config,
        folders,
        [_label("MailB", target_id="Label_1"), _label("Imported/Junk", target_id="Label_2")],
    )

    assert plan.ok
    by_folder = {(entry.source.source_account, entry.source.name): entry for entry in plan.entries}
    inbox = by_folder[("mailB@example.com", "INBOX")]
    assert [(item.name, item.status) for item in inbox.destinations] == [("MailB", "existing")]
    sent = by_folder[("mailB@example.com", "Sent")]
    assert [item.name for item in sent.destinations] == ["MailB/Sent"]

    junk_b = by_folder[("mailB@example.com", "Junk E-mail")]
    junk_c = by_folder[("mailC@example.com", "INBOX.Spam")]
    assert junk_b.assignment_source == junk_c.assignment_source == "global_role"
    assert [item.name for item in junk_b.destinations] == ["Imported/Junk"]
    assert [item.name for item in junk_c.destinations] == ["Imported/Junk"]
    assert junk_b.destinations[0].merged and junk_c.destinations[0].merged
    assert [item.to_dict() for item in junk_b.destinations[0].contributors] == [
        {"source_account": "mailB@example.com", "source_folder": "Junk E-mail"},
        {"source_account": "mailC@example.com", "source_folder": "INBOX.Spam"},
    ]
    assert "MailB/Junk" not in plan.labels_to_create
    assert "MailC/Junk" not in plan.labels_to_create
    assert plan.labels_reused == ("Imported/Junk", "MailB")


def test_account_rules_precede_global_rules_and_exact_precedes_account_role() -> None:
    config = RoutingConfig.from_dict(
        {
            "enabled": True,
            "accounts": {
                "mailB@example.com": {
                    "default_label": "MailB",
                    "default_namespace": "MailB",
                    "rules": [
                        _rule(role="sent", destinations=[_destination("Account/SentRole")]),
                        _rule(
                            folder="Sent",
                            destinations=[_destination("Account/SentExact")],
                            include_default=True,
                        ),
                    ],
                },
                "mailC@example.com": {
                    "default_namespace": "MailC",
                    "rules": [
                        _rule(role="sent", destinations=[_destination("AccountC/SentRole")])
                    ],
                },
            },
            "global_rules": [
                _rule(folder="Sent", destinations=[_destination("Global/SentExact")]),
                _rule(role="sent", destinations=[_destination("Global/SentRole")]),
            ],
        }
    )
    plan = resolve_routing_plan(
        config,
        [
            SourceFolder("mailB@example.com", "Sent", attributes=("\\Sent",)),
            SourceFolder("mailC@example.com", "Sent", attributes=("\\Sent",)),
            SourceFolder("mailD@example.com", "Sent", attributes=("\\Sent",)),
        ],
        [],
    )
    by_account = {entry.source.source_account: entry for entry in plan.entries}
    assert by_account["mailB@example.com"].assignment_source == "account_exact"
    assert [item.name for item in by_account["mailB@example.com"].destinations] == [
        "Account/SentExact",
        "MailB/Sent",
    ]
    assert by_account["mailC@example.com"].assignment_source == "account_role"
    assert [item.name for item in by_account["mailC@example.com"].destinations] == ["AccountC/SentRole"]
    assert by_account["mailD@example.com"].assignment_source == "global_exact"
    assert [item.name for item in by_account["mailD@example.com"].destinations] == ["Global/SentExact"]


def test_exclusion_multiple_destinations_and_explicit_inbox_are_typed() -> None:
    config = RoutingConfig.from_dict(
        {
            "enabled": True,
            "accounts": {
                "mailB@example.com": {
                    "default_namespace": "MailB",
                    "rules": [
                        _rule(folder="Archive", exclude=True),
                        _rule(
                            folder="INBOX",
                            destinations=[
                                _destination("MailB"),
                                _destination("inbox", GMAIL_SYSTEM),
                                _destination("Shared", GENERIC_MAILBOX),
                            ],
                        ),
                    ],
                }
            },
        }
    )
    labels = [
        TargetLabel("INBOX", GMAIL_SYSTEM, system_role="inbox", target_id="INBOX"),
        TargetLabel("Shared", GENERIC_MAILBOX),
    ]
    plan = resolve_routing_plan(
        config,
        [
            SourceFolder("mailB@example.com", "Archive", attributes=("\\Archive",)),
            SourceFolder("mailB@example.com", "INBOX", attributes=("\\Inbox",)),
        ],
        labels,
    )
    by_name = {entry.source.name: entry for entry in plan.entries}
    assert by_name["Archive"].excluded
    assert by_name["Archive"].destinations == ()
    assert not by_name["Archive"].appears_in_inbox
    assert [item.kind for item in by_name["INBOX"].destinations] == [
        CUSTOM_LABEL,
        GMAIL_SYSTEM,
        GENERIC_MAILBOX,
    ]
    assert by_name["INBOX"].appears_in_inbox


def test_unsafe_gmail_spam_and_trash_require_acknowledgement_and_emit_warning() -> None:
    with pytest.raises(ValueError, match="unsafe for historical mail"):
        Destination.from_dict(_destination("spam", GMAIL_SYSTEM))
    with pytest.raises(ValueError, match="unsafe for historical mail"):
        Destination.from_dict(_destination("trash", GMAIL_SYSTEM, allow_unsafe=False))

    config = RoutingConfig.from_dict(
        {
            "enabled": True,
            "global_rules": [
                _rule(
                    role="junk",
                    destinations=[_destination("spam", GMAIL_SYSTEM, allow_unsafe=True)],
                )
            ],
        }
    )
    plan = resolve_routing_plan(
        config,
        [SourceFolder("mailB@example.com", "Junk E-mail")],
        [TargetLabel("[Gmail]/Spam", GMAIL_SYSTEM, system_role="spam", target_id="SPAM")],
    )
    assert plan.ok
    assert plan.entries[0].destinations[0].status == "existing"
    assert any("explicitly routed to unsafe Gmail system spam" in warning for warning in plan.warnings)


def test_exact_existing_label_is_reused_but_casefold_alias_is_a_conflict() -> None:
    exact_config = RoutingConfig.from_dict(
        {
            "enabled": True,
            "accounts": {"b@example.com": {"default_label": "MailB"}},
        }
    )
    source = [SourceFolder("b@example.com", "INBOX")]
    exact = resolve_routing_plan(exact_config, source, [_label("MailB", target_id="Label_7")])
    assert exact.ok
    assert exact.labels_reused == ("MailB",)
    assert exact.entries[0].destinations[0].target_id == "Label_7"

    folded_config = RoutingConfig.from_dict(
        {
            "enabled": True,
            "accounts": {"b@example.com": {"default_label": "MAILB"}},
        }
    )
    folded = resolve_routing_plan(folded_config, source, [_label("MailB", target_id="Label_7")])
    assert not folded.ok
    assert folded.entries[0].ambiguous
    assert any("conflicts by casefold" in issue for issue in folded.entries[0].ambiguities)


def test_target_name_hierarchy_and_system_conflicts_are_detected() -> None:
    config = RoutingConfig.from_dict(
        {
            "enabled": True,
            "accounts": {"b@example.com": {"default_label": "INBOX/Imported"}},
        }
    )
    plan = resolve_routing_plan(
        config,
        [SourceFolder("b@example.com", "INBOX")],
        [
            TargetLabel("INBOX", GMAIL_SYSTEM, system_role="inbox"),
            TargetLabel("Team/Sub", CUSTOM_LABEL, delimiter="/"),
            TargetLabel("Team.Sub", CUSTOM_LABEL, delimiter="."),
        ],
    )
    assert not plan.ok
    assert any("hierarchy conflict" in issue for issue in plan.conflicts)
    assert any("Gmail system ancestor" in issue for issue in plan.entries[0].ambiguities)

    allowed = RoutingConfig.from_dict(
        {
            "enabled": True,
            "accounts": {"b@example.com": {"default_label": "Team/Imported"}},
        }
    )
    allowed_plan = resolve_routing_plan(
        allowed,
        [SourceFolder("b@example.com", "INBOX")],
        [_label("Team")],
    )
    assert allowed_plan.ok
    assert allowed_plan.labels_to_create == ("Team/Imported",)


def test_conflicting_rules_at_the_same_precedence_are_ambiguous() -> None:
    config = RoutingConfig.from_dict(
        {
            "enabled": True,
            "accounts": {"b@example.com": {"default_namespace": "MailB"}},
            "global_rules": [
                _rule(role="junk", destinations=[_destination("Imported/Junk")]),
                _rule(role="junk", destinations=[_destination("Review/Junk")]),
            ],
        }
    )
    plan = resolve_routing_plan(config, [SourceFolder("b@example.com", "Spam")], [])
    assert not plan.ok
    assert plan.entries[0].ambiguous
    assert any("multiple conflicting global role rules" in issue for issue in plan.entries[0].ambiguities)


def test_filter_rules_emit_deliveredto_actions_and_label_reuse_or_creation() -> None:
    config = RoutingConfig.from_dict(
        {
            "enabled": True,
            "filters": [
                {
                    "delivered_to": "mailB@example.com",
                    "label": "MailB",
                    "inbox": "keep",
                    "mark_read": False,
                    "conflict_policy": "error",
                },
                {
                    "delivered_to": "mailC@example.com",
                    "label": "MailC",
                    "inbox": "archive",
                    "mark_read": True,
                    "conflict_policy": "replace",
                },
            ],
        }
    )
    plan = resolve_routing_plan(config, [], [_label("MailB", target_id="Label_B")])
    assert plan.ok
    assert plan.labels_reused == ("MailB",)
    assert plan.labels_to_create == ("MailC",)
    filters = {item.rule.delivered_to: item for item in plan.filters}
    assert filters["mailB@example.com"].rule.query == "deliveredto:mailB@example.com"
    assert filters["mailB@example.com"].target_label_id == "Label_B"
    assert filters["mailC@example.com"].rule.inbox == "archive"
    assert filters["mailC@example.com"].rule.mark_read
    assert filters["mailC@example.com"].rule.conflict_policy == "replace"

    serialized = plan.to_dict()
    assert json.loads(json.dumps(serialized, sort_keys=True))["filters"][1]["query"] == (
        "deliveredto:mailC@example.com"
    )


def test_plan_rejects_multiple_exclusive_gmail_system_destinations_on_one_folder() -> None:
    config = RoutingConfig.from_dict(
        {
            "enabled": True,
            "global_rules": [
                _rule(
                    folder="Special",
                    destinations=[
                        _destination("sent", GMAIL_SYSTEM),
                        _destination("trash", GMAIL_SYSTEM, allow_unsafe=True),
                    ],
                )
            ],
        }
    )
    plan = resolve_routing_plan(
        config,
        [SourceFolder("a@example.com", "Special")],
        [
            TargetLabel("[Gmail]/Sent Mail", GMAIL_SYSTEM, system_role="sent"),
            TargetLabel("[Gmail]/Trash", GMAIL_SYSTEM, system_role="trash"),
        ],
    )

    assert not plan.ok
    assert any(
        "incompatible Gmail system locations" in issue
        for issue in plan.entries[0].ambiguities
    )


@pytest.mark.parametrize(
    ("anchor_role", "anchor_target_name", "unsafe_role", "unsafe_target_name"),
    [
        ("all", "[Gmail]/All Mail", "spam", "[Gmail]/Spam"),
        ("all", "[Gmail]/All Mail", "trash", "[Gmail]/Trash"),
        ("inbox", "INBOX", "spam", "[Gmail]/Spam"),
        ("inbox", "INBOX", "trash", "[Gmail]/Trash"),
    ],
)
def test_plan_rejects_all_mail_or_inbox_with_spam_or_trash_on_one_folder(
    anchor_role: str,
    anchor_target_name: str,
    unsafe_role: str,
    unsafe_target_name: str,
) -> None:
    config = RoutingConfig.from_dict(
        {
            "enabled": True,
            "global_rules": [
                _rule(
                    folder="Special",
                    destinations=[
                        _destination(anchor_role, GMAIL_SYSTEM),
                        _destination(unsafe_role, GMAIL_SYSTEM, allow_unsafe=True),
                    ],
                )
            ],
        }
    )
    plan = resolve_routing_plan(
        config,
        [SourceFolder("a@example.com", "Special")],
        [
            TargetLabel(anchor_target_name, GMAIL_SYSTEM, system_role=anchor_role),
            TargetLabel(unsafe_target_name, GMAIL_SYSTEM, system_role=unsafe_role),
        ],
    )

    assert not plan.ok
    assert any(
        "incompatible Gmail system locations" in issue
        and anchor_role in issue
        and unsafe_role in issue
        for issue in plan.entries[0].ambiguities
    )


def test_plan_allows_inbox_and_sent_for_one_message() -> None:
    config = RoutingConfig.from_dict(
        {
            "enabled": True,
            "global_rules": [
                _rule(
                    folder="SentToSelf",
                    destinations=[
                        _destination("inbox", GMAIL_SYSTEM),
                        _destination("sent", GMAIL_SYSTEM),
                    ],
                )
            ],
        }
    )
    plan = resolve_routing_plan(
        config,
        [SourceFolder("a@example.com", "SentToSelf")],
        [
            TargetLabel("INBOX", GMAIL_SYSTEM, system_role="inbox"),
            TargetLabel("[Gmail]/Sent Mail", GMAIL_SYSTEM, system_role="sent"),
        ],
    )

    assert plan.ok
    assert not any("mutually exclusive" in warning for warning in plan.warnings)


def test_plan_rejects_gmail_drafts_plus_custom_label_on_one_folder() -> None:
    config = RoutingConfig.from_dict(
        {
            "enabled": True,
            "global_rules": [
                _rule(
                    folder="Drafts",
                    destinations=[
                        _destination("drafts", GMAIL_SYSTEM),
                        _destination("Review"),
                    ],
                )
            ],
        }
    )
    plan = resolve_routing_plan(
        config,
        [SourceFolder("a@example.com", "Drafts", attributes=("\\Drafts",))],
        [TargetLabel("[Gmail]/Drafts", GMAIL_SYSTEM, system_role="drafts")],
    )

    assert not plan.ok
    assert any(
        "drafts destination cannot be combined" in issue.lower()
        for issue in plan.entries[0].ambiguities
    )


def test_plan_warns_when_cross_folder_membership_could_combine_drafts_and_labels() -> None:
    config = RoutingConfig.from_dict(
        {
            "enabled": True,
            "global_rules": [
                _rule(
                    folder="Drafts",
                    destinations=[_destination("drafts", GMAIL_SYSTEM)],
                ),
                _rule(folder="Review", destinations=[_destination("Review")]),
            ],
        }
    )
    plan = resolve_routing_plan(
        config,
        [
            SourceFolder("a@example.com", "Drafts", attributes=("\\Drafts",)),
            SourceFolder("a@example.com", "Review"),
        ],
        [TargetLabel("[Gmail]/Drafts", GMAIL_SYSTEM, system_role="drafts")],
    )

    assert plan.ok
    assert any("shared by those folders" in warning for warning in plan.warnings)
    assert RoutingPlan.from_dict(plan.to_dict()) == plan


@pytest.mark.parametrize(
    "patch, needle",
    [
        ({"inbox": "maybe"}, "filter inbox"),
        ({"conflict_policy": "ignore"}, "conflict_policy"),
        ({"mark_read": 1}, "mark_read"),
    ],
)
def test_filter_rule_validation_is_strict(patch: dict, needle: str) -> None:
    rule = {
        "delivered_to": "mailB@example.com",
        "label": "MailB",
        **patch,
    }
    with pytest.raises(ValueError, match=needle):
        RoutingConfig.from_dict({"enabled": True, "filters": [rule]})


def test_duplicate_filter_conditions_are_rejected() -> None:
    with pytest.raises(ValueError, match="duplicate filter delivered_to"):
        RoutingConfig.from_dict(
            {
                "enabled": True,
                "filters": [
                    {"delivered_to": "MailB@example.com", "label": "MailB"},
                    {"delivered_to": "mailb@example.com", "label": "Other"},
                ],
            }
        )


def test_mapping_digest_is_deterministic_and_independent_of_target_create_status() -> None:
    config = RoutingConfig.from_dict(
        {
            "enabled": True,
            "accounts": {
                "b@example.com": {
                    "default_label": "MailB",
                    "default_namespace": "MailB",
                }
            },
            "filters": [{"delivered_to": "b@example.com", "label": "MailB"}],
        }
    )
    folders = [
        SourceFolder("b@example.com", "Sent", attributes=("\\Sent",)),
        SourceFolder("b@example.com", "INBOX", attributes=("\\Inbox",)),
    ]
    create_plan = resolve_routing_plan(config, folders, [])
    existing_plan = resolve_routing_plan(
        config,
        list(reversed(folders)),
        [_label("MailB/Sent", target_id="Label_S"), _label("MailB", target_id="Label_B")],
    )
    assert create_plan.mapping_digest == existing_plan.mapping_digest
    assert [entry.source.name for entry in create_plan.entries] == ["INBOX", "Sent"]
    assert create_plan.labels_to_create == ("MailB", "MailB/Sent")
    assert existing_plan.labels_reused == ("MailB", "MailB/Sent")


def test_mapping_digest_binds_normalized_source_discovery_metadata() -> None:
    config = RoutingConfig.from_dict(
        {
            "enabled": True,
            "accounts": {"b@example.com": {"default_label": "MailB"}},
        }
    )
    base = resolve_routing_plan(
        config,
        [SourceFolder("b@example.com", "INBOX", attributes=("\\Inbox",))],
        [],
    )
    casing_only = resolve_routing_plan(
        config,
        [SourceFolder("b@example.com", "INBOX", attributes=("\\INBOX",))],
        [],
    )
    changed_delimiter = resolve_routing_plan(
        config,
        [SourceFolder("b@example.com", "INBOX", delimiter="/", attributes=("\\Inbox",))],
        [],
    )
    changed_attributes = resolve_routing_plan(
        config,
        [
            SourceFolder(
                "b@example.com",
                "INBOX",
                attributes=("\\Inbox", "\\HasNoChildren"),
            )
        ],
        [],
    )

    assert base.mapping_digest == casing_only.mapping_digest
    assert base.mapping_digest != changed_delimiter.mapping_digest
    assert base.mapping_digest != changed_attributes.mapping_digest
    assert base.to_dict()["version"] == 2
    assert base.to_dict()["mapping_semantics"] == "all-selectable-memberships-v2"
    assert base.to_dict()["entries"][0]["attributes"] == ["\\inbox"]


def test_routing_plan_v1_fails_closed_with_fresh_preflight_guidance() -> None:
    config = RoutingConfig.from_dict(
        {
            "enabled": True,
            "accounts": {"b@example.com": {"default_label": "MailB"}},
        }
    )
    payload = resolve_routing_plan(
        config,
        [SourceFolder("b@example.com", "INBOX")],
        [],
    ).to_dict()
    payload["version"] = 1
    payload.pop("mapping_semantics")

    with pytest.raises(
        ValueError,
        match="version 1.*fresh routing preflight.*re-export",
    ):
        RoutingPlan.from_dict(payload)


@pytest.mark.parametrize(("length", "ok"), [(225, True), (226, False)])
def test_custom_label_full_name_length_boundary(length: int, ok: bool) -> None:
    label = "L" * length
    config = RoutingConfig.from_dict(
        {
            "enabled": True,
            "global_rules": [
                _rule(folder="Folder", destinations=[_destination(label)])
            ],
        }
    )

    plan = resolve_routing_plan(
        config,
        [SourceFolder("b@example.com", "Folder")],
        [],
    )

    assert plan.ok is ok
    assert plan.entries[0].destinations[0].status == (
        "create" if ok else "conflict"
    )
    if not ok:
        assert any("225-character full-name limit" in issue for issue in plan.entries[0].ambiguities)


def test_drafts_and_all_mail_are_compatible_neutral_system_destinations() -> None:
    config = RoutingConfig.from_dict(
        {
            "enabled": True,
            "global_rules": [
                _rule(
                    folder="Drafts",
                    destinations=[
                        _destination("drafts", GMAIL_SYSTEM),
                        _destination("all", GMAIL_SYSTEM),
                    ],
                )
            ],
        }
    )
    plan = resolve_routing_plan(
        config,
        [SourceFolder("b@example.com", "Drafts", attributes=("\\Drafts",))],
        [
            TargetLabel("[Gmail]/Drafts", GMAIL_SYSTEM, system_role="drafts"),
            TargetLabel("[Gmail]/All Mail", GMAIL_SYSTEM, system_role="all"),
        ],
    )

    assert plan.ok
    assert not plan.warnings
    assert {destination.name for destination in plan.entries[0].destinations} == {
        "all",
        "drafts",
    }


def test_generic_mailbox_destination_preserves_exact_name() -> None:
    config = RoutingConfig.from_dict(
        {
            "enabled": True,
            "global_rules": [
                _rule(folder="Projects", destinations=[_destination("Projects.Shared", GENERIC_MAILBOX)])
            ],
        }
    )
    plan = resolve_routing_plan(
        config,
        [SourceFolder("b@example.com", "Projects")],
        [TargetLabel("Projects.Shared", GENERIC_MAILBOX, delimiter=".")],
    )
    assert plan.ok
    destination = plan.entries[0].destinations[0]
    assert destination.name == "Projects.Shared"
    assert destination.status == "existing"


@pytest.mark.parametrize(
    ("configured_name", "discovered_name"),
    [("inbox", "INBOX"), ("InBoX", "INBOX"), ("INBOX", "inbox")],
)
def test_generic_inbox_destination_is_case_insensitive(
    configured_name: str,
    discovered_name: str,
) -> None:
    config = RoutingConfig.from_dict(
        {
            "enabled": True,
            "global_rules": [
                _rule(
                    folder="Source",
                    destinations=[
                        _destination(configured_name, GENERIC_MAILBOX)
                    ],
                )
            ],
        }
    )

    plan = resolve_routing_plan(
        config,
        [SourceFolder("b@example.com", "Source")],
        [TargetLabel(discovered_name, GENERIC_MAILBOX)],
    )

    assert plan.ok
    destination = plan.entries[0].destinations[0]
    assert destination.name == "INBOX"
    assert destination.status == "existing"
    assert destination.existing_name == discovered_name


def test_generic_non_inbox_destination_case_variant_remains_a_conflict() -> None:
    config = RoutingConfig.from_dict(
        {
            "enabled": True,
            "global_rules": [
                _rule(
                    folder="Source",
                    destinations=[_destination("project", GENERIC_MAILBOX)],
                )
            ],
        }
    )

    plan = resolve_routing_plan(
        config,
        [SourceFolder("b@example.com", "Source")],
        [TargetLabel("Project", GENERIC_MAILBOX)],
    )

    assert not plan.ok
    assert any(
        "conflicts by casefold" in issue
        for issue in plan.entries[0].ambiguities
    )


def test_generic_inbox_case_variants_share_one_contributor_group() -> None:
    config = RoutingConfig.from_dict(
        {
            "enabled": True,
            "global_rules": [
                _rule(
                    folder="One",
                    destinations=[_destination("inbox", GENERIC_MAILBOX)],
                ),
                _rule(
                    folder="Two",
                    destinations=[_destination("InBoX", GENERIC_MAILBOX)],
                ),
            ],
        }
    )

    plan = resolve_routing_plan(
        config,
        [
            SourceFolder("b@example.com", "One"),
            SourceFolder("b@example.com", "Two"),
        ],
        [TargetLabel("INBOX", GENERIC_MAILBOX)],
    )

    assert plan.ok
    assert {
        destination.name
        for entry in plan.entries
        for destination in entry.destinations
    } == {"INBOX"}
    assert all(entry.destinations[0].merged for entry in plan.entries)


def test_routing_plan_json_round_trip_preserves_empty_target_delimiter() -> None:
    config = RoutingConfig.from_dict(
        {
            "enabled": True,
            "accounts": {"b@example.com": {"default_label": "MailB"}},
        }
    )
    plan = resolve_routing_plan(
        config,
        [SourceFolder("b@example.com", "INBOX")],
        [TargetLabel("MailB", CUSTOM_LABEL, target_id="Label_B", delimiter="")],
    )

    payload = json.loads(json.dumps(plan.to_dict()))
    loaded = RoutingPlan.from_dict(payload)

    assert loaded == plan
    assert loaded.to_dict() == payload
    assert payload["discovered_target_labels"][0]["delimiter"] == ""


@pytest.mark.parametrize(
    "mutate, needle",
    [
        (lambda payload: payload.pop("warnings"), "missing required"),
        (lambda payload: payload.__setitem__("unexpected", True), "unknown field"),
        (
            lambda payload: payload["entries"][0]["destinations"][0].__setitem__("exists", False),
            "canonical serialized form",
        ),
        (
            lambda payload: payload["entries"][0].__setitem__("appears_in_inbox", True),
            "appears_in_inbox",
        ),
        (
            lambda payload: payload.__setitem__("mapping_digest", "0" * 64),
            "does not match",
        ),
        (
            lambda payload: payload["labels_to_create"].append("Misleading"),
            "labels_to_create",
        ),
    ],
)
def test_routing_plan_deserialization_rejects_noncanonical_or_tampered_json(
    mutate,
    needle: str,
) -> None:
    config = RoutingConfig.from_dict(
        {
            "enabled": True,
            "accounts": {"b@example.com": {"default_label": "MailB"}},
        }
    )
    plan = resolve_routing_plan(
        config,
        [SourceFolder("b@example.com", "INBOX")],
        [_label("MailB", target_id="Label_B")],
    )
    payload = json.loads(json.dumps(plan.to_dict()))
    mutate(payload)

    with pytest.raises(ValueError, match=needle):
        RoutingPlan.from_dict(payload)


def test_desired_custom_label_hierarchy_casing_collisions_are_rejected() -> None:
    config = RoutingConfig.from_dict(
        {
            "enabled": True,
            "global_rules": [
                _rule(folder="One", destinations=[_destination("MailB/One")]),
                _rule(folder="Two", destinations=[_destination("mailb/Two")]),
            ],
        }
    )
    plan = resolve_routing_plan(
        config,
        [
            SourceFolder("b@example.com", "One"),
            SourceFolder("b@example.com", "Two"),
        ],
        [],
    )

    assert not plan.ok
    assert any("hierarchy conflicts by casing" in issue for issue in plan.conflicts)

    existing_collision = resolve_routing_plan(
        RoutingConfig.from_dict(
            {
                "enabled": True,
                "global_rules": [
                    _rule(folder="Two", destinations=[_destination("mailb/Two")]),
                ],
            }
        ),
        [SourceFolder("b@example.com", "Two")],
        [_label("MailB/One")],
    )
    assert not existing_collision.ok
    assert any(
        "target/requested custom label hierarchy conflicts by casing" in issue
        for issue in existing_collision.conflicts
    )


@pytest.mark.parametrize(
    "name",
    [
        r"\Inbox",
        r"\Trash",
        r"\Junk",
        r"\Important",
        r"\Flagged",
        "[Gmail]/Spam",
        "[GoogleMail]/All Mail",
    ],
)
def test_custom_labels_that_restore_as_gmail_system_labels_are_rejected(name: str) -> None:
    config = RoutingConfig.from_dict(
        {
            "enabled": True,
            "accounts": {"b@example.com": {"default_label": name}},
        }
    )
    plan = resolve_routing_plan(
        config,
        [SourceFolder("b@example.com", "INBOX")],
        [],
    )

    assert not plan.ok
    assert any("conflicts with a Gmail system name" in issue for issue in plan.entries[0].ambiguities)
