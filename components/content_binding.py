from __future__ import annotations

import contextlib
import hashlib
import itertools
import json
import re
from typing import Any, Dict, Mapping, Optional


CONTENT_BINDING_FIELD = "content_binding_sha256"
_HEX_SHA256 = re.compile(r"[0-9a-fA-F]{64}")


def _sha256_json(payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _required_content_fields(record: Mapping[str, Any]) -> Dict[str, Any]:
    expected_hash = record.get("content_sha256")
    if not isinstance(expected_hash, str) or not _HEX_SHA256.fullmatch(expected_hash):
        raise ValueError("missing or invalid content_sha256")
    expected_size = record.get("rfc822_size")
    if type(expected_size) is not int or expected_size < 0:
        raise ValueError("missing or invalid rfc822_size")
    return {
        "content_sha256": expected_hash.lower(),
        "rfc822_size": expected_size,
    }


def _add_optional_text(fields: Dict[str, Any], record: Mapping[str, Any], key: str) -> None:
    value = record.get(key)
    if isinstance(value, str) and value:
        fields[key] = value


def _add_optional_control_free_text(fields: Dict[str, Any], record: Mapping[str, Any], key: str) -> None:
    if key not in record or record.get(key) is None:
        return
    value = record.get(key)
    if value == "":
        return
    if not isinstance(value, str) or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValueError(f"invalid {key}")
    fields[key] = value


def _add_optional_int(fields: Dict[str, Any], record: Mapping[str, Any], key: str) -> None:
    value = record.get(key)
    if type(value) is int and value >= 0:
        fields[key] = value


def _add_optional_text_list(fields: Dict[str, Any], record: Mapping[str, Any], key: str) -> None:
    value = record.get(key)
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        fields[key] = list(value)


def _add_optional_text_list_strict(fields: Dict[str, Any], record: Mapping[str, Any], key: str) -> None:
    if key not in record or record.get(key) is None:
        return
    value = record.get(key)
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"invalid {key}")
    if value:
        fields[key] = list(value)


def _add_optional_text_list_map(fields: Dict[str, Any], record: Mapping[str, Any], key: str) -> None:
    if key not in record or record.get(key) is None:
        return
    value = record.get(key)
    if not isinstance(value, Mapping):
        raise ValueError(f"invalid {key}")
    normalized: Dict[str, Any] = {}
    for raw_key, raw_value in value.items():
        if not isinstance(raw_key, str):
            raise ValueError(f"invalid {key}")
        if not isinstance(raw_value, list) or any(not isinstance(item, str) for item in raw_value):
            raise ValueError(f"invalid {key}")
        normalized[raw_key] = list(raw_value)
    fields[key] = normalized


def _canonical_text_set(values: list[str]) -> list[str]:
    by_key: Dict[str, set[str]] = {}
    for value in values:
        by_key.setdefault(value.casefold(), set()).add(value)
    return [sorted(by_key[key])[0] for key in sorted(by_key)]


def normalize_provider_mailbox_attributes(value: Mapping[str, Any]) -> Dict[str, list[str]]:
    normalized: Dict[str, list[str]] = {}
    for raw_key, raw_value in value.items():
        if not isinstance(raw_key, str):
            raise ValueError("invalid source_mailbox_attributes")
        if not isinstance(raw_value, list) or any(not isinstance(item, str) for item in raw_value):
            raise ValueError("invalid source_mailbox_attributes")
        normalized[raw_key] = _canonical_text_set(raw_value)
    return normalized


def _add_optional_mailbox_attributes(fields: Dict[str, Any], record: Mapping[str, Any]) -> None:
    if "source_mailbox_attributes" not in record or record.get("source_mailbox_attributes") is None:
        return
    value = record.get("source_mailbox_attributes")
    if not isinstance(value, Mapping):
        raise ValueError("invalid source_mailbox_attributes")
    fields["source_mailbox_attributes"] = normalize_provider_mailbox_attributes(value)


def _content_binding_sha256(kind: str, fields: Mapping[str, Any]) -> str:
    return _sha256_json({"binding": "email-content-v1", "kind": kind, "fields": dict(fields)})


def legacy_content_binding_sha256(meta: Mapping[str, Any]) -> str:
    fields = _required_content_fields(meta)
    _add_optional_text(fields, meta, "account")
    _add_optional_text(fields, meta, "mailbox")
    _add_optional_int(fields, meta, "uid")
    _add_optional_text(fields, meta, "uidvalidity")
    _add_optional_text(fields, meta, "flags")
    _add_optional_text(fields, meta, "internaldate")
    _add_optional_text(fields, meta, "message_id_header")
    _add_optional_text(fields, meta, "source_delimiter")
    _add_optional_text_list_strict(fields, meta, "source_path_segments")
    return _content_binding_sha256("legacy-sidecar", fields)


def provider_content_binding_sha256(row: Mapping[str, Any]) -> str:
    return _provider_content_binding_sha256(row, normalize_mailbox_attributes=True)


def provider_content_binding_sha256_legacy_mailbox_attribute_order(row: Mapping[str, Any]) -> str:
    return _provider_content_binding_sha256(row, normalize_mailbox_attributes=False)


def _provider_content_binding_sha256(row: Mapping[str, Any], *, normalize_mailbox_attributes: bool) -> str:
    fields = _required_content_fields(row)
    for key in (
        "canonical_id",
        "source_provider",
        "source_account",
        "target_account",
        "flags",
        "internaldate",
        "eml_path",
        "metadata_path",
    ):
        _add_optional_text(fields, row, key)
    _add_optional_control_free_text(fields, row, "message_id_header")
    _add_optional_text(fields, row, "primary_mailbox")
    for key in ("source_mailboxes", "gmail_labels"):
        _add_optional_text_list(fields, row, key)
    _add_optional_text_list_map(fields, row, "source_mailbox_paths")
    if normalize_mailbox_attributes:
        _add_optional_mailbox_attributes(fields, row)
    else:
        _add_optional_text_list_map(fields, row, "source_mailbox_attributes")
    return _content_binding_sha256("provider-manifest", fields)


def provider_content_binding_matches(row: Mapping[str, Any], actual: str) -> bool:
    if actual == provider_content_binding_sha256(row):
        return True
    with contextlib.suppress(ValueError):
        if actual == provider_content_binding_sha256_legacy_mailbox_attribute_order(row):
            return True
        return actual in _provider_legacy_mailbox_attribute_order_binding_candidates(row)
    return False


def _provider_legacy_mailbox_attribute_order_binding_candidates(
    row: Mapping[str, Any],
    *,
    limit: int = 4096,
) -> set[str]:
    value = row.get("source_mailbox_attributes")
    if not isinstance(value, Mapping):
        return set()
    keys: list[str] = []
    variants_by_key: list[list[tuple[str, ...]]] = []
    candidate_count = 1
    for raw_key, raw_value in value.items():
        if not isinstance(raw_key, str):
            raise ValueError("invalid source_mailbox_attributes")
        if not isinstance(raw_value, list) or any(not isinstance(item, str) for item in raw_value):
            raise ValueError("invalid source_mailbox_attributes")
        variants = sorted(set(itertools.permutations(raw_value)))
        candidate_count *= max(1, len(variants))
        if candidate_count > limit:
            return set()
        keys.append(raw_key)
        variants_by_key.append(variants)
    candidates: set[str] = set()
    for combo in itertools.product(*variants_by_key):
        variant = dict(row)
        variant["source_mailbox_attributes"] = {
            key: list(attrs)
            for key, attrs in zip(keys, combo)
        }
        candidates.add(provider_content_binding_sha256_legacy_mailbox_attribute_order(variant))
    return candidates


def content_binding_issue(record: Mapping[str, Any], expected: str, *, required: bool = True) -> Optional[str]:
    actual = record.get(CONTENT_BINDING_FIELD)
    if actual is None:
        if required:
            return f"missing {CONTENT_BINDING_FIELD}"
        return None
    if not isinstance(actual, str) or not _HEX_SHA256.fullmatch(actual):
        return f"invalid {CONTENT_BINDING_FIELD}"
    if actual.lower() != expected:
        return f"{CONTENT_BINDING_FIELD} mismatch"
    return None


def legacy_content_binding_issue(meta: Mapping[str, Any], *, required: bool = True) -> Optional[str]:
    try:
        expected = legacy_content_binding_sha256(meta)
    except ValueError as exc:
        if required or CONTENT_BINDING_FIELD in meta:
            return f"invalid {CONTENT_BINDING_FIELD} inputs: {exc}"
        return None
    return content_binding_issue(meta, expected, required=required)


def provider_content_binding_issue(row: Mapping[str, Any], *, required: bool = True) -> Optional[str]:
    try:
        expected = provider_content_binding_sha256(row)
    except ValueError as exc:
        if required or CONTENT_BINDING_FIELD in row:
            return f"invalid {CONTENT_BINDING_FIELD} inputs: {exc}"
        return None
    actual = row.get(CONTENT_BINDING_FIELD)
    if actual is None:
        if required:
            return f"missing {CONTENT_BINDING_FIELD}"
        return None
    if not isinstance(actual, str) or not _HEX_SHA256.fullmatch(actual):
        return f"invalid {CONTENT_BINDING_FIELD}"
    if actual != expected and not provider_content_binding_matches(row, actual):
        return f"{CONTENT_BINDING_FIELD} mismatch"
    return None
