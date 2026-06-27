from __future__ import annotations

import hashlib
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
    if type(expected_size) is not int or expected_size <= 0:
        raise ValueError("missing or invalid rfc822_size")
    return {
        "content_sha256": expected_hash.lower(),
        "rfc822_size": expected_size,
    }


def _add_optional_text(fields: Dict[str, Any], record: Mapping[str, Any], key: str) -> None:
    value = record.get(key)
    if isinstance(value, str) and value:
        fields[key] = value


def _add_optional_int(fields: Dict[str, Any], record: Mapping[str, Any], key: str) -> None:
    value = record.get(key)
    if type(value) is int and value >= 0:
        fields[key] = value


def _content_binding_sha256(kind: str, fields: Mapping[str, Any]) -> str:
    return _sha256_json({"binding": "email-content-v1", "kind": kind, "fields": dict(fields)})


def legacy_content_binding_sha256(meta: Mapping[str, Any]) -> str:
    fields = _required_content_fields(meta)
    _add_optional_text(fields, meta, "mailbox")
    _add_optional_int(fields, meta, "uid")
    _add_optional_text(fields, meta, "flags")
    _add_optional_text(fields, meta, "internaldate")
    _add_optional_text(fields, meta, "message_id_header")
    return _content_binding_sha256("legacy-sidecar", fields)


def provider_content_binding_sha256(row: Mapping[str, Any]) -> str:
    fields = _required_content_fields(row)
    for key in (
        "canonical_id",
        "source_provider",
        "source_account",
        "target_account",
        "message_id_header",
        "flags",
        "internaldate",
        "eml_path",
        "metadata_path",
    ):
        _add_optional_text(fields, row, key)
    return _content_binding_sha256("provider-manifest", fields)


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
    return content_binding_issue(row, expected, required=required)
