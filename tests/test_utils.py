import pytest

from components.utils import parse_imap_uid_search_data, sanitize_for_path


@pytest.mark.parametrize(
    "source,expected",
    [
        ("INBOX", "INBOX"),
        ("INBOX/spam", "INBOX_spam"),
        ("Sent Items", "Sent_Items"),
        ("Drafts & Templates", "Drafts_Templates"),
        ("A/B\\C:D*E?F\"G<H>I|J", "A_B_C_D_E_F_G_H_I_J"),
    ],
)
def test_sanitize_for_path_equivalence(source: str, expected: str) -> None:
    assert sanitize_for_path(source) == expected


def test_parse_imap_uid_search_data_sorts_valid_uids() -> None:
    assert parse_imap_uid_search_data([b"4294967295 2 1"]) == [1, 2, 4294967295]


@pytest.mark.parametrize("payload", [b"0", b"4294967296", b"2:4", b"bad", b"01", b"\xff"])
def test_parse_imap_uid_search_data_rejects_invalid_tokens(payload: bytes) -> None:
    with pytest.raises(RuntimeError, match="UID"):
        parse_imap_uid_search_data([payload])

