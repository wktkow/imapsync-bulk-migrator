import pytest

from components.utils import sanitize_for_path


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


