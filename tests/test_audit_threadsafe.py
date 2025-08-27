import json
from pathlib import Path

from components.audit import audit_export
from components.models import Account, Config, ServerConfig


def test_audit_export_threadsafe_accum(tmp_path: Path) -> None:
    # Build a minimal fake export tree with two accounts and two folders each
    root = tmp_path / "exported"
    root.mkdir()

    emails = ["a@example.com", "b@example.com"]
    for email in emails:
        acc_dir = root / email
        acc_dir.mkdir()
        for folder in ["INBOX", "Sent Items"]:
            fdir = acc_dir / folder.replace(" ", "_")
            fdir.mkdir()
            # One message, but no json for it to force an issue
            (fdir / "u0000000001.eml").write_text("From: x\n\nbody")

    cfg = Config(server=ServerConfig(host="dummy"), accounts=[Account(email=e, password="") for e in emails])

    ok, issues = audit_export(root, cfg, max_workers=4, check_remote=False)

    assert not ok
    # Should have at least one issue per account, demonstrating accumulation worked without crashing
    assert any(i.startswith("a@example.com") for i in issues)
    assert any(i.startswith("b@example.com") for i in issues)


