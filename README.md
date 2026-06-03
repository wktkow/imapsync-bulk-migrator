# Why This Tool?

This project addresses a **very specific use case** with enterprise-grade requirements:

## 🎯 **Perfect For:**

1. **Large-scale migrations** requiring reliability and performance
2. **Server decommissioning workflows** - safely shut down source servers after export
3. **Filesystem-based operations** with full data control and portability
4. **Enterprise simplicity** - Map multiple domains, users, passwords, folders, emails, and states 1:1 from source → export → target in just **3 CLI commands**

> **Not just another imapsync wrapper** - this is a complete migration ecosystem with safety checks, validation, and automation.

## imapsync-bulk-migrator

Bulk export/import/validate IMAP mailboxes at scale with safety checks. It is safe for large batches (thousands of mailboxes).

Core features require Python 3.9+. Legacy generic IMAP connectivity tests use `imapsync --justconnect` unless skipped; provider-aware Gmail-to-iCloud mode uses Python `imaplib` directly. Optional integrations (DirectAdmin auto-provisioning and the indexer) use the `requests` package.

### Who is this for

- **Admins and migration teams** needing to back up or migrate many inboxes across domains and providers.
- **Scenario**: Backup everything from Server A first (non-destructive), later import into Server B when ready.
- **DirectAdmin environments**: When importing into a server managed by a DirectAdmin‑compatible panel, **_missing mailboxes can be auto‑created_** with the same usernames/passwords as specified in the config for a frictionless cutover.

### Assumptions

- This script is strictly for server+domain to server+domain migrations. The same account (`email` + `password`) present in `export.pass.config.json` is assumed to be used in `import.pass.config.json`. You can generate the import template automatically during export. In DirectAdmin mode, if an account is missing, it can be auto‑created with the same password before import.
- No local IMAP server. All data is written to the filesystem.
- Export is non-destructive. Import creates missing folders if needed.
- On any error/block/issue, the default behavior is to stop scheduling additional queued accounts. Accounts already in flight, up to `--max-workers`, may finish or fail. You can opt into continuing other accounts with `--ignore-errors`.

## IMPORTANT: Notes and limitations

- Flags are preserved best-effort using IMAP APPEND; server-specific flags may vary.
- Message UIDs are not preserved; a deterministic filename is stored with metadata instead.
- Special folders naming can differ across servers; the script creates folders as needed during import.
- Export will abort if two distinct mailbox names on the server sanitize to the same directory name (e.g., `Sent/Items` and `Sent|Items` both become `Sent_Items`). This prevents silent data loss.

## Installation

1. Use Python 3.9+.
2. Install `imapsync` only if you use the legacy generic IMAP workflow. Provider-aware Gmail-to-iCloud mode does not require it.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Optional, for local tests
pip install -r requirements-dev.txt
```

## Quick start

```bash
# Export from source
python imapsync_bulk_migrator.py --mode export --config export.pass.config.json

# Import into target (with optional DirectAdmin pre-provision)
python imapsync_bulk_migrator.py --mode import --config import.pass.config.json \
  --auto-provision-da --da-url https://panel:2222 --da-username user --da-password-file ./secrets/da-login-key

# Audit an existing export
python imapsync_bulk_migrator.py --mode audit --config export.pass.config.json --input-dir ./exported
```

Provider-aware Gmail-to-iCloud sequence:

```bash
python imapsync_bulk_migrator.py --mode preflight --config migration.config.json
python imapsync_bulk_migrator.py --mode export --config migration.config.json --output-dir ./exported
python imapsync_bulk_migrator.py --mode import --config migration.config.json --input-dir ./exported
python imapsync_bulk_migrator.py --mode validate --config migration.config.json --input-dir ./exported
```

## CLI

Key arguments (see `--help` for all):

- `--mode {export,import,test,validate,audit,preflight}`
- `--config PATH` (defaults per mode)
- `--output-dir` / `--input-dir`
- `--max-workers N`, `--ignore-errors`, `--log-dir`, `--min-free-gb`
- `--no-connectivity-test`, `--no-audit-after-export`, `--audit-offline`
- `--imap-timeout SECONDS` (default 60)
- `--resync-missing` is deprecated; validation reports mismatches without replaying APPENDs.

DirectAdmin (import mode):

- `--auto-provision-da`, `--da-url`, `--da-username`
- `--da-password-file PATH` or `--da-password-env NAME`; `--da-password` is still accepted for compatibility but can expose the secret through shell history or process arguments.
- `--reset` (delete and recreate each mailbox before import)
- `--da-no-verify-ssl`, `--da-dry-run`, `--da-quota-mb`

## Modes

- export: Download all folders/messages to `./exported/<email>/<folder>/` with `.eml` + `.json` metadata.
- import: Restore messages using original mailbox names in metadata; creates folders if missing.
  - Legacy import writes `import.journal.jsonl` in each staged account directory and skips already committed local messages on rerun. If a run stops after a pending append, retry stops for operator inspection because the target state is uncertain.
  - Optional DirectAdmin steps before import: `--reset` deletes then recreates each mailbox; otherwise `--auto-provision-da` only creates missing ones.
- test: Env + connectivity checks (`imaplib` plus `imapsync --justconnect` for legacy configs). `--no-connectivity-test` is not valid with `--mode test`.
- validate: Legacy mode compares local folder counts to server and reports mismatches; it does not prove message identity. Provider mode performs manifest/journal exact validation plus best-effort target checks. Validation does not automatically re-import missing mail because blind APPEND replay can create duplicates.
- audit: Thorough export check; optional remote counts unless `--audit-offline`.
- preflight: Provider-config only. Checks source/target auth, lists mailboxes, verifies Gmail capabilities, estimates source bytes, and applies the configured iCloud storage gate.

A template `import.pass.config.json` is auto-generated during export (if missing) next to your `--config` with file mode `0600`. **The template uses a placeholder server host (`CHANGE_ME.example.com`) — you must edit it to point to the destination server before running import.**

## JSON config

Legacy generic IMAP config:

```json
{
  "server": {
    "host": "imap.example.com",
    "port": 993,
    "ssl": true,
    "starttls": false
  },
  "accounts": [{ "email": "user@example.com", "password": "secret" }]
}
```

Provider-aware Gmail-to-iCloud config:

```json
{
  "source": {
    "provider": "gmail",
    "host": "imap.gmail.com",
    "port": 993,
    "ssl": true,
    "auth": {
      "method": "xoauth2"
    }
  },
  "target": {
    "provider": "icloud",
    "host": "imap.mail.me.com",
    "port": 993,
    "ssl": true,
    "available_bytes": 10737418240,
    "auth": {
      "method": "app_password"
    }
  },
  "migration": {
    "label_policy": "single_copy_preserve_metadata",
    "target_mode": "empty",
    "validation": "manifest_exact",
    "folder_map": {
      "INBOX": "INBOX",
      "[Gmail]/Sent Mail": "Sent",
      "[Gmail]/Drafts": "Drafts",
      "[Gmail]/Trash": "Deleted Messages",
      "[Gmail]/Spam": "Junk"
    }
  },
  "limits": {
    "retry_max_attempts": 5,
    "throttle": { "max_bytes_per_second": 50000 }
  },
  "accounts": [
    {
      "source_email": "user@gmail.com",
      "target_email": "user@icloud.com",
      "source_auth": {
        "method": "xoauth2",
        "username": "user@gmail.com",
        "token_file": "secrets/user.gmail.token"
      },
      "target_auth": {
        "method": "app_password",
        "username": "user",
        "password_file": "secrets/user.icloud.app-password"
      }
    }
  ]
}
```

Provider mode keeps the filesystem staging model but changes the exported layout under
`./exported/<source-email>/` to deduplicated `messages/`, `metadata/`,
`manifest.jsonl`, and `import-<target-email>.journal.jsonl` files. Gmail messages
with multiple labels are imported once by default; extra labels remain in metadata.
`target_mode: "empty"` requires target folders for uncommitted messages to be empty;
resumed runs allow messages already recorded in the import journal. Use
`target_mode: "merge"` for existing iCloud mailboxes.
Provider mode enforces the documented Gmail/iCloud IMAP endpoints: Gmail source must
use `imap.gmail.com:993` over SSL; iCloud target must use `imap.mail.me.com:993` over
SSL with an app-specific password. Workspace Gmail should use `xoauth2`; personal Gmail
can use app passwords where the account supports them. Workspace OAuth token
acquisition/refresh is external to this tool. The tool consumes the configured token
file for IMAP XOAUTH2.
Provider export is limited to messages and labels visible through Gmail IMAP for the
authenticated account. For Workspace domain-wide migrations, use an OAuth setup/scope
that exposes all labels/messages to IMAP before trusting a final validation report.
Gmail messages found in both All Mail and a special folder resolve to the special
folder first; All Mail is the Archive fallback only when no stronger folder/label wins.

## Tips

- Start with `--ignore-errors` off to fail fast; enable after you trust the environment.
- For DirectAdmin, try `--da-dry-run` first; dry-run disables both pre-provisioning and lazy create-and-retry during import.
- Use a positive finite `--imap-timeout` to avoid hanging network calls.
- Ensure sufficient free space on the target filesystem (tool checks your paths).

## Indexer (optional)

Generate `export.pass.config.json` from a DirectAdmin-compatible API:

```bash
python directadmin_indexer.py --url https://panel:2222 --username user --password-file ./secrets/da-login-key \
  --imap-host imap.example.com --imap-port 993 --out export.pass.config.json
```

## Features TODO:

- DirectAdmin full integration ✅
- Proper multithreading ✅
- cPanel full integration ❌
- cPanel<->DirectAdmin bidirectional translation layer ❌
