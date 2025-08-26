# imapsync-bulk-migrator

Bulk export/import/validate IMAP mailboxes at scale with safety checks. This tool wraps Python's `imaplib` for exporting/importing messages locally and performs connectivity prechecks using the `imapsync` binary (`--justconnect`). It aims to be simple (KISS) and safe for large batches (thousands of mailboxes).

Core features require no third-party Python packages. You need Python 3.9+ and `imapsync` installed. Optional integrations (DirectAdmin auto‑provisioning and the indexer) use the `requests` package.

### Who is this for
- **Admins and migration teams** needing to back up or migrate many inboxes across domains and providers.
- **Scenario**: Backup everything from Server A first (non-destructive), later import into Server B when ready.
 - **DirectAdmin environments**: When importing into a server managed by a DirectAdmin‑compatible panel, missing mailboxes can be auto‑created with the same usernames/passwords as specified in the config for a frictionless cutover.

### Assumptions
- This script is strictly for server+domain to server+domain migrations. The same account (`email` + `password`) present in `export.pass.config.json` is assumed to be used in `import.pass.config.json`. You can generate the import template automatically during export. In DirectAdmin mode, if an account is missing, it can be auto‑created with the same password before import.
- No local IMAP server. All data is written to the filesystem.
- Export is non-destructive. Import creates missing folders if needed.
- On any error/block/issue, the default behavior is to stop immediately. You can opt into continuing other accounts with `--ignore-errors`.

## IMPORTANT: Notes and limitations

- Flags are preserved best-effort using IMAP APPEND; server-specific flags may vary.
- Message UIDs are not preserved; a deterministic filename is stored with metadata instead.
- Special folders naming can differ across servers; the script creates folders as needed during import.

## Installation

1) Ensure `imapsync` is installed and available in `PATH`.
2) Use Python 3.9+.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Quick start

```bash
# Export from source
python imapsync_bulk_migrator.py --mode export --config export.pass.config.json

# Import into target (with optional DirectAdmin pre-provision)
python imapsync_bulk_migrator.py --mode import --config import.pass.config.json \
  --auto-provision-da --da-url https://panel:2222 --da-username user --da-password key

# Audit an existing export
python imapsync_bulk_migrator.py --mode audit --config export.pass.config.json --input-dir ./exported
```

## CLI

Key arguments (see `--help` for all):
- `--mode {export,import,test,validate,audit}`
- `--config PATH` (defaults per mode)
- `--output-dir` / `--input-dir`
- `--max-workers N`, `--ignore-errors`, `--log-dir`, `--min-free-gb`
- `--no-connectivity-test`, `--no-audit-after-export`, `--audit-offline`
- `--imap-timeout SECONDS` (default 60)

DirectAdmin (import mode):
- `--auto-provision-da`, `--da-url`, `--da-username`, `--da-password`
- `--reset` (delete and recreate each mailbox before import)
- `--da-no-verify-ssl`, `--da-dry-run`, `--da-quota-mb`

## Modes

- export: Download all folders/messages to `./exported/<email>/<folder>/` with `.eml` + `.json` metadata.
- import: Restore messages using original mailbox names in metadata; creates folders if missing.
  - Optional DirectAdmin steps before import: `--reset` deletes then recreates each mailbox; otherwise `--auto-provision-da` only creates missing ones.
- test: Env + connectivity checks (`imaplib` + `imapsync --justconnect`).
- validate: Compare local counts to server; optional `--resync-missing`.
- audit: Thorough export check; optional remote counts unless `--audit-offline`.

A template `import.pass.config.json` is auto-generated during export (if missing) next to your `--config`.

## JSON config

```json
{
  "server": { "host": "imap.example.com", "port": 993, "ssl": true, "starttls": false },
  "accounts": [ { "email": "user@example.com", "password": "secret" } ]
}
```

## Tips

- Start with `--ignore-errors` off to fail fast; enable after you trust the environment.
- For DirectAdmin, try `--da-dry-run` first; lazy create-and-retry happens automatically during import when enabled.
- Use `--imap-timeout` to avoid hanging network calls.
- Ensure sufficient free space on the target filesystem (tool checks your paths).

## Indexer (optional)

Generate `export.pass.config.json` from a DirectAdmin-compatible API:

```bash
python directadmin_indexer.py --url https://panel:2222 --username user --password key \
  --imap-host imap.example.com --imap-port 993 --out export.pass.config.json
```

