# imapsync-bulk-migrator

Bulk export/import/validate IMAP mailboxes at scale with safety checks. This tool wraps Python's `imaplib` for exporting/importing messages locally and performs connectivity prechecks using the `imapsync` binary (`--justconnect`). It aims to be simple (KISS) and safe for large batches (thousands of mailboxes).

The script does not depend on external Python packages. You only need Python 3.9+ and `imapsync` installed on the system.

### Who is this for
- **Admins and migration teams** needing to back up or migrate many inboxes across domains and providers.
- **Scenario**: Backup everything from Server A first (non-destructive), later import into Server B when ready.

### Assumptions
- This script is strictly for server+domain to server+domain migrations. The same account (`email` + `password`) present in `export.pass.config.json` is assumed to be used in `import.pass.config.json`. You can generate the import template automatically during export.
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
3) Optional: create a virtual environment and install requirements.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## CLI Usage

```bash
python imapsync_bulk_migrator.py --help
```

Key arguments:
- `--mode {export,import,test,validate}`: Operation mode.
- `--config PATH`: JSON config with `server` and `accounts`. Defaults per mode:
  - export -> `export.pass.config.json`
  - import -> `import.pass.config.json`
  - test -> `export.pass.config.json`
  - validate -> `import.pass.config.json`
- `--output-dir PATH`: Directory for exported data (default: `./exported`).
- `--input-dir PATH`: Directory to read for import/validate (default: `./exported`).
- `--max-workers N`: Parallel accounts (default: CPU cores or 4).
- `--ignore-errors`: Continue with other accounts on errors.
- `--log-dir PATH`: Log directory (default: `./logs`).
- `--min-free-gb FLOAT`: Fail if free disk is below this threshold.
- `--resync-missing`: In `validate` mode, try re-importing mismatched folders.

## Modes

- **export**: Connects to Server A and for each account downloads all folders/messages locally. Non-destructive.
- **import**: Connects to Server B and imports all previously exported messages/folders.
- **test**: Performs deep env checks: Python version, disk space, `imapsync` availability, IMAP login via `imaplib`, and `imapsync --justconnect` for each account.
- **validate**: Compares local export counts to Server B counts. Optionally resyncs missing messages with `--resync-missing`.

During `export`, a template `import.pass.config.json` is auto-generated (if missing) using the same accounts, so teams can update the target server host later and perform the import when ready.

## JSON Config Schema

Shared structure for both `export.pass.config.json` and `import.pass.config.json`:

```json
{
  "server": {
    "host": "imap.example.com",
    "port": 993,
    "ssl": true,
    "starttls": false
  },
  "accounts": [
    { "email": "user1@example.com", "password": "secret" },
    { "email": "user2@example.com", "password": "secret" }
  ]
}
```

### Example: export.pass.config.json (Server A)

```json
{
  "server": {
    "host": "imap.serverA.com",
    "port": 993,
    "ssl": true
  },
  "accounts": [
    { "email": "sales@c23.com", "password": "123" },
    { "email": "support@c23.com", "password": "123" }
  ]
}
```

### Example: import.pass.config.json (Server B)

After export, a template is written automatically. Update the `server.host` (and other fields if needed) to point to Server B:

```json
{
  "server": {
    "host": "imap.serverB.com",
    "port": 993,
    "ssl": true
  },
  "accounts": [
    { "email": "sales@c23.com", "password": "123" },
    { "email": "support@c23.com", "password": "123" }
  ]
}
```

## Case study

- Exported from `user:sales@c23.com|password:123`.
- The tool auto-generates `import.pass.config.json` with the same account credentials.
- Import is not run automatically. The other team can change DNS or swap providers and later run the import when ready.

## Data layout

Exported data is written to `./exported/<email>/<folder>/...` as `.eml` files and minimal metadata `.json` per message (flags, internaldate). Logs are written under `./logs/` with timestamped filenames.

## Safety and error handling

- Fail-fast on environment issues (Python version, disk space, missing `imapsync`).
- On any error the default is to stop. Use `--ignore-errors` to continue with other accounts.
- Thorough connectivity checks via IMAP login and `imapsync --justconnect` before any export/import work.
