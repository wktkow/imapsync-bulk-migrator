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
- `--no-audit-after-export`: Skip the automatic audit that runs after `export`.

Optional DirectAdmin auto‑provisioning flags (import mode):
- `--auto-provision-da`: Enable account auto‑creation for missing mailboxes.
- `--da-url URL`: DirectAdmin base URL, e.g. `https://panel.example.com:2222`.
- `--da-username USER`: DirectAdmin API username (user, reseller, or admin depending on scope).
- `--da-password PASS`: DirectAdmin API password or login key.
- `--da-no-verify-ssl`: Skip TLS certificate verification for the panel (use only if you understand the risks).
- `--da-dry-run`: Show what would be created without doing it.
- `--da-quota-mb N`: Quota for new mailboxes (0 = unlimited; default 0).

## Modes

- **export**: Connects to Server A and for each account downloads all folders/messages locally. Non-destructive. After export completes, an automatic audit runs (unless `--no-audit-after-export` is provided) to ensure the export is sane.
- **import**: Connects to Server B and imports all previously exported messages/folders.
- **test**: Performs deep env checks: Python version, disk space, `imapsync` availability, IMAP login via `imaplib`, and `imapsync --justconnect` for each account.
- **validate**: Compares local export counts to Server B counts. Optionally resyncs missing messages with `--resync-missing`.
- **audit**: Performs a thorough audit of an existing export directory. It checks that each folder has one `.eml` per message, pairs `.eml` with `.json` metadata, parses each message to ensure it’s valid RFC822, flags suspicious raw IMAP metadata (indicative of concatenation), and compares local counts versus the source server for each account.

During `export`, a template `import.pass.config.json` is auto-generated (if missing) using the same accounts, so teams can update the target server host later and perform the import when ready.

## Optional: Auto‑provision missing mailboxes on DirectAdmin

When importing into a DirectAdmin‑managed server, you can let the tool create any missing POP/IMAP mailboxes automatically with the same login and password as specified in your JSON config. This keeps the workflow simple and reduces manual pre‑staging.

What happens when enabled:
- Before connectivity tests in `import` mode, the tool queries the panel and creates any accounts that don’t exist yet.
- Additionally, if a login still fails during import, a one‑time “lazy” retry will auto‑create the mailbox and retry the login.
- New accounts are created with the password in your config; quota is set to `--da-quota-mb` (default 0 = unlimited).

Requirements:
- DirectAdmin URL, user, and password/login key with permission to create POP accounts for the target domains.
- The `requests` package (`pip install -r requirements.txt`).

Recommended setup (good UX):
1. Create a DirectAdmin Login Key (scoped, time‑limited, minimal privileges) rather than using a full password.
2. Ensure the API user can create POP accounts for the domains in scope.
3. Test with `--da-dry-run` first to see what would be created.

Example (pre‑provision + import):
```bash
python imapsync_bulk_migrator.py \
  --mode import \
  --config import.pass.config.json \
  --auto-provision-da \
  --da-url https://panel.example.com:2222 \
  --da-username apiuser \
  --da-password apikey_or_password \
  --da-quota-mb 0
```

Dry run first:
```bash
python imapsync_bulk_migrator.py --mode import --config import.pass.config.json \
  --auto-provision-da --da-url https://panel.example.com:2222 \
  --da-username apiuser --da-password apikey_or_password \
  --da-dry-run
```

Security notes:
- Treat `--da-password` like a secret. Prefer login keys with limited scope.
- Use `--da-no-verify-ssl` only in controlled environments.
- The tool creates only mailboxes that are missing; it does not delete or modify existing ones.

Troubleshooting tips:
- If pre‑provisioning fails, the tool will stop unless `--ignore-errors` is set. Fix credentials/permissions and retry.
- If login fails for a mailbox during import, the lazy auto‑provision will attempt a single create‑and‑retry. Check logs for `[da]` entries.

## Optional: Index domains and mailboxes from a control panel API

For environments where a control panel API is available (DirectAdmin-compatible), you can generate `export.pass.config.json` automatically by listing domains, selecting which domains are in scope, and enumerating all POP/IMAP mailboxes for those domains.

Script: `directadmin_indexer.py`

Requirements:
- Python 3.9+
- `requests` library (install via `pip install -r requirements.txt`)

Usage:

```bash
python directadmin_indexer.py \
  --url https://panel.example.com:2222 \
  --username apiuser \
  --password apikey_or_password \
  --imap-host imap.example.com \
  --imap-port 993 \
  --out export.pass.config.json
```

What it does:
- Authenticates to the API with basic auth.
- Lists all domains available to the authenticated user.
- Presents an interactive TUI to select the domains you want to include.
- Lists POP/IMAP mailboxes for the selected domains and builds a config with those addresses.
- Writes an `export.pass.config.json` compatible with this tool. You can provide a `--default-password` value to prefill passwords or leave them blank to fill later.

Flags:
- `--no-verify-ssl`: if the API uses a self-signed certificate.
- `--no-imap-ssl` and `--imap-starttls`: control IMAP connection parameters written to the JSON.
- `--overwrite`: allow overwriting an existing output file.

Example workflow:
1. Run `directadmin_indexer.py` and select affected domains.
2. Optionally edit `export.pass.config.json` to set or update passwords.
3. Run the migrator in export mode:

```bash
python imapsync_bulk_migrator.py --mode export --config export.pass.config.json
```

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
