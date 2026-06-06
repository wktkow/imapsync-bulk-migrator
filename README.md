# imapsync-bulk-migrator

Staged bulk mailbox migration tooling for IMAP providers and hosting panels.

The project is built for operators who need to move mailboxes, validate the
result, and make an evidence-based decision about when an old mail server can be
decommissioned. It exports mail into a local staging directory, imports into the
target, records journals for resume/validation, and provides guardrails for
DirectAdmin/cPanel mailbox reset workflows.

This is not a hosted migration service and it cannot prove provider behavior
without real credentials. It is designed to make live migrations safer by using
documented IMAP/control-panel behavior, local audits, explicit journals, and
fail-fast checks.

## Supported Routes

Provider staged mode supports every source-target combination of:

- `gmail`: Gmail IMAP at `imap.gmail.com:993`.
- `icloud`: iCloud Mail IMAP at `imap.mail.me.com:993`.
- `imap`: any generic IMAP server, including mailboxes normally accessed through
  Roundcube, DirectAdmin webmail, cPanel webmail, or another hosted webmail UI.

Supported route classes:

- Gmail to Gmail, iCloud, or generic IMAP.
- iCloud to Gmail, iCloud, or generic IMAP.
- Generic IMAP to Gmail, iCloud, or generic IMAP.

Roundcube is a webmail client, not a storage API. For Roundcube-backed accounts,
use the underlying IMAP host and mailbox credentials.

Legacy mode supports same-address generic IMAP export/import and can optionally
create or reset target mailboxes through DirectAdmin or cPanel before import.

## Why Staging Exists

A migration is split into explicit stages:

1. Export every selected source mailbox to local `.eml` files and metadata.
2. Audit the staged export before touching the target.
3. Import into the target with resume journals.
4. Validate staged identities against the target.
5. Only then decide whether the source server is safe to decommission.

This makes migrations inspectable and repeatable. It also gives you artifacts to
review when a provider throttles, disconnects, hides a folder, or returns
unexpected IMAP metadata.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Optional, for local tests
pip install -r requirements-dev.txt
```

Python 3.9+ is required. Message export/import uses Python `imaplib`.
DirectAdmin/cPanel integration uses `requests`. The `imapsync` binary is used
only for legacy connectivity checks, not for message copy operations.

## Provider Migration Workflow

Use provider mode for Gmail, iCloud, Gmail-to-Gmail, iCloud-to-Gmail, and generic
IMAP routes where source and target accounts can differ.

```bash
python imapsync_bulk_migrator.py --mode preflight --config migration.config.json
python imapsync_bulk_migrator.py --mode export --config migration.config.json --output-dir ./exported
python imapsync_bulk_migrator.py --mode audit --config migration.config.json --input-dir ./exported
python imapsync_bulk_migrator.py --mode import --config migration.config.json --input-dir ./exported
python imapsync_bulk_migrator.py --mode validate --config migration.config.json --input-dir ./exported
```

Minimal provider config:

```json
{
  "source": {
    "provider": "gmail",
    "host": "imap.gmail.com",
    "gmail_full_visibility_verified": false,
    "auth": {
      "method": "xoauth2"
    }
  },
  "target": {
    "provider": "icloud",
    "host": "imap.mail.me.com",
    "auth": {
      "method": "app_password"
    }
  },
  "migration": {
    "target_mode": "empty",
    "folder_map": {
      "[Gmail]/Sent Mail": "Sent",
      "[Gmail]/Drafts": "Drafts",
      "[Gmail]/Trash": "Deleted Messages",
      "[Gmail]/Spam": "Junk",
      "[Gmail]/All Mail": "Archive"
    }
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

For multi-account provider configs, put credentials and usernames on each
account override. Shared endpoint-level usernames or secrets are rejected to
avoid accidentally migrating multiple accounts with one login.

Gmail source migrations require `X-GM-EXT-1` and a visible All Mail view. Gmail
labels are captured in metadata. Provider preflight also requires
`source.gmail_full_visibility_verified=true` for Gmail sources. Set that flag
only after verifying the account is not hiding messages from IMAP, for example
by using Workspace XOAUTH2 with the `gmail.imap_admin` scope or by confirming
Gmail IMAP settings use no folder-size limit and required labels are visible in
IMAP. Without that, an IMAP scan can be internally consistent but still not be a
complete decommissioning proof.

When Gmail is the target, non-system Gmail labels are restored with
`+X-GM-LABELS`; Gmail `Starred` and `Important` are handled as special/system
labels rather than normal custom labels.

iCloud and generic IMAP do not expose Gmail's cross-label identity. Physical
copies in different folders are preserved as separate messages. iCloud `VIP` and
non-Gmail IMAP `\All` / `\Flagged` special-use views are treated as virtual
mailboxes and skipped as sources to avoid importing search views as duplicate
real folders.

For custom nested folders, provider mode stores source hierarchy segments and
translates them to the target server's advertised hierarchy delimiter during
import. If the target has no hierarchy delimiter, the source mailbox name is kept
literal. If two different source folder hierarchies would collapse into the
same translated target mailbox, import and target validation fail before
claiming the migration is safe.

Provider export writes an account-level `export-state.json` with the source
account, target account, completion flag, canonical message count, and a digest
of the manifest. Import, audit, and validation require that state to match the
manifest before trusting the staged data.

## Legacy Generic IMAP Workflow

Use legacy mode for straightforward same-address generic IMAP migrations.

```bash
python imapsync_bulk_migrator.py --mode export --config export.pass.config.json --output-dir ./exported
python imapsync_bulk_migrator.py --mode audit --config export.pass.config.json --input-dir ./exported
python imapsync_bulk_migrator.py --mode import --config import.pass.config.json --input-dir ./exported
python imapsync_bulk_migrator.py --mode validate --config import.pass.config.json --input-dir ./exported
```

Example legacy config:

```json
{
  "server": {
    "host": "imap.example.com",
    "port": 993,
    "ssl": true,
    "starttls": false
  },
  "accounts": [
    {
      "email": "user@example.com",
      "password": "secret"
    }
  ]
}
```

During legacy export, the tool generates `import.pass.config.json` with
`CHANGE_ME.example.com` as the target host. Edit that generated config before
import.

## DirectAdmin And cPanel

DirectAdmin and cPanel integration is available for legacy generic IMAP imports.
Provider configs do not call hosting panel APIs.

Every configured account must be a mailbox address in `local@domain` form. Panel
workflows fail fast for malformed accounts instead of silently skipping them.

DirectAdmin create-missing import:

```bash
python imapsync_bulk_migrator.py --mode import --config import.pass.config.json \
  --input-dir ./exported \
  --auto-provision-da \
  --da-url https://panel.example.com:2222 \
  --da-username admin \
  --da-password-file secrets/da-login-key
```

cPanel create-missing import:

```bash
python imapsync_bulk_migrator.py --mode import --config import.pass.config.json \
  --input-dir ./exported \
  --auto-provision-cpanel \
  --cpanel-url https://panel.example.com:2083 \
  --cpanel-username cpuser \
  --cpanel-token-file secrets/cpanel-api-token
```

Non-dry-run panel provisioning audits the staged export before any panel API
call. If the staged data is missing, malformed, or inconsistent, provisioning
aborts before accounts are created or reset.

## Server Decommissioning Workflows

The destructive reset path is meant for target preparation during server
replacement or decommissioning projects. It deletes and recreates target
mailboxes through the panel, then imports the staged mail.

```bash
python imapsync_bulk_migrator.py --mode import --config import.pass.config.json \
  --input-dir ./exported \
  --auto-provision-cpanel \
  --reset --reset-confirm imap.target.example.com \
  --cpanel-url https://panel.example.com:2083 \
  --cpanel-username cpuser \
  --cpanel-token-file secrets/cpanel-api-token
```

Reset safeguards:

- `--reset` requires DirectAdmin or cPanel provisioning.
- Non-dry-run reset requires `--reset-confirm` matching the target IMAP host, or
  `YES`.
- The staged legacy export must include per-message `content_sha256` and
  `rfc822_size` metadata matching the `.eml` payloads.
- The staged legacy export must include a completed account-level
  `export-state.json` written by a successful legacy export; hand-shaped or
  partial export directories are rejected before destructive reset.
- After a successful reset, stale legacy import journals for that account are
  archived before connectivity tests or import begin, so an old committed journal
  cannot make a freshly reset mailbox look imported.
- Failed panel resets cause the affected accounts to be skipped during import.
- When `--ignore-errors` is used with reset, connectivity tests and import run
  only for accounts whose panel reset succeeded; the command still exits
  non-zero if any account was skipped.
- Dry-run mode must be able to list panel mailboxes for each domain.

Use `--da-dry-run` or `--cpanel-dry-run` before destructive runs:

```bash
python imapsync_bulk_migrator.py --mode import --config import.pass.config.json \
  --input-dir ./exported \
  --auto-provision-da \
  --reset --da-dry-run \
  --da-url https://panel.example.com:2222 \
  --da-username admin \
  --da-password-file secrets/da-login-key
```

Panel dry-run exits after the panel planning/provisioning step. It does not run
connectivity tests, does not require the `imapsync` binary, and does not import
mail.

Do not decommission a source server until all of this is true:

- Export completed without ignored errors.
- Staged audit passed.
- Import completed without unresolved pending journal rows.
- Provider validation passed, or legacy validation matched expected counts and
  message identity probes.
- For Gmail sources, full IMAP visibility was verified before preflight by
  Workspace `gmail.imap_admin` access or Gmail IMAP settings that expose all
  required messages and labels.
- Representative mailbox spot checks confirm folders, flags, message bodies,
  dates, and Gmail labels where applicable.
- MX/DNS cutover, final delta policy, and rollback plan are documented outside
  this tool.

## Indexers

Indexers can generate legacy account config files from panel account listings.

DirectAdmin:

```bash
python directadmin_indexer.py \
  --url https://panel.example.com:2222 \
  --username user \
  --password-file secrets/da-login-key \
  --imap-host imap.example.com \
  --out export.pass.config.json
```

cPanel:

```bash
python cpanel_indexer.py \
  --url https://panel.example.com:2083 \
  --username cpuser \
  --token-file secrets/cpanel-api-token \
  --imap-host imap.example.com \
  --out export.pass.config.json
```

Generated config files are written with mode `0600`.

## Secret Hygiene

Local config and secret paths are ignored by Git:

- `*.pass.config.json*`
- `migration.config.json*`
- `migration.*.config.json*`
- `secrets/`

Prefer `*_file` or `*_env` options for panel credentials and mailbox secrets.
Inline password flags work where documented, but they can be exposed through
shell history or process arguments.

Log files are created with mode `0600`.

## Validation Model

Provider mode validation is manifest/journal based. It checks:

- Complete `export-state.json` matching the source account, target account,
  manifest message count, and manifest digest.
- Unique manifest identities.
- Manifest source and target account consistency.
- Required manifest integrity metadata.
- Per-message metadata JSON consistency with the manifest.
- Import journal consistency.
- Target folder mapping consistency, including translated hierarchy collision
  checks when target validation is enabled.
- Target message presence by `Message-ID` plus content hash/size where target
  validation is enabled.
- Expected Gmail labels when Gmail is the target.
- Gmail target `X-GM-MSGID` uniqueness across matched rows, so one Gmail message
  visible through multiple labels cannot satisfy multiple physical source
  messages.

Legacy validation checks folder counts and best-effort message identity by
`Message-ID` or content hash/size, consuming each remote match once so duplicate
local messages require duplicate remote messages. Legacy audit can run online or
offline; the pre-reset gate always requires strict local staged integrity checks
and completed account-level legacy export state.

## Known Constraints

- Live credentials are required for final proof. Local tests and dry-runs cannot
  guarantee a provider will accept every operation.
- Gmail Workspace migrations should use XOAUTH2. Workspace domain-wide IMAP
  migrations need OAuth setup outside this tool.
- Normal Gmail IMAP cannot prove that users disabled folder-size limits or label
  hiding. Treat Gmail source decommissioning as ready only after verifying
  Workspace `gmail.imap_admin` access or Gmail IMAP settings externally.
- Gmail app passwords are a personal-account fallback where Google still allows
  them. They are not a reliable Workspace migration strategy.
- Gmail IMAP has documented daily transfer limits. Large Gmail-target imports may
  require throttling, batching, or a Google-supported migration service.
- OAuth token acquisition and refresh are external to this tool.
- iCloud requires app-specific passwords. Apple may require the local part as
  the username, or the full address if local-part login fails.
- IMAP UIDs are not preserved. Message identity is staged through content,
  metadata, Gmail IDs where available, and import journals.
- Provider staged exports created by older versions may need to be rerun if they
  lack account-bound manifest rows or the current `export-state.json` manifest
  digest.
- DirectAdmin/cPanel reset deletes target mailbox contents. Use dry-run, verify
  staged data, and keep independent backups before destructive operations.

## Official Behavior References

- Gmail IMAP/SMTP: https://developers.google.com/workspace/gmail/imap/imap-smtp
- Gmail XOAUTH2: https://developers.google.com/workspace/gmail/imap/xoauth2-protocol
- Gmail IMAP extensions: https://developers.google.com/workspace/gmail/imap/imap-extensions
- Gmail API IMAP settings: https://developers.google.com/workspace/gmail/api/reference/rest/v1/ImapSettings
- Gmail sending/receiving limits: https://support.google.com/a/answer/1071518
- iCloud Mail settings: https://support.apple.com/en-us/102525
- Apple app-specific passwords: https://support.apple.com/en-us/102654
- DirectAdmin legacy API: https://docs.directadmin.com/developer/api/legacy-api.html
- cPanel UAPI tokens: https://api.docs.cpanel.net/cpanel/tokens/
- cPanel UAPI email operations: https://api.docs.cpanel.net/specifications/cpanel.openapi/email-accounts/
- Roundcube project: https://roundcube.net/
