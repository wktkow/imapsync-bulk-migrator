# imapsync-bulk-migrator

Bulk IMAP export, import, audit, and validation for mailbox migrations where the
operator wants a filesystem staging copy before touching the target server.

This is not a live-service test harness. Without real provider credentials it
cannot prove Gmail, iCloud, DirectAdmin, cPanel, or a hosting provider will accept
every operation. The code is built around documented IMAP/control-panel behavior,
local contract tests, journals, and fail-fast checks so an operator can run a
controlled migration and decide when a source server is safe to decommission.

## Supported Routes

Provider staged mode supports every source-target combination of:

- `gmail`: Gmail IMAP at `imap.gmail.com:993` over SSL.
- `icloud`: iCloud Mail IMAP at `imap.mail.me.com:993` over SSL.
- `imap`: any generic IMAP server, including mailboxes normally accessed through
  Roundcube, cPanel webmail, DirectAdmin webmail, or another hosted webmail UI.

That means these route classes are supported through the same staged flow:

- Gmail to Gmail, Gmail to iCloud, Gmail to generic IMAP.
- iCloud to Gmail, iCloud to iCloud, iCloud to generic IMAP.
- Generic IMAP to Gmail, generic IMAP to iCloud, generic IMAP to generic IMAP.

Roundcube is treated as generic IMAP because Roundcube is a webmail client, not a
mail storage API. Use the backing IMAP host, username, and password/app password.

Legacy mode supports generic IMAP export/import for same-address account lists.
It also supports optional target mailbox provisioning through DirectAdmin or
cPanel before import.

## What Gets Preserved

Provider staged mode writes:

- One `.eml` per canonical message under `messages/`.
- One metadata file per canonical message under `metadata/`.
- `manifest.jsonl` for exact exported-message identity.
- `import-<target>.journal.jsonl` for import resume and validation.

Gmail source messages use `X-GM-MSGID` when Gmail advertises `X-GM-EXT-1`, so
messages visible through multiple labels are exported once. Gmail labels are
stored in metadata. When Gmail is the target, non-system Gmail labels are restored
with `+X-GM-LABELS` after APPEND or when a matching existing message is found by
`Message-ID` or content hash/size.

For Gmail sources, preflight and export require Gmail to advertise `X-GM-EXT-1`
and require Gmail's All Mail view to be visible through IMAP. Workspace/domain-wide
completeness still depends on OAuth scope and Gmail IMAP settings that expose all
labels/messages; the tool can validate the staged manifest, but it cannot discover
Gmail messages hidden from IMAP by account or domain settings. Gmail `Starred` and
`Important` are treated as system/special-use labels, not normal custom labels.

Generic IMAP and iCloud do not expose Gmail's cross-label identity. Physical
copies in different folders are preserved as separate messages. iCloud `VIP` is
treated as a virtual folder and skipped as a source mailbox.

Legacy mode writes `./exported/<email>/<folder>/u0000000001.eml` plus JSON
metadata. Legacy validation checks folder counts and best-effort message identity;
provider validation is manifest/journal identity-based.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# For tests
pip install -r requirements-dev.txt
```

Python 3.9+ is required. `requests` is used for DirectAdmin/cPanel integration.
`imapsync` is only used by legacy connectivity checks through `--justconnect`;
message export/import uses Python `imaplib`.

## Provider Staged Workflow

Use this for Gmail, iCloud, and provider-aware generic IMAP migrations.

```bash
python imapsync_bulk_migrator.py --mode preflight --config migration.config.json
python imapsync_bulk_migrator.py --mode export --config migration.config.json --output-dir ./exported
python imapsync_bulk_migrator.py --mode import --config migration.config.json --input-dir ./exported
python imapsync_bulk_migrator.py --mode validate --config migration.config.json --input-dir ./exported
python imapsync_bulk_migrator.py --mode audit --config migration.config.json --input-dir ./exported
```

Minimal provider config:

```json
{
  "source": {
    "provider": "gmail",
    "host": "imap.gmail.com",
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

For multi-account provider configs, put credentials and usernames on each account
override. The loader rejects shared endpoint secrets and shared endpoint usernames
that could accidentally migrate multiple accounts with one login.

## Legacy Generic IMAP Workflow

Use this for straightforward generic IMAP export/import where the same account
addresses and passwords are known.

```bash
python imapsync_bulk_migrator.py --mode export --config export.pass.config.json --output-dir ./exported
python imapsync_bulk_migrator.py --mode import --config import.pass.config.json --input-dir ./exported
python imapsync_bulk_migrator.py --mode validate --config import.pass.config.json --input-dir ./exported
```

Legacy config. Real `*.pass.config.json` files are local operator secrets and are
ignored by Git.

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
`CHANGE_ME.example.com` as the target host. Edit it before import.

## DirectAdmin And cPanel Provisioning

Provisioning is supported only for legacy generic IMAP imports. Provider configs
are protocol-level and intentionally do not call control-panel APIs.

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

Reset deletes and recreates target mailboxes. Non-dry-run reset first runs a
local staged export audit and aborts before any panel API call if staged data is
missing or inconsistent. It also requires `--reset-confirm` matching the target
IMAP host, or `YES`.

```bash
python imapsync_bulk_migrator.py --mode import --config import.pass.config.json \
  --input-dir ./exported \
  --auto-provision-cpanel \
  --reset --reset-confirm imap.target.example.com \
  --cpanel-url https://panel.example.com:2083 \
  --cpanel-username cpuser \
  --cpanel-token-file secrets/cpanel-api-token
```

Use `--da-dry-run` or `--cpanel-dry-run` before destructive runs. Panel dry-run
mode exits after the panel planning/provisioning step and does not run
connectivity tests or IMAP import.

## Indexers

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

## Decommission Checklist

Do not decommission a source server until all of this is true:

- Export completed without ignored errors.
- Audit passed for the staged export.
- Import completed without unresolved pending journal rows.
- Provider validation passed, or legacy validation matched expected counts and
  message identity probes.
- A spot-check of representative mailboxes in the target confirms folders,
  flags, message bodies, and Gmail labels where applicable.
- DNS/MX cutover and final delta/retry policy are documented outside this tool.

For provider mode, `validate` checks manifest identities and best-effort target
presence. For legacy mode, validation checks counts and best-effort identity by
`Message-ID` or content hash/size. Legacy `audit` performs the same identity
probe when run online; `--audit-offline` only checks the staged files. Both modes
should still be paired with representative mailbox spot checks before
decommissioning.

## Known Constraints

- Gmail Workspace migrations should use XOAUTH2. Workspace domain-wide IMAP
  migrations need OAuth setup outside this tool.
- Gmail app passwords are a personal-account fallback where Google still allows
  them. They are not a reliable Workspace migration strategy.
- Gmail IMAP has documented daily transfer limits. Large Gmail-target imports may
  require throttling, batching, or a Google-supported migration service.
- OAuth tokens are read from files at connection time. Token acquisition and
  refresh are external to this tool.
- iCloud requires app-specific passwords. Apple may require the local part as the
  username, or the full address if local-part login fails.
- IMAP UIDs are not preserved. Message identity is staged through content,
  metadata, Gmail IDs where available, and import journals.
- cPanel mailbox creation sends passwords to cPanel UAPI over HTTPS POST and
  redacts request errors; log files are created with mode `0600`.

## Official Behavior References

- Gmail IMAP/SMTP: https://developers.google.com/workspace/gmail/imap/imap-smtp
- Gmail XOAUTH2: https://developers.google.com/workspace/gmail/imap/xoauth2-protocol
- Gmail IMAP extensions: https://developers.google.com/workspace/gmail/imap/imap-extensions
- Gmail sending/receiving limits: https://support.google.com/a/answer/1071518
- iCloud Mail settings: https://support.apple.com/en-us/102525
- Apple app-specific passwords: https://support.apple.com/en-us/102654
- DirectAdmin legacy API: https://docs.directadmin.com/developer/api/legacy-api.html
- cPanel UAPI tokens: https://api.docs.cpanel.net/cpanel/tokens/
- cPanel UAPI email operations: https://api.docs.cpanel.net/specifications/cpanel.openapi/email-accounts/
- Roundcube project: https://roundcube.net/
