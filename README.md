# imapsync-bulk-migrator

Staged, auditable mailbox migration tooling for IMAP providers and hosting
panels.

This project is for operators who need to move mailboxes, prove what was
staged, import into a new destination, and make a careful server
decommissioning decision. It works in explicit stages: export, audit, import,
and validate. The same workflow supports normal mailbox moves and destructive
target reset flows for DirectAdmin and cPanel hosted mail.

It is not a hosted migration service.

## What It Supports

Provider-aware migrations support every combination of:

- `gmail`: Gmail IMAP on `imap.gmail.com:993`.
- `icloud`: iCloud Mail IMAP on `imap.mail.me.com:993`.
- `imap`: generic IMAP servers, including mailboxes normally reached through
  Roundcube, DirectAdmin webmail, cPanel webmail, or another webmail UI.

That means Gmail to Gmail, Gmail to iCloud, Roundcube-backed IMAP to iCloud,
DirectAdmin-hosted IMAP to Gmail, cPanel-hosted IMAP to another IMAP server,
and many other source-target pairs use the same staged model.

Gmail routes are IMAP copy workflows. For Google Workspace Gmail targets,
Google directs migrations to supported Workspace migration options instead of
IMAP upload. Treat this tool's Workspace Gmail target path as a technical
operator-managed copy route, not Google's recommended migration path.

Legacy generic IMAP mode supports same-address migrations and optional
DirectAdmin/cPanel mailbox creation or reset before import. The reset path is
intended for server replacement and decommissioning projects where target
mailboxes must be recreated before staged mail is imported.

## Why Staging Matters

The tool writes local `.eml` payloads, metadata, manifests, export state, and
import journals. Those artifacts let you:

- audit exports before touching the destination;
- resume imports without blindly duplicating committed messages;
- validate target state against staged identities;
- bind staged data to the expected source and target endpoints;
- review evidence before shutting down an old mail server.

## Documentation

Detailed docs are in [`/docs`](docs/README.md). Start there for
provider caveats, DirectAdmin/cPanel reset safeguards, validation details, and
official behavior references.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt

# Optional, for local tests
python3 -m pip install -r requirements-dev.txt
```

Python 3.9+ is required. Provider-aware copy operations use Python `imaplib`.
DirectAdmin and cPanel integrations use `requests`. Legacy generic IMAP
connectivity tests also use the `imapsync` binary unless connectivity checks
are skipped or a panel dry-run exits before import.

Inspect the CLI with:

```bash
python3 imapsync_bulk_migrator.py --help
```

## Choose a Mode

| Use case                                                                          | Mode                                                     |
| --------------------------------------------------------------------------------- | -------------------------------------------------------- |
| Gmail, iCloud, or cross-account generic IMAP migrations                           | Provider config with `source` and `target`               |
| Roundcube-backed, DirectAdmin-hosted, or cPanel-hosted mailbox moves through IMAP | Provider config with `provider: "imap"`                  |
| Same-address generic IMAP migration                                               | Legacy config with `server` and `accounts`               |
| DirectAdmin/cPanel mailbox create or reset before import                          | Legacy import with panel flags                           |
| Merge several source inboxes into one target inbox                                | Provider config with `account_merge_mode: "many_to_one"` |

## Provider Workflow

Use provider mode when source and target accounts may differ, including Gmail,
iCloud, generic IMAP, and many-to-one account merges.

```bash
python3 imapsync_bulk_migrator.py --mode preflight --config migration.config.json
python3 imapsync_bulk_migrator.py --mode export --config migration.config.json --output-dir ./exported
python3 imapsync_bulk_migrator.py --mode audit --config migration.config.json --input-dir ./exported
python3 imapsync_bulk_migrator.py --mode import --config migration.config.json --input-dir ./exported
python3 imapsync_bulk_migrator.py --mode validate --config migration.config.json --input-dir ./exported
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

The Gmail visibility flag is deliberately false in the sample. Set it only
after verifying that Gmail IMAP exposes the full mailbox for the account.
Without that external check, a Gmail IMAP scan can be internally consistent but
still incomplete.

## Many-To-One Merges

Provider mode can intentionally import multiple source inboxes into one target
inbox. Set `migration.account_merge_mode` to `many_to_one`, point multiple
accounts at the same `target_email`, and use the same effective target login.

```json
{
  "source": {
    "provider": "imap",
    "host": "imap.old.example.com",
    "auth": {
      "method": "password"
    }
  },
  "target": {
    "provider": "imap",
    "host": "imap.new.example.com",
    "auth": {
      "method": "password",
      "username": "a@example.com",
      "password_file": "secrets/a-target.password"
    }
  },
  "migration": {
    "target_mode": "empty",
    "account_merge_mode": "many_to_one"
  },
  "accounts": [
    {
      "source_email": "a@example.com",
      "target_email": "a@example.com",
      "source_auth": {
        "method": "password",
        "username": "a@example.com",
        "password_file": "secrets/a-source.password"
      }
    },
    {
      "source_email": "b@example.com",
      "target_email": "a@example.com",
      "source_auth": {
        "method": "password",
        "username": "b@example.com",
        "password_file": "secrets/b-source.password"
      }
    }
  ]
}
```

Shared-target imports are serialized even when `--max-workers` is higher than
one. In `target_mode=empty`, the destination may contain only messages already
accounted for by journals from the same merge group.

Hybrid merge example:

```json
{
  "source": {
    "provider": "imap",
    "host": "imap.old.example.com",
    "auth": {
      "method": "password"
    }
  },
  "target": {
    "provider": "imap",
    "host": "imap.new.example.com",
    "auth": {
      "method": "password"
    }
  },
  "migration": {
    "target_mode": "empty",
    "account_merge_mode": "many_to_one"
  },
  "accounts": [
    {
      "source_email": "a@example.com",
      "target_email": "a@example.com",
      "source_auth": {"method": "password", "username": "a@example.com", "password_file": "secrets/a-source.password"},
      "target_auth": {"method": "password", "username": "a@example.com", "password_file": "secrets/a-target.password"}
    },
    {
      "source_email": "b@example.com",
      "target_email": "a@example.com",
      "source_auth": {"method": "password", "username": "b@example.com", "password_file": "secrets/b-source.password"},
      "target_auth": {"method": "password", "username": "a@example.com", "password_file": "secrets/a-target.password"}
    },
    {
      "source_email": "c@example.com",
      "target_email": "a@example.com",
      "source_auth": {"method": "password", "username": "c@example.com", "password_file": "secrets/c-source.password"},
      "target_auth": {"method": "password", "username": "a@example.com", "password_file": "secrets/a-target.password"}
    },
    {
      "source_email": "d@example.com",
      "target_email": "d@example.com",
      "source_auth": {"method": "password", "username": "d@example.com", "password_file": "secrets/d-source.password"},
      "target_auth": {"method": "password", "username": "d@example.com", "password_file": "secrets/d-target.password"}
    },
    {
      "source_email": "e@example.com",
      "target_email": "e@example.com",
      "source_auth": {"method": "password", "username": "e@example.com", "password_file": "secrets/e-source.password"},
      "target_auth": {"method": "password", "username": "e@example.com", "password_file": "secrets/e-target.password"}
    }
  ]
}
```

Here `a`, `b`, and `c` import into the target login `a@example.com`; `d` and
`e` stay one-to-one. In hybrid configs, put target credentials on each account
so unrelated one-to-one accounts do not accidentally reuse the merge target
login. In `many_to_one` mode, imports are processed by target group; the
important guarantee is that each distinct target login keeps its own
empty-target gate, while journals remain account-local and target-bound.

## Legacy Panel Workflow

Use legacy mode for same-address generic IMAP migrations and hosting-panel
workflows.

```bash
python3 imapsync_bulk_migrator.py --mode export --config export.pass.config.json --output-dir ./exported
python3 imapsync_bulk_migrator.py --mode audit --config export.pass.config.json --input-dir ./exported
python3 imapsync_bulk_migrator.py --mode import --config import.pass.config.json --input-dir ./exported
python3 imapsync_bulk_migrator.py --mode validate --config import.pass.config.json --input-dir ./exported
```

During legacy export, the tool writes an `import.pass.config.json` template with
the old server recorded as `source_server`. Edit the generated target `server`
block before import; keep `source_server` intact so audits and reset gates can
prove the staged data came from the expected old server.

DirectAdmin and cPanel imports can create missing target mailboxes:

```bash
python3 imapsync_bulk_migrator.py --mode import --config import.pass.config.json \
  --input-dir ./exported \
  --auto-provision-cpanel \
  --cpanel-url https://panel.example.com:2083 \
  --cpanel-username cpuser \
  --cpanel-token-file secrets/cpanel-api-token
```

For server decommissioning workflows, `--reset` deletes and recreates target
mailboxes through DirectAdmin or cPanel before import. Non-dry-run reset
requires `--reset-confirm` matching the target IMAP host, or `YES`.

```bash
python3 imapsync_bulk_migrator.py --mode import --config import.pass.config.json \
  --input-dir ./exported \
  --auto-provision-cpanel \
  --reset --reset-confirm imap.target.example.com \
  --cpanel-url https://panel.example.com:2083 \
  --cpanel-username cpuser \
  --cpanel-token-file secrets/cpanel-api-token
```

Use `--da-dry-run` or `--cpanel-dry-run` before destructive panel runs.

## Indexers

Read-only indexers can generate legacy account configs from panel account
listings:

```bash
python3 directadmin_indexer.py \
  --url https://panel.example.com:2222 \
  --username user \
  --password-file secrets/da-login-key \
  --imap-host imap.example.com \
  --out export.pass.config.json

python3 cpanel_indexer.py \
  --url https://panel.example.com:2083 \
  --username cpuser \
  --token-file secrets/cpanel-api-token \
  --imap-host imap.example.com \
  --out export.pass.config.json
```

Generated config files are written with mode `0600`.

## Decommissioning Checklist

Do not retire a source server until all of these are true:

- export completed without ignored errors;
- staged audit passed;
- import completed without unresolved pending journal rows;
- validation passed for the relevant provider or legacy workflow;
- Gmail full-visibility checks were performed outside the tool when Gmail is a
  source or target;
- representative mailbox spot checks confirm folders, flags, message bodies,
  dates, and labels where applicable;
- MX/DNS cutover, final delta handling, backups, and rollback are documented
  outside this tool.

## Safety Notes

- DirectAdmin/cPanel reset deletes target mailbox contents.
- OAuth token acquisition and refresh are external to this project.
- Staged exports contain full mailbox data; protect `exported/`, logs, configs,
  and secrets as sensitive data.
- iCloud requires app-specific passwords, and Apple requires two-factor
  authentication before those passwords can be generated.
- Gmail app passwords, where Google still allows them, require 2-Step
  Verification and may be unavailable for Workspace, security-key-only, or
  Advanced Protection accounts.
- Personal Gmail identities fold dotted `gmail.com` aliases and
  `googlemail.com` aliases to the same mailbox for validation and merge
  grouping.
- Google Workspace does not support password-only third-party IMAP/POP/SMTP as
  a production assumption; Workspace Gmail routes need OAuth/XOAUTH2 where
  Google permits IMAP access.
- For Google Workspace Gmail targets, Google recommends supported migration
  options instead of IMAP upload. Use this tool's Gmail target route only after
  explicitly accepting that it is an operator-managed IMAP copy outside
  Google's recommended migration path.
- IMAP UIDs are not preserved.
- Provider imports preserve portable flags where the target supports them.
  Unsupported IMAP keywords can stop an import, and Gmail targets do not
  preserve `\Deleted` as an appended message flag.
- Live credentials are required for final proof. Local tests and dry-runs cannot
  guarantee that every provider will accept every operation in production.

## Tests

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest
python3 -m compileall components imapsync_bulk_migrator.py directadmin_indexer.py cpanel_indexer.py verify_export.py
```
