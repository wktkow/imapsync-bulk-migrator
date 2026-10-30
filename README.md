# imapsync-bulk-migrator

Move mailboxes between mail servers in steps you can check, so you can prove
nothing was lost before you shut the old server down.

The tool downloads every message to your disk, checks that copy, uploads it to
the new server, and then confirms the new server has everything. Interrupted
steps can be rerun: messages that already made it across are skipped.

- Works with **Gmail**, **iCloud Mail**, and **any IMAP server**, including
  mail hosted on cPanel or DirectAdmin or read through Roundcube. Any source
  can go to any target.
- Can merge several mailboxes into one, and sort them into Gmail labels.
- Can create or wipe target mailboxes through cPanel or DirectAdmin before
  importing.

It's a command-line tool you run yourself, not a hosted migration service.
Everything beyond this page is in the [operator guide](docs/operator-guide.md).

## How it works

A migration runs in five stages, in this order:

| Stage       | What it does                                                                                             | Changes the target? |
| ----------- | -------------------------------------------------------------------------------------------------------- | ------------------- |
| `preflight` | Logs in to both sides and checks accounts, folders, and server features.                                 | No                  |
| `export`    | Downloads every message into a local staging directory (`.eml` files plus metadata), then runs `audit`. | No                  |
| `audit`     | Checks that the staged copy is complete and consistent.                                                  | No                  |
| `import`    | Uploads the staged messages, recording each one in a journal so a rerun resumes where it stopped.       | **Yes**             |
| `validate`  | Confirms every staged message is in the target.                                                          | No                  |

- `--mode migrate` runs the whole sequence as one resumable command. With
  Gmail label routing it also sets up labels and filters (see
  [when Gmail is changed](docs/operator-guide.md#when-gmail-is-changed)).
- `--mode test` only checks that every account can log in.
- `preflight` and `migrate` exist only in provider mode.

Each migration keeps its downloaded mail, plans, journals, and reports in its
**staging directory** (`./exported` by default). Point every stage
at the same one: `--output-dir` for `preflight`, `export`, and `migrate`;
`--input-dir` for `audit`, `import`, and `validate`.

> [!WARNING]
> The staging directory holds a full copy of every mailbox. Protect it, along
> with your configs, secrets, and logs.

## Install

Requires Python 3.10 or newer.

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
```

Legacy mode also needs the `imapsync` binary on your `PATH`, which it uses to
test logins. Provider mode doesn't.

## Quick start

This example moves one Gmail account to iCloud. Other providers work the same
way; only the config changes.

**1. Write `migration.config.json`.**

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

`folder_map` renames Gmail's special folders to their iCloud equivalents.

**2. Put each secret in its own file.** Relative paths start from the config
file's folder, and each file holds only the secret.

- `secrets/user.gmail.token`: a Gmail OAuth access token. The tool doesn't
  fetch or refresh tokens, so supply a valid one yourself.
- `secrets/user.icloud.app-password`: an iCloud
  [app-specific password](https://support.apple.com/en-us/102654).

**3. Confirm Gmail shows all mail over IMAP**, then change
`gmail_full_visibility_verified` to `true`. The flag is `false` in the sample
on purpose: Gmail can hide mail from IMAP, and the tool can't detect it, so
export refuses to start until you've checked. See the
[Gmail visibility check](docs/operator-guide.md#gmail-visibility-check).

**4. Check, then migrate.**

```bash
python3 imapsync_bulk_migrator.py --mode preflight --config migration.config.json --output-dir ./exported
python3 imapsync_bulk_migrator.py --mode migrate --config migration.config.json --output-dir ./exported
```

Exit code `0` means success. Anything else means stop and read the log (see
[exit codes](docs/operator-guide.md#exit-codes)). If `migrate` is interrupted,
run it again with the same staging directory. Its report is written to
`exported/migration-report.json`.

To run the stages one at a time instead:

```bash
python3 imapsync_bulk_migrator.py --mode export --config migration.config.json --output-dir ./exported
python3 imapsync_bulk_migrator.py --mode import --config migration.config.json --input-dir ./exported
python3 imapsync_bulk_migrator.py --mode validate --config migration.config.json --input-dir ./exported
```

Always pass `--config` to these: only `preflight` and `migrate` default to
`migration.config.json`. To re-check an existing export, run `--mode audit`.
To see every flag, run `python3 imapsync_bulk_migrator.py --help`.

## Which mode do I need?

The tool picks the mode from the config file: `source` and `target` objects
mean provider mode; a `server` object means legacy mode.

| You want to…                                                    | Use                                                                                                    |
| --------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| Move mail to or from Gmail or iCloud                            | [Provider mode](docs/operator-guide.md#provider-mode)                                                  |
| Move mail to a different address or provider                    | [Provider mode](docs/operator-guide.md#provider-mode)                                                  |
| Move mail hosted on cPanel, DirectAdmin, or Roundcube over IMAP | [Provider mode with `"provider": "imap"`](docs/operator-guide.md#generic-imap-roundcube-directadmin-and-cpanel-mail) |
| Merge several mailboxes into one                                | [Many-to-one merges](docs/operator-guide.md#many-to-one-merges)                                         |
| Merge several mailboxes into one Gmail account, sorted by label | [Gmail label routing](docs/operator-guide.md#gmail-label-routing)                                      |
| Move same-address mailboxes between two IMAP servers            | [Legacy mode](#legacy-mode-in-brief)                                                                   |
| Create or wipe target mailboxes through cPanel or DirectAdmin   | [Legacy mode with panel flags](docs/operator-guide.md#directadmin-and-cpanel)                          |

## Providers and credentials

| `provider` | `host`             | Allowed `auth.method`                 |
| ---------- | ------------------ | ------------------------------------- |
| `gmail`    | `imap.gmail.com`   | `xoauth2`, `app_password`             |
| `icloud`   | `imap.mail.me.com` | `app_password`                        |
| `imap`     | your server        | `password`, `app_password`, `xoauth2` |

For `imap`, use either `"ssl": true` (implicit TLS, the default) or
`"ssl": false, "starttls": true`; cleartext IMAP is rejected before any
password is sent.

Each `auth` block holds at most one secret: `password_file` (not for
`xoauth2`), `token_file` (`xoauth2` only), `env_var`, or an inline `password`.
With more than one account, credentials go on each account
(`accounts[].source_auth`, `accounts[].target_auth`). The one exception is a
`many_to_one` merge where every account shares one target, which can keep the
target login on `target.auth`. Unknown or misspelled
fields in a provider config are rejected, so a typo can't silently switch off
a safeguard.
Details: [settings](docs/operator-guide.md#settings) and
[credentials](docs/operator-guide.md#credentials).

## Legacy mode in brief

For same-address moves between two IMAP servers. Start from an
`export.pass.config.json` with a `server` and `accounts` (see the
[legacy config](docs/operator-guide.md#legacy-config), or
[generate one from a panel](docs/operator-guide.md#generating-a-config-from-a-panel)):

```bash
python3 imapsync_bulk_migrator.py --mode export --config export.pass.config.json --output-dir ./exported
python3 imapsync_bulk_migrator.py --mode import --config import.pass.config.json --input-dir ./exported
python3 imapsync_bulk_migrator.py --mode validate --config import.pass.config.json --input-dir ./exported
```

Export writes an `import.pass.config.json` template (unless one already
exists), with the target host set to `CHANGE_ME.example.com`. Fill in the target `server` before importing, and
keep `source_server` as it is. Adding panel flags to `import` creates missing
mailboxes through [cPanel or DirectAdmin](docs/operator-guide.md#directadmin-and-cpanel),
and `--reset` [wipes and recreates them](docs/operator-guide.md#destructive-reset).

## Before you shut down the old server

Don't retire the source server until all of these are true:

- [ ] Export finished without ignored errors.
- [ ] The staged audit passed.
- [ ] Import finished with no unresolved pending journal entries.
- [ ] Validation passed.
- [ ] If Gmail is the source or target, you did the
  [visibility check](docs/operator-guide.md#gmail-visibility-check) yourself.
- [ ] Representative mailbox spot checks confirm folders, flags, message
  bodies, dates, and labels where applicable.
- [ ] MX/DNS cutover, a final pass for mail that arrived during the migration,
  backups, and a rollback plan are documented outside this tool.

## Limitations

- `--reset` deletes target mailbox contents. Keep independent backups.
- IMAP UIDs aren't preserved, and Gmail targets don't keep `\Deleted` as a
  flag on appended messages.
- Live credentials are required for final proof: tests and dry runs can't
  guarantee that every provider accepts every operation in production.

The full list is in [known constraints](docs/operator-guide.md#known-constraints).

## Development

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest
python3 -m compileall components imapsync_bulk_migrator.py directadmin_indexer.py cpanel_indexer.py verify_export.py
```
