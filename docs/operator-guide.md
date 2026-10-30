# Operator guide

The full reference for imapsync-bulk-migrator: every mode, setting, safeguard,
and file it writes, for mailbox migrations and server decommissioning. For a
short introduction and a quick start, see the [README](../README.md).

Terms used throughout:

- **Staging directory**: the local folder that holds one migration's
  downloaded mail, plans, journals, and reports. Set it with `--output-dir` or
  `--input-dir` (default `./exported`). Log messages and reports call it the
  *staging root*.
- **Journal**: the per-account record of what import has done. It lets a rerun
  resume without re-importing committed messages.
- **Plan**: the routing decisions that preflight freezes for review. Later
  stages follow it exactly.

## Contents

- [Requirements](#requirements)
- [How a migration runs](#how-a-migration-runs)
- [CLI reference](#cli-reference)
- [Provider mode](#provider-mode)
- [Gmail](#gmail)
- [iCloud](#icloud)
- [Generic IMAP, Roundcube, DirectAdmin, and cPanel mail](#generic-imap-roundcube-directadmin-and-cpanel-mail)
- [Many-to-one merges](#many-to-one-merges)
- [Gmail label routing](#gmail-label-routing)
- [Workspace aliases (optional)](#workspace-aliases-optional)
- [Legacy mode](#legacy-mode)
- [DirectAdmin and cPanel](#directadmin-and-cpanel)
- [Destructive reset](#destructive-reset)
- [Validation](#validation)
- [Staged files, locks, and reports](#staged-files-locks-and-reports)
- [Secret hygiene](#secret-hygiene)
- [Export verifier](#export-verifier)
- [Known constraints](#known-constraints)
- [Official references](#official-references)

## Requirements

- Python 3.10 or newer. The CLI checks this at startup.
- The packages in `requirements.txt`: `requests`, `google-auth`, and `idna`.
  Provider copy operations use Python's `imaplib`, the DirectAdmin and cPanel
  integrations use `requests`, and Workspace service-account credentials use
  `google-auth`.
- Legacy mode only: the `imapsync` binary on your `PATH`. Legacy `export`,
  `import`, `validate`, and `test` run `imapsync --justconnect` as a login
  check. They don't need it when connectivity checks are skipped with
  `--no-connectivity-test` (not allowed with `test`), or when a panel dry run
  exits before import.
- Encrypted IMAP. Every IMAP endpoint the tool connects to must use implicit
  TLS or STARTTLS. Cleartext IMAP configs are rejected before credentials can
  be sent.

## How a migration runs

### Why staging

The tool writes every message to local `.eml` files, together with metadata,
manifests, export state, and import journals. Those files let you:

- audit an export before importing historical messages into the destination;
- resume imports without blindly duplicating committed messages;
- validate the target against the staged message identities;
- bind staged data to the expected source and target endpoints;
- review the evidence before shutting down an old mail server.

### Provider mode and legacy mode

|            | Provider mode                                                               | Legacy mode                                                        |
| ---------- | --------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| Use it for | Gmail, iCloud, generic IMAP, and any pair where the address or provider changes | Same-address generic IMAP moves, and DirectAdmin/cPanel provisioning |
| Config     | `source`, `target`, `accounts`                                              | `server`, `accounts`                                               |
| Modes      | All, including `preflight` and `migrate`                                    | `test`, `export`, `audit`, `import`, `validate`                    |
| Panel APIs | Never called                                                                | Optional mailbox create and reset                                  |

The tool picks the mode from the config file: one with both `source` and
`target` objects is a provider config, and anything else is read as a legacy
config.

### Provider stages

1. **Preflight.** Check connectivity and capacity, and build any opt-in
   routing and Workspace alias plans.
2. **Early Gmail setup** (top-level `migrate` only, when future-delivery
   filters are requested). Right after the plans are saved, reconcile and
   verify every required Gmail label and filter, before export begins.
   Standalone `export` deliberately skips Gmail reconciliation and only reads
   the frozen plans.
3. **Export.** Copy the selected source mailboxes into local `.eml` files and
   metadata.
4. **Audit.** Check the staged export before any historical mail is imported
   into the target. Export runs this audit automatically unless you
   explicitly pass `--no-audit-after-export`.
5. **Gmail labels.** A `migrate` run without filters reconciles the required
   Gmail labels here. Standalone `import` reconciles and verifies all
   requested Gmail labels and filters here, before importing.
6. **Import.** Upload into the target, with resume journals.
7. **Aliases** (Workspace alias automation only). Immediately before creating
   aliases, repeat the Gmail reconciliation and verification gate. Then create
   missing aliases, only after the filters verify and the historical import is
   complete.
8. **Validate.** Check staged identities, routed label membership, and Gmail
   settings.
9. **Verify aliases** (alias automation only). Confirm final Workspace alias
   ownership.
10. **Review.** Read the final report before deciding whether the old server
    can be decommissioned.

Most stages can also run on their own. With alias automation, provider
export, import, and validation go through `migrate`, so the audit, filter, and
Directory steps stay coupled. `migrate` runs the auditable stages as one
resumable operation; it doesn't replace staged artifacts or journals.

## CLI reference

The entry point is:

```bash
python3 imapsync_bulk_migrator.py --help
```

### Modes

| Mode        | What it does                                                                                | Config   |
| ----------- | ------------------------------------------------------------------------------------------- | -------- |
| `preflight` | Checks connectivity, folders, capabilities, and capacity; builds plans when routing is on.  | Provider |
| `test`      | Checks that every account can log in.                                                       | Both     |
| `export`    | Downloads mail into the staging directory, then audits it.                                  | Both     |
| `audit`     | Re-checks an existing export.                                                               | Both     |
| `import`    | Uploads staged mail into the target.                                                        | Both     |
| `validate`  | Checks the target against the staged mail.                                                  | Both     |
| `migrate`   | Runs the provider stages as one resumable operation.                                        | Provider |

### Default config files

| Mode                      | Default `--config`        |
| ------------------------- | ------------------------- |
| `preflight`, `migrate`    | `migration.config.json`   |
| `export`, `test`, `audit` | `export.pass.config.json` |
| `import`, `validate`      | `import.pass.config.json` |

To use a provider config with `export`, `test`, `audit`, `import`, or
`validate`, pass `--config` explicitly.

### Flags

| Flag                      | Default                                  | Notes                                                                                                        |
| ------------------------- | ---------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `--mode`                  | required                                 | One of the modes above.                                                                                      |
| `--config`                | depends on mode                          | See [default config files](#default-config-files).                                                          |
| `--output-dir`            | `./exported`                             | Staging directory written by `preflight`, `export`, and `migrate`.                                           |
| `--input-dir`             | `./exported`                             | Staging directory read by `audit`, `import`, and `validate`.                                                 |
| `--max-workers`           | 4 or the CPU count, whichever is higher  | Accounts processed in parallel. Must be at least 1.                                                          |
| `--ignore-errors`         | off                                      | Continue with other accounts after an error.                                                                 |
| `--log-dir`               | `./logs`                                 | Where the log file is written.                                                                               |
| `--min-free-gb`           | `1.0`                                    | Stop early if free disk space is lower.                                                                      |
| `--imap-timeout`          | `60`                                     | Default IMAP socket timeout, in seconds.                                                                     |
| `--no-audit-after-export` | off                                      | Skip the automatic audit after `export`. Not valid with `migrate`, which can't skip its audit.               |
| `--audit-offline`         | off                                      | Audit without contacting the IMAP server; local checks only.                                                 |
| `--no-connectivity-test`  | off                                      | Skip connectivity tests. Rejected with `test`, `preflight`, and `migrate`, where connectivity and preflight checks are a required part of the mode. |
| `--dry-run`               | off                                      | `preflight` and `migrate` only. See [dry runs](#migrate-dry-runs-and-reports).                               |
| `--report-file`           | `migration-report.json` in the staging directory | `preflight` and `migrate` only. See [report location](#report-location).                             |
| `--resync-missing`        | off                                      | Deprecated. Validation reports missing messages without appending them again.                                |

Panel flags are listed under [DirectAdmin and cPanel](#directadmin-and-cpanel).

### Output and logs

- The CLI writes its log to standard error, and also to a mode-`0600` file
  under `--log-dir`.
- Standard output normally stays clean. That includes routed `preflight` and
  `migrate`: they write the full structured report to its private file and log
  only a short status and the artifact paths to standard error.
- Each structured workflow issue and report-write diagnostic is logged on its
  own, one issue at a time.
- Diagnostics redact Authorization and Bearer credentials, passwords, secrets,
  API keys, and token names including `oauth_token`, `authorization_token`,
  and `api_token`. Redaction is case-insensitive and covers both plain and
  URL-encoded forms.

### Exit codes

| Code  | Meaning                                                                                 | What to do                                                                                                                                                 |
| ----: | --------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `0`   | The requested stage completed successfully.                                             | Continue to the next migration stage.                                                                                                                      |
| `1`   | An unexpected fatal error occurred.                                                     | Inspect the log and traceback, correct the underlying problem, then rerun the same stage.                                                                  |
| `2`   | The CLI arguments, config, a dependency, a path, or local setup is invalid.             | Correct the named input or prerequisite, then retry.                                                                                                       |
| `3`   | Connectivity or control-panel setup failed, or panel `--ignore-errors` skipped accounts. | Read the per-account log first. With `--ignore-errors`, successful accounts may already be provisioned or imported; fix only the failed accounts and rerun safely. |
| `4`   | Preflight, the staged audit, an integrity gate, or validation found issues.             | Stop the migration and resolve every reported issue.                                                                                                       |
| `130` | The process received a stop signal.                                                     | Review the journals and log, then safely rerun the interrupted stage.                                                                                      |

### Stopping a run

Stopping is cooperative. After `SIGINT` (Ctrl-C) or `SIGTERM`:

- an API or IMAP request that's already in flight may finish;
- the workflow checks the stop flag at every stage and remote-mutation
  boundary, and starts no later work;
- the interrupted migration is never marked completed, and the CLI exits
  `130`.

A stop that arrives after the final report's commit check is too late to
interrupt the run: the committed success stands and the CLI returns `0` (see
[how the final report is committed](#how-the-final-report-is-committed)).

Inspect the failed report and the resumable journals before rerunning. If the
stop arrives after a Gmail label/filter or Workspace alias change, both the
returned and the saved report keep that operation's partial result: completed
creates, deletes, and reuses, unresolved entries, and the matching rerun
action. Writing that cancellation report is local work; it doesn't start a
fresh remote discovery pass after the stop.

## Provider mode

### Providers and transport

| `provider` | Host and port          | Auth methods                          |
| ---------- | ---------------------- | ------------------------------------- |
| `gmail`    | `imap.gmail.com:993`   | `xoauth2`, `app_password`             |
| `icloud`   | `imap.mail.me.com:993` | `app_password`                        |
| `imap`     | your server            | `password`, `app_password`, `xoauth2` |

- `host` is required for every provider. Gmail and iCloud must use exactly the
  host above, port 993, and implicit TLS (`"ssl": true`, `"starttls": false`),
  which are also the defaults.
- Known Gmail and iCloud IMAP hosts are rejected under `"provider": "imap"`,
  so their provider-specific safeguards can't be bypassed by accident.
- Generic IMAP endpoints must use encrypted transport: implicit TLS with
  `"ssl": true, "starttls": false` (the default), or STARTTLS with
  `"ssl": false, "starttls": true`. Configs that enable both, or neither, are
  rejected before authentication.
- Provider account prerequisites still apply to app passwords. Gmail app
  passwords require 2-Step Verification and may be unavailable for Workspace,
  security-key-only, or Advanced Protection accounts. Apple app-specific
  passwords require two-factor authentication on the Apple Account.

### Settings

| Setting                                           | Values                                  | Meaning                                                                                                                         |
| ------------------------------------------------- | --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `migration.target_mode`                           | `empty` (default) or `merge`            | `empty` requires the target to hold no mail that this migration's journals don't account for. `merge` allows existing mail.     |
| `migration.account_merge_mode`                    | `one_to_one` (default) or `many_to_one` | See [many-to-one merges](#many-to-one-merges).                                                                                  |
| `migration.folder_map`                            | object                                  | Maps a source mailbox name to a target mailbox name.                                                                            |
| `migration.routing`                               | object                                  | Strict, opt-in account/folder routing and Gmail filter declarations. Absent means the existing behavior. See [Gmail label routing](#gmail-label-routing). |
| `limits.throttle.max_bytes_per_second`            | integer, default `0` (no limit)         | Optional import/export throttling.                                                                                              |
| `limits.retry_max_attempts`                       | integer, at least 1, default `5`        | Bounded retry budget for provider operations and Gmail/Workspace API requests.                                                  |
| `target.available_bytes`                          | integer                                 | Optional. Preflight reports an issue if the estimated source size exceeds it. Without it, preflight skips this storage check with a warning. |
| `migration.label_policy`, `migration.validation`  | fixed                                   | Accept only `single_copy_preserve_metadata` and `manifest_exact`.                                                               |

The provider root, account, auth, migration, limits, and throttle objects have
closed schemas. Any unknown field is rejected with its full configuration path and
the list of allowed names. Misspellings such as `routng`, `target_mod`, or
`limts` are never silently ignored, so a typo can't switch off a safeguard or
fall back to a default.

### Credentials

Each `auth` block has a `method`, an optional `username`, and at most one
secret source:

| Field           | Holds                                                  | Valid with                 |
| --------------- | ------------------------------------------------------ | -------------------------- |
| `password`      | An inline password or token value.                     | any method                 |
| `password_file` | Path to a file containing a password or app password.  | `password`, `app_password` |
| `token_file`    | Path to a file containing an XOAUTH2 token.            | `xoauth2` only             |
| `env_var`       | Name of an environment variable holding the secret.    | any method                 |

- The effective auth for every account must have a secret. Endpoint-level auth
  (`source.auth`, `target.auth`) may leave the secret out when account-level
  auth (`accounts[].source_auth`, `accounts[].target_auth`) supplies it.
- In multi-account configs, per-account credentials are required by default.
  Endpoint-level secrets are rejected, so one login isn't accidentally reused
  for every account. If the endpoint sets a `username`, each per-account auth
  must set its own. The explicit exception is many-to-one target mode when all
  accounts share one target mailbox.
- For Gmail and iCloud, a configured username must match the account's
  address. iCloud defaults the username as described under [iCloud](#icloud).
- Relative file paths are resolved from the config file's directory. A secret
  file holds only the secret; trailing newlines are ignored.

See [Secret hygiene](#secret-hygiene) for how to store these.

### Running the stages

For provider configs without Workspace alias automation, the individual-stage
sequence is:

```bash
python3 imapsync_bulk_migrator.py --mode preflight --config migration.config.json --output-dir ./exported
python3 imapsync_bulk_migrator.py --mode export --config migration.config.json --output-dir ./exported
python3 imapsync_bulk_migrator.py --mode import --config migration.config.json --input-dir ./exported
python3 imapsync_bulk_migrator.py --mode validate --config migration.config.json --input-dir ./exported
```

That's the shortest safe sequence, because export audits automatically. Run
`--mode audit` to re-check an existing staged export, or after an export that
deliberately used `--no-audit-after-export`.

- Use one staging directory throughout. `preflight` and `export` get it through
  `--output-dir`; `audit`, `import`, and `validate` get the same directory
  through `--input-dir`. That's where the reviewed plans and the resumable
  account artifacts are bound together.
- Standalone `export` never creates or reconciles Gmail labels or filters.
- Standalone `import` takes a fresh Gmail snapshot, reconciles all requested
  labels and future-delivery filters, and verifies the complete Gmail
  configuration before it starts the provider import. A Gmail conflict or
  verification failure therefore leaves the staged provider import untouched.
- When `target.workspace_aliases.enabled` is `true`, use `migrate` for the
  whole mutating and validation lifecycle. Standalone provider `export`,
  `import`, and `validate` exit with code `2`, because they can't safely
  provide the audited filter-before-alias ordering and the final Directory
  ownership check.

### migrate, dry runs, and reports

The equivalent orchestration command is:

```bash
python3 imapsync_bulk_migrator.py --mode migrate --config migration.config.json --output-dir ./exported
```

- `migrate --dry-run` runs only discovery, planning, local plan persistence,
  and report generation.
- Routed `preflight` always runs that same mutation-free planning workflow.
  Adding `--dry-run` to `preflight` is accepted but changes nothing.
- A routing-disabled `preflight` is normally a concise check. Passing
  `--report-file PATH` explicitly switches it to the same read-only reporting
  workflow and guarantees that `PATH` is written. No routing, Gmail, or
  Workspace alias plan is claimed or created.
- Dry-run actions name only the report and plan artifacts that the selected
  configuration actually emits.

#### Report location

`--report-file PATH` replaces the default `<staging directory>/migration-report.json`.
`PATH`:

- must be inside the staging directory;
- must not overlap a saved plan, a configured or discovered account directory,
  a message or metadata subtree, a manifest, a validation report, an import
  journal, or any location inside the reserved `.import-locks/` namespace;
- can't be a symlinked path, a hard-linked or non-regular file, or an
  unrelated existing file. A valid report from a previous run may be reused
  only when it records this exact staging directory and report path.

Saved report bindings use normalized absolute paths, so an equivalent rerun
stays valid after you change the working directory. Relative paths given on
the command line still resolve from the current directory, so spell out the
staging-directory prefix:

```bash
python3 imapsync_bulk_migrator.py --mode migrate --config migration.config.json --output-dir ./exported --report-file ./exported/reports/migration.json
```

## Gmail

Gmail migrations need extra proof, because labels and virtual mailbox views
can make a naive IMAP count misleading.

### Gmail visibility check

A Gmail **source** can only be exported when it has:

- the `X-GM-EXT-1` capability;
- a selectable All Mail view advertised with the `\All` special-use attribute;
- a full-visibility attestation.

A Gmail **target** needs the same extension and All Mail checks for import and
validation, plus its own attestation.

The attestation is your statement that IMAP shows the whole mailbox, which the
tool can't check itself: without it, a Gmail IMAP scan can be internally
consistent but still incomplete. Before setting it, verify Workspace
`gmail.imap_admin` access, or Gmail IMAP settings with no folder-size limit and
the required labels visible in IMAP. For a target, confirm it isn't hiding
messages from IMAP.

| Gmail is the | One account                             | Several accounts                                                                                                                                         |
| ------------ | --------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| source       | `source.gmail_full_visibility_verified` | `accounts[].gmail_full_visibility_verified` on each account                                                                                               |
| target       | `target.gmail_full_visibility_verified` | `accounts[].target_gmail_full_visibility_verified` on each account, unless the config is an explicit many-to-one merge into one shared Gmail target with `target.gmail_full_visibility_verified` set |

Without the attestation, preflight reports an issue. For a Gmail source,
export refuses to run; for a Gmail target, audit and validation fail and
import refuses to run.

### Labels and addresses

- Gmail target imports restore non-system labels with `+X-GM-LABELS`.
  `Starred` and `Important` are handled as Gmail system labels rather than
  normal custom labels.
- For personal Gmail addresses, dotted `gmail.com` variants and the matching
  `googlemail.com` address are treated as the same mailbox for config
  validation, target grouping, endpoint binding, and journal binding. In
  many-to-one configs, spell the target address the same way everywhere to
  keep operator output easy to read.

### Google Workspace

- Password-only third-party IMAP, POP, and SMTP access isn't a production
  assumption for Workspace accounts. Use OAuth/XOAUTH2 where Google permits
  IMAP access.
- For Workspace Gmail targets, Google directs migrations to its supported
  Workspace migration options instead of IMAP upload. Treat this tool's Gmail
  target path as an operator-managed IMAP copy route, not Google's recommended
  migration path, and use it only after explicitly accepting that.

## iCloud

- iCloud uses app-specific passwords, which require Apple Account two-factor
  authentication before they can be generated.
- When no username is configured, the tool uses the local part of the
  account's iCloud address (the part before `@`). If that fails in your
  environment, configure the exact username Apple requires for the mailbox.
- iCloud doesn't expose Gmail-style cross-label identity. Physical copies in
  different folders are kept as separate messages.
- The iCloud `VIP` view is skipped as a known search view.

## Generic IMAP, Roundcube, DirectAdmin, and cPanel mail

Provider `imap` is the right mode for mailboxes normally reached through
Roundcube, DirectAdmin webmail, cPanel webmail, or another hosted webmail UI.
Use the underlying IMAP server and the mailbox's own credentials.

- Generic IMAP scans every selectable mailbox.
- Special-use attributes such as `\All` and `\Flagged` are advisory; they
  don't prove a mailbox is purely virtual. Those views are scanned after the
  ordinary mailboxes. Byte-identical occurrences with compatible delivery
  metadata are folded into messages already exported, and unmatched
  occurrences are kept as separate messages.
- In `folder_map` and in review output, use non-INBOX mailbox names with the
  exact spelling and case that IMAP `LIST` returns. Only `INBOX` is
  case-insensitive, per the IMAP standard.
- During empty-target resume checks, generic target `\All` and `\Flagged`
  views are allowed only for messages already matched by committed journal
  rows, or by recoverable pending rows from the same migration. Unmatched
  messages still fail the empty-target gate.
- A pending row isn't production proof by itself. Import must resolve it to
  committed, and validation must pass, before decommissioning.

## Many-to-one merges

To import several source mailboxes into one target mailbox, set
`migration.account_merge_mode` to `many_to_one` and point those accounts at
the same `target_email` and the same effective target login:

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

### How merges run

- A merge group is keyed by the effective target IMAP login and endpoint.
  Imports into one group run one source at a time, even when `--max-workers`
  is higher than one. Different groups are independent and run concurrently,
  up to `--max-workers`.
- Each distinct target login keeps its own empty-target gate, while journals
  stay per account and bound to their target. In `target_mode=empty`, target
  content that no journal accounts for still fails the gate: the destination
  may contain only messages already accounted for by journals from the same
  merge group.
- Before any source starts ordinary work, the importer holds the target lock
  and resolves recoverable pending `APPEND` rows from every source journal in
  the group.
- One physical target message can be reused for byte-identical content from
  different sources, but only when the delivery metadata is compatible. Within
  one source, repeated copies keep their multiplicity and can't all consume the
  same physical occurrence.
- Validation groups physical identity by target mailbox (or by Gmail's
  cross-label physical message) and checks the aggregate max-per-source
  capacity: the expected number of matching occurrences is the greatest
  multiplicity any one source requires, not a blind sum of reusable
  cross-source copies. Missing or extra matching occurrences fail validation.

### Mixing merged and one-to-one accounts

Hybrid configs are allowed: one target group can merge `a`, `b`, and `c` into
`a`, while `d` and `e` stay one-to-one in the same provider config. In that
shape, put target credentials on every account, so the singleton targets
can't reuse the merge target's login by accident.

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

Here `a`, `b`, and `c` import into the target login `a@example.com`, while `d`
and `e` stay one-to-one.

### Gmail merge internals

The exact guarantees for Gmail targets. You don't need these to run a merge.

- Duplicate allocation is proven before any target change. The allocator
  reduces compatible destinations to the finite Draft, Sent, Spam, Trash, and
  neutral families, keeps fixed journaled Gmail message IDs, and performs a
  deterministic one-to-one matching for every source. Custom-label spelling is
  kept in the resulting label union but doesn't create redundant allocator
  states.
- Cancellation is checked throughout this proof. A deterministic
  resource-bound failure is reported as an indeterminate allocation proof, not
  as an incompatible-destination result.
- Gmail physical IDs from IMAP, journals, and recovery baselines count as
  canonical only when they are positive unsigned 64-bit decimal ASCII strings:
  no zero, sign, whitespace, leading zero, Unicode digit, integer coercion, or
  value above `18446744073709551615`.
- Immediately before a Gmail `APPEND`, the pending journal durably records the
  set of byte/date-compatible Gmail physical IDs already present.
  Confirmation then requires a one-to-one post-APPEND ID that's absent from
  that baseline. This is also the recovery proof after an interruption,
  including the case of an Important/Starred message temporarily anchored in
  All Mail before a later source moves the exact allocated physical message to
  Spam or Trash.
- Multiple pending rows are proved as one matching batch, so nested baselines
  can disambiguate each other. A non-empty but non-unique post-APPEND
  allocation fails closed and is never retried as another append. Legacy
  pending rows without this baseline also fail closed when a temporary All
  Mail anchor can't be distinguished safely.
- This global proof, the committed evidence, the capacity check, and the
  empty-target check are all read-only and run before missing-ID repair. If
  any current or peer Gmail journal also has an incomplete crash tail, every
  byte is kept until those live gates pass. Only then is the tail removed, and
  every stage reloaded and revalidated before recovery writes.

## Gmail label routing

Routing (`migration.routing`) sends one or more source mailboxes into one
target and decides where each source folder lands: a Gmail label, a Gmail
system location, or, for non-Gmail targets, a mailbox. It can also declare
Gmail filters for future mail.

### Turning routing on

- Routing is opt-in and disabled when `migration.routing` is absent. If the
  block is present, it must include `"enabled": true`; a disabled block may
  contain only `"enabled": false`. Existing `folder_map`, one-to-one, and
  many-to-one configs keep their historical behavior until you deliberately
  enable routing.
- Routing currently requires every configured account to share one target
  mailbox. With more than one account, use
  `"account_merge_mode": "many_to_one"`, the same `target_email`, and the same
  effective target IMAP login for those accounts.
- For a Gmail target, that intentional merge group may share endpoint-level
  target credentials. Each source account still needs its own effective
  source credentials.
- Preflight must resolve every discovered source folder before any target
  change is allowed. Unresolved folders deliberately stop the run.

### Where rules and defaults go

`migration.routing.accounts` is keyed by a configured source address. Unknown
accounts are rejected, and matching uses the provider's address
normalization. Each account object accepts:

- `default_label`: route every otherwise-unassigned folder to one Gmail user
  label. INBOX and all other folders use the same label.
- `default_namespace`: route INBOX to the namespace root and other folders to
  nested labels. For example, `Alias` maps INBOX to `Alias`, Sent to
  `Alias/Sent`, and `Projects.2025` with source delimiter `.` to
  `Alias/Projects/2025`.
- `rules`: account-specific exact-folder or role rules.

An account may omit both defaults, but then every discovered folder needs a
matching rule, or the plan is ambiguous. Defaults create `custom_label`
destinations, so they're Gmail-only.

`migration.routing.global_rules` holds reusable rules for all accounts; it's
the normal place for a shared Junk rule. `migration.routing.filters` declares
future-delivery Gmail filters and doesn't affect historical messages (see
[Filters](#filters)).

### Rules

Each rule has one `match` member, either an exact folder or a role:

```json
[
  {"match": {"folder": "Projects.2025"}, "destinations": [{"type": "custom_label", "name": "Alias/Projects/2025"}]},
  {"match": {"role": "junk"}, "destinations": [{"type": "custom_label", "name": "Imported/Junk"}]}
]
```

The role names are `inbox`, `sent`, `drafts`, `trash`, `archive`, and `junk`.
SPECIAL-USE attributes take priority over name-based detection. When no
applicable attribute is present, names such as `Sent Items`, `All Mail`,
`Spam`, `INBOX.Spam`, and `Junk E-mail` are recognized using the discovered
hierarchy delimiter. A folder advertising conflicting roles is ambiguous
unless an exact-folder rule resolves it.

### Destinations

Each item in `destinations` is typed:

| `type`         | Target                 | Rules                                                                                                                                                                             |
| -------------- | ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `custom_label` | Gmail user label       | May be new or an exact existing name; one rule may list several labels. Messages also appear in All Mail, and get Inbox only if the same route includes the `gmail_system` destination `inbox`. |
| `gmail_system` | Gmail system location  | Use the canonical names `inbox`, `sent`, `drafts`, `all`, `starred`, `important`, `spam`, or `trash`. System labels are reused, never created.                                   |
| `mailbox`      | Non-Gmail IMAP mailbox | Non-Gmail rules must select exactly one mailbox, and can't configure Gmail filters or defaults.                                                                                   |

- An override normally suppresses the account default. Add
  `"include_default": true` to keep the default destination as well.
- To leave a folder out, set `"exclude": true` and omit `destinations`.
  Exclusions can't include the default.
- Several rules may intentionally name the same destination. The plan records
  every contributor and treats that as a shared merge, not a collision.
  Accidental case-only, type, hierarchy, missing-system, and
  duplicate-inventory conflicts still stop the workflow before any target
  write.

### Spam and Trash

A `custom_label` named `Imported/Junk` is an ordinary user label. Messages
routed there are also visible in All Mail, and don't receive Inbox unless the
same resolved route explicitly includes the `gmail_system` destination
`inbox`.

Don't confuse that with Gmail's system `spam` or `trash`: historical mail in
those locations may be subject to provider retention or deletion. The parser
rejects either destination unless the acknowledgement is on that exact
destination:

```json
{
  "match": {"role": "junk"},
  "destinations": [
    {"type": "gmail_system", "name": "spam", "allow_unsafe": true}
  ]
}
```

`allow_unsafe` is invalid on `custom_label` and `mailbox` destinations. Even
when acknowledged, the plan shows a warning for every source folder routed to
system Spam or Trash.

### Precedence

For each discovered source folder, the first matching level wins:

1. account exact-folder rule
2. account role rule
3. global exact-folder rule
4. global role rule
5. account `default_label` or `default_namespace`

- Exact matching of `INBOX` is case-insensitive, as IMAP requires. Every
  other exact folder match keeps the source spelling and case.
- Duplicate identical rules at one level are harmless. Different matching
  rules at the same level are reported as ambiguous, instead of being ordered
  implicitly.

### The routing plan

Each resolved entry in the plan shows:

- the source account, exact source folder, delimiter, attributes, and
  detected role;
- the target destinations and their create/reuse state;
- contributors to shared destinations, and whether Inbox is present;
- the exclusion state, the assignment source, ambiguities, and warnings.

The private `routing-plan.json` stores the complete target inventory, planned
filters, label create/reuse lists, conflicts, warnings, and the mapping
SHA-256.

- The mapping digest covers the route and filter decisions. Export binds its
  state to that digest, and import and validation reload and replay the plan
  against the config.
- If the config or the discovered source-folder set changes, the tool requires
  a new preflight and review, rather than silently rerouting staged mail.
- Use a new staging directory when the target, the mapping, the required label
  set, or the filter specifications intentionally change. An existing
  reviewed plan is never overwritten with a different identity.

Preflight also writes the private `gmail-configuration-plan.json`. Its
immutable identity binds the target, the routing mapping digest, the required
user-label names, and the requested filter specifications. Live Gmail
label/filter IDs, and whether each item will be created or reused, are
discovery outcomes, so they stay dynamic report data instead of weakening that
identity.

### Folder memberships and virtual views

All selectable folders that the provider scan considers must resolve.

- Routing-plan version 2 applies every recorded selectable folder membership
  to the message. A message recorded in both `INBOX` and `[Gmail]/All Mail`,
  for example, receives the reviewed destinations from both entries.
- Virtual All Mail, Starred, Important, and Flagged views are not silently
  suppressed. Add an explicit exclusion rule for each such view whose
  membership shouldn't contribute.
- Discovery and export still de-duplicate the physical message payload; the
  saved memberships are unioned when that payload is routed.

For a routed generic-IMAP export:

- Each `\All` view is matched one-to-one by exact content, delivery flags,
  normalized `INTERNALDATE`, and occurrence multiplicity.
- Unmatched occurrences become physical anchors only after that entire
  selectable `\All` mailbox has been processed. Occurrences in one view can't
  collapse into each other, while a later, distinct `\All` view may add
  membership to those anchors.
- Routed Starred and Important views fold only when content and date identify
  exactly one unused anchor for that view. Ambiguous, unmatched, or
  missing-date occurrences remain separate payloads.
- Flagged keeps its established folding behavior, and routing-disabled exports
  keep the legacy behavior.
- The preflight storage estimate applies the same rules, so
  `target.available_bytes` is checked against the same physical-payload count
  that export will produce.

Other plan rules:

- Version 1 routing plans used the former virtual-view behavior and aren't
  safe to reinterpret. A staging directory containing a version 1
  `routing-plan.json` fails closed, with instructions to run a fresh routing
  preflight and re-export before import.
- IMAP treats `INBOX` case-insensitively. Discovery that returns more than one
  case variant, such as `INBOX` and `inbox`, for the same source account is
  rejected as ambiguous during preflight, before an unexecutable reviewed plan
  can be saved. Other source folder names keep their exact case and are
  ordered by the deterministic `(casefold, original)` key in staged routing
  metadata.

### Mutation-free preflight

Routing preflight reads:

- every configured source's retained selectable folders, delimiter, and
  SPECIAL-USE attributes;
- the target IMAP inventory, combined for Gmail with the API label inventory,
  so user/system types and internal IDs are known without asking you to copy
  IDs into the config;
- existing filters, to classify the requested filters;
- with Workspace aliases enabled: the target user, its aliases, possible
  user/group collisions, and domain verification state.

It performs no remote `CREATE`, `APPEND`, `STORE`, label POST, filter
POST/DELETE, or Directory alias POST. It reports:

- all discovered source folders and target labels;
- automatic defaults and explicit assignments;
- shared contributors and exclusions;
- labels that would be created or exactly reused;
- filters that would be created or reused;
- Workspace aliases that would be created or reused, and every ownership,
  group, user, domain, or limit conflict;
- incompatible same-condition filters;
- ambiguous folders and target hierarchy/name conflicts;
- explicit unsafe-system warnings.

The local `routing-plan.json`, `gmail-configuration-plan.json`, and
conditional `workspace-alias-plan.json` files are review evidence, not remote
changes. A plan with conflicts or ambiguities isn't executable.

These two planning commands are equivalent:

```bash
python3 imapsync_bulk_migrator.py --mode preflight --config migration.config.json --output-dir ./exported
python3 imapsync_bulk_migrator.py --mode migrate --dry-run --config migration.config.json --output-dir ./exported
```

Both write the applicable private plans and a planned `migration-report.json`
under `--output-dir`, log the status and artifact paths to standard error,
leave standard output clean, and stop before export, Gmail or Directory
writes, or import.

### Labels

- Required user labels are reconciled before filters.
- Exact-name user labels are reused, so an existing `MailB` isn't duplicated.
- Case-only matches, duplicate resources, system-name conflicts, and
  inconsistent hierarchy casing fail before the first Gmail write.
- Created labels are re-listed and verified.

### Filters

Each configured filter uses the generated query
`deliveredto:<configured-address>`, not just the visible `To` header.

| Field             | Meaning                                                                                                                                               |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `delivered_to`    | The address to match.                                                                                                                                 |
| `label`           | Required user label to apply.                                                                                                                         |
| `inbox`           | `"keep"` (default) applies the label without removing Inbox. `"archive"` applies the label and removes `INBOX`.                                       |
| `mark_read`       | `true` additionally removes `UNREAD`. Default `false`.                                                                                                |
| `conflict_policy` | `"error"` (default) reuses one equivalent filter, but reports duplicate or incompatible same-condition filters without changing them. `"replace"` explicitly deletes incompatible same-condition filters and creates or keeps exactly one equivalent result. |

- A same-condition filter with incompatible actions is a conflict under
  `"error"`. Set `"replace"` only after reviewing the plan.
- Replacement is the only filter path that deletes anything, and it affects
  only filters with the same canonical condition. This filter policy doesn't
  apply to Workspace aliases, whose only policy is the non-destructive
  `create_only`.
- Unrelated target messages, labels, filters, aliases, and mailbox settings
  are never changed.
- Labels and filters are re-listed after reconciliation and must verify
  exactly. Gmail's filter-count limit is checked before any change.

### When Gmail is changed

| Command                            | Gmail labels and filters                                                     |
| ---------------------------------- | ---------------------------------------------------------------------------- |
| `preflight` or `migrate --dry-run` | Never changed. Both stop after read-only discovery and private plan/report persistence. |
| `migrate`, filters configured      | Reconciled and verified before export.                                       |
| `migrate`, no filters              | Required custom labels reconciled after the audit, before import.            |
| `export`                           | Never changed; export only uses the frozen plans.                            |
| `import`                           | The complete requested configuration is reconciled and verified immediately before historical mail is imported. |

Gmail filters don't apply retroactively to mail delivered during the
migration window, so a `migrate` run that requests filters reconciles them
before export. Early filter verification governs only later delivery; it
doesn't claim that Gmail labeled mail received before verification.
Historical messages get their resolved labels directly during import.

### Imported messages in a Gmail target

- When strong content identity finds a message already present in the merge
  target, import reuses that Gmail message and applies every missing routed
  label with additive label operations. Existing unrelated labels stay
  attached.
- A committed journal entry isn't route-complete until its plan digest and
  required custom/system memberships match.
- Content-first reuse keeps the existing target message's `INTERNALDATE`; it
  can't retroactively replace it with the staged source date. When the dates
  differ, validation still succeeds but emits an
  `existing-target-internaldate-differs` warning containing the canonical
  identity, the mailbox, both dates, and `existing-content-reuse` provenance.
  The journal records `source_internaldate`, `target_internaldate`,
  `internaldate_provenance: "existing-content-reuse"`, and
  `internaldate_origin_action: "existing"`.
- Treat that warning as an explicit record that the source date metadata
  wasn't preserved and no duplicate was appended.

### Gmail API authorization

IMAP migration and Gmail REST provisioning are separate authorizations:

- `target.auth` or `accounts[].target_auth` authorizes Gmail IMAP. It may be
  XOAUTH2 or, where Google still permits it, an app password.
- `target.gmail_api_auth` or `accounts[].target_gmail_api_auth` supplies an
  OAuth bearer token for REST label and filter operations. Its method must be
  `xoauth2`, its username (when set) must match the target mailbox, and it must
  provide exactly one of `password`, `token_file`, or `env_var` as the token
  source.

A dedicated `target.gmail_api_auth` token is clearest, and takes precedence.
If you omit it, the effective target
XOAUTH2 token is reused, which only works when that token was minted with the
extra API scopes. App passwords never authorize the Gmail REST API. Every
routing config that uses `custom_label`, `default_label`, or
`default_namespace` therefore needs label-management API authorization, even
when it declares no filters. A route containing only `gmail_system`
destinations and exclusions can stay IMAP-only.

| Capability                | Minimum scope                                                                                                                  |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| Label creation            | `https://www.googleapis.com/auth/gmail.labels`, or a compatible `https://www.googleapis.com/auth/gmail.modify` or `https://mail.google.com/` |
| Filter creation/deletion  | Additionally `https://www.googleapis.com/auth/gmail.settings.basic`                                                            |

- A `401` is reported as an invalid or expired access token. A `403` reports
  a hint naming the precise required scope.
- Authorization headers, tokens, API response bodies, message contents, and
  user IDs embedded in transport exceptions aren't copied into errors or logs.
- The tool doesn't run an interactive OAuth flow, and doesn't acquire or
  refresh the preissued Gmail IMAP/API bearer tokens supplied through the
  config.

### Generic routing example

This config sends two independent mailboxes on one old IMAP endpoint into one
non-empty Gmail target:

- The primary account uses the normal Gmail locations.
- The secondary mailbox gets an `Alias` namespace, except that all Junk goes
  only to `Imported/Junk`.
- The exact `VIP` override shows several labels plus an explicit Inbox, and
  keeps the namespaced default with `include_default`.
- The filter archives future mail delivered to the separately provisioned
  `alias@example.com` Workspace alias, and marks it read.

This base migration owns routing, Gmail labels, and Gmail filters. It doesn't
need Directory API access and doesn't administer the alias.

```json
{
  "source": {
    "provider": "imap",
    "host": "imap.old.example.com",
    "port": 993,
    "ssl": true,
    "starttls": false,
    "auth": {"method": "password"}
  },
  "target": {
    "provider": "gmail",
    "host": "imap.gmail.com",
    "gmail_full_visibility_verified": true,
    "auth": {
      "method": "xoauth2",
      "username": "primary@example.com",
      "token_file": "secrets/primary.imap.token"
    },
    "gmail_api_auth": {
      "method": "xoauth2",
      "username": "primary@example.com",
      "token_file": "secrets/primary.gmail-api.token"
    }
  },
  "migration": {
    "target_mode": "merge",
    "account_merge_mode": "many_to_one",
    "routing": {
      "enabled": true,
      "accounts": {
        "primary@example.com": {
          "rules": [
            {"match": {"role": "inbox"}, "destinations": [{"type": "gmail_system", "name": "inbox"}]},
            {"match": {"role": "sent"}, "destinations": [{"type": "gmail_system", "name": "sent"}]},
            {"match": {"role": "drafts"}, "destinations": [{"type": "gmail_system", "name": "drafts"}]},
            {"match": {"role": "archive"}, "destinations": [{"type": "gmail_system", "name": "all"}]},
            {"match": {"role": "trash"}, "exclude": true}
          ]
        },
        "alias@example.com": {
          "default_namespace": "Alias",
          "rules": [
            {
              "match": {"folder": "VIP"},
              "destinations": [
                {"type": "custom_label", "name": "Shared/VIP"},
                {"type": "gmail_system", "name": "inbox"}
              ],
              "include_default": true
            },
            {"match": {"folder": "Do not migrate"}, "exclude": true}
          ]
        }
      },
      "global_rules": [
        {
          "match": {"role": "junk"},
          "destinations": [{"type": "custom_label", "name": "Imported/Junk"}]
        }
      ],
      "filters": [
        {
          "delivered_to": "alias@example.com",
          "label": "Alias",
          "inbox": "archive",
          "mark_read": true,
          "conflict_policy": "error"
        }
      ]
    }
  },
  "limits": {
    "throttle": {"max_bytes_per_second": 0},
    "retry_max_attempts": 5
  },
  "accounts": [
    {
      "source_email": "primary@example.com",
      "target_email": "primary@example.com",
      "source_auth": {
        "method": "password",
        "username": "primary@example.com",
        "password_file": "secrets/primary.source.password"
      }
    },
    {
      "source_email": "alias@example.com",
      "target_email": "primary@example.com",
      "source_auth": {
        "method": "password",
        "username": "alias@example.com",
        "password_file": "secrets/alias.source.password"
      }
    }
  ]
}
```

Because `target.workspace_aliases` is absent, this config never constructs a
Directory client. Provision `alias@example.com` separately, then test external
delivery before retiring the old mailbox. The Gmail label and filter remain
part of this migration: top-level `migrate` reconciles them before export,
while in the individual-stage workflow `export` leaves Gmail unchanged and
`import` reconciles them before importing.

### MailA through MailE example

This complete config routes five old IMAP accounts into the existing Google
Workspace Gmail mailbox `mailA@example.com`. It assumes that:

- the Workspace aliases `mailB@example.com` through `mailE@example.com` are
  provisioned separately; this base run owns only historical-mail routing,
  Gmail labels, and Gmail filters (or see the
  [optional alias add-on](#alias-add-on-for-the-maila-example));
- the `MailB` Gmail label already exists, so discovery reports `MailB` as
  reused, and `MailC`, `MailD`, `MailE`, and `Imported/Junk` as labels to
  create;
- `mailA` has only the folders its rules cover. Adjust its rules if preflight
  discovers more folders; unresolved folders deliberately stop the run.

```json
{
  "source": {
    "provider": "imap",
    "host": "imap.old.example.com",
    "auth": {"method": "password"}
  },
  "target": {
    "provider": "gmail",
    "host": "imap.gmail.com",
    "gmail_full_visibility_verified": true,
    "auth": {
      "method": "xoauth2",
      "username": "mailA@example.com",
      "token_file": "secrets/mailA.imap.token"
    },
    "gmail_api_auth": {
      "method": "xoauth2",
      "username": "mailA@example.com",
      "token_file": "secrets/mailA.gmail-api.token"
    }
  },
  "migration": {
    "target_mode": "merge",
    "account_merge_mode": "many_to_one",
    "routing": {
      "enabled": true,
      "accounts": {
        "mailA@example.com": {
          "rules": [
            {
              "match": {"role": "inbox"},
              "destinations": [{"type": "gmail_system", "name": "inbox"}]
            },
            {
              "match": {"role": "sent"},
              "destinations": [{"type": "gmail_system", "name": "sent"}]
            },
            {
              "match": {"role": "drafts"},
              "destinations": [{"type": "gmail_system", "name": "drafts"}]
            },
            {
              "match": {"role": "archive"},
              "destinations": [{"type": "gmail_system", "name": "all"}]
            },
            {"match": {"role": "trash"}, "exclude": true}
          ]
        },
        "mailB@example.com": {"default_namespace": "MailB"},
        "mailC@example.com": {"default_namespace": "MailC"},
        "mailD@example.com": {"default_namespace": "MailD"},
        "mailE@example.com": {"default_namespace": "MailE"}
      },
      "global_rules": [
        {
          "match": {"role": "junk"},
          "destinations": [
            {"type": "custom_label", "name": "Imported/Junk"}
          ]
        }
      ],
      "filters": [
        {
          "delivered_to": "mailB@example.com",
          "label": "MailB",
          "inbox": "keep",
          "mark_read": false,
          "conflict_policy": "error"
        },
        {
          "delivered_to": "mailC@example.com",
          "label": "MailC",
          "inbox": "keep",
          "mark_read": false,
          "conflict_policy": "error"
        },
        {
          "delivered_to": "mailD@example.com",
          "label": "MailD",
          "inbox": "keep",
          "mark_read": false,
          "conflict_policy": "error"
        },
        {
          "delivered_to": "mailE@example.com",
          "label": "MailE",
          "inbox": "keep",
          "mark_read": false,
          "conflict_policy": "error"
        }
      ]
    }
  },
  "accounts": [
    {
      "source_email": "mailA@example.com",
      "target_email": "mailA@example.com",
      "source_auth": {"method": "password", "username": "mailA@example.com", "password_file": "secrets/mailA.source.password"}
    },
    {
      "source_email": "mailB@example.com",
      "target_email": "mailA@example.com",
      "source_auth": {"method": "password", "username": "mailB@example.com", "password_file": "secrets/mailB.source.password"}
    },
    {
      "source_email": "mailC@example.com",
      "target_email": "mailA@example.com",
      "source_auth": {"method": "password", "username": "mailC@example.com", "password_file": "secrets/mailC.source.password"}
    },
    {
      "source_email": "mailD@example.com",
      "target_email": "mailA@example.com",
      "source_auth": {"method": "password", "username": "mailD@example.com", "password_file": "secrets/mailD.source.password"}
    },
    {
      "source_email": "mailE@example.com",
      "target_email": "mailA@example.com",
      "source_auth": {"method": "password", "username": "mailE@example.com", "password_file": "secrets/mailE.source.password"}
    }
  ]
}
```

With a non-empty target that already has `MailB`, the reviewed plan shows:

| Source                                         | Historical destination                    |
| ---------------------------------------------- | ----------------------------------------- |
| `mailA@example.com` Inbox/Sent/Drafts/Archive  | The configured Gmail system locations     |
| `mailB@example.com` INBOX                      | The existing `MailB` label                |
| `mailC@example.com` INBOX                      | New `MailC` label                         |
| `mailD@example.com` INBOX                      | New `MailD` label                         |
| `mailE@example.com` INBOX                      | New `MailE` label                         |
| Any detected or configured Junk or Spam folder | Only the one new shared `Imported/Junk` label |

- The global `junk` role rule outranks each non-primary account's default and
  doesn't set `include_default`. So `Junk`, `Spam`, `INBOX.Spam`, and
  `Junk E-mail` all contribute only to the shared `Imported/Junk` label, and
  no account-specific junk labels such as `MailB/Junk`, `MailC/Spam`,
  `MailD/Junk`, or `MailE/Junk` are requested.
- The four filters become Gmail queries `deliveredto:mailB@example.com`
  through `deliveredto:mailE@example.com`, each applying the matching root
  label. `inbox: "keep"` applies the label without archiving future mail; use
  `"archive"` to remove Inbox, and set `mark_read: true` when that behavior is
  wanted.
- An identical historical message found in two sources may remain one Gmail
  message, but it receives both required source labels.

The base config deliberately omits `target.workspace_aliases`, so no Admin SDK
client is constructed, and no Workspace user or alias state is inspected or
changed. Provision `mailB@example.com` through `mailE@example.com` separately
in Google Workspace, and test representative external delivery before retiring
the old mailboxes.

Run preflight first, review `routing-plan.json` and
`gmail-configuration-plan.json`, then use the resumable `migrate` workflow:

```bash
python3 imapsync_bulk_migrator.py --mode preflight --config migration.config.json --output-dir ./exported
python3 imapsync_bulk_migrator.py --mode migrate --config migration.config.json --output-dir ./exported
```

- With the documented top-level `migrate` command, the four `deliveredto:`
  filters are reconciled and verified before export, independently of who
  provisions the aliases.
- Because alias automation is disabled in the base config, the individual
  `export`, `audit`, `import`, and `validate` modes also remain available.
  Standalone `export` makes no Gmail label/filter changes, and standalone
  `import` provisions and verifies them before historical import.
- Enabling the alias add-on adds `workspace-alias-plan.json`, and requires the
  coupled `migrate` command for export, import, and validation, so its
  filter-before-alias ordering and final Directory verification can't be
  bypassed. Its Workspace discovery plans aliases already owned by MailA as
  reused and free addresses as creates. Any address that resolves to a user,
  a group, or a different alias owner stops that alias-enabled run before any
  target change.

#### Reruns of the MailA example

Base reruns reuse completed message journal entries, exact labels, and
equivalent filters, and existing matching messages receive any missing routed
labels. Committed journals prevent blind appends, and a byte-identical message
already in the target is reused rather than appended again (see
[imported messages in a Gmail target](#imported-messages-in-a-gmail-target)
for the date warning this can produce).

If the first filter authorization fails:

- in top-level `migrate`, the run stops before export;
- in standalone `import`, it stops before provider import and leaves the staged
  export untouched.

After fixing the OAuth scope, rerun against the same staging directory.
Audited mail and import journals remain valid, and no message is appended
again. In the alias add-on mode, aliases already owned by MailA are also
reused, and alias failures stay resumable.

The final `migration-report.json` always groups source-account/folder counts,
resolved labels, created/reused labels and filters, duplicate label
additions, shared merges, failures and skips, validation, conflicts, and the
remaining operator actions. It adds Workspace alias create, reuse, conflict,
and verification results only when the alias add-on is enabled. See
[report contents](#report-contents) for the provenance counts.

## Workspace aliases (optional)

`target.workspace_aliases` optionally makes the non-target source addresses
deliver to the shared Google Workspace target user after migration. It's
separate from Gmail label routing: a Gmail filter labels future mail only after
Google Workspace actually accepts the old address, while a Workspace user alias
is what makes that address deliver to the target mailbox.

### Enabling aliases

The feature is deliberately opt-in. If `workspace_aliases` is absent, no
Directory client is constructed, and the routing workflow, artifacts, and
stage order are unchanged. To spell out the off state, use exactly:

```json
{"enabled": false}
```

No other alias settings are accepted while it's disabled.

To add automatic alias creation to the [generic routing
example](#generic-routing-example), add this inside `target`:

```json
{
  "workspace_aliases": {
    "enabled": true,
    "target_user": "primary@example.com",
    "from_source_accounts": true,
    "aliases": [],
    "exclusions": [],
    "conflict_policy": "create_only",
    "admin_auth": {
      "method": "xoauth2",
      "admin_email": "workspace-admin@example.com",
      "token_file": "secrets/workspace-directory.token"
    }
  }
}
```

With that add-on, the tool derives `alias@example.com` from the non-target
source account, and creates or reuses it only after the audited historical
import. The base example stays valid without the block.

#### Alias add-on for the MailA example

To let the tool create or reuse the four aliases on `mailA` after the audited
historical import, add this inside `target` of the
[MailA config](#maila-through-maile-example):

```json
{
  "workspace_aliases": {
    "enabled": true,
    "target_user": "mailA@example.com",
    "from_source_accounts": true,
    "aliases": [],
    "exclusions": [],
    "conflict_policy": "create_only",
    "admin_auth": {
      "method": "service_account",
      "credentials_file": "secrets/workspace-directory-service-account.json",
      "delegated_admin": "workspace-admin@example.com"
    }
  }
}
```

This takes the non-target source addresses MailB through MailE, canonically
unions them with any explicit `aliases`, and then applies `exclusions`.
Preflight reports the aliases it would create, the aliases already owned by
MailA that it would reuse, and collisions; it doesn't create anything.

### Alias settings

- `target_user` is required, and must be the one shared target Gmail mailbox.
- `from_source_accounts` defaults to `true` and derives every non-target
  `accounts[].source_email`.
- `aliases` adds explicit addresses; `exclusions` removes addresses from the
  combined set.
- Addresses are trimmed, case-folded, converted to non-transitional ASCII
  IDNA, limited to 254 octets in canonical form, de-duplicated, and sorted.
- The target user's own primary address can't be an alias, and the final set
  can't be empty.
- `conflict_policy` is required; its only value is `"create_only"`.
- Every alias-enabled `migration.routing.filters[].delivered_to` is stored in
  the same case-folded, non-transitional ASCII IDNA form as the alias intent.
- Two filter spellings that normalize to the same Gmail condition are rejected
  during config validation, before any API I/O, and every final alias must
  have exactly one matching normalized filter rule.
- Routing-only configs may keep one configured address spelling in the
  routing artifact, but Gmail execution uses its canonical case-folded,
  ASCII-IDNA condition. Equivalent duplicate spellings aren't executable, and
  are rejected rather than silently selecting or combining actions.

Alias creation therefore requires a Gmail target, one shared target mailbox,
and enabled routing. Set `account_merge_mode` to `many_to_one` when several
sources target that mailbox; a one-account old-to-new migration can use the
normal one-to-one mode. The label and filter config stays the source of truth
for how future messages are presented after delivery.

### What preflight checks

Read-only preflight inventories the target user's current aliases, and checks
each requested address against Workspace users, user aliases, groups and group
aliases, and verified domains:

- An exact alias already owned by `target_user` is planned as `reuse`.
- A free address in a verified primary or secondary domain is planned as
  `create`.
- A Workspace domain-alias domain is managed automatically and is reuse-only
  here: a requested address there that doesn't already resolve to the target is
  a conflict.
- Any primary user, group, group alias, or alias owned by another user is a
  hard conflict.

All conflicts are resolved before any Gmail, IMAP, or Directory target change
begins. The tool never deletes an alias, user, or group, never transfers
ownership, and never converts or replaces a colliding Directory resource:
`create_only` isn't a takeover policy. Unrelated aliases already attached to
the target user are kept, aren't included in the requested set, and aren't
changed.

### Directory API authorization and setup

Directory administration has its own `admin_auth`; Gmail IMAP credentials and
`gmail_api_auth` aren't reused. The base routing-only config doesn't need these
credentials or scopes. Before enabling aliases:

1. Enable the **Admin SDK API** (Directory API) in the credential's Google
   Cloud project.
2. Make sure every alias domain is verified in the same Workspace customer,
   and that every address to create uses a primary or secondary domain.
   Directory domain-alias addresses are generated by Google, and this tool
   never inserts them explicitly.
3. Give the acting administrator the least Workspace privileges needed to
   manage user aliases and read users, groups, and domains.
4. Grant exactly these OAuth scopes:

   - `https://www.googleapis.com/auth/admin.directory.user.alias`
   - `https://www.googleapis.com/auth/admin.directory.user.readonly`
   - `https://www.googleapis.com/auth/admin.directory.group.readonly`
   - `https://www.googleapis.com/auth/admin.directory.domain.readonly`

**Service account with domain-wide delegation (DWD).** Create a service
account, enable domain-wide delegation, and copy its numeric OAuth client ID.
Authorize that client ID with the four comma-separated scopes under
**Admin console > Security > Access and data control > API controls > Manage
Domain Wide Delegation**. Then configure the downloaded key and the
administrator to impersonate:

```json
{
  "method": "service_account",
  "credentials_file": "secrets/workspace-directory-service-account.json",
  "delegated_admin": "workspace-admin@example.com"
}
```

In this form, `google-auth` mints and refreshes short-lived access tokens
automatically from the service-account credentials and the delegated subject.

**Preissued administrator access token.** Use exactly one non-inline secret
source:

```json
{
  "method": "xoauth2",
  "admin_email": "workspace-admin@example.com",
  "env_var": "WORKSPACE_DIRECTORY_ACCESS_TOKEN"
}
```

- `token_file` can replace `env_var`. Inline tokens are rejected.
- The tool doesn't run an OAuth consent flow, and doesn't acquire or refresh a
  preissued token.
- When a config is loaded from a file, relative `credentials_file` and
  `token_file` paths resolve from the config directory.
- Keep keys and tokens out of version control, restrict them to the migration
  operator, rotate them after use, and never copy their contents into tickets,
  logs, or reports.

### Alias plans, order, recovery, and limits

Alias-enabled planning writes the private `workspace-alias-plan.json` beside
`routing-plan.json` and `gmail-configuration-plan.json`. It records the frozen
target/candidate identity and the planned create, reuse, and conflict
outcomes. `migration-report.json` exposes `workspace_aliases` planning,
provisioning, and verification sections, plus grouped `created`, `reused`,
`conflicted`, and `actions_required` results. Secrets aren't included.

Every live alias-enabled `migrate`, whether its aliases are planned as creates
or reuses, uses this stage order:

1. `discover_plan`
2. `discover_aliases`
3. `persist_plan`
4. `persist_alias_plan`
5. `provision_labels`
6. `provision_filters`
7. `export`
8. `audit`
9. `import`
10. `reconcile_gmail_before_aliases`
11. `provision_aliases`
12. `validate_verify`
13. `verify_aliases`
14. `final_report`

- Labels and filters are reconciled before export and import for every
  configured alias, including aliases that aren't active yet. The report
  records their `timing` as `"before_export"`, and sets
  `workspace_aliases.active_alias_filters_ready_before_export` after
  verification.
- `provision_aliases` stays after import: missing aliases aren't activated
  until the audited historical transfer completes, while aliases already owned
  by the target are reused without any change.
- Immediately before `provision_aliases`, the workflow takes a fresh live Gmail
  snapshot, reconciles every required label and filter again, and runs a
  read-only full verification. Safely missing state is recreated. An
  incompatible change, an authorization failure, or a cancellation fails
  `reconcile_gmail_before_aliases` before any Directory alias insertion is
  attempted in that run.
- Routed `preflight` and `migrate --dry-run` stop after read-only discovery and
  private plan/report persistence, with no Gmail or Directory change.
- When aliases are disabled, no Directory API is constructed or called, and the
  alias-specific stages are absent.

If one alias insertion fails, the aliases created earlier in that same stage
and all audited historical imports and journals are kept. Fix the
authorization, quota, domain, or propagation issue and rerun with the same
staging directory: completed aliases and filters are reused, and committed
message journals avoid another append. A failed run never rolls back by
deleting aliases.

Google Workspace allows up to 30 added email aliases per user, so leave room
for aliases managed outside this tool. Google also warns that alias additions
can take up to 24 hours to propagate. Final verification proves that the
Directory API reports each alias on the intended user; it can't prove
immediate Internet mail delivery. Test representative external delivery
before MX cutover or source retirement.

## Legacy mode

Use legacy mode for straightforward same-address migrations between generic
IMAP servers, optionally with DirectAdmin or cPanel mailbox creation or reset.
`preflight` and `migrate` need a provider config; legacy mode checks logins
with `--mode test` instead. Gmail and iCloud hosts are rejected in legacy
configs: use provider mode so their safeguards run.

### Legacy config

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

- Legacy account configs take inline `accounts[].password` values. For large
  or public workflows, keep those configs in ignored local files and protect
  them like secrets.
- An active legacy `server` follows the same transport rule as generic
  provider endpoints: enable implicit TLS or STARTTLS. A historical
  `source_server` descriptor may stay cleartext, so old staged exports can
  still be bound and audited offline, but any attempt to connect to it is
  rejected before authentication.

### Legacy commands

```bash
python3 imapsync_bulk_migrator.py --mode export --config export.pass.config.json --output-dir ./exported
python3 imapsync_bulk_migrator.py --mode import --config import.pass.config.json --input-dir ./exported
python3 imapsync_bulk_migrator.py --mode validate --config import.pass.config.json --input-dir ./exported
```

Legacy export runs its staged audit automatically. Use `--mode audit` to
re-check an existing export, rather than repeating it after every successful
export.

### The generated import config

Legacy export writes `import.pass.config.json` next to the export config, if
that file doesn't exist yet. It copies the accounts, sets the target host to
`CHANGE_ME.example.com`, and records the export server as `source_server`.

- Edit the generated target `server` block before import.
- Don't remove `source_server`. Strict import, audit, validation, and reset
  gates require it to prove the staged data came from the expected old server.

### File permissions

Legacy export writes account and mailbox directories with mode `0700`.
Staged messages, metadata, journals, state files, and generated configs use
mode `0600`. See [legacy staged files](#legacy-staged-files) for the layout.

### Generating a config from a panel

Two read-only indexers list the mailboxes on a panel and write a legacy
`export.pass.config.json`. They make no changes on the server. Each asks which
domains to include (press Enter for all).

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

- The DirectAdmin indexer works with a user-level API login. Give its secret
  with `--password`, `--password-file`, or `--password-env`. The cPanel
  indexer also accepts `--token`, `--token-file`, or `--token-env`. The inline
  `--password` and `--token` forms are insecure, because process arguments can
  expose them.
- `--imap-port` defaults to 993, or to 143 with `--imap-starttls`. `--imap-ssl`
  (the default) uses implicit TLS. `--no-verify-ssl` disables TLS certificate
  verification for the panel.
- Mailbox passwords are left empty as placeholders unless you pass
  `--default-password`, `--default-password-file`, or `--default-password-env`.
  Fill them in the import config (`import.pass.config.json`) before the real,
  non-dry-run panel import; that's the file the password check reads.
- Generated config files are written with mode `0600`. An existing output file
  is only replaced with `--overwrite`.

## DirectAdmin and cPanel

DirectAdmin and cPanel integration is available for legacy generic IMAP
imports. Provider configs never call hosting panel APIs, and combining panel
flags with a provider config is rejected.

- Every configured account must be in `local@domain` form. Panel workflows
  fail fast for malformed accounts.
- Remote panel base URLs must use HTTPS. Plain HTTP is accepted only with a
  literal loopback address such as `http://127.0.0.1:2222`, for a client
  running on the panel host itself.
- `--da-no-verify-ssl` and `--cpanel-no-verify-ssl` allow a controlled
  self-signed certificate: they disable certificate verification, not
  encryption. Prefer installing the correct CA certificate whenever possible.
- Before a non-dry-run create or reset, every configured mailbox must have a
  non-empty `accounts[].password`, which becomes the new mailbox's password.
  This is checked before any panel API change, and before a reset archives any
  import journal, so an empty placeholder can't leave a mailbox deleted. Panel
  dry runs still work while passwords are placeholders.
- Non-dry-run panel provisioning runs a strict local staged export audit before
  any panel API call. If the staged data is missing, malformed,
  source-mismatched, or inconsistent, provisioning aborts before any account
  is created or reset.

### Panel flags

Use one panel integration at a time.

| Purpose                                      | DirectAdmin                                                   | cPanel                                                                                               |
| -------------------------------------------- | ------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| Turn on (import mode)                        | `--auto-provision-da`                                         | `--auto-provision-cpanel`                                                                            |
| Panel URL                                    | `--da-url`                                                    | `--cpanel-url`                                                                                       |
| Panel login                                  | `--da-username`                                               | `--cpanel-username`                                                                                  |
| Panel secret                                 | `--da-password-file`, `--da-password-env`, or `--da-password` | `--cpanel-token-file`, `--cpanel-token-env`, `--cpanel-token`, `--cpanel-password-file`, `--cpanel-password-env`, or `--cpanel-password` |
| Preview without changes (needs the turn-on flag) | `--da-dry-run`                                            | `--cpanel-dry-run`                                                                                   |
| Skip certificate verification                | `--da-no-verify-ssl`                                          | `--cpanel-no-verify-ssl`                                                                             |
| Quota for new mailboxes, MiB (`0` = unlimited, the default) | `--da-quota-mb`                                | `--cpanel-quota-mb`                                                                                  |

The inline `--da-password`, `--cpanel-password`, and `--cpanel-token` flags
work, but they're insecure: process arguments and shell history can expose
them. Prefer the `-file` or `-env` forms.

DirectAdmin create-missing import:

```bash
python3 imapsync_bulk_migrator.py --mode import --config import.pass.config.json \
  --input-dir ./exported \
  --auto-provision-da \
  --da-url https://panel.example.com:2222 \
  --da-username admin \
  --da-password-file secrets/da-login-key
```

cPanel create-missing import:

```bash
python3 imapsync_bulk_migrator.py --mode import --config import.pass.config.json \
  --input-dir ./exported \
  --auto-provision-cpanel \
  --cpanel-url https://panel.example.com:2083 \
  --cpanel-username cpuser \
  --cpanel-token-file secrets/cpanel-api-token
```

## Destructive reset

> [!CAUTION]
> The reset path deletes and recreates the target mailboxes through
> DirectAdmin or cPanel, then imports the staged mail. It's meant for server
> replacement and decommissioning projects, where target mailboxes must be
> recreated before staged mail is imported. Keep independent backups.

```bash
python3 imapsync_bulk_migrator.py --mode import --config import.pass.config.json \
  --input-dir ./exported \
  --auto-provision-cpanel \
  --reset --reset-confirm imap.target.example.com \
  --cpanel-url https://panel.example.com:2083 \
  --cpanel-username cpuser \
  --cpanel-token-file secrets/cpanel-api-token
```

### Reset safeguards

Before anything is deleted:

- `--reset` requires DirectAdmin or cPanel provisioning.
- A non-dry-run reset requires `--reset-confirm` matching the target IMAP host,
  or `YES`.
- The staged legacy export must include completed account-level export state.
- Staged message metadata must include `content_sha256` and `rfc822_size`
  matching each `.eml` payload.
- `export-state.json` must match the generated import config's
  `source_server`.

While it runs:

- For each account, the stale journal archive, the panel reset, and the
  subsequent import all run under one per-effective-user target lock. That
  lock is shared across staging directories, so a concurrent operation waits
  for the sequence to finish, then reloads protected state.
- Because the target mailbox is about to be recreated, the locked import
  authenticates the recreated mailbox immediately after the reset. No separate
  target connectivity pass runs before the destructive reset.
- Failed panel resets cause the affected accounts to be skipped during import.
  With `--ignore-errors`, the command still exits non-zero if any reset skipped
  an account.

If it's interrupted:

- The staged account directory keeps `reset-state.json`, and an authoritative
  global reset gate remains as durable resume evidence. The gate binds the
  reset to its owner staging directory and target configuration.
- The global reset gate and the shared target locks live outside any staging
  directory, under `/var/tmp/imapsync-bulk-migrator-<euid>/legacy-target-state/`
  (`/private/var/tmp/...` on macOS).
- Only that staging directory may resume, with the same configuration and
  `--reset`. Target-facing work from another staging directory fails closed.
- Legacy export, ordinary panel ensure, target connectivity (including
  `--mode test`), import, validation target checks, and remote audit against
  that target all check the gate under the same per-account target lock before
  any target-facing work.
- The state is cleared only after the reset callback succeeds.

### Dry run first

Run a dry run before any destructive run:

```bash
python3 imapsync_bulk_migrator.py --mode import --config import.pass.config.json \
  --input-dir ./exported \
  --auto-provision-da \
  --reset --da-dry-run \
  --da-url https://panel.example.com:2222 \
  --da-username admin \
  --da-password-file secrets/da-login-key
```

A panel dry run exits after the panel planning step. It doesn't run
connectivity tests, doesn't need the `imapsync` binary, doesn't need
`--reset-confirm`, and doesn't import mail. It must be able to list the panel
mailboxes for each domain.

## Validation

Provider validation checks:

- a completed `export-state.json`;
- manifest digest and message count consistency;
- source and target account binding;
- source and target endpoint binding;
- effective source and target login binding;
- Gmail source and target visibility attestations, when relevant;
- unique manifest identities;
- per-message metadata consistency;
- import journal consistency;
- target folder mapping and hierarchy collision checks;
- target message presence by `Message-ID`, content hash, and size, where
  target validation is enabled;
- Gmail labels and Gmail target message IDs, when Gmail is the target;
- routing plan/config digest agreement and complete source-folder assignment;
- required routed custom/system label membership on both appended and reused
  Gmail messages;
- Workspace alias plan/config identity and final ownership, when automatic
  aliases are enabled;
- many-to-one merge group boundaries.

For an end-to-end routed migration, the aggregate report also includes Gmail
label/filter reconciliation and verification, and the optional Workspace alias
reconciliation and verification. A successful message validation alone doesn't
hide an unresolved filter or alias conflict, or an operator action still
required in `migration-report.json`.

Legacy validation checks folder counts, and best-effort message identity by
`Message-ID`, or by content hash and size. Duplicate local messages require
duplicate remote messages. Legacy import, validation, and reset gates require
strict local staged integrity checks and a matching `source_server` binding.

## Staged files, locks, and reports

### Provider staged files

Provider exports write per-account staged data, including:

- `manifest.jsonl`;
- `export-state.json`;
- `source-summary.json`;
- `messages/` payloads;
- `metadata/` sidecars;
- target import journals and validation reports, after the later stages.

With routing enabled, the staging directory also holds the reviewed
`routing-plan.json` and `gmail-configuration-plan.json`; opt-in Workspace alias
creation adds `workspace-alias-plan.json`. Each account's export state and
routed journal membership is bound to the routing mapping digest. A completed
`migrate` writes the aggregate `migration-report.json` at the top of the
staging directory. These files use the same private, atomic safeguards as
other provider state.

### Legacy staged files

Legacy exports write per-account directories under `exported/<account>/`,
containing the mailbox folders, `.eml` files, sidecar metadata,
`.mailbox.json`, `export-state.json`, and, after import,
`import.journal.jsonl`.

### Keep staged files intact

Resume and validation depend on these files. Don't hand-edit staged exports,
except for forensic inspection on a copy.

- A routing-enabled import without a valid current plan fails clearly.
- Older exports remain usable for legacy routing, but must be re-exported when
  they lack the complete source-folder metadata needed to guarantee the new
  routed memberships.

### Locks

- One private, crash-releasing workflow lock serializes provider planning,
  Gmail/Workspace changes, export, import, and final reporting for a staging
  directory. Standalone provider `export`, `import`, `validate`, and `audit`
  take the same lock.
- `import`, `validate`, and `audit` acquire it before reading staged account
  state, and `import` and `validate` also run their staged-data gate and
  target connectivity checks while holding it. Standalone `export` acquires it
  before loading the frozen plans, and holds it through export and its
  optional audit.
- Per-target import locks are narrower, so separate target accounts still use
  their own journal serialization.
- The files under `.import-locks/` are persistent lock inodes, not stale work
  to clean up. A normal exception or a process crash releases the kernel lock,
  and the next run reuses the file. Don't delete or replace lock files while a
  command is active.
- The whole `.import-locks/` namespace is reserved, and can't be chosen as a
  migration report destination.

### How report writes are confirmed

- A migration report is announced as an artifact only after its exact payload
  is currently visible at its path.
- The returned `report_persisted` flag means verified current visibility, not
  guaranteed crash durability.
- When the result reports a write failure, restore writable storage and rerun.

### How the final report is committed

The exact commit protocol. You don't need this to run a migration.

1. The workflow first atomically publishes a non-success payload with
   `status=finalizing`, a unique `terminal_commit_id`, the intended success
   specification digest, and `terminal_committed=false`.
2. Immediately before the atomic success replacement, a final check confirms
   that the marker still belongs to this commit and that no cancellation has
   been requested. This check is the linearization point: a stop it observes
   publishes failure, and the CLI exits 130.
3. The replacement uses the same ID and digest, the intended `planned` or
   `completed` status, and `terminal_committed=true`. A signal that arrives
   after the check may lose to the replacement: the committed success stays in
   place, the CLI returns 0, and a later signal can't rewrite it as
   cancellation.

If the success write raises after an uncertain rename or directory sync:

- The workflow safely reads the current JSON and treats success as committed
  only if the entire intended payload, commit ID, specification digest, and
  status match.
- It then returns the committed success with a sanitized
  `report_durability_uncertain` warning. `report_persisted=true` records exact
  current visibility, even though crash durability is unknown. The committed
  JSON isn't rewritten to add that warning.
- Otherwise it returns failure and leaves the current path untouched.
- Terminal reporting never deletes, renames, quarantines, or truncates an
  uncertain report path.

The workflow lock stops cooperating commands from writing at the same time.
It doesn't defend the report path against arbitrary out-of-band changes by a
different process running as the same EUID; that's outside the trust
boundary. Don't alter the report path while a workflow command is active.

### Report contents

Provider provenance counts appear per folder, per source account, and in
`totals`:

- `imported_source_records` (also exposed as `appended_source_records`)
  counts source manifest records whose earliest valid committed origin is an
  APPEND.
- `matched_existing_source_records` counts source manifest records whose
  committed origin reused a target message, including an existing match that
  needed no later `STORE`. These source-record counts may refer to the same
  Gmail physical message in a many-to-one migration.
- `appended_gmail_physical_messages` therefore separately de-duplicates the
  appended origins by target merge group plus Gmail message ID. Gmail IDs are
  mailbox-scoped: equal raw IDs in two distinct target mailboxes count as two
  physical messages, while equal IDs contributed by sources sharing one merge
  target count once.
- `appended_gmail_physical_message_ids` lists the raw IDs in deterministic
  target order, so duplicates across targets are possible.
  `appended_gmail_physical_message_refs` gives unambiguous `target_account`
  plus `target_gmail_msgid` pairs.

Every committed per-message report record also includes its
`target_gmail_msgid`, including a matched-existing record that needed no
`STORE`.

Top-level `gmail_physical_messages` groups those records by target merge group
and physical ID, names the `target_account`, and lists the contributing source
account and canonical IDs:

- Each contributor's stable earliest current-plan, membership-complete
  `appended` or `existing` origin is reported; foreign-plan and incomplete
  commits can't change provenance.
- Each group also includes the union of required custom and system
  destinations, and the labels actually added by this migration.
- `totals.gmail_physical_messages` counts those groups, and
  `totals.gmail_physical_message_merges` counts groups with more than one
  source record.
- These records contain only migration requirements and changes, on purpose;
  unrelated pre-existing Gmail labels aren't copied into the report.

## Secret hygiene

Staged exports contain full mailbox data. Protect `exported/`, logs, configs,
and secrets as sensitive data.

Local config and secret paths are ignored by Git, including:

- `*.pass.config.json*`
- `migration.config.json*`
- `migration.*.config.json*`
- `secrets/`
- `.env` and `.env.*`
- `*.token`
- `prompt.md`
- `prompts/`

Prefer file or environment-backed secrets:

- For provider mailbox auth, use `password_file`, `token_file`, or `env_var`
  when possible.
- For panel CLI credentials, prefer the `--*-file` or `--*-env` flags. Inline
  password flags work where documented, but they can show up in shell history
  or process listings.
- Treat `gmail_api_auth` and `target_gmail_api_auth` the same way. These
  values are bearer tokens, even though the generic auth object also accepts
  the legacy field name `password`; never commit or log them.
- Handle `workspace_aliases.admin_auth` even more strictly. Preissued tokens
  are accepted only through `token_file` or `env_var`; service-account DWD
  uses `credentials_file`. Never commit the key JSON, grant broader scopes than
  those listed above, share it with another workload, or leave the delegated
  authorization active after it's no longer needed.

Run logs are written with mode `0600`.

## Export verifier

`verify_export.py` inspects `./exported` in the current directory, locally, and
reports message counts, attachment presence, parsing errors, and possible
concatenated message files.

```bash
python3 verify_export.py
```

## Known constraints

**Proof**

- Live credentials are required for final proof.
- Local tests and dry runs can't guarantee that providers accept every
  operation in production.

**Gmail and Google Workspace**

- Workspace Gmail routes need OAuth/XOAUTH2 where Google permits IMAP access;
  password-only third-party IMAP, POP, and SMTP access isn't a production
  assumption.
- For Workspace Gmail targets, Google recommends supported migration options
  instead of IMAP upload; this tool's Gmail target route is an operator-managed
  IMAP copy path outside Google's recommended migration path.
- Workspace domain-wide IMAP or Gmail API authorization, if used, must be set
  up outside this tool.
- Workspace alias automation requires Admin SDK Directory API setup and
  separate administrator authorization. It doesn't create, delete, rename, or
  take over users, groups, domains, or aliases owned by another user.
- Workspace allows at most 30 added aliases per user, requires a new explicit
  alias to use a verified primary or secondary domain in the same customer,
  and can take up to 24 hours to propagate an alias change.
- Normal Gmail IMAP can't prove that users disabled folder-size limits or label
  hiding.
- Gmail app passwords are a personal-account fallback, where Google still
  allows them. They require 2-Step Verification and may be unavailable for
  Workspace, security-key-only, or Advanced Protection accounts.
- Gmail IMAP has documented transfer limits. Gmail-target imports may need
  throttling or batching, even when the operator accepts the IMAP copy route.
- Interactive OAuth acquisition stays external, as does refreshing preissued
  Gmail or Workspace administrator bearer tokens. Workspace alias
  service-account DWD instead mints and refreshes its short-lived access tokens
  automatically through `google-auth`.
- Gmail label/filter routing in one provider config currently requires one
  shared target Gmail mailbox.
- Gmail API label/filter provisioning requires a bearer token with the scopes
  described above; an IMAP app password isn't enough.

**iCloud**

- iCloud requires app-specific passwords and Apple Account two-factor
  authentication.

**IMAP behavior**

- IMAP UIDs aren't preserved.
- Provider imports preserve portable flags where the target supports them.
  Unsupported IMAP keywords can stop an import before append, and Gmail
  targets don't preserve `\Deleted` as an appended message flag.

**Older exports**

- Provider staged exports created by older versions may need to be rerun if
  they lack the current account, endpoint, manifest, journal, source-folder,
  or routing plan bindings the selected workflow requires.
- Legacy staged exports created by older versions may need to be rerun if they
  lack `source_server`, `source_server_sha256`, or per-message integrity
  metadata.

**Destructive operations**

- DirectAdmin/cPanel reset deletes target mailbox contents. Keep independent
  backups before destructive operations.

## Official references

**Standards**

- IMAP4rev2 protocol and `INTERNALDATE` semantics: https://www.rfc-editor.org/rfc/rfc9051.html
- TLS for email access: https://www.rfc-editor.org/rfc/rfc8314.html
- IMAP special-use mailboxes: https://www.rfc-editor.org/rfc/rfc6154.html

**Gmail**

- Gmail IMAP/SMTP: https://developers.google.com/workspace/gmail/imap/imap-smtp
- Gmail XOAUTH2: https://developers.google.com/workspace/gmail/imap/xoauth2-protocol
- Gmail IMAP extensions: https://developers.google.com/workspace/gmail/imap/imap-extensions
- Gmail API IMAP settings: https://developers.google.com/workspace/gmail/api/reference/rest/v1/ImapSettings
- Gmail API label guide: https://developers.google.com/workspace/gmail/api/guides/labels
- Gmail API label resources: https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.labels
- Gmail API filter guide: https://developers.google.com/workspace/gmail/api/guides/filter_settings
- Gmail API filter resources: https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.settings.filters
- Gmail API OAuth scopes: https://developers.google.com/workspace/gmail/api/auth/scopes
- Gmail `deliveredto:` search operator: https://support.google.com/mail/answer/7190
- Gmail dotted personal-address behavior: https://support.google.com/mail/answer/7436150
- Gmail `gmail.com` and `googlemail.com` equivalence: https://support.google.com/mail/answer/10313
- Gmail bandwidth limits: https://support.google.com/a/answer/1071518

**Google Workspace**

- Google Workspace password-only access changes: https://workspaceupdates.googleblog.com/2023/09/winding-down-google-sync-and-less-secure-apps-support.html
- Google Workspace IMAP data import: https://knowledge.workspace.google.com/admin/migrate/migrate-email-from-an-imap-account
- Google Workspace data import overview: https://knowledge.workspace.google.com/admin/migrate/about-the-new-data-migration-service
- Admin SDK Directory API Python setup and API enablement: https://developers.google.com/workspace/admin/directory/v1/quickstart/python
- Directory API authorization scopes: https://developers.google.com/workspace/admin/directory/v1/guides/authorizing
- Google Workspace credentials and domain-wide delegation: https://developers.google.com/workspace/guides/create-credentials
- Directory API user alias management: https://developers.google.com/workspace/admin/directory/v1/guides/manage-user-aliases
- Google Workspace user alias limits and propagation: https://support.google.com/a/answer/33327

**Apple**

- iCloud Mail settings: https://support.apple.com/en-us/102525
- Apple app-specific passwords: https://support.apple.com/en-us/102654

**Hosting panels and webmail**

- DirectAdmin legacy API: https://docs.directadmin.com/developer/api/legacy-api.html
- cPanel UAPI tokens: https://api.docs.cpanel.net/cpanel/tokens/
- cPanel UAPI email operations: https://api.docs.cpanel.net/specifications/cpanel.openapi/email-accounts/
- Roundcube project: https://roundcube.net/
