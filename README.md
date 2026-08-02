# imapsync-bulk-migrator

Staged, auditable mailbox migration tooling for IMAP providers and hosting
panels.

This project is for operators who need to move mailboxes, prove what was
staged, import into a new destination, and make a careful server
decommissioning decision. It works in explicit stages: preflight, export,
audit, import, and validate. Provider migrations can also use one resumable
`migrate` operation to orchestrate those stages. The same workflow supports
normal mailbox moves and destructive target reset flows for DirectAdmin and
cPanel hosted mail.

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

- audit exports before importing historical messages into the destination;
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
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt

# Optional, for local tests
python3 -m pip install -r requirements-dev.txt
```

Python 3.10+ is required. Provider-aware copy operations use Python `imaplib`.
DirectAdmin and cPanel integrations use `requests`. Legacy generic IMAP
connectivity tests also use the `imapsync` binary unless connectivity checks
are skipped or a panel dry-run exits before import.

Every IMAP endpoint the tool connects to must use encrypted transport: either implicit TLS
(`"ssl": true`) or STARTTLS (`"ssl": false, "starttls": true`). Cleartext
IMAP configs are rejected before credentials can be sent.

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
| Route many sources into one Gmail mailbox with labels, filters, and optional Workspace aliases | Opt-in provider routing plus `migrate` |

## Provider Workflow

Use provider mode when source and target accounts may differ, including Gmail,
iCloud, generic IMAP, and many-to-one account merges.

The split-stage sequence below is available when Workspace alias automation is
disabled. Alias-enabled provider configs use the coupled `migrate` command for
export, import, and validation.

```bash
python3 imapsync_bulk_migrator.py --mode preflight --config migration.config.json --output-dir ./exported
python3 imapsync_bulk_migrator.py --mode export --config migration.config.json --output-dir ./exported
python3 imapsync_bulk_migrator.py --mode import --config migration.config.json --input-dir ./exported
python3 imapsync_bulk_migrator.py --mode validate --config migration.config.json --input-dir ./exported

# Or orchestrate the safe provider stages in one resumable operation
python3 imapsync_bulk_migrator.py --mode migrate --config migration.config.json --output-dir ./exported

# Preview that orchestration without remote mutations
python3 imapsync_bulk_migrator.py --mode migrate --dry-run --config migration.config.json --output-dir ./exported
```

Export runs the strict staged audit automatically by default. Use `--mode
audit` to re-check an existing export, or after an export that deliberately
used `--no-audit-after-export`.

For routing-only configs, the commands differ in Gmail mutation timing. When
filters are configured, the top-level `migrate` workflow reconciles and verifies
the requested Gmail labels and filters before export; without filters, it
reconciles required custom labels after audit and before import. Standalone
`export` only uses the frozen plans and does not change Gmail labels or filters;
standalone `import` reconciles and verifies the complete requested Gmail
configuration immediately before importing historical mail.

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

Provider configuration objects use closed schemas. Unknown fields at the root,
account, auth, migration, limits, and throttle levels are rejected with their
full configuration path and the allowed field names, so a typo cannot silently
disable a safeguard or fall back to a default.

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

Imports are scheduled by target group: sources sharing one target remain
sequential, while unrelated targets can run concurrently up to `--max-workers`.
Before normal work for a group, import holds that target's lock and resolves
recoverable pending `APPEND` rows across every source journal in the group.
Cross-source byte-identical content reuses one physical target message only
when its delivery metadata is compatible; duplicate occurrences within one
source still preserve that source's multiplicity. Validation aggregates each
physical target bucket and treats the maximum multiplicity demanded by any one
source as its expected capacity; missing or extra matching occurrences fail
validation. In `target_mode=empty`, the destination may contain only messages
already accounted for by journals from the same merge group.

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

## Opt-In Gmail Label Routing

`migration.routing` is an opt-in extension for routing several source
mailboxes into one Gmail target. If the block is absent, existing `folder_map`,
one-to-one, and many-to-one migrations behave as before. If the block is
present, `enabled` must be explicitly `true`, all configured accounts must
share one target mailbox, and preflight must resolve every discovered source
folder before a target mutation is allowed.

A route destination is typed:

- `custom_label` means an ordinary Gmail user label. Historical messages get
  that label and remain visible in All Mail; they do not get Inbox unless an
  `inbox` system destination is also configured.
- `gmail_system` means an explicitly selected Gmail system location such as
  `inbox`, `sent`, `drafts`, or `all`.
- `mailbox` is for non-Gmail routing rules. A non-Gmail rule must select exactly
  one mailbox and cannot use Gmail filters or account label namespaces.

System `spam` and `trash` are unsafe for historical mail because Gmail may
apply retention or deletion behavior. They require `"allow_unsafe": true` on
that exact `gmail_system` destination. A custom label such as
`Imported/Junk` is not system Spam and needs no acknowledgement.

Rules can match an exact source folder or a detected role (`inbox`, `sent`,
`drafts`, `trash`, `archive`, or `junk`). Resolution order is deterministic:

1. account exact-folder rule;
2. account role rule;
3. global exact-folder rule;
4. global role rule;
5. account `default_label` or `default_namespace`.

Conflicting rules at the same level are reported as ambiguous. An explicit
rule replaces the account default; set `include_default` to `true` only when
both its destinations and the normal account label are wanted. An exclusion is
`{"exclude": true}` with no destinations.

Preflight discovers selectable source folders, delimiters, SPECIAL-USE roles,
and the target Gmail system/user label inventory. It performs no remote
creates, appends, label changes, filter changes, or deletes. The reviewed
mapping is frozen in `routing-plan.json`; the requested Gmail labels and filter
specifications are frozen beside it in `gmail-configuration-plan.json`. Later
stages verify those identities instead of making hidden routing decisions.
Exact existing user-label names are reused; case-only or hierarchy conflicts
stop the run before mutation.

For a Google Workspace target, the separate opt-in
`target.workspace_aliases` block can derive user aliases from the non-target
source accounts. Its read-only discovery is frozen in
`workspace-alias-plan.json`. Omitting the block, or setting only
`{"enabled": false}`, preserves the routing-only workflow and makes no Admin
SDK calls.

Routed `preflight` and `migrate --dry-run` perform the same remote-mutation-free
planning workflow. They persist the applicable private routing and Gmail
plans, the conditional `workspace-alias-plan.json`, and a migration report
under `--output-dir`. A routing-disabled `preflight` normally remains a concise
check, but supplying `--report-file` explicitly also runs the reporting
workflow and writes that requested report; it does not invent routing, Gmail,
or alias plan artifacts. Dry-run guidance lists only the artifacts emitted by
that configuration. Standard output stays clean; the CLI logs a concise status
and artifact-path summary to standard error, while the full structured report
remains in its private file. Use `--report-file` to select a different report
path. It must be inside the staging root and cannot overlap a persisted plan,
an account staging directory, `.eml`/metadata, a manifest, validation report,
import journal, or any path in the reserved `.import-locks/` namespace. An
existing target is accepted only when it is the prior migration report bound
to that same staging root and report path; symlinks, hard links, directories,
and unrelated existing files are rejected. Persisted report bindings use
normalized absolute paths, so an equivalent rerun remains valid after changing
the current working directory. CLI-supplied relative paths retain normal
current-working-directory semantics, so with
`--output-dir ./exported`, use a nested path such as
`--report-file ./exported/reports/migration.json`.

Provider planning/migration and standalone provider export, import, validate,
and audit commands are serialized per staging root. Import, validate, and audit
acquire this lock before reading staged account state; import and validate also
perform their staged-data gate and target connectivity checks while holding it.
Standalone export acquires the lock before loading frozen plans and holds it
through export and its optional audit. The private
`.import-locks/` files are persistent lock inodes, not stale work to clean up: a
normal exception or process crash releases the kernel lock, and the next run
reuses the file. Do not delete or replace lock files while a command is active.

Failure details are written to standard error one issue at a time. A report
path is announced as an artifact only after the exact payload is currently
visible there. `report_persisted` records that verified visibility; it is not a
claim of guaranteed crash durability. Authorization headers, bearer
credentials, passwords, secrets, API keys, and token names including
`oauth_token`, `authorization_token`, and `api_token` are redacted
case-insensitively in plain and URL-encoded CLI diagnostics.

Terminal success uses an explicit two-step commit. The workflow first
atomically writes a non-success `finalizing` report with a unique commit ID and
specification digest. The final check of that marker and cancellation state,
immediately before atomic success replacement, is the linearization point. A
stop observed by that check publishes failure and exits 130. A signal arriving
after the check may lose to the terminal commit; the exact
`terminal_committed=true` success remains in place and the CLI returns 0.

If the success write raises after replacement, the workflow accepts it only
when a safe read finds the complete intended commit payload. It returns that
committed success with `report_durability_uncertain` when the raised sync error
means crash durability is unknown; the already committed JSON is not rewritten.
Otherwise it returns failure and leaves the current path untouched. Terminal
reporting never deletes, renames, quarantines, or truncates an uncertain report
path. The root workflow lock excludes cooperating writers. Arbitrary
out-of-band mutation by another same-EUID process is outside the trust boundary,
so do not alter the report path while a command is active.

### MailA through MailE example

This complete provider config routes five old IMAP accounts into the existing
Google Workspace Gmail mailbox `mailA@example.com`. It assumes the Workspace
aliases `mailB@example.com` through `mailE@example.com` are provisioned
separately; this base run owns only historical-mail routing, Gmail labels, and
Gmail filters. It also assumes the `MailB` Gmail label already exists, so
discovery reports `MailB` as reused and reports `MailC`, `MailD`, `MailE`, and
`Imported/Junk` as labels to create. Adjust the primary-account rules if
preflight discovers additional folders; unresolved folders deliberately stop
the run.

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

The global `junk` role rule outranks each non-primary account default, so `Junk`,
`Spam`, `INBOX.Spam`, and `Junk E-mail` all contribute only to the shared
`Imported/Junk` label. It does not create `MailB/Junk`, `MailC/Spam`, or other
account-specific junk labels. The four filter rules become Gmail queries such
as `deliveredto:mailB@example.com`; `inbox: "keep"` applies the label without
archiving future mail. Use `"archive"` to remove Inbox and set
`mark_read: true` when that behavior is desired.

The base config deliberately omits `target.workspace_aliases`. Provision
`mailB@example.com` through `mailE@example.com` separately in Google Workspace,
and verify representative external delivery before retiring the old mailboxes.
No Admin SDK client is constructed and no Workspace user or alias state is
inspected or changed. With the documented top-level `migrate` command, the four
Gmail filters are reconciled and verified before export, independently of who
provisions the aliases. In the split-stage workflow, standalone `export` makes
no Gmail label/filter changes and standalone `import` reconciles them before
historical import.

#### Optional Workspace alias automation add-on

To let this tool create or reuse the four Workspace user aliases after the
audited historical import, add the following optional block inside `target`:

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

This opt-in mode takes the non-target source addresses MailB through MailE,
canonically unions them with any explicit `aliases`, and then applies
`exclusions`. Every `routing.filters[].delivered_to` address is case-folded and
converted to non-transitional ASCII IDNA; two filter spellings that normalize
to the same address are rejected. Routing-only mode may retain one configured
spelling in its routing artifact, but Gmail execution uses the same canonical
condition and rejects equivalent duplicate spellings during config validation.
Every surviving alias must have an exact normalized filter entry. Preflight
reports aliases it would create, aliases already owned by MailA that it will
reuse, and collisions; it does not create anything. A user, group, or alias
owned by anyone else is a hard conflict. `create_only` never deletes, transfers,
or replaces an existing Directory resource.

#### Gmail and optional Workspace authorization

Gmail REST authorization is separate from IMAP login. Label writes require
`https://www.googleapis.com/auth/gmail.labels`, or a compatible
`gmail.modify`/full-mail scope; filter provisioning additionally requires
`https://www.googleapis.com/auth/gmail.settings.basic`. A dedicated
`target.gmail_api_auth` token is clearest, although the target XOAUTH2 token is
reused when it already has every required scope. App passwords cannot authorize
the Gmail API. Any route using `custom_label`, `default_label`, or
`default_namespace` needs this label-management authorization; a system-only
route can remain IMAP-only. The tool does not run an interactive OAuth flow or
acquire or refresh the preissued Gmail IMAP/API bearer tokens supplied through
configuration.

When the optional add-on is enabled, Workspace alias administration is a third,
separate authorization boundary. The base routing-only config above does not
need these credentials or scopes.
Enable the Admin SDK Directory API in the credential's Google Cloud project.
For the service-account form, also enable domain-wide delegation and authorize
its OAuth client ID in the Admin console for exactly these scopes:

- `https://www.googleapis.com/auth/admin.directory.user.alias`;
- `https://www.googleapis.com/auth/admin.directory.user.readonly`;
- `https://www.googleapis.com/auth/admin.directory.group.readonly`;
- `https://www.googleapis.com/auth/admin.directory.domain.readonly`.

The delegated admin also needs the corresponding Workspace privileges.
Service-account DWD uses `google-auth` to mint and refresh short-lived access
tokens automatically. As an alternative, `admin_auth` accepts a preissued
admin bearer token through `token_file` or `env_var`; this tool does not acquire
or refresh that preissued token. Keep token and service-account files out of
version control and restrict access to the migration operator.

Google requires an alias domain to be verified in the same Workspace customer.
A new explicit user alias must use a primary or secondary domain; addresses in
a Workspace domain-alias domain are automatically managed and can only be
reused when already present. Google limits a user to 30 added email aliases and
warns that changes can take up to 24 hours to propagate. Final verification
proves Directory ownership; perform a later delivery test before relying on the
new aliases for cutover.

#### Reruns and stage ordering

On a base routing-only rerun, exact labels and equivalent filters are reused,
existing matching messages receive any missing routed labels, and committed
journals prevent blind appends. In the optional alias-enabled mode, Workspace
aliases already owned by the target are also reused.
A byte-identical message already in the target is reused rather than appended
again. If its target `INTERNALDATE` differs from the source, the target date is
left unchanged and validation emits the non-fatal warning
`existing-target-internaldate-differs`, including both dates and
`existing-content-reuse` provenance. This means the source date metadata was
not preserved, but no duplicate message was created.

Every live alias-enabled workflow reconciles and verifies all required Gmail
labels and filters immediately after the plans are persisted, before export and
import, whether each configured alias will be created or reused. Workspace
alias activation remains after the audited import, followed by final ownership
verification. Routed preflight and `migrate --dry-run` remain non-mutating: they
stop after discovery and private plan/report persistence. Filter verification
governs later delivery; it does not claim that mail delivered before
verification was labeled retroactively. Historical messages receive their
resolved labels directly during import. Alias-enabled provider configs must use
the coupled `migrate` workflow for export, import, and validation: standalone
`--mode export`, `--mode import`, and `--mode validate` are rejected so they
cannot bypass the audited filter-before-alias sequence and final ownership
verification.

When alias automation is disabled, routing-only `migrate` uses the same
pre-export Gmail reconciliation for configured filters. The individual stages
remain available, but standalone `export` performs no Gmail reconciliation;
standalone `import` reconciles and verifies the requested labels and filters
before it imports messages.

A same-condition filter with incompatible actions is a conflict under
`conflict_policy: "error"`. Set `"replace"` only after reviewing the plan;
replacement explicitly deletes incompatible same-condition filters. That
filter policy does not apply to Workspace aliases, whose only policy is
non-destructive `create_only`. Unrelated target messages, labels, filters,
aliases, and settings are not changed.

## Legacy Panel Workflow

Use legacy mode for same-address generic IMAP migrations and hosting-panel
workflows.

```bash
python3 imapsync_bulk_migrator.py --mode export --config export.pass.config.json --output-dir ./exported
python3 imapsync_bulk_migrator.py --mode import --config import.pass.config.json --input-dir ./exported
python3 imapsync_bulk_migrator.py --mode validate --config import.pass.config.json --input-dir ./exported
```

Legacy export also audits automatically. Run `--mode audit` separately only
when you need to re-check staged data.

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

The journal archive, panel reset, and subsequent import for each account run
under one per-effective-user target lock shared by every staging root. A
concurrent operation waits and reloads protected state after the first
operation finishes. Because the target mailbox is about to be recreated, its
authentication check happens in the locked import immediately after reset
rather than in a separate pre-reset connectivity pass.

If destructive reset is interrupted, the account's local `reset-state.json`
and an authoritative global reset gate remain as durable resume evidence. The
gate records the owner staging root and target configuration. Only that root
may resume with the same target configuration and `--reset`; target-facing
operations from another root fail closed. Legacy export, ordinary panel ensure,
target connectivity (including `--mode test`), import, validation target checks,
and remote audit against that target all check the gate while holding the same
target lock. The state is cleared only after the reset callback succeeds.

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
Panel API URLs must use HTTPS. The only cleartext exception is `http://` with a
literal loopback address such as `127.0.0.1`, for a panel client running on the
same machine. `--da-no-verify-ssl` and `--cpanel-no-verify-ssl` support
controlled self-signed TLS deployments; they disable certificate verification,
not encryption. Before any non-dry-run panel create or reset, fill a non-empty
`accounts[].password` for every mailbox. Indexer output may leave these values
empty as placeholders.

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
- Generic IMAP credentials are sent only after implicit TLS or STARTTLS is
  active; cleartext IMAP is not supported.
- Remote DirectAdmin and cPanel API connections require HTTPS even when
  certificate verification is explicitly disabled; cleartext is limited to a
  literal loopback address.
- Interactive OAuth acquisition remains external, as does refresh of preissued
  Gmail or Workspace administrator bearer tokens. Workspace alias
  service-account DWD instead mints and refreshes its short-lived access tokens
  automatically through `google-auth`.
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
