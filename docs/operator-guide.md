# Operator Guide

This guide expands on the public README with operational details for mailbox
migrations and server decommissioning workflows.

## Workflow Model

Migrations are staged:

1. Export selected source mailboxes into local `.eml` files and metadata.
2. Audit the staged export before touching the target.
3. Import into the target with resume journals.
4. Validate staged identities against the target.
5. Decide whether the old server can be decommissioned.

Provider mode is for Gmail, iCloud, generic IMAP, and source-target pairs where
the address or provider can change. Legacy mode is for same-address generic IMAP
migrations and DirectAdmin/cPanel provisioning.

## CLI Reference

The main entry point is:

```bash
python3 imapsync_bulk_migrator.py --help
```

Supported modes are `preflight`, `test`, `export`, `audit`, `import`, and
`validate`.

Default config names are:

- `migration.config.json` for provider `preflight`;
- `export.pass.config.json` for legacy `export`, `test`, and `audit`;
- `import.pass.config.json` for legacy `import` and `validate`.

Common flags include `--config`, `--output-dir`, `--input-dir`,
`--max-workers`, `--ignore-errors`, `--log-dir`, `--min-free-gb`, and
`--imap-timeout`.

## Provider Mode

Supported providers are:

- `gmail`: `imap.gmail.com:993`; auth methods `xoauth2` or `app_password`.
- `icloud`: `imap.mail.me.com:993`; auth method `app_password`.
- `imap`: generic IMAP with `password`, `app_password`, or `xoauth2`.

For app-password auth, provider account prerequisites still apply. Gmail app
passwords require 2-Step Verification and may be unavailable for Workspace,
security-key-only, or Advanced Protection accounts. Apple app-specific
passwords require Apple Account two-factor authentication.

Known Gmail and iCloud IMAP hosts are rejected under provider `imap` so their
provider-specific safeguards cannot be bypassed by accident.

Typical command sequence:

```bash
python3 imapsync_bulk_migrator.py --mode preflight --config migration.config.json
python3 imapsync_bulk_migrator.py --mode export --config migration.config.json --output-dir ./exported
python3 imapsync_bulk_migrator.py --mode audit --config migration.config.json --input-dir ./exported
python3 imapsync_bulk_migrator.py --mode import --config migration.config.json --input-dir ./exported
python3 imapsync_bulk_migrator.py --mode validate --config migration.config.json --input-dir ./exported
```

Important provider settings:

- `migration.target_mode`: `empty` or `merge`.
- `migration.account_merge_mode`: `one_to_one` or `many_to_one`.
- `migration.folder_map`: source mailbox name to target mailbox name mapping.
- `limits.throttle.max_bytes_per_second`: optional import/export throttling.
- `limits.retry_max_attempts`: retry budget for provider operations.

In multi-account provider configs, per-account credentials are required by
default. Endpoint-level secrets are rejected so one login is not accidentally
reused for every account. The explicit exception is many-to-one target mode
when all accounts share one target mailbox.

Provider auth accepts at most one secret source per auth block. The effective
account auth must have a secret, but endpoint-level auth may omit the secret
when account-level auth supplies it.

- `password` for inline password/token values;
- `password_file` for password or app-password files;
- `token_file` for XOAUTH2 token files;
- `env_var` for secrets stored in the environment.

`token_file` is valid only for XOAUTH2. `password_file` is not valid for
XOAUTH2.

## Gmail

Gmail migrations have additional proof requirements because labels and virtual
mailbox views can make a naive IMAP count misleading.

For Gmail sources, export requires:

- `X-GM-EXT-1`;
- a selectable All Mail view advertised with the `\All` special-use attribute;
- a full-visibility attestation.

For a single account, set `source.gmail_full_visibility_verified=true` only
after confirming Gmail IMAP exposes the full mailbox. For multi-account Gmail
source migrations, each account needs
`accounts[].gmail_full_visibility_verified=true`.

For Gmail targets, import and validation require the same extension and All
Mail checks. For a single target account, set
`target.gmail_full_visibility_verified=true` only after confirming the target is
not hiding messages from IMAP. Multi-target Gmail migrations need
`accounts[].target_gmail_full_visibility_verified=true`, unless the config is an
explicit many-to-one migration into one shared Gmail target and the shared
target endpoint has `target.gmail_full_visibility_verified=true`.

Gmail target imports restore non-system labels with `+X-GM-LABELS`. `Starred`
and `Important` are handled as Gmail system labels rather than normal custom
labels.

For personal Gmail addresses, dotted `gmail.com` aliases and matching
`googlemail.com` aliases are treated as the same mailbox for config validation,
target grouping, endpoint binding, and journal binding. Use one target label
spelling consistently in many-to-one configs to keep operator output easy to
read.

For Google Workspace accounts, password-only third-party IMAP, POP, and SMTP
access is not a production assumption. Use OAuth/XOAUTH2 where Google permits
IMAP access. For Workspace Gmail targets, Google directs migrations to
supported Workspace migration options instead of IMAP upload. Treat this tool's
Gmail target path as an operator-managed IMAP copy route, not Google's
recommended migration path.

## iCloud

iCloud uses app-specific passwords, which require Apple Account two-factor
authentication before they can be generated. The tool defaults the username to
the local part of the relevant iCloud account address when one is not
configured. If that fails in your environment, configure the exact username
required by Apple for the mailbox.

iCloud does not expose Gmail-style cross-label identity. Physical copies in
different folders are preserved as separate messages. The provider skips the
iCloud `VIP` view as a known search view.

## Generic IMAP, Roundcube, DirectAdmin, and cPanel Mail

Generic IMAP mode is the correct provider mode for mailboxes normally accessed
through Roundcube, DirectAdmin webmail, cPanel webmail, or another hosted
webmail UI. Use the underlying IMAP server and mailbox credentials.

Generic IMAP exports every selectable mailbox. Special-use attributes such as
`\All` and `\Flagged` are advisory for generic IMAP and are not treated as
proof that a mailbox is virtual. Use the exact spelling and case returned by
IMAP `LIST` for non-INBOX mailbox names in `folder_map` and review output;
only `INBOX` is case-insensitive by the IMAP standard. During empty-target
resume checks, generic target `\All` and `\Flagged` views are allowed only for
messages already matched by committed journal rows or recoverable pending rows
from the same migration; unmatched messages still fail the empty-target gate.
A pending row is not production proof by itself: import must resolve it to
committed, and validation must pass before decommissioning.

## Many-To-One Merges

Use `migration.account_merge_mode=many_to_one` to merge multiple source
mailboxes into one target mailbox.

The merge group is keyed by the effective target IMAP login and endpoint. When
several accounts target the same login, imports into that target are serialized
even if `--max-workers` is higher than one. In `target_mode=empty`, unjournaled
target content still fails the empty-target gate.

Duplicate messages already present from an earlier source account are journaled
as existing instead of blindly appended again.

Hybrid configs are allowed: one target group can merge `a`, `b`, and `c` into
`a`, while `d` and `e` remain one-to-one in the same provider config. Use
per-account target auth in that shape so singleton targets do not reuse the
merge target login by accident.

## Legacy Generic IMAP Mode

Use legacy mode for straightforward same-address migrations:

```bash
python3 imapsync_bulk_migrator.py --mode export --config export.pass.config.json --output-dir ./exported
python3 imapsync_bulk_migrator.py --mode audit --config export.pass.config.json --input-dir ./exported
python3 imapsync_bulk_migrator.py --mode import --config import.pass.config.json --input-dir ./exported
python3 imapsync_bulk_migrator.py --mode validate --config import.pass.config.json --input-dir ./exported
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

Legacy export generates `import.pass.config.json` with
`CHANGE_ME.example.com` as the target host and `source_server` set to the export
server. Edit the generated target `server` block before import. Do not remove
`source_server`; strict import, audit, validation, and reset gates require it.

Legacy export writes account and mailbox directories with mode `0700`; staged
messages, metadata, journals, state files, and generated configs use mode
`0600`.

Legacy account configs accept inline `accounts[].password` values. For
large/public workflows, keep those configs in ignored local files and protect
them like secrets.

## Artifacts and Resume Data

Provider exports write per-account staged data including:

- `manifest.jsonl`;
- `export-state.json`;
- `source-summary.json`;
- `messages/` payloads;
- `metadata/` sidecars;
- target import journals and validation reports after later stages.

Legacy exports write per-account directories under `exported/<account>/`, with
mailbox folders, `.eml` files, sidecar metadata, `.mailbox.json`,
`export-state.json`, and `import.journal.jsonl` after import.

Resume and validation depend on these files. Do not hand-edit staged exports
except for forensic inspection on a copy.

## DirectAdmin and cPanel

DirectAdmin and cPanel integration is available for legacy generic IMAP imports.
Provider configs do not call hosting panel APIs.

Every configured account must be in `local@domain` form. Panel workflows fail
fast for malformed accounts.

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

Non-dry-run panel provisioning runs a strict local staged export audit before
any panel API call. If staged data is missing, malformed, source-mismatched, or
inconsistent, provisioning aborts before accounts are created or reset.

## Destructive Reset for Decommissioning

The reset path deletes and recreates target mailboxes through DirectAdmin or
cPanel, then imports staged mail. It is intended for server replacement and
decommissioning projects.

```bash
python3 imapsync_bulk_migrator.py --mode import --config import.pass.config.json \
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
- The staged legacy export must include completed account-level export state.
- Staged message metadata must include `content_sha256` and `rfc822_size`
  matching each `.eml` payload.
- `export-state.json` must match the generated import config `source_server`.
- After a successful reset, stale legacy import journals are archived before
  connectivity tests or import begin.
- Failed panel resets cause affected accounts to be skipped during import.
- With `--ignore-errors`, the command still exits non-zero if any reset skipped
  an account.
- Dry-run mode must be able to list panel mailboxes for each domain.

Use dry-run before destructive runs:

```bash
python3 imapsync_bulk_migrator.py --mode import --config import.pass.config.json \
  --input-dir ./exported \
  --auto-provision-da \
  --reset --da-dry-run \
  --da-url https://panel.example.com:2222 \
  --da-username admin \
  --da-password-file secrets/da-login-key
```

Panel dry-run exits after the panel planning step. It does not run connectivity
tests, does not require the `imapsync` binary, and does not import mail.

## Validation Model

Provider validation checks:

- completed `export-state.json`;
- manifest digest and message count consistency;
- source and target account binding;
- source and target endpoint binding;
- effective source and target login binding;
- Gmail source and target visibility attestations when relevant;
- unique manifest identities;
- per-message metadata consistency;
- import journal consistency;
- target folder mapping and hierarchy collision checks;
- target message presence by `Message-ID`, content hash, and size where target
  validation is enabled;
- Gmail labels and Gmail target message IDs when Gmail is the target;
- many-to-one merge group boundaries.

Legacy validation checks folder counts and best-effort message identity by
`Message-ID` or content hash and size. Duplicate local messages require
duplicate remote messages. Legacy import, validation, and reset gates require
strict local staged integrity checks and a matching `source_server` binding.

## Secret Hygiene

Local config and secret paths are ignored by Git:

- `*.pass.config.json*`
- `migration.config.json*`
- `migration.*.config.json*`
- `secrets/`
- `.env` and `.env.*`
- `*.token`
- `prompt.md`
- `prompts/`

Prefer file or environment-backed secret sources. For provider mailbox auth,
use `password_file`, `token_file`, or `env_var` when possible. For panel CLI
credentials, prefer the `--*-file` or `--*-env` flags. Inline password flags
work where documented, but they can appear in shell history or process
listings.

Run logs are written with mode `0600`.

## Additional Export Verifier

`verify_export.py` performs a local inspection of `./exported` and reports
message counts, attachment presence, parsing errors, and possible concatenated
message files.

```bash
python3 verify_export.py
```

## Known Constraints

- Live credentials are required for final proof.
- Local tests and dry-runs cannot guarantee provider acceptance in production.
- Workspace Gmail routes need OAuth/XOAUTH2 where Google permits IMAP access;
  password-only third-party IMAP, POP, and SMTP access is not a production
  assumption.
- For Workspace Gmail targets, Google recommends supported migration options
  instead of IMAP upload; this tool's Gmail target route is an operator-managed
  IMAP copy path outside Google's recommended migration path.
- Workspace domain-wide IMAP or Gmail API authorization, if used, must be set
  up outside this tool.
- Normal Gmail IMAP cannot prove that users disabled folder-size limits or label
  hiding.
- Gmail app passwords are a personal-account fallback where Google still allows
  them; they require 2-Step Verification and may be unavailable for Workspace,
  security-key-only, or Advanced Protection accounts.
- Gmail IMAP has documented transfer limits. Gmail-target imports may require
  throttling or batching even when the operator accepts the IMAP copy route.
- OAuth token acquisition and refresh are external to this tool.
- iCloud requires app-specific passwords and Apple Account two-factor
  authentication.
- IMAP UIDs are not preserved.
- Provider imports preserve portable flags where the target supports them.
  Unsupported IMAP keywords can stop an import before append, and Gmail targets
  do not preserve `\Deleted` as an appended message flag.
- Provider staged exports created by older versions may need to be rerun if they
  lack current account, endpoint, manifest, or journal bindings.
- Legacy staged exports created by older versions may need to be rerun if they
  lack `source_server`, `source_server_sha256`, or per-message integrity
  metadata.
- DirectAdmin/cPanel reset deletes target mailbox contents. Keep independent
  backups before destructive operations.

## Official Behavior References

- Gmail IMAP/SMTP: https://developers.google.com/workspace/gmail/imap/imap-smtp
- Gmail XOAUTH2: https://developers.google.com/workspace/gmail/imap/xoauth2-protocol
- Gmail IMAP extensions: https://developers.google.com/workspace/gmail/imap/imap-extensions
- Gmail API IMAP settings: https://developers.google.com/workspace/gmail/api/reference/rest/v1/ImapSettings
- Gmail dotted personal-address behavior: https://support.google.com/mail/answer/7436150
- Gmail `gmail.com` and `googlemail.com` equivalence: https://support.google.com/mail/answer/10313
- Google Workspace password-only access changes: https://workspaceupdates.googleblog.com/2023/09/winding-down-google-sync-and-less-secure-apps-support.html
- Google Workspace IMAP data import: https://knowledge.workspace.google.com/admin/migrate/migrate-email-from-an-imap-account
- Google Workspace data import overview: https://knowledge.workspace.google.com/admin/migrate/about-the-new-data-migration-service
- Gmail bandwidth limits: https://support.google.com/a/answer/1071518
- iCloud Mail settings: https://support.apple.com/en-us/102525
- Apple app-specific passwords: https://support.apple.com/en-us/102654
- DirectAdmin legacy API: https://docs.directadmin.com/developer/api/legacy-api.html
- cPanel UAPI tokens: https://api.docs.cpanel.net/cpanel/tokens/
- cPanel UAPI email operations: https://api.docs.cpanel.net/specifications/cpanel.openapi/email-accounts/
- Roundcube project: https://roundcube.net/
