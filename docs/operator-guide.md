# Operator Guide

This guide expands on the public README with operational details for mailbox
migrations and server decommissioning workflows.

## Workflow Model

Provider migrations are staged:

1. Preflight connectivity, capacity, and any opt-in resolved routing and
   Workspace alias plans.
2. In top-level `migrate` when future-delivery filters are requested, reconcile
   and verify all required Gmail labels and filters immediately after persisting
   the plans, before export begins. Standalone `export` deliberately skips Gmail
   reconciliation and only consumes the frozen plans.
3. Export selected source mailboxes into local `.eml` files and metadata.
4. Audit the staged export before importing historical mail into the target.
   Export performs this audit automatically unless
   `--no-audit-after-export` is explicitly used.
5. Reconcile required Gmail labels for `migrate` workflows without filters. For
   standalone `import`, reconcile and verify all requested Gmail labels and
   filters at this point, before importing.
6. Import into the target with resume journals.
7. Immediately before optional Workspace alias creation, repeat the Gmail
   reconciliation and verification gate; then create missing aliases only after
   the filters verify and historical import completes.
8. Validate staged identities, routed label membership, and Gmail settings.
9. Verify final Workspace alias ownership when automation is enabled.
10. Review the final report before deciding whether the old server can be
   decommissioned.

Most individual stages remain available. Alias-enabled provider export, import,
and validation use `migrate` so audit, filter, and Directory state stay coupled.
Provider `migrate` orchestrates the auditable stages in one resumable operation;
it does not replace staged artifacts or journals.

Provider mode is for Gmail, iCloud, generic IMAP, and source-target pairs where
the address or provider can change. Legacy mode is for same-address generic IMAP
migrations and DirectAdmin/cPanel provisioning.

## CLI Reference

The main entry point is:

```bash
python3 imapsync_bulk_migrator.py --help
```

Supported modes are `preflight`, `test`, `export`, `audit`, `import`,
`validate`, and provider-only `migrate`.

Default config names are:

- `migration.config.json` for provider `preflight` and `migrate`;
- `export.pass.config.json` for legacy `export`, `test`, and `audit`;
- `import.pass.config.json` for legacy `import` and `validate`.

Common flags include `--config`, `--output-dir`, `--input-dir`,
`--max-workers`, `--ignore-errors`, `--log-dir`, `--min-free-gb`, and
`--imap-timeout`. Provider `preflight` and `migrate` also accept `--dry-run`
and `--report-file`.

The main CLI writes its console log to standard error and also creates a
mode-`0600` file under `--log-dir`. Standard output normally stays clean; the
same is true for routed `preflight` and `migrate`. Those workflows write the
full structured report to its private artifact and log only a concise status
and artifact-path summary to standard error.
Exit codes tell the operator what to do next:

| Code | Meaning | Next action |
| ---: | --- | --- |
| `0` | The requested stage completed successfully. | Continue to the next migration stage. |
| `1` | An unexpected fatal operation error occurred. | Inspect the log and traceback, correct the underlying problem, then rerun the same stage. |
| `2` | CLI, config, dependency, path, or local setup is invalid. | Correct the named input or prerequisite before retrying. |
| `3` | Connectivity/control-panel setup failed, or panel `--ignore-errors` skipped accounts. | Inspect the per-account log first. With `--ignore-errors`, successful accounts may already have been provisioned or imported; fix only the failed accounts and rerun safely. |
| `4` | Preflight, staged audit, integrity gate, or validation found issues. | Stop the migration progression and resolve every reported evidence issue. |
| `130` | The process received a stop signal. | Review the journals/log, then safely rerun the interrupted stage. |

Stop handling is cooperative. An API or IMAP request already in flight may
finish, but after `SIGINT` or `SIGTERM` the workflow checks the stop flag at
each stage and remote-mutation boundary, starts no later work, and never marks
the interrupted migration completed. The CLI exits `130`; inspect the failed
report and resumable journals before rerunning. If cancellation arrives after
a Gmail label/filter or Workspace alias mutation, both the returned and
persisted reports retain the operation's partial result: completed creates,
deletes, or reuses, unresolved entries, and the corresponding rerun action.
Generating that cancellation report is local work and does not start a fresh
remote discovery pass after the stop signal.

`--no-connectivity-test` is intentionally rejected with `--mode test`,
`--mode preflight`, and `--mode migrate`, because connectivity/preflight is a
required part of those modes.

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

Generic IMAP endpoints require encrypted transport. Use implicit TLS with
`"ssl": true, "starttls": false`, or STARTTLS with `"ssl": false,
"starttls": true`. Configs that enable both transports or neither transport
are rejected before authentication.

For provider configs without Workspace alias automation, the individual-stage
command sequence is:

```bash
python3 imapsync_bulk_migrator.py --mode preflight --config migration.config.json --output-dir ./exported
python3 imapsync_bulk_migrator.py --mode export --config migration.config.json --output-dir ./exported
python3 imapsync_bulk_migrator.py --mode import --config migration.config.json --input-dir ./exported
python3 imapsync_bulk_migrator.py --mode validate --config migration.config.json --input-dir ./exported
```

That is the shortest safe sequence because export audits automatically. Use an
explicit `--mode audit` command to re-check an existing staged export.
Standalone `export` does not create or reconcile Gmail labels or filters. The
later standalone `import` takes a fresh Gmail snapshot, reconciles and verifies
the requested configuration, and only then imports historical messages.

The equivalent provider orchestration command is:

```bash
python3 imapsync_bulk_migrator.py --mode migrate --config migration.config.json --output-dir ./exported
```

Use `--dry-run` with `migrate` to execute only discovery, planning, local plan
persistence, and report generation. Routed `preflight` is always this
mutation-free planning workflow, so adding `--dry-run` there is accepted but
does not change its behavior. For routing-disabled `preflight`, explicitly
supplying `--report-file PATH` selects the same read-only reporting workflow and
guarantees that `PATH` is written; no routing, Gmail, or Workspace alias plan is
claimed or created. Dry-run actions name only the report and plan artifacts
that the selected configuration actually emits. `--report-file PATH`
overrides the default `<staging-root>/migration-report.json` path. `PATH` must
be inside the staging root and must not overlap a persisted plan, configured or
discovered account directory, message/metadata subtree, manifest, validation
report, import journal, or any location inside the reserved `.import-locks/`
namespace. Symlinked paths, hard-linked or non-regular targets, and unrelated
existing files are rejected. A valid report from a previous run may be reused
only when it records this exact staging root and report path.
Persisted report bindings use normalized absolute paths, so an equivalent rerun
remains valid after changing the current working directory. CLI-supplied
relative paths retain normal current-working-directory semantics, so use the
staging-root prefix explicitly:

```bash
python3 imapsync_bulk_migrator.py --mode migrate --config migration.config.json --output-dir ./exported --report-file ./exported/reports/migration.json
```

For routing-enabled individual stages, use one staging root consistently:
`preflight` and `export` receive it through `--output-dir`; `audit`, `import`,
and `validate` receive the same directory through `--input-dir`. This is where
the reviewed plans and resumable account artifacts are bound together.
Standalone routed `import` takes a fresh Gmail snapshot, reconciles all
requested labels and future-delivery filters, and verifies the complete Gmail
configuration before it starts provider import. A Gmail conflict or
verification failure therefore leaves the staged provider import untouched.

When `target.workspace_aliases.enabled` is true, use full `migrate` for the
mutating and validation lifecycle. Standalone provider `export`, `import`, and
`validate` return exit code `2` because they cannot safely provide the audited
filter-before-alias ordering and final Directory ownership verification.

Important provider settings:

- `migration.target_mode`: `empty` or `merge`.
- `migration.account_merge_mode`: `one_to_one` or `many_to_one`.
- `migration.folder_map`: source mailbox name to target mailbox name mapping.
- `migration.routing`: strict, opt-in account/folder routing and Gmail filter
  declarations. Absence preserves existing behavior.
- `limits.throttle.max_bytes_per_second`: optional import/export throttling.
- `limits.retry_max_attempts`: bounded retry budget for provider operations and
  Gmail/Workspace API requests.

Provider root, account, auth, migration, limits, and throttle objects are
closed schemas. Any unknown field is rejected with its full configuration path
and the allowed names. Correct misspellings such as `routng`, `target_mod`, or
`limts`; they are never silently ignored.

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

Generic IMAP scans every selectable mailbox. Special-use attributes such as
`\All` and `\Flagged` are advisory rather than proof that a mailbox is purely
virtual: those views are scanned after ordinary mailboxes, byte-identical
occurrences with compatible delivery metadata are folded into already exported
messages, and unmatched occurrences are preserved as separate messages. Use
the exact spelling and case returned by IMAP `LIST` for non-INBOX mailbox names
in `folder_map` and review output; only `INBOX` is case-insensitive by the IMAP
standard. During empty-target resume checks, generic target `\All` and
`\Flagged` views are allowed only for messages already matched by committed
journal rows or recoverable pending rows from the same migration; unmatched
messages still fail the empty-target gate.
A pending row is not production proof by itself: import must resolve it to
committed, and validation must pass before decommissioning.

## Many-To-One Merges

Use `migration.account_merge_mode=many_to_one` to merge multiple source
mailboxes into one target mailbox.

The merge group is keyed by the effective target IMAP login and endpoint. When
several accounts target the same login, imports into that target are serialized
even if `--max-workers` is higher than one. Different target groups are
independent and can run concurrently up to `--max-workers`. In
`target_mode=empty`, unjournaled target content still fails the empty-target
gate.

The importer acquires the target lock and resolves recoverable pending `APPEND`
rows from every source journal in the group before any source begins ordinary
work. It can reuse one physical target message for byte-identical content from
different sources only when the delivery metadata is compatible. Within one
source, repeated copies retain their multiplicity and cannot all consume the
same physical occurrence. Validation groups physical identity by target
mailbox (or Gmail's cross-label physical message) and checks the aggregate
max-per-source capacity: the expected matching occurrence count is the greatest
multiplicity required by any one source, rather than a blind sum of reusable
cross-source copies. Missing or extra matching occurrences fail validation.

For Gmail, duplicate allocation is proven before target mutation. The allocator
reduces compatible destinations to the finite Draft, Sent, Spam, Trash, and
neutral families, preserves fixed journaled Gmail message IDs, and performs a
deterministic one-to-one matching for every source. Custom-label spelling is
retained in the resulting label union but does not create redundant allocator
states. Cancellation is checked throughout this proof. A deterministic
resource-bound failure is reported as an indeterminate allocation proof, not
as an incompatible-destination result. Gmail physical IDs from IMAP, journals,
and recovery baselines are canonical only when they are positive unsigned
64-bit decimal ASCII strings: no zero, sign, whitespace, leading zero, Unicode
digit, integer coercion, or value above `18446744073709551615` is accepted.

Immediately before a Gmail `APPEND`, the pending journal durably records the
set of byte/date-compatible Gmail physical IDs already present. Confirmation
then requires a one-to-one post-APPEND ID absent from that baseline. This is
also the recovery proof after interruption, including an Important/Starred
message temporarily anchored in All Mail before a later source moves the exact
allocated physical message to Spam or Trash. Multiple pending rows are proved
as one matching batch, so nested baselines can disambiguate each other. A
non-empty but non-unique post-APPEND allocation fails closed and is never
retried as another append. Legacy pending rows without this baseline also fail
closed when a temporary All Mail anchor cannot be distinguished safely. This
global proof, committed evidence, capacity check, and empty-target check are all
read-only and run before missing-ID repair. If any current or peer Gmail journal
also has an incomplete crash tail, every byte is retained until those live gates
pass; only then is the tail removed and every stage reloaded and revalidated
before recovery writes.

Hybrid configs are allowed: one target group can merge `a`, `b`, and `c` into
`a`, while `d` and `e` remain one-to-one in the same provider config. Use
per-account target auth in that shape so singleton targets do not reuse the
merge target login by accident.

## Resolved Account and Folder Routing

Resolved routing is opt-in. The complete block lives at
`migration.routing`; it is disabled when absent. If present, it must include
`"enabled": true`. A disabled block may contain only `"enabled": false`.
Consequently, existing `folder_map`, one-to-one, and many-to-one configs keep
their historical behavior until an operator deliberately enables routing.

Routing currently requires every configured account to share one target
mailbox. With more than one account, use
`migration.account_merge_mode: "many_to_one"`, the same `target_email`, and the
same effective target IMAP login for those accounts.
For a Gmail target, endpoint-level target credentials may be shared by that
intentional merge group. Each source account still needs its own effective
source credentials.

### Configuration objects

`migration.routing.accounts` is keyed by a configured source address; unknown
accounts are rejected and matching uses the provider’s address normalization.
Each account object accepts:

- `default_label`: route every otherwise-unassigned folder to one Gmail user
  label. INBOX and other folders all use the same label.
- `default_namespace`: route INBOX to the namespace root and other folders to
  nested labels. For example, `Alias` maps INBOX to `Alias`, Sent to
  `Alias/Sent`, and `Projects.2025` with source delimiter `.` to
  `Alias/Projects/2025`.
- `rules`: account-specific exact-folder or role rules.

An account may omit both defaults, but then every discovered folder needs a
matching rule or the plan is ambiguous. Defaults create `custom_label`
destinations and are therefore Gmail-only.

`migration.routing.global_rules` applies reusable rules across all accounts.
This is the normal place for a shared Junk rule. `migration.routing.filters`
declares future-delivery Gmail filters; it does not affect historical messages.

A routing rule has one `match` member:

```json
{
  "match": {"folder": "Projects.2025"},
  "destinations": [{"type": "custom_label", "name": "Alias/Projects/2025"}]
}
```

or:

```json
{
  "match": {"role": "junk"},
  "destinations": [{"type": "custom_label", "name": "Imported/Junk"}]
}
```

The recognized role names are `inbox`, `sent`, `drafts`, `trash`, `archive`,
and `junk`. SPECIAL-USE attributes take priority over common-name inference.
When no applicable attribute is present, names such as `Sent Items`, `All
Mail`, `Spam`, `INBOX.Spam`, and `Junk E-mail` are recognized using the
discovered hierarchy delimiter. A folder advertising conflicting roles is
ambiguous unless an exact-folder rule resolves it.

Each item in `destinations` is typed:

| `type` | Target | Rules |
| --- | --- | --- |
| `custom_label` | Gmail user label | May be new or an exact existing name; one rule may contain several labels. |
| `gmail_system` | Gmail system location | Use canonical names such as `inbox`, `sent`, `drafts`, `all`, `spam`, or `trash`. System labels are reused, never created. |
| `mailbox` | Non-Gmail IMAP mailbox | Non-Gmail rules must select exactly one mailbox and cannot configure Gmail filters or defaults. |

An override normally suppresses the account default. Add
`"include_default": true` to retain the default destination as well. To omit a
folder, set `"exclude": true` and omit `destinations`; exclusions cannot include
the default.

Several rules may intentionally name the same destination. The plan records
all contributors and treats that as a shared merge, not a collision. Accidental
case-only, type, hierarchy, missing-system, and duplicate-inventory conflicts
still stop the workflow before a target write.

### Exact precedence and deterministic plans

For each discovered source folder, the first matching level wins:

1. account exact-folder rule;
2. account role rule;
3. global exact-folder rule;
4. global role rule;
5. account `default_label` or `default_namespace`.

`INBOX` exact matching is case-insensitive as required by IMAP; every other
exact folder match preserves source spelling and case. Duplicate identical
rules at one level are harmless. Different matching rules at the same level are
reported as ambiguous instead of being ordered implicitly.

The resolved entry shows the source account, exact source folder, delimiter,
attributes, detected role, target destinations, create/reuse state,
contributors to shared destinations, Inbox presence, exclusion state,
assignment source, ambiguities, and warnings. The complete target inventory,
planned filters, label create/reuse lists, conflicts, warnings, and mapping
SHA-256 are stored in the private `routing-plan.json` artifact.

The mapping digest covers the route and filter decisions. Export binds its
state to that digest, and import/validation reload and replay the plan against
the config. If the config or discovered source-folder set changes, the tool
requires a new preflight and review rather than silently rerouting staged mail.
Use a new staging directory when the target, mapping, required label set, or
filter specifications intentionally change; an existing reviewed plan is not
overwritten with a different identity.

Preflight also writes private `gmail-configuration-plan.json`. Its immutable
identity binds the target, routing mapping digest, required user-label names,
and requested filter specifications. Live Gmail label/filter IDs and whether an
item will be created or reused are discovery outcomes, so they remain dynamic
report data rather than weakening that configuration identity.

### Complete generic Gmail routing config

This example sends two independent mailboxes on one old IMAP endpoint into one
non-empty Gmail target. The primary account uses normal Gmail locations. The
secondary mailbox gets an `Alias` namespace, except all Junk goes only to
`Imported/Junk`. The exact `VIP` override demonstrates several labels plus
explicit Inbox and retains the namespaced default with `include_default`. The
filter archives and marks future delivery to the separately provisioned
`alias@example.com` Workspace alias as read. This base migration owns routing,
Gmail labels, and Gmail filters; it does not require Directory API access or
administer the alias.

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

Because `target.workspace_aliases` is absent, this complete config never
constructs a Directory client. Provision `alias@example.com` separately, then
test external delivery before retiring the old mailbox. The Gmail label and
filter remain part of this migration. Top-level `migrate` reconciles them before
export; in the individual-stage workflow, `export` leaves Gmail unchanged and
`import` reconciles them before importing.

All selectable folders considered by the existing provider scan must resolve.
Routing-plan version 2 applies every recorded selectable folder membership to
the message. A message recorded in both `INBOX` and `[Gmail]/All Mail`, for
example, receives the reviewed destinations from both entries. Virtual All
Mail, Starred, Important, and Flagged views are not silently suppressed. Add an
explicit exclusion rule for each such view whose membership should not
contribute. Discovery/export still de-duplicates the physical message payload;
the persisted memberships are unioned when routing that payload.

For a routed generic-IMAP export, each `\All` view is matched one-to-one by exact
content, delivery flags, normalized `INTERNALDATE`, and occurrence multiplicity.
Unmatched occurrences become physical anchors only after that entire selectable
`\All` mailbox has been processed: occurrences in one view cannot collapse into
each other, while a later distinct `\All` view may add membership to those
anchors. Routed Starred and Important views fold only when content and date
identify exactly one unused anchor for that view; ambiguous, unmatched, or
missing-date occurrences remain separate payloads. Flagged keeps its established
folding behavior, and routing-disabled exports keep the legacy behavior. The
preflight storage estimate applies the same rules, so `target.available_bytes`
is checked against the same physical-payload count that export will produce.

Version 1 routing plans used the former virtual-view behavior and are not safe
to reinterpret. A staged root containing a version 1 `routing-plan.json` fails
closed with instructions to run a fresh routing preflight and re-export before
import.

IMAP treats `INBOX` case-insensitively. Discovery that returns more than one
case variant such as `INBOX` and `inbox` for the same source account is rejected
as ambiguous during preflight, before an unexecutable reviewed plan can be
persisted. Other source folder names retain their exact case and are ordered by
the deterministic `(casefold, original)` key in staged routing metadata.

### Custom labels versus Spam and Trash

A `custom_label` named `Imported/Junk` is an ordinary user label. Messages
routed there are also visible in All Mail and do not receive Inbox unless the
same resolved route explicitly includes the `gmail_system` destination
`inbox`.

Do not confuse that with Gmail system `spam` or `trash`. Historical mail in
those system locations may be subject to provider retention or deletion. The
parser rejects either destination unless the acknowledgement is on that exact
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
when acknowledged, the plan displays a warning for every source folder routed
to system Spam or Trash.

### Gmail API authorization

IMAP migration and Gmail REST provisioning are separate authorization
capabilities:

- `target.auth` or `accounts[].target_auth` authorizes Gmail IMAP. It may be
  XOAUTH2 or, where Google still permits it, an app password.
- `target.gmail_api_auth` or `accounts[].target_gmail_api_auth` supplies an
  OAuth bearer token for REST label/filter operations. Its method must be
  `xoauth2`, its username (when set) must match the target mailbox, and it must
  provide exactly one of `password`, `token_file`, or `env_var` as the token
  source.

A dedicated API token takes precedence. If it is omitted, the effective target
XOAUTH2 token is reused, but only succeeds when that token was minted with the
additional API scopes. App passwords never authorize the Gmail REST API.
Every routing config that uses `custom_label`, `default_label`, or
`default_namespace` therefore needs label-management API authorization, even
when it declares no filters. A route containing only `gmail_system`
destinations and exclusions can remain IMAP-only.

Minimum write scopes are split by capability:

- label creation: `https://www.googleapis.com/auth/gmail.labels`, or compatible
  `https://www.googleapis.com/auth/gmail.modify` or
  `https://mail.google.com/`;
- filter creation/deletion: additionally
  `https://www.googleapis.com/auth/gmail.settings.basic`.

A `401` is reported as an invalid or expired access token. A `403` reports the
precise required scope hint. Authorization headers, tokens, API response
bodies, message contents, and user IDs embedded in transport exceptions are
not copied into errors or logs. The tool does not run an interactive OAuth flow
or refresh the preissued Gmail IMAP/API bearer tokens supplied through config.

### Opt-in Google Workspace user aliases

`target.workspace_aliases` optionally makes the non-target source addresses
deliver to the shared Google Workspace target user after migration. It is
separate from Gmail label routing: a Gmail filter labels future mail only after
Google Workspace actually accepts the old address, while a Workspace user
alias makes that address deliver to the target mailbox.

This feature is deliberately opt-in. If `workspace_aliases` is absent, no
Directory client is constructed and the existing routing workflow, artifacts,
and stage order are unchanged. To spell the off state explicitly, use exactly:

```json
{"enabled": false}
```

No other alias settings are accepted while disabled. When enabled, the block
has this contract:

To add automatic alias creation to the generic example above, add this block
inside `target`:

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

With that optional add-on, the tool derives `alias@example.com` from the
non-target source account and creates or reuses it only after the audited
historical import. The base example remains valid without this block.

- `target_user` is required and must be the one shared target Gmail mailbox;
- `from_source_accounts` defaults to `true` and derives every non-target
  `accounts[].source_email`;
- `aliases` adds explicit addresses, and `exclusions` removes addresses from
  the combined set;
- addresses are trimmed, case-folded, converted to non-transitional ASCII IDNA,
  limited to 254 octets in canonical form, de-duplicated, and sorted;
- the target user's own primary address cannot be an alias, and the final set
  cannot be empty;
- `conflict_policy` is required and its only value is `"create_only"`;
- every alias-enabled `migration.routing.filters[].delivered_to` is stored in
  the same case-folded, non-transitional ASCII IDNA form as alias intent;
- two filter spellings that normalize to the same Gmail condition are rejected
  during config validation, before API I/O, and every final alias must have one
  exact normalized filter rule;
- routing-only configurations may retain one configured address spelling in
  the routing artifact, but Gmail execution uses its canonical case-folded,
  ASCII-IDNA condition. Equivalent duplicate spellings are not executable and
  are rejected rather than silently selecting or combining actions.

Alias creation therefore requires a Gmail target, one shared target mailbox,
and enabled routing. Set `account_merge_mode` to `many_to_one` when multiple
sources target that mailbox; a one-account old-to-new migration can use its
normal one-to-one mode. The label/filter config remains the source of truth for
how future messages are presented after delivery.

Read-only preflight inventories the target user's current aliases and checks
each requested address against Workspace users, user aliases, groups and group
aliases, and verified domains. An exact alias already owned by `target_user` is
planned as `reuse`; a free address in a verified primary or secondary domain is
planned as `create`. A Workspace domain-alias domain is automatically managed
and is reuse-only here: a requested address that does not already resolve to
the target is a conflict. Any primary user, group, group alias, or alias owned
by another user is also a hard conflict. All conflicts are resolved before
Gmail, IMAP, or Directory target mutations begin.

The tool never deletes an alias, user, or group, never transfers ownership, and
never converts or replaces a colliding Directory resource. `create_only` is
not a takeover policy. Unrelated aliases already attached to the target user
are retained and are neither included in the requested set nor changed.

#### Directory API authorization and setup

Directory administration has its own `admin_auth`; Gmail IMAP credentials and
`gmail_api_auth` are not reused. Before enabling aliases:

1. Enable the **Admin SDK API** (Directory API) in the Google Cloud project.
2. Ensure every alias domain is verified in the same Workspace customer and
   that every address to create uses a primary or secondary domain. Directory
   domain-alias addresses are generated by Google and are not explicitly
   inserted by this tool.
3. Give the acting administrator the least Workspace privileges needed to
   manage user aliases and read users, groups, and domains.
4. Grant exactly these OAuth scopes:

   - `https://www.googleapis.com/auth/admin.directory.user.alias`
   - `https://www.googleapis.com/auth/admin.directory.user.readonly`
   - `https://www.googleapis.com/auth/admin.directory.group.readonly`
   - `https://www.googleapis.com/auth/admin.directory.domain.readonly`

For service-account domain-wide delegation, create a service account, enable
domain-wide delegation, copy its numeric OAuth client ID, and authorize that
client ID plus the four comma-separated scopes under **Admin console > Security
> Access and data control > API controls > Manage Domain Wide Delegation**.
Then configure the downloaded key and the administrator to impersonate:

```json
{
  "method": "service_account",
  "credentials_file": "secrets/workspace-directory-service-account.json",
  "delegated_admin": "workspace-admin@example.com"
}
```

For this DWD form, `google-auth` mints and refreshes short-lived access tokens
automatically from the service-account credentials and delegated subject.

For a preissued administrator access token, use exactly one non-inline secret
source:

```json
{
  "method": "xoauth2",
  "admin_email": "workspace-admin@example.com",
  "env_var": "WORKSPACE_DIRECTORY_ACCESS_TOKEN"
}
```

`token_file` can replace `env_var`. Inline tokens are rejected, and this tool
does not run an OAuth consent flow or refresh preissued tokens. When a config is
loaded from a file, relative `credentials_file` and `token_file` paths resolve
from the config directory. Keep keys and tokens outside version control,
restrict them to the migration operator, rotate them after use, and never copy
their contents into tickets, logs, or reports.

#### Plans, ordering, failure recovery, and limits

Alias-enabled planning writes private `workspace-alias-plan.json` beside
`routing-plan.json` and `gmail-configuration-plan.json`. It records the frozen
target/candidate identity and the planned create, reuse, and conflict outcomes.
`migration-report.json` exposes `workspace_aliases` planning, provisioning, and
verification sections plus grouped `created`, `reused`, `conflicted`, and
`actions_required` results. Secrets are not included.

Every alias-enabled live `migrate`, whether its aliases are planned as creates
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

Labels and filters are therefore reconciled before export and import for every
configured alias, including aliases that are not yet active. The report records
their `timing` as `"before_export"` and sets
`workspace_aliases.active_alias_filters_ready_before_export` after
verification. `provision_aliases` remains after import: missing aliases are not
activated until the audited historical transfer completes, while aliases
already owned by the target are reused without mutation.

Immediately before `provision_aliases`, the workflow takes a fresh live Gmail
snapshot, reconciles every required label and filter again, and performs a
read-only full verification. Safely missing state is recreated. An incompatible
change, authorization failure, or cancellation fails
`reconcile_gmail_before_aliases` before any Directory alias insertion is
attempted in that run.

Routed `preflight` and `migrate --dry-run` stop after read-only discovery and
private plan/report persistence; they perform no Gmail or Directory mutation.
Early filter verification applies to subsequent delivery only and is not a
claim that Gmail retroactively labeled messages received before verification;
historical staged messages receive resolved labels directly during import.
When aliases are disabled, no Directory API is constructed or called and the
alias-specific stages are absent. A routing-only top-level `migrate` that
requests filters reconciles its Gmail labels and filters before export because
Gmail filters do not apply retroactively to delivery during the migration
window. Standalone `export` performs no Gmail reconciliation; standalone
`import` reconciles and verifies the labels and filters before importing.

If one alias insertion fails, aliases created earlier in that same stage and
all audited historical imports/journals are preserved. Correct authorization,
quota, domain, or propagation issues and rerun with the same staging directory:
completed aliases and filters are reused, and committed message journals avoid
another append. An unsuccessful run does not roll back by deleting aliases.

Google Workspace permits up to 30 added email aliases per user. Plan with room
for aliases managed outside this tool. Google also warns that alias additions
can take up to 24 hours to propagate. Final verification proves that the
Directory API reports the alias on the intended user; it cannot prove immediate
Internet mail delivery. Test representative external delivery before MX
cutover or source retirement.

### Mutation-free preflight

Routing preflight reads every configured source’s retained selectable folders,
delimiter, and SPECIAL-USE attributes. It reads the target IMAP inventory and,
for Gmail, combines that with the API label inventory so user/system types and
internal IDs are known without asking the operator to copy IDs into config.
It also reads existing filters to classify requested filters.
When Workspace aliases are enabled, it additionally reads the target user,
aliases, possible user/group collisions, and domain verification state.

Preflight performs no remote `CREATE`, `APPEND`, `STORE`, label POST, filter
POST/DELETE, or Directory alias POST. It reports:

- all discovered source folders and target labels;
- automatic defaults and explicit assignments;
- shared contributors and exclusions;
- labels that would be created or exactly reused;
- filters that would be created or reused;
- Workspace aliases that would be created or reused and every ownership,
  group, user, domain, or limit conflict;
- incompatible same-condition filters;
- ambiguous folders and target hierarchy/name conflicts;
- explicit unsafe-system warnings.

The local `routing-plan.json`, `gmail-configuration-plan.json`, and conditional
`workspace-alias-plan.json` files are review evidence, not remote mutations. A
plan with conflicts or ambiguities is not executable.

The two equivalent planning invocations are:

```bash
python3 imapsync_bulk_migrator.py --mode preflight --config migration.config.json --output-dir ./exported
python3 imapsync_bulk_migrator.py --mode migrate --dry-run --config migration.config.json --output-dir ./exported
```

Both write the applicable private plans and a planned
`migration-report.json`, log the status and artifact paths to standard error,
leave standard output clean, and stop before export, Gmail/Directory writes,
or import.

### Label and filter reconciliation

Required user labels are reconciled before filters. Exact-name user labels are
reused, so an existing `MailB` is not duplicated. Case-only matches, duplicate
resources, system-name conflicts, or inconsistent hierarchy casing fail before
the first Gmail write. Created labels are re-listed and verified.

Timing depends on the command. Top-level `migrate` performs this reconciliation
before export when filters are configured. Standalone `export` performs no
Gmail writes, while standalone `import` reconciles and verifies the complete
Gmail configuration before provider import begins.

Each configured filter uses the generated query
`deliveredto:<configured-address>`, not only the visible `To` header. Filter
fields are:

- `label`: required user label;
- `inbox: "keep"`: apply the label without removing Inbox;
- `inbox: "archive"`: apply the label and remove `INBOX`;
- `mark_read: true`: additionally remove `UNREAD`;
- `conflict_policy: "error"` (default): reuse one equivalent filter, but report
  duplicate or incompatible same-condition filters without changing them;
- `conflict_policy: "replace"`: explicitly delete incompatible
  same-condition filters and create or retain exactly one equivalent result.

Replacement is the only filter path that deletes anything, and it affects only
filters with the same canonical condition. Unrelated labels, filters, mailbox
settings, and messages are not altered. Labels and filters are re-listed after
reconciliation and must verify exactly. Gmail’s filter-count limit is checked
before mutation.

Historical messages receive resolved labels directly during import; Gmail
filters are not expected to apply retroactively. When strong content identity
finds a message already present in the merge target, import reuses that Gmail
message but applies every missing routed label with additive label operations.
Existing unrelated labels stay attached. A committed journal entry is not
considered route-complete until its plan digest and required custom/system
memberships match.

Content-first reuse also preserves the already-existing target message's
`INTERNALDATE`; it cannot retroactively replace that date with the staged source
date. When those dates differ, validation remains successful but emits an
`existing-target-internaldate-differs` warning containing the canonical
identity, mailbox, source and target dates, and
`existing-content-reuse` provenance. The journal records
`source_internaldate`, `target_internaldate`,
`internaldate_provenance: "existing-content-reuse"`, and
`internaldate_origin_action: "existing"`. Treat the warning as an explicit
record that the source date metadata was not preserved and no duplicate was
appended.

### MailA acceptance result

The complete five-account config is in the
[MailA through MailE README example](../README.md#maila-through-maile-example).
With a non-empty target that already has `MailB`, its reviewed plan proves:

| Source | Historical destination |
| --- | --- |
| `mailA@example.com` Inbox/Sent/Drafts/Archive | Configured Gmail system locations |
| `mailB@example.com` INBOX | Existing `MailB` label |
| `mailC@example.com` INBOX | New `MailC` label |
| `mailD@example.com` INBOX | New `MailD` label |
| `mailE@example.com` INBOX | New `MailE` label |
| Any detected/configured Junk or Spam folder | One new shared `Imported/Junk` label only |

The base example assumes `mailB@example.com` through `mailE@example.com` are
provisioned separately as aliases of `mailA@example.com`. It makes no Directory
API calls and performs no Workspace ownership discovery. The four corresponding
`deliveredto:` filters are provisioned and verified before export by the
documented top-level `migrate` command. With individual stages, standalone
`export` does not change Gmail and standalone `import` provisions and verifies
the filters before importing. After external alias provisioning, test
representative delivery before retiring the old mailboxes.

If the optional `target.workspace_aliases` add-on is enabled, Workspace
discovery instead plans aliases already owned by MailA as reused and free
addresses as creates. Any address resolving to a user, group, or different alias
owner stops that alias-enabled run before target mutation.

Because the global Junk role rule outranks account defaults and does not set
`include_default`, no `MailB/Junk`, `MailC/Spam`, `MailD/Junk`, or `MailE/Junk`
label is requested. Four future-delivery filters use
`deliveredto:mailB@example.com` through `deliveredto:mailE@example.com` and
apply the corresponding root label. An identical historical message found in
two sources may remain one Gmail message, but it receives both required source
labels.

Run preflight first, review `routing-plan.json` and
`gmail-configuration-plan.json`, then use the resumable `migrate` workflow:

```bash
python3 imapsync_bulk_migrator.py --mode preflight --config migration.config.json --output-dir ./exported
python3 imapsync_bulk_migrator.py --mode migrate --config migration.config.json --output-dir ./exported
```

Because the base config leaves Workspace alias automation disabled, the
individual `export`, `audit`, `import`, and `validate` modes also remain
available. Enabling the optional add-on adds `workspace-alias-plan.json` and
requires the coupled `migrate` command for export, import, and validation so its
filter-before-alias ordering and final Directory verification cannot be
bypassed.

Base reruns reuse completed message journal entries, exact labels, and
equivalent filters. In top-level `migrate`, an initial filter authorization
failure stops before export; in standalone `import`, it stops before provider
import and leaves the staged export untouched. After fixing the OAuth scope,
rerun against the same staging directory. Audited mail and import journals
remain valid, and no message is appended again. In optional alias-enabled mode,
aliases already owned by MailA are also reused and alias failures remain
resumable. The final `migration-report.json` always groups
source-account/folder counts, resolved labels, created/reused labels and
filters, duplicate label additions, shared merges, failures/skips, validation,
conflicts, and remaining operator actions. It adds Workspace alias create,
reuse, conflict, and verification results only when that add-on is enabled.

Provider provenance counts are present per folder, per source account, and in
`totals`. `imported_source_records` (also exposed as
`appended_source_records`) counts source manifest records whose earliest valid
committed origin is an APPEND. `matched_existing_source_records` counts source
manifest records whose committed origin reused a target message, including an
existing match that needed no later `STORE`. These source-record counts may
refer to the same Gmail physical message in a many-to-one migration.
`appended_gmail_physical_messages` therefore separately de-duplicates the
appended origins by target merge group plus Gmail message ID. Gmail IDs are
mailbox-scoped: equal raw IDs in two distinct target mailboxes count as two
physical messages, while equal IDs contributed by sources sharing one merge
target count once. `appended_gmail_physical_message_ids` lists the raw IDs in
deterministic target order (so duplicates across targets are possible), and
`appended_gmail_physical_message_refs` provides unambiguous `target_account`
plus `target_gmail_msgid` pairs.
Every committed per-message report record also includes its
`target_gmail_msgid`, including a matched-existing record that needed no
`STORE`. Top-level `gmail_physical_messages` groups those records by target
merge group and physical ID, names the `target_account`, and lists the
contributing source account/canonical IDs. Each contributor's stable earliest
current-plan, membership-complete `appended` or `existing` origin is reported;
foreign-plan and incomplete commits cannot change provenance. Each group also
includes the union of required custom and system destinations and the labels
actually added by this migration.
`totals.gmail_physical_messages` counts those groups and
`totals.gmail_physical_message_merges` counts groups with more than one source
record. These records intentionally contain only migration requirements and
changes; unrelated pre-existing Gmail labels are not copied into the report.

## Legacy Generic IMAP Mode

Use legacy mode for straightforward same-address migrations:

```bash
python3 imapsync_bulk_migrator.py --mode export --config export.pass.config.json --output-dir ./exported
python3 imapsync_bulk_migrator.py --mode import --config import.pass.config.json --input-dir ./exported
python3 imapsync_bulk_migrator.py --mode validate --config import.pass.config.json --input-dir ./exported
```

Legacy export runs its staged audit automatically. Use `--mode audit` when
rechecking an existing export rather than repeating it after every successful
export.

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

An active legacy `server` follows the same transport rule as generic provider
endpoints: enable implicit TLS or STARTTLS. A historical `source_server`
descriptor may remain cleartext so old staged exports can still be bound and
audited offline, but any attempt to connect to it is rejected before
authentication.

## Artifacts and Resume Data

Provider exports write per-account staged data including:

- `manifest.jsonl`;
- `export-state.json`;
- `source-summary.json`;
- `messages/` payloads;
- `metadata/` sidecars;
- target import journals and validation reports after later stages.

When resolved routing is enabled, the staged root also contains the reviewed
`routing-plan.json` and `gmail-configuration-plan.json`; opt-in Workspace alias
creation adds `workspace-alias-plan.json`. Each account export state and routed
journal membership is bound to the routing mapping digest. A completed
`migrate` workflow writes the aggregate `migration-report.json` at the staged
root. These files use the same private/atomic safeguards as other provider
state.

One private, crash-releasing workflow lock serializes provider planning,
Gmail/Workspace mutation, export, import, and final reporting for a staging
root. Standalone provider export, import, validate, and audit take the same root
lock. Import, validate, and audit acquire it before reading staged account
state, and import and validate perform their staged-data gate and target
connectivity checks while holding it. Export acquires the lock before loading
frozen plans and holds it through its optional audit. Per-target import locks
remain narrower, so separate target accounts can still use their own journal
serialization. Lock files persist under `.import-locks/` after completion and
are reused; do not
delete or replace them while a command is active. The entire `.import-locks/`
namespace is reserved and cannot be chosen as a migration-report destination.

The CLI logs each structured workflow issue and report-write diagnostic
individually. It redacts Authorization/Bearer credentials, passwords, secrets,
API keys, and token names including `oauth_token`, `authorization_token`, and
`api_token` case-insensitively in both plain and URL-encoded forms. It announces
a migration report as an artifact only when the exact payload is currently
visible. The returned `report_persisted` flag means verified current visibility,
not guaranteed crash durability.

Successful terminal reporting has an explicit commit boundary. The workflow
first atomically publishes a non-success `status=finalizing` payload containing
a unique `terminal_commit_id`, the intended success specification digest, and
`terminal_committed=false`. Its final check that the marker still belongs to
this commit and that cancellation has not been requested runs immediately
before the atomic success replacement. That check is the linearization point:
a stop it observes publishes failure and the CLI exits 130, while a signal that
arrives afterward may lose to the replacement and return 0. The replacement
uses the same ID and digest with the intended `planned` or `completed` status
and `terminal_committed=true`; a later signal cannot rewrite that committed
success as cancellation.

If the success write raises after an uncertain rename or directory sync, the
workflow safely reads the current JSON and treats success as committed only if
the entire intended payload, commit ID, specification digest, and status match.
It then returns committed success with a sanitized
`report_durability_uncertain` warning; `report_persisted=true` records exact
current visibility even though crash durability is unknown. It does not rewrite
the committed JSON to add that warning. Otherwise it returns failure and leaves
the current path untouched. Terminal reporting never deletes, renames,
quarantines, or truncates an uncertain report path.

The root workflow lock prevents cooperating commands from writing concurrently.
It does not defend the report path against arbitrary out-of-band changes by a
different process running as the same EUID; such mutation is outside the trust
boundary. Do not alter the report path while a workflow command is active.
Restore writable storage and rerun when the returned result reports a write
failure.

Legacy exports write per-account directories under `exported/<account>/`, with
mailbox folders, `.eml` files, sidecar metadata, `.mailbox.json`,
`export-state.json`, and `import.journal.jsonl` after import.

Resume and validation depend on these files. Do not hand-edit staged exports
except for forensic inspection on a copy. A routing-enabled import without a
valid current plan fails clearly. Older exports remain usable for legacy
routing, but must be re-exported when they lack complete source-folder metadata
needed to guarantee the new routed memberships.

## DirectAdmin and cPanel

DirectAdmin and cPanel integration is available for legacy generic IMAP imports.
Provider configs do not call hosting panel APIs.

Every configured account must be in `local@domain` form. Panel workflows fail
fast for malformed accounts.

Remote panel base URLs must use HTTPS. Plain HTTP is accepted only with a
literal loopback address such as `http://127.0.0.1:2222`, for a client running
on the panel host itself. `--da-no-verify-ssl` and `--cpanel-no-verify-ssl` may
be used for a controlled self-signed certificate; prefer installing the correct
CA certificate whenever possible.

Before a non-dry-run create or reset, every configured mailbox must have a
non-empty `accounts[].password`. This is validated before panel API changes and
before a reset archives any import journal, so an empty placeholder cannot
leave a mailbox deleted. Read-only indexers may generate empty password
placeholders; fill them in the import config before the real panel run. Panel
dry-run remains available while passwords are still placeholders.

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
- For each account, stale journals are archived and the panel reset runs under
  the same per-effective-user target lock as the subsequent import. That lock
  is shared across staging roots, so concurrent operations wait for the
  sequence to finish.
- An interrupted destructive reset leaves both `reset-state.json` in the
  staged account directory and an authoritative global reset gate. The gate
  binds the reset to its owner staging root and target configuration. Only
  that root may resume with the same configuration and `--reset`;
  target-facing work from another root fails closed. State is cleared only
  after the reset callback succeeds.
- Legacy export, ordinary panel ensure, target connectivity (including
  `--mode test`), import, validation target checks, and remote audit against
  that target check the gate under the same per-account target lock before
  target-facing work.
- The locked import authenticates the recreated mailbox immediately after
  reset; no separate target connectivity pass runs before destructive reset.
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
- routing plan/config digest agreement and complete source-folder assignment;
- required routed custom/system label membership on both appended and reused
  Gmail messages;
- Workspace alias plan/config identity and final ownership when automatic
  aliases are enabled;
- many-to-one merge group boundaries.

For an end-to-end routed migration, the aggregate report also includes Gmail
label/filter and optional Workspace alias reconciliation and verification. A
successful message validation alone does not hide an unresolved filter/alias
conflict or an operator action still required in `migration-report.json`.

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

Use the same file/environment guidance for `gmail_api_auth` and
`target_gmail_api_auth`. These values are bearer tokens even though the generic
auth object also accepts the legacy field name `password`; never commit or log
them.

Apply stricter handling to `workspace_aliases.admin_auth` as well. Preissued
tokens are accepted only through `token_file` or `env_var`; service-account DWD
uses `credentials_file`. Never commit the key JSON, grant broader scopes than
listed above, share it with another workload, or leave the delegated
authorization active after it is no longer needed.

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
- Workspace alias automation requires Admin SDK Directory API setup and
  separate administrator authorization. It does not create, delete, rename, or
  take over users, groups, domains, or aliases owned by another user.
- Workspace permits at most 30 added aliases per user, requires a new explicit
  alias to use a verified primary or secondary domain in the same customer,
  and can take up to 24 hours to propagate an alias change.
- Normal Gmail IMAP cannot prove that users disabled folder-size limits or label
  hiding.
- Gmail app passwords are a personal-account fallback where Google still allows
  them; they require 2-Step Verification and may be unavailable for Workspace,
  security-key-only, or Advanced Protection accounts.
- Gmail IMAP has documented transfer limits. Gmail-target imports may require
  throttling or batching even when the operator accepts the IMAP copy route.
- Interactive OAuth acquisition remains external, as does refresh of preissued
  Gmail or Workspace administrator bearer tokens. Workspace alias
  service-account DWD instead mints and refreshes its short-lived access tokens
  automatically through `google-auth`.
- Gmail label/filter routing in one provider config currently requires one
  shared target Gmail mailbox.
- Gmail API label/filter provisioning requires a bearer token with the scopes
  described above; an IMAP app password is insufficient.
- iCloud requires app-specific passwords and Apple Account two-factor
  authentication.
- IMAP UIDs are not preserved.
- Provider imports preserve portable flags where the target supports them.
  Unsupported IMAP keywords can stop an import before append, and Gmail targets
  do not preserve `\Deleted` as an appended message flag.
- Provider staged exports created by older versions may need to be rerun if they
  lack current account, endpoint, manifest, journal, source-folder, or routing
  plan bindings required by the selected workflow.
- Legacy staged exports created by older versions may need to be rerun if they
  lack `source_server`, `source_server_sha256`, or per-message integrity
  metadata.
- DirectAdmin/cPanel reset deletes target mailbox contents. Keep independent
  backups before destructive operations.

## Official Behavior References

- IMAP4rev2 protocol and `INTERNALDATE` semantics: https://www.rfc-editor.org/rfc/rfc9051.html
- TLS for email access: https://www.rfc-editor.org/rfc/rfc8314.html
- IMAP special-use mailboxes: https://www.rfc-editor.org/rfc/rfc6154.html
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
- Google Workspace password-only access changes: https://workspaceupdates.googleblog.com/2023/09/winding-down-google-sync-and-less-secure-apps-support.html
- Google Workspace IMAP data import: https://knowledge.workspace.google.com/admin/migrate/migrate-email-from-an-imap-account
- Google Workspace data import overview: https://knowledge.workspace.google.com/admin/migrate/about-the-new-data-migration-service
- Admin SDK Directory API Python setup and API enablement: https://developers.google.com/workspace/admin/directory/v1/quickstart/python
- Directory API authorization scopes: https://developers.google.com/workspace/admin/directory/v1/guides/authorizing
- Google Workspace credentials and domain-wide delegation: https://developers.google.com/workspace/guides/create-credentials
- Directory API user alias management: https://developers.google.com/workspace/admin/directory/v1/guides/manage-user-aliases
- Google Workspace user alias limits and propagation: https://support.google.com/a/answer/33327
- Gmail bandwidth limits: https://support.google.com/a/answer/1071518
- iCloud Mail settings: https://support.apple.com/en-us/102525
- Apple app-specific passwords: https://support.apple.com/en-us/102654
- DirectAdmin legacy API: https://docs.directadmin.com/developer/api/legacy-api.html
- cPanel UAPI tokens: https://api.docs.cpanel.net/cpanel/tokens/
- cPanel UAPI email operations: https://api.docs.cpanel.net/specifications/cpanel.openapi/email-accounts/
- Roundcube project: https://roundcube.net/
