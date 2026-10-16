# simlessly-cli

Command-line client for the Simlessly RSP API (eSIM profiles and activation codes). Python 3.11 or newer, standard
library only, on macOS, Linux and Windows.

Independent project. Not affiliated with or endorsed by Simlessly.

## Install

```sh
uv tool install .                                 # or: pipx install .
PYTHONPATH=src python3 -m simlessly_cli --help    # or run from a checkout
```

## Credentials

The RSP API commands need an AccessKey and a SecretKey from the Simlessly web portal. Each setting comes from the
first source that has it: command-line flag (`--base-url` only), environment variable, OS secret store (macOS
Keychain, or Linux Secret Service through `secret-tool`), credentials file.

| Setting | Environment variable | Stored name | Required |
| --- | --- | --- | --- |
| access key | `SIMLESSLY_ACCESS_KEY` | `access-key` | yes |
| secret key | `SIMLESSLY_SECRET_KEY` | `secret-key` | yes |
| default profile configuration | `SIMLESSLY_CONFIG_NAME` | `config-name` | no |
| base URL | `SIMLESSLY_BASE_URL` | `base-url` | no (default `https://rsp.simlessly.com`) |
| portal session token | `SIMLESSLY_PORTAL_TOKEN` | `portal-token` | only for `portal` commands |

The stored name is the Keychain account, the Secret Service `setting` attribute and the credentials file key. The
service name is `simlessly-cli`.

The credentials file is `$SIMLESSLY_CREDENTIALS_FILE`, else `$XDG_CONFIG_HOME/simlessly-cli/credentials`, else
`~/.config/simlessly-cli/credentials`. It is an INI file with a `[default]` section. On POSIX systems it is
refused if group or others can access it or another user owns it (`chmod 600`). A refused file is an error for the
keys and a warning for the optional settings.

`SIMLESSLY_NO_KEYCHAIN=1` skips the OS secret store. `SIMLESSLY_NO_CREDENTIALS_FILE=1` skips the file.

### config commands

```sh
simlessly config check                 # where each setting comes from; never prints values
simlessly config set access-key        # hidden prompt
simlessly config set secret-key --store file
printf '%s\n' example-config | simlessly config set config-name --from-stdin
simlessly config unset config-name
```

`config set` never takes the value as an argument. `--store` is `auto`, `keychain`, `secret-service` or `file`.
`auto` picks the Keychain on macOS, Secret Service on Linux when `secret-tool` can reach a keyring, and the file
otherwise. The file is written atomically with mode 0600. Windows has no OS store. If a higher-priority source
already has the setting, `config set` says which.

SIM keys for `ac generate` are not stored. Use `SIMLESSLY_SIM_KI` and `SIMLESSLY_SIM_OPC`, or the hidden prompt.

## Commands

Global options, accepted before or after the command: `--json`, `--timeout SECONDS` (0.1 to 120, default 20),
`--base-url URL`, `--debug` (requests and answers on stderr, secrets redacted), `--version`. Examples use
fabricated values.

### RSP API

| Command | Purpose | Changes state |
| --- | --- | --- |
| `configs list [--name TEXT] [--page N] [--page-size N]` | List profile configuration names | no |
| `profile show ICCID [--reveal-ac]` | Profile detail and status meaning | no |
| `profile log ICCID [--page N] [--page-size N]` | Profile event history | no |
| `batch result BATCH_ID` | Result of a batch generation task | no |
| `ac generate --config NAME --iccid ICCID --imsi IMSI [--ki KI] [--opc OPC] [--msisdn N] [--no-ac-link] [--reveal-ac]` | Create a profile and activation code | yes |
| `profile expire ICCID` | Invalidate the current activation code | yes |
| `profile delete ICCID` | Delete the profile from the platform | yes |
| `order cancel ICCID` | Reissue step 1: cancel the order | yes |
| `order download ICCID [--config NAME]` | Reissue step 2: create a download order | yes |
| `order confirm ICCID [--reveal-ac]` | Reissue step 3: confirm and receive a new code | yes |

`--config` defaults to `SIMLESSLY_CONFIG_NAME`. `configs list` is a safe first check of the credentials.
`--page` takes 1 to 10000 and `--page-size` 1 to 1000.

`profile log` ends with a line saying whether the page has a `DELETED` event without a failure reason, the only
evidence that a profile left a phone. It warns when other on-phone events may be newer.

Reissue a code in three steps, checking the state in between:

```sh
simlessly profile show 8900000000000000001               # needs AVAILABLE or ERROR
simlessly order cancel 8900000000000000001 --yes
simlessly order download 8900000000000000001 --config example-config --yes
simlessly order confirm 8900000000000000001 --yes --reveal-ac
```

### Portal

`portal` commands use the web portal's session API, which is not part of the documented OPEN API and can change
without notice. They authenticate with a session token instead of the keys and cover what the RSP API lacks, such
as listing all profiles.

```sh
simlessly portal login --email you@example.com        # password at a hidden prompt, or --password-stdin
simlessly portal token-set                            # paste the simlessly_token cookie (SSO accounts)
simlessly portal logout
```

`login` sends the e-mail and the MD5 hex digest of the password, as the web form does. The password is never read
from arguments or the environment. The token is stored like the other secrets (`--store`, setting `portal-token`).
An expired session exits 1 with a message to log in again.

Read commands:

| Command | Purpose |
| --- | --- |
| `fleet` | List profiles. Filters: `--config --status --iccid --msisdn --since --until`. Output: `--csv FILE`, `--reveal-ac` |
| `logs` | Profile event log. Filters: `--iccid --status --since --until` |
| `profile ICCID`, `log-detail LOG_ID` | One profile (status, notes, group, recycle state, timeline); device details of a `logs` row |
| `batch-logs`, `recycle-logs`, `recycle-status ICCID...` | Batch tasks; recycle log and state |
| `campaigns`, `campaign-profiles ID` | Campaigns and their profiles |
| `groups`, `configs`, `config ID`, `blocks`, `eid-pushes`, `enums` | Groups, configurations, blocked EIDs, EID pushes, enum values |
| `stats`, `downloads`, `redownloads`, `report` | Dashboard numbers, download trends, daily report per configuration |
| `subscription`, `plans`, `orders`, `order ID`, `account` | Plan, allowance, prices, orders, account |
| `summary` | Profile counts by status and configuration (walks every page) |
| `qr ICCID --out FILE --reveal-ac` | Write the QR code as a PNG with mode 0600; never to stdout |

Other filters: `batch-logs --type --process --format`, `recycle-logs --order-id`, `campaign-profiles --eid`, `blocks --eid`,
`downloads --by`, `report --date --status`, `summary --include-demo`.

Paged lists take `--page`, `--page-size` (1 to 200) and `--all`. `--all` pauses 0.5 s between pages and stops
after 100 pages. With `--json` it reports `complete`, `truncated` and `stopReason`; `--strict` exits 1 when the
list is known to be incomplete. `--since` and `--until` take `YYYY-MM-DD` (local time) or an ISO-8601 time.
Example: `simlessly portal fleet --status DELETED --since 2026-10-01 --all --csv fleet.csv`

State-changing commands:

| Command | Effect | Billable |
| --- | --- | --- |
| `notes ICCID TEXT` or `--clear` | Set the note (up to 100 characters) | no |
| `group-assign ICCID --group NAME_OR_ID` | Put a profile in a group | no |
| `group-create NAME [--note TEXT]` | Create a group | no |
| `regenerate ICCID [--picture] [--expire-time 'YYYY/MM/DD HH:MM:SS'] [--force]` | Issue a new activation code | yes |
| `recycle ICCID --at 'YYYY/MM/DD HH' [--force]` | Set when the recycle applet removes the profile from its phone | no |
| `delete ICCID [--force]` | Delete the profile from the platform; it stays on any device | no |
| `generate-ac --config NAME_OR_ID --file FILE --upload-type pgp\|plain [--picture] [--ac-link]` | Create profiles from a `.gpg`, `.xls` or `.xlsx` file | yes |

One ICCID per call; there are no batch operations. Prefer `--upload-type pgp`: `plain` sends SIM keys to Simlessly
without the PGP layer.

`delete`, `regenerate` and `recycle` first read the profile's status and recycle state:

- `delete` and `regenerate` proceed only when the status is `AVAILABLE`, `DELETED` or `ERROR` (`delete` also
  accepts `EXPIRED`, `CANCELED` and `REMOVED`) and the recycle state is `RECYCLED` or `INVALID`. Anything else,
  including an unrecognised or missing value, exits 1 unless `--force` is given, also in a dry run.
- `recycle` requires the recycle state `AWAITING` and a status other than `AVAILABLE`.
- Demo profiles are always refused, and so are campaign and pre-occupied profiles for `delete` and `regenerate`,
  even with `--force`.

## Safety

- Without `--yes`, a state-changing command prints the request it would send, secrets redacted, and sends nothing
  (exit 2). Portal dry runs still make read-only lookups. `--yes` must be spelled in full.
- The preview lists the action, the cost, the target or inputs, the effect and the request (method and URL), then
  notes and the next step. Secret values show as `[redacted]`. `--debug` adds the request headers and, for a file
  upload, the raw form fields. Long lines wrap to the terminal width (`COLUMNS` overrides it). Bold labels and a
  highlighted `BILLABLE`, `CAUTION`, `FORCED`, `WARNING` or `OUTCOME UNKNOWN` appear only on a terminal and not
  when `NO_COLOR` is set. `--json` keeps the same fields.
- With `--yes` the request is sent once. There are no retries. Commands that may use a download credit say so in
  the preview. `profile delete` never sends `force: true`.
- If the outcome is unknown (timeout, dropped connection, 5xx, unreadable answer), the command exits 3. Check the
  profile with `profile show` or `portal profile` before sending again.

| Exit code | Meaning |
| --- | --- |
| 0 | success |
| 1 | failure: bad settings, HTTP or connection error, request refused by Simlessly, guard refusal |
| 2 | usage error or dry run |
| 3 | outcome unknown after a state-changing request |

Example preview (fabricated values):

```
$ simlessly profile delete 8999000000000000001
Dry run — nothing has been sent.

Action   Delete profile 8999000000000000001 from the Simlessly platform.
Cost     no charge documented
Target   ICCID 8999000000000000001
Effect   removes the profile and its activation code from the Simlessly platform (status REMOVED)
Request  POST https://rsp.simlessly.com/api/v1/profile/delete
Body     {"iccid":"8999000000000000001","force":false}

Notes
  - Platform-side only; do not delete while the line is still enabled or disabled on a device. The
    documented 'force' option is never set to true.

To send:  add --yes
Then:     simlessly profile show 8999000000000000001
```

With `--yes` the output starts with `Sent.` and what happened, then any result, the request and the next step.
A refused request prints `Refused. Nothing was sent.` followed by the action and the reasons.

## Output and masking

Tables by default; `--json` prints masked JSON.

- Values named `ki`, `opc`, PINs, `secret`, `password`, `token` and similar print as `[redacted]`.
- Activation codes, QR links, EIDs and IMSIs print only their last four characters, in tables, `--json`, CSV and
  error text.
- `--reveal-ac` prints activation codes in full; `--yes` does not imply it. In `portal` commands it reveals only
  activation-code fields. The RSP API commands also show EIDs and IMSIs unmasked.
- `--debug` redacts the `AccessKey`, `Signature` and `Simlessly-Token` headers and the same body fields.

## Profile status

`profile show` prints the status with a one-line meaning.

| Status | Meaning |
| --- | --- |
| `AVAILABLE` | Ready to download. Also set after a new code is issued or the profile is deleted from the phone. |
| `DOWNLOADED` | Downloaded to the device, not yet installed |
| `INSTALLED` | Installed, not yet enabled |
| `ENABLED` | Installed and active |
| `DISABLED` | Installed but inactive |
| `DELETED` | Removed from the device. The only status the phone reports itself. |
| `REMOVED` | Deleted on the platform |
| `EXPIRED` | Activation code invalidated |
| `CANCELED` | Order cancelled |
| `ERROR` | Download or install failed. See `profile log`. |

`AVAILABLE`, `EXPIRED`, `CANCELED` and `REMOVED` are platform records. They do not prove that an eSIM left a
device.

## Request signing

RSP API requests are POSTs with a JSON body and the headers `AccessKey`, `Timestamp` (epoch milliseconds),
`RequestID` (new UUID per request) and `Signature`:

```
Signature = HMAC-SHA256(key = SecretKey, message = Timestamp + RequestID + AccessKey + RequestBody), hex, uppercase
```

The body is serialized once as compact JSON, and that exact text is signed and sent. The signature does not cover
the URL, so the client accepts only `https://rsp.simlessly.com` (or `http://127.0.0.1`, `localhost`, `[::1]` for
tests) and calls only ten fixed paths. Redirects are refused; responses over 1 MiB are rejected.

## API change watch

A GitHub Actions workflow (`.github/workflows/api-watch.yml`) checks the web portal once a week (Mondays, 14:00 UTC,
and on demand from the Actions tab). `tools/api_watch.py` reads the portal's public front-end files at
`rsp.simlessly.com`, the same JavaScript every visitor downloads to see the login page, and compares them with the
committed snapshot `api-snapshot/portal.json`: every `/api/` path the front-end calls, with its HTTP method, how the
request is sent (JSON body, query string, file upload) and the page module that uses it. The request helpers are
identified by what they do (setting `params` is a GET, setting `data` is a POST, a `FormData` body is an upload), not by
their minified names. A name that is defined as two different kinds of helper is not trusted: calls through it are left
unclassified. The page module is context only; a front-end rebuild that moves a path to another chunk is not a change.

Only static files are fetched. No `/api/` endpoint is called and nothing is signed in. The API documentation is not
read by the workflow and is not stored in the repository.

If anything changed, the workflow runs the unit tests and opens or updates one pull request (branch `api-watch/update`)
with the new snapshot and a report of the differences. The pull request is a draft when the tests fail. If the files
cannot be read or their structure is not recognized, the run fails and no pull request is made. A snapshot is also
refused when it looks like a misreading: far fewer paths, many paths without a known method, a path the CLI uses that
cannot be classified, or more than five methods (or 10%) changing at once.

Applied automatically: the HTTP method of a portal path in the read group of `src/simlessly_cli/portal_endpoints.json`,
when the portal now uses another method. Nothing else in the code changes, so the commands that use that path still
build their request for the previous method (JSON body or query string). Expect the tests to fail, and the pull request
to stay a draft, until the command is adapted by hand.

Needs manual follow-up, listed in the pull request: method changes in the session and write groups (the login must stay
a POST, and the CLI refuses to load a write path that is not), new portal paths (never added to the allowlist),
allowlisted paths that disappeared, and changes in how a request is sent. Only a person adds a path or moves it between
the session, read and write groups.

The workflow does not store its token in the git configuration; only the last steps receive it. It never overwrites commits
that a person pushed to `api-watch/update` (it then only refreshes the pull request text), pushes with a lease, marks the
pull request as a draft again when the tests fail, and closes the pull request when a later run finds nothing to change.

Run it locally:

```sh
python3 tools/api_watch.py snapshot --out /tmp/api-new     # --force skips the sanity checks
python3 tools/api_watch.py diff --new /tmp/api-new --report report.md
python3 tools/api_watch.py apply --new /tmp/api-new --report report.md
cp /tmp/api-new/portal.json api-snapshot/
```

`diff` without `--new` fetches the live files itself. In the repository settings, Actions must be allowed to create pull
requests (Settings, Actions, General, Workflow permissions). GitHub pauses scheduled workflows after 60 days without
repository activity.

### Documentation check (local)

The API documentation at `docs.simlessly.com` is for signed-in customers, so it is checked on your own machine and never
committed. `docs-check` needs a stored portal session (`simlessly portal login`). It first checks the session the way the
documentation site does (one `POST /api/v1/plan/queryOrder`), and only then fetches the documentation pages, sending the
session as the `simlessly_token` cookie. It stops with `sign in first: simlessly portal login` when there is no session or
the portal does not accept it.

```sh
python3 tools/api_watch.py docs-check --update    # store the current documentation as the baseline
python3 tools/api_watch.py docs-check             # print what changed since then; exit 0: none, 1: changes
python3 tools/api_watch.py docs-check --report changes.md   # same, into a file (also outside the repository)
```

The snapshot is kept in `~/.config/simlessly-cli/docs-snapshot.json` (or `$XDG_CONFIG_HOME/simlessly-cli/`, or the path in
`SIMLESSLY_DOCS_SNAPSHOT`), readable by you only (file mode 0600, directory 0700). A path inside a git work tree is
refused, and `.gitignore` lists `docs-snapshot.json` and `api-snapshot/docs.json`. A reading with far fewer endpoints than
the stored snapshot is refused; `--force` skips that check.

## Development

Source is in `src/simlessly_cli/`: `cli.py` (commands and the `mutate()` gate), `client.py` and `auth.py` (signed
client), `config.py` and `store.py` (settings and secret stores), `output.py` (masking), `portal*.py` (portal).
The portal's paths and HTTP methods are in `portal_endpoints.json`; `tools/api_watch.py` and `api-snapshot/` belong to
the API change watch above.

```sh
python3 -m unittest discover -s tests
```

Tests use mock servers on `127.0.0.1`, a temporary home directory and fake `security` and `secret-tool`. They fail
on any non-loopback network access. The mock portal rejects a request whose method differs from the one in
`api-snapshot/portal.json`, so the CLI's own method data is checked against what the portal was last seen to use.

## License

MIT. See `LICENSE`.
