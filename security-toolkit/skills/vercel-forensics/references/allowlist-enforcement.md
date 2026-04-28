---
title: Allowlist Enforcement — read-only technical reference
---

# Allowlist Enforcement

Technical reference for the read-only enforcement pattern. Do **not**
restate runtime rules — those live in [SKILL.md §Runtime Reinforcement](../SKILL.md).
Do **not** restate banned-ops rationale — that lives in
[preservation-constraints.md](preservation-constraints.md).

## Table of contents

1. [Scope — what is and isn't code-enforced](#scope--what-is-and-isnt-code-enforced-v1-honest-statement)
2. [`ALLOWED_PATHS` structure](#1-allowed_paths-structure)
3. [Explicit reject rules](#2-explicit-reject-rules)
4. [Ingress projection field set per resource type](#3-ingress-projection-field-set-per-resource-type)
5. [Atomic-write pattern](#4-atomic-write-pattern)
6. [CSV formula-injection neutralization](#5-csv-formula-injection-neutralization)
7. [Log-request redaction](#6-log-request-redaction)

## Scope — what is and isn't code-enforced (v1 honest statement)

`_common.py::validate_url` and `_common.py::project_fields` run only in the
Python layer. The Python layer in v1 is: `_common.py` self-tests, the
five analysis scripts (`triage.py`, `timeline-fuse.py`,
`per-actor-profile.py`, `build-log-scan.py`, `rotation-worklist.py`), and
`redact.py`. The bash collection scripts
(`activity-paginate.sh`, `vercel-team-context.sh`, `vercel-per-project.sh`,
`github-repo-graphql.sh`, `github-audit-log.sh`, `vercel-build-logs.sh`)
call `vercel api` / `gh api` / `curl` directly with hardcoded hosts and
do **not** call back into `_common.py` before each request. Layer-2/3
enforcement for those calls is therefore a combination of:

- **Trusted CLI surface** — `vercel api` and `gh api` only speak to
  `api.vercel.com` / `api.github.com` respectively.
- **Upstream API contract** — plain GET endpoints do not return `value`
  or `decryptedValue`; the only path that could is `/v9/projects/:pid/env`
  with `?decrypt=true`, which `ALLOWED_PATHS` + the reject-rule list
  below explicitly refuses at the Python layer.
- **Banned-ops grep at review time** — no script constructs `-X <verb>`
  other than the documented read-only calls.

The snippet in §1 below is therefore **illustrative**. The authoritative
`ALLOWED_PATHS` lives in `scripts/_common.py`; the snippet is a
human-readable summary and may lag one patch release behind. v2 will
upgrade this to a shell-level `validate_url` helper invoked before every
outbound request in the bash layer, at which point the snippet becomes
authoritative.

Attribution: the endpoint-allowlist + ingress-projection pattern is
adopted from [garyhtou/Vercel-Env-Var-Exposure-Triager](https://github.com/garyhtou/Vercel-Env-Var-Exposure-Triager)
and extended with per-resource field sets, atomic-write TOCTOU
defenses, and CSV formula-injection neutralization.

---

## 1. `ALLOWED_PATHS` structure

A dictionary keyed by endpoint path template (with `:param` placeholders)
whose value is the set of query parameters permitted on that endpoint.
Any URL whose path does not match a key is refused before `fetch`. Any
query parameter not in the endpoint's allowed set is refused.

```python
ALLOWED_PATHS: dict[str, set[str]] = {
    # Vercel team context
    "/v2/teams/:tid":                                set(),                          # no query params
    "/v2/teams/:tid/members":                        {"limit", "since", "until"},
    "/v3/user/tokens":                               set(),
    "/v1/integration-log-drains":                    {"teamId", "projectId"},
    "/v1/integrations/configurations":               {"teamId", "view"},
    "/v1/integrations/configurations/:cid":          {"teamId"},
    "/v8/projects":                                  {"teamId", "limit", "since", "until"},
    "/v9/projects/:pid":                             {"teamId"},
    "/v9/projects/:pid/env":                         {"teamId", "decrypt"},          # "decrypt" is REJECTED (see §2)
    "/v6/deployments":                               {"teamId", "projectId", "limit", "since", "until", "target", "state"},
    "/v13/deployments/:did":                         {"teamId"},
    "/v2/deployments/:did/events":                   {"teamId", "direction", "limit"},
    "/v3/events":                                    {"teamId", "limit", "since", "until", "types", "userId"},
    # GitHub
    "/users/:user":                                  set(),
    "/orgs/:org/audit-log":                          {"phrase", "include", "per_page", "after"},
    "/enterprises/:ent/audit-log":                   {"phrase", "include", "per_page", "after"},
    "/repos/:owner/:repo":                           set(),
    "/graphql":                                      set(),                          # POST-only; body validated separately
    # ... (full list in scripts/_common.py)
}
```

**Path matching**: split incoming path on `/`, walk segment-by-segment
against each template key, match literal segments exactly and `:param`
segments as a single non-`/` segment. No regex. No wildcards. An incoming
path like `/v9/projects/prj_abc/env/env_xyz` is refused because it does
not match `/v9/projects/:pid/env` (extra segment).

**Query validation**: after path match, parse query-string; every key
must be in the path's allowed set. Unknown keys → refuse.

**Why a map of sets, not a list of regexes**: regexes are hard to
review for correctness and prone to ReDoS. A literal segment-walk with
a single placeholder class is auditable by eye in under a minute.

---

## 2. Explicit reject rules

Rules that override the `ALLOWED_PATHS` match and refuse the request
even if the path and parameter names were otherwise permitted.

**`decrypt` and `reveal` query params — always rejected (case-insensitive)**.
These parameters opt into returning the plaintext value of an env var
(Vercel) or secret (hypothetical future GitHub endpoint). The skill has
no legitimate reason to request plaintext — rotation planning needs
names + metadata only. Match case-insensitively on the raw query key
to catch `Decrypt`, `DECRYPT`, `dEcRyPt`, etc. Reject before the path
match so the error message names the offending param, not the path.

**HTTP verbs other than `GET` — always rejected**. The skill's only
legitimate interaction with `api.vercel.com` + `api.github.com` is
read. `POST` is permitted exclusively for `/graphql` (GitHub GraphQL
query operations, which travel on POST); the request body is validated
separately to refuse any operation string that begins with `mutation`
(see [preservation-constraints.md §1.4](preservation-constraints.md#14-gh-api-graphql-mutation-operations)).

**Redirects — not auto-followed**. All HTTP calls pass
`allow_redirects=False` to `urllib` / `http.client`. On a 3xx response
the script reads the `Location` header, re-runs `validate_url()`
against it, and only then follows the redirect manually. A redirect to
a host other than the originally allowed one (e.g., a 301 from
`api.vercel.com` to `api.evil.example`) is refused. A redirect to an
unknown path on the same host is also refused. This defends against a
transient or malicious edge-case redirect leaking traffic to an
unexpected destination.

---

## 3. Ingress projection field set per resource type

After the HTTP response is parsed, `project_fields(obj, kind)` walks
the top-level fields of each object in the response and drops anything
not in the kind's allowed set. Projection happens **before** the first
disk write. `value` and `decryptedValue` are dropped unconditionally
for env-var objects — regardless of whether they appeared, regardless
of whether the caller asked for them. Belt + suspenders: layer 2
refuses the `decrypt` query param in the first place.

| Resource kind | Allowed top-level fields |
|---|---|
| `team` | `id`, `slug`, `name`, `createdAt`, `updatedAt`, `billing.plan`, `resourceConfig.concurrentBuilds`, `saml.enforced`, `saml.connection`, `saml.directory`, `saml.roles` |
| `member` | `uid`, `email`, `role`, `confirmed`, `createdAt`, `joinedFrom`, `teamRoles`, `teamPermissions` |
| `user-token` | `id`, `name`, `type`, `origin`, `scopes`, `activeAt`, `createdAt`, `expiresAt` *(never `token` / `bearerToken`)* |
| `integration` | `id`, `slug`, `integrationId`, `name`, `teamId`, `userId`, `source`, `type`, `createdAt`, `updatedAt`, `scopes`, `projects`, `permissions`, `installationType` |
| `log-drain` | `id`, `name`, `clientId`, `configurationId`, `teamId`, `createdAt`, `deliveryFormat`, `sources`, `url` *(host only; query-string stripped downstream)* |
| `project` | `id`, `name`, `accountId`, `teamId`, `createdAt`, `updatedAt`, `link`, `framework`, `latestDeployments` *(projected recursively as deployment kind)*, `targets`, `env` *(projected recursively as env-var kind)*, `ssoProtection`, `passwordProtection`, `trustedIps`, `rollingRelease` |
| `env-var` | `id`, `key`, `type`, `target`, `gitBranch`, `configurationId`, `createdAt`, `updatedAt`, `lastUpdatedBy`, `lastUpdatedByDisplayName` *(**never** `value` / `decryptedValue`)* |
| `deployment` | `uid`, `name`, `url`, `created`, `source`, `state`, `target`, `creator.uid`, `creator.email`, `meta.githubCommitSha`, `meta.githubCommitRef`, `meta.githubRepo`, `inspectorUrl`, `projectId`, `teamId`, `buildingAt`, `ready`, `readyState` |
| `domain` | `name`, `apexName`, `projectId`, `verified`, `verification`, `createdAt`, `updatedAt`, `redirect`, `redirectStatusCode`, `gitBranch` |
| `alias` | `uid`, `alias`, `deploymentId`, `projectId`, `createdAt`, `protectionBypass` |
| `cert` | `id`, `cns`, `createdAt`, `expiresAt`, `autoRenew` |
| `webhook` | `id`, `url` *(host + path; query-string stripped)*, `events`, `projectIds`, `teamId`, `createdAt`, `updatedAt` |
| `firewall-config` | `version`, `updatedAt`, `firewallEnabled`, `managedRules`, `customRules`, `ipRules`, `crs`, `bypass`, `attackChallengeMode` |
| `access-group` | `id`, `name`, `teamId`, `createdAt`, `membersCount`, `projectsCount` |
| `edge-config` | `id`, `slug`, `createdAt`, `updatedAt`, `sizeInBytes`, `itemCount`, `digest` *(**never** `items` values)* |
| `activity-event` | `id`, `type`, `principalId`, `userId`, `createdAt`, `payload.*` *(payload projected per event type; see `_common.py::EVENT_PAYLOAD_PROJECTIONS`)* |
| `github-audit-event` | `@timestamp`, `action`, `actor`, `actor_ip`, `user`, `org`, `repo`, `hashed_token`, `business`, `created_at`, `operation_type` *(never full request bodies)* |
| `github-repo-graphql` | `name`, `nameWithOwner`, `isArchived`, `visibility`, `pushedAt`, `defaultBranchRef.name`, `defaultBranchRef.branchProtectionRule.*`, `deployKeys.nodes[].title`, `deployKeys.nodes[].readOnly`, `deployKeys.nodes[].createdAt` |

**Anything else is dropped silently.** v1 does top-level projection only;
nested objects are projected only when called out above (e.g., `project`
→ `latestDeployments` recurses into deployment projection). v2 upgrades
to fully recursive projection + a substring denylist on
`secret|key|token|password|credential|value|decrypted|reveal` — defends
against future API additions like a hypothetical
`saml.connection.clientSecret` field.

See [data-inventory.md](data-inventory.md) for per-tier gotchas (what
the API returns for Pro vs Enterprise, fields that are dashboard-only).

---

## 4. Atomic-write pattern

Every disk write in the case directory goes through
`_common.py::atomic_write(path, content, mode=0o600)`. Contract:

1. **Refuse if target is a symlink** — `os.lstat(path)` before opening;
   if `stat.S_ISLNK`, raise `FileExistsError`. Defends against a TOCTOU
   attack where a local process swaps the path for a symlink between
   the script's existence-check and its write.
2. **Refuse if target exists** — the case dir is **append-only** during
   collection; if `os.path.exists(path)`, raise `FileExistsError`.
   Combined with the freeze-idempotence refusal (step 5), this
   guarantees that no file inside a case dir is ever overwritten.
3. **Write to `path + ".tmp"`** with `O_CREAT | O_EXCL | O_WRONLY` and
   mode `0o600`. `O_EXCL` fails if the tmp file already exists, which
   closes the race window where two concurrent script invocations
   compete for the same filename.
4. **Rename atomic** — `os.rename(tmp, path)` is atomic on the same
   filesystem on both macOS (APFS) and Linux (ext4, xfs). A reader
   sees either the old file (nonexistent) or the complete new file;
   never a partial write.
5. **Freeze idempotence** — `freeze.sh` refuses to run if
   `MANIFEST.sha256` already exists in the case dir. Combined with
   `chmod -R a-w` at the end of freeze, this makes the case dir
   immutable post-freeze. Re-running the skill against a frozen case
   dir is a hard refuse (`scan-errors.txt` entry, exit 2).

Mode `0o600` means only the case-dir owner can read/write. The case
dir itself is created mode `0700` in `preflight.sh`. `umask` is set
to `0o077` before any write to defend against an inherited permissive
umask.

---

## 5. CSV formula-injection neutralization

The `rotation-worklist.csv` output contains user-controllable fields
(env-var key, project name, owner email, recommendation text).
Spreadsheet software (Excel, Numbers, Google Sheets, LibreOffice)
interprets cell values starting with `=`, `+`, `-`, `@`, `\t`, or
`\r` as formulas. A malicious env-var named `=HYPERLINK("http://evil/",...)`
would execute on the responder's machine when they open the CSV.

**Rule**: before writing any CSV field, if `field[0:1]` is in the set
`{"=", "+", "-", "@", "\t", "\r"}`, prefix the field with a single
quote (`'`). The single-quote prefix is the standard neutralization —
spreadsheet software displays the field as a literal string and does
not evaluate it.

Applied in `rotation-worklist.py` `neutralize_formula(field)` helper
before every `csv.writer.writerow()` call. Covers all fields, not just
those that "look risky" — whitelist of safe fields is too easy to get
wrong as schema evolves.

v2 adds Unicode homoglyph + RTL-override stripping (e.g., U+202E
overrides right-to-left display and can be used to disguise malicious
filenames). Not in v1.

---

## 6. Log-request redaction

The `--log-requests` transparency flag logs each outbound HTTP request
to stderr so the operator can confirm the skill really is read-only.
Format: `METHOD path?query`. **Redaction happens at emission time**,
not post-hoc — the log line that is ever constructed with
`Authorization` header or secret query params simply does not exist.

`_common.py::log_request(url, method, headers)` implementation:

1. Split URL into path + query-string components.
2. Parse query-string; for any key in the redaction set (match
   case-insensitively), replace the value with `<REDACTED>`. Redaction
   set: `{"token", "api_key", "apikey", "secret", "access_token",
   "client_secret", "password", "authorization"}`.
3. Re-serialize the query string with `urlencode`.
4. Never include the `Authorization` header in the log line at all —
   don't format-string it in the first place, don't pass `headers`
   through `repr()`, don't log the full request object.
5. Emit: `METHOD /path?redacted_query` to stderr.

The log line is constructed only in the `--log-requests` code path —
the default-off path does not build the string at all. This is
defensive against a future refactor accidentally logging the
un-redacted form: if the only place the string is built is inside the
redaction helper, there is nothing else to audit.

Two additional guarantees:

- **No log-file sink**: `--log-requests` writes to stderr only. There
  is no `--log-file` option. An operator who wants a persistent copy
  can `2>` redirect at the shell. This keeps the skill from becoming
  the surface that writes a redaction bug to disk.
- **No request body in the log**: even for GraphQL POSTs, only the
  path is logged, not the operation body. The operation body is
  validated separately against the mutation-prefix rule.

See [preservation-constraints.md §3](preservation-constraints.md#3-lightweight-adversary-model)
for the broader token-hygiene invariants.
