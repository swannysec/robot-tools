# Vercel CLI + API Quirks

Known CLI and API bugs encountered during the 2026-04-19 response and prior art. Use this file when a script misbehaves and you need to rule out a CLI bug before suspecting your own logic. Companion: `collection-patterns.md` (how to execute collection), `api-endpoint-reference.md` (what endpoints exist and their rate limits).

## Table of contents

1. [`vercel activity` hang under load](#vercel-activity-hang-under-load)
2. [`vercel api` POST broken](#vercel-api-post-broken)
3. [`vercel env pull` overwrites target silently](#vercel-env-pull-overwrites-target-silently)
4. [`--sensitive` forbidden on `development` target](#--sensitive-forbidden-on-development-target)
5. [`vercel project ls --json` stderr+stdout mixing](#vercel-project-ls---json-stderrstdout-mixing)
6. [Undocumented `trustedIps` field on project response](#undocumented-trustedips-field-on-project-response)
7. [GitHub `gh api graphql` does not auto-paginate](#github-gh-api-graphql-does-not-auto-paginate)
8. [GitHub audit-log 403 embedded in response](#github-audit-log-403-embedded-in-response)
9. [GitHub PAT scope gotchas](#github-pat-scope-gotchas)

## `vercel activity` hang under load

**Symptom:** `vercel activity --format json` returns an empty `events: []` array with a still-populated `pagination.next` cursor, or stops responding entirely, during Vercel-side incident response windows.

**Observed:** 2026-04-19 response, peak Vercel incident traffic. Also reported intermittently on large Enterprise teams with >10k events/day.

**Mitigation (implemented in `scripts/activity-paginate.sh`):**
- 60s per-page HTTP timeout via the ADR-004 portable watchdog pattern (macOS BSD has no GNU `timeout`).
- 5-min idle-progress watchdog — if no new events arrive for 5 minutes, abort and write `.partial` flag plus a line to `scan-errors.txt`.
- `RESUME_FROM=<cursor>` environment variable so an aborted run can be resumed from the last known-good cursor without re-fetching earlier pages.
- Partial flag propagates into the freeze manifest so `triage.py` reports the activity window as incomplete rather than claiming a full pull.

Do **not** silently retry on empty pages — that masks the bug and wastes rate-limit budget.

## `vercel api` POST broken

**Symptom:** `vercel api <path> -X POST -d '<json>'` silently drops the request body or returns 400 despite well-formed input. Long-standing CLI issue.

**Relevance to this skill:** zero. The skill is read-only and its banned-ops list forbids `POST|PUT|PATCH|DELETE` on any endpoint. Documented here for operators who transition to rotation via `subinium/vercel-incident-toolkit` or `codyhxyz/metapod-harden` and need to understand why those tools use `curl` directly.

**Workaround for future tooling (not this skill):** call `curl` with the CLI's stored token from `~/.local/share/com.vercel.cli/auth.json`. Bypassing the CLI gives correct verb + body handling.

## `vercel env pull` overwrites target silently

**Symptom:** `vercel env pull <file>` writes to `<file>` with **no prompt, no confirmation, no backup**, even when `<file>` already exists and contains unrelated content.

**Why this matters:** during forensics, any `env pull` creates a secondary exfil target on the operator's disk containing plaintext env values. That file is then subject to Time Machine backups, Spotlight indexing, iCloud sync, and casual `tar` archives.

**Policy in this skill:** `env pull` is on the banned-ops list in SKILL.md and `preservation-constraints.md`. The skill never runs it. Noted here for operators who might invoke it **outside** the skill's workflow — do not.

## `--sensitive` forbidden on `development` target

**Symptom:** Creating or updating an env var with `--sensitive` on the `development` target returns a Vercel API error and silently falls back to `encrypted`. Documented Vercel limitation.

**Relevance:** only matters during rotation, not collection. Flagged here because operators using `subinium/vercel-incident-toolkit` Flow C or `codyhxyz/metapod-harden` `/rotate-vercel-env` after running this skill will hit this if they try to promote a dev-target secret to `sensitive`. The rotation tools warn; our skill surfaces the limitation in `triage.py`'s class-taxonomy output so the rotation worklist does not recommend a promotion that will silently downgrade.

## `vercel project ls --json` stderr+stdout mixing

**Symptom:** `vercel project ls --json` writes progress/diagnostic text to **stderr** while emitting JSON on **stdout**. Redirecting only stdout without suppressing stderr pollutes terminal output; `jq` parsing still works, but interactive readability suffers.

**Workaround:** always use `2>/dev/null` when piping or redirecting JSON output to a file:

```bash
vercel project ls --json 2>/dev/null > projects.json
vercel api "/v9/projects?teamId=$TEAM_ID" --paginate 2>/dev/null > projects-full.json
```

Every bash script in `scripts/` uses this pattern. Do not "simplify" by dropping the `2>/dev/null` — scan-errors that land in scan-errors.txt are the intended signal channel, not stderr noise from success paths.

## Undocumented `trustedIps` field on project response

**Symptom:** `/v9/projects/:pid` response sometimes includes a `trustedIps` field that is **not** in the documented schema. The Terraform Vercel provider reads it; the CLI does not expose it; the API docs do not mention it.

**Mitigation in `scripts/vercel-per-project.sh`:** probe the live response for the field and capture it if present. Do not fail if absent. Report presence/absence in `data-inventory.md` output so the analyst knows whether trusted-IP enforcement is a collected fact or a known gap.

Related undocumented fields to probe opportunistically: `ssoProtection`, `passwordProtection`, `delegatedProtection`. Same strategy — capture if present, flag as gap if not.

## GitHub `gh api graphql` does not auto-paginate

**Symptom:** `gh api graphql -F query=... --paginate` silently returns only the first page. `--paginate` is **REST-only** — it processes the `Link` header that GraphQL responses do not emit.

**Mitigation in `scripts/github-repo-graphql.sh`:** hand-rolled cursor loop. Read `pageInfo.endCursor` + `pageInfo.hasNextPage` from each response and re-invoke with `-F cursor=<endCursor>` until `hasNextPage` is false.

```bash
CURSOR=""
while :; do
  RESP=$(gh api graphql -F owner="$OWNER" -F name="$REPO" -F cursor="$CURSOR" -f query="$QUERY")
  echo "$RESP" | jq -c '.data.repository.deployKeys.nodes[]' >> deploy-keys.jsonl
  HAS_NEXT=$(echo "$RESP" | jq -r '.data.repository.deployKeys.pageInfo.hasNextPage')
  CURSOR=$(echo "$RESP" | jq -r '.data.repository.deployKeys.pageInfo.endCursor')
  [ "$HAS_NEXT" = "true" ] || break
done
```

Budget: each query is ~30 points against the 5000 points/hour GraphQL limit. Shallow pagination (`first: 25`) keeps the per-repo cost bounded.

## GitHub audit-log 403 embedded in response

**Symptom:** `gh api /orgs/<org>/audit-log --paginate` on a busy org trips the 1,750 req/hr limit and appends the rate-limit error as a JSON **object** after the last good array element. The output file looks like:

```
[{event}, {event}, ..., {event}, {"message":"API rate limit exceeded...","status":"403"}
```

— a trailing object with no closing bracket. Not a clean HTTP 403; the CLI does not abort.

**Mitigation:** use the `JSONDecoder.raw_decode` repair pattern documented in `collection-patterns.md` §"Rate-limit recovery (GitHub audit log)". Resume from the oldest-captured-event boundary after the 1-hour reset window. Record both the abort and the resume in `scan-errors.txt` so the freeze manifest reflects gap boundaries.

## GitHub PAT scope gotchas

Fine-grained PAT scopes have two traps worth knowing before running `preflight.sh`:

- **`Administration: read` covers BOTH deploy keys and branch protection.** You cannot request one without the other. If an operator is scope-minimizing and deliberately withholds branch-protection read, they also lose deploy-key read — which breaks `github-repo-graphql.sh`. Document this in the Prerequisites section of SKILL.md; do not pretend finer granularity exists.
- **`Metadata: read` is auto-granted and cannot be withheld.** Do not list it as a scope the operator must grant; GitHub grants it implicitly on any fine-grained PAT. Listing it as required implies the operator has a choice they do not.

**Minimum scopes for v1 (documented in SKILL.md Prerequisites):**
- `Administration: read` (deploy keys + branch protection — coupled)
- `Contents: read` (commits, branches, file history)
- `Webhooks: read`
- `Audit log: read` (organization-level; user PATs cannot read audit log)
- `Members: read` (for org-type owners)

Classic PATs (`repo`, `read:org`, `read:audit_log`) also work but are broader than needed. Fine-grained is preferred for the "do not use a token you are about to rotate" hygiene rule — easier to mint, easier to revoke.
