---
title: Preservation Constraints — banned-ops rationale + adversary model
---

# Preservation Constraints

Rationale for the banned-ops list, the lightweight adversary model, and
evidence-directory hygiene. The canonical runtime rules live in
[SKILL.md §13 Runtime Reinforcement](../SKILL.md) — this file explains
*why*, not *what*. For the enforcement mechanics (ALLOWED_PATHS, ingress
projection, atomic writes, redaction) see
[allowlist-enforcement.md](allowlist-enforcement.md).

## Table of contents

1. [Banned operations — per-item rationale](#1-banned-operations--per-item-rationale)
   1. [Env var mutations](#11-env-var-mutations-vercel-env-addrmupdatepull)
   2. [Deployment mutations](#12-deployment-mutations-redeploydeployremoverollback)
   3. [`vercel api` / `gh api` with mutation verbs](#13-vercel-api--gh-api-with--x-patchpostputdelete)
   4. [`gh api graphql` mutations](#14-gh-api-graphql-mutation-operations)
   5. [Domain / cert / webhook mutations](#15-domain--cert--webhook-mutations)
   6. [Adjacent-system mutations](#16-adjacent-system-mutations-git-push-git-reset---hard-token-revoke-oauth-app-delete)
   7. [Permitted exception — `chmod -R a-w`](#17-permitted-exception-chmod--r-a-w-on-the-local-evidence-directory)
2. [5-layer defense-in-depth](#2-5-layer-defense-in-depth)
3. [Lightweight adversary model](#3-lightweight-adversary-model)
4. [Evidence directory `.gitignore` warning](#4-evidence-directory-gitignore-warning)

---

## 1. Banned operations — per-item rationale

Every banned operation below is refused at the prose layer (agent contract),
the script layer (verb gate), or both. This section documents the *reason*
each one is on the list. Attribution: the read-only endpoint allowlist
framing is adopted from [garyhtou/Vercel-Env-Var-Exposure-Triager](https://github.com/garyhtou/Vercel-Env-Var-Exposure-Triager);
the preserve-first threat-model framing is adopted from [subinium/vercel-incident-toolkit](https://github.com/subinium/vercel-incident-toolkit).

### 1.1 Env var mutations (`vercel env add|rm|update|pull`)

- **`vercel env pull`** — writes a `.env` file to disk. This creates a
  *new* secondary exfiltration target on the investigator's machine that
  did not exist before the forensic run. If the investigator's box is
  later compromised (or already is, which is part of the reason the
  investigation is happening), the `.env` hands decrypted values to the
  attacker. The skill never has a reason to read values; names and
  metadata are sufficient for rotation planning.
- **`vercel env add` / `rm` / `update`** — mutates state on the target
  system under investigation. Two failure modes:
  1. **Evidence contamination**: the mutation appears in Vercel's
     activity log alongside the attacker's events, which complicates
     timeline analysis and can be mistaken for further attacker activity.
  2. **Responder fingerprint**: the mutation is recorded with the
     investigator's user ID and IP. If the operator later needs to
     produce an uncontaminated log for a vendor or regulator, it is
     already tainted by their own actions.

For rotations, hand the `rotation-worklist.csv` output to
[subinium](https://github.com/subinium/vercel-incident-toolkit) Flow C or
[codyhxyz/metapod-harden](https://github.com/codyhxyz/metapod-harden)
`/rotate-vercel-env <KEY>` — both operate in a controlled window with
their own audit trail.

### 1.2 Deployment mutations (`redeploy|deploy|remove|rollback`)

- **`vercel redeploy` / `deploy`** — creates a new deployment. Alters the
  exact target state being investigated. A build triggered during
  forensics reshuffles the build queue, spawns a new serverless instance,
  and may rotate a cached build artifact that is itself evidence.
- **`vercel remove`** — deletes a deployment. Irreversible evidence
  destruction.
- **`vercel rollback`** — *especially* dangerous. The deployment that is
  the likely point of compromise is often the most recently promoted one;
  rolling it back destroys the evidence deployment, its build logs, its
  runtime logs (on Pro, 24h retention), and its git-commit provenance in
  one command. A responder's rollback cannot be undone by a later
  "rollback the rollback" — the event ordering is permanently mangled.

### 1.3 `vercel api` / `gh api` with `-X PATCH|POST|PUT|DELETE`

Category-wide ban on mutation verbs. Either CLI can invoke arbitrary
endpoints, which means arbitrary mutations if the verb is permissive.
The HTTP verb gate in `_common.py::validate_url` refuses any verb other
than `GET`; the agent-level contract refuses the CLI flag pattern to
defeat shell-history evasion. Both layers must refuse — layer 1 catches
the agent before the CLI is invoked, layer 2 catches the CLI if a script
invokes it anyway.

### 1.4 `gh api graphql` mutation operations

GraphQL mutations travel on the same HTTP verb (`POST`) as queries, so
the verb gate alone cannot distinguish them. Rule: the skill does not
call `gh api graphql` at all when the operation string begins with
`mutation`. Our only GraphQL usage is
`github-repo-graphql.sh` for read-only repo metadata; that file's
operation string is a fixed `query { ... }` template with no runtime
interpolation of the operation type.

### 1.5 Domain / cert / webhook mutations

- **Domains**: DNS posture is evidence. A webhook target domain, a
  non-primary `*.vercel.app` alias, or an unexpected custom domain may
  be attacker-staged; altering it during investigation destroys the
  record of its pre-mitigation state.
- **Certs**: TLS state is evidence. Re-issuing or removing a cert mid-
  investigation alters the certificate transparency record and may
  invalidate correlations with CT-log monitors.
- **Webhooks**: webhook configurations tell you what the attacker may
  have seen (webhook targets + events) and what they may have configured
  for persistence (a webhook pointing at their infrastructure). Deleting
  a webhook erases that evidence; modifying a webhook inserts a new
  responder-owned record into the Vercel activity log.

### 1.6 Adjacent-system mutations (`git push`, `git reset --hard`, token-revoke, OAuth-app-delete)

- **`git push`** — alters remote state. If a workflow or deployment is
  pinned to a branch and someone pushes mid-investigation, the next
  deploy (manual or auto) runs different code than was captured. Also:
  pushing from the investigator's machine registers a new event in the
  GitHub audit log with the investigator's identity — same contamination
  problem as 1.1.
- **`git reset --hard`** — destroys local commit evidence. If the
  investigator has already cloned a suspect repo, resetting loses the
  exact head SHA captured at Phase 0.
- **Token revocation** — revoking a token under investigation destroys
  the ability to correlate future telemetry against that token's IP /
  user-agent / last-used timestamp. Revoke only after collection +
  freeze, and only via the `rotation-worklist.csv` handoff to downstream
  rotation tooling.
- **OAuth-app delete** — same: the app's grant history + last-used
  metadata disappears. Deleting is a containment action, not a
  collection action.

### 1.7 Permitted exception: `chmod -R a-w` on the local evidence directory

The only state-changing operation the skill performs is
`chmod -R a-w "$CASE"` in `freeze.sh`. Rationale for the exception:

- It runs on **local investigator-owned disk**, not on the target system.
- It is **preservation-increasing** — it prevents accidental modification
  of evidence. Any modification after freeze is refused by the OS.
- It does not touch any API under investigation.
- It does not appear in any target system's audit log.

Layer-5 WORM depends on this permission. The skill explicitly refuses to
re-run against an already-frozen case directory (see
[allowlist-enforcement.md §4](allowlist-enforcement.md#4-atomic-write-pattern)).

---

## 2. 5-layer defense-in-depth

A brief recap of enforcement layering. Layer 1 fails soft (agent may be
jailbroken); layers 2-4 fail hard (script refuses to execute); layer 5 is
after-the-fact tamper-evidence.

1. **Prose / contract** — SKILL.md Preservation Contract; agent echoes
   banned-ops list verbatim before Phase 0. Social-level defense.
2. **Endpoint + query allowlist** — `ALLOWED_PATHS` map in
   `_common.py`; URL parsed + validated before any HTTP call. See
   [allowlist-enforcement.md §1](allowlist-enforcement.md#1-allowed_paths-structure).
3. **Ingress projection** — top-level field whitelist per resource type;
   `value` / `decryptedValue` dropped unconditionally before disk write.
   See [allowlist-enforcement.md §3](allowlist-enforcement.md#3-ingress-projection-field-set-per-resource-type).
4. **HTTP verb gate** — only `GET` permitted; redirects not auto-followed;
   `Location` header re-validated against `ALLOWED_PATHS` before any
   manual follow. See [allowlist-enforcement.md §2](allowlist-enforcement.md#2-explicit-reject-rules).
5. **Software WORM** — `chmod -R a-w` at end of `freeze.sh`; SHA-256
   manifest + `COLLECTOR.json`; re-run against a frozen case dir refused.

v2 adds GPG signing, dual-location manifest, `verify-scene.sh`, recursive
projection with a substring denylist, and a `SCRIPTS.sha256` integrity
pin. See the plan's v2 section; none of this ships in v1.

---

## 3. Lightweight adversary model

v1 is a private skill in an internal monorepo, not public distribution.
Adversary scope is therefore:

- **A compromised third-party OAuth app** (the actual incident class
  that drove this skill) — treated as an external attacker with
  selective Vercel + GitHub read/write posture. Our defense is: don't
  give them another target (no `.env` on disk), don't taint their audit
  trail (no mutations), don't rotate the token they might be watching
  (fresh short-lived investigation token, see SKILL.md Prerequisites).
- **An opportunistic local process** on the investigator's workstation
  — defended by: token never written to any file by the skill; case
  dir mode `0700`; case dir path outside any git repo by default.
- **The investigator themself making a mistake** — defended by: atomic
  writes, TOCTOU symlink refusal, freeze-idempotence refusal,
  formula-injection neutralization in CSV output, agent echoes
  contract before Phase 0.

**Explicitly out of scope for v1**: nation-state adversary with local
code execution, supply-chain attack on Python stdlib, compromised
macOS kernel, malicious reference-file prompt injection (v2 plugin-qa
scan). The skill's invariants:

- Token value is **never** written to any file; read from
  `--token-file` path, env var, or `getpass` (`_common.py::get_token`),
  then kept in memory only.
- No third-party-project operation — the target team + repo are
  specified explicitly in `preflight.sh` and validated against a slug
  regex; no wildcard enumeration outside the scoped team.
- No CLI-arg value injection — reject `--token <value>` form (the value
  would appear in shell history); accept `--token-file <path>` only.
- Hard-coded hostnames — only `api.vercel.com` and `api.github.com`.
  Any scheme, host, or port substitution in the ALLOWED_PATHS matcher
  is refused (no environment-variable hostname overrides, no
  `$VERCEL_API_URL` substitution).
- Zero runtime dependencies — Python 3.10 stdlib only, bash 3.2 only
  (see ADR-002); no `pip install`, no `npm install`, nothing that
  requires a package manager to reach a remote index at forensic time.

---

## 4. Evidence directory `.gitignore` warning

The case directory lives under `~/.vercel-forensics/case-<user>-<hostname>-<iso-ts>/`
by design — **outside any repository**. This is deliberate: nobody
accidentally commits `MANIFEST.sha256`, `rotation-worklist.csv`, or raw
collected evidence to source control.

**However**: if the operator copies evidence into a project directory
(sharing with a colleague via a repo, collaborating on a postmortem in
a docs repo, packaging evidence into a bundle that itself happens to be
tracked in git), the operator is responsible for the ignore-pattern
hygiene below. v1 does *not* ship an `ignore-setup.py` helper —
**warning only**. If hygiene demand materializes in practice, add the
helper in v2.

Patterns to add to **each** of `.gitignore`, `.vercelignore`,
`.dockerignore`, `.npmignore` (every ignore-surface mechanism that
might ship the file somewhere):

```
# Vercel forensics evidence — NEVER commit or publish
vercel-forensics/
case-*
MANIFEST.sha256
rotation-worklist.csv
CHAIN_OF_CUSTODY.md
COLLECTOR.json
scan-errors.txt
redactions.log
DRY-RUN-PLAN.md
analysis/
```

Why each ignore file:

- **`.gitignore`** — prevents `git add` from staging evidence.
- **`.vercelignore`** — prevents a `vercel deploy` from uploading
  evidence to a Vercel build context (a particularly cruel way to leak
  forensic data back to the platform under investigation).
- **`.dockerignore`** — prevents `docker build` from baking evidence
  into an image layer (image layers often leak via registry pulls).
- **`.npmignore`** — prevents `npm publish` from shipping evidence to
  the npm registry in a package tarball.

See [data-inventory.md](data-inventory.md) for per-tier detail on what
specifically ends up in each of these files (env-var metadata, user
emails, webhook URLs, deployment IDs — all high-signal for an
attacker).
