#!/usr/bin/env bash
# preflight.sh — vercel-forensics Phase 0
#
# Enforces the preconditions that every later phase assumes:
#   * vercel + gh authenticated (unless --no-github)
#   * no ambient $VERCEL_TOKEN (ambiguous source → fail-closed)
#   * user-supplied slugs match strict regex
#   * $USER + $(hostname -s) sanitized before path construction
#   * case directory created under ~/.vercel-forensics/ at mode 0700
#   * Vercel tier detected (saml.connection → concurrentBuilds → audit-log 404)
#   * GitHub owner type + audit-log endpoint resolved
#   * advisory lockfile held on sha256(token)[0..16]
#
# Targets bash 3.2 + BSD userland (macOS default). See ADR-002.
# Requires: jq, vercel, gh (unless --no-github), python3.
#
# Exit codes:
#   0 = PREFLIGHT OK (all checks pass)
#   1 = PREFLIGHT FAIL (reason emitted to stderr + stdout summary)

set -euo pipefail

# ---------------------------------------------------------------------------
# Constants + helpers
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMMON_PY="${SCRIPT_DIR}/_common.py"
VF_ROOT="${HOME}/.vercel-forensics"

# Slug regex — the string, not a pattern variable. Used for Vercel team slugs,
# GitHub org slugs, and GitHub enterprise slugs. Same rules as GitHub org
# naming (1–39 chars, alphanumeric + hyphen, no leading/trailing hyphen).
SLUG_RE='^[a-z0-9]([a-z0-9-]{0,37}[a-z0-9])?$'
# Case-dir segment regex — applied to $USER and $(hostname -s) before either
# is interpolated into a filesystem path. Deliberately broader than SLUG_RE
# (hostnames routinely include dots) but still fail-closed.
PATH_SEG_RE='^[A-Za-z0-9._-]{1,64}$'

NO_GITHUB=0
GITHUB_ORG=""
GITHUB_ENTERPRISE_SLUG=""
TEAM_SLUG=""

FAIL_REASON=""
CHECKS=()

emit_check() {
    # emit_check STATUS MESSAGE
    # Appends a one-line-per-check status to the CHECKS array.
    CHECKS+=("[$1] $2")
}

fail() {
    # fail REASON
    # Records the first failure reason; does not exit immediately so the
    # caller can flush the partial summary before aborting.
    if [ -z "${FAIL_REASON}" ]; then
        FAIL_REASON="$1"
    fi
}

flush_summary() {
    # flush_summary
    # Emits the accumulated check list plus the terminal PREFLIGHT line.
    local line
    for line in "${CHECKS[@]}"; do
        printf '%s\n' "${line}"
    done
    if [ -n "${FAIL_REASON}" ]; then
        printf 'PREFLIGHT FAIL: %s\n' "${FAIL_REASON}"
    else
        printf 'PREFLIGHT OK\n'
    fi
}

usage() {
    cat >&2 <<'EOF'
Usage: preflight.sh --team <vercel-team-slug> [--no-github]
                    [--github-org <slug>] [--github-enterprise <slug>]

  --team <slug>               Vercel team slug (required).
  --no-github                 Skip GitHub preflight + audit-log probe.
  --github-org <slug>         GitHub org/user slug (required unless --no-github).
  --github-enterprise <slug>  GitHub Enterprise Cloud slug (optional;
                              enables enterprise audit-log probe).

Environment:
  VERCEL_TOKEN                MUST NOT be set at invocation — the token
                              hierarchy is --token-file → env → getpass,
                              and an ambient env var is ambiguous. Pass
                              tokens to downstream scripts explicitly.

Exit codes:
  0  PREFLIGHT OK
  1  PREFLIGHT FAIL (reason in summary)
EOF
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

while [ $# -gt 0 ]; do
    case "$1" in
        --no-github)
            NO_GITHUB=1
            shift
            ;;
        --github-org)
            if [ $# -lt 2 ]; then
                echo "preflight: --github-org requires a value" >&2
                usage
                exit 1
            fi
            GITHUB_ORG="$2"
            shift 2
            ;;
        --github-enterprise)
            if [ $# -lt 2 ]; then
                echo "preflight: --github-enterprise requires a value" >&2
                usage
                exit 1
            fi
            GITHUB_ENTERPRISE_SLUG="$2"
            shift 2
            ;;
        --team)
            if [ $# -lt 2 ]; then
                echo "preflight: --team requires a value" >&2
                usage
                exit 1
            fi
            TEAM_SLUG="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "preflight: unknown argument: $1" >&2
            usage
            exit 1
            ;;
    esac
done

if [ -z "${TEAM_SLUG}" ]; then
    echo "preflight: --team <slug> is required" >&2
    usage
    exit 1
fi

if [ "${NO_GITHUB}" -eq 0 ] && [ -z "${GITHUB_ORG}" ]; then
    echo "preflight: --github-org <slug> is required unless --no-github is set" >&2
    usage
    exit 1
fi

# ---------------------------------------------------------------------------
# Check 1: refuse ambient $VERCEL_TOKEN
# ---------------------------------------------------------------------------
# The skill's token hierarchy (see _common.py::get_token) is:
#   --token-file <path>  →  $VERCEL_TOKEN / $GH_TOKEN  →  getpass(TTY).
# A pre-existing $VERCEL_TOKEN at preflight time is ambiguous — we cannot
# distinguish "operator intentionally exported it this session" from "stale
# value from a prior shell / dotfile / another project." Fail-closed.
if [ -n "${VERCEL_TOKEN:-}" ]; then
    emit_check FAIL "VERCEL_TOKEN is set in the environment (ambiguous source; unset and re-run)"
    fail "ambient-vercel-token"
    flush_summary
    exit 1
fi
emit_check OK "no ambient \$VERCEL_TOKEN"

# Also refuse ambient GitHub tokens. `gh api` / `gh auth token` happily
# consume either; a stale export from a shell/dotfile/another project can
# cause the skill to read GitHub as the wrong identity, contaminating the
# audit log with the attacker's shadow token if the laptop is compromised.
if [ "${NO_GITHUB}" -eq 0 ]; then
    for github_env in GH_TOKEN GITHUB_TOKEN; do
        eval "val=\${${github_env}:-}"
        if [ -n "${val}" ]; then
            emit_check FAIL "${github_env} is set in the environment (ambiguous source; unset and re-run)"
            fail "ambient-github-token"
            flush_summary
            exit 1
        fi
    done
    emit_check OK "no ambient \$GH_TOKEN / \$GITHUB_TOKEN"
fi

# ---------------------------------------------------------------------------
# Check 2: required binaries
# ---------------------------------------------------------------------------
for bin in vercel jq python3; do
    if ! command -v "${bin}" >/dev/null 2>&1; then
        emit_check FAIL "required binary not on PATH: ${bin}"
        fail "missing-binary-${bin}"
        flush_summary
        exit 1
    fi
done
if [ "${NO_GITHUB}" -eq 0 ]; then
    if ! command -v gh >/dev/null 2>&1; then
        emit_check FAIL "required binary not on PATH: gh (pass --no-github to skip)"
        fail "missing-binary-gh"
        flush_summary
        exit 1
    fi
fi
if [ ! -f "${COMMON_PY}" ]; then
    emit_check FAIL "_common.py missing at ${COMMON_PY}"
    fail "missing-common-py"
    flush_summary
    exit 1
fi
emit_check OK "required binaries present"

# ---------------------------------------------------------------------------
# Check 3: slug validation (Vercel team + GitHub org/enterprise)
# ---------------------------------------------------------------------------
# Performed before any interpolation into URLs or shell calls.
if ! printf '%s' "${TEAM_SLUG}" | LC_ALL=C grep -Eq "${SLUG_RE}"; then
    emit_check FAIL "team slug does not match ${SLUG_RE}: ${TEAM_SLUG}"
    fail "invalid-team-slug"
    flush_summary
    exit 1
fi
emit_check OK "team slug syntactically valid"

if [ "${NO_GITHUB}" -eq 0 ]; then
    if ! printf '%s' "${GITHUB_ORG}" | LC_ALL=C grep -Eq "${SLUG_RE}"; then
        emit_check FAIL "github-org slug does not match ${SLUG_RE}: ${GITHUB_ORG}"
        fail "invalid-github-org-slug"
        flush_summary
        exit 1
    fi
    emit_check OK "github-org slug syntactically valid"

    if [ -n "${GITHUB_ENTERPRISE_SLUG}" ]; then
        if ! printf '%s' "${GITHUB_ENTERPRISE_SLUG}" | LC_ALL=C grep -Eq "${SLUG_RE}"; then
            emit_check FAIL "github-enterprise slug does not match ${SLUG_RE}: ${GITHUB_ENTERPRISE_SLUG}"
            fail "invalid-github-enterprise-slug"
            flush_summary
            exit 1
        fi
        emit_check OK "github-enterprise slug syntactically valid"
    fi
fi

# ---------------------------------------------------------------------------
# Check 4: $USER + $(hostname -s) sanitization
# ---------------------------------------------------------------------------
CASE_USER="${USER:-}"
CASE_HOST="$(hostname -s 2>/dev/null || true)"

if [ -z "${CASE_USER}" ] || ! printf '%s' "${CASE_USER}" | LC_ALL=C grep -Eq "${PATH_SEG_RE}"; then
    emit_check FAIL "\$USER does not match ${PATH_SEG_RE}: '${CASE_USER}'"
    fail "invalid-user-segment"
    flush_summary
    exit 1
fi
if [ -z "${CASE_HOST}" ] || ! printf '%s' "${CASE_HOST}" | LC_ALL=C grep -Eq "${PATH_SEG_RE}"; then
    emit_check FAIL "hostname -s does not match ${PATH_SEG_RE}: '${CASE_HOST}'"
    fail "invalid-hostname-segment"
    flush_summary
    exit 1
fi
emit_check OK "\$USER + hostname path segments sanitized"

# ---------------------------------------------------------------------------
# Check 5: vercel whoami + gh auth status
# ---------------------------------------------------------------------------
if ! vercel whoami >/dev/null 2>&1; then
    emit_check FAIL "vercel whoami failed (run 'vercel login' first)"
    fail "vercel-unauthenticated"
    flush_summary
    exit 1
fi
emit_check OK "vercel whoami succeeded"

if [ "${NO_GITHUB}" -eq 0 ]; then
    if ! gh auth status >/dev/null 2>&1; then
        emit_check FAIL "gh auth status failed (run 'gh auth login' first)"
        fail "gh-unauthenticated"
        flush_summary
        exit 1
    fi
    emit_check OK "gh auth status succeeded"
fi

# ---------------------------------------------------------------------------
# Check 6: resolve Vercel team slug → team ID
# ---------------------------------------------------------------------------
# `vercel teams ls --json` lists the authenticated user's teams; we pick the
# matching slug. Stops here if the caller is not a member of TEAM_SLUG.
TEAMS_JSON="$(vercel teams ls --json 2>/dev/null || true)"
if [ -z "${TEAMS_JSON}" ]; then
    emit_check FAIL "vercel teams ls --json returned empty output"
    fail "vercel-teams-empty"
    flush_summary
    exit 1
fi

TEAM_ID="$(printf '%s' "${TEAMS_JSON}" \
    | jq -r --arg slug "${TEAM_SLUG}" '
        if type == "array"
            then (.[] | select(.slug == $slug) | .id)
            else (.teams // [] | .[] | select(.slug == $slug) | .id)
        end' 2>/dev/null || true)"

if [ -z "${TEAM_ID}" ] || [ "${TEAM_ID}" = "null" ]; then
    emit_check FAIL "vercel team slug not found in authenticated user's team list: ${TEAM_SLUG}"
    fail "vercel-team-not-found"
    flush_summary
    exit 1
fi
emit_check OK "vercel team resolved (slug=${TEAM_SLUG} id=${TEAM_ID})"

# ---------------------------------------------------------------------------
# Check 7: Vercel tier detection
# ---------------------------------------------------------------------------
# 1. Primary: /v2/teams/:tid  → saml.connection present → enterprise_or_pro_saml
# 2. Secondary: resourceConfig.concurrentBuilds ≥ 12 → enterprise; ≥ 1 → pro
# 3. Fallback: /v1/teams/:tid/audit-log → 200 = enterprise; 404 = pro_or_hobby
TIER=""
TEAM_JSON="$(vercel api "/v2/teams/${TEAM_ID}" 2>/dev/null || true)"

if [ -n "${TEAM_JSON}" ]; then
    if printf '%s' "${TEAM_JSON}" | jq -e '.saml.connection // empty' >/dev/null 2>&1; then
        TIER="enterprise_or_pro_saml"
    else
        CB="$(printf '%s' "${TEAM_JSON}" | jq -r '.resourceConfig.concurrentBuilds // empty' 2>/dev/null || true)"
        if [ -n "${CB}" ] && [ "${CB}" != "null" ]; then
            # Integer compare via arithmetic; empty/non-numeric → skip.
            if [ "${CB}" -ge 12 ] 2>/dev/null; then
                TIER="enterprise"
            elif [ "${CB}" -ge 1 ] 2>/dev/null; then
                TIER="pro"
            else
                TIER="hobby"
            fi
        fi
    fi
fi

if [ -z "${TIER}" ]; then
    # Fallback probe — audit-log endpoint is Enterprise-only and 404s cleanly
    # on Pro/Hobby. `vercel api` exits non-zero on 404, so we capture the
    # response body and look for the documented error code.
    AUDIT_PROBE="$(vercel api "/v1/teams/${TEAM_ID}/audit-log?limit=1" 2>&1 || true)"
    if printf '%s' "${AUDIT_PROBE}" | jq -e '.events // .data // empty' >/dev/null 2>&1; then
        TIER="enterprise"
    else
        TIER="pro_or_hobby"
    fi
fi

emit_check OK "vercel tier detected: ${TIER}"

# ---------------------------------------------------------------------------
# Check 8: GitHub owner type + audit-log endpoint resolution
# ---------------------------------------------------------------------------
GH_AUDIT_ENDPOINT=""
if [ "${NO_GITHUB}" -eq 0 ]; then
    # /users/:uid returns type: "User" | "Organization" for both user and org
    # slugs (GitHub unifies them under the /users namespace).
    OWNER_JSON="$(gh api "/users/${GITHUB_ORG}" 2>/dev/null || true)"
    if [ -z "${OWNER_JSON}" ]; then
        emit_check FAIL "gh api /users/${GITHUB_ORG} failed (owner does not exist or no permission)"
        fail "gh-owner-probe-failed"
        flush_summary
        exit 1
    fi
    OWNER_TYPE="$(printf '%s' "${OWNER_JSON}" | jq -r '.type // empty' 2>/dev/null || true)"

    case "${OWNER_TYPE}" in
        Organization)
            GH_AUDIT_ENDPOINT="/orgs/${GITHUB_ORG}/audit-log"
            emit_check OK "github owner is Organization; audit endpoint=${GH_AUDIT_ENDPOINT}"
            ;;
        User)
            GH_AUDIT_ENDPOINT=""
            emit_check OK "github owner is User; REST audit log unavailable (documented gap)"
            ;;
        *)
            emit_check FAIL "github owner type unrecognized: '${OWNER_TYPE}'"
            fail "gh-owner-type-unknown"
            flush_summary
            exit 1
            ;;
    esac

    # Enterprise Cloud probe — only if operator supplied the slug. A 200 on
    # /enterprises/:ent/audit-log promotes GH_AUDIT_ENDPOINT to the enterprise
    # path (broader scope than /orgs/:org/audit-log).
    if [ -n "${GITHUB_ENTERPRISE_SLUG}" ]; then
        ENT_PROBE="$(gh api "/enterprises/${GITHUB_ENTERPRISE_SLUG}/audit-log?per_page=1" 2>/dev/null || true)"
        if [ -n "${ENT_PROBE}" ] && printf '%s' "${ENT_PROBE}" | jq -e 'type == "array" or has("data")' >/dev/null 2>&1; then
            GH_AUDIT_ENDPOINT="/enterprises/${GITHUB_ENTERPRISE_SLUG}/audit-log"
            emit_check OK "github enterprise audit-log accessible; endpoint=${GH_AUDIT_ENDPOINT}"
        else
            emit_check WARN "github enterprise audit-log not enrolled / no permission (falling back to org-scope)"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Check 9: case directory creation
# ---------------------------------------------------------------------------
TS="$(date -u +%Y%m%dT%H%M%SZ)"
CASE="${VF_ROOT}/case-${CASE_USER}-${CASE_HOST}-${TS}"

# Parent root: 0700, no group/other access.
if [ ! -d "${VF_ROOT}" ]; then
    if ! mkdir -m 0700 "${VF_ROOT}" 2>/dev/null; then
        emit_check FAIL "failed to create ${VF_ROOT}"
        fail "mkdir-root-failed"
        flush_summary
        exit 1
    fi
else
    # Tighten existing root in case it was created with a laxer umask earlier.
    chmod 0700 "${VF_ROOT}" 2>/dev/null || true
fi

# Case dir must not pre-exist (ISO-second resolution collision is vanishingly
# rare; we still fail-closed rather than reuse a dir we did not just create).
if [ -e "${CASE}" ]; then
    emit_check FAIL "case directory already exists: ${CASE}"
    fail "case-dir-collision"
    flush_summary
    exit 1
fi
if ! mkdir -m 0700 "${CASE}" 2>/dev/null; then
    emit_check FAIL "failed to create case directory ${CASE}"
    fail "mkdir-case-failed"
    flush_summary
    exit 1
fi
for sub in raw analysis handoff; do
    if ! mkdir -m 0700 "${CASE}/${sub}" 2>/dev/null; then
        emit_check FAIL "failed to create ${CASE}/${sub}"
        fail "mkdir-subdir-failed"
        flush_summary
        exit 1
    fi
done

# Collection-start sentinel: freeze.sh reads this to populate
# COLLECTION_START_ISO in COLLECTOR.json + CHAIN_OF_CUSTODY.md. Without it
# the custody ledger reports a meaningless zero-duration collection window.
date -u +%Y-%m-%dT%H:%M:%SZ > "${CASE}/.collection-start"

emit_check OK "case dir created: ${CASE}"

# ---------------------------------------------------------------------------
# Check 10: advisory lockfile on sha256(token)[0..16]
# ---------------------------------------------------------------------------
# Token comes in via --token-file or getpass (NOT env — Check 1 forbids that).
# We need a hash without writing the value anywhere except the lockfile name.
# _common.py::token_hash does exactly that. Read via getpass if no file.
#
# Precedence matches _common.py::get_token minus env (blocked by Check 1).
TOKEN_SOURCE="getpass"
TOKEN_VALUE=""
i=0
# Scan remaining args for --token-file; argparse above already consumed our
# own flags, but the orchestrator may pass-through --token-file here later.
# For now, prompt via getpass since preflight is typically invoked interactively.
if [ -t 0 ]; then
    # Use python3 for hidden input — `read -s` is non-POSIX but bash 3.2 has
    # it; either works. Prefer python3 for consistency with _common.py.
    TOKEN_VALUE="$(python3 -c '
import sys, getpass
try:
    t = getpass.getpass("Enter Vercel token for lockfile hash (input hidden): ").strip()
except EOFError:
    t = ""
if not t:
    sys.exit(2)
sys.stdout.write(t)
' || true)"
    if [ -z "${TOKEN_VALUE}" ]; then
        emit_check FAIL "no token provided at getpass prompt (required for advisory lock hash)"
        fail "token-getpass-empty"
        flush_summary
        exit 1
    fi
else
    emit_check FAIL "preflight requires a TTY for token getpass (non-interactive invocation not supported)"
    fail "no-tty-for-token"
    flush_summary
    exit 1
fi

# Compute sha256 prefix via _common.py to guarantee identical hashing to the
# downstream Python scripts. Pipe the value on stdin so it never hits argv
# (which ps(1) could read) or a temp file.
TOKEN_HASH="$(TOKEN_VALUE_PIPE=1 python3 -c '
import sys
sys.path.insert(0, "'"${SCRIPT_DIR}"'")
from _common import token_hash
tok = sys.stdin.read()
# getpass does not include trailing newline; be defensive anyway.
print(token_hash(tok.rstrip("\n")))
' <<<"${TOKEN_VALUE}" 2>/dev/null || true)"

# Zero out the token value from shell memory as soon as possible.
TOKEN_VALUE=""
unset TOKEN_VALUE

if [ -z "${TOKEN_HASH}" ] || [ ${#TOKEN_HASH} -ne 16 ]; then
    emit_check FAIL "token hash computation failed (_common.py::token_hash)"
    fail "token-hash-failed"
    flush_summary
    exit 1
fi

LOCK_PATH="${VF_ROOT}/.lock-${TOKEN_HASH}"
# Acquire via python3 + _common.acquire_lock so fcntl.flock semantics match
# the rest of the skill. The Python process must stay alive to hold the lock;
# we therefore spawn a tiny daemon that sleeps until preflight's caller exits.
# For preflight specifically, we just test acquirability — the orchestrator
# (collect.sh) will hold the real lock. If already held, refuse.
LOCK_CHECK="$(python3 -c '
import sys
sys.path.insert(0, "'"${SCRIPT_DIR}"'")
from _common import acquire_lock, release_lock
h = "'"${TOKEN_HASH}"'"
if not acquire_lock(h):
    print("HELD")
    sys.exit(0)
release_lock(h)
print("FREE")
' 2>/dev/null || true)"

case "${LOCK_CHECK}" in
    FREE)
        emit_check OK "advisory lockfile acquirable (${LOCK_PATH})"
        ;;
    HELD)
        emit_check FAIL "advisory lockfile held by another process: ${LOCK_PATH}"
        fail "lock-held"
        flush_summary
        exit 1
        ;;
    *)
        emit_check FAIL "advisory lockfile probe failed (unexpected output: '${LOCK_CHECK}')"
        fail "lock-probe-failed"
        flush_summary
        exit 1
        ;;
esac

# ---------------------------------------------------------------------------
# Export environment for downstream scripts (collect.sh et al.)
# ---------------------------------------------------------------------------
# preflight.sh is usually `source`-d by the orchestrator; when run as a
# standalone (exec) it still prints the exports so an operator can `eval` them
# or pass them explicitly to collect.sh.
export CASE
export TIER
export TEAM_ID
export TEAM_SLUG
export GH_AUDIT_ENDPOINT
export VF_TOKEN_SOURCE="${TOKEN_SOURCE}"

printf '\n# ----- preflight exports (source or eval) -----\n'
printf 'export CASE=%q\n' "${CASE}"
printf 'export TIER=%q\n' "${TIER}"
printf 'export TEAM_ID=%q\n' "${TEAM_ID}"
printf 'export TEAM_SLUG=%q\n' "${TEAM_SLUG}"
printf 'export GH_AUDIT_ENDPOINT=%q\n' "${GH_AUDIT_ENDPOINT}"
printf 'export VF_TOKEN_SOURCE=%q\n' "${TOKEN_SOURCE}"
printf '# -----------------------------------------------\n\n'

flush_summary
exit 0
