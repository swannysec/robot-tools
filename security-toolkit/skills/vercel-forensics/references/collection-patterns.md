# Collection Patterns

Reusable collection idioms plus the full IOC regex list consumed by `scripts/build-log-scan.py`. Read this before editing any collection script. Companion files: `api-endpoint-reference.md` (what endpoints exist), `data-inventory.md` (what data they return), `vercel-cli-quirks.md` (known bugs).

## Table of contents

1. [Activity-log paginator](#activity-log-paginator)
2. [`vercel api --paginate`](#vercel-api---paginate)
3. [Parallel per-project pulls](#parallel-per-project-pulls)
4. [Background jobs for long pulls](#background-jobs-for-long-pulls)
5. [Rate-limit recovery (GitHub audit log)](#rate-limit-recovery-github-audit-log)
6. [Redaction before disk-write](#redaction-before-disk-write)
7. [JSON repair after truncation](#json-repair-after-truncation)
8. [Build-log pulls](#build-log-pulls)
9. [IOC regex list for `build-log-scan.py`](#ioc-regex-list-for-build-log-scanpy)

## Activity-log paginator

The `vercel activity` (`/v3/events`) endpoint caps at 100 events per page and requires hand-rolled pagination. Cursor is `.pagination.next` — a millisecond-epoch value passed as `--next <cursor>`. Honor three safety rails:

- **Throttle to 50 req/min** (ceiling is 60; leave 10 for retries). Sleep 1.2s between pages.
- **Per-page HTTP timeout: 60s** via the portable watchdog pattern in ADR-004 (no GNU `timeout`; use `&` + `kill` loop).
- **Idle-progress watchdog: 5 min.** If no new events observed for 5 minutes, abort and emit a partial flag to `scan-errors.txt`. Empty pages under load are the CLI bug described in `vercel-cli-quirks.md`.

Support `RESUME_FROM=<cursor>` so an interrupted run can be continued without losing earlier pages.

```bash
#!/usr/bin/env bash
set -euo pipefail

OUT_JSONL="${OUT_JSONL:-activity-90d.jsonl}"
: > "$OUT_JSONL"

NEXT="${RESUME_FROM:-}"
PAGE=0
MAX_PAGES=500
LAST_PROGRESS=$(date +%s)      # BSD-safe; do NOT use $EPOCHSECONDS
IDLE_LIMIT=300                 # 5-min watchdog

while :; do
  PAGE=$((PAGE + 1))

  # 60s per-page timeout (ADR-004 pattern; gtimeout not guaranteed)
  if [ -z "$NEXT" ]; then
    RESP=$(vercel activity --all --since 90d --format json --limit 100) || break
  else
    RESP=$(vercel activity --all --since 90d --format json --limit 100 --next "$NEXT") || break
  fi

  COUNT=$(echo "$RESP" | jq '.events | length')
  echo "$RESP" | jq -c '.events[]' >> "$OUT_JSONL"
  NEXT=$(echo "$RESP" | jq -r '.pagination.next // empty')

  NOW=$(date +%s)
  if [ "$COUNT" -gt 0 ]; then LAST_PROGRESS=$NOW; fi
  if [ $((NOW - LAST_PROGRESS)) -ge "$IDLE_LIMIT" ]; then
    echo "activity-paginate: idle watchdog tripped at page $PAGE (last cursor=$NEXT)" >> scan-errors.txt
    touch .partial
    break
  fi

  [ -z "$NEXT" ] && break
  [ "$PAGE" -ge "$MAX_PAGES" ] && break
  sleep 1.2                    # ≤50 req/min
done
```

The `.partial` flag propagates into the freeze manifest so downstream analysis knows the activity window is incomplete.

## `vercel api --paginate`

For endpoints that follow Vercel's standard pagination protocol (`Link` headers plus `.pagination.next`). Handles both automatically and emits one merged JSON array:

```bash
vercel api "/v6/deployments?projectId=$PID&teamId=$TEAM_ID" --paginate > deployments.json
vercel api "/v5/domains?teamId=$TEAM_ID" --paginate > domains.json
```

**Truncation risk:** if the CLI hits a 429 or network hiccup mid-pull, the output file may be malformed — see [JSON repair after truncation](#json-repair-after-truncation). Always validate with `jq empty` before declaring a pull good.

## Parallel per-project pulls

Run multiple endpoints per project concurrently with shell `&` + `wait`. Keeps wall-clock bounded on Pro teams (5 endpoints × 7 projects ≈ 15-30s):

```bash
for row in $(jq -r '.[] | "\(.name)|\(.id)"' projects-full.json); do
  NAME="${row%%|*}"; PID="${row##*|}"; DIR="projects/$NAME"; mkdir -p "$DIR"
  vercel api "/v6/deployments?projectId=$PID&teamId=$TEAM_ID" --paginate 2>/dev/null > "$DIR/deployments.json" &
  vercel api "/v9/projects/$PID/env?teamId=$TEAM_ID"           2>/dev/null > "$DIR/env.json" &
  vercel api "/v1/projects/$PID/domains?teamId=$TEAM_ID"       2>/dev/null > "$DIR/domains.json" &
  vercel logs --project "$NAME" --json --since 24h --limit 1000 2>/dev/null > "$DIR/logs.json" &
  wait
done
```

`2>/dev/null` is required — `vercel project ls --json` and several other sub-commands mix progress text on stderr with JSON on stdout (see `vercel-cli-quirks.md`).

## Background jobs for long pulls

GitHub's REST audit log on a dense org routinely runs 5-15+ minutes. Use one of:

- **Agent context:** pass `run_in_background: true` to the Bash tool so the shell returns immediately. Poll with `ls -lh` or `wc -l`.
- **Shell:** `nohup` + `&`.

```bash
nohup gh api "/orgs/<org>/audit-log?phrase=created:>=2026-01-19&per_page=100" --paginate \
  > audit.json 2> audit.err &
echo $! > audit.pid
```

Do not block collection orchestration on these. `collect.sh` launches them, moves on to other phases, and joins at freeze time.

## Rate-limit recovery (GitHub audit log)

GitHub's audit log rate-limits aggressively on busy orgs (~18-19 days of dense activity is the observed ceiling). The failure mode is ugly: the error is **not** a clean HTTP 403. `gh api --paginate` appends a `{"message":"API rate limit exceeded..."}` object **after the last good JSON element**, leaving a malformed file.

Typical truncated tail: `..., {...last good event...}, {"message":"API rate limit exceeded...","status":"403"}`

Repair with `JSONDecoder.raw_decode` to find the last valid boundary, strip the 403 object, and close the array:

```python
import json

data = open('audit.json').read()
marker = data.find('{"message":"API rate limit exceeded')
if marker > 0:
    before = data[:marker].rstrip().rstrip(',')
    fixed = (before + ']') if before.endswith('}') else (before + '}]')
    events = json.loads(fixed)
    with open('audit.json', 'w') as f:
        f.write(fixed)
    print(f"Recovered {len(events)} events")
```

Reset window is 1 hour. Resume with a date-range chunk bounded by the oldest captured event:

```bash
gh api "/orgs/<org>/audit-log?phrase=created:<$OLDEST_CAPTURED_DATE&per_page=100" --paginate \
  > audit-gap.json
```

Merge the two partial files post-hoc. Record both the abort and resume in `scan-errors.txt` so the freeze manifest accounts for gap boundaries.

## Redaction before disk-write

Redaction happens **in memory before the first write**, not post-hoc on frozen files. `scripts/redact.py` loads the response, matches patterns, substitutes `[REDACTED-<len>char-<kind>]`, and only then calls `atomic_write`. A sidecar `redactions.log` records paths + counts (never values).

**Patterns implemented by `redact.py`:**

- **Discord webhook tokens** — `https://discord.com/api/webhooks/<id>/<token>/github`; `<token>` path segment is the secret.
- **Zulip API keys** — `?api_key=<value>` query param.
- **Generic query-string secrets** — `?token=`, `?api_key=`, `?apikey=`, `?secret=`, `?access_token=`, `?key=`.
- **AWS pre-signed URLs** — `X-Amz-Signature=...`, `X-Amz-Credential=...` query params.
- **Slack webhooks** — `hooks.slack.com/services/T.../B.../...` path.
- **GitHub PATs** — prefixes `ghp_`, `github_pat_`, `gho_`, `ghu_`, `ghs_`.
- **Stripe keys** — prefixes `sk_live_`, `rk_live_`, `whsec_`.
- **JWTs (three segments)** — regex `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`.
- **Basic-Auth URLs** — `https://user:pass@host`.
- **Azure storage SAS tokens** — `?sv=...&sig=...` and adjacent SAS params.
- **GCP service-account inline keys** — `"private_key":"-----BEGIN PRIVATE KEY-----..."`.
- **High-entropy base64 blobs** — opt-in, threshold-based (Shannon entropy ≥ 4.5 over ≥ 40 chars).
- **Internal IPv4/IPv6** — RFC 1918 ranges + IPv6 ULA (`fc00::/7`) + link-local.

Example URL redactor (Discord + query secrets):

```python
import re, urllib.parse

QUERY_SECRET_KEYS = {'api_key', 'apikey', 'token', 'secret', 'access_token', 'key'}

def redact_url(url: str) -> str:
    m = re.match(r'^(https://discord\.com/api/webhooks/\d+/)([^/]+)(.*)$', url)
    if m:
        url = f"{m.group(1)}[REDACTED-{len(m.group(2))}char-discord]{m.group(3)}"
    if '?' in url:
        base, qs = url.split('?', 1)
        params = urllib.parse.parse_qsl(qs, keep_blank_values=True)
        cleaned = [
            (k, f"[REDACTED-{len(v)}char-qs]" if k.lower() in QUERY_SECRET_KEYS else v)
            for k, v in params
        ]
        url = base + '?' + urllib.parse.urlencode(cleaned)
    return url
```

## JSON repair after truncation

Common when `gh api --paginate` or a long `vercel api --paginate` is interrupted. Walk the buffer with `JSONDecoder.raw_decode`; handle the case where the CLI concatenated multiple arrays:

```python
import json

def recover(path: str) -> list:
    data = open(path).read()
    dec = json.JSONDecoder()
    pos, events = 0, []
    while pos < len(data):
        try:
            obj, end = dec.raw_decode(data, pos)
            if isinstance(obj, list):
                events.extend(obj)
            elif isinstance(obj, dict):
                events.append(obj)
            pos = end
            while pos < len(data) and data[pos] in ' \n\t\r':
                pos += 1
        except json.JSONDecodeError:
            break
    return events
```

Always write the repaired payload back atomically via `_common.py::atomic_write` and log the recovery event.

## Build-log pulls

Per-deployment build events at `/v3/deployments/:uid/events?builds=1`. There is **no bulk endpoint** — one HTTP call per deployment. Parallelizing via shell `&` has been observed to hit "failed to change user ID" OS errors under some macOS sandbox policies, so serial Python is the robust path:

```python
import subprocess, json, os

team = os.environ['TEAM_ID']
deps = json.load(open('deploys.json'))
os.makedirs('build_logs', exist_ok=True)

for d in deps:
    uid = d['uid']
    r = subprocess.run(
        ['vercel', 'api', f'/v3/deployments/{uid}/events?teamId={team}&builds=1'],
        capture_output=True, text=True, timeout=60,
    )
    open(f'build_logs/{uid}.json', 'w').write(r.stdout)
```

At ~1s per deployment, 24 deploys take ~25s serial. Build logs are immutable per deployment — unlike runtime logs, they do not expire within 24h (documented limitation captured in `data-inventory.md`).

## IOC regex list for `build-log-scan.py`

`scripts/build-log-scan.py` imports this catalogue and scans concatenated build-event `text` fields. Each pattern is tagged `high` (auto-flag) or `noise` (count but do not flag without a paired high-signal hit in the same log).

### Network-tool-pipe-shell (high)

Payload fetch + execute is the classic supply-chain IOC.

- `\bcurl\b.*\|\s*(ba)?sh`
- `\bwget\b.*\|\s*(ba)?sh`
- `\bnc\b` (standalone — may be a legitimate tool name, verify context)
- `\bnetcat\b`

### Lifecycle-script indicators (noise)

`postinstall` / `preinstall` strings are normal in npm output ("no postinstall script" echoes). Count, but flag only when paired with a network-tool, decode, or dynamic-exec hit in the same log.

- `postinstall`
- `preinstall`

### Encoded-payload decode (high)

Rarely legitimate in a Next.js / Node build output.

- `\bbase64\s+-d\b`
- `\bbase64\s+--decode\b`
- `\batob\s*\(`

### Dynamic code execution (high)

- `\beval\s*\(`
- `\bnew\s+Function\s*\(\s*["']`
- `\bFunction\s*\(\s*["']`
- `\bnode\s+-e\s+`

### Literal env-var echoes (high)

Env values leaking into stdout is the precise failure mode of the 2026-04-19 incident class.

- `process\.env\.[A-Z_]+\s*[,\)\}]`
- `\$[A-Z_]+\b.*>>?\s*(/dev/stdout|console|log)`

### Suspicious outbound hosts (high)

Extract hosts via `https?://([a-z0-9][a-z0-9.-]+\.[a-z]{2,})` and histogram. Known-good allowlist: `vercel.com`, `vercel.app`, `github.com`, `githubusercontent.com`, `registry.npmjs.org`, `registry.yarnpkg.com`, `pypi.org`, `pythonhosted.org`, `nextjs.org`, `jsdelivr.net`, `unpkg.com`.

Explicitly flag as high:

- TLDs in `{.tk, .ml, .ga, .cf, .gq, .xyz, .top}` (historically abused free TLDs).
- Paste services: `pastebin.com`, `paste.ee`, `hastebin.com`, `rentry.co`, `termbin.com`, `transfer.sh`.
- Tunneling / dynamic DNS: `ngrok.io`, `ngrok-free.app`, `trycloudflare.com`, `loca.lt`, `serveo.net`.
- Raw IP literals in URLs — `\bhttps?://\d{1,3}(\.\d{1,3}){3}\b`.

Unknown-but-not-explicitly-bad hosts are tagged `medium` and included in the histogram.

### NPM/PyPI postinstall shell-outs (high)

Combines the lifecycle-script noise pattern with a high-signal verb on the same line — canonical detection for npm-postinstall-exfil.

- `postinstall.*\b(curl|wget|nc|bash|sh|python|node)\b`
- `preinstall.*\b(curl|wget|nc|bash|sh|python|node)\b`

### Scan output contract

`build-log-scan.py` emits per-pattern hit counts (grouped by severity tag), a host histogram (top 20 + all flagged hosts), and a per-file summary in `analysis/build-log-scan.md`. Noise-only matches never auto-flag; a finding requires at least one `high` hit or a `postinstall` + `high` pairing in the same log.
