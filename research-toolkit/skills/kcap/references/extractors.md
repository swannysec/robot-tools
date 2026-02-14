# Extractors Reference

Reference document for kcap URL validation, type detection, normalization, and content extraction.

## URL Validation (CRITICAL)

All URLs must pass these checks before any processing:

### Scheme Validation

Only `https://` is accepted. Reject with clear message:
- `http://` — "Only https:// URLs supported. Did you mean https://...?"
- `file://` — "Local file URLs are not supported"
- `javascript:` — "Invalid URL scheme"
- `data:` — "Invalid URL scheme"
- All other schemes — "Only https:// URLs supported"

### Control Character & Injection Detection

Reject URLs containing any of:
- Backticks (`` ` ``)
- Command substitution (`$()` or `` `...` ``)
- Semicolons (`;`)
- Pipes (`|`)
- Ampersands (`&`)
- Newlines (`\n`, `\r`)
- Null bytes (`\x00`)

**Validation regex** (bash):
```bash
if [[ "$URL" =~ [\`\;\|\&\$\(] ]] || [[ "$URL" =~ $'\n' ]] || [[ "$URL" =~ $'\r' ]] || [[ "$URL" =~ $'\x00' ]]; then
  echo "ERROR: URL contains potentially dangerous characters"
  exit 1
fi
```

### SSRF Blocking

Reject URLs resolving to private/reserved IP ranges:

| Range | Description |
|-------|-------------|
| `localhost` | Loopback hostname |
| `127.0.0.0/8` | IPv4 loopback |
| `::1` | IPv6 loopback |
| `10.0.0.0/8` | RFC 1918 private |
| `172.16.0.0/12` | RFC 1918 private |
| `192.168.0.0/16` | RFC 1918 private |
| `169.254.0.0/16` | Link-local (cloud metadata endpoint) |
| `0.0.0.0` | Unspecified address |

**Hostname extraction + resolution check** (bash):
```bash
# Extract hostname from URL (safe — passed via argv, not interpolated into code)
URL_HOSTNAME=$(python3 -c "
import sys
from urllib.parse import urlparse
print(urlparse(sys.argv[1]).hostname or '')
" "$URL")

# Resolve hostname and check against private ranges
RESOLVED_IP=$(python3 -c "
import socket, sys
print(socket.gethostbyname(sys.argv[1]))
" "$URL_HOSTNAME" 2>/dev/null)

if [[ "$RESOLVED_IP" =~ ^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|169\.254\.|0\.0\.0\.0|::1) ]]; then
  echo "ERROR: URL resolves to private/reserved IP ($RESOLVED_IP). This may be an SSRF attempt."
  exit 1
fi
```

### Argument Injection Prevention

Use `--` before positional URL arguments. For tools that accept the URL via a named
flag (like trafilatura's `-u`), the flag syntax itself prevents injection:
```bash
trafilatura --markdown -u "$URL"       # URL via named -u flag — no -- needed
curl -sL --max-redirs 3 --proto =https -- "$URL"   # URL is positional — -- required
yt-dlp --dump-json --skip-download -- "$URL"        # URL is positional — -- required
bird thread -- "$URL"                               # URL is positional — -- required
```

---

## URL Type Detection

Apply regex patterns to the validated URL to determine content type:

```bash
# Twitter/X detection
if [[ "$URL" =~ ^https://(www\.)?(twitter\.com|x\.com)/.+/status/[0-9]+ ]]; then
  CONTENT_TYPE="tweet"

# YouTube detection (watch, shorts, youtu.be)
elif [[ "$URL" =~ ^https://(www\.)?youtube\.com/watch ]] || \
     [[ "$URL" =~ ^https://youtu\.be/ ]] || \
     [[ "$URL" =~ ^https://(www\.)?youtube\.com/shorts/ ]]; then
  CONTENT_TYPE="video"

# Everything else is a web page
else
  CONTENT_TYPE="article"
fi
```

---

## URL Normalization (for duplicate detection)

Normalize URLs before checking for duplicates to catch equivalent URLs:

### General normalization
1. Strip scheme (`https://`)
2. Strip `www.` prefix
3. Strip trailing slash
4. Strip tracking parameters: `utm_source`, `utm_medium`, `utm_campaign`, `utm_content`, `utm_term`, `feature`, `ref`, `ref_src`, `t`, `si`, `s`, `fbclid`, `gclid`
5. Lowercase the hostname

### YouTube normalization
Extract video ID and normalize to canonical form:
```bash
# From: https://www.youtube.com/watch?v=dQw4w9WgXcQ&feature=shared&t=42
# From: https://youtu.be/dQw4w9WgXcQ?si=abc123
# From: https://www.youtube.com/shorts/dQw4w9WgXcQ
# To:   youtube:dQw4w9WgXcQ

VIDEO_ID=$(echo "$URL" | python3 -c "
import sys, re
from urllib.parse import urlparse, parse_qs
url = sys.stdin.read().strip()
parsed = urlparse(url)
if 'youtu.be' in parsed.hostname:
    vid = parsed.path.lstrip('/')
elif '/shorts/' in parsed.path:
    vid = parsed.path.split('/shorts/')[1].split('/')[0]
else:
    vid = parse_qs(parsed.query).get('v', [''])[0]
print(vid)
")
NORMALIZED="youtube:$VIDEO_ID"
```

### Twitter/X normalization
Extract status ID and normalize:
```bash
# From: https://twitter.com/user/status/123456789
# From: https://x.com/user/status/123456789?s=20
# To:   twitter:123456789

STATUS_ID=$(echo "$URL" | python3 -c "
import sys, re
url = sys.stdin.read().strip()
match = re.search(r'/status/(\d+)', url)
print(match.group(1) if match else '')
")
NORMALIZED="twitter:$STATUS_ID"
```

### Web page normalization
```bash
# From: https://www.example.com/article?utm_source=twitter&ref=homepage
# To:   example.com/article

NORMALIZED=$(echo "$URL" | python3 -c "
import sys
from urllib.parse import urlparse, urlencode, parse_qs
url = sys.stdin.read().strip()
parsed = urlparse(url)
host = parsed.hostname
if host.startswith('www.'):
    host = host[4:]
# Remove tracking params
params = {k: v for k, v in parse_qs(parsed.query).items()
          if k not in ('utm_source','utm_medium','utm_campaign','utm_content',
                       'utm_term','feature','ref','ref_src','t','si','s','fbclid','gclid')}
query = urlencode(params, doseq=True)
path = parsed.path.rstrip('/')
result = host + path
if query:
    result += '?' + query
print(result)
")
```

### Duplicate check command
```bash
grep -Frl "source_normalized: \"$NORMALIZED\"" "$OUTPUT_DIR" 2>/dev/null
```

---

## Content Extraction

### Temp Directory Setup

All extraction work happens in a unique temp directory:
```bash
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/kcap-XXXXXXXX")
chmod 700 "$WORK_DIR"
```

Cleanup is handled by the main agent after processing (rm -rf of the WORK_DIR).

### Web Pages

**Primary — trafilatura:**
```bash
trafilatura --markdown -u "$URL" > "$WORK_DIR/content.txt" 2>/dev/null
```

**Fallback — curl + html2text:**
```bash
curl -sL --max-time 60 --max-redirs 3 --proto =https -- "$URL" 2>/dev/null | html2text > "$WORK_DIR/content.txt" 2>/dev/null
```

**Validation:**
```bash
WORD_COUNT=$(wc -w < "$WORK_DIR/content.txt" | tr -d ' ')
if [ "$WORD_COUNT" -lt 50 ]; then
  echo "ERROR: Extraction returned only $WORD_COUNT words (minimum: 50)"
  exit 1
fi
```

### YouTube Videos

**Primary — youtube-transcript-api:**
```bash
youtube_transcript_api "$VIDEO_ID" --format text > "$WORK_DIR/content.txt" 2>/dev/null
```

**Fallback — yt-dlp subtitle extraction:**
```bash
yt-dlp --write-auto-subs --sub-lang en --skip-download --sub-format srv1 \
  -o "$WORK_DIR/subs" -- "$URL" 2>/dev/null

# Convert SRT/SRV to plain text (strip timestamps and formatting)
# Note: file path passed via sys.argv to avoid shell interpolation into Python code
python3 -c "
import re, sys
with open(sys.argv[1], 'r') as f:
    text = f.read()
# Strip XML/SRT tags and timestamps
text = re.sub(r'<[^>]+>', '', text)
text = re.sub(r'\d{2}:\d{2}:\d{2}[.,]\d{3}', '', text)
text = re.sub(r'-->.*', '', text)
text = re.sub(r'^\d+$', '', text, flags=re.MULTILINE)
text = re.sub(r'\n{3,}', '\n\n', text)
print(text.strip())
" "$WORK_DIR/subs.en.srv1" > "$WORK_DIR/content.txt"
```

**Language limitation:** `--sub-lang en` restricts extraction to English subtitles.
Videos with only non-English subtitles will fail if youtube-transcript-api also fails.

**Metadata (always attempt):**
```bash
yt-dlp --dump-json --skip-download -- "$URL" > "$WORK_DIR/metadata.json" 2>/dev/null
```

Fields to extract from metadata JSON:
- `title` — video title
- `uploader` / `channel` — channel name
- `duration` — duration in seconds (convert to HH:MM:SS)
- `upload_date` — publication date (YYYYMMDD format)
- `chapters` — array of `{start_time, title}` objects

If yt-dlp metadata unavailable, the synthesis sub-agent infers title/channel from transcript context.

### Twitter/X

**Primary — bird-cli:**
```bash
bird thread -- "$URL" > "$WORK_DIR/content.txt" 2>/dev/null
```

No fallback — bird-cli is the only supported extraction tool for Twitter/X. If unavailable, fail with install instructions (see tool-setup.md).

---

## Content Size Limits

After extraction, check content size:

```bash
WORD_COUNT=$(wc -w < "$WORK_DIR/content.txt" | tr -d ' ')
```

| Condition | Action |
|-----------|--------|
| <50 words | FAIL: "No meaningful content extracted" |
| 50-15,000 words | Process normally |
| >15,000 words | Truncate to first 15,000 words; add note to sub-agent prompt |
| >15,000 words + deep mode | Warn user of estimated cost before proceeding |

**Truncation** (UTF-8 safe — entire operation in Python):
```bash
if [ "$WORD_COUNT" -gt 15000 ]; then
  mv "$WORK_DIR/content.txt" "$WORK_DIR/content_full.txt"
  python3 -c "
import sys
with open(sys.argv[1], 'r') as f:
    text = f.read()
words = text.split()
print(' '.join(words[:15000]))
" "$WORK_DIR/content_full.txt" > "$WORK_DIR/content.txt"
fi
```
