# Tool Setup Reference

Dependency installation guide and verification commands for kcap.

## Required (pre-installed on macOS)

| Tool | Purpose | Verify |
|------|---------|--------|
| `bash 3.2+` | Shell execution | `bash --version` |
| `curl` | HTTP requests, fallback extraction | `curl --version` |
| `python3` | URL parsing, text processing | `python3 --version` |

These are pre-installed on macOS. No action needed.

## Content Extraction Tools

### Web Articles

**trafilatura** (primary — recommended):
```bash
pip install trafilatura
# or
pip3 install trafilatura
```

Verify: `trafilatura --version`

**html2text** (fallback):
```bash
pip install html2text
# or
pip3 install html2text
```

Verify: `echo '<h1>test</h1>' | html2text`

### YouTube

**youtube-transcript-api** (primary — recommended):
```bash
pip install youtube-transcript-api
# or
pip3 install youtube-transcript-api
```

Verify: `youtube_transcript_api --help`

**yt-dlp** (fallback for transcripts + metadata):
```bash
pip install yt-dlp
# or
brew install yt-dlp
```

Verify: `yt-dlp --version`

### Twitter/X

**bird-cli** (required — no fallback):
```bash
# Install via Homebrew
brew install steipete/formulae/bird

# Or build from source
git clone https://github.com/steipete/bird.git
cd bird && swift build -c release
cp .build/release/bird /usr/local/bin/
```

Verify: `bird --version`

**Note:** bird-cli requires a Twitter/X account configured. See the [ai-twitter-radar skill](../../ai-twitter-radar/SKILL.md) for setup guidance.

**Authentication:** bird-cli uses browser cookies from Safari, Chrome, or Firefox
for Twitter/X authentication. Ensure you are logged into Twitter/X in one of these
browsers before using kcap's Twitter capture.

## Quick Install (minimum viable)

For basic web + YouTube capture:
```bash
pip install trafilatura youtube-transcript-api
```

For full functionality including Twitter:
```bash
pip install trafilatura youtube-transcript-api yt-dlp
brew install steipete/formulae/bird
```

## Tool Availability Check

The main agent checks tool availability at the start of each capture and reports capabilities:

| Tool Present | Capability |
|-------------|------------|
| trafilatura | Web article capture (primary) |
| html2text | Web article capture (fallback) |
| youtube-transcript-api | YouTube transcript capture (primary) |
| yt-dlp | YouTube transcript (fallback) + metadata |
| bird | Twitter/X capture |

**Capability reporting format:**
```
kcap capabilities:
  Web articles:  trafilatura (primary) + html2text (fallback)
  YouTube:       youtube-transcript-api (primary) + yt-dlp (fallback + metadata)
  Twitter/X:     bird-cli
  Missing:       [list of unavailable tools with install commands]
```

If ALL extraction tools for a content type are missing, report the install commands and fail for that content type only.
