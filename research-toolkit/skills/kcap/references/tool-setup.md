# Local dependencies

kcap requires Python 3.9 or newer and one extraction route for the requested content.
It does not install tools automatically.

| Command | Capability |
|---|---|
| `curl` | Required secure article fetch with pinned DNS and validated redirects |
| `trafilatura` | Primary local article parsing |
| `html2text` | Local article parsing fallback |
| `youtube_transcript_api` | Primary YouTube transcript extraction |
| `yt-dlp` | YouTube subtitle fallback and metadata |
| `bird` | Twitter/X thread extraction using local browser authentication |
| `claude` | Required only for synthesis through Claude Code |
| `codex` | Required only for synthesis through Codex desktop |

Typical macOS installation commands are:

```text
python3 -m pip install trafilatura html2text youtube-transcript-api yt-dlp
brew install steipete/formulae/bird
```

Verify only the tools needed for the requested URL. A missing primary tool is acceptable
when its fallback is installed. Twitter/X has no supported fallback. Codex and Claude
authentication remain host-managed and are never read from this skill's configuration.
