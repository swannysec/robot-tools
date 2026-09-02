# Extraction and URL handling

Use `scripts/kcap.py`; do not reconstruct extraction commands in the host agent.

## URL rules

- Accept only `https://` URLs with a hostname and no embedded credentials.
- Reject control characters and shell metacharacters.
- Resolve every original hostname and reject any non-global IPv4 or IPv6 address.
- Fetch articles with curl pinned to one validated address. Inspect each redirect
  without following it, require HTTPS, re-resolve and revalidate its destination, and
  stop after three redirects.
- Pass URLs to subprocesses as argument-array elements after option terminators where
  supported. The helper never invokes a shell.
- Normalize YouTube URLs to `youtube:<video-id>` and Twitter/X URLs to
  `twitter:<status-id>`.
- Normalize article URLs by lowercasing the host, removing `www.`, default port and
  trailing slash, and dropping known tracking parameters.

`validate-url` performs DNS checks by default. `--no-resolve` exists only for offline
fixture testing and must not be used before live extraction.

## Extraction routes

| Content | Primary | Fallback |
|---|---|---|
| Article | Pinned HTTPS `curl` fetch, then local `trafilatura` parsing | Local `html2text` parsing of the same fetched body |
| YouTube | `youtube_transcript_api` | English VTT subtitles from `yt-dlp` |
| Twitter/X | `bird thread` | None |

For YouTube, `yt-dlp` is also used opportunistically for title, channel, duration,
publication date, and chapters. These values remain in untrusted `metadata.json`; the
host agent must not read them.

The helper requires at least 50 words. Standard and deep modes truncate to 15,000
words after recording `original_word_count`; full mode preserves the complete content
only within the 10 MiB extraction and synthesis limit. All artifacts are UTF-8 files
under the caller-provided private work directory.

Article redirects never reach `trafilatura`; it processes the already fetched local
body. Pinning curl to a validated address prevents a second DNS lookup from changing
the destination between validation and connection.
