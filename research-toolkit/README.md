# Research Toolkit

AI/ML research and verification tools for software development.

## Features

### Skills

| Skill | Description |
|-------|-------------|
| `ai-dev-research` | World-expert technical research on AI-enabled software development topics. Covers RAG architectures, agentic workflows, LLM integration, embeddings, and AI coding tools. |
| `ai-twitter-radar` | Discover trending AI tools, news, and insights from influential developers and AI advocates on Twitter/X using Bird CLI. Read-only skill for research and discovery. |
| `research-verification` | Pre-flight verification checklist for research tasks. Prevents assumptions from becoming errors when gathering information about external systems, APIs, or configurations. |
| `kcap` | Capture and distill knowledge from URLs into structured markdown notes. Supports web articles, YouTube videos, and Twitter/X posts with dual-agent security architecture. |

## Installation

### Via Marketplace

```bash
/plugin marketplace add https://github.com/swannysec/robot-tools
/plugin install research-toolkit@robot-tools
```

### Manual Installation

```bash
git clone https://github.com/swannysec/robot-tools.git
cd robot-tools
cc --plugin-dir ./research-toolkit
```

## Usage

Skills activate automatically via trigger phrases:

**ai-dev-research**:
- `"research AI"`, `"AI research"`
- `"compare LLMs"`, `"which model should I use"`
- `"RAG architecture"`, `"agentic workflow"`
- `"AI coding tools"`, `"best practices for AI development"`

**ai-twitter-radar**:
- `"AI Twitter"`, `"trending AI tools"`, `"AI news from Twitter"`
- `"what are AI developers saying"`, `"AI tweets"`

**research-verification**:
- `"verify research"`, `"check assumptions"`, `"validate findings"`

**kcap**:
- `"capture this url"`, `"save this article"`, `"kcap"`
- `"knowledge capture"`, `"distill this"`, `"save to obsidian"`
- `"capture this video"`, `"capture this tweet"`, `"save this for later"`

> **kcap vs ai-twitter-radar:** Use kcap to save/distill a specific URL to a structured note. Use ai-twitter-radar to browse, discover, or search AI tweets.

### Example Commands

```
"Research the current state of RAG architectures"
"Compare Claude, GPT-4, and Gemini for code generation"
"Verify my research on vector databases"
"What's the best approach for building an agentic workflow?"
"What are AI developers saying on Twitter about Claude?"
"Find trending AI tools on Twitter"
"kcap https://example.com/some-article"
"Capture this YouTube video: https://www.youtube.com/watch?v=dQw4w9WgXcQ"
"kcap https://x.com/user/status/123456789 focus on the tooling recommendations"
"kcap --deep https://example.com/long-analysis"
```

## Requirements

- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) CLI
- [Bird CLI](https://github.com/steipete/bird) (for ai-twitter-radar and kcap Twitter capture)
- [trafilatura](https://trafilatura.readthedocs.io/) (for kcap web article extraction)
- [youtube-transcript-api](https://github.com/jdepoix/youtube-transcript-api) (for kcap YouTube capture)

**Optional (fallback tools):**
- [html2text](https://pypi.org/project/html2text/) (fallback for web extraction when trafilatura unavailable)
- [yt-dlp](https://github.com/yt-dlp/yt-dlp) (fallback for YouTube transcripts + metadata extraction)

## License

[MIT License with Commercial Restriction](../LICENSE)
