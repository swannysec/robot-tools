# Research Toolkit

AI/ML research and verification tools for software development.

## Features

### Skills

| Skill | Description |
|-------|-------------|
| `ai-dev-research` | World-expert technical research on AI-enabled software development topics. Covers RAG architectures, agentic workflows, LLM integration, embeddings, and AI coding tools. |
| `ai-twitter-radar` | Discover trending AI tools, news, and insights from influential developers and AI advocates on Twitter/X using Bird CLI. Read-only skill for research and discovery. |
| `research-verification` | Pre-flight verification checklist for research tasks. Prevents assumptions from becoming errors when gathering information about external systems, APIs, or configurations. |
| `kcap` | Capture and distill web articles, public YouTube videos, and Twitter/X posts into structured Markdown notes. The same self-contained package supports Claude Code and local Codex in the ChatGPT/Codex desktop app. |
| `starduster` | Catalog GitHub starred repos into a structured Obsidian vault with AI-synthesized summaries, normalized topic taxonomy, graph-optimized wikilinks, and Obsidian Bases index files. The same self-contained package supports Claude Code and local Codex in the ChatGPT/Codex desktop app. |

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

### Direct portable skill installation

The canonical packages are `research-toolkit/skills/kcap` and
`research-toolkit/skills/starduster`. Copy a complete directory unchanged to
`.claude/skills/<skill-name>` for a Claude Code project or
`$CODEX_HOME/skills/<skill-name>` for Codex desktop (normally
`~/.codex/skills/<skill-name>`). An optional distributor may use another
host-recognized shared root after verifying it. Direct installation requires neither
the plugin checkout nor hplumb. ChatGPT on the web is not supported by this profile.

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

kcap uses `~/.config/robot-tools/research-toolkit.json` with `schema_version: 1`. `RESEARCH_TOOLKIT_CONFIG` selects an alternate file, `RESEARCH_TOOLKIT_RUNTIME=claude|codex` provides an explicit runtime override, `RESEARCH_TOOLKIT_CODEX_AUTH=auto|oauth|api_key` selects Codex authentication, and `RESEARCH_TOOLKIT_NONINTERACTIVE=1` selects the controller's noninteractive duplicate and confirmation policies. The controller never opens Obsidian. Project `.claude/research-toolkit.local.md` remains readable through the `0.6.x` compatibility period and emits a migration notice. See [the package configuration reference](./skills/kcap/references/configuration.md) for the authentication and migration behavior.

**starduster**:
- `"catalog my github stars"`, `"starduster"`, `"export github stars"`
- `"github stars to obsidian"`, `"index my starred repos"`, `"organize my github stars"`
- `"starred repos catalog"`, `"star catalog"`, `"summarize my stars"`, `"what have I starred"`
- `"obsidian github stars"`, `"starred repo notes"`

starduster uses the same neutral configuration file and runtime/authentication selectors
as kcap. Its deterministic `sync` controller fetches stars through the authenticated
GitHub CLI, returns confirmation instructions when estimated rate use is high, and never
opens Obsidian. The legacy project configuration remains readable through the `0.6.x`
compatibility period and emits a migration notice. See [the package configuration
reference](./skills/starduster/references/configuration.md). Direct controller use
requires Python 3 with PyYAML and authenticated `gh`; the acceptance suite supplies
PyYAML explicitly with `uv run --with pyyaml`.

> **kcap vs ai-twitter-radar:** Use kcap to save/distill a specific URL to a structured note. Use ai-twitter-radar to browse, discover, or search AI tweets.
> **starduster vs kcap:** Use starduster to bulk-catalog your GitHub stars into a vault. Use kcap to capture a single specific URL.

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
"starduster"
"starduster 50"
"Catalog my GitHub stars into Obsidian"
"starduster --full"
```

## Requirements

- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) CLI or local Codex in the ChatGPT/Codex desktop app for kcap and starduster
- [GitHub CLI (gh)](https://cli.github.com/) (for starduster — GitHub stars fetching)
- [Bird CLI](https://github.com/steipete/bird) (for ai-twitter-radar and kcap Twitter capture)
- `curl` (for kcap's pinned HTTPS article fetch and redirect validation)
- [trafilatura](https://trafilatura.readthedocs.io/) (for kcap web article extraction)
- [youtube-transcript-api](https://github.com/jdepoix/youtube-transcript-api) (for kcap YouTube capture)

**Optional (fallback tools):**
- [html2text](https://pypi.org/project/html2text/) (fallback for web extraction when trafilatura unavailable)
- [yt-dlp](https://github.com/yt-dlp/yt-dlp) (fallback for YouTube transcripts + metadata extraction)

## License

[MIT License with Commercial Restriction](../LICENSE)
