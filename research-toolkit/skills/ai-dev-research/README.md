# AI Dev Research

A Claude Code skill for world-expert technical research on AI-enabled software development topics.

## Features

- **Deep Technical Research**: Synthesize knowledge from papers, documentation, and authoritative sources
- **Technical Consultation**: Evaluate AI architectures, approaches, and tool selection
- **Implementation Guidance**: Production-ready patterns with working code examples
- **Comparative Analysis**: Framework, model, and service comparisons
- **State-of-the-Art Analysis**: Current best practices with authoritative citations

## Topics Covered

- RAG (Retrieval-Augmented Generation) architectures
- Agentic workflows and multi-agent systems
- LLM integration and prompt engineering
- Embeddings and vector databases
- Fine-tuning strategies
- AI coding tools and assistants

## Installation

### Option 1: Clone to Claude Skills Directory

```bash
git clone https://github.com/swannysec/ai-dev-research.git ~/.claude/skills/ai-dev-research
```

### Option 2: Symlink from Custom Location

```bash
git clone https://github.com/swannysec/ai-dev-research.git ~/my-skills/ai-dev-research
ln -s ~/my-skills/ai-dev-research ~/.claude/skills/ai-dev-research
```

## Usage

Once installed, the skill activates automatically when you use trigger phrases:

- `"research AI"` or `"AI research"`
- `"compare LLMs"` or `"which model should I use"`
- `"RAG architecture"` or `"agentic workflow"`
- `"AI coding tools"` or `"best practices for AI development"`
- `"production AI systems"` or `"AI implementation guidance"`

### Example Commands

```
"Research the current state of RAG architectures"
"Compare Claude, GPT-4, and Gemini for code generation"
"What's the best approach for building an agentic workflow?"
"How should I implement semantic search with embeddings?"
```

## Research Methodology

The skill follows a structured research process:

1. **Scope Definition**: Clarify questions and success criteria
2. **Multi-Source Research**: Primary (docs, papers), secondary (eng blogs), tertiary (community)
3. **Synthesis & Citation**: Cross-reference findings with URLs for all claims

## Requirements

- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) CLI

## Structure

```
ai-dev-research/
├── SKILL.md              # Main skill definition
└── references/
    ├── agentic-systems.md
    ├── code-generation.md
    ├── rag-systems.md
    └── source-directory.md
```

## License

[MIT License with Commercial Product Restriction](LICENSE)
