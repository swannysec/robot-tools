# Code Analysis Toolkit

Codebase flow analysis, dependency visualization, impact assessment, and health scoring tools.

## Features

### Skills

| Skill | Description |
|-------|-------------|
| `impact-flow` | Comprehensive codebase analysis including dependency graphs, blast radius analysis, health scoring (A-F grades), execution flow tracing, and dead code detection. |

## Key Capabilities

- **Dependency Graph**: Visualize module relationships and coupling metrics
- **Blast Radius Analysis**: Assess impact of changing specific symbols or files
- **Health Scoring**: Generate A-F grades based on coupling, complexity, dead code, tests, and documentation
- **Flow Tracing**: Trace execution paths through call trees
- **Dead Code Detection**: Find unused exports safe to delete

## Installation

### Via Marketplace

```bash
/plugin marketplace add https://github.com/swannysec/robot-tools
/plugin install code-analysis-toolkit@robot-tools
```

### Manual Installation

```bash
git clone https://github.com/swannysec/robot-tools.git
cd robot-tools
cc --plugin-dir ./code-analysis-toolkit
```

## Usage

Skills activate automatically via trigger phrases:

**impact-flow**:
- `"impact-flow"`, `"impact flow"`
- `"dependency graph"`, `"module dependencies"`
- `"blast radius"`, `"impact analysis"`
- `"health score"`, `"codebase health"`
- `"trace execution"`, `"call graph"`
- `"dead code"`, `"unused exports"`

### Example Commands

```
"Run impact-flow on this codebase"
"What's the blast radius if I change UserService?"
"Generate a health score for the src/ directory"
"Show me the dependency graph for the auth module"
"Find dead code I can safely delete"
```

## Requirements

- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) CLI
- Optionally: [Serena MCP](https://github.com/oraios/serena) for token-efficient symbol analysis

## License

[MIT License with Commercial Restriction](../LICENSE)
