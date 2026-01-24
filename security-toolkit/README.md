# Security Toolkit

Security investigation and analysis tools for GitHub secret scanning and security workflows.

## Features

### Skills

| Skill | Description |
|-------|-------------|
| `secret-scanning-investigator` | Investigate GitHub secret scanning alerts with evidence-based analysis. Trace provenance of leaked secrets, assess risk, and generate structured security reports. Includes batch processing and parallel sub-agent execution. |

## Installation

### Via Marketplace

```bash
/plugin marketplace add https://github.com/swannysec/robot-tools
/plugin install security-toolkit@robot-tools
```

### Manual Installation

```bash
git clone https://github.com/swannysec/robot-tools.git
cd robot-tools
cc --plugin-dir ./security-toolkit
```

## Usage

Skills activate automatically via trigger phrases:

**secret-scanning-investigator**:
- `"investigate secret scanning alert"`
- `"analyze leaked secret"`
- `"trace secret provenance"`
- `"secret scanning report"`

### Example Commands

```
"Investigate the secret scanning alerts in this repo"
"Analyze the leaked AWS key found in commit abc123"
"Generate a secret scanning report for the last 30 days"
```

## Safety Features

- **Evidence-based only**: All findings cite specific commits, timestamps, or API responses
- **Double confirmation**: Modifying operations require explicit `CONFIRM`
- **Read-only by default**: GET operations and local analysis don't require confirmation

## Requirements

- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) CLI
- GitHub CLI (`gh`) authenticated with appropriate permissions
- Git

## License

[MIT License with Commercial Restriction](../LICENSE)
