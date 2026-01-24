# Secret Scanning Investigator

A Claude Code skill for investigating GitHub secret scanning alerts with evidence-based analysis and structured reporting.

## Features

- **Alert Investigation**: Trace provenance of leaked secrets through git history
- **Batch Processing**: Handle multiple alerts in a single investigation
- **Risk Assessment**: Evaluate exposure scope and potential impact
- **Structured Reports**: Generate security-professional-ready documentation
- **Parallel Execution**: Sub-agents accelerate investigation of complex alerts

## Installation

### Option 1: Clone to Claude Skills Directory

```bash
git clone https://github.com/swannysec/secret-scanning-investigator.git ~/.claude/skills/secret-scanning-investigator
```

### Option 2: Symlink from Custom Location

```bash
git clone https://github.com/swannysec/secret-scanning-investigator.git ~/my-skills/secret-scanning-investigator
ln -s ~/my-skills/secret-scanning-investigator ~/.claude/skills/secret-scanning-investigator
```

## Usage

Once installed, the skill activates automatically when you use trigger phrases:

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

This skill includes safeguards for sensitive operations:

- **Evidence-based only**: All findings cite specific commits, timestamps, or API responses
- **Double confirmation**: Modifying operations (resolving alerts, posting comments) require explicit `CONFIRM`
- **Read-only by default**: GET operations and local analysis don't require confirmation

## Requirements

- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) CLI
- GitHub CLI (`gh`) authenticated with appropriate permissions
- Git

## Structure

```
secret-scanning-investigator/
├── SKILL.md                    # Main skill definition
└── references/
    ├── actions/                # Action templates (rotation, cleanup, etc.)
    ├── phases/                 # Investigation phase guides
    ├── sub-agents/             # Parallel execution definitions
    └── report-template.md      # Output report structure
```

## License

[MIT License with Commercial Product Restriction](LICENSE)
