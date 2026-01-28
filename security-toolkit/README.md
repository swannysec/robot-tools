# Security Toolkit

Security investigation and analysis tools for GitHub secret scanning and security workflows.

> **Disclaimer**: These security tools are intended for **initial triage and context gathering only**. All findings, risk assessments, and recommendations must be validated by qualified security professionals before taking action. AI-generated security analysis may contain errors, miss critical context, or produce false positives/negatives. Never rely solely on automated analysis for security decisions.

## Features

### Skills

| Skill | Description |
|-------|-------------|
| `secret-scanning-investigator` | Investigate GitHub secret scanning alerts with evidence-based analysis. Trace provenance of leaked secrets, assess risk, and generate structured security reports. Includes batch processing and parallel sub-agent execution. |
| `security-vuln-analyzer` | Multi-agent security vulnerability analysis and remediation. Orchestrates 4 parallel security agents (Security Auditor, Threat Modeling Expert, Backend Security Coder, Comprehensive Reviewer) to analyze vulnerability reports, validate findings, assess risk with CVSS scoring, and provide framework-specific fix recommendations. |

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

**security-vuln-analyzer**:
- `"vulnerability report"`
- `"security disclosure"`
- `"analyze this CVE"`
- `"clickjacking vulnerability"`
- `"XSS/CSRF/injection issue"`
- `"bug bounty submission"`

### Example Commands

```
"Investigate the secret scanning alerts in this repo"
"Analyze the leaked AWS key found in commit abc123"
"Generate a secret scanning report for the last 30 days"
"I received a vulnerability report for clickjacking on our signup page"
"Analyze this security disclosure and recommend fixes"
"Review this CVE and assess its impact on our application"
```

## Safety Features

- **Evidence-based only**: All findings cite specific commits, timestamps, or API responses
- **Double confirmation**: Modifying operations require explicit `CONFIRM`
- **Read-only by default**: GET operations and local analysis don't require confirmation
- **Human validation required**: All security findings require review by qualified personnel

## Requirements

- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) CLI
- GitHub CLI (`gh`) authenticated with appropriate permissions
- Git

## License

[MIT License with Commercial Restriction](../LICENSE)
