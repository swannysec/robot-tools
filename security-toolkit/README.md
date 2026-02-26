# Security Toolkit

Security investigation and analysis tools for GitHub secret scanning and security workflows.

> **Disclaimer**: These security tools are intended for **initial triage and context gathering only**. All findings, risk assessments, and recommendations must be validated by qualified security professionals before taking action. AI-generated security analysis may contain errors, miss critical context, or produce false positives/negatives. Never rely solely on automated analysis for security decisions.

## Features

### Skills

| Skill | Description |
|-------|-------------|
| `secret-scanning-investigator` | Investigate GitHub secret scanning alerts with evidence-based analysis. Trace provenance of leaked secrets, assess risk, and generate structured security reports. Includes batch processing and parallel sub-agent execution. |
| `security-vuln-analyzer` | Multi-agent security vulnerability analysis and remediation. Orchestrates 5 parallel agents (Security Sentinel, Threat Modeling Expert, Backend Security Coder, Comprehensive Reviewer, Codex 5.3) with evidence-only policy, EPSS+KEV+CVSS scoring, STRIDE-per-interaction threat modeling, Rust-specific security patterns, and standardized output format for consistent synthesis. Includes 5 reference files for detailed methodology. |
| `gha-hardening` | GitHub Actions security hardening and configuration best practices. Covers workflow permissions, secrets, OIDC, attack patterns (injection, pwn requests, supply chain), detection tools (zizmor, scorecard, poutine, actionlint, harden-runner), runner security, and incident response. |

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

**gha-hardening**:
- `"github actions security"`, `"gha security"`, `"gha hardening"`
- `"workflow security"`, `"actions hardening"`, `"secure github actions"`
- `"pull_request_target"`, `"script injection actions"`, `"sha pinning actions"`
- `"zizmor"`, `"scorecard checks"`, `"harden-runner"`, `"self-hosted runner security"`

### Example Commands

```
"Investigate the secret scanning alerts in this repo"
"Analyze the leaked AWS key found in commit abc123"
"Generate a secret scanning report for the last 30 days"
"I received a vulnerability report for clickjacking on our signup page"
"Analyze this security disclosure and recommend fixes"
"Review this CVE and assess its impact on our application"
"Harden this GitHub Actions workflow for security"
"Is this pull_request_target workflow safe?"
"What zizmor rules should I care about?"
"How do I set up OIDC for AWS in GitHub Actions?"
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
