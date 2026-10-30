# Security Toolkit

Security investigation and analysis tools for GitHub secret scanning and security workflows.

> **Disclaimer**: These security tools are intended for **initial triage and context gathering only**. All findings, risk assessments, and recommendations must be validated by qualified security professionals before taking action. AI-generated security analysis may contain errors, miss critical context, or produce false positives/negatives. Never rely solely on automated analysis for security decisions.

## Features

### Skills

| Skill | Description |
|-------|-------------|
| `secret-scanning-investigator` | Investigate GitHub secret scanning alerts with evidence-based analysis. Trace provenance of leaked secrets, assess risk, and generate structured security reports. Includes batch processing and parallel sub-agent execution. |
| `security-vuln-analyzer` | Portable evidence-led vulnerability analysis for Claude Code and Codex/ChatGPT Desktop. Runs three isolated native-model discovery roles and requires cold native plus cross-provider verification for every vulnerability or primary-control claim. Mechanical Reconciliation preserves counterevidence and unresolved disputes without voting or orchestrator judgment. Includes Rust security guidance plus retained `--verify-fix` and human-gated `--develop-fix` modes. Product-specific context remains run input rather than distributable skill content. |
| `gha-hardening` | GitHub Actions security hardening and configuration best practices. Covers workflow permissions, secrets, OIDC, attack patterns (injection, pwn requests, supply chain), detection tools (zizmor, scorecard, poutine, actionlint, harden-runner), runner security, and incident response. |
| `vanta` | Vanta compliance platform operations — posture analysis, audit readiness, vulnerability management, personnel compliance, and flexible reporting. Complements the official vanta-mcp-plugin with analysis workflows, direct API operations, and reporting. |
| `vercel-forensics` | Preservation-first forensic evidence collection and analysis for Vercel incidents (OAuth supply-chain compromise, env-var exposure, audit-log triage). Read-only by construction: per-path `ALLOWED_PATHS` map, ingress field projection, GET-only verb gate, software WORM (SHA-256 manifest + `chmod -R a-w`). Emits 8-section findings report, fused Vercel + GitHub timeline, per-actor profiles, build-log IOC scan, and a rotation-worklist CSV for handoff to subinium/metapod. Engineering-triage grade — not court-admissible. |

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
- `"vulnerability report"`, `"security issue"`
- `"security disclosure"`, `"bug bounty submission"`
- `"analyze this CVE"`, `"vulnerability analysis"`
- `"clickjacking"`, `"XSS"`, `"CSRF"`, `"injection"`
- `"verify fix"`, `"fix verification"`, `"post-fix verification"`
- `"is this fixed"`, `"closure verification"` (invokes `--verify-fix` mode)
- `"develop the fix"`, `"author the fix for finding N"`, `"remediate this finding"` (invokes `--develop-fix` mode — Rust-first; human-gated candidate patch)

**gha-hardening**:
- `"github actions security"`, `"gha security"`, `"gha hardening"`
- `"workflow security"`, `"actions hardening"`, `"secure github actions"`
- `"pull_request_target"`, `"script injection actions"`, `"sha pinning actions"`
- `"zizmor"`, `"scorecard checks"`, `"harden-runner"`, `"self-hosted runner security"`

**vanta**:
- `"vanta"`, `"vanta compliance"`, `"vanta audit"`
- `"compliance posture"`, `"audit readiness"`, `"compliance gap"`
- `"vanta tests"`, `"vanta controls"`, `"vanta vulnerabilities"`
- `"vulnerability sla"`, `"compliance report"`, `"vanta api"`

**vercel-forensics**:
- `"vercel incident"`, `"vercel forensics"`, `"vercel breach"`
- `"vercel oauth"`, `"vercel supply chain"`, `"vercel compromise"`
- `"vercel env exposure"`, `"vercel env leak"`, `"vercel env rotation"`
- `"vercel audit log"`, `"vercel activity log"`, `"vercel triage"`
- `"rotation worklist"`, `"audit log triage"`, `"preservation first forensics"`

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

- Claude Code or Codex/ChatGPT Desktop as the host harness
- Both the Claude Code and Codex CLIs, authenticated and authorized for the repository, when cross-model verification is required
- Git
- GitHub CLI (`gh`) only for GitHub-backed inputs or landing workflows

## License

[MIT License with Commercial Restriction](../LICENSE)
