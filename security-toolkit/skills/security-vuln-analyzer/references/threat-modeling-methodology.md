# Threat Modeling Methodology Reference

STRIDE-per-interaction analysis, attack tree construction, control library, defense-in-depth assessment, and risk calibration data.

## STRIDE-per-Interaction Mapping

Apply STRIDE categories based on the source→target element pair in each data flow, not uniformly to every component:

| Source | Target | Applicable STRIDE Categories |
|--------|--------|------------------------------|
| External Entity | Process | **S**poofing, **T**ampering, **R**epudiation, **D**enial of Service |
| Process | Data Store | **T**ampering, **I**nformation Disclosure, **D**enial of Service |
| Process | External Entity | **S**poofing, **T**ampering, **R**epudiation, **I**nformation Disclosure, **D**enial of Service |
| Process | Process | **S**poofing, **T**ampering, **R**epudiation, **I**nformation Disclosure, **D**enial of Service, **E**levation of Privilege |
| Data Store | Process | **T**ampering, **I**nformation Disclosure |

### STRIDE Category Definitions

| Category | Question to Ask | Example Controls |
|----------|----------------|------------------|
| **S**poofing | Can an attacker impersonate a legitimate user or system? | Authentication (MFA, certificates), session management |
| **T**ampering | Can data be modified in transit or at rest? | Input validation, checksums, encryption, digital signatures |
| **R**epudiation | Can a user deny performing an action? | Audit logging, timestamps, non-repudiation controls |
| **I**nformation Disclosure | Can sensitive data be exposed? | Encryption, access controls, data classification |
| **D**enial of Service | Can the system be made unavailable? | Rate limiting, resource quotas, redundancy |
| **E**levation of Privilege | Can a user gain unauthorized access levels? | RBAC, least privilege, input validation |

## Attack Tree Model

### Node Attributes

Each node in an attack tree carries quantifiable attributes:

| Attribute | Values | Description |
|-----------|--------|-------------|
| Difficulty | Low / Medium / High | Attacker skill level required |
| Cost | Low / Medium / High | Resources needed (tools, infrastructure, time investment) |
| Detection Risk | Low / Medium / High | Likelihood the attack is detected during execution |
| Time | Hours / Days / Weeks | Estimated duration to execute this step |
| Insider Required | Yes / No | Whether internal access is needed |

### Path Analysis

For each attack tree, identify three priority paths:

1. **Easiest path**: Sequence of nodes with lowest cumulative difficulty. This is what script kiddies and automated tools will attempt first.
2. **Cheapest path**: Sequence with lowest cumulative cost. This is what resource-constrained attackers will prefer.
3. **Stealthiest path**: Sequence with lowest cumulative detection risk. This is what APTs and nation-state actors will use.

Mitigations should block all three paths. If only the easiest path is blocked, sophisticated attackers still have options.

### Node Types

- **OR node**: Attacker needs to complete ANY child node (alternative attack methods)
- **AND node**: Attacker needs to complete ALL child nodes (multi-step attack)
- **LEAF node**: Atomic attack step (cannot be decomposed further)

## Control Library

### Control Types

| Type | Purpose | Example |
|------|---------|---------|
| Preventive | Stop attacks before they succeed | Input validation, authentication, encryption |
| Detective | Identify attacks during or after execution | IDS/IPS, audit logging, anomaly detection |
| Corrective | Recover from successful attacks | Incident response, backup restoration, patch deployment |

### Control Layers (Defense-in-Depth)

| Layer | Scope | Example Controls |
|-------|-------|------------------|
| Application | Code-level security | Input validation, output encoding, auth, session management |
| Infrastructure | Network and hosting | Firewalls, network segmentation, encryption in transit, WAF |
| CI/CD | Build and deployment pipeline | Supply chain integrity, secrets management, image scanning, signed commits |

### Gap Detection Rules

Flag these as security gaps:
- Any control layer with **coverage < 50%** of identified threats
- Any threat with only **one type of control** (missing defense-in-depth — need at least preventive + detective)
- Any layer with **no control diversity** (e.g., only preventive controls, no detective)
- Any **Critical-severity threat** with no corrective control (no recovery plan)

## Risk Calibration Data

### Empirical Finding Frequency

Calibrate likelihood estimates against real-world scan data:

| Finding Type | Frequency in Typical Scans | Typical Severity |
|-------------|---------------------------|------------------|
| SQL Injection | ~35% | High-Critical |
| Exposed Secrets | ~28% | High-Critical |
| Vulnerable Dependencies | ~25% | Medium-High |
| Missing Authentication | ~18% | High-Critical |
| XSS Vulnerabilities | ~15% | Medium-High |
| Weak Encryption | ~12% | Medium |
| Missing Security Headers | ~10% | Low-Medium |
| CSRF Vulnerabilities | ~8% | Medium |
| Insecure Deserialization | ~5% | High |
| Security Misconfiguration | ~4% | Medium |

### Risk Matrix

| | Low Impact | Medium Impact | High Impact | Critical Impact |
|--|-----------|---------------|-------------|-----------------|
| **High Likelihood** | Medium | High | Critical | Critical |
| **Medium Likelihood** | Low | Medium | High | Critical |
| **Low Likelihood** | Low | Low | Medium | High |
