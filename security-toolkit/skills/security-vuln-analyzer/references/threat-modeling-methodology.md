# Threat Modeling Methodology Reference

STRIDE-per-interaction analysis, attack tree construction, control library, defense-in-depth assessment, and risk calibration data.

## Table of Contents

- [STRIDE-per-Interaction Mapping](#stride-per-interaction-mapping)
- [Attack Tree Model](#attack-tree-model)
- [Control Library](#control-library)
- [Risk Calibration Data](#risk-calibration-data)
- [Primitive Class Enumeration](#primitive-class-enumeration)

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

## Primitive Class Enumeration

For the attacker's goal, enumerate the full equivalence class of inputs that achieves it, not exemplars within one class.

This rule is the antidote to the most common variant-miss: identifying *one* primitive class as "the attack vector," enumerating exemplars within that class, and missing the equivalent classes that achieve the same goal through different mechanisms. The attacker's primitive class includes every input that leads to the same observable outcome — not just the family the analysis happened to start with.

### Domain examples

Apply across any vulnerability class with multiple equivalent input primitives:

**Sanitization / filtering**
- Character categories: whitespace, format characters, control characters, combining marks
- Encoding variants: URL encoding, HTML entity encoding, Unicode escape sequences, double-encoding, mixed-encoding
- Case variants: upper / lower / title / full-width / Turkic-i / Greek final-sigma

**Injection**
- Payload delivery vectors: query string, headers, cookies, request body, multipart fields, websocket frames
- Serialization formats: JSON, XML, YAML, form-encoded, msgpack, protobuf
- Context-specific syntax: SQL dialect variants, shell quoting styles, template engines (Jinja, ERB, Handlebars)

**Authorization**
- Attribute substitution paths: user ID, session token, role claim, group membership, tenant ID
- Bypass primitives: TOCTOU, race, redirect, CSRF, alternate endpoint, parameter tampering

**Deserialization**
- Gadget chains within and across known sink libraries
- Format alternatives that share a parser (e.g., XML/SOAP variants, YAML/JSON parsers, native binary serializers in dynamic languages)
- Polymorphism abuse (e.g., `__class__`, type-coercing magic methods, custom reduce-style hooks)

**Logic**
- Ordering primitives: out-of-order step submission, skipping intermediate states
- State-transition variants: re-entering states the design assumed terminal
- Concurrency interleavings: parallel requests racing for the same resource
- Retry / replay: idempotency token reuse, message replay against single-use endpoints

### Checklist

Apply at threat-modeling time, before recommending a fix:

1. **State the attacker's goal** in one sentence — the observable outcome the attacker wants, not implementation jargon.
2. **Identify the primitive class** needed to achieve that goal — the named family of inputs, not a specific exemplar.
3. **Enumerate the full class** — every member, drawn from the canonical source (stdlib, language spec, library inventory). Do not stop at exemplars.
4. **For each member, state whether it is in scope of the proposed fix.** Members outside the fix scope are bypass candidates and must be tracked as such.

### Where this is applied downstream

- **Step 1.5 SURFACE MAP construction** in `SKILL.md` references this section; the attack surface enumeration includes all primitive class members, not exemplars of one family.
- **FINDER 2 (Threat Modeler)** in `step-2-agent-prompts.md` emits a Primitive Class Enumeration as a finding artifact for any vulnerability with multiple variants.
- **FINDER 3 (Backend Coder)** consumes the enumeration to draft the Invariant + Adversarial Test Contract; each enumerated member is tested against the fix.
- **FINDER 5 (Codex) Phase 2 variant probe** uses the enumeration to construct candidate bypass inputs.
- **Class Coverage Check** in `deterministic-validation.md` runs the enumeration deterministically (no LLM judgment) against the fix's filter to produce a list of missed members.
