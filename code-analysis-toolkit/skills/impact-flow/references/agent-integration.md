# Agent Integration Reference

Guidelines for when to defer to specialized agents and how to create complementary workflows.

---

## Deferral Matrix

| Request Pattern | Primary Agent | Impact-Flow Role |
|-----------------|---------------|------------------|
| Security vulnerabilities, OWASP, injection | **security-sentinel** | Defer completely |
| Anti-patterns, code smells, design patterns | **pattern-recognition-specialist** | Defer completely |
| Architecture compliance, layer violations | **architecture-strategist** | Defer completely |
| Performance bottlenecks, optimization | **performance-oracle** | Defer completely |
| Dependency graphs, imports, module relationships | **impact-flow** | Handle directly |
| Blast radius, change impact, risk assessment | **impact-flow** | Handle directly |
| Health score, technical debt metrics | **impact-flow** | Handle directly |
| Execution flow, call trees, trace | **impact-flow** | Handle directly |

---

## Deferral Detection

### Trigger Phrases by Agent

**security-sentinel:**
- "security", "vulnerability", "CVE", "injection"
- "XSS", "CSRF", "authentication flaw"
- "secret", "credential", "hardcoded"
- "OWASP", "security audit"

**pattern-recognition-specialist:**
- "anti-pattern", "code smell", "design pattern"
- "god class", "spaghetti code"
- "naming convention", "style violation"
- "duplicated code", "copy paste"

**architecture-strategist:**
- "architecture", "layer violation"
- "clean architecture", "hexagonal"
- "dependency inversion", "SOLID"
- "component boundaries", "modular design"

**performance-oracle:**
- "performance", "slow", "bottleneck"
- "memory leak", "CPU usage"
- "optimization", "profiling"
- "latency", "throughput"

---

## Handoff Phrasing

### To security-sentinel

```
"This request involves security analysis. For comprehensive vulnerability
scanning, I recommend using **security-sentinel** which specializes in:
- Security vulnerability detection
- OWASP compliance checking
- Secret/credential scanning

Would you like me to invoke security-sentinel?"
```

### To pattern-recognition-specialist

```
"Detecting anti-patterns and code smells is handled by
**pattern-recognition-specialist**, which excels at:
- Design pattern violations
- Code smell detection
- Naming convention analysis

Shall I run pattern analysis instead?"
```

### To architecture-strategist

```
"Architecture compliance review is **architecture-strategist**'s specialty:
- Layer boundary enforcement
- Dependency direction validation
- Component coupling analysis

Want me to start an architecture review?"
```

### To performance-oracle

```
"Performance analysis is best handled by **performance-oracle**:
- Bottleneck identification
- Memory/CPU profiling
- Query optimization suggestions

Should I invoke performance analysis?"
```

---

## Complementary Workflows

### Workflow 1: Pre-Refactoring Assessment

**Goal**: Comprehensive analysis before major refactoring

```
Step 1: impact-flow health [scope]
        → Get baseline health score
        → Identify highest-debt areas

Step 2: impact-flow dependencies [high-debt-module]
        → Understand coupling
        → Find cycle issues

Step 3: pattern-recognition-specialist [high-debt-module]
        → Identify anti-patterns to fix

Step 4: impact-flow impact [target-function]
        → Assess blast radius for planned changes

Step 5: architecture-strategist [scope]
        → Ensure changes align with architecture
```

### Workflow 2: Security Vulnerability Prioritization

**Goal**: Prioritize security fixes by impact

```
Step 1: security-sentinel [scope]
        → Get list of vulnerabilities

Step 2: For each vulnerability:
        impact-flow impact [vulnerable-symbol]
        → Calculate blast radius
        → Assign risk priority

Step 3: Sort vulnerabilities by:
        (severity × blast_percentage)
        → Highest combined score = highest priority
```

### Workflow 3: New Developer Onboarding

**Goal**: Help new team members understand codebase

```
Step 1: impact-flow health .
        → Overall codebase health snapshot

Step 2: impact-flow dependencies [entry-points]
        → Show how major components connect

Step 3: For key features:
        impact-flow trace [entry-function]
        → Trace execution through the feature

Step 4: architecture-strategist overview
        → Explain architectural patterns
```

### Workflow 4: Change Risk Assessment

**Goal**: Assess risk before deploying changes

```
Step 1: impact-flow impact [changed-symbols]
        → Calculate blast radius for each change

Step 2: If blast_percentage > 15%:
        security-sentinel [affected-files]
        → Check for security implications

Step 3: If complexity increases:
        pattern-recognition-specialist [changed-files]
        → Check for introduced anti-patterns

Step 4: Synthesize risk report:
        - Blast radius: [%]
        - Security issues: [count]
        - New anti-patterns: [count]
        → Recommend: deploy / staged rollout / hold
```

---

## Integration Points

### Data Sharing

Impact-flow can provide context to other agents:

| From Impact-Flow | To Agent | Use Case |
|------------------|----------|----------|
| Dependency graph | architecture-strategist | Layer validation context |
| High-coupling modules | pattern-recognition-specialist | Focus areas for analysis |
| Blast radius data | security-sentinel | Vulnerability prioritization |
| Call trees | performance-oracle | Performance trace context |

### Report Combination

When generating comprehensive reports, combine outputs:

```markdown
# Comprehensive Codebase Analysis

## Health Overview (impact-flow)
[Health score report]

## Architecture Compliance (architecture-strategist)
[Architecture findings]

## Security Status (security-sentinel)
[Security findings]

## Code Quality (pattern-recognition-specialist)
[Pattern findings]

## Recommendations (synthesized)
1. [Priority 1 from combined analysis]
2. [Priority 2 from combined analysis]
```

---

## Boundaries

### What Impact-Flow DOES:

- ✅ Dependency graph generation and visualization
- ✅ Blast radius/impact calculation
- ✅ Unified health scoring with A-F grades
- ✅ Execution flow tracing
- ✅ Dead code detection
- ✅ Coupling metrics (Ca, Ce, Instability)

### What Impact-Flow does NOT do:

- ❌ Security vulnerability scanning (→ security-sentinel)
- ❌ Anti-pattern/code smell detection (→ pattern-recognition-specialist)
- ❌ Architecture rule enforcement (→ architecture-strategist)
- ❌ Performance profiling (→ performance-oracle)
- ❌ Code style/linting (→ external tools)
- ❌ Test generation (→ test-automator)

### Gray Areas

Some requests may span multiple domains. Use this guidance:

| Request | Primary | Secondary |
|---------|---------|-----------|
| "Is this module safe to change?" | impact-flow (blast radius) | security-sentinel (if security-critical) |
| "Why is this module hard to work with?" | impact-flow (coupling) | pattern-recognition (anti-patterns) |
| "Analyze this before refactoring" | impact-flow (dependencies) | architecture-strategist (compliance) |
| "What's the risk of this PR?" | impact-flow (impact) | All agents (comprehensive) |

---

## Invocation Examples

### Direct Invocation

```
User: "Show me the dependency graph for src/api/"
→ Impact-flow handles directly (Mode 1)

User: "What's affected if I change the UserService class?"
→ Impact-flow handles directly (Mode 2)
```

### Deferral Invocation

```
User: "Are there any security issues in the auth module?"
→ Suggest security-sentinel, do not attempt security analysis

User: "Does this code follow clean architecture?"
→ Suggest architecture-strategist, do not attempt architecture review
```

### Combined Invocation

```
User: "Give me a full analysis of the payments module"
→ Start with impact-flow health + dependencies
→ Suggest security-sentinel for security aspect
→ Suggest architecture-strategist for architecture aspect
→ Offer to synthesize findings
```
