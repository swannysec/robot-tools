# Adversarial Verification Reference

Four-gate review checklist, framework security defaults, common LLM verification shortcuts to reject, and environment protection categories for adversarial verification of security findings.

## Four-Gate Review Checklist

Each finding must be challenged through 4 gates. A finding is CONFIRMED only if it passes all applicable gates. If any gate fails, the finding is REFUTED with the failed gate cited.

### Reachability Gate

Is the vulnerable code actually reachable from attacker-controlled input?

| Requirement | Details |
|-------------|---------|
| Trace call chain | Map the full path from external entry point to the vulnerable code |
| Verify no sanitization | Confirm input is not sanitized, validated, or transformed before reaching the sink |
| Check dispatch paths | For Rust: verify trait dispatch or generics mean the vulnerable path is actually invoked at runtime |
| **FAIL criteria** | No path from attacker input to vulnerable code, or input is fully sanitized before reaching it |

### Real Impact Gate

If exploited, what is the actual (not theoretical) damage?

| Requirement | Details |
|-------------|---------|
| Classify impact type | Distinguish RCE, privilege escalation, data disclosure, DoS — each has different real-world impact |
| Assess data sensitivity | Consider the classification and sensitivity of data that could be exposed |
| Evaluate blast radius | Consider blast radius and recovery difficulty |
| **FAIL criteria** | Impact is purely theoretical, or the exploitable state has no meaningful consequence |

### Mitigation Check Gate

Are there existing controls that neutralize this vulnerability?

| Requirement | Details |
|-------------|---------|
| Check framework defaults | See Framework Security Defaults table below |
| Check middleware protections | Review middleware/extractor protections in the request pipeline |
| Check type system constraints | Rust newtypes, type-state patterns, sealed traits |
| Check input validation | Verify validation at trust boundaries |
| **FAIL criteria** | Existing controls already prevent exploitation |

### Environment Check Gate

Do deployment-level protections reduce exploitability?

| Requirement | Details |
|-------------|---------|
| WAF/CDN rules | Check for request filtering at the edge |
| CSP policy | Verify Content-Security-Policy blocks the attack vector |
| Network segmentation | Determine if the endpoint is internet-facing |
| Auth requirements | Check authentication requirements on the affected path |
| Container isolation | Check runtime restrictions and sandboxing |
| **FAIL criteria** | Deployment protections prevent exploitation even if code is vulnerable |

## Framework Security Defaults

Verifiers must check these before claiming a vulnerability is exploitable.

| Framework | Built-in Protections |
|-----------|---------------------|
| **Rust/Axum** | Type-safe extractors reject malformed input, Tower middleware composition for auth/CORS/rate-limiting, ownership system prevents use-after-free in safe code, no null pointers |
| **Rust/Actix** | Guards system for route protection, middleware pipeline, actor model for concurrency isolation, payload size limits |
| **Next.js (14+)** | Automatic HTML escaping in JSX, CSRF tokens in Server Actions, CSP nonce support, API route isolation, built-in image optimization prevents SSRF via domains allowlist |
| **Rails** | CSRF protection on by default (`protect_from_forgery`), parameterized queries via ActiveRecord, Content-Security-Policy middleware, strong parameters |
| **Django** | CSRF middleware enabled by default, ORM prevents SQL injection, template auto-escaping, clickjacking protection (X-Frame-Options middleware), password hashing with PBKDF2 |

## Common LLM Verification Shortcuts to Reject

Adversarial verifiers must NOT accept these reasoning patterns. If a finding's evidence relies on any of these, challenge it.

| Shortcut | Why It Fails | What to Do Instead |
|----------|-------------|-------------------|
| "This pattern looks dangerous" | Pattern does not equal exploitability. Context determines risk. | Trace the actual data flow from input to sink. |
| "Similar code was vulnerable elsewhere" | Different codebase, different context, different mitigations. | Verify THIS code has the same conditions. |
| "No sanitization visible in this file" | Sanitization may be in middleware, callers, or framework defaults. | Check non-target files and framework protections. |
| "This CWE is typically Critical" | Severity depends on context, not CWE classification. | Assess based on observed evidence only. |
| "The function name suggests insecurity" | Naming does not equal behavior. `unsafe_parse()` may have safe invariants. | Read the implementation, check SAFETY comments. |
| "Multiple agents agree" | Consensus from shared training data is not independent confirmation. | Check if agents cited independent evidence or echoed each other. |
| "CVSS base score is X for this type" | Base score ignores environmental and temporal factors. | Use CVSS with environmental metrics, add EPSS/KEV context, and express likelihood using ICD 203 estimative language. |

## Environment Protection Categories

Categories to verify during the Environment Check Gate.

### Network Protections

- WAF rules (ModSecurity, Cloudflare, AWS WAF)
- CDN edge rules and geographic restrictions
- Rate limiting and DDoS protection
- IP allowlisting and network ACLs
- TLS termination and certificate pinning
- DNS-level filtering and sinkholing

### Runtime Protections

- Container isolation (Docker, gVisor, Kata Containers)
- Seccomp profiles and AppArmor/SELinux policies
- Read-only filesystems and non-root execution
- Resource limits (memory, CPU, file descriptors, PID limits)
- Namespace isolation (PID, network, mount, user)
- Runtime application self-protection (RASP) agents

### Platform Protections

- Cloud provider guardrails (Security Groups, firewall rules, NSGs)
- Managed service protections (RDS encryption, S3 bucket policies)
- IAM role boundaries and least-privilege enforcement
- VPC isolation and private subnet placement
- Service mesh mTLS (Istio, Linkerd) between internal services
- Secrets management (Vault, AWS Secrets Manager, SOPS)

### Application Protections

- Framework middleware (auth, CORS, CSP, rate limiting)
- Authentication layer requirements (JWT validation, session management)
- Authorization checks (RBAC, ABAC, policy engines)
- Input validation at API gateway and handler boundaries
- Structured logging with sensitive field redaction
- Circuit breakers and graceful degradation on failure paths
