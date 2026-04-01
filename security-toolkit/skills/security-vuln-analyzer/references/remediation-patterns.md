# Remediation Patterns Reference

Fix templates, security headers implementation, common mistakes, CWE classifications, and OWASP Top 10:2025 quick reference.

## Fix Template Structure

Every remediation recommendation should follow this format:

```
### [CWE-NNN] Vulnerability Title

**Vulnerable pattern:**
[Code showing the insecure implementation]

**Secure fix:**
[Code showing the corrected implementation]

**Verification:**
[Command or test to confirm the fix works]
```

## OWASP Top 10:2025 Quick Reference

| Rank | Category | Key Controls | Test Items |
|------|----------|-------------|------------|
| A01 | Broken Access Control | RBAC, deny by default, rate limiting, CORS, disable directory listing | Verify all endpoints enforce auth; test horizontal/vertical privilege escalation |
| A02 | Security Misconfiguration | Hardened defaults, remove unused features, patch management, error handling | Check debug mode, default credentials, unnecessary services, stack traces |
| **A03** | **Software Supply Chain Failures** (new in 2025) | Dependency auditing, SBOM, lockfiles, signature verification, vendor assessment | `cargo audit`, `cargo deny`, check for typosquatting, verify package integrity |
| A04 | Cryptographic Failures | TLS 1.2+, strong ciphers, no MD5/SHA-1, key management | Check cert config, data-at-rest encryption, password hashing algorithms |
| A05 | Injection | Parameterized queries, input validation, output encoding, allowlisting | Test SQL/NoSQL/OS/LDAP injection, verify parameterized queries, check encoding |
| A06 | Insecure Design | Threat modeling (STRIDE), secure design patterns, abuse case testing | Review design docs, check for business logic flaws, test abuse scenarios |
| A07 | Authentication Failures | MFA, strong password policies, session management, credential stuffing protection | Test brute force protection, session fixation, token handling |
| A08 | Software or Data Integrity Failures | Code signing, CI/CD integrity, update verification, serialization validation | Check pipeline security, verify update mechanisms, test deserialization |
| A09 | Security Logging and Alerting Failures | Audit logging, alerting, log integrity, incident detection | Verify auth events logged, check log injection, test alert triggers |
| **A10** | **Mishandling of Exceptional Conditions** (new in 2025) | Graceful error handling, resource limits, circuit breakers, panic-safe code | Test error paths, resource exhaustion, malformed input handling |

## Security Headers Implementation

### Required Headers

| Header | Value | Purpose | Grading Weight |
|--------|-------|---------|---------------|
| Content-Security-Policy | `default-src 'self'; script-src 'self'` (tune per app) | XSS prevention, injection control | 25/100 |
| Strict-Transport-Security | `max-age=31536000; includeSubDomains` | Force HTTPS | 20/100 |
| X-Frame-Options | `DENY` (or `SAMEORIGIN`) | Clickjacking prevention | 15/100 |
| X-Content-Type-Options | `nosniff` | MIME sniffing prevention | 10/100 |
| Referrer-Policy | `strict-origin-when-cross-origin` | Information leakage prevention | 10/100 |
| Permissions-Policy | `camera=(), microphone=(), geolocation=()` | Feature restriction | 10/100 |
| Cache-Control | `no-store` (for sensitive pages) | Prevent caching of sensitive data | 10/100 |

**Header security score** = sum of weights for present headers. Target: >80/100.

### CSP Progressive Deployment

1. **Audit**: Deploy `Content-Security-Policy-Report-Only` with `report-uri` to collect violations without blocking
2. **Tune**: Review violation reports, add legitimate sources to the policy
3. **Enforce**: Switch to `Content-Security-Policy` (blocking mode) once violations are resolved
4. **Monitor**: Keep `report-uri` active to catch regressions

## Common Security Mistakes

| Bad Practice | Correct Approach | Risk |
|-------------|-----------------|------|
| `unwrap()` in server handlers | `map_err()` + proper error response | DoS via panic |
| `format!("SELECT * FROM users WHERE id = {}", id)` | `sqlx::query!("SELECT * FROM users WHERE id = $1", id)` | SQL injection |
| `Command::new("sh").arg("-c").arg(user_input)` | `Command::new("program").arg(sanitized_arg)` | Command injection |
| Hardcoded `let api_key = "sk-..."` | `std::env::var("API_KEY")` | Credential exposure |
| `#[derive(Deserialize)]` without limits | `#[serde(deny_unknown_fields)]` + size limits on body | Deserialization attacks |
| `path.join(user_input)` | `path.join(user_input)` then `canonicalize()` + prefix check | Path traversal |
| MD5/SHA-1 for password hashing | Argon2id or bcrypt with appropriate cost | Credential cracking |
| `SameSite=None` without `Secure` | `SameSite=Strict` or `SameSite=Lax` | CSRF |
| Arithmetic without overflow checks | `checked_add()`, `saturating_mul()`, or `#[deny(clippy::arithmetic_side_effects)]` | Integer overflow |

## CWE Classification for Rust

| CWE | Name | Rust-Specific Pattern | Detection Method |
|-----|------|----------------------|------------------|
| CWE-78 | OS Command Injection | `std::process::Command` with unsanitized args | Grep for `Command::new` with variable arguments |
| CWE-22 | Path Traversal | `std::path::Path::join()` without canonicalize + prefix check | Grep for `join` on Path/PathBuf with user input |
| CWE-89 | SQL Injection | `format!()` in SQL query strings | Grep for `format!` near query/execute calls |
| CWE-94 | Code Injection | `unsafe` blocks, FFI boundaries | `cargo-geiger`, manual audit of `unsafe` |
| CWE-129 | Unchecked Index | `slice[i]` without bounds check | `cargo clippy -W clippy::indexing_slicing` |
| CWE-190 | Integer Overflow | Arithmetic in release builds (wraps silently) | `cargo clippy -W clippy::arithmetic_side_effects` |
| CWE-248 | Uncaught Exception | `unwrap()`/`expect()` in non-test code | `cargo clippy -W clippy::unwrap_used` |
| CWE-416 | Use After Free | Raw pointer dereference after owned value dropped | `miri`, manual unsafe audit |
| CWE-502 | Deserialization of Untrusted Data | `serde` without field/size constraints | Review `Deserialize` derives on public API types |
| CWE-798 | Hardcoded Credentials | String literals matching key/token/password patterns | Regex scan, `cargo clippy` |
