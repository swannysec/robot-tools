# CWE Verification Procedures Reference

Per-CWE detection checklists, verification steps, and known mitigations. Use to guide vulnerability analysis when the CWE class is identified.

## CWE-79: Cross-Site Scripting (XSS)
### Detection Patterns
- Template rendering with unescaped user input (triple-brace in Handlebars, `| safe` in Jinja2, raw HTML insertion in React)
- String concatenation into HTML response bodies without encoding
- Reflected parameters echoed directly in server responses
### Verification Steps
1. **Reachability Gate**: Trace user-controlled input to the rendering call — confirm no sanitization in the path
2. **Mitigation Check Gate**: Check for CSP `script-src` directive, auto-escaping template defaults, and sanitizer libraries
3. Assign CONFIRMED if unsanitized input reaches rendered output; REFUTED if auto-escaping or CSP blocks execution
### Known Mitigations
- Context-aware output encoding (HTML, URL, JS, CSS contexts each need distinct encoding)
- CSP with `script-src 'self'` (no `unsafe-inline`); auto-escaping engines (Tera, Askama, Jinja2 strict)

## CWE-89: SQL Injection
### Detection Patterns
- `format!()` or string concatenation in SQL strings passed to `query()` / `execute()`
- Raw SQL builders accepting unparameterized user input; ORM `.raw()` with interpolated variables
### Verification Steps
1. **Reachability Gate**: Confirm user input flows into the SQL string without a parameterized query interface
2. **Real Impact Gate**: Check whether parameterized queries are available but bypassed
3. Assign CONFIRMED (High Confidence) if `format!()` builds a query with user input; REFUTED if bind parameters used
### Known Mitigations
- Parameterized queries (`sqlx::query!("... $1", param)` in Rust, `?` placeholders elsewhere)
- ORM query builders enforcing parameterization; least-privilege database users

## CWE-78: OS Command Injection
### Detection Patterns
- `Command::new("sh").arg("-c").arg(user_input)` — shell invocation with user-controlled arguments
- User input reaching `Command` arguments without allowlist validation
- Python `subprocess` with `shell=True` or direct shell execution with interpolated strings
### Verification Steps
1. **Reachability Gate**: Trace input from HTTP param / CLI arg / env var to the `Command` call
2. **Environment Check Gate**: Determine if the binary runs in a sandboxed container or restricted shell
3. Assign CONFIRMED if unsanitized input reaches a shell command; INCONCLUSIVE if partial sanitization exists
### Known Mitigations
- Pass arguments as discrete `arg()` calls, never through a shell interpreter
- Allowlist validation of permitted values; avoid `sh -c` — invoke binaries directly

## CWE-22: Path Traversal
### Detection Patterns
- `Path::join(user_input)` or `PathBuf::push(user_input)` without canonicalization and prefix check
- File-serving endpoints resolving `../` against a document root; archive extraction without path validation (zip slip)
### Verification Steps
1. **Reachability Gate**: Confirm user-controlled path segments reach filesystem operations
2. **Mitigation Check Gate**: Check for `canonicalize()` followed by `starts_with(allowed_root)`
3. Assign CONFIRMED if traversal can escape the intended root; REFUTED if canonicalize + prefix check is present
### Known Mitigations
- `canonicalize()` then `starts_with()` against the allowed base directory
- Reject components containing `..` or absolute prefixes; container filesystem isolation (defense in depth)

## CWE-352: Cross-Site Request Forgery (CSRF)
### Detection Patterns
- State-mutating endpoints (POST/PUT/DELETE) lacking CSRF token validation middleware
- `SameSite=None` on session cookies without additional token checks; forms missing hidden CSRF fields
### Verification Steps
1. **Mitigation Check Gate**: Verify CSRF middleware is registered and covers all state-mutating routes
2. **Environment Check Gate**: Check `SameSite` cookie attribute — `Strict` or `Lax` reduces risk
3. Assign CONFIRMED if no token enforcement on state-mutating endpoints; REFUTED if CSRF middleware is active
### Known Mitigations
- Synchronizer token pattern (server-generated, validated per state-mutating request)
- `SameSite=Strict` or `Lax` on session cookies; custom request headers for API calls

## CWE-918: Server-Side Request Forgery (SSRF)
### Detection Patterns
- HTTP client calls (`reqwest::get()`, `hyper::Client`) with user-controlled URLs
- URL params passed to webhook dispatchers, image proxies, or internal service fetchers
- DNS rebinding where URL validation occurs before resolution
### Verification Steps
1. **Reachability Gate**: Trace user-supplied URL to an outbound HTTP request
2. **Mitigation Check Gate**: Check for URL allowlisting, RFC 1918/link-local IP blocking, DNS pinning
3. Assign CONFIRMED if arbitrary URLs trigger internal requests; INCONCLUSIVE if partial validation exists
### Known Mitigations
- URL allowlist (permitted schemes, hosts, ports); block private/loopback/metadata IPs post-resolution
- Network-level egress filtering (firewall rules, service mesh policies)

## CWE-287: Improper Authentication
### Detection Patterns
- Endpoints missing authentication middleware or guard annotations
- JWT validation skipping signature verification or accepting `alg: none`
- Password comparison using non-constant-time equality (`==` instead of `constant_time_eq`)
### Verification Steps
1. **Mitigation Check Gate**: Verify auth middleware is applied globally or per-route for protected resources
2. **Real Impact Gate**: Confirm unauthenticated access reaches sensitive data or operations
3. Assign CONFIRMED if protected routes are accessible without valid credentials; REFUTED if coverage is complete
### Known Mitigations
- Global auth middleware with explicit opt-out only for public routes
- JWT configured to reject `none` algorithm; constant-time credential comparison

## CWE-862: Missing Authorization
### Detection Patterns
- Endpoints authenticating callers but not checking resource ownership or role permissions
- Direct object references (`/api/users/{id}/records`) without ownership validation
- Admin operations lacking role checks beyond authentication
### Verification Steps
1. **Reachability Gate**: Confirm authenticated user can access another user's resources or escalate roles
2. **Mitigation Check Gate**: Check for RBAC/ABAC middleware, ownership guards, or policy enforcement points
3. Assign CONFIRMED if privilege escalation is possible; REFUTED if authorization gates every access path
### Known Mitigations
- Deny-by-default authorization with explicit per-endpoint grants
- Resource-level ownership checks scoped to authenticated user's ID; centralized policy enforcement

## CWE-190: Integer Overflow (Rust-relevant)
### Detection Patterns
- Arithmetic on `u32`/`u64`/`usize`/signed types in Rust release builds (wraps silently)
- User-controlled numeric input in size calculations, allocation lengths, or loop bounds
- `as` casts that truncate values (e.g., `u64 as u32`)
### Verification Steps
1. **Reachability Gate**: Confirm user-controlled integers reach unchecked arithmetic operations
2. **Environment Check Gate**: Debug mode panics on overflow; release mode wraps — determine build profile
3. Assign CONFIRMED (Moderate Confidence) if unchecked arithmetic on user input in release; REFUTED if `checked_*`/`saturating_*` used
### Known Mitigations
- `checked_add()`, `checked_mul()`, `saturating_sub()` for untrusted inputs
- `#[deny(clippy::arithmetic_side_effects)]` at crate level; `TryFrom`/`TryInto` over `as` casts

## CWE-416: Use After Free (Rust unsafe)
### Detection Patterns
- `unsafe` blocks dereferencing raw pointers after the owning value is dropped or moved
- FFI boundaries where Rust passes a pointer to C code that retains it beyond the object's lifetime
- Manual `drop()` followed by raw pointer access in the same scope
### Verification Steps
1. **Reachability Gate**: Trace raw pointer lifetimes in `unsafe` blocks against owning allocations
2. **Mitigation Check Gate**: Check for Miri (`cargo +nightly miri test`) in CI
3. Assign CONFIRMED (High Confidence) if dereference provably occurs post-drop; INCONCLUSIVE if ambiguous
### Known Mitigations
- Minimize `unsafe` — prefer `Arc`, `Rc`, `Pin` over raw pointers
- Run Miri in CI; encapsulate raw pointer usage in small, auditable modules with documented invariants

## CWE-119: Buffer Overflow (Rust unsafe/FFI)
### Detection Patterns
- `unsafe` blocks using `get_unchecked()` / `get_unchecked_mut()` or raw pointer arithmetic
- FFI calls passing Rust buffers to C without length params or with mismatched lengths
- `std::slice::from_raw_parts()` with an incorrect length argument
### Verification Steps
1. **Reachability Gate**: Confirm user-controlled data influences buffer sizes or offsets in `unsafe`/FFI code
2. **Mitigation Check Gate**: Check for bounds validation before `unsafe` access; Miri/AddressSanitizer in CI
3. Assign CONFIRMED if out-of-bounds access is reachable; REFUTED if bounds checks precede all unsafe indexing
### Known Mitigations
- Safe indexing (`slice.get()`) over `get_unchecked()` where performance permits
- Validate lengths/offsets at FFI boundary; enable AddressSanitizer and Miri in CI
