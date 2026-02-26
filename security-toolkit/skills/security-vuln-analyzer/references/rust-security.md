# Rust Security Reference

Shared reference for agents analyzing Rust codebases. Covers vulnerability patterns, SAST toolchain, remediation idioms, and web framework security.

## Rust Vulnerability Patterns

| Pattern | CWE | Risk | Detection |
|---------|-----|------|-----------|
| `unsafe` blocks without `// SAFETY:` justification | CWE-94 | Memory corruption, undefined behavior | `cargo-geiger`, manual audit |
| FFI boundaries with unchecked inputs | CWE-94 | Buffer overflow, type confusion | Review `extern "C"` functions |
| Integer overflow in release builds | CWE-190 | Logic errors, bypasses (Rust wraps in release, panics in debug) | `cargo clippy -W clippy::arithmetic_side_effects` |
| Use-after-free via raw pointers | CWE-416 | Memory corruption | `cargo-geiger`, `miri` |
| Unchecked indexing (`slice[i]` without bounds check) | CWE-129 | Panic (DoS in servers) | `cargo clippy -W clippy::indexing_slicing` |
| `unwrap()` / `expect()` in request handlers | CWE-248 | Panic = DoS for server processes | `cargo clippy -W clippy::unwrap_used` |
| Unvalidated `serde` deserialization | CWE-502 | Attacker-controlled data shapes, resource exhaustion | Review `#[derive(Deserialize)]` without `#[serde(deny_unknown_fields)]` or size limits |
| Raw SQL via `format!()` | CWE-89 | SQL injection | Grep for `format!` near `query`/`execute`; use `sqlx::query!` or `diesel` |
| `std::process::Command` with user input | CWE-78 | OS command injection | Grep for `Command::new` with variable args |
| `std::path::Path` with user-controlled segments | CWE-22 | Path traversal | Check for `canonicalize()` and prefix validation |
| Hardcoded secrets (API keys, tokens, passwords) | CWE-798 | Credential exposure | `cargo clippy`, regex scan for key patterns |

## SAST Toolchain

| Tool | Purpose | Command |
|------|---------|---------|
| `cargo audit` | Check dependencies against RustSec advisory database | `cargo audit --json` |
| `cargo deny` | License compliance + advisory policy + source checks | `cargo deny check` |
| `cargo clippy` | Lint for security-relevant patterns | `cargo clippy -- -W clippy::unwrap_used -W clippy::indexing_slicing -W clippy::arithmetic_side_effects` |
| `cargo-geiger` | Measure `unsafe` code surface area (own + deps) | `cargo geiger --output-format ascii` |
| `cargo-vet` | Supply chain vetting — verify audits for dependencies | `cargo vet` |
| `cargo-crev` | Code review trust network for crate auditing | `cargo crev verify` |
| `cargo outdated` | Find dependencies with newer versions available | `cargo outdated -R` |
| `cargo udeps` | Detect unused dependencies | `cargo +nightly udeps` |
| `miri` | Detect undefined behavior in unsafe code at runtime | `cargo +nightly miri test` |
| `proptest` | Property-based testing for fuzzing security-sensitive code | Add `proptest` dev-dependency; write `proptest!` macro tests |

## Remediation Idioms

### Type-State Pattern for Auth Flows
```rust
// Enforce auth state transitions at compile time
struct Unauthenticated;
struct Authenticated { user_id: UserId }

struct Session<State> { state: State, /* ... */ }

impl Session<Unauthenticated> {
    fn authenticate(self, creds: Credentials) -> Result<Session<Authenticated>, AuthError> { /* ... */ }
}

impl Session<Authenticated> {
    fn access_resource(&self) -> Resource { /* ... */ } // Only callable when authenticated
}
```

### Newtype Pattern for Validated Input
```rust
// Prevent use of unvalidated strings
struct ValidatedEmail(String);

impl TryFrom<String> for ValidatedEmail {
    type Error = ValidationError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        if EMAIL_REGEX.is_match(&s) { Ok(Self(s)) } else { Err(ValidationError::InvalidEmail) }
    }
}

// Use with serde: #[serde(try_from = "String")]
```

### Unsafe Code Discipline
```rust
#![deny(unsafe_code)] // At crate level — opt-in to unsafe per-module

// When unsafe is required:
// SAFETY: `ptr` is guaranteed non-null and properly aligned because [specific reason].
// The referenced data outlives this scope because [specific reason].
unsafe { *ptr }
```

## Axum/Tower Security Middleware

```rust
// Compose security layers with tower::ServiceBuilder
let app = Router::new()
    .route("/api/*path", get(handler))
    .layer(
        ServiceBuilder::new()
            .layer(CorsLayer::permissive().allow_origin(AllowOrigin::exact("https://example.com".parse().unwrap())))
            .layer(SetResponseHeaderLayer::overriding(
                header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY")))
            .layer(SetResponseHeaderLayer::overriding(
                header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff")))
            .layer(SetResponseHeaderLayer::overriding(
                header::STRICT_TRANSPORT_SECURITY, HeaderValue::from_static("max-age=31536000; includeSubDomains")))
            .layer(RateLimitLayer::new(100, Duration::from_secs(60)))
            .layer(middleware::from_fn(auth_middleware))
    );
```
