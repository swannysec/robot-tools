# CWE Candidate-Analysis Reference

Use this reference during discovery to locate evidence, counterevidence, variant families, and deterministic checks. It does not confer `CONFIRMED`, `REFUTED`, or `INCONCLUSIVE`; those results belong only to the two cold Stage 2 verifiers under `cross-model-verification.md`.

A CWE label describes a weakness class, not validity, reachability, impact, or severity. For every candidate, cite the actual source-to-sink path, attacker preconditions, relevant controls, class variants, and remaining uncertainty. A nearby control is counterevidence to test, not automatic refutation.

## Common candidate record

For the applicable class, discovery roles should emit:

- exact input source, transformations, guards, sink/observable, and pinned locations;
- attacker capability and trust boundary;
- evidence and material counterevidence;
- primitive class, variants, and canonical enumeration source;
- distinct validity, reachability, impact, and mitigation/fix-state observations;
- a predeclared deterministic check and literal result-routing table when one exists.

## CWE-79: Cross-site scripting

Look for untrusted values reaching HTML, attribute, URL, CSS, JavaScript, SVG/MathML, template, or DOM execution contexts. Record the rendering context and the exact encoding or sanitization applied there. Test alternative tags, event attributes, protocol handlers, namespace changes, DOM sinks, and encoding/normalization variants supported by the parser.

Auto-escaping, a sanitizer, Trusted Types, and CSP are separate controls. CSP alone does not refute XSS: document the effective policy, response owner, inline/eval allowances, browser context, and whether the injection still changes executable or security-sensitive markup.

## CWE-89: SQL injection

Trace untrusted data into query structure, identifiers, operators, ordering, fragments, raw-query APIs, and second-order stored values. Parameter binding is strong counterevidence only for values actually passed through bind parameters; identifiers and raw fragments may require allowlisted construction. Include numeric contexts, alternate comments/encoding, nested queries, and parser/driver differences in the variant family.

## CWE-78: OS command injection

Distinguish direct process argument arrays from shell evaluation. Trace executable selection, each argument, environment variables, current directory, wrapper scripts, and any later shell or interpreter parsing. Include command separators, substitutions, whitespace and environment expansion, platform-specific quoting, option injection, and executable/PATH substitution where supported. A sandbox or restricted account changes impact and reachability; it does not erase the injection primitive.

## CWE-22: Path traversal and link escape

Trace the raw path through decoding, normalization, joining, authorization, open/create/rename/extract operations, and every link-following boundary. Enumerate absolute paths, parent components, alternate separators, double decoding, Unicode/case behavior, symlinks/junctions, archive link entries, replacement races, and time-of-check/time-of-use windows.

Lexical cleaning is not filesystem authorization. `canonicalize` plus a prefix comparison is material counterevidence only for the exact object and operation proven race-safe; it may fail for non-existent destinations, later replacement, links introduced after the check, platform path semantics, or a separate final open.

## CWE-352: Cross-site request forgery

Inventory every state-changing route and its accepted methods/content types. Trace credential attachment and verify token, Origin/Referer, custom-header, or same-site enforcement for each route. Cookie `SameSite`, CSRF middleware, CORS, and clickjacking controls are distinct. Include login CSRF, subdomain/site relationships, method override, alternate content types, and routes omitted from middleware.

## CWE-918: Server-side request forgery

Trace user influence over scheme, host, port, path, redirects, proxy selection, DNS resolution, and the final connection address. Enumerate alternate IP forms, IPv4/IPv6 mappings, DNS rebinding, redirect chains, parser discrepancies, non-HTTP schemes, metadata endpoints, and proxy/environment behavior. Host allowlists and private-range blocking must be checked after every resolution/redirect step they claim to govern.

## CWE-287: Improper authentication

Map protected resources and every authentication entry point. Record middleware coverage, token type/audience/issuer/signature/expiry checks, session transitions, reset and OAuth flows, credential comparison, and fail-open paths. Include algorithm/token confusion, session fixation, reset reuse, redirect manipulation, and route-specific opt-outs. Authentication evidence does not establish authorization.

## CWE-862: Missing authorization

For each operation, record caller identity, target object/tenant, required action, policy decision, and enforcement point. Include indirect/nested object access, bulk and GraphQL operations, method overrides, mass assignment, duplicate parameters, background jobs, and service-to-service paths. Central middleware is counterevidence only when its coverage and object/action semantics resolve for the cited path.

## CWE-190: Integer overflow and truncation

Trace untrusted or cross-boundary numeric values through conversions and arithmetic used for sizes, offsets, quotas, durations, allocations, and loop bounds. Record concrete types and build overflow behavior. Include signedness changes, narrowing casts, multiplication/addition order, unit conversion, and platform-width differences. Checked/saturating operations are counterevidence only if their error or saturation behavior preserves the security invariant.

## CWE-416: Use after free and lifetime violations

Trace allocation ownership, raw-pointer creation, moves/drops, callbacks, async/thread transfer, and each dereference. For FFI, document who retains and frees memory and whether callbacks can outlive the Rust owner. `Arc`, `Pin`, safe wrappers, `SAFETY` invariants, Miri, and sanitizers are evidence to inspect; their presence alone does not prove the cited path safe.

## CWE-119: Out-of-bounds memory access

Trace attacker-controlled lengths/offsets through raw pointer arithmetic, unchecked indexing, `from_raw_parts`, layout calculations, and FFI calls. Record allocation size, element size, alignment, provenance, integer conversions, and bounds checks on the exact path. Include zero-length, wraparound, unit mismatch, platform-width, and caller/callee length disagreements. Safe indexing or dynamic tooling is counterevidence only for the operations and inputs it actually covers.

## Verification boundary

Discovery returns candidate observations under `discovery-contract.md`. Stage 1 independently records location observations without the proposition. Stage 2 alone returns `CONFIRMED`, `REFUTED`, or `INCONCLUSIVE`. If a control appears complete, preserve its evidence and the class members tested; do not turn that observation into a verifier result during discovery.
