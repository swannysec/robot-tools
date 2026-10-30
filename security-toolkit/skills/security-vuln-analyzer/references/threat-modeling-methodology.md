# Threat Modeling Methodology

Threat modeling establishes testable propositions; it does not assign a finding disposition by itself. Use the evidence and output boundaries in [discovery-contract.md](discovery-contract.md).

## Per-interaction analysis

For each source-to-target interaction, record the attacker capability, trust boundary/security authority, input transformation, guard/control, sink or observable, and evidence source. Apply STRIDE only where the interaction makes a category relevant:

| Category | Question |
|---|---|
| Spoofing | Can an attacker impersonate a principal or trusted system? |
| Tampering | Can attacker-controlled state cross an integrity boundary? |
| Repudiation | Can the system fail to produce trustworthy action evidence? |
| Information disclosure | Can the attacker observe protected information? |
| Denial of service | Can the attacker exhaust or block a protected resource? |
| Elevation of privilege | Can the attacker obtain authority beyond the intended boundary? |

For each proposition, state separately the evidence for validity, reachability, impact, and mitigation/fix state. Do not infer reachability from a source-to-sink resemblance, impact from a CWE label, or mitigation from a control's existence.

## Attack paths

Model AND/OR paths from attacker preconditions to observable consequence. Each node records preconditions, boundary crossed, cited evidence, control, and uncertainty. A path is useful only when its nodes can be checked against the pinned target and declared deployment context.

## Primitive Class Enumeration

For the attacker goal, enumerate the full set of evidence-supported inputs or representations that could produce the same observable outcome—not examples from the first family noticed.

1. State the attacker goal in observable terms.
2. Name each primitive class and its canonical source (language/protocol specification, documented grammar, Unicode property set, library inventory, or other declared source).
3. Enumerate members/variants, including alternative encodings, representations, delivery paths, state transitions, and concurrency interleavings where relevant.
4. State which variants are in scope of the proposed control, which are not, and which cannot be enumerated with the available evidence.
5. For each fix-bearing candidate, Role 3 owns the **Invariant + Adversarial Test Contract**: invariant, attacker-controlled input classes, expected secure behavior, sink/observable, deterministic oracle, and benign/negative control.

An unenumerated or untestable member is an explicit uncertainty, not a passing result. Deterministic class coverage uses [deterministic-validation.md](deterministic-validation.md).

## Threat-model output

Return the normalized proposition, target/revision and locations, trust-boundary evidence, primitive classes/variants/enumeration source, attacker preconditions, attack path, controls and counterevidence, assumptions/uncertainty, and proposed disposition. Preserve stable IDs and provenance through [orchestrator-contract.md](orchestrator-contract.md); verification proceeds under [cross-model-verification.md](cross-model-verification.md).
