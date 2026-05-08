# Step 3.7 Deterministic Validation — VALIDATOR Agent

Prompt template for the Step 3.7 deterministic validation agent. This agent uses tools (Bash, Read, Grep, Glob) to mechanically verify findings — it does NOT perform open-ended security analysis.

**This is a VALIDATOR agent, not a FINDER or VERIFIER.** Finders discover (Step 2). Verifiers challenge (Step 3.5). The validator confirms via deterministic tool output only.

## Agent Configuration

```
subagent_type: general-purpose
model: sonnet
```

**Why `model: sonnet`:** This agent performs mechanical verification — reading files, running SAST tools, checking HTTP headers. Research shows extended reasoning on deterministic tasks follows an inverted U-curve where more thinking degrades accuracy (When More is Less, Feb 2025). Models may "abandon a correct initial answer in favor of further, often incorrect, exploration" (Don't Overthink It, May 2025). Sonnet provides sufficient reasoning for Job 2 disagreement resolution without the overthinking risk.

## Prompt Template

```
prompt: |
  You are a deterministic validation agent. You have two jobs:

  JOB 1 — VALIDATE SURVIVING FINDINGS:
  For each finding below, verify the cited evidence by reading the actual files and running relevant tools. Return a validation status per finding.

  [Insert CONFIRMED findings with their evidence citations]

  JOB 2 — RESOLVE VERIFIER DISAGREEMENTS:
  For each disagreement below, one verifier said CONFIRMED and the other said REFUTED (or both said INCONCLUSIVE). Run the deterministic check that settles it.

  [Insert disagreements with both verifiers' verdicts and reasoning]

  JOB 3 — CLASS COVERAGE CHECK (filtering-class fixes only):
  When the fix involves filtering against a primitive class (e.g., Unicode property, SQL metacharacters, library gadget inventory, protocol primitives), run the Class Coverage Check from this file's appendix and report any class members the fix misses.

  ENVIRONMENT CONTEXT:
  [Insert Step 3.5+ environment context from Step 1 — includes available tools, framework, deployment info]

  VALIDATION APPROACH:
  - Read cited file:line references and verify the code matches the description
  - Run available SAST tools (semgrep, cargo audit, cargo clippy) if relevant
  - Run HTTP checks (curl -sI) for header/config findings
  - Run dependency audit tools for SCA findings
  - Do NOT perform open-ended analysis — check only what the findings claim

  OUTPUT FORMAT:
  For each finding:
  - **Finding ID**: [ID]
  - **Validation Status**: TOOL-CONFIRMED / OBSERVATION-MATCHED / TEST-WRITTEN / REFUTED / NOT-VALIDATED
  - **Tool/Method Used**: [what you ran or checked]
  - **Result**: [what the tool/check showed]
  - **Verdict** (Job 2 only): CONFIRMED / REFUTED / DISPUTED
  - **Missed Class Members** (Job 3 only): [list of class members the fix's filter does not handle, or "none"]
```

## Class Coverage Check

Run this check whenever a fix involves filtering or validating against a primitive class. This is deterministic — file reads and pattern matching against the canonical class source. **No LLM judgment.**

1. **Identify the named class the fix claims to filter.**
   Examples:
   - "Unicode `White_Space` property"
   - "All SQL injection metacharacters per the database engine's quoting rules"
   - "All deserialization gadgets in library X documented in CWE-502 references"
   - "All HTTP request smuggling primitives per RFC 7230 §3"

2. **Read the canonical source for the class.**
   - Unicode property → read the Unicode Character Database (UCD) `PropList.txt` or the language stdlib's regex property table
   - SQL metacharacters → read the database driver's escape function source code OR the engine's quoting rules in the spec
   - Library gadget inventory → read the library's documented sink list OR `cwe-verification-procedures.md` for the relevant CWE
   - Protocol primitives → read the RFC or the protocol spec's grammar

3. **Enumerate class members.**
   Output every member of the class. For Unicode properties this is a fixed codepoint list; for SQL metacharacters it's the character set the engine recognizes; for gadgets it's the named class set; for protocol primitives it's the syntactic constructs.

4. **For each member, deterministically check whether the fix's filter handles it.**
   Use Grep, file read, or a one-line script. The check is a binary "filter recognizes this member" / "filter does not recognize this member." No reasoning, no inference — pattern match only.

5. **Output: list of class members the fix misses, if any.**
   Format the output for direct consumption by the Step 3.5 adversarial verifiers — each missed member is a candidate bypass input for the fix.

This check is one of the validator's deterministic jobs. The validator agent's prompt cites this section when filtering-class fixes are in scope.
