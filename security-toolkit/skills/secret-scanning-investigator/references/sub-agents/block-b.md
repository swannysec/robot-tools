# Parallel Block B: Sub-Agent Prompts

Block B agents run after Block A completes and has the repository clone available.

---

## Agent B1: TruffleHog Scan

```
subagent_type: "Bash"
run_in_background: true
prompt: |
  ## Agent B1: TruffleHog Scan

  ### Objective
  Run TruffleHog security scanner to detect and optionally verify the secret.
  Cross-validate GitHub's finding with independent detection.

  ### Context
  Clone Path: /tmp/{repo}-investigation
  Mode: {ACTIVE|PASSIVE}
  Secret Pattern (partial, for matching): {partial_secret}
  Alert Number: {alert_number}
  Artifact Directory: /tmp/secret-scan-{alert_number}

  ### Output
  Write findings to `/tmp/secret-scan-{alert_number}/trufflehog.json`:
  ```json
  {
    "agent": "B1",
    "status": "complete",
    "tool": "trufflehog",
    "version": "3.63.0",
    "mode": "PASSIVE",
    "findings": [
      {
        "detector_type": "PrivateKey",
        "verified": false,
        "raw_preview": "-----BEGIN RSA...[first 50 chars]",
        "file": "crates/zed/Zed.toml",
        "line": 10,
        "commit": "abc123..."
      }
    ],
    "target_secret_found": true,
    "target_secret_verified": null,
    "total_findings": 3,
    "scan_duration_seconds": 12
  }
  ```

  Return only: `{"status": "complete", "artifact": "/tmp/secret-scan-{alert_number}/trufflehog.json"}`

  ### Tools
  - USE: `trufflehog git file:///tmp/...` or `trufflehog filesystem /tmp/...`
  - USE: `trufflehog --version` for version info
  - USE: `--no-verification` flag in PASSIVE mode
  - USE: `--only-verified` flag in ACTIVE mode only
  - AVOID: Scanning remote URLs directly (use local clone)

  ### Boundaries
  - DO NOT clone the repository (Agent A2 already did this)
  - DO NOT delete the clone (other agents may need it)
  - DO NOT send output to external services in PASSIVE mode
  - DO NOT run gitleaks (Agent B2 handles this)
  - STOP after writing artifact file

  ### Effort Scaling
  - Expected: 2-4 tool calls (version check, scan, write artifact)
  - If scan runs >60 seconds: note in output, may need shallower clone
  - If exceeding 6 calls: something is wrong

  ### Execution Steps
  1. Check trufflehog version
  2. Run appropriate scan based on mode:
     - PASSIVE: `trufflehog git file:///tmp/{repo}-investigation --no-verification --json 2>/dev/null`
     - ACTIVE: `trufflehog git file:///tmp/{repo}-investigation --only-verified --json 2>/dev/null`
  3. Filter output for target secret
  4. Write JSON artifact
  5. Return artifact reference
```

---

## Agent B2: Gitleaks Scan

```
subagent_type: "Bash"
run_in_background: true
prompt: |
  ## Agent B2: Gitleaks Scan

  ### Objective
  Run Gitleaks scanner for cross-validation and SARIF output generation.
  Provide independent detection to compare with GitHub and TruffleHog.

  ### Context
  Clone Path: /tmp/{repo}-investigation
  Alert Number: {alert_number}
  Secret Pattern (partial): {partial_secret}
  Artifact Directory: /tmp/secret-scan-{alert_number}

  ### Output
  Write findings to `/tmp/secret-scan-{alert_number}/gitleaks.json`:
  ```json
  {
    "agent": "B2",
    "status": "complete",
    "tool": "gitleaks",
    "version": "8.18.0",
    "findings": [
      {
        "rule_id": "private-key",
        "file": "crates/zed/Zed.toml",
        "line": 10,
        "entropy": 5.2,
        "secret_preview": "-----BEGIN...[first 30 chars]"
      }
    ],
    "target_secret_found": true,
    "total_findings": 2,
    "sarif_path": "/tmp/secret-scan-{alert_number}/gitleaks.sarif",
    "scan_duration_seconds": 8
  }
  ```

  Return only: `{"status": "complete", "artifact": "/tmp/secret-scan-{alert_number}/gitleaks.json"}`

  ### Tools
  - USE: `gitleaks detect --source /tmp/... --report-format json`
  - USE: `gitleaks version` for version info
  - USE: `--report-format sarif` for SARIF output (secondary)
  - AVOID: `--no-git` unless clone detection fails

  ### Boundaries
  - DO NOT clone the repository (Agent A2 already did this)
  - DO NOT delete the clone
  - DO NOT run trufflehog (Agent B1 handles this)
  - DO NOT analyze entropy (Agent B3 handles this)
  - STOP after writing artifact file

  ### Effort Scaling
  - Expected: 3-5 tool calls (version, JSON scan, SARIF scan, write artifact)
  - If exceeding 7 calls: something is wrong

  ### Execution Steps
  1. Check gitleaks version
  2. Run JSON scan: `gitleaks detect --source /tmp/{repo}-investigation --report-format json --report-path /tmp/secret-scan-{alert_number}/gitleaks-raw.json`
  3. Run SARIF scan: `gitleaks detect --source /tmp/{repo}-investigation --report-format sarif --report-path /tmp/secret-scan-{alert_number}/gitleaks.sarif`
  4. Filter and transform results
  5. Write JSON artifact
  6. Return artifact reference
```

---

## Agent B3: Entropy Analysis

```
subagent_type: "Bash"
run_in_background: true
prompt: |
  ## Agent B3: Entropy Analysis

  ### Objective
  Calculate Shannon entropy and analyze secret structure to determine
  likelihood of being a genuine machine-generated secret vs. false positive.

  ### Context
  Secret Value: {secret_value}
  Secret Type (from GitHub): {secret_type}
  Alert Number: {alert_number}
  Artifact Directory: /tmp/secret-scan-{alert_number}

  ### Output
  Write findings to `/tmp/secret-scan-{alert_number}/entropy.json`:
  ```json
  {
    "agent": "B3",
    "status": "complete",
    "entropy": {
      "shannon": 5.234,
      "assessment": "HIGH",
      "explanation": "Entropy >4.5 indicates likely machine-generated secret"
    },
    "structure": {
      "length": 1024,
      "unique_chars": 65,
      "char_distribution": "base64-like"
    },
    "pattern_match": {
      "detected_type": "RSA Private Key",
      "confidence": "high",
      "markers": ["BEGIN RSA PRIVATE KEY", "END RSA PRIVATE KEY"]
    },
    "false_positive_likelihood": "low"
  }
  ```

  Return only: `{"status": "complete", "artifact": "/tmp/secret-scan-{alert_number}/entropy.json"}`

  ### Tools
  - USE: `python3` for entropy calculation
  - AVOID: External network calls
  - AVOID: Running security scanners (Agents B1, B2 handle this)

  ### Boundaries
  - DO NOT test the secret against external services (Agent B4 handles active testing)
  - DO NOT clone repositories or access git history
  - DO NOT run trufflehog or gitleaks
  - STOP after writing artifact file

  ### Effort Scaling
  - Expected: 1-2 tool calls (python script execution, artifact write)
  - This agent should be very fast
  - If exceeding 3 calls: something is wrong

  ### Entropy Thresholds
  - >4.5: HIGH - likely machine-generated (base64, random bytes)
  - 3.5-4.5: MEDIUM - possible secret, needs context
  - <3.5: LOW - likely not a secret (words, patterns)

  ### Python Script
  ```python
  import math, json, sys

  secret = """{secret_value}"""

  # Shannon entropy
  if len(secret) > 0:
      prob = [secret.count(c) / len(secret) for c in set(secret)]
      entropy = -sum(p * math.log2(p) for p in prob if p > 0)
  else:
      entropy = 0

  result = {
      "agent": "B3",
      "status": "complete",
      "entropy": {
          "shannon": round(entropy, 3),
          "assessment": "HIGH" if entropy > 4.5 else "MEDIUM" if entropy > 3.5 else "LOW",
          "explanation": f"Entropy {entropy:.2f} indicates {'machine-generated' if entropy > 4.5 else 'possible secret' if entropy > 3.5 else 'likely not a secret'}"
      },
      "structure": {
          "length": len(secret),
          "unique_chars": len(set(secret)),
          "char_distribution": "base64-like" if entropy > 4.5 else "mixed"
      },
      "pattern_match": {"detected_type": None, "confidence": "low", "markers": []},
      "false_positive_likelihood": "low" if entropy > 4.0 else "medium" if entropy > 3.0 else "high"
  }

  # Pattern detection
  patterns = [
      ("ghp_", "GitHub PAT (classic)"),
      ("github_pat_", "GitHub PAT (fine-grained)"),
      ("gho_", "GitHub OAuth Token"),
      ("AKIA", "AWS Access Key"),
      ("xoxb-", "Slack Bot Token"),
      ("xoxp-", "Slack User Token"),
      ("sk-", "OpenAI/Stripe Key"),
      ("BEGIN RSA PRIVATE KEY", "RSA Private Key"),
      ("BEGIN OPENSSH PRIVATE KEY", "SSH Private Key"),
      ("BEGIN EC PRIVATE KEY", "EC Private Key"),
  ]
  for marker, type_name in patterns:
      if marker in secret:
          result["pattern_match"] = {"detected_type": type_name, "confidence": "high", "markers": [marker]}
          break

  print(json.dumps(result, indent=2))
  ```
```

---

## Agent B4: Service Analysis

```
subagent_type: "Explore"
run_in_background: true
prompt: |
  ## Agent B4: Service Analysis

  ### Objective
  Analyze the associated service to determine credential status by comparing
  leaked identifiers with current public metadata. For GitHub Apps, compare
  App IDs to determine if credentials have been rotated.

  ### Context
  Secret Type: {secret_type}
  Associated Service: {service_hint} (e.g., github_app, aws, slack)
  Leaked Identifiers: {app_id}, {client_id}, etc.
  Mode: {ACTIVE|PASSIVE}
  Alert Number: {alert_number}
  Artifact Directory: /tmp/secret-scan-{alert_number}

  ### Output
  Write findings to `/tmp/secret-scan-{alert_number}/service.json`:
  ```json
  {
    "agent": "B4",
    "status": "complete",
    "service_type": "github_app",
    "service_name": "zed-local-development",
    "current_state": {
      "app_id": 159810,
      "slug": "zed-local-development",
      "owner": "zed-industries",
      "created_at": "2021-12-20T00:00:00Z",
      "permissions": {"contents": "write", "metadata": "read"}
    },
    "credential_comparison": {
      "leaked_app_id": 12345,
      "current_app_id": 159810,
      "ids_match": false,
      "interpretation": "Leaked credentials likely from deleted/rotated app"
    },
    "validity_assessment": {
      "likely_valid": false,
      "confidence": "high",
      "evidence": [
        "App IDs do not match (12345 vs 159810)",
        "Current app created after leak date",
        "Pattern suggests app was deleted and recreated"
      ]
    }
  }
  ```

  Return only: `{"status": "complete", "artifact": "/tmp/secret-scan-{alert_number}/service.json"}`

  ### Tools
  - USE: `gh api /apps/{slug}` for GitHub App metadata (public, no auth needed)
  - USE: `gh api /users/{login}` for user/org info
  - AVOID: Active credential testing in PASSIVE mode
  - AVOID: Sending credentials to external services in PASSIVE mode

  ### Boundaries
  - DO NOT test the credential against the service API (unless ACTIVE mode AND user confirmed)
  - DO NOT run security scanners (Agents B1, B2 handle this)
  - DO NOT analyze entropy (Agent B3 handles this)
  - DO NOT clone repositories
  - STOP after writing artifact file

  ### Effort Scaling
  - GitHub App: 2-4 tool calls
  - AWS credential: 1-2 calls (mostly passive analysis)
  - Unknown service: 1-2 calls (metadata only)
  - If exceeding 6 calls: checkpoint and report

  ### Service-Specific Analysis

  **GitHub App:**
  - Query: `gh api /apps/{app_slug}`
  - Compare: leaked_app_id vs current app.id
  - If mismatch: credentials likely rotated

  **AWS Key:**
  - Analyze AKIA prefix format
  - Check key length and character set
  - DO NOT call AWS APIs in PASSIVE mode

  **Slack Token:**
  - Analyze xoxb-/xoxp- prefix
  - Extract workspace ID from token structure
  - DO NOT call Slack APIs in PASSIVE mode

  ### Execution Steps
  1. Identify service type from secret_type
  2. Query public metadata where available
  3. Compare leaked identifiers with current state
  4. Assess validity based on comparison
  5. Write JSON artifact
  6. Return artifact reference
```

---

## Coordinator: Collecting Results and Synthesis

After launching parallel agents with `run_in_background: true`, the coordinator collects all artifacts:

### Artifact Collection

1. Wait for all Block A agents to complete:
   ```
   TaskOutput(task_id="{agent_a1_id}", block=true)
   TaskOutput(task_id="{agent_a2_id}", block=true)
   TaskOutput(task_id="{agent_a3_id}", block=true)
   ```

2. Wait for all Block B agents to complete:
   ```
   TaskOutput(task_id="{agent_b1_id}", block=true)
   TaskOutput(task_id="{agent_b2_id}", block=true)
   TaskOutput(task_id="{agent_b3_id}", block=true)
   TaskOutput(task_id="{agent_b4_id}", block=true)
   ```

3. Read all artifacts ONCE for synthesis:
   ```bash
   # Read all artifacts
   cat /tmp/secret-scan-{alert_number}/alert.json
   cat /tmp/secret-scan-{alert_number}/provenance.json
   cat /tmp/secret-scan-{alert_number}/context.json
   cat /tmp/secret-scan-{alert_number}/trufflehog.json
   cat /tmp/secret-scan-{alert_number}/gitleaks.json
   cat /tmp/secret-scan-{alert_number}/entropy.json
   cat /tmp/secret-scan-{alert_number}/service.json
   ```

4. Synthesize findings into unified report (Phase 7)

5. Cleanup after successful completion:
   ```bash
   rm -rf /tmp/secret-scan-{alert_number}
   rm -rf /tmp/{repo}-investigation
   ```

### Error Handling in Parallel Execution

| Scenario | Handling |
|----------|----------|
| Agent fails | Log failure, continue with other agents, note missing data in report |
| Agent times out | Checkpoint partial results if available, offer retry |
| Artifact file missing | Check agent status, retry or proceed with partial data |
| Clone not available | Block B agents report "clone_missing", note limitation |
| All agents fail | Report error, offer to retry entire block |

### Recovery from Partial Failure

If some agents complete but others fail:
1. Read successful artifacts
2. Note which data is missing in the report
3. Offer to retry failed agents individually
4. Proceed with synthesis using available data
