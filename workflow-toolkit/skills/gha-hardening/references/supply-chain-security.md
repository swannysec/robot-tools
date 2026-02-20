# Supply Chain Security Reference

Action pinning, dependency management, typosquatting defense, and
compromised action detection for GitHub Actions.

---

## Table of Contents

- [SHA Pinning](#sha-pinning)
- [Dependabot for Actions](#dependabot-for-actions)
- [Typosquatting](#typosquatting)
- [Impostor Commits](#impostor-commits)
- [Allowed Actions Policy](#allowed-actions-policy)
- [Action Evaluation Checklist](#action-evaluation-checklist)
- [SLSA and Artifact Provenance](#slsa-and-artifact-provenance)

---

## SHA Pinning

### Why Tags Are Dangerous

Tags are mutable — anyone with write access to an action repository can
silently redirect a tag to a malicious commit. This is exactly how the
tj-actions/changed-files attack (CVE-2025-30066) worked.

### Tag vs SHA Comparison

| Dimension | Tag (`@v4`) | SHA (`@abc123...`) |
|-----------|-------------|---------------------|
| Immutability | None — can be redirected | Complete — immutable |
| Supply chain risk | High — compromised tag = instant exploitation | Eliminated for already-pinned commits |
| Human readability | High | Low (add version comment) |
| Dependabot support | Full | Full (bumps SHA + updates comment) |
| Recommended for | Internal first-party actions only | All third-party actions |

### Best Practice: SHA Pin with Version Comment

```yaml
# INSECURE — tag is mutable
- uses: actions/checkout@v4

# SECURE — immutable SHA with version comment for readability
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
```

Dependabot updates both the SHA and the comment when a new release is available.

### Bulk Pinning Tools

- `zizmor --fix` — auto-pins `uses:` clauses to SHA
- `suzuki-shunsuke/pinact` — update and hash-pin workflows and actions
- `davidism/gha-update` — update and hash-pin workflow definitions
- `stacklok/frizbee` — hash-pin (but not update) workflow definitions
- StepSecurity Harden-Runner can automate bulk SHA-pinning

---

## Dependabot for Actions

### Minimal Configuration

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
```

### Security-Hardened Configuration

```yaml
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
      time: "09:00"
      timezone: "UTC"
    open-pull-requests-limit: 10
    commit-message:
      prefix: "ci"
      include: "scope"
    labels:
      - "dependencies"
      - "github-actions"
    reviewers:
      - "security-team"
    groups:
      github-actions:
        patterns:
          - "*"    # group all action updates into single PR
```

### Dependabot + SHA Pinning Workflow

1. You pin: `uses: actions/checkout@692973e3d937...  # v4.1.7`
2. New release `v4.2.0` published
3. Dependabot opens PR: updates SHA + comment to `# v4.2.0`
4. You review the diff, approve, merge
5. Audit trail of every action version change

---

## Typosquatting

### How It Works

Attacker registers a GitHub org whose name is a common misspelling of a
popular action publisher. Developers who typo the org name silently run
malicious code.

### Real-World Examples (Orca Security 2024)

| Typosquatted Name | Intended Name | GitHub Search Hits |
|-------------------|---------------|-------------------|
| `actons/checkout` | `actions/checkout` | 198 workflow files |
| `action/checkout` | `actions/checkout` | Multiple hits |
| `google-github-actons` | `google-github-actions` | Confirmed |
| `circelci` | `circleci` | Confirmed |

The org `actons` accumulated victims organically without any promotion.

### Why SHA Pinning Doesn't Fully Help

If you typo the org name but provide a valid SHA from the real repo,
the workflow will fail (SHA not found in typo repo). But if you typo
the org name and use a tag, the attacker controls what runs.

### Prevention

- Maintain an org-level allowlist of approved actions
- Prefer actions from verified creators (blue checkmark)
- Automated scanning: zizmor, Raven, Octoscan validate publisher identity
- Double-check org names before adding `uses:` references

---

## Impostor Commits

### How It Works

GitHub's fork network allows a commit from a fork to be referenced via
the parent repository's slug. An attacker can:

1. Fork a popular action repository
2. Push a malicious commit to their fork
3. Reference the commit using the parent's `owner/repo@SHA` format
4. The workflow runs attacker code that appears legitimately SHA-pinned

### Detection

Zizmor's `impostor-commit` rule detects commits within a repository action's
fork network that are not present on the repository itself.

### Mitigation

- Verify that pinned SHAs correspond to tagged releases on the actual repo
- Use zizmor to audit for impostor commits
- Check the commit on the upstream repo before pinning

---

## Allowed Actions Policy

### Organization-Level Control

| Mode | Description |
|------|-------------|
| Allow all | No restriction (not recommended) |
| Same enterprise/org | Only actions from repos within enterprise/org |
| Verified + specific list | GitHub-owned + verified badge + explicit allowlist |
| Specific allowlist | Glob patterns only: `actions/cache@*`, `aws-actions/*` |

### Configuration Hierarchy

Enterprise policy → org policy → repo policy. Children cannot be more
permissive than parents.

### Recommended Setup

1. Enterprise: Allow verified creators + specific list
2. Org: Maintain a curated allowlist of approved actions
3. Repo: Inherit org policy (do not weaken)

---

## Action Evaluation Checklist

Before approving a third-party action:

- [ ] **Verified creator badge** on GitHub Marketplace
- [ ] **Source code reviewed** — especially `action.yml`, entrypoint, package.json
- [ ] **Maintenance status** — recent commits, responsive to issues
- [ ] **Community adoption** — stars, forks, dependents count
- [ ] **Dependency tree** — does the action pull in other actions?
- [ ] **Unpinnable dependencies** — does it fetch external resources at runtime?
- [ ] **OpenSSF Scorecard** — check project health score
- [ ] **Known CVEs** — check GitHub Advisories and OSV
- [ ] **Permission requirements** — does it need write access? Why?
- [ ] **Network access** — does it make outbound calls? To where?

---

## SLSA and Artifact Provenance

### Build Provenance

Use `actions/attest-build-provenance` to generate SLSA provenance
attestations for release artifacts:

```yaml
- uses: actions/attest-build-provenance@<SHA>
  with:
    subject-path: dist/release.tar.gz
```

### Signature Verification

Tools and frameworks for artifact integrity:
- **SLSA** — Supply chain Levels for Software Artifacts (levels 0–4)
- **Sigstore** — Keyless code signing (cosign, fulcio, rekor)
- **in-toto** — Supply chain layout verification

### Scorecard Release Checks

Scorecard's `Signed-Releases` check looks for signature files
(`.minisig`, `.asc`, `.sig`, `.sigstore`, `.intoto.jsonl`) in the
last 5 releases. SLSA provenance file gives maximum score (10/10).
