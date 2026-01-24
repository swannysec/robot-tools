# Phases 2-6: Investigation Details

## Phase 2: Full Alert Acquisition

### 2.1 Complete Alert Details

```bash
# Full alert data
gh api repos/{owner}/{repo}/secret-scanning/alerts/{alert_number}

# All locations
gh api repos/{owner}/{repo}/secret-scanning/alerts/{alert_number}/locations
```

Extract and record:
- Secret type and display name
- File path, line numbers, blob SHA
- Introducing commit SHA
- Alert state, validity, creation date
- Whether secret is base64 encoded
- All location types (commits, wiki, issues, discussions, PRs)

### 2.2 Current Code Status

```bash
# Check if secret exists in current HEAD
gh api repos/{owner}/{repo}/contents/{path} --jq '.content' 2>/dev/null | \
  base64 -d 2>/dev/null | grep -q "{unique_pattern}" && \
  echo "SECRET IN CURRENT CODE" || echo "HISTORY ONLY"
```

### 2.3 GitHub Validity Status

Record GitHub's validity assessment:
- `active`: GitHub confirmed credential is valid
- `inactive`: GitHub confirmed credential is revoked/expired
- `unknown`: GitHub could not determine status

---

## Phase 3: Multi-Tool Cross-Validation

### 3.1 TruffleHog Scan (if available)

**ACTIVE MODE ONLY for --only-verified flag:**

```bash
# Clone repo temporarily
cd /tmp && rm -rf {repo}-investigation
git clone --depth=100 https://github.com/{owner}/{repo}.git {repo}-investigation

# ACTIVE MODE: Full verification
trufflehog git file:///tmp/{repo}-investigation --only-verified --json 2>/dev/null | \
  jq 'select(.Raw | contains("{partial_secret}"))'

# PASSIVE MODE: Detection without verification
trufflehog git file:///tmp/{repo}-investigation --no-verification --json 2>/dev/null | \
  jq 'select(.Raw | contains("{partial_secret}"))'
```

### 3.2 Gitleaks Scan (if available)

```bash
# Both modes - gitleaks does not verify by default
gitleaks detect --source /tmp/{repo}-investigation --report-format json --report-path /tmp/gitleaks-{alert}.json

# Extract matching findings
jq '.[] | select(.Secret | contains("{partial_secret}"))' /tmp/gitleaks-{alert}.json
```

### 3.3 Cross-Tool Correlation

Compare findings across tools:
- Secrets found by all tools: HIGH confidence
- Secrets found by 2/3 tools: MEDIUM confidence
- Secrets found by 1 tool only: Investigate further

### 3.4 Entropy Analysis (for unrecognized secrets)

```bash
# Calculate Shannon entropy
python3 -c "
import math
s = '{secret_value}'
if len(s) > 0:
    prob = [s.count(c) / len(s) for c in set(s)]
    entropy = -sum(p * math.log2(p) for p in prob if p > 0)
    print(f'Entropy: {entropy:.2f}')
    # Thresholds: base64 >4.5, hex >3.0, alphanumeric >3.7
    if entropy > 4.5:
        print('HIGH ENTROPY - likely machine-generated secret')
    elif entropy > 3.5:
        print('MEDIUM ENTROPY - possible secret')
    else:
        print('LOW ENTROPY - likely not a secret')
"
```

---

## Phase 4: Provenance Tracing

### 4.1 Repository Clone (if not already done)

```bash
cd /tmp && rm -rf {repo}-investigation 2>/dev/null
git clone --filter=blob:none --sparse https://github.com/{owner}/{repo}.git {repo}-investigation
cd {repo}-investigation
git sparse-checkout set {directory_containing_secret}
```

### 4.2 File History

```bash
# Full file history
git log --follow --oneline --all -- "{file_path}"

# Find when secret content was added (pickaxe search)
git log -p --all -S "{unique_secret_substring}" -- "{file_patterns}" | head -200

# Check state before introducing commit
git show {introducing_commit}^:{file_path} 2>/dev/null || echo "File did not exist before this commit"
```

### 4.3 Exposure Timeline Calculation

```bash
# Get introduction date
INTRO_DATE=$(gh api repos/{owner}/{repo}/git/commits/{introducing_sha} --jq '.author.date')

# Calculate exposure window
INTRO_EPOCH=$(date -d "$INTRO_DATE" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%SZ" "$INTRO_DATE" +%s)
NOW_EPOCH=$(date +%s)
DAYS_EXPOSED=$(( (NOW_EPOCH - INTRO_EPOCH) / 86400 ))

echo "Exposure window: $DAYS_EXPOSED days (since $INTRO_DATE)"
```

### 4.4 Cleanup

```bash
# ALWAYS cleanup temporary clone
cd /tmp && rm -rf {repo}-investigation
```

---

## Phase 5: Commit and PR Context

### 5.1 Commit Details

```bash
gh api repos/{owner}/{repo}/git/commits/{sha} --jq '{
  sha,
  author: .author,
  committer: .committer,
  message
}'
```

### 5.2 Associated PR

```bash
# Find PR containing commit
PR_DATA=$(gh api repos/{owner}/{repo}/commits/{sha}/pulls --jq '.[0] | {number, title, body, user: .user.login}' 2>/dev/null)

if [ -n "$PR_DATA" ]; then
  PR_NUM=$(echo "$PR_DATA" | jq -r '.number')

  # Get full PR details
  gh pr view $PR_NUM --repo {owner}/{repo} --json title,body,author,comments,reviews

  # Get linked issues
  gh api repos/{owner}/{repo}/pulls/$PR_NUM --jq '.body' | grep -oE '#[0-9]+' | while read issue; do
    gh issue view ${issue#\#} --repo {owner}/{repo} --json title,body 2>/dev/null
  done
fi
```

### 5.3 Security Discussion Search

```bash
# Search PR comments for security-related discussion
gh api repos/{owner}/{repo}/pulls/{pr_number}/comments --jq \
  '.[] | select(.body | test("secret|credential|key|token|password|security"; "i")) | {user: .user.login, body}'
```

---

## Phase 6: Secret-Specific Analysis

### 6.1 Secret Type Identification

| Secret Type | Active Analysis Available | Passive Analysis |
|-------------|---------------------------|------------------|
| GitHub Token | Yes - `gh api /user` | Token prefix, expiry format |
| AWS Key | Yes - `aws sts get-caller-identity` | Key ID format (AKIA*) |
| Slack Token | Yes - `slack api auth.test` | Token prefix (xoxb-, xoxp-) |
| RSA Private Key | Yes - TruffleHog Driftwood | Key length, format |
| Generic API Key | Depends on service | Entropy, context |

### 6.2 Active Verification (ACTIVE MODE ONLY)

**Requires explicit user confirmation for each verification:**

```
⚠️  ACTIVE VERIFICATION REQUEST

I will attempt to verify this {secret_type} by making an API call to {service}.

This will:
- Send the credential to {endpoint}
- May generate logs/alerts at the target service
- Confirm whether the credential is currently valid

Type 'CONFIRM' to proceed or 'skip' to use passive analysis only:
```

**GitHub Token Verification:**
```bash
# Test token validity
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: token {secret}" \
  -H "Accept: application/vnd.github+json" \
  https://api.github.com/user)

case $RESPONSE in
  200) echo "VERIFIED: Token is ACTIVE" ;;
  401) echo "VERIFIED: Token is INVALID/REVOKED" ;;
  403) echo "VERIFIED: Token is ACTIVE but rate-limited or scope-restricted" ;;
  *) echo "UNKNOWN: Unexpected response code $RESPONSE" ;;
esac
```

**AWS Key Verification:**
```bash
AWS_ACCESS_KEY_ID="{key_id}" \
AWS_SECRET_ACCESS_KEY="{secret_key}" \
aws sts get-caller-identity --output json 2>&1
```

### 6.3 TruffleHog Analyze (ACTIVE MODE ONLY, if available)

For supported credential types, enumerate permissions:

```bash
# Requires user confirmation
echo "{secret}" | trufflehog analyze --json 2>/dev/null
```

This returns:
- Owner/creator information
- Accessible resources
- Permission levels (read/write/admin)
- Scope limitations

### 6.4 Passive Analysis (BOTH MODES)

```bash
# Analyze secret structure without probing
SECRET="{secret_value}"

# Check for known prefixes
case "$SECRET" in
  ghp_*) echo "GitHub Personal Access Token (classic)" ;;
  gho_*) echo "GitHub OAuth Access Token" ;;
  ghu_*) echo "GitHub User-to-Server Token" ;;
  ghs_*) echo "GitHub Server-to-Server Token" ;;
  ghr_*) echo "GitHub Refresh Token" ;;
  github_pat_*) echo "GitHub Personal Access Token (fine-grained)" ;;
  AKIA*) echo "AWS Access Key ID" ;;
  xoxb-*) echo "Slack Bot Token" ;;
  xoxp-*) echo "Slack User Token" ;;
  sk-*) echo "Possible OpenAI/Stripe Secret Key" ;;
  pk_*) echo "Possible Stripe Publishable Key" ;;
  *) echo "Unknown format - analyze entropy and context" ;;
esac
```

### 6.5 GitHub App Analysis (for GitHub App credentials)

```bash
# Query current app state (public info, no auth needed)
gh api /apps/{app_slug} --jq '{
  id,
  slug,
  name,
  owner: .owner.login,
  created_at,
  permissions,
  events
}'

# Compare with leaked credentials
echo "Leaked App ID: {leaked_app_id}"
echo "Current App ID: $(gh api /apps/{app_slug} --jq '.id')"
echo "Match: $([ "{leaked_app_id}" = "$(gh api /apps/{app_slug} --jq '.id')" ] && echo 'YES' || echo 'NO - credentials likely rotated')"
```

### 6.6 Public Leak Check (PASSIVE - if ggshield available)

Check if the secret has been exposed in other public repositories:

```bash
# This is passive - it sends a hash, not the actual secret
ggshield secret check-secret "{secret_value}" 2>/dev/null
```
