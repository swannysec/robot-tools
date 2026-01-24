# Credential Rotation Guides (8.9)

Based on secret type, provide specific rotation instructions.

---

## GitHub Personal Access Token

1. Go to: https://github.com/settings/tokens
2. Find the compromised token (may be listed by note/name)
3. Click "Delete" to revoke immediately
4. Click "Generate new token" to create replacement
5. Update all systems using the old token

**Verification:**
```bash
# Test old token is revoked
curl -H "Authorization: token {old_token}" https://api.github.com/user
# Should return 401 Unauthorized
```

---

## GitHub App Private Key

1. Go to: https://github.com/organizations/{org}/settings/apps/{app}
2. Scroll to "Private keys"
3. Click "Generate a private key" for new key
4. Update all systems using the old key
5. Delete the old key from the settings page

**Verification:**
```bash
# Generate JWT with new key and test
gh api /app -H "Authorization: Bearer {new_jwt}"
```

---

## AWS Access Key

1. Go to: https://console.aws.amazon.com/iam/
2. Navigate to Users → {user} → Security credentials
3. Click "Create access key" for new credentials
4. Update all systems using the old key
5. Click "Make inactive" then "Delete" for old key

**Verification:**
```bash
# Test old key is revoked
AWS_ACCESS_KEY_ID="{old_key}" \
AWS_SECRET_ACCESS_KEY="{old_secret}" \
aws sts get-caller-identity
# Should return InvalidClientTokenId error
```

---

## Slack Token

### Bot Token (xoxb-)
1. Go to: https://api.slack.com/apps/{app_id}
2. Navigate to "OAuth & Permissions"
3. Click "Reinstall to Workspace" to rotate tokens
4. Update all systems using the old token

### User Token (xoxp-)
1. User must reauthorize the application
2. Or revoke from: https://slack.com/apps/manage

**Verification:**
```bash
# Test old token is revoked
curl -X POST https://slack.com/api/auth.test \
  -H "Authorization: Bearer {old_token}"
# Should return invalid_auth error
```

---

## OpenAI API Key

1. Go to: https://platform.openai.com/api-keys
2. Click "Create new secret key" for replacement
3. Update all systems using the old key
4. Delete the old key from the dashboard

**Verification:**
```bash
# Test old key is revoked
curl https://api.openai.com/v1/models \
  -H "Authorization: Bearer {old_key}"
# Should return 401 Unauthorized
```

---

## Stripe API Key

1. Go to: https://dashboard.stripe.com/apikeys
2. Click "Roll key" for the compromised key
3. Stripe will generate a new key immediately
4. Update all systems within the grace period (24 hours default)

**Verification:**
```bash
# Test old key after grace period
curl https://api.stripe.com/v1/charges \
  -u {old_key}:
# Should return invalid_api_key error
```

---

## Generic Rotation Checklist

For any credential type:

1. **Identify all usage locations**
   - Search codebase: `grep -r "{partial_secret}" .`
   - Check CI/CD secrets
   - Check environment variables
   - Check deployment configurations

2. **Generate new credential**
   - Use the service's credential management interface
   - Follow service-specific instructions above

3. **Update all usage locations**
   - Update in order of criticality
   - Test each location after update

4. **Revoke old credential**
   - Only after all locations are updated
   - Verify revocation works as expected

5. **Monitor for failures**
   - Watch logs for authentication failures
   - Be prepared to rollback if issues arise

6. **Document the rotation**
   - Record in incident tracker
   - Update runbooks if needed
