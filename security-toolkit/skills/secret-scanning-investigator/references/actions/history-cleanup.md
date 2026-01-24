# Action: Generate History Cleanup Commands (8.5)

## Warning

```
⚠️  HISTORY REWRITE COMMANDS

The following commands will PERMANENTLY modify git history.
These are provided for reference only - review carefully before executing.

PREREQUISITES:
- Backup your repository
- Ensure all collaborators are informed
- The secret MUST be revoked BEFORE cleanup (cleanup does not revoke!)
```

## Option A: git-filter-repo (Recommended)

```bash
# Install if needed: pip install git-filter-repo

git clone --mirror https://github.com/{owner}/{repo}.git {repo}-mirror
cd {repo}-mirror
git filter-repo --replace-text <(echo '{secret}==>REDACTED')
git push --force --all
git push --force --tags
```

## Option B: BFG Repo-Cleaner (Faster for large repos)

```bash
# Install if needed: brew install bfg

git clone --mirror https://github.com/{owner}/{repo}.git {repo}-mirror
cd {repo}-mirror
echo '{secret}' > ../secrets-to-remove.txt
bfg --replace-text ../secrets-to-remove.txt
git reflog expire --expire=now --all
git gc --prune=now --aggressive
git push --force --all
git push --force --tags
```

## Post-Cleanup Steps

```
POST-CLEANUP:
- Force collaborators to rebase (not merge) their branches
- Re-enable branch protections
- Verify secret no longer appears: git log -p --all -S '{partial_secret}'
```

## When NOT to Rewrite History

History cleanup may not be worthwhile when:
- Secret is already revoked and poses no risk
- Repository is public and may have been cloned/forked
- Many collaborators would need to reset their local branches
- The secret has already been captured by external services

In these cases, focus on:
1. Revoking the credential
2. Monitoring for unauthorized access
3. Adding preventive measures for future
