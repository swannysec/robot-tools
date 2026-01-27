---
description: Clean up git branches - removes merged branches, warns about stale branches, syncs with remote
arguments:
  - name: mode
    description: "Cleanup mode: 'safe' (merged only), 'stale' (include old branches), or 'sync' (fetch and prune)"
    required: false
---

# Git Branch Cleanup

Mode: $ARGUMENTS.mode (default: safe)

## 1. Sync with Remote
```bash
git fetch --all --prune
```

This updates remote tracking branches and removes references to deleted remote branches.

## 2. Current State
```bash
echo "Current branch:"
git branch --show-current

echo "\nAll local branches:"
git branch -vv

echo "\nRemote branches:"
git branch -r
```

## 3. Identify Branches for Cleanup

### Merged Branches (Safe to Delete)
```bash
echo "Branches merged into main/master:"
git branch --merged main 2>/dev/null || git branch --merged master 2>/dev/null

echo "\nBranches merged into current branch:"
git branch --merged
```

### Stale Branches (Caution)
```bash
echo "Branches with no recent commits (>30 days):"
for branch in $(git branch --format='%(refname:short)'); do
  last_commit=$(git log -1 --format='%cr' "$branch" 2>/dev/null)
  echo "  $branch: $last_commit"
done
```

### Gone Branches (Remote Deleted)
```bash
echo "Local branches whose remote is gone:"
git branch -vv | grep ': gone]' | awk '{print $1}'
```

## 4. Cleanup Actions

### Safe Mode (merged only)
Delete branches that have been merged:
```bash
# List branches to delete (excluding main, master, develop)
git branch --merged | grep -vE '^\*|main|master|develop' 

# Delete them (requires confirmation)
# git branch -d <branch-name>
```

### Stale Mode (include old branches)
Review and potentially delete branches with no recent activity:
```bash
# For each stale branch, show last commit
git log -1 --format='%h %s (%cr)' <branch-name>

# Delete if confirmed (force delete for unmerged)
# git branch -D <branch-name>
```

### Sync Mode (fetch and prune only)
Just sync with remote, don't delete local branches:
```bash
git fetch --all --prune
git remote prune origin
```

## 5. Cleanup Report

Provide summary:
```markdown
## Branch Cleanup Report

### Deleted
- [branch-name] (reason: merged/stale/gone)

### Kept
- [branch-name] (reason: current/protected/unmerged)

### Warnings
- [branch-name]: Has unmerged changes, review before deleting

### Remote Status
- Pruned [N] stale remote references
```

## Safety Rules

**Never delete:**
- Current branch (switch first if needed)
- `main`, `master`, `develop` (protected branches)
- Branches with unpushed commits (warn user)

**Always confirm before:**
- Force deleting unmerged branches (`-D`)
- Deleting branches with recent commits (<7 days)

## Post-Cleanup
```bash
echo "Remaining branches:"
git branch -vv
```
