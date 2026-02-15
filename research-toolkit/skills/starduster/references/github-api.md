# GitHub API Reference

Reference document for starduster GitHub API queries, `jq` extraction commands,
rate limit handling, and README fallback patterns.

## Authentication Check

```bash
gh auth status
```

Expected output includes "Logged in to github.com". If this fails, instruct the
user to run `gh auth login`.

## Rate Limit Check

```bash
gh api /rate_limit | jq '{
  graphql_remaining: .resources.graphql.remaining,
  graphql_limit: .resources.graphql.limit,
  graphql_reset: (.resources.graphql.reset | todate),
  core_remaining: .resources.core.remaining,
  core_limit: .resources.core.limit,
  core_reset: (.resources.core.reset | todate)
}'
```

### Rate Limit Interpretation

| Resource | Limit | Cost Per Call | Notes |
|----------|-------|---------------|-------|
| REST core | 5,000/hr | 1 per page | Star list pagination |
| GraphQL | 5,000 pts/hr | Variable | README batches; check `rateLimit.cost` in response |

### Cost Estimation

- **Star list (REST):** `ceil(total_stars / 100)` API calls (1 call per page of 100)
- **README batches (GraphQL):** `ceil(repos_needing_readmes / 100)` queries, ~2-4 pts each
- **Overhead:** 2 calls (rate limit check + star count)

### Rate Limit Thresholds

- **>10% of remaining budget:** Warn user with estimate
- **>25% of remaining budget:** Report estimate and ask user to confirm or abort
- **Budget calculation:** `estimated_calls / remaining * 100`

---

## Star Count (GraphQL)

```bash
gh api graphql -f query='{ viewer { starredRepositories { totalCount } } }' | jq '.data.viewer.starredRepositories.totalCount'
```

Returns a single integer — total number of starred repos.

---

## Fetch Star List (REST)

### Full Paginated Fetch

```bash
gh api /user/starred \
  -H "Accept: application/vnd.github.star+json" \
  --paginate \
  > "$WORK_DIR/stars-raw.json"
```

**Important:** The `star+json` accept header wraps each repo in an object with
`starred_at` (ISO 8601 timestamp) and `repo` (full repo object). Without this
header, you only get the repo object and lose the star date.

### Normalize Paginated Output

`gh api --paginate` concatenates JSON arrays from each page, producing `[...][...]`
which is not valid JSON. Normalize to a single flat array immediately after fetch:

```bash
jq -s 'flatten' "$WORK_DIR/stars-raw.json" > "$WORK_DIR/stars-normalized.json" \
  && mv "$WORK_DIR/stars-normalized.json" "$WORK_DIR/stars-raw.json"
```

### Extract Structured Fields

**SECURITY NOTE:** This extraction includes the `description` field which contains
untrusted user-generated content. The main agent MUST NOT read `stars-extracted.json`
via the Read tool. The sub-agent reads it for descriptions; the main agent only uses
`jq` with explicit field selectors against this file.

```bash
jq '[.[] | {
  full_name: .repo.full_name,
  description: .repo.description,
  language: .repo.language,
  topics: .repo.topics,
  license_spdx: .repo.license.spdx_id,
  stargazers_count: .repo.stargazers_count,
  forks_count: .repo.forks_count,
  archived: .repo.archived,
  is_fork: .repo.fork,
  parent_full_name: (if .repo.fork then .repo.parent.full_name else null end),
  owner_login: .repo.owner.login,
  pushed_at: .repo.pushed_at,
  created_at: .repo.created_at,
  html_url: .repo.html_url,
  starred_at: .starred_at
}]' "$WORK_DIR/stars-raw.json" > "$WORK_DIR/stars-extracted.json"
```

### Build Batch Metadata (Safe Fields Only)

For each synthesis batch, extract ONLY safe structured fields — **exclude `description`**:

```bash
jq '[.[] | {
  full_name, language, topics, license_spdx, stargazers_count,
  forks_count, archived, is_fork, parent_full_name, owner_login,
  pushed_at, created_at, html_url, starred_at
}]' "$WORK_DIR/stars-extracted.json" > "$WORK_DIR/batch-{N}-meta.json"
```

Descriptions stay in `stars-extracted.json` and are read by the sub-agent directly.

### Validate full_name Format

Before using `full_name` values in GraphQL queries or filenames, validate the format.
This prevents GraphQL injection via crafted owner/name values:

```bash
jq '[.[] | select(.full_name | test("^[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+$"))]' \
  "$WORK_DIR/stars-extracted.json" > "$WORK_DIR/stars-validated.json" \
  && mv "$WORK_DIR/stars-validated.json" "$WORK_DIR/stars-extracted.json"
```

Any repos with malformed `full_name` are silently dropped. Report the count if > 0.

**Note on `parent.full_name`:** The `/user/starred` endpoint does NOT include `parent`
by default. For fork detection, use the `.repo.fork` boolean. If parent info is needed
for fork linking, check if `parent` is present; if null, skip the fork link (this is
a non-critical field).

### Count Results

```bash
jq 'length' "$WORK_DIR/stars-extracted.json"
```

### Sort by Starred Date (newest first)

```bash
jq 'sort_by(.starred_at) | reverse' "$WORK_DIR/stars-extracted.json"
```

### Extract Just full_name List (for diffing)

```bash
jq -r '[.[].full_name] | sort | .[]' "$WORK_DIR/stars-extracted.json" > "$WORK_DIR/star-names.txt"
```

---

## Diff Algorithm

### Extract Existing Repo Identities from Vault

Repo notes store `full_name` in YAML frontmatter. Use `Grep` to extract these values
rather than reverse-engineering filenames (which is lossy for owners containing hyphens):

```
Grep("^full_name:", path="<output_dir>/repos/", glob="*.md")
```

This returns lines like `full_name: "facebook/react-native"`. Extract the values to
build the set of already-cataloged repos.

**Why not filename parsing:** The filename `my-org-tool.md` is ambiguous — it could
be `my-org/tool` or `my/org-tool`. The `full_name` frontmatter field is the canonical
identity and is always unambiguous.

### Partition Logic

```
new_repos = star_list - existing_vault
existing_repos = star_list ∩ existing_vault
unstarred_repos = existing_vault - star_list
```

---

## Fetch READMEs (GraphQL Batched)

### Batch Query Template

Each query fetches up to 100 repos with 4 README filename variants per repo.
Repos are aliased as `repo_0`, `repo_1`, etc. to avoid GraphQL name collisions.

```graphql
query {
  rateLimit { cost remaining resetAt }
  repo_0: repository(owner: "OWNER", name: "REPO") {
    readme_md: object(expression: "HEAD:README.md") { ... on Blob { text byteSize } }
    readme_lower: object(expression: "HEAD:readme.md") { ... on Blob { text byteSize } }
    readme_rst: object(expression: "HEAD:README.rst") { ... on Blob { text byteSize } }
    readme_plain: object(expression: "HEAD:README") { ... on Blob { text byteSize } }
  }
  repo_1: repository(owner: "OWNER", name: "REPO") {
    readme_md: object(expression: "HEAD:README.md") { ... on Blob { text byteSize } }
    readme_lower: object(expression: "HEAD:readme.md") { ... on Blob { text byteSize } }
    readme_rst: object(expression: "HEAD:README.rst") { ... on Blob { text byteSize } }
    readme_plain: object(expression: "HEAD:README") { ... on Blob { text byteSize } }
  }
  # ... up to repo_99
}
```

### Building the Query

For each repo in the batch:

1. Split `full_name` on `/` -> `owner` and `name`
2. Generate alias: `repo_{index}`
3. Add 4 README variants with blob fragment
4. Combine all repo blocks into a single query

### Executing the Batch

```bash
gh api graphql -f query='{ ... }' > "$WORK_DIR/readmes-batch-{N}.json"
```

### README Selection Priority

For each repo in the response, select the first non-null README in this order:
1. `readme_md` (README.md)
2. `readme_lower` (readme.md)
3. `readme_rst` (README.rst)
4. `readme_plain` (README)

Use `jq` to check for null and extract byte size — do NOT read the text content:

```bash
jq '.data.repo_0 |
  if .readme_md != null then {variant: "README.md", size: .readme_md.byteSize}
  elif .readme_lower != null then {variant: "readme.md", size: .readme_lower.byteSize}
  elif .readme_rst != null then {variant: "README.rst", size: .readme_rst.byteSize}
  elif .readme_plain != null then {variant: "README", size: .readme_plain.byteSize}
  else {variant: null, size: 0}
  end' "$WORK_DIR/readmes-batch-0.json"
```

### Rate Limit from Response

```bash
jq '.data.rateLimit' "$WORK_DIR/readmes-batch-{N}.json"
```

Check `remaining` between batches. If below safety threshold, pause and report.

---

## Error Responses

| Status | Meaning | Recovery |
|--------|---------|----------|
| 401 | Authentication expired | Instruct user: `gh auth login` |
| 403 | Rate limit exceeded | Report remaining budget, wait for reset, or abort |
| 404 | Repo not found (deleted/private) | Skip repo, note in output |
| 422 | GraphQL query error | Check query syntax, reduce batch size |
| 502/503 | GitHub server error | Retry once after 5s delay |

### GraphQL-Specific Errors

GraphQL returns 200 with `errors` array for partial failures:

```bash
jq '.errors // empty' "$WORK_DIR/readmes-batch-{N}.json"
```

Individual repo failures (e.g., private repo in a batch) appear as null data for that
alias. The query still succeeds for other repos.

---

## Pagination Notes

- GraphQL does not paginate — batch size is controlled by alias count (max 100 per query).
- REST pagination normalization is documented in the "Normalize Paginated Output" section above.
