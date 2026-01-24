# Action: Generate SARIF Output (8.4)

## Using Gitleaks (if available)

```bash
# If gitleaks available
gitleaks detect --source {repo_path} --report-format sarif --report-path {output_path}/secret-scan-{date}.sarif
```

## Manual SARIF Generation

For GitHub alerts without gitleaks:

```bash
cat > {output_path}/secret-scan-{date}.sarif << 'EOF'
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "secret-scanning-investigator",
        "version": "1.0.0",
        "informationUri": "https://github.com/features/security"
      }
    },
    "results": [
      {
        "ruleId": "{secret_type}",
        "level": "{severity}",
        "message": {"text": "{description}"},
        "locations": [{
          "physicalLocation": {
            "artifactLocation": {"uri": "{file_path}"},
            "region": {"startLine": {line}}
          }
        }],
        "partialFingerprints": {
          "primaryLocationLineHash": "{hash}"
        }
      }
    ]
  }]
}
EOF
```

## Severity Mapping

| Risk Rating | SARIF Level |
|-------------|-------------|
| CRITICAL | error |
| HIGH | error |
| MEDIUM | warning |
| LOW | note |

## Integration with Security Dashboards

The SARIF file can be uploaded to:
- GitHub Code Scanning (via API or Action)
- Azure DevOps
- Defect Dojo
- Other SARIF-compatible tools

```bash
# Upload to GitHub Code Scanning
gh api repos/{owner}/{repo}/code-scanning/sarifs \
  --method POST \
  -f commit_sha="{sha}" \
  -f ref="refs/heads/{branch}" \
  -f sarif="$(gzip -c {sarif_file} | base64)"
```
