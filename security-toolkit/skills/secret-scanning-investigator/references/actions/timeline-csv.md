# Action: Export Timeline as CSV (8.8)

## Output Format

```bash
cat > {output_path}/timeline-{alert_number}.csv << 'EOF'
date,event,source,details
{date},{event},{source},{details}
...
EOF
```

## Example Output

```csv
date,event,source,details
2024-01-15T10:30:00Z,Secret committed,"git log",Commit abc123 by user@example.com
2024-01-15T10:35:00Z,PR merged,"GitHub API","PR #123: Add configuration"
2024-01-15T11:00:00Z,Alert opened,"GitHub API",Alert #19 created
2024-01-20T14:00:00Z,Investigation started,"Manual","Triggered by security team"
2024-01-20T14:30:00Z,Credential verified inactive,"TruffleHog","App ID mismatch indicates rotation"
2024-01-20T15:00:00Z,Investigation completed,"Manual","Risk rating: MEDIUM"
```

## CSV Fields

| Field | Description | Example |
|-------|-------------|---------|
| date | ISO 8601 timestamp | 2024-01-15T10:30:00Z |
| event | Brief description of what happened | Secret committed |
| source | How this was determined | git log, GitHub API, TruffleHog |
| details | Additional context | Commit SHA, PR number, etc. |

## Usage

The CSV can be imported into:
- Spreadsheet applications (Excel, Google Sheets)
- Security information and event management (SIEM) systems
- Compliance reporting tools
- Custom dashboards

## Generating from Investigation Data

```python
import csv
import json

# Load artifacts
with open('/tmp/secret-scan-{alert_number}/provenance.json') as f:
    provenance = json.load(f)
with open('/tmp/secret-scan-{alert_number}/context.json') as f:
    context = json.load(f)

# Build timeline
events = [
    {
        'date': provenance['introducing_commit']['author_date'],
        'event': 'Secret committed',
        'source': 'git log',
        'details': f"Commit {provenance['introducing_commit']['sha']}"
    },
    # Add more events...
]

# Sort by date
events.sort(key=lambda x: x['date'])

# Write CSV
with open('timeline.csv', 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=['date', 'event', 'source', 'details'])
    writer.writeheader()
    writer.writerows(events)
```
