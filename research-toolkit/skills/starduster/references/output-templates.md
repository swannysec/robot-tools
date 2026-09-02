# Output contract and templates

This reference describes the deterministic controller's validated output. It is not a
host workflow, model prompt, or command recipe. Raw GitHub and model content remains in
the private controller boundary until it passes strict validation and sanitization.

## Synthesis record

For every repository, the adapter requires one JSON object with exactly these fields:

| Field | Validated form |
|---|---|
| `full_name` | Matching input owner/repository identity |
| `html_url` | Matching GitHub repository URL |
| `category` | One fixed normalized category |
| `normalized_topics` | Lowercase hyphenated topic list |
| `summary` | Bounded sanitized summary |
| `key_features` | Bounded sanitized string list |
| `similar_to` | Bounded owner/repository list |
| `use_case` | Bounded sanitized sentence |
| `maturity` | `experimental`, `active`, `mature`, or `unmaintained` |
| `author_display` | Bounded sanitized display string |

The controller rejects malformed records, wrong identities, extra fields, forbidden
active markup, invalid tags, unsafe link targets, credentials, and values beyond the
field limits. It does not auto-fill missing required synthesis fields from untrusted
metadata. One bounded retry may occur inside the selected isolated adapter; a repeated
invalid response is a safe failure.

## Repository note shape

Validated repository notes have YAML frontmatter for identity and catalog metadata,
followed by a controller-managed body with Summary, Key Features, Use Case, Maturity,
Topics, Similar Projects, and Links sections. The controller preserves explicit
user-managed sections on refresh and regenerates only auto-managed fields. Every path
is derived from a sanitized repository identity and checked to remain under the configured
catalog root.

The controller also regenerates category, topic, and author hub notes and seven Bases
indexes. It writes each validated artifact atomically and returns only aggregate counts;
the public result does not include note text, raw descriptions, README content, or model
prose.

## Sanitization invariants

Strings are normalized to a single safe line where required. YAML delimiters, Templater
expressions, Dataview fields, active HTML, embeds, image tracking syntax, unsafe URI
schemes, control characters, and credential-like material are rejected or removed before
rendering. Wikilink and tag targets use the same lowercase hyphenated validation rule.
The final frontmatter must parse as YAML before a note is published.
