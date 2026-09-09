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
| `tags` | One to five lowercase-hyphenated local discovery terms |
| `summary` | Bounded sanitized summary |
| `key_features` | Bounded sanitized string list |
| `similar_to` | Bounded owner/repository list |
| `use_case` | Bounded sanitized sentence |
| `maturity` | `experimental`, `active`, `mature`, or `unmaintained` |
| `author_display` | Bounded sanitized display string |

The controller rejects malformed records, wrong identities, extra fields, forbidden
active markup, invalid tags, unsafe link targets, credentials, and values beyond the
field limits. The synthesizer aims for a useful mix of broad and specific terms, not a
padded maximum. The deterministic validator retains only one to five unique,
lowercase-hyphenated tags, rejects generic or digit-only values, and imposes the same
bounded tag syntax used by the rest of the catalog. One bounded retry may occur inside
the selected isolated adapter; a repeated invalid response is a safe failure.

GitHub topics are not a synthesis field. The controller obtains them from the GitHub
repository metadata, normalizes them deterministically, and retains them as source
metadata even when no suitable local discovery tag exists.

## Repository note shape

Validated repository notes have YAML frontmatter for identity and catalog metadata,
followed by a controller-managed body with Summary, Key Features, Use Case, Maturity,
GitHub Topics, Similar Projects, and Links sections. The controller preserves explicit
user-managed sections on refresh and regenerates only auto-managed fields. Every path
is derived from a sanitized repository identity and checked to remain under the configured
catalog root.

Every generated repository note and Markdown hub includes the deterministic `starduster`
provenance tag. Each repository note also includes one to five model-selected semantic
discovery tags derived primarily from the gathered description and README content.
Controller-managed tracking lets refresh replace only the prior generated tags while
preserving user-managed tags and deduplicating the provenance tag. GitHub topics remain
separate source metadata and render as local links to their topic hubs; they are context
for synthesis, not the source list for the Obsidian `tags` property.

The controller also regenerates category, topic, and author hub notes and seven Bases
indexes. Bases use self-relative filters and the current `order` and `groupBy` syntax;
open them directly rather than embedding them, because embedding changes Obsidian's
`this` context. The controller writes each validated artifact atomically and returns only aggregate counts;
the public result does not include note text, raw descriptions, README content, or model
prose. When publication requires a narrow elevated `commit-output`, the pending catalog
contains only sanitized final artifacts and a bounded manifest; raw inputs and model
responses are removed first. Unpublished sanitized catalogs expire after seven days.

## Sanitization invariants

Strings are normalized to a single safe line where required. YAML delimiters, Templater
expressions, Dataview fields, active HTML, embeds, image tracking syntax, unsafe URI
schemes, control characters, and credential-like material are rejected or removed before
rendering. Wikilink and tag targets use the same lowercase hyphenated validation rule.
The final frontmatter must parse as YAML before a note is published.
