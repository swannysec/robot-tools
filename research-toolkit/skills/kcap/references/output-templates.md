# Synthesis and output contract

The normative model-output schemas are `schemas/standard.json`, `schemas/deep.json`,
and `schemas/full.json`. Runtime adapters validate and write `synthesis.json`; `render`
validates it again before writing the note.

## Standard mode

Required synthesis fields include title, author, published date, one-sentence TL;DR,
summary, takeaways, detailed notes, quotes, references, tags, chapters, and thread
posts. Non-applicable `chapters` and `thread` values are empty arrays. The body
order is:

1. `## TL;DR`
2. `## Chapters` for videos when chapters exist, or `## Thread` for multi-post data
3. `## Summary`
4. `## Key Takeaways`
5. `## Detailed Notes`
6. `## Notable Quotes` when present
7. `## References & Resources` when present
8. `## Source Metadata`

## Deep mode

Deep mode keeps all standard sections and inserts these after detailed notes:

1. `## Critical Analysis`
2. `## Counterarguments & Limitations`
3. `## Open Questions`
4. `## Connections`
5. `## Action Items`

Quotes add significance and references add context.

## Full mode

Full mode returns title, author, published date, tags, and complete cleaned Markdown.
It removes navigation, advertisements, cookie notices, and footer boilerplate; fixes
broken formatting; and preserves all substantive text, code, quotes, data, ordering,
and structure. It never summarizes or editorializes. The body is only:

```markdown
## Source

[example.com](https://example.com/source)

{cleaned_content}
```

Full mode always adds the `full-capture` tag and is unavailable for YouTube.

## Shared frontmatter

Every note preserves this shape, with content-type-specific additions:

```yaml
---
title: "Title"
source: "https://example.com/source"
source_normalized: "example.com/source"
date_captured: 2026-08-28
content_type: article
capture_mode: standard
author: "Author"
domain: "example.com"
description: "One-line description"
tags:
  - topic
---
```

Articles add `reading_time` when a word count is available and `published`. Videos add
`duration`, `channel`, and `published`. Tweets add `author_handle` and `thread_length`.
Full mode omits `description`.

Filenames are `YYYY-MM-DD-<slug>.md`. Slugs are lowercase ASCII, hyphenated, at most
50 characters, and fall back to `capture-<timestamp>`.

## Validation and sanitization

- Require a non-empty single-line title and at least one valid tag.
- Require TL;DR to contain no more than 30 words.
- Require full cleaned content to contain at least 50 words.
- Permit tags only when they match `^[a-z0-9]+(-[a-z0-9]+)*$`.
- Remove null/control characters, Obsidian Templater blocks, Dataview inline fields,
  and HTML script blocks from generated prose.
- Keep model-proposed reference URLs only when they pass HTTPS syntax and
  private-address-literal checks; sanitization performs no DNS lookup.
- JSON-quote every string inserted into YAML frontmatter.
