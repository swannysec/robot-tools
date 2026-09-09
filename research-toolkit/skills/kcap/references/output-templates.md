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
  - kcap
  - broad-topic
  - specific-topic
---
```

Articles add `reading_time` when a word count is available and `published`. Videos add
`duration`, `channel`, and `published`. Tweets add `author_handle` and `thread_length`.
Full mode omits `description`.

Filenames are `YYYY-MM-DD-<slug>.md`. Slugs are lowercase ASCII, hyphenated, at most
50 characters, and fall back to `capture-<timestamp>`.

When `vault_name` is configured, success metadata may include an `obsidian_uri`. It is
emitted only when the controller can prove the written note is below the configured
output root and has a non-empty vault-relative path. A retained `vault_name` therefore
does not guarantee a URI: an exact configured path can legitimately suppress it rather
than inventing a vault-relative location.

## Validation and sanitization

- Require a non-empty single-line title and at least one valid tag.
- For standard and deep captures, ask for an ordinary 35-50 word TL;DR. Accuracy and
  effectiveness take priority over hitting an exact length.
- Enforce a hidden deterministic TL;DR ceiling of 75 words. Do not present that ceiling
  as the ordinary model target. The first two synthesis attempts use the ordinary policy;
  only after two responses are too long does a third, explicit repair request state the
  ceiling. If that repair is still too long, fail the capture. Full mode remains
  unchanged: it has no TL;DR target or repair path and keeps its normal two-attempt
  validation behavior.
- Require full cleaned content to contain at least 50 words.
- The renderer always prepends the deterministic `kcap` provenance tag. This tag is
  separate from the synthesis tag limit and is emitted exactly once even when defaults
  or model output also contain it.
- Ask for 1-5 grounded, topical tags, favoring a useful mix of established higher-level
  subjects and specific topics. For example, a United States Civil War battle may use
  `us-civil-war`, `battle`, and `military-history` rather than only people, dates, or a
  campaign name. Deterministic structural policy retains only
  unique, ordered tags that match `^[a-z0-9]+(-[a-z0-9]+)*$`, are at most 48 characters,
  are not digits only, and are not exact generic labels such as `article`, `video`,
  `tweet`, `summary`, or `content`; it rejects zero retained tags or more than five.
  This structural filtering cannot establish semantic relevance, so the model prompt and
  review remain responsible for topical grounding.
- Remove null/control characters, Obsidian Templater blocks, Dataview inline fields,
  and HTML script blocks from generated prose.
- Keep model-proposed reference URLs only when they pass HTTPS syntax and
  private-address-literal checks; sanitization performs no DNS lookup.
- JSON-quote every string inserted into YAML frontmatter.
