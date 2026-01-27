---
name: ai-twitter-radar
description: |
  Discover trending AI tools, news, and insights from influential developers and AI advocates on Twitter/X using Bird CLI. Use PROACTIVELY when users need:
  (1) AI-related tweets, tools, or discussions from Twitter
  (2) What influential AI developers are currently talking about
  (3) AI news and trends from social media
  (4) Developer sentiment on AI tools and frameworks
  (5) New AI projects being shared on Twitter

  This is a READ-ONLY skill - no posting, liking, or account modifications.

  Triggers: "AI Twitter", "trending AI tools", "AI news Twitter", "what are AI developers saying", "AI tweets", "Twitter AI trends", "developer sentiment AI", "AI influencers"
---

# AI Twitter Radar

Discover AI trends, tools, and insights from Twitter/X using Bird CLI.

## Prerequisites

Bird CLI must be installed and authenticated:
```bash
# Check installation
bird --version

# Authentication uses browser cookies (Safari/Chrome/Firefox)
# If not authenticated, bird commands will fail with auth errors
```

## Core Discovery Workflows

### 1. AI News Feed

Get curated AI news from Twitter's Explore:
```bash
bird news --ai-only -n 20
```

Include related tweets for deeper context:
```bash
bird news --ai-only -n 10 --with-tweets
```

### 2. Search AI Topics

Search for specific AI tools, models, or concepts:
```bash
bird search "Claude AI" -n 30
bird search "GPT-4 API" -n 30
bird search "LLM agents" -n 30
bird search "AI coding assistant" -n 30
```

Filter to recent/popular:
```bash
bird search "Cursor IDE" -n 50 --json
```

### 3. Follow Influential Voices

Retrieve tweets from key AI developers and advocates:
```bash
bird user-tweets @karpathy -n 20
bird user-tweets @ylecun -n 20
bird user-tweets @sama -n 20
bird user-tweets @emaborisov -n 20
```

See references/influential-accounts.md for curated list.

### 4. Explore Discussions

Read full threads for context:
```bash
bird thread <tweet-url>
```

See what people are saying in replies:
```bash
bird replies <tweet-url> -n 50
```

### 5. Track Mentions

Find discussions about specific tools or people:
```bash
bird mentions --user @AnthropicAI -n 30
bird mentions --user @OpenAI -n 30
```

## Output Handling

### JSON for Analysis
```bash
bird search "AI agents" -n 100 --json > ai_agents.json
```

### Pagination for Volume
```bash
bird search "machine learning" -n 50 --max-pages 3
```

## Example Research Session

```bash
# 1. Check AI news
bird news --ai-only -n 15

# 2. Search trending topic
bird search "MCP servers Claude" -n 30

# 3. Check what key voices are saying
bird user-tweets @steipete -n 10
bird user-tweets @simonw -n 10

# 4. Deep-dive interesting thread
bird thread <interesting-tweet-url>
```

## Constraints

**READ-ONLY**: This skill only supports read operations:
- `bird read` / `bird <url>`
- `bird thread`
- `bird replies`
- `bird search`
- `bird mentions`
- `bird user-tweets`
- `bird news`

**DO NOT USE** any write operations (post, like, retweet, follow, etc.).
