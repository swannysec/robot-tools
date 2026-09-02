# Topic Normalization Reference

Reference document for starduster category taxonomy, static topic mapping table,
normalization rules, and controller classification fallback.

## Fixed Category List

Exactly one category is assigned per repo. The controller must choose from this list only.

| Category | Description |
|----------|-------------|
| AI & Machine Learning | ML frameworks, LLMs, NLP, computer vision, data science, model training/serving |
| CLI & Terminal Tools | Command-line utilities, shell tools, terminal emulators, TUI frameworks |
| Cloud & Infrastructure | Cloud providers, IaC, Kubernetes, Docker, serverless, monitoring, orchestration |
| Cybersecurity | Security tools, vulnerability scanners, penetration testing, SIEM, threat intel |
| Data & Databases | Databases, ORMs, query engines, data pipelines, ETL, analytics, visualization |
| Developer Tools | IDEs, editors, linters, formatters, build tools, package managers, dev utilities |
| Documentation & Writing | Documentation generators, static site generators, note-taking, knowledge management |
| Frontend & UI | Web frameworks, CSS libraries, component systems, design systems, animation |
| Game Development | Game engines, game frameworks, game tools, assets, physics engines |
| Mobile Development | iOS, Android, React Native, Flutter, cross-platform mobile frameworks |
| Networking & Protocols | HTTP libraries, WebSocket, gRPC, DNS, proxies, VPNs, networking utilities |
| Operating Systems & Low-Level | OS kernels, drivers, embedded systems, firmware, assembly, system programming |
| Programming Languages & Runtimes | Language implementations, compilers, interpreters, VMs, language tools |
| Web Backend & APIs | Web frameworks, REST/GraphQL APIs, authentication, middleware, microservices |
| Uncategorized | Repos that don't clearly fit any other category |

---

## Static Topic Mapping Table

This table maps common GitHub topics to normalized topic names and their default category.
The controller uses **exact matching** against this table first before applying
normalization rules or controller classification.

| Raw Topic (GitHub) | Normalized Topic | Default Category |
|---------------------|-----------------|------------------|
| `artificial-intelligence` | `artificial-intelligence` | AI & Machine Learning |
| `ai` | `artificial-intelligence` | AI & Machine Learning |
| `machine-learning` | `machine-learning` | AI & Machine Learning |
| `ml` | `machine-learning` | AI & Machine Learning |
| `deep-learning` | `deep-learning` | AI & Machine Learning |
| `neural-network` | `neural-networks` | AI & Machine Learning |
| `neural-networks` | `neural-networks` | AI & Machine Learning |
| `nlp` | `natural-language-processing` | AI & Machine Learning |
| `natural-language-processing` | `natural-language-processing` | AI & Machine Learning |
| `computer-vision` | `computer-vision` | AI & Machine Learning |
| `cv` | `computer-vision` | AI & Machine Learning |
| `llm` | `large-language-models` | AI & Machine Learning |
| `llms` | `large-language-models` | AI & Machine Learning |
| `large-language-model` | `large-language-models` | AI & Machine Learning |
| `gpt` | `large-language-models` | AI & Machine Learning |
| `chatgpt` | `large-language-models` | AI & Machine Learning |
| `transformer` | `transformers` | AI & Machine Learning |
| `transformers` | `transformers` | AI & Machine Learning |
| `pytorch` | `pytorch` | AI & Machine Learning |
| `tensorflow` | `tensorflow` | AI & Machine Learning |
| `rag` | `retrieval-augmented-generation` | AI & Machine Learning |
| `data-science` | `data-science` | AI & Machine Learning |
| `cli` | `command-line` | CLI & Terminal Tools |
| `command-line` | `command-line` | CLI & Terminal Tools |
| `terminal` | `terminal` | CLI & Terminal Tools |
| `tui` | `terminal-ui` | CLI & Terminal Tools |
| `shell` | `shell` | CLI & Terminal Tools |
| `bash` | `bash` | CLI & Terminal Tools |
| `zsh` | `zsh` | CLI & Terminal Tools |
| `kubernetes` | `kubernetes` | Cloud & Infrastructure |
| `k8s` | `kubernetes` | Cloud & Infrastructure |
| `docker` | `docker` | Cloud & Infrastructure |
| `terraform` | `terraform` | Cloud & Infrastructure |
| `aws` | `aws` | Cloud & Infrastructure |
| `cloud` | `cloud` | Cloud & Infrastructure |
| `devops` | `devops` | Cloud & Infrastructure |
| `infrastructure` | `infrastructure` | Cloud & Infrastructure |
| `security` | `security` | Cybersecurity |
| `cybersecurity` | `cybersecurity` | Cybersecurity |
| `hacking` | `penetration-testing` | Cybersecurity |
| `pentesting` | `penetration-testing` | Cybersecurity |
| `vulnerability` | `vulnerability-scanning` | Cybersecurity |
| `database` | `database` | Data & Databases |
| `sql` | `sql` | Data & Databases |
| `postgresql` | `postgresql` | Data & Databases |
| `mysql` | `mysql` | Data & Databases |
| `sqlite` | `sqlite` | Data & Databases |
| `redis` | `redis` | Data & Databases |
| `mongodb` | `mongodb` | Data & Databases |
| `elasticsearch` | `elasticsearch` | Data & Databases |
| `graphql` | `graphql` | Web Backend & APIs |
| `etl` | `etl` | Data & Databases |
| `data-pipeline` | `data-pipelines` | Data & Databases |
| `vim` | `vim` | Developer Tools |
| `neovim` | `neovim` | Developer Tools |
| `vscode` | `vscode` | Developer Tools |
| `editor` | `editor` | Developer Tools |
| `ide` | `ide` | Developer Tools |
| `linter` | `linting` | Developer Tools |
| `formatter` | `formatting` | Developer Tools |
| `git` | `git` | Developer Tools |
| `github` | `github` | Developer Tools |
| `testing` | `testing` | Developer Tools |
| `documentation` | `documentation` | Documentation & Writing |
| `docs` | `documentation` | Documentation & Writing |
| `markdown` | `markdown` | Documentation & Writing |
| `static-site-generator` | `static-site-generator` | Documentation & Writing |
| `obsidian` | `obsidian` | Documentation & Writing |
| `note-taking` | `note-taking` | Documentation & Writing |
| `react` | `react` | Frontend & UI |
| `reactjs` | `react` | Frontend & UI |
| `vue` | `vue` | Frontend & UI |
| `vuejs` | `vue` | Frontend & UI |
| `svelte` | `svelte` | Frontend & UI |
| `nextjs` | `nextjs` | Frontend & UI |
| `tailwindcss` | `tailwind-css` | Frontend & UI |
| `tailwind` | `tailwind-css` | Frontend & UI |
| `css` | `css` | Frontend & UI |
| `html` | `html` | Frontend & UI |
| `typescript` | `typescript` | Programming Languages & Runtimes |
| `javascript` | `javascript` | Programming Languages & Runtimes |
| `python` | `python` | Programming Languages & Runtimes |
| `rust` | `rust` | Programming Languages & Runtimes |
| `golang` | `go` | Programming Languages & Runtimes |
| `go` | `go` | Programming Languages & Runtimes |
| `ruby` | `ruby` | Programming Languages & Runtimes |
| `java` | `java` | Programming Languages & Runtimes |
| `swift` | `swift` | Programming Languages & Runtimes |
| `ios` | `ios` | Mobile Development |
| `android` | `android` | Mobile Development |
| `react-native` | `react-native` | Mobile Development |
| `flutter` | `flutter` | Mobile Development |
| `api` | `api` | Web Backend & APIs |
| `rest` | `rest-api` | Web Backend & APIs |
| `restful` | `rest-api` | Web Backend & APIs |
| `fastapi` | `fastapi` | Web Backend & APIs |
| `django` | `django` | Web Backend & APIs |
| `flask` | `flask` | Web Backend & APIs |
| `express` | `express` | Web Backend & APIs |
| `nodejs` | `nodejs` | Web Backend & APIs |
| `rails` | `ruby-on-rails` | Web Backend & APIs |

---

## Normalization Rules

For topics NOT found in the static mapping table, apply these rules in order:

1. **Lowercase:** Convert to lowercase
2. **Hyphenate:** Replace spaces, underscores, and dots with hyphens
3. **Strip invalid chars:** Remove characters not matching `[a-z0-9-]`
4. **Collapse hyphens:** Replace consecutive hyphens with a single hyphen
5. **Strip version suffixes:** Remove trailing version numbers (e.g., `react-18` -> `react`, `python3` -> `python`)
6. **Deduplicate:** If a repo has both a raw topic and its normalized equivalent, keep only the normalized form
7. **Validate format:** Final topic must match `^[a-z0-9]+(-[a-z0-9]+)*$`

### Version Stripping Examples

| Input | Output |
|-------|--------|
| `python3` | `python` |
| `react-18` | `react` |
| `es2024` | `es2024` (keep — this is a spec name, not a version) |
| `vue3` | `vue` |
| `http2` | `http2` (keep — this is a protocol name) |

**Heuristic:** Strip trailing digits only if the remaining string is a known technology
name in the static table. Otherwise, keep the digits.

---

## Controller Classification Fallback

For topics that cannot be normalized via the static table or rules, the controller
uses the following deterministic classification rules:

1. **Read the topic in context** of the repo's description, language, and other topics
2. **Select the most appropriate category** from the fixed list
3. **Generate a normalized topic name** following the rules above
4. **Do NOT invent new categories** — use "Uncategorized" if truly ambiguous

### Internal Classification Rules

For each unknown topic, the controller applies this classification pattern:

```
For each unknown topic, consider:
- What technology domain does this topic belong to?
- Which fixed category best matches?
- What would be a concise, hyphenated, lowercase name for this concept?

Examples of good normalization:
  "state management" -> "state-management" -> Frontend & UI
  "web scraping" -> "web-scraping" -> Data & Databases
  "code review" -> "code-review" -> Developer Tools
  "load balancing" -> "load-balancing" -> Cloud & Infrastructure
```

---

## Hub Note Threshold Rules

| Hub Type | Threshold | Rationale |
|----------|-----------|-----------|
| Category | 1+ repos | Categories are a fixed list; always generate if populated |
| Topic | 3+ repos | Prevents graph pollution from one-off topics |
| Author | 2+ repos | Single-repo authors don't provide discovery value |

### On Update Runs

- **New hubs:** Generate if threshold newly met
- **Existing hubs below threshold:** Stop regenerating the hub but do NOT delete the
  existing file. It becomes stale but harmless.
- **Existing hubs at or above threshold:** Regenerate entirely (hub notes contain no user content)
