# Code Generation & AI Coding Tools Reference

## Table of Contents
1. [Code LLMs Overview](#code-llms-overview)
2. [AI Coding Assistants](#ai-coding-assistants)
3. [Code Generation Techniques](#code-generation-techniques)
4. [Evaluation & Benchmarks](#evaluation--benchmarks)
5. [IDE Integrations](#ide-integrations)
6. [Specialized Tools](#specialized-tools)
7. [Best Practices](#best-practices)
8. [Authoritative Sources](#authoritative-sources)

---

## Code LLMs Overview

### Current Code Models (2024-2025)
| Model | Provider | Context | Strengths | URL |
|-------|----------|---------|-----------|-----|
| Claude 3.5 Sonnet / Claude 3 Opus | Anthropic | 200K | Reasoning, long context, agentic | https://docs.anthropic.com/en/docs/about-claude/models |
| GPT-4 Turbo / GPT-4o | OpenAI | 128K | Broad capability, function calling | https://platform.openai.com/docs/models |
| Gemini 1.5 Pro | Google | 1M+ | Massive context, multimodal | https://ai.google.dev/gemini-api/docs |
| DeepSeek Coder V2 | DeepSeek | 128K | Strong code, open weights | https://github.com/deepseek-ai/DeepSeek-Coder |
| CodeLlama | Meta | 100K | Open source, fine-tunable | https://github.com/facebookresearch/codellama |
| StarCoder2 | BigCode | 16K | Open source, multi-language | https://huggingface.co/bigcode/starcoder2-15b |
| Codestral | Mistral | 32K | Fast, efficient | https://mistral.ai/news/codestral/ |
| Qwen2.5-Coder | Alibaba | 128K | Strong benchmarks, open | https://huggingface.co/Qwen/Qwen2.5-Coder-32B |

### Model Selection Guide
| Use Case | Recommended | Rationale |
|----------|-------------|-----------|
| Complex refactoring | Claude 3 Opus, GPT-4 | Best reasoning |
| Quick completions | Codestral, GPT-4o-mini | Fast, cost-effective |
| Long codebase context | Gemini 1.5 Pro, Claude 3.5 | Large context windows |
| Self-hosted | DeepSeek, Qwen2.5-Coder | Open weights, strong performance |
| Security-sensitive | Self-hosted models | Data stays local |

### Foundational Papers
| Paper | Year | Contribution | URL |
|-------|------|--------------|-----|
| Codex | 2021 | Foundation for Copilot | https://arxiv.org/abs/2107.03374 |
| StarCoder | 2023 | Open code model | https://arxiv.org/abs/2305.06161 |
| CodeLlama | 2023 | Llama for code | https://arxiv.org/abs/2308.12950 |
| DeepSeek-Coder | 2024 | Strong open code model | https://arxiv.org/abs/2401.14196 |
| AlphaCode | 2022 | Competitive programming | https://arxiv.org/abs/2203.07814 |

---

## AI Coding Assistants

### Commercial Tools
| Tool | Type | Model | Key Features | URL |
|------|------|-------|--------------|-----|
| GitHub Copilot | IDE plugin | GPT-4 class | Completions, chat, CLI | https://github.com/features/copilot |
| Cursor | IDE | Multiple | AI-first editor, codebase awareness | https://cursor.sh/ |
| Claude Code | CLI | Claude | Terminal agent, tool use | https://docs.anthropic.com/en/docs/claude-code |
| Codeium | IDE plugin | Proprietary | Free tier, fast | https://codeium.com/ |
| Amazon CodeWhisperer | IDE plugin | Proprietary | AWS integration, security scanning | https://aws.amazon.com/codewhisperer/ |
| Tabnine | IDE plugin | Multiple | Local/cloud, enterprise | https://www.tabnine.com/ |
| Sourcegraph Cody | IDE/Web | Multiple | Codebase context, search | https://sourcegraph.com/cody |
| Replit AI | IDE | Proprietary | Browser IDE, instant deploy | https://replit.com/ai |
| Windsurf | IDE | Multiple | AI-native editor | https://codeium.com/windsurf |
| Zed AI | IDE | Multiple | Fast editor, AI inline | https://zed.dev/ |

### Feature Comparison
| Feature | Copilot | Cursor | Claude Code | Codeium |
|---------|---------|--------|-------------|---------|
| Inline completion | ✓ | ✓ | - | ✓ |
| Chat interface | ✓ | ✓ | ✓ | ✓ |
| Codebase awareness | Partial | ✓ | ✓ | Partial |
| Multi-file edits | Limited | ✓ | ✓ | Limited |
| Terminal/CLI | ✓ | - | ✓ | - |
| Custom models | - | ✓ | - | - |
| Free tier | - | Limited | - | ✓ |

### Open Source Tools
| Tool | Description | URL |
|------|-------------|-----|
| Continue | Open-source AI code assistant | https://github.com/continuedev/continue |
| Tabby | Self-hosted AI coding assistant | https://github.com/TabbyML/tabby |
| Aider | AI pair programming in terminal | https://github.com/paul-gauthier/aider |
| GPT-Engineer | Generate codebases from prompts | https://github.com/gpt-engineer-org/gpt-engineer |
| OpenHands (Devin OSS) | Autonomous AI software engineer | https://github.com/All-Hands-AI/OpenHands |
| SWE-agent | Autonomous bug fixing agent | https://github.com/princeton-nlp/SWE-agent |

---

## Code Generation Techniques

### Prompting Strategies
| Strategy | Description | Best For |
|----------|-------------|----------|
| Zero-shot | Direct request | Simple tasks |
| Few-shot | Examples in prompt | Pattern-heavy tasks |
| Chain-of-thought | Step-by-step reasoning | Complex logic |
| Self-debugging | Generate → Test → Fix | Iterative refinement |
| Specification-first | Describe then implement | Precise requirements |

### Effective Code Prompts
```markdown
# Good prompt structure
## Context
- Language/framework
- Existing code patterns
- Constraints

## Task
Specific, clear description

## Requirements
- Functional requirements
- Non-functional (performance, style)
- Edge cases to handle

## Examples (if helpful)
Input → Expected output
```

### Code-Specific Techniques

#### 1. Fill-in-the-Middle (FIM)
```
<prefix>def calculate_total(items):
    """Calculate total price with discounts."""
<suffix>
    return total</suffix>
<middle>    total = 0
    for item in items:
        total += item.price * (1 - item.discount)
</middle>
```
Used by: StarCoder, CodeLlama, Codestral

#### 2. Repository-Level Context
```python
# Include relevant context
context = f"""
# Project structure
{tree_output}

# Related files
## {related_file_1}
{file_1_content}

# Current file
## {current_file}
{current_content}

# Task: {user_request}
"""
```

#### 3. Test-Driven Generation
```
1. Write test cases first
2. Generate implementation
3. Run tests
4. Iterate until passing
```

---

## Evaluation & Benchmarks

### Code Benchmarks
| Benchmark | Focus | Languages | URL |
|-----------|-------|-----------|-----|
| HumanEval | Function synthesis | Python | https://github.com/openai/human-eval |
| HumanEval+ | Extended HumanEval | Python | https://github.com/evalplus/evalplus |
| MBPP | Basic programming | Python | https://github.com/google-research/google-research/tree/master/mbpp |
| MultiPL-E | Multi-language | 18+ languages | https://github.com/nuprl/MultiPL-E |
| DS-1000 | Data science | Python | https://github.com/xlang-ai/DS-1000 |
| SWE-bench | Real GitHub issues | Python | https://github.com/princeton-nlp/SWE-bench |
| CodeContests | Competitive programming | Multiple | https://github.com/google-deepmind/code_contests |
| LiveCodeBench | Continuously updated | Multiple | https://livecodebench.github.io/ |
| BigCodeBench | Complex tasks | Python | https://github.com/bigcode-project/bigcodebench |

### Benchmark Results (Approximate, 2024-2025)
| Model | HumanEval | MBPP | SWE-bench |
|-------|-----------|------|-----------|
| Claude 3.5 Sonnet | 92% | 90% | 49% |
| GPT-4o | 90% | 87% | 33% |
| DeepSeek-Coder-V2 | 90% | 89% | 22% |
| Gemini 1.5 Pro | 84% | 81% | - |
| CodeLlama-70B | 67% | 65% | - |

*Note: Benchmarks are frequently updated; verify current scores*

### Evaluation Metrics
| Metric | Description | Use Case |
|--------|-------------|----------|
| pass@k | % passing with k samples | Generation capability |
| Code BLEU | Syntax-aware BLEU | Translation quality |
| Exact Match | Exact string match | Deterministic tasks |
| Functional Correctness | Tests pass | Real-world utility |
| Code Quality | Lint, complexity | Production readiness |

---

## IDE Integrations

### VS Code Extensions
| Extension | Provider | Features | URL |
|-----------|----------|----------|-----|
| GitHub Copilot | GitHub | Completions, chat | https://marketplace.visualstudio.com/items?itemName=GitHub.copilot |
| Continue | Continue | Open source, multi-model | https://marketplace.visualstudio.com/items?itemName=Continue.continue |
| Codeium | Codeium | Free completions | https://marketplace.visualstudio.com/items?itemName=Codeium.codeium |
| Cody | Sourcegraph | Codebase-aware | https://marketplace.visualstudio.com/items?itemName=sourcegraph.cody-ai |
| Amazon Q | AWS | AWS integration | https://marketplace.visualstudio.com/items?itemName=AmazonWebServices.amazon-q-vscode |

### JetBrains IDEs
| Plugin | Features | URL |
|--------|----------|-----|
| GitHub Copilot | Full Copilot features | https://plugins.jetbrains.com/plugin/17718-github-copilot |
| Codeium | Free AI completions | https://plugins.jetbrains.com/plugin/20540-codeium |
| Tabnine | Enterprise-friendly | https://plugins.jetbrains.com/plugin/12798-tabnine |
| Amazon Q | AWS integration | https://plugins.jetbrains.com/plugin/24267-amazon-q |

### Neovim
| Plugin | Description | URL |
|--------|-------------|-----|
| copilot.vim | Official Copilot | https://github.com/github/copilot.vim |
| codeium.vim | Codeium | https://github.com/Exafunction/codeium.vim |
| avante.nvim | Multi-model AI | https://github.com/yetone/avante.nvim |
| ChatGPT.nvim | ChatGPT integration | https://github.com/jackMort/ChatGPT.nvim |

---

## Specialized Tools

### Code Review
| Tool | Focus | URL |
|------|-------|-----|
| CodeRabbit | PR review automation | https://coderabbit.ai/ |
| Greptile | Codebase Q&A, PR review | https://greptile.com/ |
| What The Diff | PR summaries | https://whatthediff.ai/ |
| Codacy | Quality & security | https://www.codacy.com/ |

### Documentation Generation
| Tool | Focus | URL |
|------|-------|-----|
| Mintlify | Docs from code | https://mintlify.com/ |
| Swimm | Code documentation | https://swimm.io/ |
| Docstring AI | Python docstrings | Various IDE plugins |

### Testing
| Tool | Focus | URL |
|------|-------|-----|
| Codium AI | Test generation | https://www.codium.ai/ |
| Diffblue Cover | Java unit tests | https://www.diffblue.com/ |
| Ponicode | AI test writing | https://www.ponicode.com/ |

### Code Search & Understanding
| Tool | Focus | URL |
|------|-------|-----|
| Sourcegraph | Code search + AI | https://sourcegraph.com/ |
| Bloop | AI code search | https://bloop.ai/ |
| Phind | Developer search | https://phind.com/ |

---

## Best Practices

### Effective Use of AI Coding Tools
1. **Provide context**: Include relevant code, types, and comments
2. **Be specific**: Clear, detailed prompts get better results
3. **Iterate**: Refine generated code through conversation
4. **Verify**: Always review and test generated code
5. **Learn patterns**: Understand what the tool generates well

### Code Quality Considerations
| Aspect | Mitigation |
|--------|------------|
| Security | Review for vulnerabilities, use SAST tools |
| Correctness | Write tests, verify edge cases |
| Performance | Profile generated code, benchmark |
| Maintainability | Ensure code follows project conventions |
| Licensing | Be aware of training data implications |

### Security Best Practices
1. **Never trust generated code blindly** - Review for injection, auth issues
2. **Sanitize inputs** - AI may not consider all attack vectors
3. **Check dependencies** - Verify suggested packages are legitimate
4. **Secrets handling** - AI may expose or mishandle secrets
5. **Code review** - Human review remains essential

### When AI Coding Tools Excel
- Boilerplate code generation
- API integration patterns
- Unit test scaffolding
- Documentation generation
- Syntax translation between languages
- Common algorithm implementations

### When to Be Cautious
- Security-critical code
- Novel algorithmic problems
- Domain-specific optimization
- Complex stateful systems
- Performance-critical paths

---

## Authoritative Sources

### Official Documentation
- GitHub Copilot Docs: https://docs.github.com/en/copilot
- OpenAI Code Guide: https://platform.openai.com/docs/guides/code
- Anthropic Claude Docs: https://docs.anthropic.com/
- Google Code with Gemini: https://ai.google.dev/gemini-api/docs/code-execution

### Research
- Code LLM Survey: https://arxiv.org/abs/2311.10372
- SWE-bench Paper: https://arxiv.org/abs/2310.06770
- Repository-Level Code: https://arxiv.org/abs/2403.04143
- AI-Assisted Programming Survey: https://arxiv.org/abs/2302.06590

### Engineering Blogs
- GitHub Engineering: https://github.blog/engineering/
- Cursor Blog: https://cursor.sh/blog
- Sourcegraph Blog: https://about.sourcegraph.com/blog
- Continue Dev Blog: https://blog.continue.dev/

### Leaderboards
- Big Code Models Leaderboard: https://huggingface.co/spaces/bigcode/bigcode-models-leaderboard
- SWE-bench Leaderboard: https://www.swebench.com/
- LiveCodeBench: https://livecodebench.github.io/
