# Agentic Systems & Workflows Reference

## Table of Contents
1. [Foundational Concepts](#foundational-concepts)
2. [Agent Architectures](#agent-architectures)
3. [Tool Use & Function Calling](#tool-use--function-calling)
4. [Multi-Agent Systems](#multi-agent-systems)
5. [Orchestration Frameworks](#orchestration-frameworks)
6. [Planning & Reasoning](#planning--reasoning)
7. [Memory Systems](#memory-systems)
8. [Production Patterns](#production-patterns)
9. [Authoritative Sources](#authoritative-sources)

---

## Foundational Concepts

### Core Agent Papers
| Paper | Authors | Year | Key Contribution | URL |
|-------|---------|------|------------------|-----|
| ReAct: Synergizing Reasoning and Acting | Yao et al. | 2022 | Reason+Act paradigm | https://arxiv.org/abs/2210.03629 |
| Toolformer | Schick et al. | 2023 | Self-taught tool use | https://arxiv.org/abs/2302.04761 |
| Chain-of-Thought Prompting | Wei et al. | 2022 | Step-by-step reasoning | https://arxiv.org/abs/2201.11903 |
| Tree of Thoughts | Yao et al. | 2023 | Deliberate problem solving | https://arxiv.org/abs/2305.10601 |
| Reflexion | Shinn et al. | 2023 | Self-reflection for learning | https://arxiv.org/abs/2303.11366 |
| HuggingGPT/JARVIS | Shen et al. | 2023 | LLM as controller | https://arxiv.org/abs/2303.17580 |
| AutoGPT | Significant Gravitas | 2023 | Autonomous agents | https://github.com/Significant-Gravitas/AutoGPT |
| Generative Agents | Park et al. | 2023 | Believable simulacra | https://arxiv.org/abs/2304.03442 |

### Agent Definition
An **AI agent** is a system that:
1. Perceives its environment (via tools, APIs, user input)
2. Reasons about goals and plans
3. Takes actions to achieve objectives
4. Learns from feedback/results

### Agent vs Workflow Spectrum
```
Simple Prompt → Chain → Router → Agent → Multi-Agent
     ↑                                        ↑
  Deterministic                         Autonomous
  Low complexity                       High complexity
  Predictable                          Emergent behavior
```

---

## Agent Architectures

### ReAct Pattern (Reasoning + Acting)
```
Thought: I need to find the current weather in Paris
Action: weather_api(location="Paris")
Observation: Temperature: 15°C, Condition: Cloudy
Thought: I have the information needed to answer
Action: respond("The current weather in Paris is 15°C and cloudy")
```

**Implementation:**
```python
# LangChain ReAct
from langchain.agents import create_react_agent
from langchain_openai import ChatOpenAI

agent = create_react_agent(
    llm=ChatOpenAI(model="gpt-4"),
    tools=[weather_tool, search_tool],
    prompt=react_prompt
)
```

### Plan-and-Execute Pattern
```
1. Planner: Create step-by-step plan
2. Executor: Execute each step
3. Re-planner: Adjust based on results
```

**Best for:** Complex multi-step tasks where planning upfront is valuable

### LATS (Language Agent Tree Search)
```
                    [Root Query]
                   /      |      \
            [Plan A]  [Plan B]  [Plan C]
              /  \       |        /  \
          [...]  [...]  [...]  [...]  [...]
```
- Explores multiple solution paths
- Uses tree search with LLM as heuristic
- Paper: https://arxiv.org/abs/2310.04406

### Function Calling Agent
```python
# OpenAI native function calling
response = client.chat.completions.create(
    model="gpt-4-turbo",
    messages=messages,
    tools=[{
        "type": "function",
        "function": {
            "name": "get_weather",
            "description": "Get current weather",
            "parameters": {
                "type": "object",
                "properties": {
                    "location": {"type": "string"}
                },
                "required": ["location"]
            }
        }
    }],
    tool_choice="auto"
)
```

---

## Tool Use & Function Calling

### Tool Definition Best Practices
| Aspect | Recommendation | Rationale |
|--------|----------------|-----------|
| Name | Verb-noun, snake_case | `search_web`, not `webSearcher` |
| Description | Clear, specific | LLM uses this to decide when to call |
| Parameters | Minimal required | Reduce decision complexity |
| Return format | Structured, consistent | Easier for LLM to parse |
| Error handling | Clear error messages | LLM can recover or retry |

### Tool Categories
| Category | Examples | Considerations |
|----------|----------|----------------|
| Information retrieval | Search, RAG, API queries | Rate limits, caching |
| Code execution | Python REPL, sandbox | Security sandboxing |
| File operations | Read, write, edit | Permission scoping |
| External services | Email, calendar, Slack | Authentication, rate limits |
| Browser automation | Playwright, Selenium | Reliability, wait strategies |

### Function Calling Comparison
| Provider | Format | Parallel Calls | Streaming | URL |
|----------|--------|----------------|-----------|-----|
| OpenAI | JSON Schema | Yes | Yes | https://platform.openai.com/docs/guides/function-calling |
| Anthropic | JSON Schema | Yes | Yes | https://docs.anthropic.com/en/docs/build-with-claude/tool-use |
| Google | Proto-like | Yes | Yes | https://ai.google.dev/gemini-api/docs/function-calling |
| Mistral | JSON Schema | Yes | No | https://docs.mistral.ai/capabilities/function_calling/ |

---

## Multi-Agent Systems

### Architectures

#### 1. Hierarchical (Manager-Worker)
```
         [Orchestrator Agent]
        /         |          \
[Research]   [Writing]    [Review]
  Agent        Agent        Agent
```
- Clear chain of command
- Orchestrator delegates and synthesizes
- Examples: CrewAI, AutoGen hierarchical

#### 2. Peer-to-Peer (Collaborative)
```
[Agent A] ←→ [Agent B] ←→ [Agent C]
     ↖          ↑          ↗
       ←→ [Agent D] ←→
```
- Agents communicate directly
- No central controller
- Emergent collaboration

#### 3. Debate/Adversarial
```
[Proposer] → [Critic] → [Proposer] → [Judge]
```
- Multiple agents argue positions
- Improves reasoning through challenge
- Paper (Debate): https://arxiv.org/abs/1805.00899

#### 4. Mixture of Experts
```
[Router] → [Expert 1: Code]
         → [Expert 2: Writing]
         → [Expert 3: Research]
```
- Route queries to specialized agents
- Reduces individual agent complexity

### Framework Comparison
| Framework | Architecture | Strengths | URL |
|-----------|--------------|-----------|-----|
| AutoGen | Conversational | Flexible dialogues | https://microsoft.github.io/autogen/ |
| CrewAI | Role-based | Simple setup, good defaults | https://www.crewai.com/ |
| LangGraph | Graph-based | Fine-grained control | https://langchain-ai.github.io/langgraph/ |
| Swarm (OpenAI) | Handoff-based | Lightweight, educational | https://github.com/openai/swarm |
| Agency Swarm | Hierarchical | Communication flows | https://github.com/VRSEN/agency-swarm |

---

## Orchestration Frameworks

### LangGraph
State machine approach to agent orchestration.

```python
from langgraph.graph import StateGraph, END

# Define state
class AgentState(TypedDict):
    messages: list
    next_step: str

# Build graph
workflow = StateGraph(AgentState)
workflow.add_node("research", research_node)
workflow.add_node("write", write_node)
workflow.add_node("review", review_node)

workflow.add_edge("research", "write")
workflow.add_conditional_edges("write", should_review)
workflow.add_edge("review", END)

app = workflow.compile()
```

**Documentation:** https://langchain-ai.github.io/langgraph/

### AutoGen
Conversation-centric multi-agent framework.

```python
from autogen import AssistantAgent, UserProxyAgent

assistant = AssistantAgent("assistant", llm_config=llm_config)
user_proxy = UserProxyAgent("user_proxy", code_execution_config={"work_dir": "coding"})

user_proxy.initiate_chat(assistant, message="Write a Python function to...")
```

**Documentation:** https://microsoft.github.io/autogen/

### CrewAI
Role-based agent teams.

```python
from crewai import Agent, Task, Crew

researcher = Agent(
    role="Senior Researcher",
    goal="Find comprehensive information",
    backstory="Expert at synthesizing research",
    tools=[search_tool]
)

task = Task(
    description="Research AI agents",
    agent=researcher
)

crew = Crew(agents=[researcher], tasks=[task])
result = crew.kickoff()
```

**Documentation:** https://docs.crewai.com/

---

## Planning & Reasoning

### Planning Strategies
| Strategy | Description | Best For |
|----------|-------------|----------|
| Zero-shot | Direct task execution | Simple tasks |
| Few-shot | Examples guide planning | Pattern-matching tasks |
| Chain-of-Thought | Step-by-step reasoning | Complex reasoning |
| Plan-then-Execute | Upfront planning | Multi-step tasks |
| Iterative Refinement | Plan → Execute → Revise | Uncertain tasks |

### Reasoning Techniques
| Technique | Description | Paper |
|-----------|-------------|-------|
| Chain-of-Thought (CoT) | Explicit reasoning steps | https://arxiv.org/abs/2201.11903 |
| Self-Consistency | Multiple reasoning paths, vote | https://arxiv.org/abs/2203.11171 |
| Tree of Thoughts (ToT) | Explore reasoning branches | https://arxiv.org/abs/2305.10601 |
| Graph of Thoughts (GoT) | Non-linear reasoning | https://arxiv.org/abs/2308.09687 |
| Skeleton-of-Thought | Parallel generation | https://arxiv.org/abs/2307.15337 |

### Self-Correction Patterns
```
Execute → Evaluate → Critique → Revise → Re-execute
```

Key papers:
- Reflexion: https://arxiv.org/abs/2303.11366
- Self-Refine: https://arxiv.org/abs/2303.17651
- CRITIC: https://arxiv.org/abs/2305.11738

---

## Memory Systems

### Memory Types
| Type | Scope | Implementation | Use Case |
|------|-------|----------------|----------|
| Working Memory | Current task | Context window | Active reasoning |
| Short-term | Session | In-memory store | Conversation context |
| Long-term | Persistent | Vector DB + KV store | User preferences, facts |
| Episodic | Event-based | Structured logs | Past interactions |
| Semantic | Knowledge | Knowledge graph | Domain knowledge |
| Procedural | Skills | Tool definitions | Learned capabilities |

### Memory Architecture (Generative Agents)
```
Experience Stream → Reflection → Memory Retrieval → Planning → Action
                         ↓
                   Higher-level insights
                   (stored as memories)
```
Paper: https://arxiv.org/abs/2304.03442

### Implementation Patterns
```python
# Memory with recency, importance, relevance scoring
def retrieve_memories(query, memories, top_k=5):
    scores = []
    for memory in memories:
        recency = decay_function(memory.timestamp)
        importance = memory.importance_score
        relevance = cosine_similarity(embed(query), memory.embedding)

        score = recency * 0.3 + importance * 0.3 + relevance * 0.4
        scores.append((memory, score))

    return sorted(scores, key=lambda x: x[1], reverse=True)[:top_k]
```

---

## Production Patterns

### Reliability Strategies
| Strategy | Implementation | Benefit |
|----------|----------------|---------|
| Retry with backoff | Exponential backoff on failures | Handle transient errors |
| Fallback models | Try GPT-4 → GPT-3.5 → Claude | Cost/reliability trade-off |
| Timeout management | Per-step and total timeouts | Prevent runaway agents |
| Human-in-the-loop | Approval gates for actions | Safety for high-stakes |
| Checkpointing | Save state between steps | Resume on failure |

### Cost Control
| Approach | Savings | Trade-off |
|----------|---------|-----------|
| Model routing | 50-80% | Complexity |
| Caching | Variable | Stale results |
| Shorter prompts | 20-40% | Less context |
| Fewer iterations | Linear | Quality |
| Smaller models | 10-100x | Capability |

### Observability Stack
| Component | Tools | Purpose |
|-----------|-------|---------|
| Tracing | LangSmith, Phoenix, Langfuse | Track execution flow |
| Logging | Structured logs, OpenTelemetry | Debug failures |
| Metrics | Latency, cost, success rate | Monitor health |
| Evaluation | RAGAS, custom evals | Quality assurance |

### Security Considerations
1. **Prompt injection**: Validate and sanitize all inputs
2. **Tool permissions**: Principle of least privilege
3. **Output validation**: Check agent outputs before acting
4. **Rate limiting**: Prevent runaway loops
5. **Sandboxing**: Isolate code execution

---

## Authoritative Sources

### Official Documentation
- LangChain Agents: https://python.langchain.com/docs/modules/agents/
- LlamaIndex Agents: https://docs.llamaindex.ai/en/stable/module_guides/deploying/agents/
- OpenAI Assistants: https://platform.openai.com/docs/assistants/overview
- Anthropic Tool Use: https://docs.anthropic.com/en/docs/build-with-claude/tool-use

### Research Collections
- Awesome LLM Agents: https://github.com/kaushikb11/awesome-llm-agents
- Agent Survey (Wang et al.): https://arxiv.org/abs/2308.11432
- Tool Learning Survey: https://arxiv.org/abs/2304.08354

### Engineering Blogs
- Anthropic Building Agents: https://www.anthropic.com/research/building-effective-agents
- LangChain Blog: https://blog.langchain.dev/
- Lilian Weng's Blog: https://lilianweng.github.io/
- Chip Huyen's Blog: https://huyenchip.com/blog/

### Tutorials & Courses
- DeepLearning.AI Agents: https://www.deeplearning.ai/short-courses/
- Full Stack LLM Bootcamp: https://fullstackdeeplearning.com/
- Prompt Engineering Guide: https://www.promptingguide.ai/
