# RAG Systems & Vector Databases Reference

## Table of Contents
1. [Foundational Concepts](#foundational-concepts)
2. [RAG Architectures](#rag-architectures)
3. [Chunking Strategies](#chunking-strategies)
4. [Embedding Models](#embedding-models)
5. [Vector Databases](#vector-databases)
6. [Retrieval Strategies](#retrieval-strategies)
7. [Evaluation & Benchmarks](#evaluation--benchmarks)
8. [Production Patterns](#production-patterns)
9. [Authoritative Sources](#authoritative-sources)

---

## Foundational Concepts

### Core RAG Papers
| Paper | Authors | Year | Key Contribution | URL |
|-------|---------|------|------------------|-----|
| RAG: Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks | Lewis et al. | 2020 | Original RAG formulation | https://arxiv.org/abs/2005.11401 |
| REALM: Retrieval-Augmented Language Model Pre-Training | Guu et al. | 2020 | Pre-training with retrieval | https://arxiv.org/abs/2002.08909 |
| Self-RAG: Learning to Retrieve, Generate, and Critique | Asai et al. | 2023 | Self-reflective RAG | https://arxiv.org/abs/2310.11511 |
| CRAG: Corrective RAG | Yan et al. | 2024 | Self-correcting retrieval | https://arxiv.org/abs/2401.15884 |
| Adaptive-RAG | Jeong et al. | 2024 | Query complexity routing | https://arxiv.org/abs/2403.14403 |

### RAG vs Fine-Tuning Decision Matrix
| Criterion | RAG Preferred | Fine-Tuning Preferred |
|-----------|---------------|----------------------|
| Data freshness | Dynamic/frequently updated | Static domain knowledge |
| Data volume | Large corpus (>10K docs) | Smaller, curated dataset |
| Interpretability | Need to cite sources | Black-box acceptable |
| Cost | Lower inference cost acceptable | Minimize per-query latency |
| Customization | Factual recall | Style/format adaptation |

---

## RAG Architectures

### Naive RAG
```
Query → Embed → Vector Search → Top-K → Concatenate → LLM → Response
```
- Simple but effective baseline
- Issues: Lost in the middle, irrelevant retrieval, no query understanding

### Advanced RAG Patterns

#### 1. Query Transformation
```
Query → Query Rewriting → Multi-Query Generation → Retrieval → Fusion → LLM
```
- **HyDE** (Hypothetical Document Embeddings): Generate hypothetical answer, embed that instead
  - Paper: https://arxiv.org/abs/2212.10496
- **Multi-Query**: Generate multiple query variations, retrieve for each, fuse results
- **Step-Back Prompting**: Abstract query to higher-level concept first

#### 2. Hierarchical Retrieval
```
Query → Coarse Retrieval (BM25) → Fine Retrieval (Dense) → Reranking → LLM
```
- Two-stage retrieval improves precision
- BM25 for recall, dense embeddings for semantic matching
- Reranker (e.g., Cohere Rerank, cross-encoder) for final ordering

#### 3. Agentic RAG
```
Query → Agent → [Tool Selection: Search | Retrieve | Calculate] → Iterate → Response
```
- Agent decides when/what to retrieve
- Can combine RAG with other tools
- Examples: LangChain agents, LlamaIndex agents

#### 4. Graph RAG
```
Documents → Entity Extraction → Knowledge Graph → Graph Traversal + Vector Search → LLM
```
- Microsoft GraphRAG: https://microsoft.github.io/graphrag/
- Combines structured relationships with semantic search
- Better for multi-hop reasoning

---

## Chunking Strategies

### Chunking Methods Comparison
| Method | Pros | Cons | Best For |
|--------|------|------|----------|
| Fixed-size | Simple, predictable | Breaks semantic units | Uniform documents |
| Recursive | Respects structure | Complex implementation | Code, structured text |
| Semantic | Meaningful boundaries | Computationally expensive | Long-form content |
| Document-based | Preserves context | Large chunks | Short documents |
| Sentence-based | Natural boundaries | May be too granular | QA systems |

### Chunking Best Practices
- **Chunk size**: 256-1024 tokens typical; larger for synthesis, smaller for precision
- **Overlap**: 10-20% overlap prevents information loss at boundaries
- **Metadata**: Preserve source, page, section for citation
- **Parent-child**: Store both chunk and parent document for context expansion

### Implementation References
- LangChain text splitters: https://python.langchain.com/docs/modules/data_connection/document_transformers/
- LlamaIndex node parsers: https://docs.llamaindex.ai/en/stable/module_guides/loading/node_parsers/

---

## Embedding Models

### Current Leaders (as of 2024-2025)
| Model | Dimensions | Context | MTEB Score | Provider | URL |
|-------|------------|---------|------------|----------|-----|
| text-embedding-3-large | 3072 | 8191 | 64.6 | OpenAI | https://platform.openai.com/docs/guides/embeddings |
| text-embedding-3-small | 1536 | 8191 | 62.3 | OpenAI | https://platform.openai.com/docs/guides/embeddings |
| voyage-3 | 1024 | 32000 | 67.2 | Voyage AI | https://docs.voyageai.com/docs/embeddings |
| embed-v3 | 1024 | 512 | 66.3 | Cohere | https://docs.cohere.com/docs/embed |
| bge-large-en-v1.5 | 1024 | 512 | 64.2 | BAAI (OSS) | https://huggingface.co/BAAI/bge-large-en-v1.5 |
| gte-large | 1024 | 512 | 63.1 | Alibaba (OSS) | https://huggingface.co/thenlper/gte-large |
| nomic-embed-text-v1.5 | 768 | 8192 | 62.3 | Nomic (OSS) | https://huggingface.co/nomic-ai/nomic-embed-text-v1.5 |

### Embedding Selection Criteria
- **Dimension trade-offs**: Higher dims = better quality, more storage/compute
- **Context length**: Critical for long documents; voyage-3 leads at 32K
- **Domain specificity**: Consider domain-tuned models for specialized use
- **Matryoshka embeddings**: text-embedding-3 supports dimension reduction

### Benchmarks
- MTEB Leaderboard: https://huggingface.co/spaces/mteb/leaderboard
- BEIR Benchmark: https://github.com/beir-cellar/beir

---

## Vector Databases

### Database Comparison
| Database | Type | Scalability | Filtering | Managed Option | URL |
|----------|------|-------------|-----------|----------------|-----|
| Pinecone | Cloud-native | Excellent | Rich metadata | Yes (only) | https://www.pinecone.io/ |
| Weaviate | Hybrid | Excellent | GraphQL | Yes | https://weaviate.io/ |
| Qdrant | Self-hosted/Cloud | Excellent | Payload filtering | Yes | https://qdrant.tech/ |
| Milvus | Self-hosted/Cloud | Excellent | Expression | Yes (Zilliz) | https://milvus.io/ |
| Chroma | Embedded | Moderate | Basic | No | https://www.trychroma.com/ |
| pgvector | Postgres extension | Good | SQL | Via providers | https://github.com/pgvector/pgvector |
| LanceDB | Embedded | Good | SQL-like | No | https://lancedb.github.io/lancedb/ |

### Selection Guide
| Use Case | Recommended | Rationale |
|----------|-------------|-----------|
| Prototype/POC | Chroma, LanceDB | Zero config, embedded |
| Production SaaS | Pinecone, Weaviate Cloud | Managed, scalable |
| Self-hosted prod | Qdrant, Milvus | Feature-rich, scalable |
| Existing Postgres | pgvector | No new infra |
| Cost-sensitive | Qdrant (self-hosted), pgvector | No per-query costs |

### Index Types
- **HNSW**: Best quality, higher memory (default for most)
- **IVF**: Good quality, lower memory, slower
- **PQ**: Compressed, fastest, lower quality
- **Hybrid**: HNSW + PQ for balance

---

## Retrieval Strategies

### Retrieval Methods
| Method | Mechanism | Strengths | Weaknesses |
|--------|-----------|-----------|------------|
| Dense (vector) | Semantic similarity | Handles paraphrasing | Misses exact matches |
| Sparse (BM25) | Keyword matching | Precise term matching | No semantic understanding |
| Hybrid | Dense + Sparse fusion | Best of both | More complex |
| Reranking | Cross-encoder scoring | High precision | Slower, limited candidates |

### Hybrid Search Implementation
```python
# Reciprocal Rank Fusion (RRF) example
def rrf_fusion(dense_results, sparse_results, k=60):
    scores = {}
    for rank, doc in enumerate(dense_results):
        scores[doc.id] = scores.get(doc.id, 0) + 1 / (k + rank + 1)
    for rank, doc in enumerate(sparse_results):
        scores[doc.id] = scores.get(doc.id, 0) + 1 / (k + rank + 1)
    return sorted(scores.items(), key=lambda x: x[1], reverse=True)
```

### Reranking Models
| Model | Provider | Latency | Quality | URL |
|-------|----------|---------|---------|-----|
| rerank-v3 | Cohere | Fast | Excellent | https://docs.cohere.com/docs/rerank |
| bge-reranker-v2-m3 | BAAI | Medium | Very Good | https://huggingface.co/BAAI/bge-reranker-v2-m3 |
| cross-encoder/ms-marco | Sentence-Transformers | Slow | Good | https://huggingface.co/cross-encoder/ms-marco-MiniLM-L-6-v2 |

---

## Evaluation & Benchmarks

### RAG Evaluation Frameworks
| Framework | Focus | URL |
|-----------|-------|-----|
| RAGAS | End-to-end RAG metrics | https://docs.ragas.io/ |
| TruLens | Feedback functions | https://www.trulens.org/ |
| LangSmith | Tracing & evaluation | https://docs.smith.langchain.com/ |
| Phoenix (Arize) | Observability | https://docs.arize.com/phoenix |

### Key Metrics
| Metric | Measures | Computation |
|--------|----------|-------------|
| Context Relevance | Retrieval quality | Relevance of retrieved chunks to query |
| Faithfulness | Groundedness | Answer supported by retrieved context |
| Answer Relevance | Response quality | Answer addresses the query |
| Context Precision | Retrieval precision | Relevant chunks ranked higher |
| Context Recall | Retrieval recall | All relevant info retrieved |

### RAGAS Implementation
```python
from ragas import evaluate
from ragas.metrics import faithfulness, context_relevancy, answer_relevancy

result = evaluate(
    dataset,
    metrics=[faithfulness, context_relevancy, answer_relevancy]
)
```

---

## Production Patterns

### Scaling Considerations
1. **Embedding caching**: Cache embeddings to reduce API costs
2. **Async retrieval**: Parallelize retrieval across indices
3. **Result caching**: Cache frequent queries with TTL
4. **Batch processing**: Batch embedding requests (OpenAI supports up to 2048)

### Cost Optimization
| Strategy | Savings | Trade-off |
|----------|---------|-----------|
| Smaller embedding model | 5-10x | Slight quality drop |
| Dimension reduction | 2-4x storage | Minimal quality impact |
| Aggressive chunking | Fewer embeddings | May lose context |
| Query caching | Variable | Stale results |

### Monitoring Checklist
- [ ] Retrieval latency (p50, p95, p99)
- [ ] Embedding API costs
- [ ] Vector DB query costs
- [ ] Retrieval relevance scores
- [ ] LLM token usage
- [ ] End-to-end latency
- [ ] Error rates by component

---

## Authoritative Sources

### Official Documentation
- OpenAI Embeddings Guide: https://platform.openai.com/docs/guides/embeddings
- Anthropic RAG Guide: https://docs.anthropic.com/en/docs/build-with-claude/retrieval-augmented-generation
- LangChain RAG: https://python.langchain.com/docs/tutorials/rag/
- LlamaIndex: https://docs.llamaindex.ai/

### Research & Surveys
- RAG Survey (Gao et al., 2024): https://arxiv.org/abs/2312.10997
- Chunking Survey: https://arxiv.org/abs/2402.05131
- MTEB Benchmark: https://arxiv.org/abs/2210.07316

### Engineering Blogs
- Pinecone Learning Center: https://www.pinecone.io/learn/
- Weaviate Blog: https://weaviate.io/blog
- LangChain Blog: https://blog.langchain.dev/
