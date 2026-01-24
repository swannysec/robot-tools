# Health Metrics Reference

Detailed scoring algorithms, weights, and thresholds for the Health Score analysis mode.

## Composite Score Formula

```
composite_score = Σ(metric_score × weight)

Where:
  - coupling_score × 0.25
  - complexity_score × 0.25
  - dead_code_score × 0.20
  - test_coverage_score × 0.15
  - documentation_score × 0.15
```

---

## Metric Calculations

### 1. Coupling Score (25% weight)

Measures how interconnected modules are. Lower coupling = more maintainable.

**Data Collection:**
```
For each exported symbol:
  → find_referencing_symbols(symbol, file)
  → Count unique referencing files
```

**Formula:**
```
avg_refs_per_export = total_references / total_exports
coupling_score = max(0, 100 - (avg_refs_per_export × 5))
```

**Interpretation:**
| Avg Refs | Score | Interpretation |
|----------|-------|----------------|
| 0-4 | 80-100 | Low coupling, well-isolated modules |
| 5-10 | 50-75 | Moderate coupling, some shared utilities |
| 11-15 | 25-45 | High coupling, consider refactoring |
| 16+ | 0-20 | Critical coupling, modules tightly bound |

**Flags:**
- 🔴 Any module with Ca (afferent coupling) > 15
- 🟠 Any module with Ce (efferent coupling) > 10
- 🔄 Circular dependencies between modules

---

### 2. Complexity Score (25% weight)

Measures cyclomatic complexity and decision points in code.

**Data Collection:**
```
For each function body:
  → Count: if, elif, else, for, while, try, except, case/match
  → Sum all decision points
```

**Formula:**
```
avg_branches_per_function = total_decision_points / total_functions
complexity_score = max(0, 100 - (avg_branches_per_function × 3))
```

**Interpretation:**
| Avg Branches | Score | Interpretation |
|--------------|-------|----------------|
| 0-5 | 85-100 | Simple, easy to understand |
| 6-10 | 70-82 | Moderate complexity |
| 11-20 | 40-67 | Complex, consider splitting |
| 21+ | 0-37 | Very complex, refactor needed |

**Flags:**
- 🔴 Any function with > 20 decision points
- 🟠 Any function with > 10 decision points
- Functions with complexity > 15 should be listed individually

---

### 3. Dead Code Score (20% weight)

Measures unused exports that may be technical debt.

**Data Collection:**
```
For each exported symbol:
  → find_referencing_symbols(symbol, file)
  → If reference_count == 0, mark as dead
```

**Formula:**
```
dead_ratio = dead_exports / total_exports
dead_code_score = 100 - (dead_ratio × 100)
```

**Interpretation:**
| Dead Ratio | Score | Interpretation |
|------------|-------|----------------|
| 0-5% | 95-100 | Minimal dead code |
| 6-15% | 85-94 | Some cleanup needed |
| 16-30% | 70-84 | Notable technical debt |
| 31%+ | <70 | Significant cleanup required |

**Flags:**
- List all dead exports by file
- Mark exports that may be entry points (main, cli, api handlers)
- Exclude test files from dead code analysis

**Exclusions:**
- `__init__` / `__main__` / entry point patterns
- Public API exports explicitly documented
- Test fixtures and helpers

---

### 4. Test Coverage Score (15% weight)

Approximates test coverage using file-based heuristics.

**Data Collection:**
```
test_files = files matching: *_test.*, test_*.*, *.spec.*, */tests/*
code_files = total code files - test_files
```

**Formula:**
```
test_ratio = test_files / code_files
test_coverage_score = min(100, test_ratio × 100)
```

**Interpretation:**
| Test Ratio | Score | Interpretation |
|------------|-------|----------------|
| 1.0+ | 100 | Excellent test coverage |
| 0.5-0.99 | 50-99 | Good coverage |
| 0.2-0.49 | 20-49 | Basic coverage |
| <0.2 | <20 | Minimal testing |

**Flags:**
- 🔴 Directories with 0 test files
- 🟠 Large files (>200 lines) with no corresponding test
- List untested modules

**Note:** This is a proxy metric. For accurate coverage, recommend running actual coverage tools.

---

### 5. Documentation Score (15% weight)

Measures presence of docstrings and comments.

**Data Collection:**
```
For each public symbol:
  → find_symbol(symbol, include_info=true)
  → Check if docstring/comment exists
```

**Formula:**
```
documented_symbols = symbols with docstrings
documentation_score = (documented_symbols / total_public_symbols) × 100
```

**Interpretation:**
| Doc Ratio | Score | Interpretation |
|-----------|-------|----------------|
| 80-100% | 80-100 | Well documented |
| 50-79% | 50-79 | Partially documented |
| 20-49% | 20-49 | Sparse documentation |
| <20% | <20 | Minimal documentation |

**Flags:**
- 🔴 Public classes with no docstring
- 🟠 Public functions with no docstring
- Complex functions (>10 branches) with no documentation

---

## Grade Thresholds

| Score Range | Grade | Label | Action |
|-------------|-------|-------|--------|
| 90-100 | A | Excellent | Maintain current practices |
| 80-89 | B | Good | Minor improvements recommended |
| 70-79 | C | Fair | Plan incremental improvements |
| 60-69 | D | Poor | Prioritize technical debt |
| 0-59 | F | Critical | Immediate attention needed |

---

## Sample Score Calculation

```
Example codebase analysis:

Coupling:
  - 150 exports, 450 total references
  - avg_refs = 450/150 = 3.0
  - score = 100 - (3.0 × 5) = 85

Complexity:
  - 80 functions, 400 decision points
  - avg_branches = 400/80 = 5.0
  - score = 100 - (5.0 × 3) = 85

Dead Code:
  - 150 exports, 12 dead
  - dead_ratio = 12/150 = 0.08
  - score = 100 - (0.08 × 100) = 92

Test Coverage:
  - 60 code files, 30 test files
  - test_ratio = 30/60 = 0.5
  - score = min(100, 0.5 × 100) = 50

Documentation:
  - 100 public symbols, 70 documented
  - doc_ratio = 70/100 = 0.70
  - score = 70

Composite:
  = (85 × 0.25) + (85 × 0.25) + (92 × 0.20) + (50 × 0.15) + (70 × 0.15)
  = 21.25 + 21.25 + 18.4 + 7.5 + 10.5
  = 78.9

Grade: C (Fair)
```

---

## Weight Rationale

| Metric | Weight | Rationale |
|--------|--------|-----------|
| Coupling | 25% | High impact on maintainability and change risk |
| Complexity | 25% | Direct correlation with bug density |
| Dead Code | 20% | Significant but less impactful than coupling |
| Test Coverage | 15% | Important but proxy metric only |
| Documentation | 15% | Valuable but subjective |

Weights can be adjusted per project by modifying calculations in the skill workflow.
