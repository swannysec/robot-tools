# Baseline Detection — Language-Agnostic Probes

Stage 0 uses these detection tables to find test runners, linters, typecheckers, and coverage tools. The agent should probe in order and use the first match in each category.

## Priority: Custom Commands First

Before probing by ecosystem, check for explicit configuration:

1. **CLAUDE.md / .claude/settings.json** — look for test/lint commands specified in project instructions
2. **Makefile** — check for `test`, `lint`, `check`, `coverage` targets: `make -n test 2>/dev/null`
3. **package.json scripts** — check `scripts.test`, `scripts.lint`, `scripts.typecheck`, `scripts.test:coverage`
4. **justfile** — check for `just test`, `just lint`, etc.

If a custom command is found, prefer it over the ecosystem probes below.

---

## Test Runner Detection

Probe in this order. Use the first match.

| Priority | Indicator File | Test Command | Ecosystem |
|----------|---------------|-------------|-----------|
| 1 | `Cargo.toml` | `cargo test` | Rust |
| 2 | `package.json` | `npm test` | Node/TS |
| 2a | `pnpm-lock.yaml` | `pnpm test` | Node/TS (pnpm) |
| 2b | `yarn.lock` | `yarn test` | Node/TS (yarn) |
| 2c | `bun.lockb` | `bun test` | Node/TS (bun) |
| 3 | `pytest.ini` or `pyproject.toml` with `[tool.pytest]` | `pytest` | Python |
| 3a | `setup.py` or `setup.cfg` | `python -m pytest` | Python (fallback) |
| 4 | `go.mod` | `go test ./...` | Go |
| 5 | `mix.exs` | `mix test` | Elixir |
| 6 | `Gemfile` with `rspec` | `bundle exec rspec` | Ruby |
| 6a | `Gemfile` with `minitest` | `bundle exec rake test` | Ruby (minitest) |
| 7 | `*.bats` files in `test/` or `tests/` | `bats test/` | Shell (bats) |
| 7a | `test.sh` or `tests/*.sh` | `bash test.sh` or `bash tests/*.sh` | Shell (ad-hoc) |
| 8 | `Makefile` with `test` target | `make test` | Generic |

**Detection command pattern:**
```bash
# Check for file existence
test -f Cargo.toml && echo "cargo test"
test -f package.json && echo "npm test"
# etc.
```

**If no test runner is detected:** Ask the user for the test command. Store it for subsequent stages.

---

## Linter Detection

Probe and run all that are available. Multiple linters can coexist.

| Indicator | Lint Command | Ecosystem |
|-----------|-------------|-----------|
| `Cargo.toml` | `cargo clippy -- -D warnings 2>&1` | Rust |
| `.eslintrc*` or `eslint.config.*` | `npx eslint . 2>&1` | JS/TS (eslint) |
| `biome.json` or `biome.jsonc` | `npx biome check . 2>&1` | JS/TS (biome) |
| `pyproject.toml` with `[tool.ruff]` or `.ruff.toml` | `ruff check . 2>&1` | Python (ruff) |
| `pyproject.toml` with `[tool.flake8]` or `.flake8` | `flake8 . 2>&1` | Python (flake8) |
| `.rubocop.yml` | `bundle exec rubocop 2>&1` | Ruby |
| `go.mod` | `go vet ./... 2>&1` | Go |
| `.shellcheckrc` or shell scripts present | `shellcheck scripts/*.sh 2>&1` or `shellcheck **/*.sh 2>&1` | Shell |
| `mix.exs` | `mix credo 2>&1` | Elixir |

**For shellcheck detection:** Look for `.sh` files in common locations (`scripts/`, `bin/`, project root). If shellcheck is installed (`command -v shellcheck`), run it on discovered scripts.

**If a linter is not installed:** Skip it — record as "SKIPPED (not installed)". Do not fail on missing linters.

---

## Typecheck Detection

| Indicator | Typecheck Command | Ecosystem |
|-----------|------------------|-----------|
| `Cargo.toml` | `cargo check 2>&1` | Rust (compiler check) |
| `tsconfig.json` | `npx tsc --noEmit 2>&1` | TypeScript |
| `pyproject.toml` with `[tool.mypy]` or `mypy.ini` | `mypy . 2>&1` | Python (mypy) |
| `pyproject.toml` with `[tool.pyright]` or `pyrightconfig.json` | `pyright 2>&1` | Python (pyright) |
| `go.mod` | (covered by `go vet` above) | Go |
| `sorbet/config` | `bundle exec srb tc 2>&1` | Ruby (sorbet) |

**If no typechecker is available:** Record as "SKIPPED (not available)" and continue.

---

## Coverage Detection

| Indicator | Coverage Command | Output Format |
|-----------|-----------------|---------------|
| `Cargo.toml` + `cargo-tarpaulin` installed | `cargo tarpaulin --out json 2>&1` | JSON → parse `"covered"` percentage |
| `Cargo.toml` + `cargo-llvm-cov` installed | `cargo llvm-cov --json 2>&1` | JSON |
| `vitest.config.*` | `npx vitest run --coverage 2>&1` | Terminal → parse percentage |
| `jest.config.*` or package.json `jest` config | `npx jest --coverage 2>&1` | Terminal → parse percentage |
| package.json `scripts.test:coverage` | `npm run test:coverage 2>&1` | Terminal → parse percentage |
| `pyproject.toml` with `[tool.coverage]` or `.coveragerc` | `pytest --cov --cov-report=term 2>&1` | Terminal → parse percentage |
| `go.mod` | `go test -cover ./... 2>&1` | Terminal → parse `coverage: XX.X%` |
| `Gemfile` with `simplecov` | `COVERAGE=true bundle exec rspec 2>&1` | Terminal → parse percentage |

**Coverage tool detection:**
```bash
# Rust
command -v cargo-tarpaulin >/dev/null 2>&1 && echo "cargo tarpaulin --out json"
command -v cargo-llvm-cov >/dev/null 2>&1 && echo "cargo llvm-cov --json"
```

**If no coverage tool is available:** Record "not measured" and continue. Coverage comparison in Stage 11 will be skipped.

---

## Recording Baseline Results

After running all probes, store the following for use in later stages:

- **Test command** — exact command to re-run in Stages 3, 5, 7, 10, 11
- **Lint commands** — list of commands that were run (for re-run in Stage 11)
- **Typecheck command** — if available (for re-run in Stage 11)
- **Coverage command** — if available (for re-run in Stage 11)
- **Baseline test counts** — passing, failing, skipped
- **Baseline coverage percentage** — if measured
- **Baseline lint status** — pass/fail per tool
- **Baseline typecheck status** — pass/fail

These values are referenced by the test gate checks in fix stages and by Stage 11's comparison logic.
