# CodeSentinel

**Language-agnostic AI code triage.** Point it at any folder, in any language, and it reports security risks, code slop, and loose ends, each with an exact `file:line`, a severity and a suggested fix.

- **Security:** hardcoded secrets, injection, `eval`/`exec`, disabled TLS verification, debug mode
- **Slop:** dead code, unused imports, duplicated functions, stubs, commented-out code
- **Gaps:** TODO/FIXME, swallowed exceptions, tests without assertions, missing tests

It ships as a **CLI** (terminal summary or Markdown report) and a **web service** (JSON API plus a paste-and-scan UI).

## Table of contents
1. [Quick start](#quick-start)
2. [CLI usage](#cli-usage)
3. [Web service and API](#web-service-and-api)
4. [Analysis rules](#analysis-rules)
5. [Architecture](#architecture)
6. [Tests and CI](#tests-and-ci)
7. [Project structure](#project-structure)
8. [Configuration](#configuration)
9. [Limitations and privacy](#limitations-and-privacy)

## Quick start

Requires Python 3.10+.

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install -r requirements.txt

python agent.py ./dummy_target --offline    # no API key needed
```

For AI analysis, add your Anthropic API key and drop `--offline`:

```bash
echo "ANTHROPIC_API_KEY=sk-ant-your-key" > .env
python agent.py ./dummy_target
```

With no key, or an invalid one, the agent falls back to offline mode instead of crashing.

## CLI usage

```bash
python agent.py ./my_repo                      # colorized terminal summary
python agent.py ./my_repo --report report.md   # also write a Markdown report
python agent.py ./my_repo --fail-on high       # exit 1 if high/critical found (CI)
python agent.py ./my_repo --offline            # deterministic rules only
python agent.py ./my_repo --offline --format sarif > out.sarif   # SARIF 2.1.0 for code scanning
python agent.py ./my_repo --fix                # dry run: show verified fixes as diffs
python agent.py ./my_repo --fix --apply        # write the verified fixes to disk
```

| Flag | Purpose | Default |
|---|---|---|
| `--offline` | Skip the LLM; use deterministic rules only | off |
| `--report FILE` | Also write a Markdown report | none |
| `--format text\|json\|sarif` | Output on stdout (json/sarif keep stdout machine-readable) | `text` |
| `--exclude GLOBS` | Comma-separated paths/globs to skip, e.g. `tests,*.md` | none |
| `--fix` / `--apply` | Show / write verified fixes for Python files | off |
| `--fail-on LEVEL` | Exit 1 at/above `critical\|high\|medium\|low` | `none` |
| `--model NAME` | Anthropic model (or set `ANTHROPIC_MODEL`) | `claude-sonnet-5-5` |
| `--workers N` | Parallel LLM requests | 4 |
| `--chunk-chars N` | Characters of code per request | 12000 |
| `--max-files N` / `--max-file-kb N` | Cost and size guards | 200 / 300 |

## Web service and API

```bash
python app.py        # http://localhost:8000
```

| Endpoint | Description |
|---|---|
| `GET /` | Web UI: paste code, click **Scan** |
| `GET /health` | Returns `{"ok": true}` |
| `POST /classify` | `{"text": "..."}` returns `{"category", "urgency", "confidence"}` (deterministic keyword triage) |
| `POST /api/scan` | `{"filename", "code", "offline"}` returns scan findings |

```bash
curl -s localhost:8000/classify -H "Content-Type: application/json" \
  -d '{"text":"Urgent: payment failed, please refund"}'
```

Requests are rate-limited per client IP (`RATE_LIMIT_PER_MIN`, default 300) and return `429` when exceeded. Bodies are size-capped (16 KB for `/classify`, 200 KB for `/api/scan`), client sockets time out after 5 seconds, and request contents are never logged. The web service uses only the Python standard library for serving; AI analysis in `/api/scan` runs only if the request asks for it and the server has `ANTHROPIC_API_KEY`.

## Analysis rules

Python files get deterministic, offline AST analysis (no API key needed). Every finding has a rule ID, severity, confidence and evidence.

| Rule | Category | Detects |
|---|---|---|
| SEC002 | Security | MD5/SHA-1, unverified SSL contexts |
| SEC003 | Security | `eval`/`exec`, `os.system`, `shell=True`, unsafe deserialization |
| SEC004 | Security | SQL built with concatenation, f-strings, `%` or `.format` |
| SLP001 | Slop | Functions identical after renaming (duplicates) |
| SLP002 | Slop | Unreachable statements, uncalled private functions |
| SLP003 | Slop | Unused imports |
| SLP004 | Slop | Comment blocks that parse as code |
| SLP005 | Slop | Stub bodies (`pass`, `...`, `NotImplementedError`) |
| GAP001 | Gaps | Exceptions swallowed silently |
| GAP002 | Gaps | Network calls (`requests`, `httpx`, `urlopen`) without a timeout |
| GAP003 | Gaps | Test functions with no meaningful assertions |
| DEP002 | Slop | Import that is not stdlib, not local and not in `requirements*.txt` (only when a manifest exists) |

On Python files the AST rules replace the regex versions of SEC003, SEC004 and GAP001, so strings and comments that merely mention `eval` or `shell=True` are not flagged. All languages additionally get regex rules (secrets, `eval`/`exec`, SQL string-building, TLS verification off, debug mode, TODO/FIXME, empty catch) and, when an API key is set, Claude's semantic analysis.

### Suppressions

Silence a finding on its own line, or on the line above it, with a rule ID and a **reason**:

```python
os.system(cmd)  # sentinel:ignore[SEC003] cmd is a constant from our config
```

JS/Go/Java use `//`. A suppression without a reason suppresses nothing and is reported as `SUP001`. The suppressed count appears in every report.

### Verified fixes

`--fix` handles Python only: unused imports, unreachable code, commented-out code, `verify=False`, and `except: pass` (replaced with a logged exception). A patch is kept only if the result still parses, the targeted finding is gone, and no rule has more findings than before. Rejected patches are listed with the reason. Without `--apply` nothing is written.

## Architecture

```
 local dir ──► pathlib walker ──► line-numbered chunker ──► Claude (forced tool call) ──┐
 (skips hidden,   (text only,      (12k chars, gutter          structured JSON findings  │
  binaries,        size-capped)     "  42| code")                                        │
  node_modules)                          │                                              ├─► merge + dedupe ─► terminal / Markdown / JSON
                                         ├──► Python AST analyzers (offline) ───────────┤   + health score
                                         └──► regex rules (offline) ────────────────────┘
```

1. **No per-language parsers required.** The walker only decides whether a file is readable text, so any language can be scanned.
2. **Line-numbered chunks** let the model cite exact locations.
3. **Structured LLM output** through a forced tool call, so there is no fragile text parsing.
4. **Deterministic layers** (AST + regex) work offline and back up the LLM. Duplicates are merged, and AST findings win ties.
5. **Safety:** scanned code is treated as untrusted data (prompt-injection guard), and secret values are redacted from reports.

## Tests and CI

```bash
python -m unittest discover -v
```

58 tests cover chunking, file discovery, the regex and AST rules, suppressions, JSON/SARIF output, the fixers, the benchmark, merging and redaction, the classifier, the rate limiter and the HTTP API. See [BENCHMARK.md](BENCHMARK.md) and [SELF_AUDIT.md](SELF_AUDIT.md) for what the benchmark and the self-scan do and do not show. GitHub Actions runs the same command on every push (`.github/workflows/ci.yml`).

## Project structure

```
.
├── agent.py             # CLI scanner: walker, chunker, LLM + regex analysis, reports
├── analyzers.py         # offline Python AST analyzers (rules SEC/SLP/GAP/DEP)
├── suppress.py          # sentinel:ignore[RULE] reason parsing
├── report.py            # JSON and SARIF 2.1.0 output
├── fixers.py            # verified auto-fixes (--fix / --apply)
├── scripts/evaluate.py  # precision / recall / F1 on the seeded benchmark
├── demo-messy-repo/     # seeded benchmark (.sample files) + expected.json
├── app.py               # web service: /health, /classify, /api/scan, UI
├── test_agent.py        # tests: scanner, classifier, rate limiter, HTTP API
├── test_analyzers.py    # tests: AST analyzers
├── test_extensions.py   # tests: new rules, suppressions, reports, fixers, benchmark
├── BENCHMARK.md         # benchmark method and honest caveats
├── SELF_AUDIT.md        # CodeSentinel scanning its own source
├── arena.json           # hackathon runner config (install / test / start / port)
├── requirements.txt     # pinned dependencies
├── README.md
├── AI_LOG.md            # how AI was used to build this project
├── .github/workflows/ci.yml
└── dummy_target/        # deliberately bad demo files (all secrets are fake)
    ├── bad_code.py
    └── bad_code.js
```

## Configuration

| Variable | Purpose |
|---|---|
| `ANTHROPIC_API_KEY` | Enables AI analysis (environment or `.env`; never commit `.env`) |
| `ANTHROPIC_MODEL` | Override the default model |
| `PORT` | Web service port (default 8000) |
| `RATE_LIMIT_PER_MIN` | Per-IP request limit (default 300) |

## Limitations and privacy

- AST analysis and `--fix` cover Python only. There is no taint tracking, so SEC003/SEC004 are pattern-level, not data-flow. Other languages rely on regex rules and the LLM.
- Full semantic analysis needs an Anthropic API key. In AI mode, scanned source text is sent to the Anthropic API, so use `--offline` for code you can't share.
- Rules are heuristics and can miss patterns or flag false positives. Treat results as triage, not a verdict.
- `/classify` is a deterministic keyword classifier, not a trained model.
- Large repos are capped by `--max-files` and `--max-file-kb` to control cost.
