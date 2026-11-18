# CodeSentinel

**Language-agnostic AI code triage.** Point it at any folder, in any language, and it reports security risks, code slop, and loose ends, each with an exact `file:line`, a severity and a suggested fix.

- **Security:** hardcoded secrets, injection, `eval`/`exec`, disabled TLS verification, debug mode, insecure configs
- **Slop:** dead code, unused imports/variables, deep nesting, duplication, bad formatting
- **Gaps:** TODO/FIXME, empty catch blocks, unhandled errors, missing tests, stubs

It ships as a **CLI** (terminal summary or Markdown report) and a **web demo** (paste code, get findings).

---

## Table of contents
1. [Quick start](#quick-start)
2. [Usage](#usage)
3. [Web demo and API](#web-demo-and-api)
4. [Architecture](#architecture)
5. [Running tests](#running-tests)
6. [Docker (optional)](#docker-optional)
7. [Project structure](#project-structure)
8. [Configuration](#configuration)
9. [Limitations and privacy](#limitations-and-privacy)

---

## Quick start

Requires Python 3.10+.

```bash
# 1. Install
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install -r requirements.txt

# 2. Run the bundled demo (no API key needed)
python agent.py ./dummy_target --offline
```

To enable full AI analysis, add your Anthropic API key and drop `--offline`:

```bash
echo "ANTHROPIC_API_KEY=sk-ant-your-key" > .env
python agent.py ./dummy_target
```

With no key, or an invalid one, the agent falls back to offline regex mode automatically instead of crashing.

---

## Usage

```bash
python agent.py ./dummy_target                      # colorized terminal summary
python agent.py ./my_repo --report report.md        # also write a Markdown report
python agent.py ./my_repo --fail-on high            # exit code 1 if high/critical found (CI)
python agent.py ./my_repo --offline                 # regex rules only, no API key
python agent.py ./my_repo --model claude-sonnet-5-5 # choose a model
```

| Flag | Purpose | Default |
|---|---|---|
| `--offline` | Skip the LLM and run regex rules only | off |
| `--report FILE` | Also write a Markdown report | none |
| `--fail-on LEVEL` | Exit 1 at/above `critical\|high\|medium\|low` | `none` |
| `--model NAME` | Anthropic model (or set `ANTHROPIC_MODEL`) | `claude-sonnet-5-5` |
| `--workers N` | Parallel LLM requests | 4 |
| `--chunk-chars N` | Characters of code per request | 12000 |
| `--max-files N` / `--max-file-kb N` | Cost and size guards | 200 / 300 |

---

## Web demo and API

```bash
python app.py        # then open http://localhost:8000
```

The server uses only the Python standard library and listens on port 8000 (override with the `PORT` environment variable).

| Endpoint | Description |
|---|---|
| `GET /` | Web UI: paste code, click **Scan** |
| `GET /health` | Returns `{"status": "ok"}` |
| `POST /api/scan` | Scan a snippet and return JSON findings |

```bash
curl -s localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"filename":"demo.py","offline":true,"code":"# TODO fix\npassword = \"abcdef123\"\n"}'
```

The response contains `mode`, `score` (0-100 health score) and a `findings` list. The web demo is offline (regex) by default. AI analysis runs only if you tick the box and the server has `ANTHROPIC_API_KEY`. Request bodies are capped at 200 KB.

---

## Architecture

```
 local dir ──► pathlib walker ──► line-numbered chunker ──► Claude (forced tool call) ──┐
 (skips hidden,   (text only,      (12k chars, gutter          structured JSON findings  │
  binaries,        size-capped)     "  42| code")                                        ├─► merge + dedupe ─► terminal / Markdown / JSON
  node_modules)                          │                                              │   + health score
                                         └──► regex safety net (offline, deterministic) ┘
```

**Why it stays language-agnostic**
1. **No AST, no parsers.** The walker only decides whether a file is readable text (null-byte sniff, extension denylist, size cap). It never needs to know the language.
2. **Line-numbered chunks.** Files are split on line boundaries and each line is prefixed with its absolute number, so the model can cite exact locations in any language.
3. **Semantic analysis by Claude.** A strict system prompt defines three categories (security, slop, gaps) and a severity rubric. Output is forced through a tool-call JSON schema, so there is no fragile text parsing.
4. **Regex safety net.** A small local rule set runs alongside the LLM, so results appear instantly offline and cover the LLM's blind spots. Duplicates are merged and LLM findings win.
5. **Safety by design.** Scanned code is treated as untrusted data (prompt-injection guard), secret values are redacted from reports, and hidden folders, lockfiles and binaries are never sent.

---

## Running tests

```bash
python -m unittest discover -v
```

The tests cover chunking, the regex rules against the demo files, merge and redaction, file discovery (hidden, binary and vendor files skipped), and the web API.

---

## Docker (optional)

```bash
docker build -t codesentinel .

# CLI demo (no key needed)
docker run --rm -it codesentinel dummy_target --offline

# With AI analysis
docker run --rm -it --env-file .env codesentinel

# Scan your own code and save a report
mkdir -p reports
docker run --rm -it --env-file .env \
  -v "$(pwd)/path/to/repo:/scan:ro" -v "$(pwd)/reports:/out" \
  codesentinel /scan --report /out/report.md

# Web demo
docker run --rm -p 8000:8000 --entrypoint python codesentinel app.py
```

---

## Project structure

```
.
├── agent.py            # CLI scanner: walker, chunker, LLM + regex analysis, reports
├── app.py              # web demo and JSON API (stdlib, port 8000)
├── test_agent.py       # unit tests
├── arena.json          # hackathon runner config (install / test / start / port)
├── AI_LOG.md           # how AI was used to build this project
├── README.md
├── requirements.txt    # anthropic, rich, python-dotenv
├── Dockerfile
└── dummy_target/       # deliberately bad demo files (all secrets are fake)
    ├── bad_code.py
    └── bad_code.js
```

---

## Configuration

| Variable | Purpose |
|---|---|
| `ANTHROPIC_API_KEY` | Enables AI analysis. Set it in the environment or a `.env` file. Never commit `.env`. |
| `ANTHROPIC_MODEL` | Override the default model |
| `PORT` | Web demo port (default 8000) |

---

## Limitations and privacy

- Full semantic analysis needs an Anthropic API key. Without one, only the regex rules run.
- In AI mode, scanned source text is sent to the Anthropic API. Don't scan code you aren't allowed to share, or use `--offline` for a fully local run.
- Regex rules are heuristics and can miss patterns or flag false positives. Treat results as triage, not a verdict.
- Large repos are capped by `--max-files` and `--max-file-kb` to control cost.