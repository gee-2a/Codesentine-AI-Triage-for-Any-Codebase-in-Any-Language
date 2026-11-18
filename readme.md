# CodeSentinel

**Language-agnostic AI code triage.** Point it at any folder. It finds security holes, code slop, and loose ends in Python, JavaScript, Go, Rust, Terraform, shell scripts and anything else, with no per-language parsers.

## Architecture: why it stays language-agnostic

```
 local dir ──► pathlib walker ──► line-numbered chunker ──► Claude (forced tool call) ──┐
 (skips hidden,   (text only,      (12k chars, gutter          structured JSON findings  │
  binaries,        size-capped)     "  42| code")                                        ├─► merge + dedupe ─► rich terminal
  node_modules)                          │                                              │   + score          + Markdown report
                                         └──► regex safety net (offline, deterministic) ┘
```

1. **No AST, no parsers.** The walker only decides "is this readable text?" using a null-byte sniff, an extension denylist and a size cap. It never decides which language it is.
2. **Line-numbered chunks.** Files are split on line boundaries and every line is prefixed with its absolute number. The model can cite exact locations in any language.
3. **Semantic analysis by Claude.** A strict system prompt defines three categories (Security, Slop, Gaps) and a severity rubric. Output is forced through a tool-call JSON schema, so there is no fragile text parsing.
4. **Regex safety net.** A small rule set (secrets, `eval`, SQL string-building, empty catch, TODO) runs locally. It gives instant results offline, and it backs up the LLM. Duplicates are merged, and LLM findings win.
5. **Safety.** Code is treated as untrusted data (prompt-injection guard). Secret values are redacted from reports. Hidden folders, lockfiles and binaries are never sent.

## Setup (2 steps)

### Option A: Docker (nothing to install)

```bash
# 1. Build
docker build -t codesentinel .

# 2. Run the bundled demo (put your key in a .env file first)
echo "ANTHROPIC_API_KEY=sk-ant-your-key" > .env
docker run --rm -it --env-file .env codesentinel
```

Scan your own code and save a report:

```bash
mkdir -p reports
docker run --rm -it --env-file .env \
  -v "$(pwd)/path/to/repo:/scan:ro" -v "$(pwd)/reports:/out" \
  codesentinel /scan --report /out/report.md
```

### Option B: Local Python 3.10+

```bash
# 1. Install
pip install -r requirements.txt

# 2. Configure + run
echo "ANTHROPIC_API_KEY=sk-ant-your-key" > .env
python agent.py ./dummy_target
```

## Usage

```bash
python agent.py ./dummy_target                      # colorized terminal summary
python agent.py ./my_repo --report report.md        # + Markdown report
python agent.py ./my_repo --fail-on high            # exit 1 in CI if high/critical found
python agent.py ./my_repo --offline                 # regex only, no API key needed
python agent.py ./my_repo --model claude-sonnet-5-5 # pick a model (or set ANTHROPIC_MODEL)
```

| Flag | Purpose |
|---|---|
| `--workers N` | Parallel LLM requests (default 4) |
| `--chunk-chars N` | Characters of code per request (default 12000) |
| `--max-files N` / `--max-file-kb N` | Cost and size guards (200 files / 300 KB) |

If `ANTHROPIC_API_KEY` is missing, or the API fails, the agent degrades to regex-only mode instead of crashing.

## What it reports

- **Security:** hardcoded secrets, injection, `eval`/`exec`, disabled TLS verification, debug mode, insecure configs.
- **Slop:** dead code, unused imports/variables, deep nesting, duplication, bad formatting.
- **Gaps:** TODO/FIXME, empty catch blocks, unhandled errors, missing tests, stubs.

Each finding has a severity (critical to info), an exact `file:line`, an explanation and a one-line fix. The report ends with a 0-100 health score.

## Privacy note

Scanned source text is sent to the Anthropic API. Do not scan code you are not allowed to share. Use `--offline` for a fully local run.