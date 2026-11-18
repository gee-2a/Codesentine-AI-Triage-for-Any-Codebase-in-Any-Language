# AI Usage Log

## Tools used
- **Claude (Anthropic), chat**: designed and generated the first version of the project (CLI scanner, web service, tests, README).
- **Claude, with access to the project folder**: applied the later changes below directly to the files and ran the tests in a sandbox.
- **Claude API (`claude-sonnet-5-5`)**: used at runtime by the scanner for optional semantic analysis. All grading-relevant paths work without it.

## What AI generated
- `agent.py` (file walker, chunker, LLM analysis, regex rules, reports), `app.py` (web service), `test_agent.py`, the demo files in `dummy_target/`, and the first README.
- In the third iteration: `suppress.py`, `report.py`, `fixers.py`, the SEC002/003/004, GAP002 and DEP002 rules, `scripts/evaluate.py`, the `demo-messy-repo/` benchmark, `test_extensions.py`, `BENCHMARK.md` and `SELF_AUDIT.md`.
- In the second iteration: `analyzers.py` and `test_analyzers.py` (deterministic Python AST analyzers), the `/classify` endpoint, the rate limiter, `.github/workflows/ci.yml`, pinned `requirements.txt`, and this README.

## What I did myself
- Set up the environment, installed dependencies, and ran the scanner locally (offline mode on the demo files reported 15 findings).
- Read the automatic grader's scorecard and directed the second iteration from it: add the graded `/classify` and `/health` contract, rate limiting, CI, pinned dependencies, and fix the XSS finding in the demo file.
- Decided to drop Docker because the task does not use it.
- Supplied a product-requirements document for a code-triage tool and asked for it to be adapted to this project, keeping the name CodeSentinel and focusing on source code. Only the stdlib-feasible subset was built (rule catalogue, suppressions, SARIF, verified fixers, benchmark); tree-sitter, multi-language ASTs, taint analysis and an LLM critic were deliberately left out.
- Provided reference material (a design document and a tree-sitter probe script). Ideas were taken from it (rule IDs, confidence scores, deterministic offline analysis); no code was copied.
- The organizer's sample project was used only to learn the public endpoint contract (`POST /classify`, `GET /health`); none of its code or text was copied.

## Verification
- `python -m unittest discover -v`: 58 tests pass on a clean install from the pinned `requirements.txt`.
- Started `python app.py` and checked `/health`, `/classify`, `/classify` with bad input, and `/api/scan`.
- Ran `python agent.py dummy_target --offline` end to end, including `--format json`.
- `python scripts/evaluate.py` on the seeded benchmark, and a self-scan (see SELF_AUDIT.md).
- Not yet re-graded by the platform at the time of writing.

## Prompts (summary)
1. Asked for a language-agnostic code analysis agent covering security, slop and coding gaps.
2. Follow-ups on API keys, free options, the `arena.json` format and the required repo files.
3. Asked Claude to fix the scorecard failures and to add offline deterministic analysis inspired by the reference material.
4. Asked Claude to adapt the reference requirements document into the existing project (suppressions, SARIF, fixers, benchmark).

## Known limitations
- The benchmark labels were written by the same author as the rules, so its score is a regression guard and not an accuracy claim.
- AST analysis and `--fix` cover Python only; other languages rely on regex rules and the LLM.
- `/classify` is a keyword classifier, so its category and urgency labels may differ from what a grader expects.
- Rules are heuristics and can produce false positives or miss issues.
- Scanned code is sent to the Anthropic API in AI mode.
