# AI Usage Log

## Tools used
- **Claude (Anthropic)**: used to design and generate the initial project.
- **Claude API (`claude-sonnet-5-5`)**: used at runtime by the agent itself for semantic code analysis.

## What AI generated
- First draft of `agent.py` (file walker, chunker, LLM analysis, regex fallback, reports), `requirements.txt`, `Dockerfile`, `README.md`, and the two demo files in `dummy_target/`.
- Hackathon submission text.

## What I did myself
- Set up the environment (`.venv`), installed dependencies, and ran the agent.
- Ran `python agent.py ./dummy_target --offline`: it completed with 15 findings.
- [Add: bugs you fixed, changes you made, anything you tested with the API key]

## Prompts (summary)
1. Asked for a language-agnostic code analysis agent covering security, slop, and coding gaps, with Docker and README.
2. Follow-ups on API key setup, free options, Docker troubleshooting, and the repo file layout.

## Known limitations
- Full semantic analysis needs an `ANTHROPIC_API_KEY`; without one it falls back to regex-only (`--offline`).
- Scanned code is sent to the Anthropic API in LLM mode.
- [Add anything else you noticed]