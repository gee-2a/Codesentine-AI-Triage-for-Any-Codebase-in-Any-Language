# Self-audit

CodeSentinel scanned its own source:

```bash
python agent.py . --offline --exclude "test_*.py,demo-messy-repo,dummy_target,scripts,*.md,.github"
```

Tests, the intentionally bad demo files and docs are excluded, because they contain fake secrets and flawed code on purpose.

## First scan: 20 findings

Most were noise from the scanner's own rule definitions: regexes and docstrings that contain the words `eval`, `shell=True` or `TODO` were matched by the regex rules. Real items:

| Finding | Resolution |
|---|---|
| `hashlib.sha1` in `analyzers.py` used as a dedupe key (SEC002) | Real flag, not a security use. Fixed with `usedforsecurity=False`. |
| Three narrow `except ...: continue` handlers (GAP001) | Intentional skips. Suppressed with written reasons. |
| `log_message` no-op in `app.py` (SLP005) | Intentional, keeps request data out of logs. Suppressed with a reason. |

## Root cause fixed

On Python files the regex versions of SEC003, SEC004 and GAP001 are now skipped, since the AST rules cover them precisely. Python TODO markers only count inside comments.

## Remaining: 4 findings, all understood

- `app.py` SEC001 and GAP004: the demo snippet shown in the web UI's text box. It is deliberately bad sample code with a fake key. It sits in an HTML string, so an inline suppression is not possible.
- `<project>` GAP005 "No tests found": appears only because this scan excludes tests.

The 3 suppressions in the tree each carry a reason; the report shows the suppressed count.
