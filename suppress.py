"""Inline suppressions: a finding can be silenced only with a rule ID and a written reason.

Syntax (Python/Shell use '#', JS/Go/Java use '//'):

    risky_call()  # sentinel:ignore[SEC003] input is validated upstream by the schema layer

The comment may sit on the finding's line, or alone on the line directly above it.
A suppression without a reason does not suppress anything and is itself reported (SUP001).
"""
from __future__ import annotations

import re

_PATTERN = re.compile(r"(?:#|//)\s*sentinel:ignore\[([A-Za-z0-9_,\s]+)\](.*)$")


def parse_suppressions(text: str) -> tuple[dict[int, tuple[set[str], str, bool]], list[int]]:
    """Return ({line: (rule_ids, reason, standalone)}, [lines with a missing reason])."""
    valid: dict[int, tuple[set[str], str, bool]] = {}
    invalid: list[int] = []
    for no, line in enumerate(text.splitlines(), 1):
        m = _PATTERN.search(line)
        if not m:
            continue
        rules = {r.strip().upper() for r in m.group(1).split(",") if r.strip()}
        reason = m.group(2).strip(" :-\t")
        standalone = line.lstrip().startswith(("#", "//"))
        if rules and reason:
            valid[no] = (rules, reason, standalone)
        else:
            invalid.append(no)
    return valid, invalid
