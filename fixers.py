"""Deterministic fixers with a verification loop (Python files only).

A patch is accepted only if ALL of these hold; otherwise it is discarded:
  1. the fixer produced a change,
  2. the result still parses,
  3. re-running the analyzers shows the targeted finding is gone,
  4. no rule has more findings than before (no regressions).
"""
from __future__ import annotations

import ast
import difflib
import re
from collections import Counter
from typing import Callable, Optional

ScanFn = Callable[[str, str], list]


def _parse(text: str) -> Optional[ast.Module]:
    try:
        return ast.parse(text)
    except (SyntaxError, ValueError):
        return None


def _indent(line: str) -> str:
    return re.match(r"\s*", line).group(0)


# --------------------------------------------------------------------------- #
# Individual fixers: (text, finding) -> new text, or None if not applicable
# --------------------------------------------------------------------------- #
def fix_unused_import(text: str, f) -> Optional[str]:
    m = re.search(r"'([^']+)' is imported", f.detail)
    tree = _parse(text)
    if not m or tree is None:
        return None
    bound = m.group(1)
    lines = text.split("\n")
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Import, ast.ImportFrom)) or node.lineno != f.line:
            continue
        span = "\n".join(lines[node.lineno - 1:node.end_lineno])
        if ";" in span.split("#")[0]:
            return None  # other statements share the line
        def name_of(a):
            if isinstance(node, ast.Import):
                return a.asname or a.name.split(".")[0]
            return a.asname or a.name
        keep = [a for a in node.names if name_of(a) != bound]
        if len(keep) == len(node.names):
            return None
        start, end = node.lineno - 1, node.end_lineno
        replacement: list[str] = []
        if keep:
            node.names = keep
            replacement = [_indent(lines[start]) + ast.unparse(node)]
        return "\n".join(lines[:start] + replacement + lines[end:])
    return None


def fix_unreachable(text: str, f) -> Optional[str]:
    if f.end_line < f.line:
        return None
    lines = text.split("\n")
    segment = lines[f.line - 1:f.end_line]
    if any(";" in s.split("#")[0] for s in segment):
        return None
    return "\n".join(lines[:f.line - 1] + lines[f.end_line:])


def fix_commented_code(text: str, f) -> Optional[str]:
    if f.end_line < f.line:
        return None
    lines = text.split("\n")
    segment = lines[f.line - 1:f.end_line]
    if not all(s.lstrip().startswith("#") for s in segment):
        return None
    return "\n".join(lines[:f.line - 1] + lines[f.end_line:])


def fix_tls_verification(text: str, f) -> Optional[str]:
    lines = text.split("\n")
    if not 1 <= f.line <= len(lines):
        return None
    new = re.sub(r"verify\s*=\s*False", "verify=True", lines[f.line - 1])
    if new == lines[f.line - 1]:
        return None
    lines[f.line - 1] = new
    return "\n".join(lines)


def fix_empty_except(text: str, f) -> Optional[str]:
    tree = _parse(text)
    if tree is None:
        return None
    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler) or node.lineno != f.line:
            continue
        if len(node.body) != 1:
            return None
        stmt = node.body[0]
        is_pass = isinstance(stmt, ast.Pass) or (
            isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant)
            and stmt.value.value is Ellipsis)
        if not is_pass or stmt.lineno == node.lineno:
            return None
        lines = text.split("\n")
        lines[stmt.lineno - 1:stmt.end_lineno] = [
            _indent(lines[stmt.lineno - 1]) + 'logging.getLogger(__name__).exception("Ignored exception")']
        if not any(isinstance(n, ast.Import) and any(a.name == "logging" and a.asname is None
                                                      for a in n.names) for n in tree.body):
            lines.insert(_logging_import_position(tree), "import logging")
        return "\n".join(lines)
    return None


def _logging_import_position(tree: ast.Module) -> int:
    """0-based line index at which to insert 'import logging'."""
    body, idx, last_end = tree.body, 0, 0
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
            and isinstance(body[0].value.value, str):
        last_end, idx = body[0].end_lineno or 0, 1
    while idx < len(body) and isinstance(body[idx], ast.ImportFrom) and body[idx].module == "__future__":
        last_end, idx = body[idx].end_lineno or last_end, idx + 1
    if idx > 0:
        return last_end
    first = body[0]
    return min([first.lineno] + [d.lineno for d in getattr(first, "decorator_list", [])]) - 1


# rule -> (fixer, predicate deciding whether the finding is auto-fixable)
FIXERS = {
    "SLP003": (fix_unused_import, lambda f: True),
    "SLP002": (fix_unreachable, lambda f: "Unreachable" in f.title),
    "SLP004": (fix_commented_code, lambda f: True),
    "SEC002": (fix_tls_verification, lambda f: "TLS verification" in f.title),
    "GAP001": (fix_empty_except, lambda f: f.confidence >= 0.9),
}


# --------------------------------------------------------------------------- #
# Verification loop
# --------------------------------------------------------------------------- #
def unified_diff(rel: str, old: str, new: str) -> str:
    return "".join(difflib.unified_diff(old.splitlines(keepends=True), new.splitlines(keepends=True),
                                        fromfile=f"a/{rel}", tofile=f"b/{rel}"))


def _verify(rel: str, new: str, target, before: list, scan_fn: ScanFn) -> Optional[str]:
    """Return None if the patch is safe, else the reason it was rejected."""
    if _parse(new) is None:
        return "result does not parse"
    after = scan_fn(rel, new)
    b, a = Counter(x.rule for x in before), Counter(x.rule for x in after)
    if a[target.rule] >= b[target.rule]:
        return "targeted finding was not removed"
    for rule in a:
        if a[rule] > b[rule]:
            return f"introduces a new {rule} finding"
    return None


def run_fixes(rel: str, text: str, scan_fn: ScanFn, max_patches: int = 200):
    """Apply every verifiable fix to `text`. Returns (new_text, accepted, rejected)."""
    if not rel.endswith(".py"):
        return text, [], []
    accepted: list[dict] = []
    rejected: list[dict] = []
    skip: set[tuple] = set()
    current = text
    for _ in range(max_patches):
        before = scan_fn(rel, current)
        candidates = [f for f in before if f.rule in FIXERS and FIXERS[f.rule][1](f)
                      and (f.rule, f.title, f.line) not in skip]
        if not candidates:
            break
        f = candidates[0]
        skip.add((f.rule, f.title, f.line))
        try:
            new = FIXERS[f.rule][0](current, f)
        except (SyntaxError, ValueError, IndexError):
            new = None
        reason = "fixer not applicable here" if new is None or new == current \
            else _verify(rel, new, f, before, scan_fn)
        record = {"rule": f.rule, "line": f.line, "title": f.title}
        if reason:
            rejected.append({**record, "reason": reason})
            continue
        accepted.append({**record, "diff": unified_diff(rel, current, new)})
        current = new
    return current, accepted, rejected
