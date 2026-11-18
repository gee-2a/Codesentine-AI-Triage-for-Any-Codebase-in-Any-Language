"""Deterministic, offline Python analyzers built on the stdlib `ast` module.

No network, no API key, no extra dependencies. Every finding carries a rule ID
and a confidence score so results are reproducible and explainable.

Rules
    SLP001 duplicate-code        functions with equal normalized AST
    SLP002 dead-code             unreachable statements, uncalled private functions
    SLP003 unused-import         imports never referenced
    SLP004 commented-out-code    comment blocks that parse as code
    SLP005 stub-body             pass / ... / NotImplementedError / dummy return
    GAP001 empty-catch           except blocks that swallow the error
    GAP003 empty-test            test functions without meaningful assertions
"""
from __future__ import annotations

import ast
import builtins
import copy
import hashlib
import io
import re
import textwrap
import tokenize
from typing import NamedTuple


class Raw(NamedTuple):
    rule: str
    line: int
    category: str      # security | slop | gaps
    severity: str      # critical | high | medium | low | info
    title: str
    detail: str
    fix: str
    confidence: float  # 0.0 - 1.0


_FUNCS = (ast.FunctionDef, ast.AsyncFunctionDef)
_BUILTINS = set(dir(builtins))
_TEST_FILE = re.compile(r"(^|/)(test_[^/]+\.py|[^/]+_test\.py|tests?/[^/]+\.py)$")
_MIN_DUP_NODES = 25


def _bodies(node: ast.AST):
    """Yield every statement list owned by `node`."""
    for field in ("body", "orelse", "finalbody"):
        stmts = getattr(node, field, None)
        if isinstance(stmts, list) and stmts and isinstance(stmts[0], ast.stmt):
            yield stmts


def _docstring_split(body: list[ast.stmt]) -> tuple[bool, list[ast.stmt]]:
    if (body and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)):
        return True, body[1:]
    return False, body


# --------------------------------------------------------------------------- #
# SLP003 unused imports
# --------------------------------------------------------------------------- #
def _unused_imports(tree: ast.Module, rel: str) -> list[Raw]:
    if rel.endswith("__init__.py"):
        return []  # re-exports are intentional
    imported: list[tuple[str, int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                imported.append((a.asname or a.name.split(".")[0], node.lineno, a.name))
        elif isinstance(node, ast.ImportFrom):
            if node.module == "__future__":
                continue
            for a in node.names:
                if a.name != "*":
                    imported.append((a.asname or a.name, node.lineno,
                                     f"{node.module or '.'}.{a.name}"))
    used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    for node in ast.walk(tree):  # names listed in __all__ count as used
        if (isinstance(node, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets)
                and isinstance(node.value, (ast.List, ast.Tuple))):
            used |= {e.value for e in node.value.elts
                     if isinstance(e, ast.Constant) and isinstance(e.value, str)}
    return [
        Raw("SLP003", line, "slop", "low", f"[SLP003] Unused import '{full}'",
            f"'{bound}' is imported but never referenced in this file.",
            "Remove the import.", 0.85)
        for bound, line, full in imported if bound not in used
    ]


# --------------------------------------------------------------------------- #
# SLP002 dead code
# --------------------------------------------------------------------------- #
def _dead_code(tree: ast.Module) -> list[Raw]:
    out: list[Raw] = []
    for node in ast.walk(tree):
        for stmts in _bodies(node):
            for i, stmt in enumerate(stmts[:-1]):
                if isinstance(stmt, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
                    nxt = stmts[i + 1]
                    out.append(Raw(
                        "SLP002", nxt.lineno, "slop", "medium", "[SLP002] Unreachable code",
                        f"This statement follows `{type(stmt).__name__.lower()}` "
                        f"(line {stmt.lineno}) and can never run.",
                        "Delete the unreachable statements.", 0.95))
                    break
    private = [n for n in tree.body if isinstance(n, _FUNCS)
               and n.name.startswith("_") and not n.name.startswith("__")]
    if private:
        used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
        used |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        for fn in private:
            if fn.name not in used:
                out.append(Raw(
                    "SLP002", fn.lineno, "slop", "low",
                    f"[SLP002] Private function '{fn.name}' is never called",
                    "No reference to this module-private function exists in the file.",
                    "Remove it or add the missing call site.", 0.6))
    return out


# --------------------------------------------------------------------------- #
# SLP005 stub bodies
# --------------------------------------------------------------------------- #
def _exempt_functions(tree: ast.Module) -> set[int]:
    """ids of functions inside Protocol/ABC classes or marked abstract/overload."""
    exempt: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            bases = {getattr(b, "id", getattr(b, "attr", "")) for b in node.bases}
            if bases & {"Protocol", "ABC"}:
                exempt |= {id(n) for n in ast.walk(node) if isinstance(n, _FUNCS)}
        if isinstance(node, _FUNCS):
            for d in node.decorator_list:
                name = getattr(d, "id", getattr(d, "attr", ""))
                if name in {"abstractmethod", "overload"}:
                    exempt.add(id(node))
    return exempt


def _stubs(tree: ast.Module) -> list[Raw]:
    exempt = _exempt_functions(tree)
    out: list[Raw] = []
    for fn in ast.walk(tree):
        if not isinstance(fn, _FUNCS) or id(fn) in exempt or fn.name.startswith("__"):
            continue
        has_doc, body = _docstring_split(list(fn.body))
        kind, conf = None, 0.8
        if not body:
            kind, conf = ("a docstring only", 0.6) if has_doc else (None, 0)
        elif len(body) == 1:
            s = body[0]
            if isinstance(s, ast.Pass):
                kind = "`pass`"
            elif (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)
                  and s.value.value is Ellipsis):
                kind = "`...`"
            elif isinstance(s, ast.Raise) and s.exc is not None:
                exc = s.exc.func if isinstance(s.exc, ast.Call) else s.exc
                if getattr(exc, "id", "") == "NotImplementedError":
                    kind = "`raise NotImplementedError`"
            elif isinstance(s, ast.Return) and isinstance(s.value, ast.Constant):
                kind, conf = "a constant dummy return", 0.5
        if kind:
            out.append(Raw("SLP005", fn.lineno, "slop", "low" if conf < 0.7 else "medium",
                           f"[SLP005] Stub function '{fn.name}'",
                           f"Body is only {kind}; it looks finished but does nothing.",
                           "Implement it, or remove it if unused.", conf))
    return out


# --------------------------------------------------------------------------- #
# GAP001 empty catch
# --------------------------------------------------------------------------- #
def _empty_catches(tree: ast.Module) -> list[Raw]:
    out: list[Raw] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue
        stmts = [s for s in node.body
                 if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))]
        if all(isinstance(s, (ast.Pass, ast.Continue)) for s in stmts):
            only_continue = bool(stmts) and all(isinstance(s, ast.Continue) for s in stmts)
            out.append(Raw(
                "GAP001", node.lineno, "gaps", "low" if only_continue else "medium",
                "[GAP001] Exception swallowed silently",
                "The handler does nothing, so failures disappear without a trace.",
                "Log the error or handle it explicitly.", 0.6 if only_continue else 0.9))
    return out


# --------------------------------------------------------------------------- #
# GAP003 empty tests
# --------------------------------------------------------------------------- #
def _empty_tests(tree: ast.Module, rel: str) -> list[Raw]:
    if not _TEST_FILE.search(rel):
        return []
    out: list[Raw] = []
    for fn in ast.walk(tree):
        if not isinstance(fn, _FUNCS) or not fn.name.startswith("test"):
            continue
        meaningful = False
        for n in ast.walk(fn):
            if isinstance(n, ast.Assert):
                if not (isinstance(n.test, ast.Constant) and n.test.value):
                    meaningful = True
            elif isinstance(n, ast.Call):
                name = (n.func.attr if isinstance(n.func, ast.Attribute)
                        else getattr(n.func, "id", ""))
                if name.startswith(("assert", "fail")) or name in {"raises", "warns", "approx"}:
                    meaningful = True
            if meaningful:
                break
        if not meaningful:
            out.append(Raw("GAP003", fn.lineno, "gaps", "medium",
                           f"[GAP003] Test '{fn.name}' asserts nothing",
                           "No assertion (or only a trivially true one) was found.",
                           "Assert on the behaviour under test.", 0.8))
    return out


# --------------------------------------------------------------------------- #
# SLP001 duplicate functions (renamed copies)
# --------------------------------------------------------------------------- #
class _Normalizer(ast.NodeTransformer):
    def __init__(self) -> None:
        self.names: dict[str, str] = {}

    def _rename(self, ident: str) -> str:
        return self.names.setdefault(ident, f"v{len(self.names)}")

    def visit_Name(self, node: ast.Name) -> ast.AST:
        if node.id not in _BUILTINS:
            node.id = self._rename(node.id)
        return node

    def visit_arg(self, node: ast.arg) -> ast.AST:
        node.arg = self._rename(node.arg)
        return self.generic_visit(node)


def _fingerprint(fn: ast.AST) -> str:
    clone = copy.deepcopy(fn)
    _, rest = _docstring_split(clone.body)
    clone.body = rest or [ast.Pass()]
    clone.name = "f"
    _Normalizer().visit(clone)
    return hashlib.sha1(ast.dump(clone, annotate_fields=False).encode()).hexdigest()


def _duplicates(tree: ast.Module) -> list[Raw]:
    groups: dict[str, list[ast.AST]] = {}
    for fn in ast.walk(tree):
        if isinstance(fn, _FUNCS) and sum(1 for _ in ast.walk(fn)) >= _MIN_DUP_NODES:
            groups.setdefault(_fingerprint(fn), []).append(fn)
    out: list[Raw] = []
    for fns in groups.values():
        fns.sort(key=lambda f: f.lineno)
        first = fns[0]
        for dup in fns[1:]:
            out.append(Raw(
                "SLP001", dup.lineno, "slop", "low",
                f"[SLP001] '{dup.name}' duplicates '{first.name}'",
                f"Same structure as '{first.name}' (line {first.lineno}) apart from names.",
                "Extract the shared logic into one function.", 0.8))
    return out


# --------------------------------------------------------------------------- #
# SLP004 commented-out code
# --------------------------------------------------------------------------- #
_CODEISH = (ast.Assign, ast.AugAssign, ast.Import, ast.ImportFrom, ast.FunctionDef,
            ast.AsyncFunctionDef, ast.ClassDef, ast.If, ast.For, ast.While,
            ast.Return, ast.Try, ast.With)
_DIRECTIVES = ("!", "-*-", "type:", "noqa", "pylint", "fmt:", "pragma", "TODO", "FIXME",
               "HACK", "XXX")


def _commented_code(text: str) -> list[Raw]:
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return []
    comments = [(t.start[0], t.string) for t in tokens
                if t.type == tokenize.COMMENT and t.line.strip().startswith("#")]
    blocks: list[list[tuple[int, str]]] = []
    for line, content in comments:
        if blocks and blocks[-1][-1][0] == line - 1:
            blocks[-1].append((line, content))
        else:
            blocks.append([(line, content)])
    out: list[Raw] = []
    for block in blocks:
        source = textwrap.dedent("\n".join(re.sub(r"^#\s?", "", c) for _, c in block))
        if source.lstrip().startswith(_DIRECTIVES):
            continue
        try:
            parsed = ast.parse(source)
        except (SyntaxError, ValueError):
            continue
        if any(isinstance(n, _CODEISH)
               or (isinstance(n, ast.Expr) and isinstance(n.value, ast.Call))
               for n in parsed.body):
            out.append(Raw("SLP004", block[0][0], "slop", "low",
                           "[SLP004] Commented-out code",
                           f"{len(block)} comment line(s) parse as valid Python.",
                           "Delete it; version control keeps the history.", 0.7))
    return out


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def analyze_python(rel: str, text: str) -> list[Raw]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
        return [Raw("PARSE", getattr(exc, "lineno", None) or 1, "gaps", "low",
                    "[PARSE] File does not parse as Python 3",
                    f"{type(exc).__name__}: {exc}", "Fix the syntax error.", 1.0)]
    findings: list[Raw] = []
    for check in (_unused_imports, _empty_tests):
        findings += check(tree, rel)
    findings += _dead_code(tree) + _stubs(tree) + _empty_catches(tree)
    findings += _duplicates(tree) + _commented_code(text)
    return sorted(findings, key=lambda r: (r.line, r.rule))
