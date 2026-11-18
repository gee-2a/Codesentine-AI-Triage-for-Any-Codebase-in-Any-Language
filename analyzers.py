"""Deterministic, offline Python analyzers built on the stdlib `ast` module.

No network, no API key, no extra dependencies. Every finding carries a rule ID
and a confidence score so results are reproducible and explainable.

Rules
    SEC002 weak-crypto           MD5/SHA1 hashes, unverified SSL contexts
    SEC003 dangerous-sink        eval/exec, os.system, shell=True, unsafe deserialization
    SEC004 sql-injection         string-built SQL passed to execute-like calls
    SLP001 duplicate-code        functions with equal normalized AST
    SLP002 dead-code             unreachable statements, uncalled private functions
    SLP003 unused-import         imports never referenced
    SLP004 commented-out-code    comment blocks that parse as code
    SLP005 stub-body             pass / ... / NotImplementedError / dummy return
    GAP001 empty-catch           except blocks that swallow the error
    GAP002 no-timeout            network calls without a timeout
    GAP003 empty-test            test functions without meaningful assertions
    DEP002 undeclared-import     import not stdlib, not local, not in a manifest
"""
from __future__ import annotations

import ast
import builtins
import copy
import hashlib
import io
import re
import sys
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
    end_line: int = 0  # last line of the finding's span (0 = same as line)


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
                        "Delete the unreachable statements.", 0.95,
                        stmts[-1].end_lineno or nxt.lineno))
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
    return hashlib.sha1(ast.dump(clone, annotate_fields=False).encode(), usedforsecurity=False).hexdigest()


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
        except (SyntaxError, ValueError):  # sentinel:ignore[GAP001] unparsable comment block is simply not code
            continue
        if any(isinstance(n, _CODEISH)
               or (isinstance(n, ast.Expr) and isinstance(n.value, ast.Call))
               for n in parsed.body):
            out.append(Raw("SLP004", block[0][0], "slop", "low",
                           "[SLP004] Commented-out code",
                           f"{len(block)} comment line(s) parse as valid Python.",
                           "Delete it; version control keeps the history.", 0.7,
                           block[-1][0]))
    return out


# --------------------------------------------------------------------------- #
# SEC002 / SEC003 / SEC004 / GAP002  call-based rules
# --------------------------------------------------------------------------- #
_SQL_WORDS = re.compile(r"(?is)\b(select|insert|update|delete)\b.*\b(from|into|set|where|values)\b")
_EXECUTE_ATTRS = {"execute", "executemany", "executescript", "raw", "read_sql", "read_sql_query"}
_HTTP_CALLS = {
    "requests.get", "requests.post", "requests.put", "requests.patch", "requests.delete",
    "requests.head", "requests.request", "urllib.request.urlopen",
    "httpx.get", "httpx.post", "httpx.put", "httpx.patch", "httpx.delete", "httpx.request",
}


def _dotted(node: ast.AST) -> str:
    """'a.b.c' for a Name/Attribute chain, '' for anything else."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def _kwarg(call: ast.Call, name: str) -> ast.keyword | None:
    return next((k for k in call.keywords if k.arg == name), None)


def _is_true(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _is_dynamic_sql(arg: ast.AST) -> bool:
    """True if `arg` is a string built from non-constant parts and looks like SQL."""
    if isinstance(arg, ast.JoinedStr):
        dynamic = any(isinstance(n, ast.FormattedValue) for n in ast.walk(arg))
    elif isinstance(arg, ast.BinOp) and isinstance(arg.op, (ast.Add, ast.Mod)):
        dynamic = any(isinstance(n, (ast.Name, ast.Attribute, ast.Subscript, ast.Call))
                      for n in ast.walk(arg))
    elif (isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute)
          and arg.func.attr == "format"):
        dynamic = any(not isinstance(a, ast.Constant) for a in arg.args) or bool(arg.keywords)
    else:
        return False
    texts = [n.value for n in ast.walk(arg)
             if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    return dynamic and any(_SQL_WORDS.search(t) for t in texts)


def _call_rules(tree: ast.Module) -> list[Raw]:
    out: list[Raw] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _dotted(node.func)
        line = node.lineno
        attr = node.func.attr if isinstance(node.func, ast.Attribute) else ""

        if name in {"eval", "exec"}:
            literal = bool(node.args) and isinstance(node.args[0], ast.Constant)
            out.append(Raw("SEC003", line, "security", "medium" if literal else "high",
                           f"[SEC003] Dynamic code execution ({name})",
                           f"`{name}` runs arbitrary code" + (" (literal argument)." if literal
                                                             else " built at runtime."),
                           "Use ast.literal_eval or an explicit dispatch table.",
                           0.5 if literal else 0.9))
        elif name in {"os.system", "os.popen"}:
            out.append(Raw("SEC003", line, "security", "high", f"[SEC003] Shell command via {name}",
                           "The command string is interpreted by a shell.",
                           "Use subprocess.run with an argument list and no shell.", 0.85))
        elif name.startswith("subprocess.") and (kw := _kwarg(node, "shell")) and _is_true(kw.value):
            out.append(Raw("SEC003", line, "security", "high", "[SEC003] subprocess with shell=True",
                           "shell=True lets metacharacters in arguments run extra commands.",
                           "Pass an argument list and drop shell=True.", 0.9))
        elif name in {"pickle.load", "pickle.loads", "marshal.load", "marshal.loads"} or (
                name == "yaml.load" and _kwarg(node, "Loader") is None):
            out.append(Raw("SEC003", line, "security", "medium", f"[SEC003] Unsafe deserialization ({name})",
                           "Deserializing untrusted data can execute code.",
                           "Use json or yaml.safe_load for untrusted input.", 0.7))
        elif name in {"hashlib.md5", "hashlib.sha1"}:
            kw = _kwarg(node, "usedforsecurity")
            if not (kw and isinstance(kw.value, ast.Constant) and kw.value.value is False):
                out.append(Raw("SEC002", line, "security", "medium",
                               f"[SEC002] Weak hash ({name.split('.')[1].upper()})",
                               "MD5/SHA-1 are broken for security purposes.",
                               "Use hashlib.sha256 (or pass usedforsecurity=False for checksums).",
                               0.7))
        elif name == "ssl._create_unverified_context":
            out.append(Raw("SEC002", line, "security", "medium", "[SEC002] Unverified SSL context",
                           "Certificates are not validated.", "Use ssl.create_default_context().", 0.9))

        if attr in _EXECUTE_ATTRS and node.args and _is_dynamic_sql(node.args[0]):
            out.append(Raw("SEC004", line, "security", "high", "[SEC004] SQL built from strings",
                           "The query is assembled with concatenation/formatting, so input can alter it.",
                           "Use parameterized queries (placeholders plus a parameter tuple).", 0.8))

        if name in _HTTP_CALLS and _kwarg(node, "timeout") is None and not any(
                k.arg is None for k in node.keywords):
            out.append(Raw("GAP002", line, "gaps", "medium", f"[GAP002] {name} has no timeout",
                           "Without a timeout the call can hang forever.",
                           "Pass timeout=<seconds>.", 0.75))
    return out


# --------------------------------------------------------------------------- #
# DEP002 undeclared imports (needs repo context: local modules + manifest)
# --------------------------------------------------------------------------- #
_ALIASES = {
    "dotenv": "python-dotenv", "yaml": "pyyaml", "cv2": "opencv-python", "pil": "pillow",
    "sklearn": "scikit-learn", "bs4": "beautifulsoup4", "dateutil": "python-dateutil",
    "jwt": "pyjwt", "serial": "pyserial", "attr": "attrs",
}


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _undeclared_imports(tree: ast.Module, ctx: dict | None) -> list[Raw]:
    if not ctx or ctx.get("declared") is None:
        return []
    stdlib = getattr(sys, "stdlib_module_names", None)
    if stdlib is None:
        return []
    declared = {_norm(d) for d in ctx["declared"]}
    local = ctx.get("local", set())
    out: list[Raw] = []
    seen: set[str] = set()
    for node in ast.walk(tree):
        tops: list[str] = []
        if isinstance(node, ast.Import):
            tops = [a.name.split(".")[0] for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            tops = [node.module.split(".")[0]]
        for top in tops:
            if top in stdlib or top in local or top in seen:
                continue
            if {_norm(top), _norm(_ALIASES.get(top.lower(), top))} & declared:
                continue
            seen.add(top)
            out.append(Raw("DEP002", node.lineno, "slop", "low",
                           f"[DEP002] Import '{top}' is not declared in a manifest",
                           "Not stdlib, not a local module, and not listed in requirements.",
                           "Add it to requirements.txt, or remove the import if it does not exist.",
                           0.4))
    return out


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def analyze_python(rel: str, text: str, ctx: dict | None = None) -> list[Raw]:
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
    findings += _call_rules(tree) + _undeclared_imports(tree, ctx)
    return sorted(findings, key=lambda r: (r.line, r.rule))
