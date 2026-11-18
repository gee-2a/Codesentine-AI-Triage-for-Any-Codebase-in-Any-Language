"""Tests for the rule additions, suppressions, report formats, fixers and benchmark."""
import json
import sys
import unittest
from pathlib import Path

import agent
from analyzers import analyze_python
from fixers import run_fixes
from report import to_json, to_sarif
from suppress import parse_suppressions

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "scripts"))
import evaluate  # noqa: E402


def rules(code, ctx=None):
    return [r.rule for r in analyze_python("m.py", code, ctx)]


def scan(rel, text):
    kept, _ = agent.apply_suppressions(agent.merge(agent.static_scan(rel, text)), {rel: text})
    return kept


class RuleTests(unittest.TestCase):
    def test_sql_injection_variants(self):
        self.assertIn("SEC004", rules("def f(c, n):\n    c.execute(\"SELECT * FROM t WHERE a='\" + n + \"'\")\n"))
        self.assertIn("SEC004", rules("def f(c, n):\n    c.execute(f\"SELECT * FROM t WHERE a='{n}'\")\n"))
        self.assertIn("SEC004", rules("def f(c, n):\n    c.execute(\"SELECT * FROM t WHERE a=%s\" % n)\n"))

    def test_parameterized_sql_is_clean(self):
        self.assertNotIn("SEC004", rules("def f(c, n):\n    c.execute(\"SELECT * FROM t WHERE a=?\", (n,))\n"))
        self.assertNotIn("SEC004", rules("def f(c):\n    c.execute(\"SELECT * FROM t\")\n"))

    def test_dangerous_sinks(self):
        self.assertIn("SEC003", rules("import os\ndef f(x):\n    os.system(x)\n"))
        self.assertIn("SEC003", rules("def f(x):\n    return eval(x)\n"))
        self.assertIn("SEC003", rules("import subprocess\ndef f(x):\n    subprocess.run(x, shell=True)\n"))
        self.assertNotIn("SEC003", rules("import subprocess\ndef f(x):\n    subprocess.run([x])\n"))

    def test_weak_hash_and_checksum_exemption(self):
        self.assertIn("SEC002", rules("import hashlib\nh = hashlib.md5(b'x')\n"))
        self.assertNotIn("SEC002", rules("import hashlib\nh = hashlib.md5(b'x', usedforsecurity=False)\n"))

    def test_missing_timeout(self):
        self.assertIn("GAP002", rules("import requests\nrequests.get('http://x')\n"))
        self.assertNotIn("GAP002", rules("import requests\nrequests.get('http://x', timeout=5)\n"))

    def test_undeclared_import_needs_manifest(self):
        code = "import numpy\nimport json\nimport helper\nprint(numpy, json, helper)\n"
        self.assertNotIn("DEP002", rules(code, None))
        got = analyze_python("m.py", code, {"declared": {"requests"}, "local": {"helper"}})
        self.assertEqual([r.rule for r in got if r.rule == "DEP002"], ["DEP002"])
        ok = analyze_python("m.py", code, {"declared": {"numpy"}, "local": {"helper"}})
        self.assertFalse([r for r in ok if r.rule == "DEP002"])

    def test_regex_does_not_fire_inside_python_strings(self):
        text = 'RULE = "uses eval( and shell=True"\n'
        self.assertFalse([f for f in scan("m.py", text) if f.rule in {"SEC003", "SEC004"}])


class SuppressionTests(unittest.TestCase):
    CODE = "import os\ndef f(x):\n    os.system(x)  # sentinel:ignore[SEC003] {reason}\n"

    def test_reasoned_suppression_silences(self):
        text = self.CODE.format(reason="x is a constant from our config")
        self.assertNotIn("SEC003", [f.rule for f in scan("m.py", text)])

    def test_missing_reason_does_not_suppress_and_is_reported(self):
        text = self.CODE.format(reason="")
        found = [f.rule for f in scan("m.py", text)]
        self.assertIn("SEC003", found)
        self.assertIn("SUP001", found)

    def test_wrong_rule_does_not_suppress(self):
        text = self.CODE.format(reason="ok").replace("SEC003]", "SEC002]")
        self.assertIn("SEC003", [f.rule for f in scan("m.py", text)])

    def test_standalone_comment_applies_to_next_line(self):
        text = "import os\ndef f(x):\n    # sentinel:ignore[SEC003] fixed command\n    os.system(x)\n"
        self.assertNotIn("SEC003", [f.rule for f in scan("m.py", text)])

    def test_parse(self):
        valid, bad = parse_suppressions("a  // sentinel:ignore[GAP001, SEC001] because\nb # sentinel:ignore[X]\n")
        self.assertEqual(valid[1][0], {"GAP001", "SEC001"})
        self.assertEqual(bad, [2])


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.findings = scan("m.py", "import os\ndef f(x):\n    os.system(x)\n")

    def test_json(self):
        data = json.loads(to_json(self.findings, {"files": 1, "chunks": 1, "mode": "offline rules"}, "/t"))
        self.assertEqual(data["tool"], "CodeSentinel")
        self.assertTrue(all(f["rule"] for f in data["findings"]))

    def test_sarif_shape(self):
        doc = json.loads(to_sarif(self.findings, "/t"))
        self.assertEqual(doc["version"], "2.1.0")
        res = doc["runs"][0]["results"][0]
        self.assertIn(res["level"], {"error", "warning", "note"})
        self.assertGreaterEqual(res["locations"][0]["physicalLocation"]["region"]["startLine"], 1)


class FixerTests(unittest.TestCase):
    def fix(self, code):
        return run_fixes("m.py", code, scan)

    def test_unused_import_removed_and_partial_kept(self):
        new, ok, _ = self.fix("import os, sys\nprint(os.name)\n")
        self.assertEqual(new, "import os\nprint(os.name)\n")
        self.assertEqual(len(ok), 1)

    def test_unreachable_removed(self):
        new, ok, _ = self.fix("def f(a):\n    b = a + 1\n    return b\n    print('x')\n")
        self.assertNotIn("print", new)

    def test_empty_except_gets_logging(self):
        new, ok, _ = self.fix("def f():\n    try:\n        return 1\n    except Exception:\n        pass\n")
        self.assertIn("import logging", new)
        self.assertIn("logging.getLogger", new)
        compile(new, "m.py", "exec")

    def test_fixed_output_always_parses(self):
        code = "import os, sys\n\ndef f(a):\n    return a\n    x = 1\n\n# old = f(1)\n# old2 = old + 1\n"
        new, ok, bad = self.fix(code)
        compile(new, "m.py", "exec")

    def test_non_python_untouched(self):
        new, ok, bad = run_fixes("a.js", "var x;\n", scan)
        self.assertEqual((new, ok, bad), ("var x;\n", [], []))

    def test_clean_code_has_no_fixes(self):
        code = "import os\n\n\ndef f():\n    return os.name\n"
        new, ok, bad = self.fix(code)
        self.assertEqual((new, ok), (code, []))


class BenchmarkTests(unittest.TestCase):
    def test_seeded_benchmark_stays_healthy(self):
        r = evaluate.evaluate(ROOT / "demo-messy-repo")
        self.assertGreaterEqual(r["f1"], 0.9, r)
        self.assertEqual(r["clean_file_fp"], 0)


class CliTests(unittest.TestCase):
    def test_exclude_matching(self):
        self.assertTrue(agent.is_excluded("tests/a.py", ["tests"]))
        self.assertTrue(agent.is_excluded("pkg/test_a.py", ["test_*.py"]))
        self.assertFalse(agent.is_excluded("src/a.py", ["tests", "*.md"]))


if __name__ == "__main__":
    unittest.main()
