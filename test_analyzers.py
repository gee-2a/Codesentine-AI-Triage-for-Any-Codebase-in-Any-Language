import unittest

from analyzers import analyze_python


def rules(rel, src):
    return [(r.rule, r.line) for r in analyze_python(rel, src)]


class UnusedImportTests(unittest.TestCase):
    def test_flags_only_unused(self):
        src = "import os\nimport sys\nprint(sys.argv)\n"
        self.assertEqual(rules("a.py", src), [("SLP003", 1)])

    def test_future_all_and_init_are_exempt(self):
        self.assertEqual(rules("a.py", "from __future__ import annotations\n"), [])
        self.assertEqual(rules("a.py", "import os\n__all__ = ['os']\n"), [])
        self.assertEqual(rules("pkg/__init__.py", "import os\n"), [])


class DeadCodeTests(unittest.TestCase):
    def test_unreachable_after_return(self):
        src = "def f():\n    return 1\n    print('x')\n"
        self.assertIn(("SLP002", 3), rules("a.py", src))

    def test_uncalled_private_function(self):
        self.assertIn(("SLP002", 1), rules("a.py", "def _h():\n    return 1\n"))

    def test_called_private_function_is_fine(self):
        src = "def _h():\n    return 1\n\ndef main():\n    return _h()\n"
        self.assertNotIn("SLP002", [r for r, _ in rules("a.py", src)])


class StubTests(unittest.TestCase):
    def test_pass_and_not_implemented(self):
        src = "def a():\n    pass\n\ndef b():\n    raise NotImplementedError\n"
        self.assertEqual([r for r in rules("a.py", src) if r[0] == "SLP005"],
                         [("SLP005", 1), ("SLP005", 4)])

    def test_abstract_and_protocol_are_exempt(self):
        src = ("from abc import ABC, abstractmethod\n"
               "class A(ABC):\n    @abstractmethod\n    def m(self):\n        pass\n"
               "class P(Protocol):\n    def n(self):\n        ...\n")
        self.assertNotIn("SLP005", [r for r, _ in rules("a.py", src)])


class EmptyCatchTests(unittest.TestCase):
    def test_pass_handler_flagged_logging_handler_not(self):
        bad = "try:\n    x()\nexcept Exception:\n    pass\n"
        good = "try:\n    x()\nexcept Exception as e:\n    print(e)\n"
        self.assertIn(("GAP001", 3), rules("a.py", bad))
        self.assertNotIn("GAP001", [r for r, _ in rules("a.py", good)])


class EmptyTestTests(unittest.TestCase):
    SRC = ("def test_a():\n    x = 1\n\n"
           "def test_b():\n    assert 1 == 1\n\n"
           "def test_c():\n    assert True\n\n"
           "class T:\n    def test_d(self):\n        self.assertEqual(1, 1)\n")

    def test_only_assertionless_tests_flagged(self):
        got = [r for r in rules("test_x.py", self.SRC) if r[0] == "GAP003"]
        self.assertEqual(got, [("GAP003", 1), ("GAP003", 7)])

    def test_non_test_files_ignored(self):
        self.assertNotIn("GAP003", [r for r, _ in rules("util.py", self.SRC)])


class DuplicateTests(unittest.TestCase):
    SRC = ("def a(items):\n    total = 0\n    for item in items:\n"
           "        if item > 10:\n            total += item * 2\n"
           "        else:\n            total -= 1\n    return total\n\n"
           "def b(values):\n    acc = 0\n    for v in values:\n"
           "        if v > 10:\n            acc += v * 2\n"
           "        else:\n            acc -= 1\n    return acc\n")

    def test_renamed_copy_detected(self):
        self.assertIn(("SLP001", 10), rules("a.py", self.SRC))

    def test_different_logic_not_flagged(self):
        other = self.SRC.replace("acc -= 1", "acc *= 3")
        self.assertNotIn("SLP001", [r for r, _ in rules("a.py", other)])


class CommentedCodeTests(unittest.TestCase):
    def test_code_block_flagged_prose_not(self):
        src = "# x = compute(1)\n# y = x + 1\nprint(1)\n# This is prose about things\n# TODO: fix\n"
        self.assertEqual([r for r in rules("a.py", src) if r[0] == "SLP004"],
                         [("SLP004", 1)])


class RobustnessTests(unittest.TestCase):
    def test_syntax_error_does_not_crash(self):
        got = analyze_python("a.py", "def broken(:\n")
        self.assertEqual(got[0].rule, "PARSE")

    def test_every_finding_has_evidence_and_confidence(self):
        src = "import os\ndef f():\n    return 1\n    pass\n"
        for r in analyze_python("a.py", src):
            self.assertTrue(r.title and r.detail and r.fix)
            self.assertTrue(0.0 <= r.confidence <= 1.0)


if __name__ == "__main__":
    unittest.main()
