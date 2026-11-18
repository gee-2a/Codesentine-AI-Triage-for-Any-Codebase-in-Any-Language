import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

import agent
import app

ROOT = Path(__file__).resolve().parent
DEMO = ROOT / "dummy_target"


class ChunkingTests(unittest.TestCase):
    def test_chunks_are_contiguous_and_numbered(self):
        text = "\n".join(["x" * 10] * 10)
        chunks = agent.chunk_text(text, max_chars=40)
        self.assertEqual(len(chunks), 5)
        self.assertEqual(chunks[0].start, 1)
        self.assertEqual(chunks[-1].end, 10)
        for prev, cur in zip(chunks, chunks[1:]):
            self.assertEqual(cur.start, prev.end + 1)
        self.assertIn("    1| xxxxxxxxxx", chunks[0].body)


class StaticScanTests(unittest.TestCase):
    def titles(self, name):
        text = (DEMO / name).read_text(encoding="utf-8")
        return {f.title for f in agent.static_scan(name, text)}

    def test_python_demo(self):
        t = self.titles("bad_code.py")
        for expected in ("Hardcoded credential", "AWS access key ID",
                         "Dynamic code execution (eval/exec)", "TODO/FIXME marker",
                         "Empty/swallowing exception handler", "TLS verification disabled"):
            self.assertIn(expected, t)

    def test_python_demo_ast_rules(self):
        text = (DEMO / "bad_code.py").read_text(encoding="utf-8")
        rules = {f.rule for f in agent.static_scan("bad_code.py", text)}
        self.assertTrue({"SLP003", "GAP001"} <= rules)

    def test_javascript_demo(self):
        t = self.titles("bad_code.js")
        for expected in ("Hardcoded credential", "Dynamic code execution (eval/exec)",
                         "TODO/FIXME marker", "Empty/swallowing exception handler"):
            self.assertIn(expected, t)


class MergeAndRedactTests(unittest.TestCase):
    def test_llm_finding_replaces_static_duplicate(self):
        s = agent.Finding("a.py", 3, "security", "high", "static", source="static")
        l = agent.Finding("a.py", 3, "security", "medium", "llm", source="llm")
        merged = agent.merge([s, l])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].source, "llm")

    def test_ast_and_regex_duplicates_collapse_to_one(self):
        text = "try:\n    x()\nexcept Exception:\n    pass\n"
        merged = agent.merge(agent.static_scan("a.py", text))
        self.assertEqual([f.line for f in merged if f.category == "gaps"], [3])

    def test_redact_hides_secrets(self):
        self.assertNotIn("IOSFODNN7", agent.redact("key AKIAIOSFODNN7EXAMPLE"))
        self.assertNotIn("hunter2xx", agent.redact('password = "hunter2xx"'))

    def test_has_tests(self):
        self.assertFalse(agent.has_tests(["src/a.py"]))
        self.assertTrue(agent.has_tests(["tests/test_a.py"]))


class FileDiscoveryTests(unittest.TestCase):
    def test_skips_hidden_binary_and_vendor_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "main.py").write_text("print('hi')\n")
            (root / ".env").write_text("TOKEN=abcdef123\n")
            (root / ".gitignore").write_text(".env\n")
            (root / ".hidden").mkdir()
            (root / ".hidden" / "x.py").write_text("x = 1\n")
            (root / "node_modules").mkdir()
            (root / "node_modules" / "y.js").write_text("var y;\n")
            (root / "img.png").write_bytes(b"\x89PNG\x00\x00")
            (root / "data.txt").write_bytes(b"abc\x00def")
            (root / "package-lock.json").write_text("{}\n")
            found = {p.relative_to(root).as_posix()
                     for p in agent.collect_files(root, 300, 200)}
            self.assertEqual(found, {"main.py", ".env"})


class ClassifyTests(unittest.TestCase):
    def test_billing(self):
        self.assertEqual(app.classify_text("Please refund this invoice")["category"], "billing")

    def test_technical(self):
        self.assertEqual(app.classify_text("The screen is broken")["category"], "technical")

    def test_account(self):
        self.assertEqual(app.classify_text("I forgot my password")["category"], "account")

    def test_urgency(self):
        self.assertEqual(app.classify_text("Urgent outage")["urgency"], "high")
        self.assertEqual(app.classify_text("Just a question")["urgency"], "low")

    def test_unknown_is_general_with_valid_confidence(self):
        result = app.classify_text("Hello team")
        self.assertEqual(result["category"], "general")
        self.assertTrue(0 <= result["confidence"] <= 1)


class RateLimiterTests(unittest.TestCase):
    def test_blocks_after_limit_then_recovers(self):
        now = [0.0]
        rl = app.RateLimiter(2, window=60, clock=lambda: now[0])
        self.assertTrue(rl.allow("ip"))
        self.assertTrue(rl.allow("ip"))
        self.assertFalse(rl.allow("ip"))
        now[0] = 61
        self.assertTrue(rl.allow("ip"))


class WebApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = app.make_server(host="127.0.0.1", port=0)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def post(self, path, body: bytes):
        req = urllib.request.Request(self.base + path, data=body,
                                     headers={"Content-Type": "application/json"})
        return urllib.request.urlopen(req)

    def test_health(self):
        with urllib.request.urlopen(self.base + "/health") as r:
            self.assertEqual(json.load(r), {"ok": True})

    def test_classify_ok(self):
        with self.post("/classify", json.dumps({"text": "Refund my payment"}).encode()) as r:
            data = json.load(r)
        self.assertEqual(set(data), {"category", "urgency", "confidence"})
        self.assertEqual(data["category"], "billing")

    def test_classify_requires_text(self):
        for body in (b'{"text": ""}', b'{"text": 5}', b'{}', b'[]'):
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                self.post("/classify", body)
            self.assertEqual(ctx.exception.code, 400)

    def test_classify_invalid_json_is_400(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.post("/classify", b"not json")
        self.assertEqual(ctx.exception.code, 400)

    def test_unknown_route_is_404(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(self.base + "/nope")
        self.assertEqual(ctx.exception.code, 404)

    def test_scan_offline_redacts_values(self):
        payload = {"filename": "bad.py", "offline": True,
                   "code": "# TODO fix\npassword = \"abcdef123\"\n"}
        with self.post("/api/scan", json.dumps(payload).encode()) as r:
            raw = r.read().decode()
        self.assertGreaterEqual(len(json.loads(raw)["findings"]), 2)
        self.assertNotIn("abcdef123", raw)


if __name__ == "__main__":
    unittest.main()
