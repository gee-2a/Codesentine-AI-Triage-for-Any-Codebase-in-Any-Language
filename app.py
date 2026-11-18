#!/usr/bin/env python3
"""CodeSentinel web service (stdlib HTTP server, port 8000).

GET  /            web UI
GET  /health      {"ok": true}
POST /classify    {"text": "..."} -> {"category", "urgency", "confidence"}
POST /api/scan    {"filename", "code", "offline"} -> code-scan findings
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
from collections import deque
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import agent

MAX_CLASSIFY_BODY = 16_384
MAX_SCAN_BODY = 200_000
_FAILED = object()  # sentinel: an error response was already sent

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CodeSentinel</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#1a1a1a}
 textarea{width:100%;height:220px;font-family:ui-monospace,monospace;font-size:13px}
 input[type=text]{padding:.4rem;width:200px}
 button{padding:.5rem 1rem;cursor:pointer}
 table{border-collapse:collapse;width:100%;margin-top:1rem}
 td,th{border-bottom:1px solid #ddd;padding:.5rem;text-align:left;vertical-align:top}
 .critical{background:#c62828;color:#fff}.high{color:#c62828;font-weight:700}
 .medium{color:#b26a00}.low{color:#00695c}.info{color:#666}
 .tag{padding:2px 6px;border-radius:4px;font-size:12px;text-transform:uppercase}
</style></head><body>
<h1>CodeSentinel</h1>
<p>Language-agnostic code triage: security, slop, and loose ends. Paste code below.</p>
<p>File name (helps language detection): <input type="text" id="fn" value="snippet.py">
 <label><input type="checkbox" id="ai"> use AI analysis (needs server API key)</label></p>
<textarea id="code"># TODO: remove before launch
API_KEY = "supersecret-api-key-12345"
def run(x):
    try:
        return eval(x)
    except Exception:
        pass
</textarea>
<p><button id="go">Scan</button> <span id="status"></span></p>
<div id="out"></div>
<script>
const $ = (id) => document.getElementById(id);
$("go").onclick = async () => {
  $("status").textContent = "Scanning...";
  $("out").textContent = "";
  try {
    const r = await fetch("/api/scan", {method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({filename: $("fn").value, code: $("code").value, offline: !$("ai").checked})});
    const data = await r.json();
    if (!r.ok) { $("status").textContent = data.error || "Error"; return; }
    $("status").textContent = "Health score " + data.score + "/100 | " + data.mode;
    const t = document.createElement("table");
    const head = t.insertRow();
    ["Severity", "Type", "Line", "Finding"].forEach(h => { const c = document.createElement("th"); c.textContent = h; head.appendChild(c); });
    data.findings.forEach(f => {
      const row = t.insertRow();
      const sev = row.insertCell(); const tag = document.createElement("span");
      tag.className = "tag " + f.severity; tag.textContent = f.severity; sev.appendChild(tag);
      row.insertCell().textContent = f.category;
      row.insertCell().textContent = f.line;
      row.insertCell().textContent = f.title + (f.fix ? " - Fix: " + f.fix : "");
    });
    $("out").appendChild(t);
  } catch (e) { $("status").textContent = "Request failed: " + e; }
};
</script></body></html>"""


# --------------------------------------------------------------------------- #
# Rate limiting (per client IP, sliding window)
# --------------------------------------------------------------------------- #
class RateLimiter:
    def __init__(self, limit: int, window: float = 60.0, clock=time.monotonic):
        self.limit, self.window, self.clock = limit, window, clock
        self._hits: dict[str, deque] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = self.clock()
        with self._lock:
            hits = self._hits.setdefault(key, deque())
            while hits and now - hits[0] > self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            if len(self._hits) > 10_000:  # bound memory
                self._hits = {k: v for k, v in self._hits.items()
                              if v and now - v[-1] <= self.window}
            return True


LIMITER = RateLimiter(int(os.getenv("RATE_LIMIT_PER_MIN", "300")))


# --------------------------------------------------------------------------- #
# /classify : deterministic keyword triage (no external calls, no secrets)
# --------------------------------------------------------------------------- #
CATEGORIES = {
    "billing": ("refund", "invoice", "payment", "charge", "billing", "receipt",
                "subscription", "credit card", "pricing"),
    "technical": ("error", "crash", "bug", "broken", "exception", "timeout",
                  "not working", "fail", "outage", "slow"),
    "account": ("login", "log in", "sign in", "password", "account", "username",
                "2fa", "locked out"),
}
_PATTERNS = {
    label: re.compile(r"\b(?:" + "|".join(re.escape(w) for w in words) + r")\w*")
    for label, words in CATEGORIES.items()
}
_URGENT = re.compile(
    r"\b(?:urgent|urgently|outage|immediately|asap|emergency|critical)\b"
    r"|\b(?:site|server|production|service) (?:is )?down\b")


def classify_text(text: str) -> dict:
    lowered = text.lower()
    counts = {label: len(p.findall(lowered)) for label, p in _PATTERNS.items()}
    best = max(counts, key=counts.get)
    hits = counts[best]
    return {
        "category": best if hits else "general",
        "urgency": "high" if _URGENT.search(lowered) else "low",
        "confidence": 0.3 if not hits else round(min(0.95, 0.55 + 0.1 * hits), 2),
    }


# --------------------------------------------------------------------------- #
# /api/scan : CodeSentinel code analysis
# --------------------------------------------------------------------------- #
def scan_code(filename: str, code: str, want_llm: bool) -> dict:
    rel = Path(filename or "snippet.txt").name or "snippet.txt"
    findings = agent.static_scan(rel, code)
    mode = "offline rules"
    if want_llm and os.getenv("ANTHROPIC_API_KEY"):
        try:
            import anthropic

            client = anthropic.Anthropic(max_retries=2)
            lang = agent.LANG_BY_EXT.get(Path(rel).suffix.lower(), "unknown (infer from content)")
            for chunk in agent.chunk_text(code):
                findings += agent.analyze_chunk(client, agent.DEFAULT_MODEL, rel, lang, chunk)
            mode = f"LLM ({agent.DEFAULT_MODEL}) + rules"
        except Exception as exc:  # never fail the request because the LLM failed
            mode = f"offline rules (LLM unavailable: {type(exc).__name__})"
    merged, suppressed = agent.apply_suppressions(agent.merge(findings), {rel: code})
    return {"mode": mode, "score": agent.risk_score(merged), "suppressed": len(suppressed),
            "findings": [asdict(f) for f in merged]}


# --------------------------------------------------------------------------- #
# HTTP handler
# --------------------------------------------------------------------------- #
class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(5)  # guard against slow/stalled clients

    def _send(self, code: int, body: bytes, ctype: str = "application/json",
              extra: dict | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, payload: dict, extra: dict | None = None) -> None:
        self._send(code, json.dumps(payload).encode("utf-8"), extra=extra)

    def _allow(self) -> bool:
        if LIMITER.allow(self.client_address[0]):
            return True
        self._json(429, {"error": "rate_limited"}, {"Retry-After": "60"})
        return False

    def _read_json(self, limit: int):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._json(400, {"error": "invalid_length"})
            return _FAILED
        if not 1 <= length <= limit:
            self._json(413, {"error": "body_size"})
            return _FAILED
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeError, OSError):
            self._json(400, {"error": "invalid_json"})
            return _FAILED

    def do_GET(self):  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/health":
            return self._json(200, {"ok": True})
        if not self._allow():
            return
        if path == "/":
            self._send(200, PAGE.encode("utf-8"), "text/html; charset=utf-8")
        else:
            self._json(404, {"error": "not_found"})

    def do_POST(self):  # noqa: N802
        if not self._allow():
            return
        path = self.path.split("?", 1)[0]
        if path == "/classify":
            data = self._read_json(MAX_CLASSIFY_BODY)
            if data is _FAILED:
                return
            text = data.get("text") if isinstance(data, dict) else None
            if not isinstance(text, str) or not text.strip():
                return self._json(400, {"error": "text_required"})
            return self._json(200, classify_text(text))
        if path == "/api/scan":
            data = self._read_json(MAX_SCAN_BODY)
            if data is _FAILED:
                return
            if not isinstance(data, dict) or not isinstance(data.get("code"), str):
                return self._json(400, {"error": "code_required"})
            return self._json(200, scan_code(str(data.get("filename", "")),
                                             data["code"], not data.get("offline", True)))
        self._json(404, {"error": "not_found"})

    def log_message(self, *_):
        # sentinel:ignore[SLP005] deliberate no-op: never log request content or client addresses
        pass


def make_server(host: str = "0.0.0.0", port: int = 8000) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), Handler)


if __name__ == "__main__":
    from dotenv import load_dotenv

    load_dotenv()
    port = int(os.getenv("PORT", "8000"))
    print(f"CodeSentinel listening on http://localhost:{port}")
    make_server(port=port).serve_forever()
