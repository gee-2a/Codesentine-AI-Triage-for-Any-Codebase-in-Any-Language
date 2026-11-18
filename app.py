#!/usr/bin/env python3
"""CodeSentinel web demo: paste code, get findings. Stdlib HTTP server on port 8000.

GET  /           simple web UI
GET  /health     {"status": "ok"}
POST /api/scan   {"filename": "x.py", "code": "...", "offline": true} -> findings JSON
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import anthropic
from dotenv import load_dotenv

import agent

MAX_BODY = 200_000  # bytes

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


def scan_code(filename: str, code: str, want_llm: bool) -> dict:
    rel = Path(filename or "snippet.txt").name or "snippet.txt"
    findings = agent.static_scan(rel, code)
    mode = "offline regex"
    if want_llm and os.getenv("ANTHROPIC_API_KEY"):
        try:
            client = anthropic.Anthropic(max_retries=2)
            lang = agent.LANG_BY_EXT.get(Path(rel).suffix.lower(), "unknown (infer from content)")
            for chunk in agent.chunk_text(code):
                findings += agent.analyze_chunk(client, agent.DEFAULT_MODEL, rel, lang, chunk)
            mode = f"LLM ({agent.DEFAULT_MODEL}) + regex"
        except Exception as exc:  # never fail the request because the LLM failed
            mode = f"offline regex (LLM unavailable: {type(exc).__name__})"
    merged = agent.merge(findings)
    return {"mode": mode, "score": agent.risk_score(merged),
            "findings": [asdict(f) for f in merged]}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: bytes, ctype: str = "application/json") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, payload: dict) -> None:
        self._send(code, json.dumps(payload).encode("utf-8"))

    def do_GET(self):  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/":
            self._send(200, PAGE.encode("utf-8"), "text/html; charset=utf-8")
        elif path == "/health":
            self._json(200, {"status": "ok"})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802
        if self.path.split("?", 1)[0] != "/api/scan":
            return self._json(404, {"error": "not found"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self._json(400, {"error": "bad Content-Length"})
        if length <= 0 or length > MAX_BODY:
            return self._json(413, {"error": f"body must be 1..{MAX_BODY} bytes"})
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8"))
            code = data["code"]
            if not isinstance(code, str):
                raise TypeError("code must be a string")
        except (ValueError, KeyError, TypeError) as exc:
            return self._json(400, {"error": f"invalid request: {exc}"})
        result = scan_code(str(data.get("filename", "")), code, not data.get("offline", True))
        self._json(200, result)

    def log_message(self, fmt, *args):  # keep logs short
        print("[codesentinel]", fmt % args)


def make_server(host: str = "0.0.0.0", port: int = 8000) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), Handler)


if __name__ == "__main__":
    load_dotenv()
    port = int(os.getenv("PORT", "8000"))
    print(f"CodeSentinel web demo on http://localhost:{port}")
    make_server(port=port).serve_forever()