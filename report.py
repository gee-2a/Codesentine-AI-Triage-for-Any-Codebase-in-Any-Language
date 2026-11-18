"""Machine-readable reports: JSON and SARIF 2.1.0."""
from __future__ import annotations

import json
from dataclasses import asdict

TOOL_NAME = "CodeSentinel"
TOOL_VERSION = "1.1.0"
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def _rule_id(f) -> str:
    return f.rule or "LLM001"


def to_json(findings, stats: dict, target: str) -> str:
    payload = {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "target": target,
        "run": {k: stats[k] for k in ("files", "chunks", "mode", "suppressed") if k in stats},
        "findings": [{**asdict(f), "rule": _rule_id(f), "end_line": f.end_line or f.line}
                     for f in findings],
    }
    return json.dumps(payload, indent=2)


def to_sarif(findings, target: str) -> str:
    rules: dict[str, dict] = {}
    results = []
    for f in findings:
        rid = _rule_id(f)
        rules.setdefault(rid, {"id": rid, "name": rid,
                               "shortDescription": {"text": f.title},
                               "properties": {"category": f.category}})
        results.append({
            "ruleId": rid,
            "level": _SARIF_LEVEL.get(f.severity, "note"),
            "message": {"text": f"{f.title}. {f.detail}".strip()},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.file},
                "region": {"startLine": max(f.line, 1), "endLine": max(f.end_line or f.line, 1)},
            }}],
            "properties": {"confidence": f.confidence, "source": f.source, "fix": f.fix},
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": TOOL_NAME, "version": TOOL_VERSION,
                                "rules": list(rules.values())}},
            "originalUriBaseIds": {"SRCROOT": {"uri": target}},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2)
