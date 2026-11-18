"""Score CodeSentinel's deterministic rules against the seeded benchmark.

    python scripts/evaluate.py            # prints precision / recall / F1 and misses
    python scripts/evaluate.py --min-f1 0.8

The seeded files use a `.sample` suffix so security scanners do not treat the
intentional flaws as real vulnerabilities; they are copied to a temp dir without it.
Rules only (no LLM, no network), so results are deterministic.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import agent  # noqa: E402


def evaluate(bench: Path):
    spec = json.loads((bench / "expected.json").read_text(encoding="utf-8"))
    tol = spec.get("tolerance_lines", 1)
    expected = spec["expected"]
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        for f in bench.glob("*.sample"):
            shutil.copy(f, work / f.name[: -len(".sample")])
        texts = {p.name: p.read_text(encoding="utf-8") for p in work.iterdir()}
        ctx = {"local": set(), "declared": None}
        found = []
        for rel, text in texts.items():
            found += agent.static_scan(rel, text, ctx)
        found, _ = agent.apply_suppressions(agent.merge(found), texts)
    found = [f for f in found if f.rule and f.file != "<project>"]

    unmatched = list(found)
    tp, missed = 0, []
    for e in expected:
        hit = next((f for f in unmatched if f.file == e["file"] and f.rule == e["rule"]
                    and abs(f.line - e["line"]) <= tol), None)
        if hit:
            unmatched.remove(hit)
            tp += 1
        else:
            missed.append(e)
    # anything left that is not a labeled finding is a false positive
    # (marker-density etc. count too: the benchmark is strict on purpose)
    fp = unmatched
    precision = tp / (tp + len(fp)) if tp + len(fp) else 0.0
    recall = tp / len(expected) if expected else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    clean_fp = [f for f in fp if f.file in spec.get("clean_files", [])]
    return {"tp": tp, "fp": len(fp), "fn": len(missed), "precision": precision, "recall": recall,
            "f1": f1, "missed": missed, "false_positives": fp, "clean_file_fp": len(clean_fp)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bench", default=str(ROOT / "demo-messy-repo"))
    ap.add_argument("--min-f1", type=float, default=0.0)
    args = ap.parse_args()
    r = evaluate(Path(args.bench))
    print(f"TP={r['tp']} FP={r['fp']} FN={r['fn']}  "
          f"precision={r['precision']:.2f} recall={r['recall']:.2f} F1={r['f1']:.2f}  "
          f"false positives on clean files={r['clean_file_fp']}")
    for m in r["missed"]:
        print(f"  MISSED  {m['file']}:{m['line']} {m['rule']}")
    for f in r["false_positives"]:
        print(f"  EXTRA   {f.file}:{f.line} {f.rule} {f.title}")
    return 0 if r["f1"] >= args.min_f1 and r["clean_file_fp"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
