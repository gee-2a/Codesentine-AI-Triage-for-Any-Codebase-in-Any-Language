# Benchmark

`python scripts/evaluate.py` scans `demo-messy-repo/` with the deterministic rules only (no LLM, no network) and compares the findings with `demo-messy-repo/expected.json`.

## Method

- Four files: two seeded-bad (`inventory.py.sample`, `helpers.js.sample`) and two clean controls (`clean_utils.py.sample`, `clean_service.js.sample`).
- 14 labeled findings. A finding counts as a hit when file, rule ID and line (within 1 line) match.
- Any other finding is a false positive, including those on the clean files, which must be zero.
- Seeded files end in `.sample` so security scanners do not report the intentional flaws; the script copies them to a temp directory without that suffix.

## Result

| TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|
| 14 | 0 | 0 | 1.00 | 1.00 | 1.00 |

## How to read this

This is a regression guard, not an accuracy claim. The labels were written by the same author who wrote the rules, after the rules existed, on 14 hand-made cases. A perfect score here says the rules still do what their authors intended; it says nothing about how they perform on real, unseen code. Proper evaluation would need independently labeled code from real projects. CI runs the script, and the test suite fails if F1 drops below 0.9 or a clean file is flagged.
