#!/usr/bin/env python3
"""purge_holdout.py - remove held-out eval findings from training files so fine-tunes never train on
the eval. Default level=contest: drop EVERY row from a holdout CONTEST (strict: model never sees a
holdout project's code/test harness). level=finding: drop only the exact (contest, finding_id) rows.
2023-10-wildcat is a DIFFERENT audit from holdout 'wildcat' and is preserved. Non-destructive: writes
<file>.nohold.jsonl.

  python purge_holdout.py --list          # preview (contest level)
  python purge_holdout.py                  # write .nohold.jsonl (contest level)
  python purge_holdout.py --finding-level  # looser: only exact eval findings

Importable: is_holdout(record, level="contest") -- harvest excludes holdout at generation time."""
import json, argparse, collections
from pathlib import Path

ROOT = Path(__file__).resolve().parent
HOLDOUT_MANIFEST = ROOT / "eval_set" / "manifest_holdout.json"

def _core(tag: str) -> str:
    return tag.replace("sherlock-", "").split("--")[0]

_hold = json.loads(HOLDOUT_MANIFEST.read_text())
HOLD_PAIRS = {(_core(t), fid) for t, e in _hold.items() for fid in e["ids"]}
HOLD_CONTESTS = {_core(t) for t in _hold}

def is_holdout(record: dict, level: str = "contest") -> bool:
    cc = _core(str(record.get("contest", "")))
    if level == "finding":
        return (cc, record.get("finding_id")) in HOLD_PAIRS
    return cc in HOLD_CONTESTS

DEFAULT_FILES = [
    "dataset_poc/pocs.jsonl", "dataset_poc/examples.jsonl", "dataset_poc/examples_all.jsonl",
    "dataset_poc/repairs.jsonl", "dataset_poc/repairs_all.jsonl",
    "dataset_poc/plans.jsonl", "dataset_poc/assist_examples.jsonl", "dataset_poc/assist_repairs.jsonl",
]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--files", nargs="+", default=DEFAULT_FILES)
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--finding-level", action="store_true", help="drop only exact eval findings (looser)")
    a = ap.parse_args()
    level = "finding" if a.finding_level else "contest"
    print(f"level={level} | {len(HOLD_CONTESTS)} holdout contests, {len(HOLD_PAIRS)} (contest,id) pairs")
    total = 0
    for fn in a.files:
        p = ROOT / fn
        if not p.exists(): print(f"  {fn}: (missing)"); continue
        rows = [json.loads(l) for l in p.read_text().splitlines() if l.strip()]
        removed = [r for r in rows if is_holdout(r, level)]
        keep = [r for r in rows if not is_holdout(r, level)]
        total += len(removed)
        print(f"  {fn}: {len(rows)} -> {len(keep)} ({'WOULD REMOVE' if a.list else 'removed'} {len(removed)})")
        if not a.list:
            p.with_suffix(".nohold.jsonl").write_text("".join(json.dumps(r) + "\n" for r in keep))
    print(f"total removed: {total}")
    print("sanity: 2023-10-wildcat is_holdout(contest)? ->", is_holdout({'contest':'2023-10-wildcat'}), "(must be False)")

if __name__ == "__main__":
    main()
