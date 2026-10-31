#!/usr/bin/env python3
"""build_impact.py - dataset for the first per-step model: finding -> impact type (+ which assert proves it).

Labels come from rules over each report's title, description and (if any) coded test, so they are noisy:
spot-check them (--show N). Input is the finding WITHOUT code blocks, like a hunter's claim before a PoC exists.
Held-out / dev contests (the PoC eval's) are the test split, so nothing leaks.

  python3 build_impact.py            # writes dataset_impact/{train,test}.jsonl + stats
  python3 build_impact.py --show 20  # also print N random labeled examples to check by eye
"""
import argparse
import json
import random
import re
from collections import Counter
from pathlib import Path

import next_finding as nf

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "dataset_impact"

from impact_rules import TEMPLATES, LABELS, SYSTEM, RULES, FROM_DESCRIPTION, strip_code, label_of  # noqa


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--show", type=int, default=0, help="print N random labeled examples for a spot check")
    args = ap.parse_args()
    held = nf.excluded_projects()
    train, test, dropped = [], [], 0
    for key, root, truth in nf.projects():
        try:
            items = nf.parse_truth(truth)
        except Exception:  # noqa
            continue
        for it in items:
            fid = str(it.get("id", ""))
            if fid[:1] not in ("H", "M"):
                continue
            title, desc = str(it.get("title", "")), str(it.get("description", "") or "")
            lab = label_of(title, desc)
            if lab is None:
                dropped += 1
                continue
            claim = f"TITLE: {title}\nSEVERITY: {it.get('severity', '')}\nDESCRIPTION: {strip_code(desc)[:3000]}"
            row = {"contest": key, "finding_id": fid, "label": lab, "variant": "impact",
                   "messages": [{"role": "system", "content": SYSTEM},
                                {"role": "user", "content": claim},
                                {"role": "assistant", "content": json.dumps({"impact": lab, "assert": TEMPLATES[lab]})}]}
            (test if nf.project_id(key) in held else train).append(row)
    OUT.mkdir(exist_ok=True)
    for name, rows in (("train.jsonl", train), ("test.jsonl", test)):
        with open(OUT / name, "w") as fh:
            for r in rows:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"[*] train {len(train)}  test {len(test)}  dropped (no rule matched) {dropped}")
    for split, rows in (("train", train), ("test", test)):
        print(f"    {split}: " + ", ".join(f"{k} {v}" for k, v in Counter(r["label"] for r in rows).most_common()))
    if args.show:
        for r in random.Random(1).sample(train, min(args.show, len(train))):
            print(f"\n[{r['label']}] {r['contest']} {r['finding_id']}: {r['messages'][1]['content'][7:160]}")


if __name__ == "__main__":
    main()
