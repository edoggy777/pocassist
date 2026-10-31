#!/usr/bin/env python3
"""
export_sessions.py - turn poc_assist sessions (sessions/<project>/<test>/) into training rows.

Each session you worked to PROVED gives:
  assisted_verified   prompt (claim + parent + plan) -> your final proved test
                      (the plan/requirements comments the tool added are stripped)
and every step where a check got FURTHER than the one before gives:
  assisted_repair     prompt + forge's verdict + the file you checked -> your next version
                      (how to fix "reverts with LOCKER_NOT_FOUND": the skill the model lacks)

Outputs (same format as gen_pocs.py, so train_lora.py reads them):
  dataset_poc/assist_examples.jsonl     label assisted_verified, variant bare
  dataset_poc/assist_repairs.jsonl      label assisted_repair, variant repair
  --merge also writes dataset_poc/examples_all.jsonl and repairs_all.jsonl (old data + these)

Sessions on held-out test contests are exported too but marked; train_lora.py --exclude-contests drops them,
so practising on the test set never leaks into training.

  python export_sessions.py
  python export_sessions.py --merge
"""
import argparse
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "dataset_poc"
STAGE_NAME = {0: "doesn't compile", 1: "reverts", 2: "assertion fails", 3: "passes, not proved", 4: "controls + warnings",
              5: "PROVED"}


def project_id(contest: str) -> str:
    return contest.split("+")[0].split("--")[0]


def clean(code: str) -> str:
    """The test as a model should write it: without the assistant's plan / requirements comment blocks."""
    code = re.sub(r"/\* (ATTACK PLAN|WHAT THE CODE REQUIRES).*?\*/\n?", "", code, flags=re.S)
    return code.strip() + "\n"


def load(sdir: Path):
    meta = json.loads((sdir / "session.json").read_text()) if (sdir / "session.json").exists() else None
    ev = [json.loads(l) for l in (sdir / "events.jsonl").read_text().splitlines() if l.strip()] \
        if (sdir / "events.jsonl").exists() else []
    for e in ev:
        f = sdir / e["file"]
        e["code"] = f.read_text(errors="ignore") if f.exists() else ""
    return meta, ev


def error_of(fb: str) -> str:
    """The revert reason / failing assertion that check reported for this step."""
    m = re.search(r"(?:reverts before your assertions|it reverts|an assertion fails):?\s*\n?\s*([^\n]+)", fb)
    return m.group(1).strip()[:150] if m else ""


def n_compile_errors(fb: str) -> int:
    return len(re.findall(r"(?m)^\s*(?:Error|error)\b", fb))


def progressed(a: dict, b: dict) -> bool:
    """A fix step worth learning from: the test got further (higher stage), or it stayed at the same stage but
    the error it hit is gone and a different, later one shows (fixed one precondition, met the next),
    or it still doesn't compile but with fewer errors."""
    if b["stage"] > a["stage"]:
        return True
    if b["stage"] != a["stage"]:
        return False
    if a["stage"] in (1, 2):
        ea, eb = error_of(a["feedback"]), error_of(b["feedback"])
        return bool(ea) and ea != eb and ea not in b["feedback"]
    if a["stage"] == 0:
        return 0 < n_compile_errors(b["feedback"]) < n_compile_errors(a["feedback"])
    return False


def main():
    ap = argparse.ArgumentParser(description="poc_assist sessions -> training rows")
    ap.add_argument("--sessions", type=Path, default=ROOT / "sessions")
    ap.add_argument("--merge", action="store_true", help="also write examples_all.jsonl / repairs_all.jsonl")
    args = ap.parse_args()
    held = set()
    if (DATA / "holdout_contests.txt").exists():
        held = {project_id(l.strip()) for l in (DATA / "holdout_contests.txt").read_text().splitlines() if l.strip()}

    examples, repairs, report = [], [], []
    for sfile in sorted(args.sessions.glob("*/*/session.json")):
        sdir = sfile.parent
        meta, ev = load(sdir)
        if not meta or not ev or not meta.get("prompt"):
            continue
        base = {"contest": meta["contest"], "finding_id": meta.get("finding_id"), "origin": "assist",
                "title": meta.get("title"), "session": str(sdir.relative_to(args.sessions))}
        system = meta.get("system", "")
        proved = [e for e in ev if e["stage"] == 5]
        if proved:
            examples.append({**base, "variant": "bare", "label": "assisted_verified", "verified": True,
                             "messages": [{"role": "system", "content": system},
                                          {"role": "user", "content": meta["prompt"]},
                                          {"role": "assistant", "content": clean(proved[-1]["code"])}]})
        n_rep = 0
        for a, b in zip(ev, ev[1:]):
            if progressed(a, b) and clean(a["code"]) != clean(b["code"]):
                user = (meta["prompt"] + "\n\nRESULT OF RUNNING YOUR FILE (forge + attack-removed control):\n"
                        + a["feedback"] + "\n\nFix it and output the COMPLETE file.\n\nYOUR PREVIOUS FILE:\n" + clean(a["code"]))
                repairs.append({**base, "variant": "repair", "label": "assisted_repair",
                                "from_stage": a["stage"], "next_stage": b["stage"],
                                "messages": [{"role": "system", "content": system},
                                             {"role": "user", "content": user},
                                             {"role": "assistant", "content": clean(b["code"])}]})
                n_rep += 1
        path = " -> ".join(STAGE_NAME[e["stage"]] for e in ev)
        report.append((base["session"], bool(proved), n_rep, project_id(meta["contest"]) in held, path))

    DATA.mkdir(exist_ok=True)
    for name, rows in (("assist_examples.jsonl", examples), ("assist_repairs.jsonl", repairs)):
        with open(DATA / name, "w") as fh:
            for r in rows:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    if args.merge:
        for old, new, rows in (("examples.jsonl", "examples_all.jsonl", examples),
                               ("repairs.jsonl", "repairs_all.jsonl", repairs)):
            prev = (DATA / old).read_text() if (DATA / old).exists() else ""
            (DATA / new).write_text(prev + "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows))

    print(f"{'session':55} proved  repair pairs  held-out  path")
    for sess, pr, nr, h, path in report:
        print(f"{sess[:55]:55} {'yes' if pr else 'no ':6}  {nr:12}  {'YES' if h else '   ':8}  {path}")
    n_held = sum(1 for r in report if r[3])
    print(f"\n[*] {len(examples)} proved PoCs -> dataset_poc/assist_examples.jsonl")
    print(f"[*] {len(repairs)} repair steps -> dataset_poc/assist_repairs.jsonl")
    if n_held:
        print(f"[*] {n_held} session(s) are on held-out test contests: train_lora.py --exclude-contests drops them")
    if args.merge:
        print("[*] merged: dataset_poc/examples_all.jsonl, dataset_poc/repairs_all.jsonl")
        print("    train with: --jsonl dataset_poc/examples_all.jsonl --repairs dataset_poc/repairs_all.jsonl "
              "--labels control_verified,report_test_passes,assisted_verified")


if __name__ == "__main__":
    main()
