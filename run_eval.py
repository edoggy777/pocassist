#!/usr/bin/env python3
"""
run_eval.py - score PoC-writer models on the test set built by `sherlock_harvest.py --eval`.

Every finding in the test set is one whose warden's own PoC passed in this harness, so each one is
provable here. Models get only the finding description (no report PoC), like a hunter's claim.

  python run_eval.py --models poc-7b-v1 poc-7b-v3               # run (resumable) and print the table
  python run_eval.py --models poc-7b-v1 poc-7b-v3 --score-only  # just the table from existing runs
  python run_eval.py --models poc-7b-v3 --limit 20              # first 20 findings, for a quick look
  python run_eval.py --manifest eval_set/manifest_holdout.json --models qwen2.5-coder:7b poc-7b-v3h

Scores per model, plus where each finding ended (doesn't compile / missing precondition / wrong impact /
passes without the attack ...), so a change can be checked against the weakness it targets.

Scores per model:
  verified    pass, and fails with the attack removed (and the malicious setup removed)
  any pass    verified + pass_unverified + pass_no_control (setup right, proof not shown yet)
  ran         the test compiled and ran (anything except compile_error / no_test / setup_error)
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
EVAL = ROOT / "eval_set"
RUNS = ROOT / "eval_runs"
NOT_RAN = {"compile_error", "no_test", "setup_error", "no_parent_test", "not_demonstrable", None}


MANIFEST = EVAL / "manifest.json"
CONFIRMED = EVAL / "confirmed.json"     # your verdicts after reading each auto-verified PoC


def findings(limit: int | None) -> list[tuple[str, dict, str]]:
    manifest = json.loads(MANIFEST.read_text())
    out = [(tag, e, fid) for tag, e in sorted(manifest.items()) for fid in e["ids"]]
    return out[:limit] if limit else out


def run(model: str, items, args):
    by_tag = {}
    for tag, e, fid in items:
        by_tag.setdefault(tag, (e, []))[1].append(fid)
    for i, (tag, (e, ids)) in enumerate(sorted(by_tag.items()), 1):
        out = RUNS / run_name(model, args) / tag
        done = {r["id"] for r in json.loads((out / "results.json").read_text())} if (out / "results.json").exists() else set()
        todo = [f for f in ids if f not in done]
        if not todo:
            continue
        print(f"[{model}] {i}/{len(by_tag)} {tag}: {' '.join(todo)}", flush=True)
        part = out if not done else out.parent / f"{tag}+{len(done)}"
        cmd = [sys.executable, str(ROOT / "poc_loop.py"), e["project"], "--truth", e["truth"], "--only", *todo,
               "--model", model, "--samples", str(args.samples), "--tries", str(args.tries),
               "--num-ctx", "16384", "--out", str(part)] + (["--hints"] if args.hints else [])
        if args.plans:
            pf = RUNS / run_name(model, args) / f"{tag}.plans.json"
            pf.parent.mkdir(parents=True, exist_ok=True)
            pf.write_text(json.dumps(plans_for(tag, args), indent=1))
            cmd += ["--plans", str(pf)]
        part.mkdir(parents=True, exist_ok=True)
        with open(part / "loop.log", "w") as fh:
            p = subprocess.run(cmd, stdout=fh, stderr=subprocess.STDOUT, cwd=ROOT)
        if p.returncode != 0:
            print(f"    [!] poc_loop exited {p.returncode} (see {part}/loop.log)", flush=True)
        if part != out and (part / "results.json").exists():      # merge a resumed partial run into the main one
            merged = json.loads((out / "results.json").read_text()) + json.loads((part / "results.json").read_text())
            (out / "results.json").write_text(json.dumps(merged, indent=1))


FAILURE_ORDER = ["verified", "verified (unread)", "verified, read as false", "copied a project test", "attack unrelated to finding", "passes without attack",
                 "unverified pass", "missing precondition (reverts)",
                 "wrong impact (assertion fails)", "no assertion", "doesn't compile", "setup / harness", "other"]


# how far a finding got (same stages as poc_assist check): partial credit, so progress shows before proofs do
STAGE_OF_MODE = {"doesn't compile": 0, "setup / harness": 0, "other": 0,
                 "missing precondition (reverts)": 1,
                 "wrong impact (assertion fails)": 2,
                 "passes without attack": 3, "unverified pass": 3, "copied a project test": 3,
                 "attack unrelated to finding": 3, "no assertion": 3,
                 "verified": 4}     # verified: 5 if read as real, 3 if read as false, 4 while unread


def failure_mode(r: dict) -> str:
    """Why a finding ended where it did, from the loop's own record (best = furthest the model got)."""
    o = r.get("outcome")
    if o == "pass" and r.get("control") == "fail":
        return "verified"
    if o == "pass_copied_test":
        return "copied a project test"          # an existing happy-path test with markers added
    if o == "pass_irrelevant":
        return "attack unrelated to finding"    # the ATTACK block calls nothing the finding is about
    if o == "pass_no_control":
        return "passes without attack"          # asserted something true anyway: wrong property
    if o in ("pass_unverified", "pass"):
        return "unverified pass"                # no/overlapping markers, or an unmarked mock contract
    if o == "no_assert":
        return "no assertion"
    if o == "compile_error":
        return "doesn't compile"                # harness skill: names, imports, signatures
    if o in ("setup_error", "no_parent_test", "no_test", "not_demonstrable"):
        return "setup / harness"
    if o == "fail":
        ran = [t for t in r.get("tries", []) if t.get("outcome") == "fail"]
        reason = (ran[-1].get("reason") or "") if ran else ""
        if "assert" in reason.lower() or (r.get("assert_fails") and not r.get("test_reverts")):
            return "wrong impact (assertion fails)"
        return "missing precondition (reverts)"   # the attack call reverted: a condition was not set up
    return "other"


def run_name(model: str, args) -> str:
    """Folder (and table row) for one model + prompt setting, so variants never overwrite each other."""
    plans = getattr(args, "plans", None)
    return (model + ("+hints" if getattr(args, "hints", False) else "")
            + (f"+plan-{plans.replace(':', '_')}" if plans else "")
            + (f"#{args.tag}" if getattr(args, "tag", "") else ""))


def plans_for(tag: str, args) -> dict:
    """{finding id: plan} for one project: the reference plans (oracle = upper bound) or a model's plans."""
    if args.plans in ("oracle", "oracle-full"):
        refs = json.loads((EVAL / ("plans_holdout_full.json" if args.plans == "oracle-full" else "plans_holdout.json")).read_text())
        key = tag.split("--")[0]
        return {k.split(" ", 1)[1]: v for k, v in refs.items() if k.split(" ", 1)[0] == key}
    f = ROOT / "eval_runs_plans" / args.plans.replace(":", "_") / f"{tag}.json"
    return {fid: v["plan"] for fid, v in json.loads(f.read_text()).items()} if f.exists() else {}


def score(model: str, items) -> dict:
    results = {}
    for d in (RUNS / model).glob("*"):   # model = run name (model[+hints])
        if (d / "results.json").exists() and "+" not in d.name:
            for r in json.loads((d / "results.json").read_text()):
                results[(d.name, r["id"])] = r
    confirmed = json.loads(CONFIRMED.read_text()) if CONFIRMED.exists() else {}
    s = {"total": 0, "attempted": 0, "verified": 0, "any_pass": 0, "ran": 0, "compile_error": 0, "verified_ids": [],
         "confirmed": 0, "rejected": 0, "unread": [],
         "modes": {k: 0 for k in FAILURE_ORDER}, "backwards_once": 0, "progress": 0}
    for tag, _, fid in items:
        s["total"] += 1
        r = results.get((tag, fid))
        if not r:
            continue
        s["attempted"] += 1
        mode = failure_mode(r)
        st = STAGE_OF_MODE.get(mode, 0)
        if mode == "verified":
            v = confirmed.get(f"{model} {tag} {fid}")
            st = 5 if v == "real" else 3 if v == "false" else 4
            mode = "verified" if v == "real" else "verified, read as false" if v == "false" else "verified (unread)"
        s["modes"][mode] += 1
        s["progress"] += st
        s["backwards_once"] += bool(r.get("inverted_first"))
        o = r.get("outcome")
        if o == "pass" and r.get("control") == "fail":
            s["verified"] += 1
            s["verified_ids"].append(f"{tag.replace('sherlock-', '')} {fid}")
            verdict = confirmed.get(f"{model} {tag} {fid}")
            if verdict == "real":
                s["confirmed"] += 1
            elif verdict == "false":
                s["rejected"] += 1
            else:
                s["unread"].append(f"{model} {tag} {fid}  ->  {RUNS / model / tag}/PoC_{r.get('n', '?')}.t.sol")
        if o and o.startswith("pass"):
            s["any_pass"] += 1
        if o not in NOT_RAN:
            s["ran"] += 1
        if o == "compile_error":
            s["compile_error"] += 1
    return s


def main():
    ap = argparse.ArgumentParser(description="Score PoC-writer models on the provable test set")
    ap.add_argument("--models", nargs="+", required=True)
    ap.add_argument("--samples", type=int, default=3)
    ap.add_argument("--tries", type=int, default=3)
    ap.add_argument("--limit", type=int, help="Only the first N findings (quick look)")
    ap.add_argument("--score-only", action="store_true")
    ap.add_argument("--plans", help="Give the PoC writer a plan: 'oracle' (extracted from the verified PoC; upper bound) "
                                    "or a plan_eval model name (its own plans), e.g. qwen2.5-coder:7b")
    ap.add_argument("--tag", default="",
                    help="Name a repeat run (e.g. r2): scored as <model>#r2, so repeats never overwrite each other")
    ap.add_argument("--hints", action="store_true",
                    help="Run poc_loop with --hints (extracted preconditions in the prompt); scored as <model>+hints")
    ap.add_argument("--manifest", type=Path, default=EVAL / "manifest.json",
                    help="Which test set (eval_set/manifest_holdout.json from make_holdout.py)")
    args = ap.parse_args()
    global MANIFEST, RUNS
    MANIFEST = args.manifest.resolve()
    if MANIFEST.name != "manifest.json":
        RUNS = ROOT / f"eval_runs_{MANIFEST.stem.replace('manifest_', '')}"   # keep each test set's runs apart
    if not MANIFEST.exists():
        sys.exit(f"[!] no test set at {MANIFEST}")

    items = findings(args.limit)
    print(f"[*] test set: {len(items)} provable findings, {len({t for t, _, _ in items})} projects")
    if not args.score_only:
        for m in args.models:
            run(m, items, args)

    rows = [(run_name(m, args), score(run_name(m, args), items)) for m in args.models]
    lines = ["| model | attempted | **confirmed** (read) | progress (0-5) | auto-verified | any pass | test ran | compile error |",
             "|---|---|---|---|---|---|---|---|"]
    for m, s in rows:
        conf = f"**{s['confirmed']}**" + (f" ({len(s['unread'])} unread)" if s["unread"] else "")
        prog = f"{s['progress'] / s['attempted']:.2f}" if s["attempted"] else "-"
        lines.append(f"| {m} | {s['attempted']}/{s['total']} | {conf} | {prog} | {s['verified']} | {s['any_pass']} | {s['ran']} | {s['compile_error']} |")
    lines += ["", "**Where each finding ended** (the furthest the model got):", "",
              "| | " + " | ".join(m for m, _ in rows) + " |", "|---|" + "---|" * len(rows)]
    for k in FAILURE_ORDER:
        lines.append(f"| {k} | " + " | ".join(str(s["modes"][k]) for _, s in rows) + " |")
    lines.append("| *(wrote the test backwards at least once)* | " + " | ".join(str(s["backwards_once"]) for _, s in rows) + " |")
    print("\n" + "\n".join(lines))
    unread = [u for _, s in rows for u in s["unread"]]
    if unread:
        print(f"\nRead these auto-verified PoCs, then record each in {CONFIRMED} as \"real\" or \"false\":")
        for u in unread:
            print("  " + u)
        print('  e.g. {"poc-7b-v3h sherlock-2024-08-flayer--moongate H-02": "false"}')
    RUNS.mkdir(exist_ok=True)
    (RUNS / "scores.md").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
