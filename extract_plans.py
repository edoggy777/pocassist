#!/usr/bin/env python3
"""
extract_plans.py - turn verified PoCs into structured attack PLANS (no model involved).

A plan is what a hunter needs to write the PoC, without the PoC itself:
  poc_type     direct_call | malicious_contract | flash_loan | price_manipulation | dos_revert | fuzz
  actors       accounts the test acts as (vm.prank / startPrank targets)
  setup        ordered preconditions: (actor, call) pairs and cheatcode steps (time passes, funding)
  attack       the call(s) inside the ATTACK block (or, for report tests, the calls after the last setup step)
  asserts      what is checked at the end (the impact)
  functions    every protocol function the test calls

Outputs:
  dataset_poc/plans.jsonl        one plan per verified PoC NOT in the held-out contests (training labels)
  eval_set/plans_holdout.json    reference plans for the held-out findings (answer key for plan_eval.py)

  python extract_plans.py
  python extract_plans.py --show 3     # print a few plans to eyeball them
"""
import argparse
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "dataset_poc"
CHEAT = re.compile(r"^(vm|cheats|hevm|console|console2|Test|StdCheats|stdstore)$")
GETTER = re.compile(r"^(get[A-Z_]|balanceOf$|owner$|total|is[A-Z]|has[A-Z]|preview|convert|allowance$|decimals$|nonces$|"
                    r"name$|symbol$|party$|[a-z]+Of$|[a-z]+Count$|DOMAIN_SEPARATOR)")
SKIP_FN = {"assertEq", "assertTrue", "assertFalse", "assertGt", "assertGe", "assertLt", "assertLe", "assertNotEq",
           "assertApproxEqAbs", "assertApproxEqRel", "require", "log", "emit", "makeAddr", "label", "bound"}


def test_fn_body(code: str) -> str:
    m = re.search(r"function\s+test_PoC\s*\([^)]*\)[^{]*\{", code) or re.search(r"function\s+test\w*\s*\([^)]*\)[^{]*\{", code)
    if not m:
        return ""
    depth, i = 1, m.end()
    while i < len(code) and depth:
        depth += {"{": 1, "}": -1}.get(code[i], 0)
        i += 1
    return code[m.end(): i - 1]


def statements(body: str) -> list[str]:
    body = re.sub(r"/\*.*?\*/", "", body, flags=re.S)
    out, cur = [], []
    for line in body.splitlines():
        if "ATTACK-START" in line or "ATTACK-END" in line or "MALICIOUS-SETUP" in line:
            if cur:
                out.append(" ".join(cur)); cur = []
            out.append(line.strip())
            continue
        line = re.sub(r"//.*", "", line).strip()
        if not line:
            continue
        cur.append(line)
        joined = " ".join(cur)
        paren_ok = joined.count("(") <= joined.count(")")
        brace_ok = joined.count("{") == joined.count("}")
        if joined.endswith((";", "}")) and paren_ok and brace_ok:
            out.append(joined); cur = []
    if cur:
        out.append(" ".join(cur))
    return out


def calls_in(stmt: str) -> list[str]:
    """obj.fn(...) calls in a statement, skipping cheatcodes/console/asserts."""
    res = []
    for obj, fn in re.findall(r"\b([A-Za-z_]\w*(?:\[[^\]]*\])?)\s*\.\s*([A-Za-z_]\w*)\s*(?:\{[^}]*\})?\s*\(", stmt):
        base = obj.split("[")[0]
        if CHEAT.match(base) or fn in SKIP_FN or fn in ("selector", "encode", "encodeWithSelector", "encodeCall",
                                                          "encodePacked", "decode", "push", "pop", "length"):
            continue
        if fn[0].isupper():
            continue                                    # Struct(...) constructor / Contract.Type, not a call
        res.append(f"{base}.{fn}")
    return res


def poc_type(code: str, body: str) -> str:
    extra = [c for c in re.findall(r"^\s*contract\s+(\w+)", code, re.M) if not c.startswith("PoC_")]
    if re.search(r"flashLoan|flashloan|FlashLoan", body):
        return "flash_loan"
    if extra or re.search(r"\bnew\s+\w*(Malicious|Attack|Evil|Reenter|Exploit)\w*\s*\(", body):
        return "malicious_contract"
    if re.search(r"expectRevert", body):
        return "dos_revert"
    if re.search(r"\bbound\s*\(|testFuzz", code):
        return "fuzz"
    if re.search(r"setPrice|setAnswer|updatePrice|oracle\.\w*set|mockPrice", body, re.I):
        return "price_manipulation"
    return "direct_call"


def extract(code: str) -> dict:
    body = test_fn_body(code)
    actor, pranked_once = "test", None
    setup, attack, asserts, actors, functions = [], [], [], [], []
    in_attack, saw_marker = False, "ATTACK-START" in body
    for st in statements(body):
        if "ATTACK-START" in st:
            in_attack = True
            continue
        if "ATTACK-END" in st:
            in_attack = False
            continue
        if "MALICIOUS-SETUP" in st:
            continue
        m = re.search(r"(?:vm|cheats|hevm)\.(startPrank|prank)\s*\(\s*([^,;]+?)\)\s*;", st) or \
            re.search(r"(?:vm|cheats|hevm)\.(startPrank|prank)\s*\(\s*([^,)]+)", st)
        if m:
            who = m.group(2).strip()
            if who not in actors:
                actors.append(who)
            if m.group(1) == "startPrank":
                actor = who
            else:
                pranked_once = who
            continue
        if re.search(r"(?:vm|cheats|hevm)\.stopPrank", st):
            actor = "test"
            continue
        if re.search(r"\bassert\w*\s*\(", st) or (re.match(r"require\s*\(", st) and (attack or not saw_marker)):
            asserts.append(re.sub(r"\s+", " ", st))
            continue
        if re.search(r"vm\.(warp|roll|skip)\b|\bskip\s*\(", st):
            (attack if in_attack else setup).append(
                {"actor": "-", "step": re.sub(r"\s+", " ", st).strip() if FULL else "time passes"})
            continue
        if re.search(r"\b(deal|vm\.deal|hoax)\s*\(", st):
            setup.append({"actor": "-", "step": re.sub(r"\s+", " ", st).strip() if FULL else "fund account"})
            if FULL:
                continue
        cs = calls_in(st)
        if not cs:
            # full mode keeps everything else too: mocks, helper calls, declarations the later lines need
            if FULL and ("(" in st or "=" in st) and not st.strip().startswith(("//", "/*", "*")):
                (attack if in_attack else setup).append(
                    {"actor": pranked_once or actor, "step": re.sub(r"\s+", " ", st).strip()})
                pranked_once = None
            continue
        who = pranked_once or actor
        pranked_once = None
        is_decl = re.match(r"^[\w.\[\]]+(\s+(memory|storage|calldata))?\s+\w+\s*=|^\(.*\)\s*=|^\w+\s*=", st)
        added = False
        for c in cs:
            fn = c.split(".")[1]
            if is_decl and GETTER.match(fn) and not in_attack and not FULL:
                continue                                # a read for bookkeeping, not a step of the attack
            functions.append(fn)
            if FULL:
                if not added:                           # the whole statement, arguments included, once
                    (attack if in_attack else setup).append({"actor": who, "step": re.sub(r"\s+", " ", st).strip()})
                    added = True
            else:
                (attack if in_attack else setup).append({"actor": who, "step": c})
    if not saw_marker and setup:
        # report tests have no markers: treat the last protocol call before the asserts as the attack
        last = [s for s in setup if s["step"] not in ("time passes", "fund account")]
        if last:
            attack = [last[-1]]
            setup = setup[: len(setup) - 1 - setup[::-1].index(last[-1])] + setup[len(setup) - setup[::-1].index(last[-1]):]
    return {"poc_type": poc_type(code, body), "actors": actors, "setup": setup[:25], "attack": attack[:6],
            "asserts": asserts[:8], "functions": sorted(set(functions))}


FULL = False


def main():
    ap = argparse.ArgumentParser(description="Extract structured attack plans from verified PoCs")
    ap.add_argument("--show", type=int, default=0, help="Print this many plans")
    ap.add_argument("--full", action="store_true", help="Steps are whole call lines (with arguments) -> *_full.json")
    args = ap.parse_args()
    global FULL
    FULL = args.full
    rows = [json.loads(l) for l in (DATA / "pocs.jsonl").read_text().splitlines() if l.strip()]
    rows = [r for r in rows if r.get("verified")]
    held = set()
    if (DATA / "holdout_contests.txt").exists():
        held = {l.strip() for l in (DATA / "holdout_contests.txt").read_text().splitlines() if l.strip()}
    train, ref = [], {}
    for r in rows:
        plan = extract(r["poc"])
        if not plan["attack"] or not plan["functions"]:
            continue
        rec = {"contest": r["contest"], "finding_id": r["finding_id"], "title": r.get("title"), "label": r.get("label"),
               "origin": r.get("origin"), "prompt": r.get("prompt"), "claim_text_bare": r.get("claim_text_bare"),
               "claim_text": r.get("claim_text"), "plan": plan}
        if r["contest"].split("--")[0] in held:
            ref.setdefault(f"{r['contest']} {r['finding_id']}", plan)
        else:
            train.append(rec)
    with open(DATA / "plans.jsonl", "w") as fh:
        for t in train:
            fh.write(json.dumps(t, ensure_ascii=False) + "\n")
    (ROOT / "eval_set").mkdir(exist_ok=True)
    _holdout_path = ROOT / "eval_set" / ("plans_holdout_full.json" if FULL else "plans_holdout.json")
    # Guard: never shrink or wipe the holdout answer key. A truncated holdout_contests.txt
    # or a pocs.jsonl that lost its verified rows yields a smaller ref than what's on disk;
    # overwriting then silently destroys oracle plans (once wiped 37 -> {}).
    _prev = {}
    if _holdout_path.exists():
        try:
            _prev = json.loads(_holdout_path.read_text())
        except Exception:
            _prev = {}
    if len(ref) < len(_prev):
        if len(ref) == 0:
            print(f"[=] {_holdout_path.name} is FROZEN ({len(_prev)} plans); this run produced 0 "
                  f"(no verified holdout PoCs in pocs.jsonl). Kept frozen key. This is expected.")
        else:
            print(f"[!] REFUSING to overwrite {_holdout_path.name}: new set has {len(ref)} plans "
                  f"but existing file has {len(_prev)}. Existing file left untouched. "
                  f"If the shrink is intentional, delete the file first.")
    else:
        _tmp = _holdout_path.with_suffix(_holdout_path.suffix + ".tmp")
        _tmp.write_text(json.dumps(ref, indent=1))
        _tmp.replace(_holdout_path)   # atomic: never leaves a half-written answer key
    types = {}
    for t in train:
        types[t["plan"]["poc_type"]] = types.get(t["plan"]["poc_type"], 0) + 1
    print(f"[*] {len(train)} training plans -> dataset_poc/plans.jsonl   (types: {types})")
    print(f"[*] {len(ref)} reference plans for held-out findings -> eval_set/plans_holdout.json")
    for t in train[: args.show]:
        print(f"\n--- {t['contest']} {t['finding_id']}: {t['title']}")
        print(json.dumps(t["plan"], indent=1))


if __name__ == "__main__":
    main()
