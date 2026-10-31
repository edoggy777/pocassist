#!/usr/bin/env python3
"""
plan_eval.py - ask a model for an attack PLAN (not a PoC) and score it against the plan extracted from
a verified PoC of the same finding (extract_plans.py -> eval_set/plans_holdout.json).

The model sees the same context as the PoC loop (finding description without any report PoC, the parent
test, related tests, project API, source, optionally extracted preconditions) and answers with JSON:
  {"poc_type": ..., "actors": [...], "setup": [{"actor":..., "step": "contract.function"}], "attack": [...],
   "assert": "what to check"}

Scores per finding (no model judge; string matching against the verified plan):
  attack hit     the plan's attack calls the same function the verified PoC attacks with
  setup recall   share of the verified PoC's setup functions the plan also names
  order          longest common subsequence of function calls / length of the verified sequence
  type match     same poc_type
  real names     share of the plan's functions that exist in the project's API (no invented functions)

  python plan_eval.py --models qwen2.5-coder:7b qwen3-coder:30b
  python plan_eval.py --models qwen2.5-coder:7b --hints
  python plan_eval.py --models qwen2.5-coder:7b qwen3-coder:30b --score-only
  python plan_eval.py --models baseline:title          # no model: functions named in the finding title
"""
import argparse
import json
import re
import sys
from pathlib import Path

from audit_assist import llm_call
from eval_audit import parse_truth
from poc_loop import api_index, build_prompt, load_project, precondition_hints, prepare_item

ROOT = Path(__file__).resolve().parent
EVAL = ROOT / "eval_set"

SYSTEM = """You are a senior smart-contract security researcher. You are given a claimed vulnerability and the
project's own test harness and source. Do NOT write a test. Write the PLAN a researcher would follow to prove
the claim with a Foundry test on top of the given parent test: which accounts act, the exact sequence of
calls that puts the protocol into the vulnerable state, the attack call(s), and what to assert to show the
impact. Use only contract variables and functions that exist in the given parent test and API.

Answer with JSON only:
{"poc_type": "direct_call" | "malicious_contract" | "flash_loan" | "price_manipulation" | "dos_revert" | "fuzz",
 "actors": ["names of the accounts that act (as in the parent test, or new ones like attacker)"],
 "setup": [{"actor": "who calls (or '-' for time passing / funding)", "step": "contractVariable.function"}],
 "attack": [{"actor": "...", "step": "contractVariable.function"}],
 "assert": "the condition that holds only because of the bug (e.g. attacker balance after > before)"}"""


def fn_name(step: str) -> str:
    """'phiFactory.createArt(signedData, sig)' -> 'createArt' (arguments and call syntax dropped)."""
    if not step:
        return ""
    head = step.split("(")[0].split("{")[0].strip()
    return head.split(".")[-1].strip()


def lcs(a: list[str], b: list[str]) -> int:
    dp = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a)):
        for j in range(len(b)):
            dp[i + 1][j + 1] = dp[i][j] + 1 if a[i] == b[j] else max(dp[i][j + 1], dp[i + 1][j])
    return dp[-1][-1]


def score_plan(plan: dict, ref: dict, api_names: set[str]) -> dict:
    steps = lambda key, p: [fn_name(s.get("step", "")) for s in p.get(key, []) if isinstance(s, dict)
                            and s.get("step") not in ("time passes", "fund account")]
    ref_attack, ref_setup = set(steps("attack", ref)), set(steps("setup", ref))
    m_attack, m_setup = steps("attack", plan), steps("setup", plan)
    m_all = m_setup + m_attack
    ref_seq = steps("setup", ref) + steps("attack", ref)
    return {
        "attack_hit": bool(ref_attack & set(m_attack)),
        "setup_recall": (len(ref_setup & set(m_all)) / len(ref_setup)) if ref_setup else (1.0 if m_all else 0.0),
        "order": (lcs(ref_seq, m_all) / len(ref_seq)) if ref_seq else 0.0,
        "type_match": plan.get("poc_type") == ref.get("poc_type"),
        "real_names": (sum(1 for f in m_all if f in api_names) / len(m_all)) if m_all else 0.0,
    }


def normalize_plan(p) -> dict:
    """Accept the shapes small models actually produce: nested under "plan", steps as plain strings,
    "steps"/"attack_steps"/"calls" keys, step objects keyed call/function/action instead of step."""
    if isinstance(p, list):
        p = {"setup": p[:-1], "attack": p[-1:]}
    if not isinstance(p, dict):
        return {}
    for k in ("plan", "attack_plan", "result"):
        if isinstance(p.get(k), dict):
            p = p[k]
    def steps(v):
        out = []
        for s in v if isinstance(v, list) else ([v] if v else []):
            if isinstance(s, str):
                m = re.match(r"\s*(?:(\w+)\s*[:-]\s*)?([\w.]+)", s)
                out.append({"actor": (m.group(1) if m and m.group(1) else "?"), "step": m.group(2) if m else s})
            elif isinstance(s, dict):
                st = s.get("step") or s.get("call") or s.get("function") or s.get("action") or ""
                out.append({"actor": s.get("actor") or s.get("caller") or s.get("from") or "?", "step": str(st)})
        return out
    return {"poc_type": p.get("poc_type") or p.get("type"),
            "actors": p.get("actors") or [],
            "setup": steps(p.get("setup") or p.get("steps") or p.get("preconditions") or []),
            "attack": steps(p.get("attack") or p.get("attack_steps") or p.get("exploit") or []),
            "assert": p.get("assert") or p.get("assertion") or p.get("check") or ""}


def parse_json(text: str) -> dict:
    try:
        return json.loads(text)
    except Exception:  # noqa
        m = re.search(r"\{.*\}", text or "", re.S)
        try:
            return json.loads(m.group(0)) if m else {}
        except Exception:  # noqa
            return {}


def run(model: str, args, manifest: dict, refs: dict):
    tag_name = model + ("+hints" if args.hints else "")
    outdir = ROOT / "eval_runs_plans" / tag_name.replace(":", "_")
    outdir.mkdir(parents=True, exist_ok=True)
    for tag, e in sorted(manifest.items()):
        key_contest = tag.split("--")[0]
        ids = [i for i in e["ids"] if f"{key_contest} {i}" in refs]
        out = outdir / f"{tag}.json"
        done = json.loads(out.read_text()) if out.exists() else {}
        todo = [i for i in ids if i not in done]
        if not todo:
            continue
        root = Path(e["project"])
        src_dir, test_dir, files = load_project(root, leftover_glob="PoC_*.t.sol")
        api = api_index(root, files)
        items = {t["id"]: t for t in parse_truth(Path(e["truth"]))}
        for fid in todo:
            item = items.get(fid)
            if not item:
                continue
            src, claim_fns, src_files, source_block, parents = prepare_item(item, root, test_dir, files, 14000)
            if not parents:
                continue
            hints = precondition_hints((root / src).read_text(errors="ignore"), claim_fns) if (args.hints and src) else ""
            user, *_ = build_prompt(1, item, root, test_dir, src, claim_fns, src_files, source_block, parents[0],
                                    False, hints=hints)
            user = user.split("// ===== SKELETON")[0] + "\nWrite the JSON plan now."
            ref = refs[f"{key_contest} {fid}"]
            api_names = {re.match(r"(\w+)", sig).group(1) for sigs in api.values() for sig in sigs}
            if model == "baseline:title":
                # no model: attack = every real function the finding's TITLE names (what "attack hit" gets for free)
                named = [w for w in re.findall(r"\b([A-Za-z_]\w+)\b", str(item.get("title", ""))) if w in api_names]
                resp, plan = "", {"poc_type": "direct_call", "setup": [],
                                  "attack": [{"actor": "?", "step": w} for w in dict.fromkeys(named)]}
            else:
                # no forced JSON mode: it made small models collapse into empty output earlier in this project
                resp = llm_call("ollama", SYSTEM, user, model, 16384, "http://localhost:11434", json_mode=False)
                plan = normalize_plan(parse_json(resp))
            done[fid] = {"plan": plan, "raw": (resp or "")[:3000], "score": score_plan(plan, ref, api_names),
                         "empty": not (plan.get("setup") or plan.get("attack")), "parent": parents[0][2]}
            out.write_text(json.dumps(done, indent=1))
            sc = done[fid]["score"]
            print(f"[{tag_name}] {tag} {fid}: attack {'HIT ' if sc['attack_hit'] else 'miss'} "
                  f"setup {sc['setup_recall']:.0%} order {sc['order']:.0%} names {sc['real_names']:.0%}", flush=True)


def rescore(models: list[str], args, manifest: dict, refs: dict):
    """Recompute every saved plan's score with the current scorer (no model calls)."""
    api_cache = {}
    for m in models:
        d = ROOT / "eval_runs_plans" / (m + ("+hints" if args.hints else "")).replace(":", "_")
        for f in d.glob("*.json") if d.exists() else []:
            tag = f.stem
            e = manifest.get(tag)
            if not e:
                continue
            if tag not in api_cache:
                root = Path(e["project"])
                _, _, files = load_project(root, leftover_glob="__none__")
                api_cache[tag] = {re.match(r"(\w+)", sig).group(1) for sigs in api_index(root, files).values() for sig in sigs}
            data = json.loads(f.read_text())
            for fid, v in data.items():
                ref = refs.get(f"{tag.split('--')[0]} {fid}")
                if ref:
                    v["plan"] = normalize_plan(v["plan"]) if v.get("plan") else v["plan"]
                    v["score"] = score_plan(v["plan"], ref, api_cache[tag])
            f.write_text(json.dumps(data, indent=1))


def table(models: list[str], args):
    rows = []
    for m in models:
        tag_name = m + ("+hints" if args.hints else "")
        d = ROOT / "eval_runs_plans" / tag_name.replace(":", "_")
        vals = [v for f in d.glob("*.json") for v in json.loads(f.read_text()).values()] if d.exists() else []
        scores = [v["score"] for v in vals]
        empties = sum(1 for v in vals if v.get("empty", not (v["plan"].get("setup") or v["plan"].get("attack"))))
        n = len(scores) or 1
        rows.append((tag_name, len(scores), sum(s["attack_hit"] for s in scores),
                     sum(s["setup_recall"] for s in scores) / n, sum(s["order"] for s in scores) / n,
                     sum(s["type_match"] for s in scores), sum(s["real_names"] for s in scores) / n,
                     sum(1 for s in scores if s["attack_hit"] and s["setup_recall"] >= 0.3), empties))
    print("\n| model | findings | empty/unparsed plans | attack hit | setup recall | order | type match | real names | **good plan** (attack hit + a third of the setup) |")
    print("|---|---|---|---|---|---|---|---|---|")
    for r in rows:
        print(f"| {r[0]} | {r[1]} | {r[8]} | {r[2]} | {r[3]:.0%} | {r[4]:.0%} | {r[5]} | {r[6]:.0%} | **{r[7]}** |")


def main():
    ap = argparse.ArgumentParser(description="Score attack plans against verified PoC plans")
    ap.add_argument("--models", nargs="+", required=True)
    ap.add_argument("--hints", action="store_true")
    ap.add_argument("--score-only", action="store_true")
    args = ap.parse_args()
    manifest = json.loads((EVAL / "manifest_holdout.json").read_text())
    refs = json.loads((EVAL / "plans_holdout.json").read_text())
    if not args.score_only:
        for m in args.models:
            run(m, args, manifest, refs)
    else:
        rescore(args.models, args, manifest, refs)
    table(args.models, args)


if __name__ == "__main__":
    main()
