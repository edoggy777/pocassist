#!/usr/bin/env python3
"""
poc_assist.py - a PoC assistant for bug hunters: the model does the tedious part, you write the attack,
forge decides.

  start   claim -> attack plan + a test file that compiles, on the right parent test, in the project
  check   your edited test -> forge, plus the "attack removed" controls -> a plain verdict

  python poc_assist.py start ~/targets/proto --claims claims.json --id 1
  python poc_assist.py check ~/targets/proto test/PoC_1.t.sol --claims claims.json --id 1

start
  1. finds the source of the claim and the project test whose setUp() deploys what you need (parent)
  2. asks the model for an attack PLAN: accounts, setup calls in order, the attack call, what to assert
  3. asks the model for a DRAFT test that follows the plan, and fixes compile errors (no model needed for
     most: missing accounts/imports/private helpers) until it compiles. If it can't, you get a compiling
     skeleton with the plan written in as comments instead.
  4. runs the draft once and tells you where it stands (passes / reverts at X / assertion fails)
  The test file is written NEXT TO the parent test (its imports are relative), with a <name>.plan.md beside it.

check  (run it after every edit; it never changes your file unless you pass --fix)
  compile error   -> each error, its line, and what to use instead (+ --fix applies the automatic fixes)
  test fails      -> the revert reason, a hint for common reverts, the trace around it
  test passes     -> re-runs WITHOUT the ATTACK block (and without the MALICIOUS-SETUP block, if any).
                     PROVED only if those fail; plus warnings for a copied project test, an attack that
                     calls nothing the claim is about, a test written backwards, no assertion.

Claims file: the same claims.json as poc_loop.py (title, severity, contract, function, description).
--id is the 1-based position in the file, or the entry's "id". Or test on a published report with
--truth <report> --id H-01.
"""
import argparse
import json
import os
import re
import shutil
import sys
import time
from pathlib import Path

import poc_loop as pl
from audit_assist import DEFAULT_MODEL, check_backend, llm_call
from eval_audit import parse_truth
from plan_eval import SYSTEM as PLAN_SYSTEM, normalize_plan, parse_json

NEVER = "__poc_assist_never_matches__"      # load_project must not delete the hunter's PoC files


# ---------------------------------------------------------------- claims

def load_claim(args) -> dict:
    if args.truth:
        items = parse_truth(Path(args.truth))
    elif args.claims:
        data = json.loads(Path(args.claims).read_text())
        items = data if isinstance(data, list) else [data]
    else:
        return {}
    if not items:
        sys.exit("[!] no claims in the file")
    if args.id is None:
        if len(items) > 1:
            sys.exit("[!] the file has several claims: pick one with --id (1, 2, ... or its id)\n"
                     + "\n".join(f"    {i}. {c.get('id', '')} {str(c.get('title', ''))[:80]}" for i, c in enumerate(items, 1)))
        return items[0]
    for c in items:
        if str(c.get("id")) == str(args.id):
            return c
    if str(args.id).isdigit() and 1 <= int(args.id) <= len(items):
        return items[int(args.id) - 1]
    sys.exit(f"[!] no claim with id {args.id}")


OUTBUF: list[str] = []          # everything check/start printed: the feedback text saved with each session step


def say(msg=""):
    OUTBUF.append(str(msg))
    print(msg, flush=True)


# ---------------------------------------------------------------- sessions (training data)
# Every start/check is saved under sessions/<project>/<test name>/ so each bug you work on becomes training
# data: the prompt, the model's draft, every version you checked with forge's verdict, and the proved test.
# export_sessions.py turns them into rows for train_lora.py. They stay on this computer.

import impact_rules as bi
CURRENT_IMPACT = ""      # "dos: how to prove it" for the skeleton of the current start

SESS_ROOT = Path(os.environ.get("POC_ASSIST_SESSIONS", Path(__file__).resolve().parent / "sessions"))
STAGES = [("PROVED (mechanically)", 5), ("PASSES THE CONTROLS, BUT", 4), ("NOT PROVED", 3), ("NOT CHECKED", 3),
          ("an assertion fails", 2), ("reverts before", 1), ("it reverts:", 1), ("passes (not checked", 3),
          ("NOT YET", 0)]


def session_dir(root: Path, poc: Path) -> Path:
    return SESS_ROOT / "_".join(root.parts[-2:]) / poc.name.removesuffix(".t.sol")


def stage_of(text: str) -> int:
    """How far a check got: 0 doesn't compile/run .. 1 reverts .. 2 assertion fails .. 3 passes but not proved ..
    4 passes the controls with warnings .. 5 proved."""
    for key, st in STAGES:
        if key in text:
            return st
    return 0


def contest_key(args, root: Path) -> str:
    """Same key the dataset uses, so held-out contests stay out of training (train_lora --exclude-contests)."""
    return Path(args.truth).stem if getattr(args, "truth", None) else "assist-" + "_".join(root.parts[-2:])


def log_step(sdir: Path, code: str, feedback: str, kind: str):
    sdir.mkdir(parents=True, exist_ok=True)
    events = sdir / "events.jsonl"
    lines = events.read_text().splitlines() if events.exists() else []
    if lines:                                    # same file, same verdict as last time: nothing new to learn
        last = json.loads(lines[-1])
        if (sdir / last["file"]).read_text() == code and last["stage"] == stage_of(feedback):
            return
    n = len(lines)
    (sdir / f"v{n:03d}.t.sol").write_text(code)
    with events.open("a") as fh:
        fh.write(json.dumps({"n": n, "kind": kind, "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                             "stage": stage_of(feedback), "file": f"v{n:03d}.t.sol",
                             "feedback": feedback[-5000:]}) + "\n")


def own_funds_roundtrip(code: str) -> list:
    """Asserts that check exactly an amount which the test itself put in before the attack AND the attack
    takes out again: someone getting their own funds back (normal use), not damage."""
    s, e = code.find("ATTACK-START"), code.find("ATTACK-END")
    b = code.find("function test_PoC")
    if min(s, e, b) < 0:
        return []
    norm = lambda x: re.sub(r"[\s_]", "", x)
    lit = r"[0-9][0-9_]*(?:\s*\*\s*[0-9e_.]+)?(?:\s*(?:ether|gwei|wei))?"
    def amounts(txt):
        return {norm(a) for a in re.findall(r"[(,]\s*(" + lit + r")\s*(?=[,)])", txt)} - {"0", "1"}
    before, attack, after = code[b:s], code[s:e], code[e:]
    common_in = amounts(before) & amounts(attack)
    hits = []
    for m in re.finditer(r"\b(assert\w*)\s*\(([^;]*)\);", after):
        used = {norm(x) for x in re.findall(lit, m.group(2))} & common_in
        if used:
            hits.append(f"{m.group(1)}(... {sorted(used)[0]} ...)")
    return hits


def writer_prompt_for(args, root: Path, test_dir, files, poc: Path, code: str, claim: dict) -> dict:
    """The writer prompt `start` would have built for this claim, without calling a model: so a PoC written by
    hand (no `start`) still becomes a training row. Parent = the one the PoC actually inherits, if listed."""
    max_src = getattr(args, "max_src", None) or 12000
    src, claim_fns, src_files, source_block, parents = pl.prepare_item(claim, root, test_dir, files, max_src)
    if not parents:
        return {}
    m = re.search(r"\bcontract\s+PoC_\w+\s+is\s+([\w\s,]+)\{", code)
    bases = [b.strip() for b in m.group(1).split(",")] if m else []
    parent = next((p for p in parents if p[2] in bases), None)
    standalone = parent is None
    parent = parent or parents[0]
    hints = pl.precondition_hints((root / src).read_text(errors="ignore"), claim_fns) if src else ""
    n = poc.stem.removeprefix("PoC_")
    user2, *_ = pl.build_prompt(n, claim, root, test_dir, src, claim_fns, src_files, source_block, parent, False,
                                hints=hints)
    if standalone:
        user2 = (user2.split("// ===== SKELETON")[0] + "// ===== SKELETON (standalone: the parent's state is not "
                 "usable from a child, so write a self-contained test contract that deploys what it needs)\n")
    return {"prompt": user2, "system": pl.SYSTEM, "source": str(src) if src else None,
            "parent": "standalone" if standalone else f"{parent[1].relative_to(root)}::{parent[2]}",
            "prompt_built_by": "check"}


def ensure_session(sdir: Path, args, root: Path, poc: Path, test_dir=None, files=None, code: str = ""):
    """A check on a test that never went through `start` (hand-written PoC): write session.json, and if it has
    no prompt yet, build the one `start` would have used, so next_finding sees the finding as done and
    export_sessions can turn it into training data."""
    meta = json.loads((sdir / "session.json").read_text()) if (sdir / "session.json").exists() else None
    if meta and meta.get("prompt"):
        return
    claim = {}
    try:
        claim = load_claim(args) or {}
    except (Exception, SystemExit):            # no claim given: still record the session
        pass
    try:
        rel = str(poc.resolve().relative_to(root.resolve()))
    except ValueError:
        rel = str(poc)
    if meta is None:
        meta = {"contest": contest_key(args, root), "finding_id": claim.get("id") or getattr(args, "id", None),
                "title": claim.get("title"), "project": str(root), "poc": rel, "parent": None, "source": None,
                "model": "hand-written", "planner": None, "plan": None,
                "started": time.strftime("%Y-%m-%d %H:%M:%S"), "started_by": "check"}
    if claim and test_dir is not None and files is not None and code:
        try:
            meta.update(writer_prompt_for(args, root, test_dir, files, poc, code, claim))
        except Exception as e:  # noqa - never let prompt building break a check
            say(f"[!] couldn't build a training prompt for this session ({type(e).__name__}: {e}); it is logged anyway")
    sdir.mkdir(parents=True, exist_ok=True)
    (sdir / "session.json").write_text(json.dumps(meta, indent=1))


# ---------------------------------------------------------------- start

def skeleton_with_plan(skeleton: str, plan: dict, hints: str) -> str:
    """The bare skeleton, with the plan as TODO comments where the code goes. Always compiles."""
    lines = ["        // PLAN (written by the model: check every step against the code)"]
    for i, st in enumerate(plan.get("setup", []) or [], 1):
        lines.append(f"        // setup {i}: " + (f"as {st.get('actor')}: " if st.get("actor") not in ("-", "?", None) else "")
                     + safe_comment(str(st.get("step"))))
    lines.append("        // (if the attack needs a hostile contract or crafted input, wrap ITS setup lines in")
    lines.append("        //  a malicious-setup block: the two marker comments, as in the ATTACK block below)")
    lines.append("        // record the state you will assert on BEFORE the attack (balances, shares, debt)")
    lines.append("")
    lines.append("        // ATTACK-START")
    for st in plan.get("attack", []) or []:
        lines.append(f"        // TODO " + (f"as {st.get('actor')}: " if st.get("actor") not in ("-", "?", None) else "")
                     + safe_comment(str(st.get("step"))))
    lines.append("        // ATTACK-END")
    lines.append("")
    if CURRENT_IMPACT:
        lines.append(f"        // HOW TO PROVE ({safe_comment(CURRENT_IMPACT)[:300]})")
    a = plan.get("assert") or "; ".join(plan.get("asserts") or [])
    lines.append(f"        // TODO assert: {safe_comment(a) if a else 'the damage (attacker gained / victim lost / funds stuck)'}")
    body = "\n".join(lines)
    out = skeleton.replace("        // TODO\n", body + "\n")
    if hints:
        out = out.replace("contract PoC_", "/* WHAT THE CODE REQUIRES on the path to the bug (extracted, no model):\n"
                          + safe_comment(hints) + "\n*/\ncontract PoC_", 1)
    return out


def safe_comment(text: str) -> str:
    """Text for a comment in the test file: never the marker words (check would cut there) or a comment end."""
    return (text.replace("*/", "* /").replace("// ATTACK-START ... // ATTACK-END", "the ATTACK block")
            .replace("ATTACK-START", "attack start").replace("ATTACK-END", "attack end")
            .replace("MALICIOUS-SETUP-START", "malicious setup start").replace("MALICIOUS-SETUP-END", "malicious setup end"))


VM_MINI = """/// Foundry cheatcodes, declared by hand (this project's test base has no `vm`)
interface Vm {
    function prank(address) external;
    function startPrank(address) external;
    function stopPrank() external;
    function warp(uint256) external;
    function roll(uint256) external;
    function deal(address, uint256) external;
    function expectRevert() external;
    function expectRevert(bytes calldata) external;
    function expectRevert(bytes4) external;
    function label(address, string calldata) external;
}
"""


def needs_standalone(parent) -> str:
    """Why inheriting this parent gives the PoC nothing to work with ('' = inheriting is fine)."""
    _, ppath, pname, pragma, imports, text, s, e, bases = parent
    fam = text[s:e] + "".join(b[0][b[1]:b[2]] for b in bases)
    hdr = re.search(rf"contract\s+{re.escape(pname)}\s+is\s+([^{{]*)\{{", text)
    base_names = hdr.group(1) if hdr else ""
    has_vm = bool(re.search(r"\bvm\s*\.", fam) or re.search(r"\b(Test|StdCheats|PRBTest|CommonBase)\b", base_names))
    acc, priv, _ = pl.parent_vars(pl.parent_context(text, s, e, limit=10 ** 6))
    if not has_vm:
        return "its test base has no `vm` cheatcodes (plain DSTest)"
    if priv and not acc:
        return "all its variables are private, so a PoC that inherits it can't use them"
    # the state setUp() builds is what the PoC needs: if most of THAT is private, inheriting gives nothing usable
    m = re.search(r"\bfunction\s+setUp\s*\([^)]*\)[^{]*\{", fam)
    if m and priv:
        body = fam[m.end(): m.end() + 8000]
        nxt = re.search(r"\n\s*function\s", body)
        body = body[:nxt.start()] if nxt else body
        name = lambda v: str(v).split()[-1].strip(";")
        assigned = lambda v: re.search(rf"\b{re.escape(name(v))}\b\s*(=[^=]|\.|\[)", body)
        p_set = [name(v) for v in priv if assigned(v)]
        local = lambda v: re.search(rf"\b[\w.\[\]]+\s+(?:memory\s+|storage\s+)?{re.escape(name(v))}\s*[=;]", body)
        a_set = [name(v) for v in acc if assigned(v) and not local(v)]   # locals declared in setUp are not state
        if p_set and len(p_set) >= len(a_set):
            return (f"the state its setUp() builds is private ({', '.join(p_set[:4])}), "
                    "so a PoC that inherits it can't use it")
    return ""


def standalone_skeleton(n: str, parent, root: Path, poc_dir: Path) -> str:
    """The parent's state variables, setUp and helpers COPIED into the PoC (private -> internal), plus `vm`
    if the base lacks it: everything inheriting would have given, but usable."""
    _, ppath, pname, pragma, imports, text, s, e, bases = parent
    body = text[s:e]
    out, cut = [], 0
    for name, fs, fe in pl._functions(body):
        if name.lower().startswith("test") and name != "setUp":
            out.append(body[cut:fs])
            cut = fe
    out.append(body[cut:])
    body = re.sub(r"\bprivate\b", "internal", "".join(out))
    body = re.sub(r"\n{3,}", "\n\n", body).rstrip()
    hdr = re.search(rf"contract\s+{re.escape(pname)}\s*(is\s+[^{{]*)?\{{", text)
    is_part = (hdr.group(1) or "").strip() if hdr else ""
    vm_decl, vm_import = "", ""
    if needs_standalone(parent).startswith("its test base has no"):
        fs_vm = root / "lib" / "forge-std" / "src" / "Vm.sol"
        if fs_vm.exists():
            vm_import = f'import {{Vm}} from "{os.path.relpath(fs_vm, poc_dir)}";\n'
        else:
            vm_import = "\n" + VM_MINI
        vm_decl = '    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));\n'
    return (f"// SPDX-License-Identifier: UNLICENSED\n{pragma}\n\n" + "\n".join(imports) + "\n" + vm_import
            + f"\n// standalone: {pname}'s setup copied in ({ppath.name}), because inheriting it gives nothing usable\n"
            + f"contract PoC_{n} {is_part} {{\n" + vm_decl
            + f"    // ----- copied from {pname} -----{body}\n    // ----- end of copy -----\n\n"
            + "    function test_PoC() public {\n        // TODO\n    }\n}\n").replace(f"contract PoC_{n}  {{", f"contract PoC_{n} {{")


def test_copies(root: Path, src: Path | None, test_dir: Path) -> list[str]:
    """Contracts of the audited source file that the TEST folder redefines (a test copy, like TestCooler.sol):
    a PoC on the project's tests may then exercise the copy, not the audited code."""
    if not src:
        return []
    names = re.findall(r"^\s*(?:abstract\s+)?contract\s+(\w+)", (root / src).read_text(errors="ignore"), re.M)
    hits = []
    for nm in names:
        for d in pl.SYMBOLS.get(nm, []):
            if d["kind"] == "contract" and d["file"] != str(src) and pl.is_test_path(Path(d["file"]), test_dir):
                hits.append(f"{nm} (also defined in {d['file']})")
    return hits


def plan_header(plan: dict) -> str:
    return "/* ATTACK PLAN (from the model; verify it):\n" + safe_comment(pl.plan_text(plan)) + "\n*/\n"


def compile_until_ok(code: str, poc: Path, root: Path, args, user: str, acc_vars, priv_vars, api) -> tuple[str, int, str]:
    """Automatic repairs, then up to --fix-rounds model rounds that only fix compile errors.
    Returns (code, rc, forge output) of the version with the fewest compile errors."""
    best = None
    for rnd in range(args.fix_rounds + 1):
        poc.write_text(code)
        rc, out = pl.run_forge(root, poc, args.timeout)
        for _ in range(4):
            if pl.classify(rc, out) != "compile_error":
                break
            rep = pl.auto_repair(code, out, root, poc.parent)
            if not rep:
                break
            poc.write_text(rep)
            rc2, out2 = pl.run_forge(root, poc, args.timeout)
            if pl.classify(rc2, out2) != "compile_error" or len(pl.errors_at(out2)) < len(pl.errors_at(out)):
                code, rc, out = rep, rc2, out2
            else:
                break
        n_err = len(pl.errors_at(out)) if pl.classify(rc, out) == "compile_error" else 0
        if best is None or n_err < best[0]:
            best = (n_err, code, rc, out)
        if n_err == 0:
            break
        if rnd < args.fix_rounds:
            say(f"    compile errors: {n_err}, asking the model to fix them (round {rnd + 1}/{args.fix_rounds})")
            prompt = (user + "\n\n" + pl.FIX.format(error=pl.compile_errors(out, code, acc_vars, priv_vars, api))
                      + "\n\nYOUR PREVIOUS FILE:\n" + code)
            code = pl.strip_fences(llm_call(args.backend, pl.SYSTEM, prompt, args.model, args.num_ctx,
                                            args.ollama_host, json_mode=False))
    _, code, rc, out = best
    return code, rc, out


def status_line(rc: int, out: str, code: str) -> str:
    o = pl.classify(rc, out)
    if o == "compile_error":
        return f"does not compile ({len(pl.errors_at(out))} errors)"
    if o == "setup_error":
        return "the parent's setUp() fails here (fork URL / env var?): try another parent with --parent"
    if o == "no_test":
        return "compiles, but there is no test_PoC()"
    if o == "pass":
        return "compiles and PASSES (run `check` to see whether it proves anything)"
    r = pl.fail_reason(out)
    if r and "assert" in r.lower():
        return f"compiles and runs; an assertion fails: {r[:150]}"
    return f"compiles and runs; it reverts: {r[:150] or '(see the trace with check)'}"


def cmd_start(args):
    root = args.repo.resolve()
    claim = load_claim(args)
    if not claim:
        sys.exit("[!] give the claim with --claims claims.json (or --truth <report>)")
    check_backend(args.backend, args.ollama_host, args.model)
    src_dir, test_dir, files = pl.load_project(root, leftover_glob=NEVER)
    say(f"[*] claim: {claim.get('title', '')}")
    say("[*] building the project (the first build can take minutes) ...")
    rc, out = pl.sh(["forge", "build"], root, args.timeout)
    if rc != 0:
        sys.exit("[!] the project doesn't build yet; fix that first:\n" + out[-1500:])
    miss = pl.missing_rpc(root)
    if miss:
        say(f"[!] this project's tests fork a live chain and read {', '.join(miss)}: add them to {pl.RPC_ENV_FILE} "
            "(KEY=url, an ARCHIVE RPC if the tests pin an old block). Until then setUp() will fail.")

    if args.source and not (root / args.source).is_file():
        sys.exit(f"[!] --source {args.source}: no such file in the project")
    src, claim_fns, src_files, source_block, parents = pl.prepare_item(claim, root, test_dir, files, args.max_src,
                                                                       src_override=args.source)
    if not parents:
        sys.exit("[!] no project test with a setUp() found to build on")
    if args.parent_file:
        pf, _, pn = args.parent_file.partition("::")
        match = [p for p in parents if p[1].resolve() == (root / pf).resolve() and (not pn or p[2] == pn)]
        if not match:
            sys.exit(f"[!] --parent-file {args.parent_file}: no test contract with its own or an inherited setUp() there")
        parents = match + [p for p in parents if all(p is not m for m in match)]
        args.parent = 1
    say(f"[*] source: {src or '?'}   functions in the claim: {', '.join(sorted(claim_fns)) or '?'}")
    say("[*] parent test candidates (the PoC inherits its setUp):")
    for i, p in enumerate(parents[:3], 1):
        say(f"    {i}. {p[1].relative_to(root)} :: {p[2]}" + ("   <- using" if i == args.parent else ""))
    if args.parent > len(parents):
        sys.exit(f"[!] only {len(parents)} candidate(s)")
    parent = parents[args.parent - 1]
    ppath = parent[1]
    if src:
        stem = Path(str(src)).stem
        fam = parent[5] + "".join(b[0] for b in parent[8])
        # a concrete contract only: abstract bases (wfCashLogic) are deployed through the contracts that inherit them
        is_contract = re.search(rf"(?<!abstract )\bcontract\s+{re.escape(stem)}\b", (root / src).read_text(errors="ignore"))
        if is_contract and not re.search(rf"\b{re.escape(stem)}\b", fam):
            base = re.sub(r"V\d+$", "", stem)
            other = base != stem and re.search(rf"\b{re.escape(base)}\b", fam)
            say(f"[!] warning: the parent never mentions {stem}"
                + (f" but uses {base} (a different version)" if other else "")
                + ": its setUp likely doesn't deploy the contract under test. "
                  "Deploy it in the PoC, or pick another parent with --parent-file")
    n = args.name.removeprefix("PoC_").removesuffix(".t.sol")
    if not re.fullmatch(r"\w+", n):
        sys.exit("[!] --name must be letters, digits and _ only (e.g. PoC_pauseBypass)")
    poc = ppath.parent / f"PoC_{n}.t.sol"
    if poc.exists() and not args.force:
        sys.exit(f"[!] {poc.relative_to(root)} exists (your work?). Use another --name, or --force to overwrite")

    standalone = needs_standalone(parent)
    if standalone:
        say(f"[*] standalone test: {standalone}. Copying {parent[2]}'s setup into the PoC instead of inheriting it")
    copies = test_copies(root, src, test_dir)
    if copies:
        say("[!] WARNING: the project's tests define their own copy of the audited contract: " + "; ".join(copies)
            + ". Make sure your PoC deploys the REAL one from " + str(src) + " (import it by name).")

    hints = pl.precondition_hints((root / src).read_text(errors="ignore"), claim_fns) if src else ""
    global CURRENT_IMPACT
    impact = bi.label_of(str(claim.get("title", "")), str(claim.get("description", "") or ""))
    impact_text = (f"\n\n// ===== IMPACT TYPE (rule-based, from the claim's wording; verify it): {impact}\n"
                   f"// How a PoC proves this kind of impact: {bi.TEMPLATES[impact]}\n") if impact else ""
    CURRENT_IMPACT = f"{impact}: {bi.TEMPLATES[impact]}" if impact else ""
    if impact:
        say(f"[*] impact type: {impact} (from the claim's wording)")
    user, skeleton, pctx, acc_vars, priv_vars, related = pl.build_prompt(
        n, claim, root, test_dir, src, claim_fns, src_files, source_block, parent, False, hints=hints)
    api = pl.api_index(root, src_files)

    # 1. plan
    say(f"[*] planning with {args.planner} ...")
    plan_prompt = user.split("// ===== SKELETON")[0] + "\nWrite the JSON plan now."
    plan = {}
    for _ in range(2):                          # one retry if the answer isn't usable JSON
        plan = normalize_plan(parse_json(llm_call(args.backend, PLAN_SYSTEM, plan_prompt, args.planner, args.num_ctx,
                                                  args.ollama_host, json_mode=False)))
        if plan.get("attack") or plan.get("setup"):
            break
    if not (plan.get("attack") or plan.get("setup")):
        say("    [!] the model gave no usable plan; continuing without one")
        plan = {}
    else:
        say("\n" + "\n".join("    " + l for l in pl.plan_text(plan).splitlines()) + "\n")

    # 2. draft that follows the plan, fixed until it compiles
    code, rc, out, draft = None, 1, "", ""
    user2, *_ = pl.build_prompt(n, claim, root, test_dir, src, claim_fns, src_files, source_block, parent,
                                False, hints=hints, plan=plan or None)
    if standalone:
        skeleton = standalone_skeleton(n, parent, root, poc.parent)
        user2 = (user2.split("// ===== SKELETON")[0] + "// ===== SKELETON (standalone: the parent's setup is copied "
                 "in; fill in test_PoC, keep the rest) =====\n" + skeleton)
    try:
        if not args.no_draft and not standalone:      # the model only knows how to write inheriting drafts
            say(f"[*] drafting the test with {args.model} ...")
            draft = pl.strip_fences(llm_call(args.backend, pl.SYSTEM, user2, args.model, args.num_ctx,
                                             args.ollama_host, json_mode=False))
            if draft.lstrip().startswith("// NOT_DEMONSTRABLE"):
                say(f"    the model thinks this can't be shown in a unit test: {draft.strip()[:200]}")
            else:
                code, rc, out = compile_until_ok(draft, poc, root, args, user2, acc_vars, priv_vars, api)
        if code is None or pl.classify(rc, out) == "compile_error":
            if code is not None:
                say(f"    [!] the draft still doesn't compile: keeping it as PoC_{n}.draft.txt (for reference) "
                    "and writing a compiling skeleton")
                (poc.parent / f"PoC_{n}.draft.txt").write_text(code)     # .txt: forge must not compile it
            code = skeleton_with_plan(skeleton, plan, hints)
            poc.write_text(code)
            rc, out = pl.run_forge(root, poc, args.timeout)
            if pl.classify(rc, out) == "compile_error":
                rep = pl.auto_repair(code, out, root, poc.parent)
                if rep:
                    code = rep
                    poc.write_text(code)
                    rc, out = pl.run_forge(root, poc, args.timeout)
        if plan and "ATTACK PLAN" not in code:
            hdr = plan_header(plan).rstrip("\n")
            code = re.sub(r"\ncontract PoC_", lambda m: "\n" + hdr + m.group(0), code, count=1)
            poc.write_text(code)
    except KeyboardInterrupt:
        if code:
            poc.write_text(code)
        raise

    # 3. notes
    notes = poc.parent / f"PoC_{n}.plan.md"
    rel_poc = poc.relative_to(root)
    claim_arg = f"--truth {args.truth}" if args.truth else (f"--claims {args.claims}" if args.claims else "")
    id_arg = f" --id {args.id}" if args.id is not None else ""
    notes.write_text(
        f"# {claim.get('title', '')}\n\n"
        f"Test file: `{rel_poc}`  \nParent: `{ppath.relative_to(root)} :: {parent[2]}`  \nSource: `{src}`\n\n"
        + (f"**Standalone test:** {standalone}; the parent's setup is copied into the PoC.\n\n" if standalone else "")
        + (f"**WARNING:** the tests define their own copy of the audited contract ({'; '.join(copies)}). "
           f"Deploy the real one from `{src}`.\n\n" if copies else "")
        + f"## Plan (model; verify)\n\n```\n{pl.plan_text(plan) if plan else '(none)'}\n```\n\n"
        f"## What the code requires (extracted)\n\n```\n{hints or '(nothing found)'}\n```\n\n"
        f"## Project tests that call these functions (copy their setup steps)\n\n"
        + "\n".join(f"- {l[9:].strip()}" for l in related.splitlines() if l.startswith("// ----- ")) + "\n\n"
        f"## Status\n\n{status_line(rc, out, code)}\n\n"
        f"## Check it\n\n```\npython poc_assist.py check {root} {rel_poc} {claim_arg}{id_arg}\n```\n")

    if not args.no_log:
        sdir = session_dir(root, poc)
        if sdir.exists():                        # a fresh start on the same test name: keep the old session
            sdir.rename(sdir.with_name(sdir.name + time.strftime("-%Y%m%d-%H%M%S")))
        sdir.mkdir(parents=True)
        (sdir / "session.json").write_text(json.dumps({
            "contest": contest_key(args, root), "finding_id": claim.get("id") or args.id, "title": claim.get("title"),
            "project": str(root), "poc": str(rel_poc), "parent": f"{ppath.relative_to(root)}::{parent[2]}",
            "source": str(src), "model": args.model, "planner": args.planner, "plan": plan,
            "plan_prompt": plan_prompt, "prompt": user2, "system": pl.SYSTEM, "draft_raw": draft,
            "standalone": standalone, "test_copies": copies,
            "started": time.strftime("%Y-%m-%d %H:%M:%S")}, indent=1))
        fb = status_line(rc, out, code)
        o = pl.classify(rc, out)
        fb = ("NOT YET: " + fb + ("\n" + pl.failure_trace(out) if o == "fail" else "")
              + ("\n" + pl.compile_errors(out, code, n=8) if o == "compile_error" else ""))
        if o == "pass":
            fb = "NOT YET: compiles and runs, but nothing is checked yet (no attack / assertion written)"
        log_step(sdir, code, fb, "start")

    say(f"\n[*] test:   {rel_poc}")
    say(f"[*] notes:  {notes.relative_to(root)}")
    say(f"[*] status: {status_line(rc, out, code)}")
    say(f"\nEdit the test (the ATTACK-START/END block is yours), then after each edit:\n"
        f"  python poc_assist.py check {root} {rel_poc} {claim_arg}{id_arg}")


# ---------------------------------------------------------------- check

def inverted(code: str) -> bool:
    """Written backwards = expects the ATTACKER's call to be blocked. An expectRevert AFTER the attack block
    (the victim's call now reverts: a DoS proof) is fine; so is anything when there are no markers yet
    (then fall back to the loop's stricter check)."""
    m = re.search(r"ATTACK-START(.*?)ATTACK-END", code, re.S)
    if not m:
        return pl.looks_inverted(code)
    before_and_attack = pl.test_body(code[: m.end()])
    after = code[m.end():]
    return bool(re.search(r"expectRevert|\btry\s+\w[\w.]*\s*\.\s*\w+\s*\(", before_and_attack)) or \
        pl.looks_inverted("function test_PoC() {" + re.sub(r"expectRevert|\btry\b", "", after))

def cmd_check(args):
    root = args.repo.resolve()
    poc = (args.poc if args.poc.is_absolute() else (root / args.poc if (root / args.poc).exists() else args.poc.resolve())).resolve()
    if not poc.exists():
        sys.exit(f"[!] {poc} not found")
    try:
        poc.relative_to(root)
    except ValueError:
        sys.exit(f"[!] the test must be inside the project ({root})")
    original = poc.read_text()
    code = original
    claim = load_claim(args)
    src_dir, test_dir, files = pl.load_project(root, leftover_glob=NEVER)
    m = re.search(r"\bcontract\s+PoC_\w+\s+is\s+(\w+)", code)
    pl.CURRENT_PARENT = m.group(1) if m else ""
    if "function test_PoC" not in code:
        sys.exit("[!] the test function must be named exactly test_PoC (that is what check runs)")

    say(f"[*] forge test {poc.relative_to(root)} ...")
    rc, out = pl.run_forge(root, poc, args.timeout)
    o = pl.classify(rc, out)
    verdict = None
    try:
        if o == "compile_error" and args.fix:
            for _ in range(4):
                rep = pl.auto_repair(code, out, root, poc.parent)
                if not rep:
                    break
                poc.write_text(rep)
                rc2, out2 = pl.run_forge(root, poc, args.timeout)
                if pl.classify(rc2, out2) != "compile_error" or len(pl.errors_at(out2)) < len(pl.errors_at(out)):
                    code, rc, out, o = rep, rc2, out2, pl.classify(rc2, out2)
                    original = code                      # keep the fixes: --fix means "write them"
                    say("    applied automatic fixes (accounts / imports / private helpers)")
                else:
                    poc.write_text(code)
                    break
        if o == "compile_error":
            api = pl.api_index(root, [f for f in files if not pl.is_test_path(f, test_dir)])
            say("\nNOT YET: it does not compile.\n")
            msg = pl.compile_errors(out, code, api=api, n=8)
            if re.search(r"`makeAddr` does not exist", msg):    # old forge-std (before makeAddr existed)
                msg = re.sub(r"fix: `makeAddr` does not exist[^\n]*",
                             "fix: this project's forge-std is too old for makeAddr: use a fixed address instead, "
                             "e.g. `address attacker = address(0xBAD);`", msg)
            say(msg)
            if not args.fix:
                say("\n(try --fix: it adds missing accounts/imports and copies private parent helpers automatically)")
            return
        if o == "setup_error":
            say(f"\nNOT YET: the parent's setUp() fails: {pl.fail_reason(out, 'setUp')}\n"
                "Usually a fork RPC URL or env var the project needs; or start over on another parent (--parent 2).")
            miss = pl.missing_rpc(root)
            if miss:
                say(f"This project reads {', '.join(miss)}, which you haven't set: add them to {pl.RPC_ENV_FILE}")
            return
        if o == "no_test":
            say("\nNOT YET: forge found no test_PoC() in this file.")
            return
        if o == "fail":
            r = pl.fail_reason(out)
            if inverted(code):
                say("\nNOTE: the test looks written BACKWARDS (it expects the attack to be blocked). An exploit test "
                    "must pass when the bug exists.")
            if r and "assert" in r.lower():
                say(f"\nNOT YET: the test runs to the end, but an assertion fails:\n  {r}\n"
                    "Either the attack didn't have the effect you expect, or you assert the wrong value/contract "
                    "(e.g. shares vs assets). Trace:\n")
            else:
                h = pl.revert_hint(r)
                say(f"\nNOT YET: the test reverts before your assertions: {r or '(see trace)'}\n"
                    + (f"What this usually means: {h}\n" if h else "")
                    + "A precondition isn't met yet (role, approval, balance, time, state). Trace around the revert:\n")
            say(pl.failure_trace(out))
            return

        # passes: now the controls
        if inverted(code):
            verdict = "NOT PROVED: it passes, but it expects the attacker's call to be BLOCKED (expectRevert on or " \
                      "before the attack / 'unchanged'). That tests that the code is safe, the opposite of the claim. " \
                      "(For a DoS, put the expectRevert on the VICTIM's call AFTER the ATTACK block.)"
            return
        m_end = re.search(r"ATTACK-END", code)
        victim_reverts = bool(m_end and re.search(r"expectRevert", code[m_end.end():]))   # DoS proof
        if not pl.HAS_ASSERT.search(code) and not victim_reverts:
            verdict = "NOT PROVED: it passes, but asserts nothing. Add assertions on the damage."
            return
        stray = [i + 1 for i, l in enumerate(code.splitlines())
                 if re.search(r"(ATTACK|MALICIOUS-SETUP)-(START|END)", l)
                 and not re.fullmatch(r"\s*//\s*(ATTACK|MALICIOUS-SETUP)-(START|END)\b.*", l)]
        if stray:
            verdict = (f"NOT CHECKED: line(s) {', '.join(map(str, stray))} mention ATTACK-START/END (or MALICIOUS-SETUP) "
                       "outside a marker line, e.g. in a comment. Each marker must be its own line `// ATTACK-START`; "
                       "reword or delete the others.")
            return
        ctrl = pl.control_version(code)
        if ctrl is None:
            verdict = ("NOT CHECKED: it passes, but there are no // ATTACK-START / // ATTACK-END lines around the "
                       "attacker's call, so I can't re-run it without the attack. Add them and check again.")
            return
        if pl.markers_nested(code):
            verdict = "NOT CHECKED: the MALICIOUS-SETUP block contains the ATTACK block; make them separate."
            return
        say("[*] passes. Re-running WITHOUT the ATTACK block ...")
        poc.write_text(ctrl)
        crc, cout = pl.run_forge(root, poc, args.timeout)
        c = pl.classify(crc, cout)
        why = pl.fail_reason(cout) if c == "fail" else ""
        if c == "pass":
            verdict = ("NOT PROVED: it ALSO passes without the attack. What you assert is true anyway, so it says "
                       "nothing about the bug. Assert something that only the attack causes (compare before/after).")
            return
        if c == "compile_error":
            verdict = ("NOT CHECKED: without the ATTACK block the test doesn't compile (a variable declared inside the "
                       "block is used later?). Declare variables BEFORE // ATTACK-START.")
            return
        ctrl2 = pl.control_version(code, "MALICIOUS-SETUP")
        if ctrl2 is not None:
            say("[*] re-running WITHOUT the MALICIOUS-SETUP block ...")
            poc.write_text(ctrl2)
            c2 = pl.classify(*pl.run_forge(root, poc, args.timeout))
            if c2 == "pass":
                verdict = ("NOT PROVED: it also passes without the MALICIOUS-SETUP block, so the hostile piece "
                           "isn't what causes the damage.")
                return
        warnings, notes = [], []
        own_mocks = pl.project_mocks(root)
        if ctrl2 is None and pl.needs_setup_markers(code, allowed=own_mocks):
            warnings.append("it deploys a mock/malicious contract without MALICIOUS-SETUP markers: wrap that setup "
                            "so it gets knocked out too")
        used_own = sorted(n for n in set(re.findall(r"\bnew\s+(\w+)\s*\(", code)) if n in own_mocks and pl.MOCKISH.search(n))
        if used_own:
            notes.append(f"uses the project's own test mocks ({', '.join(used_own)}): normal setup, but check none of "
                         "them replaces the contract under test (e.g. code etched over it)")
        for a in pl.readback_asserts(code):
            warnings.append(f"{a} only reads back a value the ATTACK block passed in: true for any normal call. "
                            "Assert the damage instead (a balance, a limit broken, a state that shouldn't be possible)")
        for a in own_funds_roundtrip(code):
            warnings.append(f"{a}: the attack takes out the same amount the test put in earlier, and the assert "
                            "checks exactly that amount came back. That is normal use (getting your own funds back), "
                            "not damage. Assert what the bug breaks: a victim's loss, funds that can't be withdrawn, "
                            "or getting out MORE than was put in")
        sim, twin = pl.copied_project_test(code, root, test_dir)
        if sim >= pl.COPY_THRESHOLD:
            warnings.append(f"it is {sim:.0%} the same as the project's own test {twin}: a normal-use test with markers "
                            "added proves nothing; the attack must be the abnormal step")
        if claim:
            src = pl.find_source(root, files, claim)
            fns = pl.claim_functions((root / src).read_text(errors="ignore"), claim) if src else set()
            calls = pl.called_functions(pl.attack_block(code))
            wanted = {f.lstrip("_") for f in fns} | pl.claim_idents(claim)
            m_end = re.search(r"ATTACK-END", code)
            after = pl.called_functions(code[m_end.end():]) if m_end else set()
            if fns and not (calls & wanted):
                if after & wanted:
                    # e.g. time passes / a state change in the block, then the VICTIM's call to the claimed
                    # function breaks: a valid shape for 'funds stuck later' bugs
                    notes.append(f"the ATTACK block only calls {', '.join(sorted(calls)) or 'nothing'}; the claimed "
                                 f"function ({', '.join(sorted(after & wanted))}) is called after it. Fine if the block "
                                 "is something that happens anyway (time passing) or an attacker can do")
                else:
                    warnings.append(f"the ATTACK block calls {', '.join(sorted(calls)) or 'nothing'}, none of which "
                                    f"the claim is about ({', '.join(sorted(fns))})")
        # control failed only because nothing changed: "5 >= 5" shows that the attack did SOMETHING,
        # not that it did the claimed damage (e.g. it only undid part of its own earlier step)
        m_eq = None
        for ln in (why or "").splitlines():
            m_eq = re.search(r"(-?\d+|0x[0-9a-fA-F]+)(?:\s*\[[^\]]*\])?\s*(==|!=|>=|<=|>|<)\s*"
                             r"(-?\d+|0x[0-9a-fA-F]+)(?:\s*\[[^\]]*\])?\s*$", ln.strip())
            if m_eq:
                break
        if m_eq and m_eq.group(1) == m_eq.group(3):
            warnings.append(f"without the attack both sides of the assertion are equal ({m_eq.group(0)}): nothing "
                            "changed. That shows the attack changed something, not that it did the claimed damage. "
                            "Compare against the state BEFORE the victim/other party acted (their original value or "
                            "balance), not against a value from just before the attack")
        if warnings:
            verdict = "PASSES THE CONTROLS, BUT:\n" + "\n".join(f"  - {w}" for w in warnings)
        else:
            verdict = ("PROVED (mechanically): passes with the attack, fails without it"
                       + (f".\nWithout the attack it fails with: {why[:200]}\n"
                          "Make sure THAT is the reason you expect (your assertion / the expected revert not "
                          "happening), not some unrelated step reverting" if why else "")
                       + (", and fails without the malicious setup" if ctrl2 is not None else "") + ".\n"
                       "Now read it once as a judge would: is the asserted damage really the claimed impact, "
                       "and is every step something an attacker could do (no admin powers, no vm.store on the target)?"
                       + "".join(f"\nNote: {n}" for n in notes))
    finally:
        poc.write_text(original)                 # controls never leave your file changed
        if verdict:
            say("\n" + verdict)
        if not args.no_log:
            text = "\n".join(OUTBUF)
            feedback = text.split(" ...\n", 1)[-1].strip()      # drop the "[*] forge test <file> ..." line
            sdir = session_dir(root, poc)
            ensure_session(sdir, args, root, poc, test_dir=test_dir, files=files, code=code)
            log_step(sdir, code, feedback, "check")
            if stage_of(feedback) == 5:
                say(f"\n[*] saved to {sdir} (training data: python export_sessions.py)")


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description="PoC assistant: plan + compiling draft, then forge-checked verdicts",
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--claims", help="claims.json (same format as poc_loop.py)")
    common.add_argument("--truth", help="a published report instead (to try it on known bugs)")
    common.add_argument("--id", help="which claim: 1-based position, or its id (e.g. H-01)")
    common.add_argument("--timeout", type=int, default=600)
    common.add_argument("--no-log", action="store_true", help="don't save this session for training")

    s = sub.add_parser("start", parents=[common], help="plan + draft test for a claim")
    s.add_argument("repo", type=Path, help="the Foundry project (folder with foundry.toml)")
    s.add_argument("--model", help="writes the draft (default: qwen2.5-coder:7b)")
    s.add_argument("--planner", help="writes the plan (default: same as --model)")
    s.add_argument("--name", default="PoC_1", help="test file/contract name (default PoC_1)")
    s.add_argument("--parent", type=int, default=1, help="which parent candidate to build on (1-3)")
    s.add_argument("--source", help="source file of the bug, relative to the project (overrides the automatic pick)")
    s.add_argument("--parent-file", help="parent test file relative to the project, optionally ::Contract "
                                         "(overrides --parent; any test with a setUp)")
    s.add_argument("--no-draft", action="store_true", help="just the plan + a compiling skeleton")
    s.add_argument("--fix-rounds", type=int, default=2, help="model rounds to fix compile errors in the draft")
    s.add_argument("--force", action="store_true", help="overwrite an existing test file of that name")
    s.add_argument("--backend", default="ollama")
    s.add_argument("--ollama-host", default="http://localhost:11434")
    s.add_argument("--num-ctx", type=int, default=16384)
    s.add_argument("--max-src", type=int, default=14000)

    c = sub.add_parser("check", parents=[common], help="forge + controls on your edited test")
    c.add_argument("repo", type=Path)
    c.add_argument("poc", type=Path, help="the test file (path inside the project)")
    c.add_argument("--fix", action="store_true", help="apply automatic compile fixes to the file")

    args = ap.parse_args()
    if not shutil.which("forge"):
        sys.exit("[!] forge not found: curl -L https://foundry.paradigm.xyz | bash && foundryup")
    if not (args.repo.resolve() / "foundry.toml").exists():
        sys.exit(f"[!] {args.repo} has no foundry.toml")
    if args.cmd == "start":
        args.model = args.model or "qwen2.5-coder:7b"
        args.planner = args.planner or args.model
        cmd_start(args)
    else:
        cmd_check(args)


if __name__ == "__main__":
    main()
