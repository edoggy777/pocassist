#!/usr/bin/env python3
"""
next_finding.py - pick the next finding to work on with poc_assist, and start it.

Looks at every built Foundry contest you have (Code4rena contests/ + Sherlock sherlock/) with a report,
skips the held-out test contests (and the dev test set), skips findings you already have a session for,
and picks one. By default it prefers findings whose report has a warden PoC (so it IS provable, and you
can compare afterwards) that are NOT already in the training data (so the session adds something new).

  python next_finding.py                 # suggest 5, best first, with the command for each
  python next_finding.py --go            # start the best one right away
  python next_finding.py --contest ethena --go
  python next_finding.py --list 30       # more suggestions
  python next_finding.py --random --go   # a random one instead of the best
"""
import re
import os
import argparse
import json
import random
import subprocess
import sys
from pathlib import Path

from eval_audit import parse_truth
from gen_pocs import project_of_run
from poc_loop import report_code_blocks
from setup_contests import CONTEST_DIR, load_catalog

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "dataset_poc"
SESS = ROOT / "sessions"


def project_id(c: str) -> str:
    return str(c).split("+")[0].split("--")[0]


def excluded_projects() -> set[str]:
    out = set()
    f = DATA / "holdout_contests.txt"
    if f.exists():
        out |= {project_id(l.strip()) for l in f.read_text().splitlines() if l.strip()}
    for m in (ROOT / "eval_set").glob("manifest*.json"):          # holdout + dev test sets
        out |= {project_id(t) for t in json.loads(m.read_text())}
    return out


def projects() -> list[tuple[str, Path, Path]]:
    """(contest key, project root, report) for every built Foundry project with a report."""
    out = []
    status = json.loads((DATA / "build_status.json").read_text()) if (DATA / "build_status.json").exists() else {}
    try:
        cat = load_catalog()
    except Exception:  # noqa
        cat = {}
    for name, e in sorted(cat.items()):
        root = CONTEST_DIR / name
        if e.get("truth") and (root / "foundry.toml").exists() and status.get(name, {}).get("ok", True):
            out.append((name, root, ROOT / e["truth"]))
    for f in sorted((ROOT / "sherlock").glob("sherlock-*.json")):
        r = project_of_run(Path(f.stem))
        if r and r[0] and (r[0] / "foundry.toml").exists():
            out.append((f.stem, r[0], f))
    return out


FORK = ("createSelectFork", "createFork(", "selectFork(", "rpcUrl(", "vm.rpcUrl", "ETH_RPC_URL", "MAINNET_RPC",
        "FORK_URL", "RPC_URL", "vm.envString(")
SKIP_DIRS = {"lib", "node_modules", "out", "cache", ".git", "artifacts", "broadcast"}


def test_sol_files(root: Path, limit: int = 600):
    """Test .sol files anywhere in the project: test*/ folders at any depth (test/, contracts/tests/,
    src/**/tests/) and any *.t.sol file. Skips dependency and build folders without walking into them."""
    n = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.endswith(".sol")]
        rel = Path(dirpath).relative_to(root).parts
        in_test_dir = any(part.lower().startswith("test") for part in rel)
        for name in filenames:
            if name.endswith(".sol") and (in_test_dir or name.endswith(".t.sol")):
                yield Path(dirpath) / name
                n += 1
                if n >= limit:
                    return


# findings that are hard to prove mechanically: missing features ("doesn't distribute rewards"), and impacts that
# hinge on economics (donation / inflation). Not "missing check" or "front-run": those prove fine.
WEAK_TITLE = re.compile(r"(doesn'?t|does not|never|won'?t)\s+(distribut|claim|accru|pay|refund|forward|collect)"
                        r"|\bno (way|mechanism|method|function|ability) to\b|\black of (?:slippage|deadline|incentive|transparency|notification|minimum|safety|burn)|\bdonation\b"
                        r"|\binflation attack\b|\bfirst deposit", re.I)


try:
    import poc_loop as _pl
except Exception:  # noqa
    _pl = None


_HARNESS: dict[str, bool] = {}


def has_harness(root: Path) -> bool:
    """Any Foundry test with a setUp() to build on? (projects tested only with Hardhat have none:
    poc_assist start can't do anything there, so don't pick them)"""
    key = str(root)
    if key not in _HARNESS:
        _HARNESS[key] = False
        for f in test_sol_files(root):
            try:
                if re.search(r"\bfunction\s+setUp\s*\(", f.read_text(errors="ignore")):
                    _HARNESS[key] = True
                    break
            except OSError:
                continue
    return _HARNESS[key]


def needs_rpc(root: Path) -> bool:
    """Tests that run on a live-chain fork need an RPC URL (and are slow): rank those last."""
    toml = (root / "foundry.toml").read_text(errors="ignore") if (root / "foundry.toml").exists() else ""
    if "eth_rpc_url" in toml or "fork_url" in toml:
        return True
    for f in test_sol_files(root):
        try:
            txt = f.read_text(errors="ignore")
        except OSError:
            continue
        if any(k in txt for k in FORK):
            return True
    return False


def main():
    ap = argparse.ArgumentParser(description="Pick the next finding for poc_assist")
    ap.add_argument("--go", action="store_true", help="run poc_assist start on the pick")
    ap.add_argument("--contest", help="only contests whose name contains this")
    ap.add_argument("--list", type=int, default=5, help="how many suggestions to show")
    ap.add_argument("--random", action="store_true", help="random order instead of best first")
    ap.add_argument("--model", help="passed to poc_assist start")
    ap.add_argument("--planner", help="passed to poc_assist start")
    args = ap.parse_args()

    skip = excluded_projects()
    done = set()
    for s in SESS.glob("*/*/session.json"):
        m = json.loads(s.read_text())
        done.add((project_id(m.get("contest")), str(m.get("finding_id"))))
    in_data = set()
    if (DATA / "pocs.jsonl").exists():
        for l in (DATA / "pocs.jsonl").read_text().splitlines():
            if l.strip():
                r = json.loads(l)
                if r.get("verified"):
                    in_data.add((project_id(r["contest"]), str(r["finding_id"])))

    cands, n_proj = [], 0
    for key, root, truth in projects():
        if project_id(key) in skip or (args.contest and args.contest not in key):
            continue
        try:
            items = parse_truth(truth)
        except Exception:  # noqa
            continue
        n_proj += 1
        if not has_harness(root):
            continue                             # no Foundry test with a setUp(): nothing for start to build on
        fork = needs_rpc(root)
        if fork and _pl is not None and _pl.rpc_needs(root) and not _pl.missing_rpc(root):
            fork = False                         # forks, but you've provided every RPC it reads (rpc.env)
        for it in items:
            fid = str(it.get("id", ""))
            if not fid[:1] in ("H", "M") or (project_id(key), fid) in done:
                continue
            # a CODED test, not just a pasted snippet of the source (burve H-07 had only NoopVault's code)
            has_poc = any(re.search(r"\bfunction\s+test\w*\s*\(|\bvm\.\w+\s*\(", b)
                          for b in report_code_blocks(str(it.get("description", ""))))
            weak = bool(WEAK_TITLE.search(str(it.get("title", ""))))
            new = (project_id(key), fid) not in in_data
            # best first: provable (warden PoC) and new to the data; then new; then the rest. H before M.
            score = (not fork, not weak, 2 if has_poc and new else 1 if new else 0, fid.startswith("H"))
            cands.append((score, key, root, truth, fid, str(it.get("title", "")), has_poc, new, fork))

    if not cands:
        sys.exit(f"[!] nothing left to pick ({n_proj} projects looked at). Try without --contest.")
    if args.random:
        random.shuffle(cands)
    else:
        random.Random(len(done)).shuffle(cands)          # vary within a score level, stable per session count
        cands.sort(key=lambda c: c[0], reverse=True)

    print(f"[*] {len(cands)} findings available in {n_proj} projects (held-out/dev test sets and done ones skipped)\n")
    for i, (score, key, root, truth, fid, title, has_poc, new, fork) in enumerate(cands[:args.list], 1):
        tags = ", ".join(t for t, on in (("warden PoC in report", has_poc), ("new to training data", new), ("weak/missing-feature title", bool(WEAK_TITLE.search(title))),
                                         ("NEEDS AN RPC URL (fork tests)", fork)) if on)
        print(f"{i}. {key} {fid}: {title[:90]}")
        print(f"   ({tags or 'already in the training data'})")
        print(f"   python3 poc_assist.py start {root} --truth {truth} --id {fid} --name PoC_{fid.replace('-', '')}\n")

    if args.go:
        _, key, root, truth, fid, title, *_ = cands[0]
        cmd = [sys.executable, str(ROOT / "poc_assist.py"), "start", str(root), "--truth", str(truth),
               "--id", fid, "--name", f"PoC_{fid.replace('-', '')}"]
        if args.model:
            cmd += ["--model", args.model]
        if args.planner:
            cmd += ["--planner", args.planner]
        print(f"[*] starting #1: {key} {fid}\n")
        sys.exit(subprocess.run(cmd, cwd=ROOT).returncode)


if __name__ == "__main__":
    main()
