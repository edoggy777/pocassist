#!/usr/bin/env python3
"""
build_dataset.py - Turn the `train` contests into fine-tuning examples for audit_assist.

For every High/Medium finding in a train contest's report, find the code it links to
(GitHub permalinks like .../blob/<ref>/src/Vault.sol#L120-L131), and build one chat example:

  system    = audit_assist's own system prompt (single unfocused pass, same as --passes all)
  user      = audit_assist's own user prompt for that file (or the part of it holding the bug)
  assistant = {"hypotheses": [...]} with the REAL findings for that code, in findings.json format,
              code_evidence copied verbatim from the linked lines

Plus some negative examples (in-scope files no finding points at -> {"hypotheses": []}) so the
model learns that most code is fine.

  python build_dataset.py                      # clone missing train repos, build dataset/
  python build_dataset.py --no-clone           # only use what is already cloned
  python build_dataset.py --only party maia    # a few contests, to check the output

Output: dataset/train.jsonl, dataset/val.jsonl (split by contest), dataset/stats.json.
Only contests with role "train" are used; dev/holdout are never touched.
After fine-tuning, run audit_assist with --passes all so inference matches the training prompt.
"""
import argparse
import json
import random
import re
from pathlib import Path

from audit_assist import (EXTS, build_user_prompt, cargo_context, detect_protocols, is_skipped,
                          norm_ws, split_code, strip_rust_tests, system_prompt)
from eval_audit import parse_truth
from setup_contests import CONTEST_DIR, ROOT, clone, load_catalog

LINK = re.compile(r"https://github\.com/[\w.-]+/[\w.-]+/blob/[^/\s]+/([^\s#)\]>\"']+\.(?:sol|rs))"
                  r"#L(\d+)(?:-L(\d+))?")
FN_DEF = re.compile(r"^\s*(?:function|modifier)\s+(\w+)|^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+(\w+)")
CONTRACT_DEF = re.compile(r"^\s*(?:abstract\s+)?(?:contract|library|interface)\s+(\w+)|^\s*(?:pub\s+)?mod\s+(\w+)")

VULN_CLASSES = [
    ("reentran", "reentrancy"), ("signature|replay|nonce|ecrecover|permit", "signature/replay"),
    ("oracle|price|stale|twap|chainlink", "oracle/price manipulation"),
    ("round|precision|truncat|division", "rounding/precision"),
    ("overflow|underflow|cast", "integer overflow/cast"),
    ("access|auth|onlyowner|permission|unprotected|anyone can|privilege", "access control"),
    ("dos|denial|grief|block|stuck|frozen|freeze|locked|brick", "DoS/stuck funds"),
    ("inflation|first deposit|share", "share inflation/accounting"),
    ("slippage|deadline|sandwich|frontrun|front-run|mev", "slippage/front-running"),
    ("liquidat", "liquidation logic"), ("reward|emission|incentive", "reward accounting"),
    ("fee", "fee accounting"), ("upgrade|initiali", "upgradeability/initialization"),
    ("transfer|erc20|token|approve", "token handling"),
]


def vuln_class(title: str, body: str) -> str:
    t = (title + " " + body[:400]).lower()
    for pat, name in VULN_CLASSES:
        if re.search(pat, t):
            return name
    return "logic error"


def clean_body(body: str) -> str:
    """Report body -> plain prose: no code blocks, link-only lines, 'Submitted by', headings."""
    body = re.sub(r"```.*?```", " ", body, flags=re.S)
    body = re.sub(r"</?[A-Za-z][^<>\n]*>", " ", body)           # html tags (<details>, <br> ...)
    out = []
    for line in body.splitlines():
        s = re.sub(r"^(?:[<>]\s*)+", "", line.strip())           # blockquote / stray < > at line start
        if not s or s.startswith("#") or s.lower().startswith(("*submitted by", "submitted by", "_submitted by")):
            continue
        if re.fullmatch(r"[-*\s]*\[?https?://\S+\]?(\(\S+\))?", s):
            continue
        s = re.sub(r"\[([^\]]*)\]\(https?://[^)]*\)", r"\1", s)
        s = re.sub(r"https?://\S+", "", s)
        out.append(s)
    text = re.sub(r"\s+", " ", " ".join(out))
    text = text.replace("**", "").replace("__", "")
    return re.sub(r"\s+", " ", text).strip()


def cut(text: str, n: int) -> str:
    """Shorten to n chars at a sentence end (or word end), never mid-word."""
    if len(text) <= n:
        return text
    head = text[:n]
    i = head.rfind(". ")
    return head[:i + 1] if i > n // 2 else head[:head.rfind(" ")].rstrip(",;:") + " ..."


def scenario(body: str, desc: str) -> list[str]:
    """Steps from a 'Proof of Concept' section if there is one, else the first sentences."""
    m = re.search(r"proof of concept|poc|attack scenario|steps", body, re.I)
    steps = []
    if m:
        for line in body[m.end():].splitlines():
            s = line.strip()
            if s.startswith("#") and steps:
                break
            mm = re.match(r"^(?:\d+[.)]|[-*])\s+(.{15,})", s)
            if mm and "```" not in s:
                st = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", mm.group(1)).replace("**", "").replace("__", "")
                steps.append(cut(st.strip(), 300))
            if len(steps) >= 6:
                break
    if len(steps) < 2:
        sents = re.split(r"(?<=[.!?])\s+", desc)
        steps = [cut(s, 300) for s in sents[:4] if len(s) > 20]
    return steps


def file_index(repo: Path) -> list[Path]:
    out = []
    for ext in (".sol", ".rs"):
        for p in repo.rglob(f"*{ext}"):
            rel = p.relative_to(repo)
            if p.is_file() and not is_skipped(rel):
                out.append(rel)
    return out


def resolve(path: str, files: list[Path]) -> Path | None:
    """Permalink path -> file in our clone. Exact match, else the longest matching path suffix."""
    parts = Path(path).parts
    best, best_n = None, 0
    for f in files:
        fp = f.parts
        n = 0
        while n < min(len(fp), len(parts)) and fp[-1 - n] == parts[-1 - n]:
            n += 1
        if n > best_n:
            best, best_n = f, n
    return best if best_n >= 1 else None


def evidence_lines(lines: list[str], a: int, b: int) -> str:
    """Up to 3 meaningful lines from the linked range (1-based, inclusive)."""
    b = min(max(a, b), a + 15, len(lines))
    picked = []
    for ln in lines[a - 1:b]:
        s = ln.strip()
        if not s or s.startswith(("//", "/*", "*", "{", "}")) or len(s) < 6:
            continue
        picked.append(ln.rstrip())
        if len(picked) == 3:
            break
    return "\n".join(picked)


def enclosing(lines: list[str], a: int, pat) -> str:
    for i in range(min(a, len(lines)) - 1, -1, -1):
        m = pat.match(lines[i])
        if m:
            return next(g for g in m.groups() if g)
    return ""


def build_contest(name: str, entry: dict, max_code: int, neg_ratio: float, rng, neg_min_located: float = 0.6) -> tuple[list, dict]:
    repo = CONTEST_DIR / name
    truth = parse_truth(ROOT / entry["truth"])
    files = file_index(repo)
    stats = {"findings": len(truth), "located": 0, "pos": 0, "neg": 0}
    if not files or not truth:
        return [], stats
    texts = {}

    def text(f):
        if f not in texts:
            texts[f] = (repo / f).read_text(errors="ignore")
        return texts[f]

    # 1. locate every finding: file + verbatim evidence
    by_file: dict[Path, list[dict]] = {}
    linked_files = set()
    for t in truth:
        loc = None
        for path, a, b in LINK.findall(t["description"]):
            f = resolve(path, files)
            if not f:
                continue
            linked_files.add(f)
            lines = text(f).splitlines()
            a, b = int(a), int(b or a)
            if a > len(lines):
                continue
            ev = evidence_lines(lines, a, b)
            if len(norm_ws(ev)) < 12:
                continue
            loc = (f, a, ev, lines)
            break
        if not loc:
            continue
        f, a, ev, lines = loc
        desc = clean_body(t["description"])
        hyp = {
            "title": t["title"].strip()[:200],
            "severity": t["severity"],
            "confidence": "high",
            "contract": enclosing(lines, a, CONTRACT_DEF) or f.stem,
            "function": enclosing(lines, a, FN_DEF),
            "vuln_class": vuln_class(t["title"], desc),
            "description": cut(desc, 900),
            "code_evidence": ev,
            "attack_scenario": scenario(t["description"], desc),
            "preconditions": "",
            "poc_plan": "",
            "slither_refs": [],
        }
        by_file.setdefault(f, []).append(hyp)
        stats["located"] += 1

    lang = "rust" if entry.get("lang") == "rust" else "solidity"
    langs = {lang}
    cargo = cargo_context(repo) if lang == "rust" else ""
    src_files = [f for f in files if f.suffix in EXTS[lang]]
    sample = "\n".join(text(f)[:4000] for f in src_files[:40])
    protocols = detect_protocols(sample, max_n=1)
    system = system_prompt(langs, protocols, None)
    all_names = [str(f) for f in src_files][:80]

    def make(f: Path, piece: str, label: str, hyps: list[dict]) -> dict:
        block = f"// ===== FILE: {label} =====\n{piece}\n"
        user = build_user_prompt([(label, block)], all_names, [], "", cargo, "")
        return {"messages": [{"role": "system", "content": system},
                             {"role": "user", "content": user},
                             {"role": "assistant", "content": json.dumps({"hypotheses": hyps[:8]},
                                                                         ensure_ascii=False)}],
                "contest": name, "file": label, "n_findings": len(hyps[:8])}

    def pieces(f: Path):
        t = text(f)
        if f.suffix == ".rs":
            t = strip_rust_tests(t)
        parts = split_code(t, max_code)
        for n, p in enumerate(parts, 1):
            yield p, (str(f) if len(parts) == 1 else f"{f} (part {n}/{len(parts)})")

    # 2. positive examples: each file part with the findings whose evidence is in it
    examples = []
    for f, hyps in by_file.items():
        for piece, label in pieces(f):
            flat = norm_ws(piece)
            here = [h for h in hyps if norm_ws(h["code_evidence"].splitlines()[0]) in flat]
            if here:
                examples.append(make(f, piece, label, here))
                stats["pos"] += 1

    # 3. negatives: only in contests where most findings were located (so "no finding" is trustworthy),
    #    only from files no finding links to at all
    if stats["located"] >= neg_min_located * stats["findings"] and stats["pos"]:
        quiet = [f for f in src_files if f not in linked_files and f not in by_file
                 and not re.search(r"interface|mock|test", str(f), re.I) and len(text(f)) > 800]
        rng.shuffle(quiet)
        want = int(stats["pos"] * neg_ratio / (1 - neg_ratio))
        for f in quiet:
            if stats["neg"] >= want:
                break
            piece, label = next(pieces(f))
            examples.append(make(f, piece, label, []))
            stats["neg"] += 1
    return examples, stats


def main():
    ap = argparse.ArgumentParser(description="Build fine-tuning data from train contests")
    ap.add_argument("--only", nargs="+", help="Just these catalog names")
    ap.add_argument("--no-clone", action="store_true", help="Skip contests that aren't cloned yet")
    ap.add_argument("--max-code-chars", type=int, default=20000,
                    help="Max chars of code per example (keeps examples trainable on 12 GB)")
    ap.add_argument("--neg-ratio", type=float, default=0.25, help="Share of examples with no findings")
    ap.add_argument("--neg-min-located", type=float, default=0.6,
                    help="Only take negatives from contests where at least this share of findings was located")
    ap.add_argument("--val-frac", type=float, default=0.06, help="Share of contests held out for validation")
    ap.add_argument("--out", type=Path, default=ROOT / "dataset")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    cat = load_catalog()
    blocked = {n.split("-")[0] for n, e in cat.items() if e.get("role") in ("dev", "holdout")}
    names = args.only or sorted(n for n, e in cat.items() if e.get("role") == "train")
    args.out.mkdir(exist_ok=True)
    all_stats, by_contest = {}, {}
    for name in names:
        e = cat.get(name, {})
        if e.get("role") != "train" or not e.get("truth"):
            print(f"    {name:32} skipped (not a train contest with a report)")
            continue
        base = re.sub(r"^\d{4}-\d{2}-", "", name).split("-")[0]
        if base in blocked:
            print(f"    {name:32} skipped (same protocol as a dev/holdout contest)")
            continue
        if not (CONTEST_DIR / name).exists():
            if args.no_clone or not clone(name, e["repo"]):
                print(f"    {name:32} skipped (not cloned)")
                continue
        try:
            ex, st = build_contest(name, e, args.max_code_chars, args.neg_ratio, rng, args.neg_min_located)
        except Exception as err:  # noqa
            print(f"    {name:32} failed: {err}")
            continue
        all_stats[name] = st
        by_contest[name] = ex
        print(f"    {name:32} {st['located']:3}/{st['findings']:<3} findings located -> "
              f"{st['pos']} positive, {st['neg']} negative examples")

    contests = sorted(c for c in by_contest if by_contest[c])
    rng.shuffle(contests)
    n_val = max(1, int(len(contests) * args.val_frac)) if len(contests) > 5 else 0
    val_set = set(contests[:n_val])
    with open(args.out / "train.jsonl", "w") as tr, open(args.out / "val.jsonl", "w") as va:
        for c in contests:
            for ex in by_contest[c]:
                (va if c in val_set else tr).write(json.dumps(ex, ensure_ascii=False) + "\n")
    tot = {k: sum(s[k] for s in all_stats.values()) for k in ("findings", "located", "pos", "neg")}
    n_val_ex = sum(len(by_contest[c]) for c in val_set)
    (args.out / "stats.json").write_text(json.dumps({"total": tot, "val_contests": sorted(val_set),
                                                     "per_contest": all_stats}, indent=2))
    pct = tot["located"] / tot["findings"] if tot["findings"] else 0
    print(f"\n[*] {len(all_stats)} contests: {tot['located']}/{tot['findings']} findings located ({pct:.0%})")
    print(f"[*] {tot['pos']} positive + {tot['neg']} negative examples; "
          f"{n_val_ex} in val.jsonl ({len(val_set)} contests), the rest in train.jsonl")
    print(f"[*] Written to {args.out}/")


if __name__ == "__main__":
    main()
