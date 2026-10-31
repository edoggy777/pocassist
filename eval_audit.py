#!/usr/bin/env python3
"""
eval_audit.py - Score audit_assist.py against past contests with known findings.

The real (published) High/Medium findings are the answer key. A judge model decides
which of your tool's hypotheses describe the same root cause as each real finding.

Two modes:

  score   one contest: an existing findings.json vs the published report
    python3 eval_audit.py score --hypotheses audit_out/findings.json --truth report.md

  suite   many contests: runs audit_assist.py on each, scores, prints a summary table
    python3 eval_audit.py suite manifest.json

manifest.json:
  [
    {"name": "c4-2024-xyz", "repo": "contests/2024-xyz", "truth": "truth/2024-xyz.md",
     "docs": "contests/2024-xyz/README.md", "src": ["src"], "lang": "auto"},
    ...
  ]
  "docs", "src", "lang" (auto/solidity/rust/both) and "protocol" (e.g. "lending") are optional.

Answer-key formats:
  .md   a Code4rena or Sherlock report. Headings like "[H-01] Title" or
        "Issue M-3: Title" are parsed automatically; Low/QA are ignored.
  .json [{"id": "H-01", "severity": "high", "title": "...", "description": "..."}]

Keep audit_assist.py in the same folder.
"""
import argparse
import json
import re
import subprocess
from html.parser import HTMLParser
import sys
from pathlib import Path

import requests

from audit_assist import llm_call, check_backend, BACKENDS, DEFAULT_MODEL, score as rank_score

JUDGE_SYSTEM = """You judge whether an automated auditor found a known vulnerability.
You get ONE real finding from a published audit and a numbered list of candidate hypotheses.

Work in this order:
1. State the real finding's ROOT CAUSE in one sentence: the specific wrong logic, missing check or
   wrong value, and where it is (contract/module + function).
2. Pick the single candidate closest to that root cause, or null if none is close.
3. State that candidate's root cause in one sentence.
4. Decide if they are the SAME root cause in the same code path.

Strict rules:
- Same general area or category is NOT a match. "Missing authorization in liquidation" does not
  match "liquidation leaves bad debt" or "close factor checked in the wrong order".
- A generic candidate ("missing auth in X", "possible overflow", "reentrancy risk") only matches if
  it names the exact missing check/flaw the real finding describes.
- The right bug with a wrong severity or weaker impact still matches.
- When unsure, answer false. A false match makes the auditor look better than it is.

Respond with ONE JSON object:
{"real_root_cause": str, "best_candidate": <number or null>, "candidate_root_cause": str,
 "same_root_cause": true|false, "reason": "<one sentence>"}"""


# ---------------------------------------------------------------- answer key

class _HtmlToMd(HTMLParser):
    """Turn a saved report page into markdown-ish text: <h2> -> '## ', blocks -> newlines."""
    BLOCKS = {"p", "div", "li", "br", "tr", "pre", "section", "article", "table", "ul", "ol"}

    def __init__(self):
        super().__init__()
        self.out, self.skip = [], 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "noscript"):
            self.skip += 1
        elif re.fullmatch(r"h[1-6]", tag):
            self.out.append("\n" + "#" * int(tag[1]) + " ")
        elif tag in self.BLOCKS:
            self.out.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style", "noscript"):
            self.skip = max(0, self.skip - 1)
        elif re.fullmatch(r"h[1-6]", tag) or tag in self.BLOCKS:
            self.out.append("\n")

    def handle_data(self, data):
        if not self.skip:
            self.out.append(data.replace("\n", " ") if self.out and self.out[-1].startswith("\n#") else data)


def html_to_md(html: str) -> str:
    p = _HtmlToMd()
    p.feed(html)
    text = "".join(p.out)
    # join heading fragments that were split across inline tags onto one line
    text = re.sub(r"(\n#{1,6} [^\n]*)\n(?!\n|#)([^\n]*)", r"\1\2", text)
    return re.sub(r"\n{3,}", "\n\n", text)


# heading-less lines that still start a finding: "Issue H-1: ..." (Sherlock),
# "[H-01] ..." (Code4rena copy-paste), "H-01: ..." / "H-01." (Cantina and others)
PLAIN_FINDING = re.compile(r"^()\s*((?:Issue\s+[HM]-\d+\s*:|\[{1,2}[HM]-\d+\]|[HM]-\d+\s*[:.)\]]).*)$")


def parse_truth(path: Path) -> list[dict]:
    if path.suffix == ".json":
        items = json.loads(path.read_text())
        return [i for i in items if str(i.get("severity", "")).lower() in ("high", "medium", "critical")]
    raw = path.read_text(errors="ignore")
    if path.suffix.lower() in (".html", ".htm"):
        raw = html_to_md(raw)
    lines = raw.splitlines()
    # if real headings carry finding IDs, ignore plain lines (tables of contents, nav links)
    use_plain = not any(re.match(r"^#{1,6}\s+.*\b[HM]-\d+\b", l) for l in lines)
    heads = []
    for n, line in enumerate(lines):
        m = re.match(r"^(#{1,6})\s+(.*)$", line)
        if not m and use_plain:
            m = PLAIN_FINDING.match(line)
        if not m:
            continue
        text = m.group(2)
        sev = re.search(r"\b([HM])-0*(\d+)\b", text)
        if not sev:
            heads.append((n, len(m.group(1)), None, None, None))
            continue
        title = re.sub(r"\]\(https?://[^)]*\)", "", text)          # drop markdown link targets
        title = text_after = title[title.find(sev.group(0)) + len(sev.group(0)):]
        title = re.sub(r"^[\]\):\s-]+", "", text_after).strip(" []")
        heads.append((n, len(m.group(1)), sev.group(1), sev.group(2), title))
    findings = []
    for i, (n, level, s, num, title) in enumerate(heads):
        if not s:
            continue
        end = len(lines)
        for n2, level2, *_ in heads[i + 1:]:
            if level2 <= level:
                end = n2
                break
        body = "\n".join(lines[n + 1:end]).strip()
        findings.append({"id": f"{s}-{int(num):02d}",
                         "severity": "high" if s == "H" else "medium",
                         "title": title, "description": body})
    # reports often repeat IDs in a summary table; keep the longest body per ID
    best = {}
    for f in findings:
        if f["id"] not in best or len(f["description"]) > len(best[f["id"]]["description"]):
            best[f["id"]] = f
    return sorted(best.values(), key=lambda f: (f["severity"] != "high", f["id"]))


# ---------------------------------------------------------------- judging

def hyp_line(i, h):
    loc = f"{h.get('contract', h.get('file', '?'))}.{h.get('function', '?')}"
    desc = str(h.get("description", ""))[:400].replace("\n", " ")
    return f"[{i}] {h.get('title', '')} | {loc} | {h.get('vuln_class', h.get('bug_class', ''))} | {desc}"


JUDGE_STOP = {"the", "a", "an", "of", "in", "to", "and", "or", "for", "is", "can", "be", "via", "with",
              "by", "on", "not", "no", "are", "that", "this", "from", "as", "it", "its", "when", "if",
              "function", "contract", "user", "users", "attacker", "could", "would", "should", "may",
              "will", "which", "than", "then", "into", "any", "all", "does", "has", "have", "been"}


def _words(text: str) -> set[str]:
    toks = set()
    for w in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", text):
        toks.add(w.lower())
        # split snake_case and camelCase identifiers into their parts too
        for part in re.split(r"_|(?<=[a-z])(?=[A-Z])", w):
            if len(part) > 2:
                toks.add(part.lower())
    return toks - JUDGE_STOP


def shortlist(truth: dict, hyps: list[dict], k: int) -> list[int]:
    """Indexes of the k hypotheses that share the most vocabulary with the real finding.
    Identifiers (function/contract names) count double. Hypotheses with zero overlap are
    dropped: they cannot describe the same bug."""
    if len(hyps) <= k:
        return list(range(len(hyps)))
    t_words = _words(truth["title"] + " " + truth["description"][:3000])
    t_idents = {w for w in re.findall(r"[a-z]+_[a-z_0-9]+|[a-z]+[A-Z][A-Za-z0-9]+", truth["title"] + " " + truth["description"][:3000])}
    t_idents = {w.lower() for w in t_idents}
    scored = []
    for i, h in enumerate(hyps):
        text = " ".join(str(h.get(f, "")) for f in ("title", "contract", "function", "vuln_class", "description"))
        hw = _words(text)
        idents = {w.lower() for w in re.findall(r"[a-z]+_[a-z_0-9]+|[a-z]+[A-Z][A-Za-z0-9]+", text)}
        sc = len(hw & t_words) + 2 * len(idents & t_idents)
        if sc:
            scored.append((sc, i))
    scored.sort(reverse=True)
    return [i for _, i in scored[:k]]


def judge(truth, hyps, backend, model, num_ctx, host, budget, k=40):
    """Return (index of matching hypothesis or None, reason)."""
    t = (f"REAL FINDING {truth['id']} ({truth['severity']}): {truth['title']}\n\n"
         f"{truth['description'][:2500]}")
    keep = shortlist(truth, hyps, k)
    if not keep:
        return None, "no candidate shares any vocabulary with the finding"
    lines = [hyp_line(i, hyps[i]) for i in keep]
    groups, cur, size = [], [], 0
    for line in lines:
        if cur and size + len(line) > budget:
            groups.append(cur)
            cur, size = [], 0
        cur.append(line)
        size += len(line)
    if cur:
        groups.append(cur)
    for group in groups:
        user = t + "\n\nCANDIDATES:\n" + "\n".join(group)
        try:
            resp = llm_call(backend, JUDGE_SYSTEM, user, model, num_ctx, host)
        except requests.RequestException as e:
            return None, f"judge call failed: {e}"
        m = re.search(r"\{.*\}", resp, re.S)
        try:
            obj = json.loads(m.group(0)) if m else {}
        except json.JSONDecodeError:
            obj = {}
        idx = obj.get("best_candidate", obj.get("match"))
        if isinstance(idx, str) and idx.strip().isdigit():
            idx = int(idx)
        same = obj.get("same_root_cause")
        if isinstance(same, str):
            same = same.strip().lower() == "true"
        if same is True and isinstance(idx, int) and 0 <= idx < len(hyps):
            return idx, (f"{obj.get('reason', '')} | real: {obj.get('real_root_cause', '')} "
                         f"| candidate: {obj.get('candidate_root_cause', '')}")
    return None, "no candidate matched"


def pre_verification_ranks(hyps):
    """Rank each hypothesis as it stood before the verifier changed the order."""
    stripped = []
    for h in hyps:
        c = dict(h)
        c.pop("verdict", None)
        c.pop("verified_severity", None)
        stripped.append(c)
    order = sorted(range(len(hyps)), key=lambda i: rank_score(stripped[i]), reverse=True)
    return {i: r + 1 for r, i in enumerate(order)}


def score_one(hyps, truth, args, label):
    print(f"[*] {label}: {len(truth)} real H/M findings, {len(hyps)} hypotheses")
    pre = pre_verification_ranks(hyps)
    rows, matched_hyps = [], set()
    for t in truth:
        idx, reason = (judge(t, hyps, args.backend, args.model, args.num_ctx, args.ollama_host,
                             args.judge_chars, args.shortlist) if hyps else (None, "no hypotheses"))
        if idx is not None:
            matched_hyps.add(idx)
        rows.append({"id": t["id"], "severity": t["severity"], "title": t["title"],
                     "found": idx is not None, "hypothesis": idx,
                     "hypothesis_title": hyps[idx].get("title") if idx is not None else None,
                     "reason": reason})
        line = f"    {'FOUND ' if idx is not None else 'missed'} {t['id']}: {t['title'][:60]}"
        if idx is not None:
            v = hyps[idx].get("verdict", "unverified")
            line += (f"\n           <- [{idx}] {str(hyps[idx].get('title', ''))[:60]}"
                     f"  (rank before verify: {pre[idx]}, verifier: {v})")
        print(line)
    highs = [r for r in rows if r["severity"] == "high"]
    meds = [r for r in rows if r["severity"] == "medium"]
    summary = {
        "contest": label,
        "real_high": len(highs), "found_high": sum(r["found"] for r in highs),
        "real_medium": len(meds), "found_medium": sum(r["found"] for r in meds),
        "hypotheses": len(hyps), "useful_hypotheses": len(matched_hyps),
    }
    summary["recall"] = round((summary["found_high"] + summary["found_medium"]) / len(rows), 3) if rows else None
    # each hypothesis may only be credited once: a stricter, more honest recall
    credits = {}
    for r in rows:
        if r["found"]:
            credits[r["hypothesis"]] = credits.get(r["hypothesis"], 0) + 1
    summary["recall_1to1"] = round(len(matched_hyps) / len(rows), 3) if rows else None
    ranks = sorted(matched_hyps)
    pre_ranks = sorted(pre[i] for i in matched_hyps)
    summary["hit_ranks"] = [r + 1 for r in ranks]
    summary["hit_ranks_pre_verify"] = pre_ranks
    summary["hits_top50"] = sum(1 for r in pre_ranks if r <= 50)
    summary["hits_top100"] = sum(1 for r in pre_ranks if r <= 100)
    verdicts = {}
    for i in matched_hyps:
        v = hyps[i].get("verdict", "unverified")
        verdicts[v] = verdicts.get(v, 0) + 1
    summary["hit_verdicts"] = verdicts
    if ranks:
        print(f"[*] Ranks of matched hypotheses BEFORE verification (1 = top): {pre_ranks}  "
              f"-> {summary['hits_top50']} in top 50, {summary['hits_top100']} in top 100")
        print(f"[*] Final ranks (after verifier re-ordering): {summary['hit_ranks']}")
        print(f"[*] Verifier's verdicts on the real hits: {verdicts}")
        n_ver = sum(n for v, n in verdicts.items() if v != "unverified")
        if n_ver:
            print(f"    -> of the real hits the verifier looked at, it confirmed "
                  f"{verdicts.get('confirmed', 0)} and rejected {verdicts.get('rejected', 0)}")
    multi = {i: n for i, n in credits.items() if n > 1}
    if multi:
        print("[!] Some hypotheses were credited for several different real findings, "
              "which usually means the judge was too generous:")
        for i, n in sorted(multi.items(), key=lambda x: -x[1]):
            print(f"      [{i}] x{n}: {str(hyps[i].get('title', ''))[:70]}")
    summary["precision"] = round(len(matched_hyps) / len(hyps), 3) if hyps else None
    return summary, rows


def fmt(x):
    return "-" if x is None else f"{x:.0%}"


def write_md(summaries, path):
    out = ["| Contest | Highs found | Mediums found | Recall | Recall 1:1 | Hypotheses | Precision | Hits in top 50/100 |",
           "|---|---|---|---|---|---|---|---|"]
    for s in summaries:
        out.append(f"| {s['contest']} | {s['found_high']}/{s['real_high']} | "
                   f"{s['found_medium']}/{s['real_medium']} | {fmt(s['recall'])} | {fmt(s.get('recall_1to1'))} | "
                   f"{s['hypotheses']} | {fmt(s['precision'])} | {s.get('hits_top50', '-')}/{s.get('hits_top100', '-')} |")
    if len(summaries) > 1:
        rh = sum(s["real_high"] for s in summaries); fh = sum(s["found_high"] for s in summaries)
        rm = sum(s["real_medium"] for s in summaries); fm = sum(s["found_medium"] for s in summaries)
        hy = sum(s["hypotheses"] for s in summaries); us = sum(s["useful_hypotheses"] for s in summaries)
        rec = (fh + fm) / (rh + rm) if rh + rm else None
        pre = us / hy if hy else None
        r11 = us / (rh + rm) if rh + rm else None
        t50 = sum(s.get("hits_top50", 0) for s in summaries); t100 = sum(s.get("hits_top100", 0) for s in summaries)
        out.append(f"| **TOTAL** | **{fh}/{rh}** | **{fm}/{rm}** | **{fmt(rec)}** | **{fmt(r11)}** | **{hy}** | **{fmt(pre)}** | **{t50}/{t100}** |")
    path.write_text("\n".join(out) + "\n")
    print("\n" + "\n".join(out))


# ---------------------------------------------------------------- modes

def cmd_score(args):
    hyps = json.loads(Path(args.hypotheses).read_text())
    truth = parse_truth(Path(args.truth))
    if not truth:
        sys.exit("[!] No High/Medium findings parsed from the answer key. Check its format.")
    summary, rows = score_one(hyps, truth, args, args.name or Path(args.truth).stem)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "eval_detail.json").write_text(json.dumps({"summary": summary, "findings": rows}, indent=2))
    write_md([summary], out / "eval_summary.md")


def cmd_suite(args):
    manifest = json.loads(Path(args.manifest).read_text())
    here = Path(__file__).resolve().parent
    out = Path(args.out)
    summaries = []
    for c in manifest:
        name = c["name"]
        cdir = out / name
        hyp_file = cdir / "findings.json"
        if not (args.reuse and hyp_file.exists()):
            cmd = [sys.executable, str(here / "audit_assist.py"), c["repo"], "--out", str(cdir),
                   "--backend", args.audit_backend or args.backend, "--num-ctx", str(args.num_ctx)]
            if args.audit_model:
                cmd += ["--model", args.audit_model]
            if c.get("docs"):
                cmd += ["--docs", c["docs"]]
            if c.get("protocol"):
                cmd += ["--protocol", *([c["protocol"]] if isinstance(c["protocol"], str) else c["protocol"])]
            if args.passes:
                cmd += ["--passes", *args.passes]
            if args.verify:
                cmd += ["--verify"]
            if args.workers:
                cmd += ["--workers", str(args.workers)]
            if args.fresh:
                cmd += ["--fresh"]
            if args.drop_ungrounded:
                cmd += ["--drop-ungrounded"]
            if args.max_hyps:
                cmd += ["--max-hyps", str(args.max_hyps)]
            if args.verify_backend:
                cmd += ["--verify-backend", args.verify_backend]
            if args.verify_model:
                cmd += ["--verify-model", args.verify_model]
            if args.verify_top:
                cmd += ["--verify-top", str(args.verify_top)]
            if args.verify_trust:
                cmd += ["--verify-trust", args.verify_trust]
            if args.samples:
                cmd += ["--samples", str(args.samples)]
            if args.temperature is not None:
                cmd += ["--temperature", str(args.temperature)]
            if c.get("lang"):
                cmd += ["--lang", c["lang"]]
            if c.get("src"):
                cmd += ["--src", *c["src"]]
            if args.no_slither:
                cmd += ["--no-slither"]
            print(f"\n[*] Auditing {name} ...")
            if subprocess.run(cmd).returncode != 0 or not hyp_file.exists():
                print(f"[!] audit_assist failed for {name}; skipping")
                continue
        truth = parse_truth(Path(c["truth"]))
        if not truth:
            print(f"[!] No H/M findings parsed for {name}; skipping")
            continue
        hyps = json.loads(hyp_file.read_text())
        if any("verdict" in h for h in hyps):
            c = {k: sum(1 for h in hyps if h.get("verdict") == k) for k in ("confirmed", "unclear", "rejected")}
            print(f"[*] {name}: verifier said {c['confirmed']} confirmed, {c['unclear']} unclear, {c['rejected']} rejected")
            if args.only_confirmed:
                hyps = [h for h in hyps if h.get("verdict") == "confirmed"]
        summary, rows = score_one(hyps, truth, args, name)
        (cdir / "eval_detail.json").write_text(json.dumps({"summary": summary, "findings": rows}, indent=2))
        summaries.append(summary)
    if summaries:
        out.mkdir(parents=True, exist_ok=True)
        (out / "eval_all.json").write_text(json.dumps(summaries, indent=2))
        write_md(summaries, out / "eval_summary.md")


def cmd_compare(args):
    """Side-by-side view of several run folders: which real findings each run found."""
    import glob as _glob
    runs = [Path(r) for r in args.runs]
    contests = {}
    for r in runs:
        for f in _glob.glob(str(r / "*" / "eval_detail.json")):
            d = json.loads(Path(f).read_text())
            name = d["summary"]["contest"]
            c = contests.setdefault(name, {"findings": {}, "runs": {}})
            found = {x["id"]: x for x in d["findings"] if x["found"]}
            c["runs"][r.name] = {"found": found, "hyps": d["summary"]["hypotheses"],
                                 "ranks": d["summary"].get("hit_ranks_pre_verify", d["summary"].get("hit_ranks", []))}
            for x in d["findings"]:
                c["findings"][x["id"]] = x["title"]
    for name, c in contests.items():
        run_names = [r.name for r in runs if r.name in c["runs"]]
        total = len(c["findings"])
        print(f"\n== {name}: {total} real H/M findings, {len(run_names)} run(s)")
        print(f"   {'finding':8} " + " ".join(f"{rn[:12]:>12}" for rn in run_names) + "   found-in  title")
        union = set()
        for fid, title in sorted(c["findings"].items()):
            marks, n = [], 0
            for rn in run_names:
                hit = fid in c["runs"][rn]["found"]
                n += hit
                marks.append(f"{'X' if hit else '.':>12}")
            if n:
                union.add(fid)
            print(f"   {fid:8} " + " ".join(marks) + f"   {n}/{len(run_names)}      {title[:55]}")
        line = f"   {'recall':8} "
        for rn in run_names:
            k = len(c["runs"][rn]["found"])
            line += f"{f'{k}/{total}':>12} "
        print(line + f"   union {len(union)}/{total}")
        line = f"   {'hyps':8} " + " ".join(f"{c['runs'][rn]['hyps']:>12}" for rn in run_names)
        print(line)
        line = f"   {'top100':8} " + " ".join(f"{sum(1 for x in c['runs'][rn]['ranks'] if x <= 100):>12}" for rn in run_names)
        print(line + "   (hits ranked in top 100, before verification)")
    stable = {}
    for name, c in contests.items():
        for fid in c["findings"]:
            n = sum(fid in c["runs"][rn]["found"] for rn in c["runs"])
            if n >= 2:
                stable[f"{name} {fid}"] = n
    if stable:
        print(f"\n[*] Findings caught in 2+ runs (stable capability): {len(stable)}")


def main():
    ap = argparse.ArgumentParser(description="Score audit_assist.py against known findings")
    sub = ap.add_subparsers(dest="mode", required=True)
    cp = sub.add_parser("compare", help="Compare several run folders side by side")
    cp.add_argument("runs", nargs="+", help="Run folders, e.g. runs_sol runs_sol_v6 runs_sol_v7")
    for name in ("score", "suite"):
        p = sub.add_parser(name)
        p.add_argument("--backend", choices=BACKENDS, default="ollama",
                       help="Backend for judging (and auditing unless --audit-backend is set)")
        p.add_argument("--model", help="Judge model (default depends on backend)")
        p.add_argument("--ollama-host", default="http://localhost:11434")
        p.add_argument("--num-ctx", type=int, default=16384)
        p.add_argument("--shortlist", type=int, default=40,
                       help="Per real finding, judge only the N hypotheses with the most word overlap")
        p.add_argument("--judge-chars", type=int, default=20000,
                       help="Max chars of candidate hypotheses per judge call")
        if name == "score":
            p.add_argument("--hypotheses", required=True, help="findings.json from audit_assist")
            p.add_argument("--truth", required=True, help="Published report (.md) or .json answer key")
            p.add_argument("--name")
            p.add_argument("--out", default="eval_out")
        else:
            p.add_argument("manifest")
            p.add_argument("--audit-backend", choices=BACKENDS,
                           help="Backend for audit_assist (default: same as --backend). "
                                "E.g. audit with claude-code, judge locally with ollama.")
            p.add_argument("--audit-model", help="Model for audit_assist (default: its own default)")
            p.add_argument("--no-slither", action="store_true")
            p.add_argument("--passes", nargs="+", help="Passed to audit_assist (e.g. money access external, or all)")
            p.add_argument("--verify", action="store_true", help="Run audit_assist's verification pass")
            p.add_argument("--workers", type=int, help="Parallel LLM calls for audit_assist")
            p.add_argument("--fresh", action="store_true", help="Don't resume from saved responses")
            p.add_argument("--drop-ungrounded", action="store_true",
                           help="Discard hypotheses whose quoted evidence isn't in the code before verifying")
            p.add_argument("--max-hyps", type=int, help="Max candidates per audit call (default 8)")
            p.add_argument("--verify-backend", choices=BACKENDS, help="Backend for the verify pass")
            p.add_argument("--verify-model", help="Model for the verify pass")
            p.add_argument("--verify-top", type=int, help="Only verify the N highest-ranked hypotheses")
            p.add_argument("--verify-trust", choices=["auto", "weak", "strong"],
                           help="How much verifier verdicts move the ranking (see audit_assist)")
            p.add_argument("--samples", type=int, help="Ask each batch/pass N times and merge (audit_assist --samples)")
            p.add_argument("--temperature", type=float, help="Sampling temperature for the audit model")
            p.add_argument("--only-confirmed", action="store_true",
                           help="Score only hypotheses the verifier confirmed (needs --verify)")
            p.add_argument("--reuse", action="store_true",
                           help="Reuse existing findings.json instead of re-auditing")
            p.add_argument("--out", default="eval_runs")
    args = ap.parse_args()
    if args.mode == "compare":
        return cmd_compare(args)
    if not args.model:
        args.model = DEFAULT_MODEL[args.backend]
    if args.backend != "ollama":
        args.judge_chars = max(args.judge_chars, 150_000)
    check_backend(args.backend, args.ollama_host, args.model)
    cmd_score(args) if args.mode == "score" else cmd_suite(args)


if __name__ == "__main__":
    main()
