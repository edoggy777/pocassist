#!/usr/bin/env python3
"""
setup_contests.py - Build an eval set from past Code4rena contests.

Three steps:

  1. discover   Read the saved Code4rena reports page, find each contest's repo, size and language,
                and write contests_catalog.json.
                  Open https://code4rena.com/reports in your browser, scroll to the bottom so every
                  card has loaded, press Ctrl+S, save as truth/reports.html, then:
                  python setup_contests.py discover truth/reports.html
                You can also pass slugs by hand:  python setup_contests.py discover --slugs 2025-11-merkl ...

  2. setup      Clone + build the contests you pick (from the catalog), check their reports, write
                manifest_sol.json / manifest_rust.json.
                  python setup_contests.py setup                 # everything in the catalog marked "pick"
                  python setup_contests.py setup merkl megapot   # just these
                  python setup_contests.py setup --max-files 25  # auto-pick: Solidity, <= 25 in-scope files

  3. status     What is cloned, built, has a report, and which reports still need saving.
                  python setup_contests.py status

Reports must be saved by hand (the site renders them in the browser): the status output prints
the exact URL and filename for each one.

The catalog has a "role" per contest: dev (tune on it), holdout (final-exam set: run rarely, never
tune on it), train (future fine-tuning data: never evaluate on it), skip. Edit it freely.
"""
import argparse
import json
import re
import shutil
import subprocess
import sys
from html.parser import HTMLParser
from pathlib import Path

from eval_audit import parse_truth

ROOT = Path(__file__).resolve().parent
CONTEST_DIR = ROOT / "contests"
TRUTH_DIR = ROOT / "truth"
CATALOG = ROOT / "contests_catalog.json"
ORG = "code-423n4"


# ---------------------------------------------------------------- helpers

def sh(cmd, cwd=None, timeout=1800):
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return 1, str(e)
    return p.returncode, (p.stdout + p.stderr)


def repo_exists(name):
    return sh(["git", "ls-remote", "-q", f"https://github.com/{ORG}/{name}", "HEAD"], timeout=30)[0] == 0


def guess_repo(slug):
    """Report slug -> repo name. Usually identical; sometimes the slug has extra words
    (2025-11-sequence-transaction-rails -> 2025-11-sequence)."""
    parts = slug.split("-")
    cands = [slug] + ["-".join(parts[:k]) for k in range(len(parts) - 1, 2, -1)]
    for c in cands:
        if repo_exists(c):
            return c
    return None


def load_catalog():
    return json.loads(CATALOG.read_text()) if CATALOG.exists() else {}


def save_catalog(cat):
    CATALOG.write_text(json.dumps(cat, indent=2, sort_keys=True) + "\n")


# ---------------------------------------------------------------- discover

class _Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.slugs, self.text = [], []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            href = dict(attrs).get("href", "") or ""
            m = re.search(r"/reports/(\d{4}-\d{2}-[a-z0-9-]+)", href)
            if m and m.group(1) not in self.slugs:
                self.slugs.append(m.group(1))

    def handle_data(self, data):
        self.text.append(data)


def slugs_from_html(path: Path):
    p = _Links()
    p.feed(path.read_text(errors="ignore"))
    if not p.slugs:  # fallback: raw regex over the file (works on copy-pasted text too)
        p.slugs = list(dict.fromkeys(re.findall(r"/reports/(\d{4}-\d{2}-[a-z0-9-]+)", path.read_text(errors="ignore"))))
    return p.slugs


def inspect_repo(repo):
    """Shallow, blob-less clone to read scope.txt, README and file types without downloading code."""
    tmp = ROOT / ".inspect" / repo
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.parent.mkdir(exist_ok=True)
    rc, out = sh(["git", "clone", "-q", "--depth", "1", "--filter=blob:none", "--no-checkout",
                  f"https://github.com/{ORG}/{repo}", str(tmp)], timeout=300)
    if rc != 0:
        return None
    rc, tree = sh(["git", "ls-tree", "-r", "--name-only", "HEAD"], cwd=tmp)
    files = tree.split()
    info = {
        "repo": f"{ORG}/{repo}",
        "sol_files": sum(f.endswith(".sol") for f in files),
        "rs_files": sum(f.endswith(".rs") for f in files),
        "has_scope": "scope.txt" in files,
        "build": ("foundry" if "foundry.toml" in files else
                  "hardhat" if any(f.startswith("hardhat.config") for f in files) else
                  "cargo" if "Cargo.toml" in files else "unknown"),
    }
    if info["has_scope"]:
        rc, scope = sh(["git", "show", "HEAD:scope.txt"], cwd=tmp)
        lines = [l.strip() for l in scope.splitlines() if l.strip() and not l.startswith("#")]
        info["scope_files"] = len(lines)
        info["scope_sol"] = sum(l.endswith(".sol") for l in lines)
        info["scope_rs"] = sum(l.endswith(".rs") for l in lines)
    rc, readme = sh(["git", "show", "HEAD:README.md"], cwd=tmp)
    m = re.search(r"\|\s*\**Totals?\**\s*\|[^\n]*?\**\s*([\d,]{3,7})\s*\**", readme, re.I)
    if m:
        info["nsloc"] = int(m.group(1).replace(",", ""))
    m = re.search(r"Total Prize Pool:\s*\$?([\d,]+)", readme, re.I)
    if m:
        info["prize_usd"] = int(m.group(1).replace(",", ""))
    shutil.rmtree(tmp, ignore_errors=True)
    lang = "rust" if info["rs_files"] > info["sol_files"] else "solidity" if info["sol_files"] else "other"
    info["lang"] = lang
    return info


def slug_from_report_page(path: Path):
    """A saved report page references its own URL (canonical/og:url links, nav links)."""
    text = path.read_text(errors="ignore")
    m = re.search(r'(?:canonical|og:url)[^>]*?code4rena\.com/reports/(\d{4}-\d{2}-[a-z0-9-]+)', text)
    if m:
        return m.group(1)
    found = re.findall(r"code4rena\.com/reports/(\d{4}-\d{2}-[a-z0-9-]+)", text) or \
            re.findall(r"/reports/(\d{4}-\d{2}-[a-z0-9-]+)", text)
    if found:
        return max(set(found), key=found.count)   # the page's own slug is the most frequent one
    return slug_from_title_and_date(text, path)


MONTHS = {m: i for i, m in enumerate(["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], 1)}


def slug_from_title_and_date(text: str, path: Path):
    """No self-link in the page: build YYYY-MM-name from the title and the first contest date,
    and confirm a repo with that name exists."""
    plain = re.sub(r"<[^>]+>", " ", text)
    m = re.search(r"<title>([^<|]+)", text, re.I)
    names = []
    if m:
        t = re.sub(r"(?i)\b(audit|report|code4rena|findings?|security)\b", " ", m.group(1))
        names.append(re.sub(r"[^a-z0-9]+", "-", t.lower()).strip("-"))
    names.append(re.sub(r"[^a-z0-9]+", "-", path.stem.lower()).strip("-"))
    dates = []
    for d, mon, y in re.findall(r"\b(\d{1,2})\s+([A-Za-z]{3})[a-z]*\s+(20\d{2})\b", plain):
        if mon.lower() in MONTHS:
            dates.append(f"{y}-{MONTHS[mon.lower()]:02d}")
    for mon, d, y in re.findall(r"\b([A-Za-z]{3})[a-z]*\s+(\d{1,2}),?\s+(20\d{2})\b", plain):
        if mon.lower() in MONTHS:
            dates.append(f"{y}-{MONTHS[mon.lower()]:02d}")
    dates += re.findall(r"\b(20\d{2}-\d{2})-\d{2}\b", plain)
    seen = set()
    for ym in dates[:12]:
        for nm in names:
            if not nm:
                continue
            for cand in {f"{ym}-{nm}", f"{ym}-{nm.split('-')[0]}"}:
                if cand in seen:
                    continue
                seen.add(cand)
                if repo_exists(cand):
                    return cand
    return None


def cmd_discover(args):
    cat = load_catalog()
    slugs = list(args.slugs or [])
    truth_map = {}
    if args.html:
        slugs += slugs_from_html(Path(args.html))
    if args.from_truth:
        for f in sorted(TRUTH_DIR.glob("*.html")):
            if f.name == "reports.html":
                continue
            slug = slug_from_report_page(f)
            if slug:
                slugs.append(slug)
                truth_map[slug] = f
                print(f"    {f.name}: {slug}")
            else:
                print(f"    {f.name}: couldn't find its report slug in the page")
    slugs = list(dict.fromkeys(slugs))
    if not slugs:
        sys.exit("[!] No report slugs found. Save https://code4rena.com/reports as HTML (after scrolling "
                 "to the bottom) or pass --slugs.")
    print(f"[*] {len(slugs)} report slug(s) to look up")
    known = {e.get("report_slug") for e in cat.values()}
    for slug in slugs:
        if slug in known and not args.refresh:
            print(f"    {slug}: already in catalog")
            continue
        repo = guess_repo(slug)
        if not repo:
            print(f"    {slug}: no public {ORG} repo found (maybe named differently)")
            cat.setdefault("-".join(slug.split("-")[2:]), {})["report_slug"] = slug
            continue
        name = "-".join(repo.split("-")[2:])          # 2025-11-sequence -> sequence
        if name in cat and cat[name].get("report_slug") not in (None, slug):
            name = repo                                # same protocol audited twice: keep both
        if slug not in truth_map:
            for stem in (name, name.split("-")[0], "-".join(slug.split("-")[2:])):
                f = TRUTH_DIR / f"{stem}.html"
                if f.exists():
                    truth_map[slug] = f
                    break
        info = inspect_repo(repo)
        if not info:
            print(f"    {slug}: repo {repo} found but could not inspect it")
            continue
        entry = cat.get(name, {})
        entry.update(info)
        entry.update({"report_slug": slug, "date": slug[:7], "role": entry.get("role", "new")})
        if slug in truth_map:
            entry["truth"] = str(truth_map[slug].relative_to(ROOT))
        cat[name] = entry
        size = entry.get("nsloc", "?")
        print(f"    {slug}: {entry['lang']:8} {entry['build']:8} nSLOC {size!s:>6}  "
              f"scope files {entry.get('scope_files', '?')}  -> {repo}")
    save_catalog(cat)
    print(f"\n[*] Catalog written to {CATALOG} ({len(cat)} contests). Edit 'role' per contest, then run setup.")


# ---------------------------------------------------------------- setup

def clone(name, repo):
    dest = CONTEST_DIR / name
    if dest.exists():
        return True
    rc, out = sh(["git", "clone", "--quiet", "--depth", "1", f"https://github.com/{repo}", str(dest)], timeout=900)
    if rc != 0:
        print("    [!] clone failed:", out.strip().splitlines()[-1:] or out)
    return rc == 0


def node_install(d):
    if (d / "node_modules").exists():
        return True
    if (d / "yarn.lock").exists():
        if not shutil.which("yarn"):
            sh(["npm", "i", "-g", "yarn"])
        cmd = ["yarn", "install", "--ignore-scripts"]
    elif (d / "pnpm-lock.yaml").exists():
        if not shutil.which("pnpm"):
            sh(["npm", "i", "-g", "pnpm"])
        cmd = ["pnpm", "install", "--ignore-scripts"]
    else:
        cmd = ["npm", "install", "--no-audit", "--no-fund", "--ignore-scripts"]
    print(f"    $ {' '.join(cmd)}")
    rc, out = sh(cmd, cwd=d)
    if rc != 0:
        print("    [!] install failed:\n" + "\n".join("      " + l for l in out.strip().splitlines()[-8:]))
    return rc == 0



def foundry_out(d):
    """Return the configured forge out dir (respects `out = ...` in foundry.toml)."""
    import json, subprocess
    try:
        cfg = json.loads(subprocess.run(["forge", "config", "--json"], cwd=d,
                                        capture_output=True, text=True).stdout)
        return d / cfg.get("out", "out")
    except Exception:
        return d / "out"

def foundry_built(d):
    return (foundry_out(d) / "build-info").exists()

def build(name, system):
    d = CONTEST_DIR / name
    if system == "foundry":
        if not shutil.which("forge"):
            print("    [!] forge not found: curl -L https://foundry.paradigm.xyz | bash && foundryup")
            return False
        if (d / "package.json").exists() and not (d / "node_modules").exists():
            node_install(d)
        sh(["forge", "install"], cwd=d)
        print("    $ forge build")
        rc, out = sh(["forge", "build", "--skip", "*/invariants/*", "--skip", "*Crytic*", "--skip", "*.s.sol"], cwd=d)
        if rc != 0 and "node_modules" in out and not (d / "node_modules").exists():
            node_install(d)
            rc, out = sh(["forge", "build", "--skip", "*/invariants/*", "--skip", "*Crytic*", "--skip", "*.s.sol"], cwd=d)
        if rc != 0:
            print("    [!] forge build failed:\n" + "\n".join("      " + l for l in out.strip().splitlines()[-8:]))
        return rc == 0 and foundry_built(d)
    if system == "hardhat":
        if not shutil.which("npm"):
            print("    [!] npm not found: sudo apt install nodejs npm")
            return False
        if not node_install(d):
            return False
        if not (d / ".env").exists() and (d / ".env.example").exists():
            shutil.copy(d / ".env.example", d / ".env")
        print("    $ npx hardhat compile")
        rc, out = sh(["npx", "hardhat", "compile"], cwd=d)
        if rc != 0:
            print("    [!] hardhat compile failed:\n" + "\n".join("      " + l for l in out.strip().splitlines()[-8:]))
        return rc == 0 and (d / "artifacts" / "build-info").exists()
    if system == "cargo":
        return True  # Rust: no build needed for the audit (Slither isn't used)
    print(f"    [?] unknown build system; audit still works, Slither won't")
    return True


def is_built(name, system):
    d = CONTEST_DIR / name
    if system == "foundry":
        return foundry_built(d)
    if system == "hardhat":
        return (d / "artifacts" / "build-info").exists()
    return d.exists()


def truth_status(name, entry=None):
    cands = []
    if entry and entry.get("truth"):
        cands.append(ROOT / entry["truth"])
    cands += [TRUTH_DIR / f"{name}{ext}" for ext in (".html", ".txt", ".md")]
    for f in cands:
        if f.exists():
            try:
                return parse_truth(f), f
            except Exception as e:  # noqa
                print(f"    [!] could not parse {f}: {e}")
                return [], f
    return None, TRUTH_DIR / f"{name}.html"


def write_manifests(cat):
    by_lang = {}
    for name, e in cat.items():
        if e.get("role") in ("skip", "new", None) or not e.get("ready"):
            continue
        entry = {"name": name, "repo": f"contests/{name}", "date": e.get("date"), "lang": e.get("lang"),
                 "role": e.get("role"), "truth": e["truth"]}
        if (CONTEST_DIR / name / "README.md").exists():
            entry["docs"] = f"contests/{name}/README.md"
        by_lang.setdefault(e.get("lang", "other"), []).append(entry)
    for lang, entries in by_lang.items():
        dev = [x for x in entries if x["role"] == "dev"]
        hold = [x for x in entries if x["role"] == "holdout"]
        if dev:
            (ROOT / f"manifest_{lang}_dev.json").write_text(json.dumps(dev, indent=2) + "\n")
        if hold:
            (ROOT / f"manifest_{lang}_holdout.json").write_text(json.dumps(hold, indent=2) + "\n")
        print(f"[*] {lang}: {len(dev)} dev -> manifest_{lang}_dev.json, {len(hold)} holdout -> manifest_{lang}_holdout.json")


def cmd_setup(args):
    cat = load_catalog()
    if not cat:
        sys.exit("[!] No catalog yet. Run: python setup_contests.py discover truth/reports.html")
    if args.names:
        names = args.names
    else:
        names = [n for n, e in cat.items()
                 if e.get("repo") and e.get("role") not in ("skip",)
                 and (args.lang == "any" or e.get("lang") == args.lang)
                 and (not args.max_files or (e.get("scope_files") or 10 ** 6) <= args.max_files)]
        print(f"[*] Auto-picked {len(names)} contest(s): {args.lang}, <= {args.max_files or 'any'} in-scope files")
    CONTEST_DIR.mkdir(exist_ok=True)
    TRUTH_DIR.mkdir(exist_ok=True)
    for name in names:
        e = cat.get(name)
        if not e or not e.get("repo"):
            print(f"[!] {name}: not in catalog or no repo; run discover first")
            continue
        print(f"\n== {name}  ({e['repo']}, {e.get('lang')}, {e.get('build')}, {e.get('scope_files', '?')} files in scope)")
        ok = clone(name, e["repo"]) and build(name, e.get("build"))
        e["built"] = bool(ok)
        if e.get("role") in (None, "new"):
            e["role"] = "dev"
        findings, f = truth_status(name, e)
        if findings is None:
            print(f"    [ ] report missing -> open https://code4rena.com/reports/{e['report_slug']} , Ctrl+S, save as {f}")
        elif not findings:
            print(f"    [!] {f.name} saved but no H/M findings parsed (try Ctrl+A, copy, paste into {f.with_suffix('.txt')})")
        else:
            hi = sum(1 for t in findings if t["severity"] == "high")
            e["findings_high"], e["findings_medium"] = hi, len(findings) - hi
            e["truth"] = str(f.relative_to(ROOT))
            print(f"    [x] report: {hi} high, {len(findings) - hi} medium")
        # usable for the eval once cloned and the report parses; a failed build only costs Slither hints
        e["ready"] = bool((CONTEST_DIR / name).exists() and findings)
        if e["ready"] and not e.get("built"):
            print("    [~] usable without Slither hints (build failed); fix the build later if you want them")
        save_catalog(cat)
    write_manifests(cat)
    cmd_status(args, cat)


def cmd_status(args, cat=None):
    cat = cat or load_catalog()
    print(f"\n{'contest':22} {'role':8} {'lang':9} {'build':8} {'files':>5} {'nSLOC':>6}  cloned built report  H/M")
    todo = []
    for name, e in sorted(cat.items(), key=lambda x: x[1].get("date", "")):
        if not e.get("repo"):
            continue
        cloned = (CONTEST_DIR / name).exists()
        built = is_built(name, e.get("build")) if cloned else False
        findings, f = truth_status(name, e)
        rep = "yes" if findings else ("empty" if findings is not None else "no")
        hm = f"{e.get('findings_high', '?')}/{e.get('findings_medium', '?')}" if findings else ""
        print(f"{name:22} {e.get('role', ''):8} {e.get('lang', ''):9} {e.get('build', ''):8} "
              f"{e.get('scope_files', '?')!s:>5} {e.get('nsloc', '?')!s:>6}  "
              f"{'yes' if cloned else 'no':6} {'yes' if built else 'no':5} {rep:6} {hm}")
        if cloned and findings is None and e.get("role") != "skip":
            todo.append((name, e["report_slug"], f))
    if todo:
        print("\nReports still to save (open URL, scroll to bottom, Ctrl+S, save as the filename):")
        for name, slug, f in todo:
            print(f"  https://code4rena.com/reports/{slug}   ->   {f.relative_to(ROOT)}")
        print("Then: python setup_contests.py setup  (re-checks reports and rewrites the manifests)")


def main():
    ap = argparse.ArgumentParser(description="Build a Code4rena eval set")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("discover", help="Read saved reports page, look up repos, write catalog")
    d.add_argument("html", nargs="?", help="Saved https://code4rena.com/reports page")
    d.add_argument("--slugs", nargs="+", help="Report slugs by hand, e.g. 2025-11-merkl")
    d.add_argument("--refresh", action="store_true", help="Re-inspect contests already in the catalog")
    d.add_argument("--from-truth", action="store_true",
                   help="Read the slug out of every saved report in truth/*.html")
    s = sub.add_parser("setup", help="Clone, build, check reports, write manifests")
    s.add_argument("names", nargs="*", help="Contest names (default: auto-pick from catalog)")
    s.add_argument("--lang", default="solidity", choices=["solidity", "rust", "any"])
    s.add_argument("--max-files", type=int, default=30, help="Auto-pick only contests with <= N in-scope files")
    sub.add_parser("status", help="Show what is ready and which reports still need saving")
    args = ap.parse_args()
    {"discover": cmd_discover, "setup": cmd_setup, "status": cmd_status}[args.cmd](args)


if __name__ == "__main__":
    main()
