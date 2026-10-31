#!/usr/bin/env python3
"""
audit_assist.py - Step 1 of an LLM-assisted Web3 audit pipeline.

Reads a smart-contract project (Solidity, Rust, or both), runs Slither on the
Solidity part, sends the code + hints to an LLM, and writes ranked vulnerability
hypotheses to <out>/findings.json and <out>/report.md.

Rust covers Solana (Anchor or native), Stellar/Soroban, CosmWasm, NEAR, ink!, etc.

Usage:
  python audit_assist.py /path/to/repo                          # auto-detects language, local Ollama
  python audit_assist.py /path/to/repo --docs notes.md          # add protocol docs (recommended)
  python audit_assist.py /path/to/repo --lang rust              # force a language: solidity|rust|both
  python audit_assist.py /path/to/repo --backend anthropic      # Claude API (ANTHROPIC_API_KEY)
  python audit_assist.py /path/to/repo --backend claude-code    # Claude Code CLI on a Pro/Max plan
  python audit_assist.py /path/to/repo --dry-run                # write prompts, no LLM calls

Requirements:
  pip install requests            (+ slither-analyzer for Solidity)
  Solidity projects must compile (`forge build`) for Slither to work.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests

SEV_SCORE = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
CONF_SCORE = {"high": 3, "medium": 2, "low": 1}

EXTS = {"solidity": (".sol",), "rust": (".rs",)}
SKIP_DIRS = {"lib", "node_modules", "test", "tests", "script", "scripts", "mocks", "mock",
             "out", "cache", "artifacts", "broadcast", "target", "benches", "examples",
             "fuzz", "test-utils", "testutils", "integration-tests", ".git"}
DEFAULT_SRC = {"solidity": ["src", "contracts"], "rust": [], "both": []}  # [] = whole repo

BASE_PROMPT = """You are an expert smart contract security researcher competing in audit contests.
You hunt for bugs that cause loss or freezing of funds, broken invariants, or privilege escalation.

{focus}
{protocol}
{pass_focus}
Rules:
- Static-analysis findings, if given, are hints and many are false positives. Confirm or reject them.
- Only report issues tied to specific code. No generic best-practice advice, no gas optimizations.
- Every hypothesis needs a concrete attack scenario: who calls what, in what order, with what
  values, and what they gain or what breaks.
- Mark confidence honestly. Low-confidence candidates are welcome: list them and mark them "low".
  Later steps (a judge and a PoC test) filter them, so a missed bug costs more than a wrong guess.
- Return up to {max_hyps} candidates, fewer is fine. Return an empty list if nothing in your focus is wrong.
- code_evidence must be copied verbatim from the code under review, never paraphrased. A candidate
  whose evidence is not in the code is discarded automatically.

Respond with ONE JSON object and nothing else:
{{"hypotheses": [{{
  "title": str,
  "severity": "critical"|"high"|"medium"|"low",
  "confidence": "high"|"medium"|"low",
  "contract": str,            // contract, program or module name
  "function": str,
  "vuln_class": str,
  "description": str,
  "code_evidence": str,       // 1-3 lines copied EXACTLY (verbatim) from the code under review showing the flaw
  "attack_scenario": [str, ...],
  "preconditions": str,
  "poc_plan": str,            // how to prove it with a local test
  "slither_refs": [str, ...]  // static-analysis detector names this relates to, may be empty
}}]}}
"""

FOCUS = {
    "solidity": """For SOLIDITY code, pay particular attention to: access control and missing modifiers;
reentrancy (cross-function and read-only); oracle and spot-price manipulation; rounding direction
and precision loss; ERC-4626 share inflation and first-depositor issues; signature replay,
malleability and missing nonces/chainId; unchecked return values and weird ERC20s (fee-on-transfer,
rebasing, no-return); accounting drift between related state variables; DoS via unbounded loops or
griefing; flash-loan attack surface; upgradeability and initializer bugs; and logic that contradicts
the protocol's stated intent. PoC plan: a Foundry test on a local fork.""",
    "rust": """For RUST smart contracts (Solana/Anchor, Soroban, CosmWasm, NEAR, ink! and similar), pay
particular attention to: missing authorization (missing signer checks, require_auth, info.sender /
predecessor checks, admin-only paths callable by anyone); account and input validation (Solana: owner,
discriminator, PDA seeds/bump, account substitution, duplicate mutable accounts; CosmWasm: unvalidated
addresses and funds); integer overflow/underflow (check Cargo.toml `overflow-checks`; plain `+ - *`
wraps in release builds without it), unsafe `as` casts and truncation; rounding direction and
precision loss in integer division; panics an attacker can trigger (`unwrap`, `expect`, indexing,
division by zero) causing DoS or stuck funds; cross-contract / CPI calls with unchecked results,
reentrancy through callbacks, and state written after external calls; storage issues (Soroban TTL /
archival, key collisions, stale or uninitialised state); oracle and price manipulation; unbounded
iteration hitting compute/gas/budget limits; and logic that contradicts the protocol's stated intent.
PoC plan: a unit or integration test in the project's own test framework.""",
}


MAX_HYPS = 8

PROTOCOLS = {
    "lending": {
        "keywords": ["borrow", "collateral", "liquidat", "health factor", "health_factor", "debt",
                     "lending", "interest rate", "ltv", "reserve"],
        "checklist": """liquidation math (close factor, liquidation bonus, rounding of seized collateral,
order of checks, min-remaining-debt rules, partial vs full liquidation, liquidations that make the
position worse); bad debt and deficit accounting (when debt is written off, who absorbs it, deficit
counted as available liquidity); health-factor inputs (stale interest indices, stale or cached prices,
disabled or zero-balance collateral still counted, thresholds ignored on some paths); interest index
and scaled-balance accounting (rounding direction on mint/burn, zero-amount operations, dust cleanup);
caps and ceilings (supply/borrow caps, debt ceilings, deficit excluded from cap checks); pause / freeze /
inactive states that some entry points forget to check (flash loans, transfers, liquidations, swaps of
collateral); self-liquidation and same-asset borrow/collateral; flash loans and flash liquidations;
first-deposit and max-reserves limits bypassable via alternative entry points (swaps, transfers);
interest accrual while repayment is paused; fee and treasury accrual timing; reward/incentive
accounting on balance changes.""",
    },
    "dex": {
        "keywords": ["swap", "liquidity", "amm", "pair", "slippage", "tick", "sqrt_price", "sqrtprice",
                     "getamountout", "get_amount_out", "token0", "token1"],
        "checklist": """price manipulation via spot reserves; slippage and deadline checks; rounding in
swap math and LP share minting/burning (first LP, donation attacks); fee accounting and fee-on-transfer
tokens; overflow in quote/price math; reentrancy through token callbacks; tick/range boundary bugs;
trusting swap outputs without checking balances actually received.""",
    },
    "vault": {
        "keywords": ["vault", "erc4626", "shares", "strategy", "harvest", "deposit", "redeem"],
        "checklist": """share inflation / first-depositor attacks; rounding direction in
convertToShares/convertToAssets and previews; totalAssets manipulable by donations; strategy losses not
reflected; withdrawal queues and stuck funds; harvest/fee timing sandwiches; accounting when strategies
report gains/losses.""",
    },
    "staking": {
        "keywords": ["stake", "staking", "reward", "validator", "delegat", "unbond", "epoch", "emission",
                     "distributor", "claim", "lock", "vest"],
        "checklist": """reward-per-token accounting updated before every balance change; rewards lost or
double-claimed when supply hits zero; emission-rate changes applied retroactively; stale reward indexes
across inactive periods; unbonding/cooldown bypass; slashing accounting; checkpoint loops hitting
compute limits.""",
    },
    "bridge": {
        "keywords": ["bridge", "cross-chain", "crosschain", "relayer", "message", "wormhole", "layerzero"],
        "checklist": """message replay and missing nonces/chain IDs; signature/threshold verification;
mint without matching lock/burn; finality assumptions; failed-message handling and refunds; decimals
mismatches between chains.""",
    },
    "governance": {
        "keywords": ["proposal", "vote", "voting", "timelock", "quorum", "governor", "delegate"],
        "checklist": """flash-loaned voting power and snapshot timing; double voting via transfers;
quorum/threshold math; timelock bypass and proposal cancellation; admin role transfer leaving stale
authority behind.""",
    },
}

PASSES = {
    "money": "IN THIS PASS focus only on MONEY FLOW AND ACCOUNTING: math, rounding, interest/reward "
             "indices, liquidations, fees, caps, share/balance bookkeeping, and invariants between "
             "related state variables. Trace values across functions using the project map. "
             "Method: list every place value is computed, moved, minted, burned or compared against a "
             "limit; for each, ask what happens at zero, at the maximum, with rounding in the wrong "
             "direction, with two calls in a row, with a stale value, and when the stated rule (docs) "
             "and the code disagree. Report the ones where you can describe a concrete failure.",
    "access": "IN THIS PASS focus only on PERMISSIONS AND STATE GATES: authorization checks, admin and "
              "emergency roles (including after role transfers), pause/freeze/inactive flags, "
              "initialization and upgrades, and entry points that skip checks their siblings perform.",
    "external": "IN THIS PASS focus only on EXTERNAL INTERACTIONS AND LIMITS: oracles and price caching/"
                "staleness, swaps and their outputs, cross-contract calls and token transfers, "
                "reentrancy/callbacks, panics, overflow, and DoS through unbounded loops or "
                "compute/memory/gas limits.",
}


def detect_protocols(text: str, max_n: int = 2) -> list[str]:
    low = text.lower()
    scores = {name: sum(low.count(k) for k in p["keywords"]) for name, p in PROTOCOLS.items()}
    ranked = [n for n, sc in sorted(scores.items(), key=lambda x: -x[1]) if sc >= 15]
    return ranked[:max_n]


def system_prompt(langs: set[str], protocols: list[str] = (), pass_name: str | None = None) -> str:
    proto = ""
    if protocols:
        proto = "\n" + "\n\n".join(
            f"This looks like a {name.upper()} protocol. Known bug patterns for this type, check each one: "
            + PROTOCOLS[name]["checklist"] for name in protocols) + "\n"
    return BASE_PROMPT.format(
        max_hyps=MAX_HYPS,
        focus="\n\n".join(FOCUS[l] for l in ("solidity", "rust") if l in langs),
        protocol=proto,
        pass_focus=("\n" + PASSES[pass_name] + "\n") if pass_name else "")


# ---------------------------------------------------------------- docs condensing

DOCS_SYSTEM = """You condense smart-contract protocol documentation for a security auditor.
Keep ONLY what helps find bugs: what the protocol does; actors and roles and what each may do;
intended invariants and rules (limits, caps, thresholds, ordering, who pays/absorbs losses);
trust assumptions; external dependencies (oracles, DEXes, tokens); known issues and anything stated as
out of scope (so the auditor doesn't report them). Drop marketing, setup/build instructions, links,
and tables of file names. Use terse bullet points. Plain text, no JSON."""


def condense_docs(docs: str, limit: int, llm, out_dir: Path, dry_run: bool) -> str:
    """Long docs crowd out code. Summarise them once (cached) so they fit in `limit` chars."""
    if len(docs) <= limit:
        return docs
    cache = out_dir / "docs_condensed.md"
    if cache.exists():
        print(f"[*] Using condensed docs from {cache}")
        return cache.read_text()[:limit]
    if dry_run:
        print(f"[*] Docs are {len(docs):,} chars; a real run condenses them to ~{limit:,}. "
              f"Dry run just truncates.")
        return docs[:limit]
    print(f"[*] Docs are {len(docs):,} chars; condensing to ~{limit:,} chars (one-time) ...")
    chunk = max(limit * 2, 12_000)
    pieces = [docs[i:i + chunk] for i in range(0, len(docs), chunk)]
    per = max(limit // len(pieces), 800)
    notes = []
    for n, piece in enumerate(pieces, 1):
        try:
            notes.append(llm(DOCS_SYSTEM, f"Condense this documentation (part {n}/{len(pieces)}) to at "
                                          f"most {per} characters:\n\n{piece}"))
        except requests.RequestException as e:
            print(f"[!] Condensing failed ({e}); truncating docs instead")
            return docs[:limit]
    out = "\n\n".join(x.strip() for x in notes)[:limit]
    cache.write_text(out)
    return out


# ---------------------------------------------------------------- project map

RS_SIG = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:const\s+)?fn\s+\w+[^{;]*"
                    r"|^\s*(?:pub\s+)?(?:struct|enum|trait)\s+\w+"
                    r"|^\s*impl\b[^{]*"
                    r"|^\s*(?:pub\s+)?const\s+[A-Z_][A-Z0-9_]*\s*:[^=]*=[^;]{0,60}")
SOL_SIG = re.compile(r"^\s*(?:abstract\s+)?(?:contract|interface|library)\s+\w+[^{]*"
                     r"|^\s*function\s+\w+[^{;]*"
                     r"|^\s*modifier\s+\w+[^{]*"
                     r"|^\s*(?:struct|enum|event|error)\s+\w+[^{;]*"
                     r"|^\s*[\w\[\]().=> ]+\s+(?:public|private|internal|constant|immutable)\b[^;]*")


def project_map(repo: Path, files: list[Path], max_chars: int) -> str:
    """Compact list of signatures across all in-scope files, so each batch knows what exists
    elsewhere. Private Rust fns are dropped first if the map is too big."""
    def build(include_private: bool) -> str:
        out = []
        for f in files:
            text = (repo / f).read_text(errors="ignore")
            if f.suffix == ".rs":
                text = strip_rust_tests(text)
            pat = RS_SIG if f.suffix == ".rs" else SOL_SIG
            sigs = []
            for line in text.splitlines():
                m = pat.match(line)
                if not m:
                    continue
                sig = " ".join(m.group(0).split())
                if f.suffix == ".rs" and not include_private and sig.startswith("fn "):
                    continue
                sigs.append("  " + sig[:160])
            if sigs:
                out.append(f"{f}:\n" + "\n".join(sigs))
        return "\n".join(out)
    m = build(True)
    if len(m) > max_chars:
        m = build(False)
    if len(m) > max_chars:
        m = m[:max_chars] + "\n  ... (map truncated)"
    return m


# ---------------------------------------------------------------- language & sources

def is_skipped(rel: Path) -> bool:
    if any(part.lower() in SKIP_DIRS for part in rel.parts[:-1]):
        return True
    name = rel.name.lower()
    return name.endswith((".t.sol", ".s.sol", "_test.rs", "_tests.rs")) or name in ("test.rs", "tests.rs")


def detect_lang(repo: Path) -> str:
    counts = {"solidity": 0, "rust": 0}
    for lang, exts in EXTS.items():
        for ext in exts:
            for p in repo.rglob(f"*{ext}"):
                if not is_skipped(p.relative_to(repo)):
                    counts[lang] += 1
    sol, rs = counts["solidity"], counts["rust"]
    if sol and rs:
        return "both"
    return "rust" if rs > sol else "solidity"


def read_scope_file(repo: Path, scope_file: Path) -> list[Path]:
    """A contest scope list (e.g. Code4rena's scope.txt): one file path per line."""
    files = []
    for line in scope_file.read_text(errors="ignore").splitlines():
        line = line.strip().split()[0] if line.strip() else ""
        if not line or line.startswith("#"):
            continue
        rel = Path(line.removeprefix("./"))
        if rel.suffix in (".sol", ".rs") and (repo / rel).is_file():
            files.append(rel)
    return sorted(set(files))


def collect_sources(repo: Path, src_dirs: list[str], lang: str) -> list[Path]:
    exts = EXTS["solidity"] + EXTS["rust"] if lang == "both" else EXTS[lang]
    roots = [repo / s for s in src_dirs if (repo / s).is_dir()] or [repo]
    files = set()
    for root in roots:
        for ext in exts:
            for p in root.rglob(f"*{ext}"):
                rel = p.relative_to(repo)
                if not is_skipped(rel):
                    files.add(rel)
    return sorted(files)


def strip_rust_tests(text: str) -> str:
    """Remove `#[cfg(test)] mod x { ... }` blocks so test code doesn't eat the context."""
    out, i = [], 0
    pat = re.compile(r"#\[cfg\(test\)\]\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*\{")
    while True:
        m = pat.search(text, i)
        if not m:
            out.append(text[i:])
            break
        out.append(text[i:m.start()])
        depth, j = 1, m.end()
        while j < len(text) and depth:
            depth += {"{": 1, "}": -1}.get(text[j], 0)
            j += 1
        out.append("// [test module removed]\n")
        i = j
    return "".join(out)


def cargo_context(repo: Path, max_chars: int = 2500) -> str:
    """The parts of Cargo.toml files that matter for an audit: build profiles (overflow-checks!)
    and the smart-contract SDK versions."""
    keep_dep = re.compile(r"^\s*(soroban|anchor|solana|cosmwasm|cw-|near-|ink|sp-|spl-)[\w-]*\s*=", re.I)
    parts, size = [], 0
    for p in sorted(repo.rglob("Cargo.toml")):
        rel = p.relative_to(repo)
        if is_skipped(rel):
            continue
        lines, section = [], ""
        for line in p.read_text(errors="ignore").splitlines():
            st = line.strip()
            if st.startswith("["):
                section = st
                if section.startswith("[profile"):
                    lines.append(st)
                continue
            if section.startswith("[profile") and st:
                lines.append(st)
            elif "dependencies" in section and keep_dep.match(st):
                lines.append(st)
        if lines:
            block = f"# {rel}\n" + "\n".join(lines) + "\n"
            if size + len(block) > max_chars:
                break
            parts.append(block)
            size += len(block)
    return "".join(parts)


BOUNDARY = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:fn|function|impl|modifier|struct|enum|#\[)\b"
                      r"|^\s*$")


def split_code(text: str, limit: int) -> list[str]:
    """Split a large file into parts under `limit` chars, preferring to cut before a
    function/impl/attribute or at a blank line so functions stay whole where possible."""
    if len(text) <= limit:
        return [text]
    parts, cur = [], []
    size = 0
    for line in text.splitlines(keepends=True):
        if size + len(line) > limit and cur:
            # walk back to the last good boundary in the current part
            cut = next((i for i in range(len(cur) - 1, len(cur) // 2, -1) if BOUNDARY.match(cur[i])), None)
            if cut:
                parts.append("".join(cur[:cut]))
                cur = cur[cut:]
            else:
                parts.append("".join(cur))
                cur = []
            size = sum(len(l) for l in cur)
        cur.append(line)
        size += len(line)
    if cur:
        parts.append("".join(cur))
    return parts


def make_batches(repo: Path, files: list[Path], max_chars: int) -> list[list[tuple[str, str]]]:
    """Group files into batches that fit the model's context budget."""
    batches, cur, size = [], [], 0
    for f in files:
        text = (repo / f).read_text(errors="ignore")
        if f.suffix == ".rs":
            text = strip_rust_tests(text)
        pieces = split_code(text, max_chars - 200)
        if len(pieces) > 1:
            print(f"[*] {f} is large; reviewing it in {len(pieces)} parts")
        for n, piece in enumerate(pieces, 1):
            label = str(f) if len(pieces) == 1 else f"{f} (part {n}/{len(pieces)})"
            block = f"// ===== FILE: {label} =====\n{piece}\n"
            if cur and size + len(block) > max_chars:
                batches.append(cur)
                cur, size = [], 0
            cur.append((label, block))
            size += len(block)
    if cur:
        batches.append(cur)
    return batches


# ---------------------------------------------------------------- Slither

def run_slither(repo: Path, filter_paths: str) -> list[dict]:
    out = Path(tempfile.mkdtemp()) / "slither.json"
    cmd = ["slither", ".", "--json", str(out), "--filter-paths", filter_paths,
           "--exclude-informational", "--exclude-optimization"]
    print(f"[*] Running Slither in {repo} ...")
    try:
        proc = subprocess.run(cmd, cwd=repo, capture_output=True, text=True)
    except FileNotFoundError:
        print("[!] slither not found (pip install slither-analyzer); continuing without it")
        return []
    if not out.exists():
        print("[!] Slither produced no JSON. Last stderr lines:")
        print("\n".join(proc.stderr.strip().splitlines()[-15:]))
        return []
    data = json.loads(out.read_text())
    if not data.get("success"):
        print(f"[!] Slither reported an error: {data.get('error')}")
    findings = []
    for d in (data.get("results") or {}).get("detectors", []):
        files = sorted({
            el.get("source_mapping", {}).get("filename_relative", "")
            for el in d.get("elements", [])
        } - {""})
        findings.append({
            "check": d.get("check"),
            "impact": d.get("impact"),
            "confidence": d.get("confidence"),
            "description": (d.get("description") or "").strip(),
            "files": files,
        })
    print(f"[*] Slither: {len(findings)} findings (informational/optimization excluded)")
    return findings


# Slither detectors that are noise for bug hunting (style, info, or almost never exploitable).
SLITHER_SKIP = {
    "naming-convention", "solc-version", "pragma", "assembly", "low-level-calls", "similar-names",
    "too-many-digits", "dead-code", "unused-state", "costly-loop", "cache-array-length",
    "constable-states", "immutable-states", "external-function", "reentrancy-benign",
    "reentrancy-events", "reentrancy-unlimited-gas", "timestamp", "missing-zero-check",
    "events-access", "events-maths", "missing-inheritance", "shadowing-local", "shadowing-builtin",
    "shadowing-abstract", "boolean-equal", "redundant-statements", "unused-import", "cyclomatic-complexity",
    "void-cst", "calls-loop", "incorrect-modifier", "uninitialized-local", "unused-return", "divide-before-multiply",
}
SLITHER_IMPACT = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3, "Optimization": 4}


def select_slither(slither, names, budget):
    """Only high/medium-impact detectors, de-duplicated by check, cut to a character budget."""
    rel = [x for x in slither if (not x["files"] or names & set(x["files"]))
           and x.get("check") not in SLITHER_SKIP and x.get("impact") in ("High", "Medium")]
    rel.sort(key=lambda x: (SLITHER_IMPACT.get(x.get("impact"), 9), x.get("confidence") != "High"))
    out, size, per_check = [], 0, {}
    for x in rel:
        per_check[x["check"]] = per_check.get(x["check"], 0) + 1
        if per_check[x["check"]] > 3:          # the 4th "reentrancy-no-eth" adds nothing
            continue
        line = f"- [{x['impact']}/{x['confidence']}] {x['check']}: {x['description'][:400]}"
        if size + len(line) > budget:
            break
        out.append(line)
        size += len(line)
    dropped = len(rel) - len(out)
    return out, dropped


def build_user_prompt(batch, all_files, slither, docs, cargo, pmap="", slither_budget=3000) -> str:
    names = {name for name, _ in batch}
    parts = []
    if docs:
        parts.append("## Protocol documentation / intended behaviour\n" + docs.strip())
    if pmap:
        parts.append("## Project map (signatures in all in-scope files; code you can't see in full)\n" + pmap)
    else:
        parts.append("## All in-scope files in this project\n" + "\n".join(f"- {f}" for f in all_files))
    if cargo and any(n.endswith(".rs") for n in names):
        parts.append("## Cargo.toml files\n```toml\n" + cargo + "```")
    if any(n.endswith(".sol") for n in names) and slither:
        lines, dropped = select_slither(slither, names, slither_budget)
        if lines:
            parts.append("## Static-analysis hints for these files (Slither; most are false positives. "
                         "Do NOT restate a hint as a finding unless you can show a concrete exploit path)\n"
                         + "\n".join(lines)
                         + (f"\n- ... {dropped} more lower-priority hints omitted" if dropped else ""))
    parts.append("## Code under review\n" + "".join(block for _, block in batch))
    parts.append("Analyse the code under review and return the JSON object described in your instructions.")
    return "\n\n".join(parts)


# ---------------------------------------------------------------- verification

VERIFY_SYSTEM = """You are a senior smart contract auditor doing a second, skeptical review of ONE candidate
finding produced by a junior auditor who saw only part of the code. You now get the full source of the
relevant file(s) plus a map of the whole project. Decide whether the finding is real.

Check specifically:
- Is the claimed flaw actually in the code as written (not a paraphrase or a misread)?
- Is there a check elsewhere in the shown code (a caller, a modifier/guard, a require_auth, a math
  helper that rounds correctly, a cap) that already prevents the attack?
- Can the attack scenario really be executed by the stated actor with the stated inputs?
- Is the impact as claimed, or is it smaller/larger?

Respond with ONE JSON object:
{"verdict": "confirmed"|"rejected"|"unclear",
 "verified_severity": "critical"|"high"|"medium"|"low"|"none",
 "reason": "<2-4 sentences citing the exact code that confirms or refutes it>",
 "missing_context": "<what else you would need to see, if unclear>"}
Be strict: "confirmed" means you would stake your reputation on a report. Default to "unclear" when
the deciding code is not shown, and "rejected" when the shown code already prevents the attack."""


def norm_ws(t: str) -> str:
    return re.sub(r"\s+", " ", t).strip()


def ground(hyps: list[dict], code: str) -> None:
    """Mark whether each hypothesis's quoted evidence really appears in the code it reviewed."""
    flat = norm_ws(code)
    for h in hyps:
        ev = norm_ws(str(h.get("code_evidence", "")))
        if len(ev) < 12:
            h["grounded"] = False
            continue
        # try the whole quote, then each line (small models often merge/split lines)
        found = ev in flat
        if not found:
            lines = [norm_ws(l) for l in str(h.get("code_evidence", "")).splitlines() if len(norm_ws(l)) >= 12]
            found = bool(lines) and sum(l in flat for l in lines) >= max(1, len(lines) // 2)
        h["grounded"] = found


def locate_files(h: dict, files: list[Path]) -> list[Path]:
    """Files most likely to contain the hypothesis: by file path, then contract/module name, then function."""
    names = [str(f) for f in files]
    hits = []
    for key in ("file", "contract"):
        v = str(h.get(key, "")).strip()
        if not v:
            continue
        v_low = v.lower().replace("::", "/")
        for f, nm in zip(files, names):
            low = nm.lower()
            if v_low in low or low.endswith(v_low + ".rs") or low.endswith(v_low + ".sol") \
                    or Path(nm).stem.lower() == v_low or v_low in Path(nm).stem.lower().replace("_", ""):
                hits.append(f)
    return list(dict.fromkeys(hits))


def verify_one(h, repo, files, pmap, cargo, llm, budget) -> dict:
    fn = str(h.get("function", "")).split("(")[0].split(".")[-1].split("::")[-1].strip()
    cands = locate_files(h, files)
    if fn:
        for f in files:  # files that define or call the function
            try:
                text = (repo / f).read_text(errors="ignore")
            except OSError:
                continue
            if re.search(r"\bfn\s+" + re.escape(fn) + r"\b|\bfunction\s+" + re.escape(fn) + r"\b", text):
                cands.insert(0, f)
            elif fn in text:
                cands.append(f)
    cands = list(dict.fromkeys(cands))
    blocks, size = [], 0
    for f in cands:
        text = (repo / f).read_text(errors="ignore")
        if f.suffix == ".rs":
            text = strip_rust_tests(text)
        block = f"// ===== FILE: {f} =====\n{text}\n"
        if size + len(block) > budget:
            if not blocks:  # single huge file: keep the part around the function
                i = text.find(fn) if fn else 0
                lo = max(0, i - budget // 2)
                block = f"// ===== FILE: {f} (excerpt) =====\n{text[lo:lo + budget]}\n"
                blocks.append(block)
            break
        blocks.append(block)
        size += len(block)
    shown = [b.split("\n", 1)[0] for b in blocks]
    user = "\n\n".join(filter(None, [
        "## Candidate finding\n```json\n" + json.dumps(
            {k: h.get(k) for k in ("title", "severity", "confidence", "contract", "function", "vuln_class",
                                   "description", "code_evidence", "attack_scenario", "preconditions")},
            indent=1) + "\n```",
        "## Project map\n" + pmap if pmap else "",
        "## Cargo.toml\n```toml\n" + cargo + "```" if cargo else "",
        "## Relevant source\n" + ("".join(blocks) if blocks else "(no matching file found; judge from the map)"),
        "Verify the candidate and return the JSON object described in your instructions."]))
    out = dict(h)
    try:
        resp = llm(VERIFY_SYSTEM, user)
        obj = parse_json_object(resp)
    except requests.RequestException as e:
        obj = {"verdict": "unclear", "reason": f"verification call failed: {e}"}
    out["verdict"] = str(obj.get("verdict", "unclear")).lower()
    if out["verdict"] not in ("confirmed", "rejected", "unclear"):
        out["verdict"] = "unclear"
    vs = str(obj.get("verified_severity", "")).lower()
    if vs in SEV_SCORE or vs == "none":
        out["verified_severity"] = vs
    out["verify_reason"] = obj.get("reason", "")
    out["verify_files"] = shown
    if obj.get("missing_context"):
        out["missing_context"] = obj["missing_context"]
    return out


# ---------------------------------------------------------------- LLM backends

def with_retries(fn, attempts=3, wait=5):
    """Retry transient failures (network, 5xx, 429) with simple backoff."""
    def wrapped(*a, **kw):
        for i in range(attempts):
            try:
                return fn(*a, **kw)
            except requests.RequestException as e:
                status = getattr(getattr(e, "response", None), "status_code", None)
                if i == attempts - 1 or (status and 400 <= status < 500 and status != 429):
                    raise
                time.sleep(wait * (2 ** i))
    return wrapped


def parse_json_object(text: str) -> dict:
    text = re.sub(r"^```(?:json)?\s*|```\s*$", "", text.strip(), flags=re.M)
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text, re.S)
        try:
            obj = json.loads(m.group(0)) if m else {}
        except json.JSONDecodeError:
            obj = {}
    return obj if isinstance(obj, dict) else {}


TEMPERATURE = 0.2

# Ollama can constrain output to a JSON schema. Requiring the "hypotheses" key stops the model from
# collapsing to "{}" (the shortest valid JSON), which plain format=json allows and which happens a
# lot at higher temperature or with long prompts.
HYPOTHESES_SCHEMA = {
    "type": "object",
    "properties": {
        "hypotheses": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                    "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
                    "contract": {"type": "string"},
                    "function": {"type": "string"},
                    "vuln_class": {"type": "string"},
                    "description": {"type": "string"},
                    "code_evidence": {"type": "string"},
                    "attack_scenario": {"type": "array", "items": {"type": "string"}},
                    "preconditions": {"type": "string"},
                    "poc_plan": {"type": "string"},
                    "slither_refs": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["title", "severity", "confidence", "contract", "function", "vuln_class",
                             "description", "code_evidence", "attack_scenario"],
            },
        }
    },
    "required": ["hypotheses"],
}


def is_degenerate(resp: str) -> bool:
    """'{}' or similar: the model produced no answer at all (distinct from an empty list)."""
    t = re.sub(r"\s", "", resp or "")
    return t in ("", "{}", "[]", "null", '{"hypotheses":null}')


# Model families with a "thinking" mode. We turn it off: the reasoning block multiplies the time
# per call and the pipeline wants the structured answer, not a transcript.
THINKING_MODELS = re.compile(r"^(qwen3(?!-coder)|deepseek-r1|gpt-oss|magistral|phi4-reasoning|granite3\.3|cogito)", re.I)
THINK = False


def call_ollama(system, user, model, num_ctx, host, json_mode=True, schema=None, temperature=None) -> str:
    fmt = schema if (json_mode and schema) else ("json" if json_mode else None)
    if re.search(r"gpt-oss", model or "", re.I):
        extra = {"think": "low"}   # gpt-oss reasons enormously; cap it so content isn't starved of the budget
    elif THINKING_MODELS.match(model or ""):
        extra = {"think": THINK}
    else:
        extra = {}
    r = requests.post(f"{host}/api/chat", timeout=3600, json={
        "model": model,
        "stream": False,
        **extra,
        **({"format": fmt} if fmt else {}),
        "options": {"num_predict": 12288, "num_ctx": num_ctx, "temperature": TEMPERATURE if temperature is None else temperature},
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": user}],
    })
    r.raise_for_status()
    msg = r.json().get("message", {})
    content = msg.get("content") or ""
    if not content.strip():                 # reasoning models sometimes leave the answer in 'thinking'
        content = msg.get("thinking") or ""
    return content


def call_anthropic(system, user, model) -> str:
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        sys.exit("[!] Set ANTHROPIC_API_KEY to use the anthropic backend.")
    r = requests.post("https://api.anthropic.com/v1/messages", timeout=900, headers={
        "x-api-key": key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }, json={
        "model": model,
        "max_tokens": 8000,
        "system": system,
        "messages": [{"role": "user", "content": user}],
    })
    r.raise_for_status()
    return "".join(b.get("text", "") for b in r.json().get("content", []) if b.get("type") == "text")


def call_claude_code(system, user, model) -> str:
    """Run a one-shot prompt through the Claude Code CLI (`claude -p`), which bills to a
    Claude Pro/Max subscription instead of API credits. Tools are disabled, so it is a plain
    model call. Requires `claude` on PATH and `claude auth login` done once."""
    cmd = ["claude", "-p", "--bare", "--tools", "", "--max-turns", "1",
           "--no-session-persistence", "--permission-prompts", "none",
           "--output-format", "json", "--system-prompt", system]
    if model:
        cmd += ["--model", model]
    try:
        proc = subprocess.run(cmd, input=user, capture_output=True, text=True, timeout=1800)
    except FileNotFoundError:
        sys.exit("[!] `claude` CLI not found. Install Claude Code (https://code.claude.com/docs) "
                 "and run `claude auth login`, or use --backend anthropic / ollama.")
    except subprocess.TimeoutExpired:
        raise requests.ConnectionError("claude -p timed out")
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout).strip()[-600:]
        if "rate limit" in err.lower() or "usage limit" in err.lower() or "overloaded" in err.lower():
            raise requests.ConnectionError(f"claude -p: {err}")   # retried with backoff
        raise requests.HTTPError(f"claude -p failed (exit {proc.returncode}): {err}")
    out = proc.stdout.strip()
    try:
        obj = json.loads(out)
        if isinstance(obj, dict):
            if obj.get("is_error"):
                raise requests.ConnectionError(f"claude -p error: {str(obj.get('result'))[:300]}")
            return str(obj.get("result", ""))
        if isinstance(obj, list):   # stream-style array: last result message
            for m in reversed(obj):
                if isinstance(m, dict) and m.get("type") == "result":
                    return str(m.get("result", ""))
    except json.JSONDecodeError:
        pass
    return out


def check_claude_code():
    try:
        proc = subprocess.run(["claude", "auth", "status"], capture_output=True, text=True, timeout=30)
    except FileNotFoundError:
        sys.exit("[!] `claude` CLI not found. Install Claude Code and run `claude auth login`.")
    if proc.returncode != 0:
        sys.exit("[!] Claude Code is not signed in. Run: claude auth login")


BACKENDS = ("ollama", "anthropic", "claude-code")
DEFAULT_MODEL = {"ollama": "qwen2.5-coder:14b", "anthropic": "claude-sonnet-5-5", "claude-code": "sonnet"}


def llm_call(backend, system, user, model, num_ctx=16384, host="http://localhost:11434", json_mode=True,
             schema=None, temperature=None):
    """One entry point for every backend, with retries."""
    if backend == "ollama":
        return with_retries(call_ollama)(system, user, model, num_ctx, host, json_mode, schema, temperature)
    if backend == "anthropic":
        return with_retries(call_anthropic)(system, user, model)
    if backend == "claude-code":
        return with_retries(call_claude_code, attempts=4, wait=20)(system, user, model)
    raise ValueError(backend)


def check_backend(backend, host, model):
    if backend == "ollama":
        check_ollama(host, model)
    elif backend == "claude-code":
        check_claude_code()
    elif backend == "anthropic" and not os.environ.get("ANTHROPIC_API_KEY"):
        sys.exit("[!] Set ANTHROPIC_API_KEY to use the anthropic backend.")


def check_ollama(host, model):
    try:
        tags = requests.get(f"{host}/api/tags", timeout=5).json()
    except requests.RequestException:
        sys.exit(f"[!] Can't reach Ollama at {host}. Start it with `ollama serve` "
                 f"(or install it: curl -fsSL https://ollama.com/install.sh | sh).")
    names = {m.get("name") for m in tags.get("models", [])}
    if model not in names and f"{model}:latest" not in names:
        sys.exit(f"[!] Model {model} isn't pulled. Run: ollama pull {model}")
    try:
        ver = requests.get(f"{host}/api/version", timeout=5).json().get("version", "0")
        if tuple(int(x) for x in re.findall(r"\d+", ver)[:2]) < (0, 5):
            print(f"[!] Ollama {ver} is older than 0.5 and can't enforce a JSON schema; empty '{{}}' answers "
                  f"will be retried but not prevented. Consider `curl -fsSL https://ollama.com/install.sh | sh` to update.")
    except Exception:  # noqa
        pass


def parse_hypotheses(text: str) -> list[dict]:
    text = re.sub(r"^```(?:json)?\s*|```\s*$", "", text.strip(), flags=re.M)
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text, re.S)
        if not m:
            return []
        try:
            obj = json.loads(m.group(0))
        except json.JSONDecodeError:
            return []
    items = obj if isinstance(obj, list) else obj.get("hypotheses", [])
    return [h for h in items if isinstance(h, dict) and h.get("title")]


# ---------------------------------------------------------------- ranking / report

# Claims small models make reflexively. They only count when a static check backs them up.
GENERIC_CLASSES = {
    "auth": r"authoriz|authentic|access control|permission|unprotected|onlyowner|only admin|admin check|signer|caller check",
    "overflow": r"overflow|underflow|wrap|truncat",
    "reentrancy": r"reentran",
    "unchecked": r"unchecked (return|result|call)|return value|call result|try_invoke",
    "generic_dos": r"denial of service|\bdos\b|gas limit|out of gas",
}


MISSING_CLAIM = re.compile(r"\b(no|missing|lack of|lacks|insufficient|without|does not|doesn't|not)\b.{0,40}"
                           r"\b(valid|check|verif|require|ensur|guard|handl)|\bunchecked\b|\bunvalidated\b", re.I)
GUARD_LINE = re.compile(r"\brequire\s*\(|\brevert\b|\bassert\s*\(|\bif\s*\(.*\)\s*(?:revert|throw|return false)|"
                        r"\?\s*;|\?\s*$|\brequire!|\bensure!|\bassert!|\.expect\(|\bok_or\b|\bunwrap_or\b|"
                        r"\b(?:only|when)[A-Z]\w*\b|\bmodifier\b|safeTransfer|SafeERC20", re.M)


def self_refuting(h: dict) -> bool:
    """'X is not checked' while the quoted evidence IS the check (a require/revert/?/assert on X)."""
    text = f"{h.get('title', '')} {h.get('description', '')[:300]}"
    ev = str(h.get("code_evidence", ""))
    return bool(MISSING_CLAIM.search(text) and GUARD_LINE.search(ev))


def claim_kind(h: dict) -> str | None:
    text = f"{h.get('title', '')} {h.get('vuln_class', '')}".lower()
    for kind, pat in GENERIC_CLASSES.items():
        if re.search(pat, text):
            return kind
    return None


def score(h: dict) -> float:
    """Rank by evidence, not by the model's self-reported severity.
    The model's severity/confidence are nearly uninformative for small models; what predicts a
    real finding is: a real quote, being raised independently more than once, a specific function
    that exists, a concrete multi-step scenario, and not being a reflexive generic claim that a
    static check already contradicts."""
    v = h.get("verdict")
    base = 1.0
    base *= 1.0 if h.get("grounded") else 0.35
    if h.get("seen", 1) > 1:
        base *= 1.6
    if h.get("samples_seen", 1) > 1:
        base *= 1.0 + 0.7 * (h["samples_seen"] - 1)      # independently reproduced: strong signal
    if h.get("raised", 1) > 2:
        base *= 1.2
    if h.get("fn_exists"):
        base *= 1.4
    steps = h.get("attack_scenario") or []
    if isinstance(steps, list) and len(steps) >= 3:
        base *= 1.25
    if len(str(h.get("description", ""))) > 300:
        base *= 1.1
    if h.get("self_refuting"):
        base *= 0.15                       # evidence quotes the very guard the claim says is missing
    kind = claim_kind(h)
    if kind:
        base *= 0.45                       # reflexive claim class
        if h.get("auth_present"):
            base *= 0.25                   # "missing auth" but the function checks auth
        if h.get("overflow_checked"):
            base *= 0.3                    # "overflow" but overflow-checks = true (panics, no wrap)
    sev = h.get("verified_severity") if v == "confirmed" and h.get("verified_severity") in SEV_SCORE \
        else str(h.get("severity", "")).lower()
    base *= {"critical": 1.2, "high": 1.15, "medium": 1.0, "low": 0.7}.get(sev, 0.8)
    w = VERIFY_WEIGHTS[VERIFY_TRUST]
    if v == "confirmed":
        base *= w["confirmed"]
    elif v == "rejected":
        base *= w["rejected"]
    elif v == "unclear":
        base *= w["unclear"]
    return base


# How much a verifier verdict moves the ranking. A small local model rejects most real findings
# too (measured on K2: 9 of 9 real hits it saw), so its "rejected" is nearly noise. A strong
# model's verdict is worth acting on.
VERIFY_WEIGHTS = {
    "weak":   {"confirmed": 1.6, "rejected": 0.7, "unclear": 1.0},
    "strong": {"confirmed": 3.0, "rejected": 0.1, "unclear": 0.9},
}
VERIFY_TRUST = "weak"


AUTH_TOKENS = re.compile(
    r"require_auth|require_admin|require_owner|only_admin|only_owner|onlyOwner|onlyAdmin|onlyRole|"
    r"_checkOwner|_checkRole|hasRole|has_role|is_admin|check_admin|assert_admin|ensure_admin|"
    r"verify_admin|assert_owner|ensure_owner|check_role|ensure_role|msg\.sender\s*==|"
    r"info\.sender\s*[!=]=|predecessor_account_id|env::signer|Signer<|is_signer|"
    r"\b(?:require|ensure|check|verify|assert|validate|authorize|authenticate|only|enforce)_?(?:auth|admin|owner|role|caller|sender|access|permission|authorized|emergency|configurator|router|pool|governance|manager|operator|guardian)\w*\s*\(", re.I)


_BODY_CACHE: dict[int, list[tuple[str, str]]] = {}


def _index(all_text: str) -> list[tuple[str, str]]:
    key = id(all_text)
    if key not in _BODY_CACHE:
        bodies = []
        for m in re.finditer(DEF_RE + r"(\w+)\b[^{;]*\{", all_text, re.M):
            b = function_body(all_text[m.start():], m.group(1))
            if b:
                bodies.append((m.group(1), b))
        _BODY_CACHE[key] = bodies
    return _BODY_CACHE[key]


def all_defs(all_text: str, fn: str) -> list[str]:
    """Every definition of a function called `fn` (entry point + same-named impl in another module)."""
    return [b for name, b in _index(all_text) if name == fn]


def all_bodies(all_text: str, fn: str) -> list[str]:
    """Bodies of every function that calls `fn`."""
    pat = re.compile(r"\b" + re.escape(fn) + r"\s*\(")
    return [b for name, b in _index(all_text) if name != fn and pat.search(b)]


def checks_auth(body: str, all_text: str, fn: str) -> bool:
    """Does this body check authorization, directly or through something it calls (one level,
    including a same-named implementation in another module that it delegates to)?"""
    if AUTH_TOKENS.search(body):
        return True
    for callee in set(re.findall(r"\b([a-z_][a-z0-9_]*)\s*\(", body)):
        for cb in all_defs(all_text, callee):
            if cb is not body and cb != body and AUTH_TOKENS.search(cb):
                return True
    return False


def is_entry_point(all_text: str, fn: str) -> bool:
    """Roughly: can an external transaction call this function directly?
    Soroban: pub fn inside a #[contractimpl] impl. Solidity: public/external function.
    Anchor: pub fn inside #[program]. CosmWasm: execute/instantiate/query..."""
    for m in re.finditer(r"#\[contractimpl\]\s*impl\b[^{]*\{", all_text):
        i, depth = m.end(), 1
        while i < len(all_text) and depth:
            depth += {"{": 1, "}": -1}.get(all_text[i], 0)
            i += 1
        if re.search(r"\bpub\s+fn\s+" + re.escape(fn) + r"\b", all_text[m.end():i]):
            return True
    if re.search(r"#\[program\][\s\S]{0,20000}?\bpub\s+fn\s+" + re.escape(fn) + r"\b", all_text):
        return True
    if re.search(r"^[ \t]*function\s+" + re.escape(fn) + r"\b[^{;]*\b(public|external)\b", all_text, re.M):
        return True
    return fn in ("execute", "instantiate", "query", "migrate", "reply", "sudo")


DEF_RE = r"^[ \t]*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+|unsafe\s+|const\s+|extern\s+\"C\"\s+)*(?:fn|function|modifier)\s+"


def strip_comments(text: str) -> str:
    """Remove // and /* */ comments (keeps line structure) so words like 'function' in
    doc comments don't look like definitions."""
    text = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def function_body(text: str, fn: str) -> str | None:
    m = re.search(DEF_RE + re.escape(fn) + r"\b[^{;]*\{", text, re.M)
    if not m:
        return None
    i, depth = m.end(), 1
    while i < len(text) and depth:
        depth += {"{": 1, "}": -1}.get(text[i], 0)
        i += 1
    return text[m.start():i]


def static_checks(hyps: list[dict], repo: Path, files: list[Path], overflow_checked: bool) -> None:
    """Cheap facts the ranking can use: does the named function exist, does it (or a direct callee)
    check authorization, is overflow checking on."""
    sources = {}
    for f in files:
        try:
            t = (repo / f).read_text(errors="ignore")
        except OSError:
            continue
        sources[f] = strip_comments(strip_rust_tests(t) if f.suffix == ".rs" else t)
    all_text = "\n".join(sources.values())
    for h in hyps:
        fn = str(h.get("function", "")).split("(")[0].split("::")[-1].split(".")[-1].strip()
        h["overflow_checked"] = bool(overflow_checked and claim_kind(h) == "overflow")
        h["self_refuting"] = self_refuting(h)
        if not fn or not re.match(r"^[A-Za-z_]\w*$", fn):
            h["fn_exists"] = False
            continue
        body = None
        for f in locate_files(h, files) + list(files):
            body = function_body(sources.get(f, ""), fn)
            if body:
                break
        h["fn_exists"] = body is not None
        if body is None or claim_kind(h) != "auth":
            continue
        has = any(checks_auth(b, all_text, fn) for b in (all_defs(all_text, fn) or [body]))
        if not has and not is_entry_point(all_text, fn):
            # Not an entry point: the callers are what matter. If every caller checks auth
            # (directly or via a helper), the claim is moot.
            callers = all_bodies(all_text, fn)
            if callers:
                has = all(checks_auth(cb, all_text, fn) for cb in callers)
                h["internal_fn"] = True
        h["auth_present"] = has


STOP = {"the", "a", "an", "of", "in", "to", "and", "or", "for", "is", "can", "be", "via", "with",
        "by", "on", "not", "no", "missing", "incorrect", "wrong", "lack", "due", "when", "that"}


def _norm_name(v: str) -> str:
    v = str(v or "").lower().strip()
    v = v.split("(")[0].split("::")[-1].split(".")[-1]
    return re.sub(r"[^a-z0-9]", "", v)


def _tokens(h: dict) -> set[str]:
    text = f"{h.get('title', '')} {h.get('vuln_class', '')}".lower()
    return {t for t in re.findall(r"[a-z0-9_]+", text) if t not in STOP and len(t) > 2}


def dedupe(hyps: list[dict]) -> list[dict]:
    """Merge hypotheses that describe the same bug: same function (or contract) and overlapping
    title/class words. Keeps the strongest version and counts how many times it was raised."""
    groups: list[dict] = []
    for h in hyps:
        fn, ct, toks = _norm_name(h.get("function")), _norm_name(h.get("contract")), _tokens(h)
        target = None
        for g in groups:
            same_place = (fn and fn == g["fn"]) or (not fn and ct == g["ct"])
            if not same_place:
                continue
            overlap = len(toks & g["toks"]) / max(1, min(len(toks), len(g["toks"])))
            if overlap >= 0.5 or _norm_name(h.get("vuln_class")) == _norm_name(g["best"].get("vuln_class")):
                target = g
                break
        if target is None:
            groups.append({"fn": fn, "ct": ct, "toks": toks, "best": dict(h), "n": 1,
                           "passes": {h.get("pass", "all")}, "samples": {h.get("sample", 0)}})
        else:
            target["n"] += 1
            target["passes"].add(h.get("pass", "all"))
            target["samples"].add(h.get("sample", 0))
            target["toks"] |= toks
            if score(h) > score(target["best"]):
                target["best"] = dict(h)
    out = []
    for g in groups:
        b = g["best"]
        b["seen"] = len(g["passes"]) if len(g["passes"]) > 1 else 1
        b["samples_seen"] = len(g["samples"])
        b["raised"] = g["n"]
        out.append(b)
    return sorted(out, key=score, reverse=True)


def write_report(hyps: list[dict], path: Path):
    verified = any("verdict" in h for h in hyps)
    lines = ["# Audit hypotheses\n",
             "LLM output. Every item still needs a passing PoC test before it is a finding.\n"]
    counts = {}
    for h in hyps:
        counts[h.get("verdict", "unverified")] = counts.get(h.get("verdict", "unverified"), 0) + 1
    lines.append("Summary: " + ", ".join(f"{v} {k}" for k, v in counts.items())
                 + f"; {sum(1 for h in hyps if h.get('grounded') is False)} with evidence not found in code.\n")
    order = {"confirmed": 0, "unclear": 1, "unverified": 1, "rejected": 2}
    hyps = sorted(hyps, key=lambda h: (order.get(h.get("verdict", "unverified"), 1), -score(h)))
    section = None
    for i, h in enumerate(hyps, 1):
        v = h.get("verdict", "unverified")
        if verified and v != section:
            section = v
            lines.append(f"\n# {section.upper()}\n")
        sev = h.get("verified_severity") if v == "confirmed" and h.get("verified_severity") in SEV_SCORE else h.get("severity", "?")
        flags = []
        if h.get("grounded") is False:
            flags.append("evidence not found in code")
        if h.get("seen", 1) > 1:
            flags.append(f"raised in {h['seen']} passes")
        if h.get("samples_seen", 1) > 1:
            flags.append(f"reproduced in {h['samples_seen']} samples")
        if h.get("auth_present"):
            flags.append("function already checks auth")
        if h.get("overflow_checked"):
            flags.append("overflow-checks is on")
        if h.get("fn_exists") is False:
            flags.append("function not found")
        if h.get("self_refuting"):
            flags.append("evidence is the check itself")
        lines.append(f"## {i}. [{str(sev).upper()} / conf {h.get('confidence','?')}] {h['title']}"
                     + (f"  _({'; '.join(flags)})_" if flags else ""))
        lines.append(f"**Location:** `{h.get('contract','?')}.{h.get('function','?')}`  ")
        lines.append(f"**Class:** {h.get('vuln_class','?')}  ")
        if h.get("code_evidence"):
            lines.append(f"\n```\n{str(h['code_evidence']).strip()}\n```")
        if h.get("verify_reason"):
            lines.append(f"\n**Verifier ({v}):** {h['verify_reason']}  ")
            if h.get("verify_files"):
                lines.append(f"**Verifier saw:** {', '.join(x.replace('// ===== FILE: ', '').replace(' =====', '') for x in h['verify_files'])}  ")
            if h.get("missing_context"):
                lines.append(f"**Still needs:** {h['missing_context']}  ")
        if h.get("slither_refs"):
            lines.append(f"**Slither:** {', '.join(map(str, h['slither_refs']))}  ")
        lines.append(f"\n{h.get('description','')}\n")
        steps = h.get("attack_scenario") or []
        if isinstance(steps, str):
            steps = [steps]
        if steps:
            lines.append("**Attack scenario:**")
            lines += [f"{n}. {s}" for n, s in enumerate(steps, 1)]
        if h.get("preconditions"):
            lines.append(f"\n**Preconditions:** {h['preconditions']}")
        if h.get("poc_plan"):
            lines.append(f"\n**PoC plan:** {h['poc_plan']}")
        lines.append("")
    path.write_text("\n".join(lines))


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description="Smart-contract vulnerability hypothesis generator")
    ap.add_argument("repo", type=Path, help="Path to the project")
    ap.add_argument("--lang", choices=["auto", "solidity", "rust", "both"], default="auto")
    ap.add_argument("--src", nargs="+", help="In-scope source dirs (default: src/ and contracts/ "
                    "for Solidity, whole repo for Rust)")
    ap.add_argument("--scope-file", type=Path, help="File listing in-scope paths, one per line "
                    "(default: the repo's scope.txt if it has one and --src isn't given)")
    ap.add_argument("--docs", type=Path, help="Markdown/text file describing the protocol")
    ap.add_argument("--backend", choices=BACKENDS, default="ollama",
                    help="ollama (local GPU), anthropic (API key, pay per token), "
                         "claude-code (Claude Code CLI on a Pro/Max subscription)")
    ap.add_argument("--model", help="Model name (default depends on backend)")
    ap.add_argument("--ollama-host", default="http://localhost:11434")
    ap.add_argument("--num-ctx", type=int, default=16384, help="Ollama context window (tokens)")
    ap.add_argument("--max-chars", type=int, help="Code chars per LLM call (default depends on backend)")
    ap.add_argument("--filter-paths", default=r"(^|/)(lib|libs|node_modules|test|tests|script|scripts|mocks?)/",
                    help="Regex of paths Slither should ignore (anchored to whole folder names, so a "
                         "parent folder called e.g. 'contests' is not matched by 'test')")
    ap.add_argument("--no-slither", action="store_true", help="Skip Slither")
    ap.add_argument("--protocol", nargs="+", default=["auto"],
                    help=f"Protocol type(s) for bug checklists: auto, none, or {', '.join(PROTOCOLS)}")
    ap.add_argument("--passes", nargs="+", default=list(PASSES),
                    help=f"Focused review passes per batch (default: all of {', '.join(PASSES)}). "
                         f"Use 'all' for a single unfocused pass.")
    ap.add_argument("--no-map", action="store_true", help="Don't include the project map")
    ap.add_argument("--map-chars", type=int, help="Max chars for the project map")
    ap.add_argument("--verify", action="store_true",
                    help="Second pass: re-check each hypothesis against the full relevant file(s)")
    ap.add_argument("--verify-model", help="Model for the verify pass (default: same as --model)")
    ap.add_argument("--verify-backend", choices=BACKENDS,
                    help="Backend for the verify pass (default: same as --backend). "
                         "E.g. audit locally, verify with claude-code.")
    ap.add_argument("--verify-top", type=int, default=0,
                    help="Only verify the N highest-ranked hypotheses (0 = all)")
    ap.add_argument("--verify-trust", choices=["auto", "weak", "strong"], default="auto",
                    help="How much verifier verdicts move the ranking. auto: weak for ollama, "
                         "strong for anthropic/claude-code")
    ap.add_argument("--drop-ungrounded", action="store_true",
                    help="Discard hypotheses whose quoted code_evidence isn't in the code (default: keep, down-rank)")
    ap.add_argument("--max-hyps", type=int, default=8, help="Max candidates the model may return per call")
    ap.add_argument("--samples", type=int, default=1,
                    help="Ask each batch/pass N times and merge. Bugs raised in several independent "
                         "samples rank higher. 2-3 is a good trade-off.")
    ap.add_argument("--temperature", type=float, help="Sampling temperature (default 0.2, or 0.5 with --samples > 1)")
    ap.add_argument("--think", action="store_true",
                    help="Let thinking models (qwen3, deepseek-r1, ...) reason before answering. Much slower.")
    ap.add_argument("--workers", type=int, help="Parallel LLM calls (default 1 for ollama, 4 for anthropic)")
    ap.add_argument("--fresh", action="store_true", help="Ignore saved responses in --out/raw and re-ask")
    ap.add_argument("--out", type=Path, default=Path("audit_out"))
    ap.add_argument("--dry-run", action="store_true", help="Write prompts only, no LLM calls")
    args = ap.parse_args()

    global MAX_HYPS, TEMPERATURE, THINK
    MAX_HYPS = args.max_hyps
    THINK = bool(args.think)
    TEMPERATURE = args.temperature if args.temperature is not None else (0.2 if args.samples <= 1 else 0.5)
    repo = args.repo.resolve()
    if not repo.is_dir():
        sys.exit(f"[!] {repo} is not a directory")
    scope_file = args.scope_file or (repo / "scope.txt" if not args.src and (repo / "scope.txt").is_file() else None)
    scoped = read_scope_file(repo, scope_file) if scope_file else []
    if scope_file and not scoped:
        print(f"[!] {scope_file} listed no .sol/.rs files that exist; ignoring it")
    if args.lang != "auto":
        lang = args.lang
    elif scoped:
        kinds = {f.suffix for f in scoped}
        lang = "both" if len(kinds) > 1 else ("rust" if ".rs" in kinds else "solidity")
    else:
        lang = detect_lang(repo)
    langs = {"solidity", "rust"} if lang == "both" else {lang}
    model = args.model or DEFAULT_MODEL[args.backend]
    max_chars = args.max_chars or (args.num_ctx * 2 if args.backend == "ollama" else 400_000)
    if not args.dry_run:
        check_backend(args.backend, args.ollama_host, model)
    args.out.mkdir(parents=True, exist_ok=True)
    raw_dir = args.out / "raw"
    raw_dir.mkdir(exist_ok=True)

    docs = args.docs.read_text(errors="ignore") if args.docs else ""
    if scoped:
        files = [f for f in scoped if f.suffix in (EXTS["solidity"] + EXTS["rust"] if lang == "both" else EXTS[lang])]
        print(f"[*] Using scope list {scope_file}")
    else:
        files = collect_sources(repo, args.src if args.src else DEFAULT_SRC[lang], lang)
    if not files:
        sys.exit(f"[!] No in-scope {lang} files found. Check --src / --lang.")
    print(f"[*] Language: {lang} | {len(files)} in-scope files")

    run_sl = "solidity" in langs and not args.no_slither and any(f.suffix == ".sol" for f in files)
    slither = run_slither(repo, args.filter_paths) if run_sl else []
    (args.out / "slither.json").write_text(json.dumps(slither, indent=2))
    cargo = cargo_context(repo) if "rust" in langs else ""

    # protocol type -> bug checklist
    if args.protocol == ["auto"]:
        sample = docs + "\n" + "\n".join((repo / f).read_text(errors="ignore")[:4000] for f in files[:40])
        protocols = detect_protocols(sample, max_n=1 if args.backend == "ollama" else 2)
    elif args.protocol == ["none"]:
        protocols = []
    else:
        protocols = [p for p in args.protocol if p in PROTOCOLS]
    print(f"[*] Protocol checklist(s): {', '.join(protocols) or 'none'}")

    # project map: ~20% of the budget locally, more on the API
    pmap = ""
    if not args.no_map:
        map_budget = args.map_chars or (max_chars * 15 // 100 if args.backend == "ollama" else 60_000)
        pmap = project_map(repo, files, map_budget)
        print(f"[*] Project map: {len(pmap):,} chars")

    passes = [None] if args.passes == ["all"] else [p for p in args.passes if p in PASSES]

    # keep docs to ~20% of each call locally (condensed once if longer)
    if docs:
        llm = lambda sy, us: llm_call(args.backend, sy, us, model, args.num_ctx, args.ollama_host, json_mode=False)
        docs = condense_docs(docs, max_chars * 15 // 100 if args.backend == "ollama" else 80_000,
                             llm, args.out, args.dry_run)
        print(f"[*] Docs in each prompt: {len(docs):,} chars")

    sys_len = max(len(system_prompt(langs, protocols, p)) for p in passes)
    slither_budget = min(3000, max_chars // 10) if slither else 0
    budget = max(max_chars - sys_len - len(docs) - len(cargo) - len(pmap) - slither_budget - 1500, 4000)
    if budget < max_chars // 4:
        print(f"[!] Docs + map leave only {budget:,} chars for code per call. Consider a shorter "
              f"--docs file, --map-chars, or a bigger --num-ctx.")
    batches = make_batches(repo, files, budget)
    total = len(batches) * len(passes) * args.samples
    print(f"[*] {len(batches)} batch(es) x {len(passes)} pass(es) x {args.samples} sample(s) = {total} "
          f"LLM call(s) using {args.backend}:{model} (temperature {TEMPERATURE})")
    workers = args.workers or {"ollama": 1, "anthropic": 4, "claude-code": 2}[args.backend]

    def ask(system, user, mdl, schema=None, temperature=None):
        return llm_call(args.backend, system, user, mdl, args.num_ctx, args.ollama_host,
                        schema=schema, temperature=temperature)

    degenerate = {"n": 0, "saved": 0}

    jobs = []
    for i, batch in enumerate(batches, 1):
        user = build_user_prompt(batch, [str(f) for f in files], slither, docs, cargo, pmap, slither_budget)
        code = "".join(block for _, block in batch)
        for pname in passes:
            system = system_prompt(langs, protocols, pname)
            base_tag = f"{i:02d}" + (f"_{pname}" if pname else "")
            (raw_dir / f"prompt_{base_tag}.md").write_text(system + "\n\n---\n\n" + user)
            if len(system) + len(user) > max_chars * 1.05:
                print(f"[!] Prompt {base_tag} is {len(system) + len(user):,} chars, over the {max_chars:,} "
                      f"budget; the model may not see all of it")
            for k in range(args.samples):
                tag = base_tag + (f"_s{k}" if k else "")
                jobs.append((i, pname, tag, system, user, code, batch, k))

    if args.dry_run:
        print(f"[*] Dry run: prompts written to {raw_dir}")
        return

    def run_job(job):
        i, pname, tag, system, user, code, batch, k = job
        resp_file = raw_dir / f"response_{tag}.txt"
        resumed = False
        if resp_file.exists() and not args.fresh:
            resp, resumed = resp_file.read_text(), True
            if is_degenerate(resp) or (not parse_hypotheses(resp) and '"hypotheses"' not in resp):
                resumed = False      # saved response was "{}" or garbage; ask again
                degenerate["saved"] += 1
        if not resumed:
            try:
                resp = ask(system, user, model, schema=HYPOTHESES_SCHEMA)
                # "{}" / garbage: the model produced nothing. Retry cooler, then once more plain.
                for attempt, temp in ((1, 0.2), (2, 0.1)):
                    if not (is_degenerate(resp) or (not parse_hypotheses(resp) and '"hypotheses"' not in resp)):
                        break
                    degenerate["n"] += 1
                    resp = ask(system, user + "\n\nReturn ONLY the JSON object with the \"hypotheses\" "
                               "array (it may be empty).", model, schema=HYPOTHESES_SCHEMA, temperature=temp)
            except requests.RequestException as e:
                return job, None, f"LLM call failed: {e}"
            resp_file.write_text(resp)
        hyps = parse_hypotheses(resp)
        ground(hyps, code)
        for h in hyps:
            h["pass"] = pname or "all"
            h["sample"] = k
            h["batch_files"] = [nm for nm, _ in batch]
        return job, hyps, "resumed" if resumed else ""

    all_hyps, done = [], 0
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for job, hyps, note in ex.map(run_job, jobs):
            done += 1
            i, pname, k = job[0], job[1], job[7]
            label = f"[*] Call {done}/{total} (batch {i}, pass {pname or 'all'}" + (f", sample {k + 1}" if args.samples > 1 else "") + ")"
            if hyps is None:
                print(f"{label}: [!] {note}")
                continue
            ung = sum(1 for h in hyps if not h.get("grounded"))
            print(f"{label}: {len(hyps)} hypotheses" + (f", {ung} with evidence not in code" if ung else "")
                  + (" (resumed)" if note else ""))
            all_hyps += hyps

    if degenerate["n"] or degenerate["saved"]:
        print(f"[*] Degenerate '{{}}' answers: {degenerate['saved']} found in saved responses and re-asked, "
              f"{degenerate['n']} retried during this run")
    if args.drop_ungrounded:
        before = len(all_hyps)
        all_hyps = [h for h in all_hyps if h.get("grounded")]
        print(f"[*] Dropped {before - len(all_hyps)} ungrounded hypotheses")

    ranked = dedupe(all_hyps)
    overflow_on = bool(re.search(r"overflow-checks\s*=\s*true", cargo))
    static_checks(ranked, repo, files, overflow_on)
    ranked.sort(key=score, reverse=True)
    n_auth = sum(1 for h in ranked if h.get("auth_present"))
    n_ovf = sum(1 for h in ranked if h.get("overflow_checked"))
    n_gen = sum(1 for h in ranked if claim_kind(h))
    n_self = sum(1 for h in ranked if h.get("self_refuting"))
    print(f"[*] {n_self} self-refuting claims (evidence quotes the guard said to be missing) pushed down")
    print(f"[*] {len(all_hyps)} raw -> {len(ranked)} distinct hypotheses; {n_gen} generic-class claims, "
          f"{n_auth} 'missing auth' where the function checks auth, {n_ovf} overflow claims with "
          f"overflow-checks on")

    if args.verify and ranked:
        global VERIFY_TRUST
        vbackend = args.verify_backend or args.backend
        VERIFY_TRUST = args.verify_trust if args.verify_trust != "auto" else ("weak" if vbackend == "ollama" else "strong")
        print(f"[*] Verifier trust: {VERIFY_TRUST} (rejected x{VERIFY_WEIGHTS[VERIFY_TRUST]['rejected']}, "
              f"confirmed x{VERIFY_WEIGHTS[VERIFY_TRUST]['confirmed']})")
        vmodel = args.verify_model or (model if vbackend == args.backend else DEFAULT_MODEL[vbackend])
        if vbackend != args.backend or args.verify_model:
            check_backend(vbackend, args.ollama_host, vmodel)
        vmax = args.num_ctx * 2 if vbackend == "ollama" else 400_000
        vbudget = max(vmax - len(VERIFY_SYSTEM) - len(pmap) - len(cargo) - 3000, 4000)
        vworkers = args.workers or {"ollama": 1, "anthropic": 4, "claude-code": 2}[vbackend]
        to_verify = ranked[:args.verify_top] if args.verify_top else ranked
        skipped = ranked[len(to_verify):]
        print(f"[*] Verifying {len(to_verify)} of {len(ranked)} hypotheses with {vbackend}:{vmodel} ...")
        vdir = args.out / "verify"
        vdir.mkdir(exist_ok=True)

        def verify_job(ih):
            idx, h = ih
            cache = vdir / f"{idx:03d}.json"
            if cache.exists() and not args.fresh:
                saved = json.loads(cache.read_text())
                if saved.get("title") == h.get("title"):
                    return idx, saved
            res = verify_one(h, repo, files, pmap, cargo,
                             lambda sy, us: llm_call(vbackend, sy, us, vmodel, args.num_ctx, args.ollama_host),
                             vbudget)
            cache.write_text(json.dumps(res, indent=2))
            return idx, res

        verified = [None] * len(to_verify)
        with ThreadPoolExecutor(max_workers=vworkers) as ex:
            for n, (idx, res) in enumerate(ex.map(verify_job, enumerate(to_verify)), 1):
                verified[idx] = res
                print(f"    [{n}/{len(to_verify)}] {res['verdict']:9} {str(res.get('title'))[:70]}")
        ranked = sorted(verified + skipped, key=score, reverse=True)
        c = {k: sum(1 for h in ranked if h.get("verdict") == k) for k in ("confirmed", "unclear", "rejected")}
        print(f"[*] Verified: {c['confirmed']} confirmed, {c['unclear']} unclear, {c['rejected']} rejected")
    (args.out / "findings.json").write_text(json.dumps(ranked, indent=2))
    write_report(ranked, args.out / "report.md")
    print(f"[*] {len(ranked)} ranked hypotheses -> {args.out/'report.md'}")
    for h in ranked[:8]:
        tag = h.get("verdict", "")
        print(f"    [{str(h.get('severity','?')).upper():8}]{(' ' + tag) if tag else ''} {h['title']}")


if __name__ == "__main__":
    main()
