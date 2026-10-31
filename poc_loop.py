#!/usr/bin/env python3
"""
poc_loop.py - Make the model PROVE a finding: it writes a Foundry test, `forge test` decides.

  # ceiling: can the model write a passing PoC for the REAL findings? (dev contests)
  python poc_loop.py contests/sukukfi --truth truth/sukukfi.html --out poc_sukukfi_truth

  # real use: try to prove the top-N hypotheses from an audit run
  python poc_loop.py contests/sukukfi --hypotheses runs_dev9/sukukfi/findings.json --top 15 --out poc_sukukfi

How it works (v2):
  * The PoC EXTENDS one of the project's own test contracts, so its setUp() (deployments, proxies,
    KYC, roles, funded users, signer keys) is inherited and correct by construction. The model only
    writes the attack: `test_PoC()` plus any helper contract it needs.
  * The model marks the attack lines with `// ATTACK-START` / `// ATTACK-END`. When a test passes,
    the loop removes those lines and runs it again: if it STILL passes, the assertions did not
    depend on the attack and the result is downgraded (pass_no_control).
  * Failures come back with the forge call trace (which call reverted, with what), not just the
    error name. Compile errors come back with the offending lines quoted.
  * --samples N asks for N candidates per round (higher temperature) and keeps the first that passes.

Outcomes:  pass              passed, and failed once the attack was removed (a real proof - still read it)
           pass_no_control   passed with AND without the attack (or without the malicious setup):
                             the assertions do not depend on the exploit
           pass_unverified   passed, but the control run could not be done (no markers / didn't compile)
           fail              compiled and ran; assertion failed or reverted (claim not demonstrated)
           compile_error     never compiled within --tries
           setup_error       the inherited setUp() reverted (fork, env) - tried every parent
           no_assert         passed but asserts nothing
           not_demonstrable  the model said it needs state it cannot set up
Results: <out>/results.json, <out>/summary.md, <out>/PoC_<n>*.t.sol (every attempt kept).
The contest's test folder is left as it was.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from audit_assist import BACKENDS, DEFAULT_MODEL, check_backend, llm_call
try:
    from assert_pass import flag_powers, impact_mismatch
except Exception:
    flag_powers = lambda code: []
    impact_mismatch = lambda code, impact: []
from build_dataset import LINK, file_index, resolve
from eval_audit import parse_truth
import eval_audit as _ea


class _HtmlToMdWithCode(_ea._HtmlToMd):
    """Reports saved from the website keep their code in <pre>; the base converter flattened it into
    plain text, so report PoCs were invisible (every dev finding looked like 'no PoC in report').
    Emit fenced ```solidity blocks for <pre> instead."""
    def handle_starttag(self, tag, attrs):
        if tag == "pre":
            self.out.append("\n```solidity\n")
            self.in_pre = True
        else:
            super().handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if tag == "pre":
            self.out.append("\n```\n")
            self.in_pre = False
        else:
            super().handle_endtag(tag)


_ea._HtmlToMd = _HtmlToMdWithCode

SYSTEM = """You are a senior smart-contract security researcher writing a Foundry proof-of-concept exploit.

You get: a claimed vulnerability, the Solidity source it concerns, and an EXISTING TEST CONTRACT from
the project whose setUp() already deploys and configures everything (contracts, proxies, roles, KYC,
funded accounts, signer keys). Your test contract INHERITS from it, so all of that is done for you:
use its state variables and helper functions exactly as named. Do NOT write setUp(), do NOT redeploy.

Fill in the SKELETON you are given and output the COMPLETE file (Solidity only, no prose, no fences).

Rules:
- Keep the skeleton's pragma, imports and `contract PoC_<n> is <Parent>` header exactly.
  Add imports only if you need a type the parent file does not already import.
- Write `function test_PoC() public`. You may add helper contracts (e.g. an attacker contract for
  reentrancy) ABOVE the PoC contract, and private helper functions inside it.
- Wrap the attacker's action(s) - and nothing else - between two comment lines:
      // ATTACK-START
      vm.prank(attacker); vault.withdraw(...);
      // ATTACK-END
  Declare any variables you need BEFORE the block. The block must contain only calls.
  The loop re-runs your test with the block deleted; a real exploit test must FAIL then.
- If the exploit depends on something MALICIOUS the attacker prepares beforehand (a hostile
  callback/recipient contract, a bad return value, a crafted parameter, a griefing deposit), wrap
  those preparation lines in `// MALICIOUS-SETUP-START` / `// MALICIOUS-SETUP-END` as well. The loop
  also re-runs the test without them; it must FAIL then too. Make sure the malicious piece is
  registered for the account whose action triggers the bug (check what msg.sender a setter uses).
- The test must PASS when the vulnerability EXISTS: it is an exploit, not a regression test.
  Never wrap the attacker's call in vm.expectRevert. Record balances/state BEFORE the attack, then
  assert the damage AFTER it (attacker gained, victim lost, invariant broken, funds stuck).
- Assert where the value sits: after a deposit the victim holds vault SHARES (share balance), not
  the asset; after a withdraw the attacker holds the ASSET. Check the PROJECT API for WHICH contract
  holds the balance: in split designs (ERC-7575, separate share token) the vault has no balanceOf;
  shares are on the share token contract.
- Before calling any function, find it in the PROJECT API or the PARENT TEST. If it is not there,
  it does not exist - use the function that is.
- Preconditions: set up the victim's NORMAL actions first (deposit, approve, signed permit, time
  passing) exactly the way the project's own tests do - copy from the examples given. Then attack.
- Call only functions that exist (PROJECT API below, the parent's helpers, inherited OpenZeppelin
  functions like transfer/approve/balanceOf, or forge-std). Never invent mint()/setPrice() style
  functions. Give tokens with forge-std `deal(address(token), who, amount)`; ETH with vm.deal.
- Use accounts the parent already has (user/alice/bob/attacker/owner/admin...) when they exist;
  otherwise `address attacker = makeAddr("attacker")`.
- If the claim cannot be demonstrated in a unit test, output exactly one line:
  // NOT_DEMONSTRABLE: <one-sentence reason>
"""

FIX = """Your file did not compile. Below is each compiler error, the line of YOUR file it points at,
and the concrete fix. Apply exactly those fixes (do not invent other function names), keep everything
else, and output the COMPLETE corrected file (Solidity only). Keep the skeleton header and imports;
keep setUp inherited (do not define it); keep the ATTACK markers.

{error}
"""

REVERTED = """test_PoC() reverted before reaching your assertions, so the claim was not tested.
Revert: {reason}
{hint}
Call trace of the failing run (innermost call last; the line with [Revert] is where it died):
{trace}

This is almost always a missing PRECONDITION of the attack, not a wrong attack: an approval or a
signed permit the victim normally gives, a deposit, a role, time passing, an oracle value. Look at
which call reverted and at how the project's own tests (PARENT TEST / RELATED TESTS) make that same
call succeed, then add those steps BEFORE the ATTACK block. Keep the attack and the assertions.
Output the COMPLETE corrected file (Solidity only).
"""

ASSERT_FAILED = """test_PoC() ran to the end but an assertion failed:
{reason}

Call trace of the run:
{trace}

Either the impact shows up somewhere else than you asserted (e.g. shares vs assets, a different
account, an accumulator or pending-balance variable), or the attack did not have the claimed effect.
Re-read the CLAIMED VULNERABILITY, check what actually changed in the trace, and fix the assertions
(or the attack). Output the COMPLETE corrected file (Solidity only).
"""

INVERTED = """Your test is written backwards: it expects the attacker's call to be blocked (vm.expectRevert,
try/catch around the attack, "should have reverted", "balance unchanged"), i.e. it tests that the
code is SAFE. Such a test passes for the wrong reason (the call reverts for an unrelated cause and
nothing changes). Rewrite it as an exploit that PASSES only when the vulnerability exists: call the
attack directly (no expectRevert, no try/catch); record state before; assert the DAMAGE after
(attacker gained, victim lost, funds stuck, invariant broken). Keep the ATTACK markers.
Output the COMPLETE corrected file (Solidity only).

forge output:
{error}
"""

NO_MARKERS = """Your test passed, but it has no `// ATTACK-START` / `// ATTACK-END` lines, so it cannot be
verified. Add exactly those two comment lines around the attacker's call(s) only (declare variables
before the block; the block must contain only calls). Change nothing else.
Output the COMPLETE file (Solidity only).
"""

NO_PRIVILEGE = """Your test passed and the attack matters, but it only works because the setup reconfigures
the protocol or hands the attacker privileged power ({hits}) that a real attacker on a deployed contract
would NOT have. That is a happy path under admin control, not an exploit. Rewrite it as an UNPRIVILEGED
attacker: do NOT call owner/admin/governance-only functions, do NOT flip global config (e.g. globals.setBool
/ setAddress), do NOT grant yourself roles or authority (addAuthority / grantRole / transferOwnership), and
do NOT deploy a replacement core/singleton and point the system at it. Use only calls any external account
can make, plus the normal preconditions the finding describes. If the bug genuinely cannot be triggered
without those privileges, then it is not attacker-exploitable - keep the ATTACK markers only around what the
attacker actually does."""

NO_CONTROL = """Your test passed, but it ALSO passes with {which} removed. So what you assert is true
regardless of the attack: it does not demonstrate the vulnerability. Fix the assertions, not the setup:
record the relevant state BEFORE the attack (balances, shares, fees, owner, a storage value), run the
attack, then assert the DIFFERENCE the attack caused (attacker gained X, victim lost Y, invariant broken,
a value that should be Z is W). Do not assert things that were already true before the attack.
Keep the markers. Output the COMPLETE corrected file (Solidity only).
"""

ASSERT_SHAPE = """Your test passes and the attack matters, but its ASSERTIONS do not prove the
claimed impact - they likely check normal behaviour or read back a value instead of the damage.

This finding's impact type is: {label}
How a PoC of THIS impact must assert it: {template}

Rewrite ONLY the assertion lines to match that. Keep the ATTACK block, the setup, the markers, and the
preparation EXACTLY as they are - change nothing but the asserts. Record the relevant state BEFORE the
attack if you need a baseline, and assert the DIFFERENCE the attack caused (never a hardcoded number,
never a value that was already true before the attack). Output the COMPLETE corrected file (Solidity only).
"""


NO_SETUP_MARKERS = """Your test passed, but it deploys or configures a malicious/mock contract and has no
`// MALICIOUS-SETUP-START` / `// MALICIOUS-SETUP-END` lines around that preparation, so it cannot be
checked that the malicious ingredient matters. Wrap ONLY the attacker's preparation (deploying the
malicious contract, registering it, setting it as recipient/callback/hook, funding it) in those two
comment lines, separate from and before the ATTACK block. Also make sure the preparation is done AS
the right account (vm.prank the victim/user whose setting it is: functions like setClaimRecipient,
setDelegate, setHook key on msg.sender). Change nothing else.
Output the COMPLETE file (Solidity only).
"""

def same_value_failure(reason: str) -> str:
    """'5 >= 5'-style failure (both sides equal) in a control run: nothing changed without the attack."""
    for ln in (reason or "").splitlines():
        m = re.search(r"(-?\d+|0x[0-9a-fA-F]+)(?:\s*\[[^\]]*\])?\s*(==|!=|>=|<=|>|<)\s*"
                      r"(-?\d+|0x[0-9a-fA-F]+)(?:\s*\[[^\]]*\])?\s*$", ln.strip())
        if m:
            return m.group(0) if m.group(1) == m.group(3) else ""
    return ""


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


def attacker_granted_privilege(code: str) -> list:
    """The ATTACK block's actor was handed ownership / a privileged role somewhere in the test
    body (not only inside the ATTACK block, which privileged_setup_in_attack scans): the attack
    then just uses that admin power -- a happy path under admin control, not an exploit. The
    control run keeps a grant placed outside the ATTACK / MALICIOUS-SETUP markers, so it passes."""
    s, e = code.find("ATTACK-START"), code.find("ATTACK-END")
    b = code.find("function test_PoC")
    if min(s, e, b) < 0:
        return []
    attack = code[s:e]
    actors = set(re.findall(r"vm\.(?:prank|startPrank)\(\s*(?:address\(\s*)?([A-Za-z_]\w*)", attack))
    if not actors:
        return []
    body = code[b:]
    hits = []
    for a in sorted(actors):
        pats = [
            r"\.\s*transferOwnership\s*\(\s*(?:address\(\s*)?" + re.escape(a) + r"\b",
            r"\bgrantRole\s*\([^;]*\b" + re.escape(a) + r"\b",
            r"\.\s*set(?:Owner|Admin|Authority|Operator|Pauser|Guardian|Minter|Governance|Governor)\s*\(\s*(?:address\(\s*)?" + re.escape(a) + r"\b",
            r"\baddAuthority\s*\([^;]*\b" + re.escape(a) + r"\b",
        ]
        if any(re.search(p, body) for p in pats):
            hits.append("attack actor '" + a + "' is granted ownership/role in setup (happy path, not an exploit)")
    return hits


def pure_computation_attack(code: str) -> list:
    """The ATTACK block makes no state change: no prank, no state cheatcode, and it only
    re-calls a function the pre-attack baseline already calls (computing a value to compare).
    control_version keeps the attack's variable as a zeroed declaration, so the assert fails
    trivially in the knockout -- fake control-sensitivity. A property/comparison test, not an
    exploit. Narrow by design: a real exploit calls a different method than the baseline."""
    s, e = code.find("ATTACK-START"), code.find("ATTACK-END")
    b = code.find("function test_PoC")
    if min(s, e, b) < 0:
        return []
    before, attack = code[b:s], code[s:e]
    if re.search(r"\b(?:vm|hevm)\.(?:prank|startPrank|store|deal|warp|roll|etch|mockCall)\b", attack):
        return []
    calls = re.findall(r"\b[A-Za-z_]\w*\s*\.\s*([A-Za-z_]\w*)\s*\(", attack)
    if not calls:
        return []
    base_methods = set(re.findall(r"\.\s*([A-Za-z_]\w*)\s*\(", before))
    if all(m in base_methods for m in calls):
        return ["attack only re-computes via '" + sorted(set(calls))[0] +
                "' (no state change; same call as the baseline): property/comparison, not an exploit"]
    return []


def readback_asserts(code: str) -> list[str]:
    """assertEq(x, y) after the ATTACK block where y is just a value the ATTACK block passed in: that checks
    the call stored its input, which is true for any normal call (wildcat M-05: grantRole(t, ts) then
    assertEq(status.lastApprovalTimestamp, ts)). Trivial values (numbers, true/false, short names) ignored."""
    m_s, m_e = re.search(r"ATTACK-START", code), re.search(r"ATTACK-END", code)
    if not (m_s and m_e):
        return []
    norm = lambda t: re.sub(r"\b(?:u?int\d*|bytes\d*|address|payable)\s*\(", "(", re.sub(r"\s+", "", t))
    attack = norm(code[m_s.end():m_e.start()])
    out = []
    for m in re.finditer(r"\bassertEq\s*\(", code[m_e.end():]):
        args = _balanced(code[m_e.end():], m.end() - 1)
        parts = [a.strip() for a in re.split(r",(?![^()]*\))", args)]
        if len(parts) < 2:
            continue
        y = norm(parts[1]).strip("()")
        if len(y) < 6 or re.fullmatch(r"[\d_.e]+|true|false|\w{1,6}", y):
            continue
        if y in attack:
            # a balance change compared to an amount is a real damage check (user paid the full deposit),
            # not a read-back of a stored field: skip when the left side is / was computed from a balance
            x = parts[0].strip()
            defn = re.search(rf"\b{re.escape(x)}\s*=\s*([^;]+);", code[m_e.end():]) if re.fullmatch(r"\w+", x) else None
            if "balance" in x.lower() or (defn and re.search(r"balance", defn.group(1), re.I)):
                continue
            out.append(f"assertEq({parts[0]}, {parts[1]})")
    return out


MOCKISH = re.compile(r"(Mock|Malicious|Evil|Attack|Fake|Wrong|Bad|Revert|Reenter|Exploit)", re.I)
_PROJECT_MOCKS: dict[str, set[str]] = {}


def project_mocks(root: Path) -> set[str]:
    """Contracts the project's OWN tests deploy with `new X(` (price-feed mocks, mock tokens...). A PoC that
    uses those is doing normal test setup, not bringing a hostile contract."""
    key = str(Path(root).resolve())
    if key not in _PROJECT_MOCKS:
        names: set[str] = set()
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in ("lib", "node_modules", "out", "cache", ".git")
                           and not d.endswith(".sol")]
            rel = Path(dirpath).relative_to(root).parts
            if not any(part.lower().startswith("test") for part in rel):
                continue
            for fn in filenames:
                if fn.endswith(".sol") and not fn.startswith("PoC_"):
                    try:
                        names |= set(re.findall(r"\bnew\s+(\w+)\s*\(", (Path(dirpath) / fn).read_text(errors="ignore")))
                    except OSError:
                        pass
        _PROJECT_MOCKS[key] = names
    return _PROJECT_MOCKS[key]


def needs_setup_markers(code: str, allowed: set[str] = frozenset()) -> bool:
    """A test that brings its own contract (mock recipient, reentrant token, malicious hook) must mark
    that preparation, or the second knockout cannot run and 'it passed' proves little.
    Mocks the project's own tests already deploy (`allowed`) are normal setup and don't count."""
    helpers = re.findall(r"^\s*contract\s+(\w+)", code, re.M)
    if any(h and not h.startswith("PoC_") for h in helpers):
        return True
    return any(MOCKISH.search(n) and n not in allowed for n in re.findall(r"\bnew\s+(\w+)\s*\(", code))


NESTED_MARKERS = """Your test passed, but the `// MALICIOUS-SETUP-START..END` block contains the `// ATTACK-START..END`
block (or the other way round). The two blocks must be SEPARATE and non-overlapping: MALICIOUS-SETUP
holds only the attacker's preparation (deploying a malicious contract, registering, funding, approving),
ATTACK holds only the exploiting call(s) that come after it. If there is no separate preparation step,
remove the MALICIOUS-SETUP lines entirely. Change nothing else.
Output the COMPLETE file (Solidity only).
"""


def markers_nested(code: str) -> bool:
    """True if an ATTACK block and a MALICIOUS-SETUP block overlap (one knockout would remove both)."""
    depth = {"ATTACK": 0, "MALICIOUS-SETUP": 0}
    for l in code.splitlines():
        for m in depth:
            if f"{m}-START" in l:
                if any(depth[o] > 0 for o in depth if o != m):
                    return True
                depth[m] += 1
            elif f"{m}-END" in l:
                depth[m] = max(0, depth[m] - 1)
    return False

TEST_FAIL = re.compile(r"\[FAIL(?::\s*(.*?))?\]\s*test_PoC\(\)")
SETUP_FAIL = re.compile(r"\[FAIL(?::\s*(.*?))?\]\s*setUp\(\)")
HAS_ASSERT = re.compile(r"\bassert(Eq|True|False|Gt|Ge|Lt|Le|NotEq|ApproxEq\w*)?\s*\(")


# ---------------------------------------------------------------- shell / project

RPC_ENV_FILE = Path(os.environ.get("POC_RPC_ENV", str(Path(__file__).resolve().parent / "rpc.env")))
_RPC_NEEDS: dict[str, set[str]] = {}


def load_rpc_env(root=None) -> dict[str, str]:
    """Your RPC URLs from rpc.env: KEY=url lines; KEY@part=url applies only to projects whose path contains `part`
    (for generic names like RPC_URL). Scoped lines win over global ones."""
    glob, scoped = {}, {}
    if RPC_ENV_FILE.exists():
        for line in RPC_ENV_FILE.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = (x.strip() for x in line.split("=", 1))
            v = v.strip('"').strip("'")
            if "@" in k:
                k, part = k.split("@", 1)
                if root is not None and part and part in str(Path(root).resolve()):
                    scoped[k] = v
            else:
                glob[k] = v
    return {**glob, **scoped}


def rpc_needs(root: Path) -> set[str]:
    """RPC env vars the project's tests / foundry.toml read (vm.envString("X_RPC_URL"), ${X} in foundry.toml)."""
    key = str(Path(root).resolve())
    if key not in _RPC_NEEDS:
        names: set[str] = set()
        rpcish = re.compile(r"RPC|URL|NODE", re.I)
        toml = Path(root) / "foundry.toml"
        if toml.exists():
            names |= {n for n in re.findall(r"\$\{(\w+)\}", toml.read_text(errors="ignore")) if rpcish.search(n)}
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in ("lib", "node_modules", "out", "cache", ".git")
                           and not d.endswith(".sol")]
            rel = Path(dirpath).relative_to(root).parts
            if not any(part.lower().startswith("test") for part in rel):
                continue
            for fn in filenames:
                if fn.endswith(".sol") and not fn.startswith("PoC_"):
                    try:
                        t = (Path(dirpath) / fn).read_text(errors="ignore")
                    except OSError:
                        continue
                    names |= {n for n in re.findall(r'vm\.env(?:String|Or)\(\s*"(\w+)"', t) if rpcish.search(n)}
        _RPC_NEEDS[key] = names
    return _RPC_NEEDS[key]


def missing_rpc(root: Path) -> list[str]:
    have = load_rpc_env(root)
    return sorted(n for n in rpc_needs(root) if not os.environ.get(n) and not have.get(n))


def forge_env(root: Path) -> dict:
    env = dict(os.environ)
    env.update(load_rpc_env(root))
    return env


def redact_rpc(text: str, root) -> str:
    """Never let an RPC URL (often with an API key) reach logs, sessions or training data."""
    for k, v in load_rpc_env(root).items():
        if v and len(v) > 8:
            text = text.replace(v, f"<{k}>")
    return text


def sh(cmd, cwd, timeout, env=None):
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env)
        out = p.stdout + p.stderr
        return p.returncode, (redact_rpc(out, cwd) if env is not None else out)
    except subprocess.TimeoutExpired:
        return 124, "forge timed out"


def project_layout(root: Path):
    src, test = "src", "test"
    toml = root / "foundry.toml"
    if toml.exists():
        t = toml.read_text(errors="ignore")
        m = re.search(r'^\s*src\s*=\s*["\']([^"\']+)', t, re.M)
        if m:
            src = m.group(1).strip("/")
        m = re.search(r'^\s*test\s*=\s*["\']([^"\']+)', t, re.M)
        if m:
            test = m.group(1).strip("/")
    rc, out = sh(["forge", "remappings"], root, 60)
    remaps = [l.strip() for l in out.splitlines() if "=" in l] if rc == 0 else []
    return root / src, root / test, remaps


# ---------------------------------------------------------------- text helpers

def clean_report_text(desc: str) -> str:
    """Drop the warden credit lines that open every Code4rena finding."""
    keep = []
    for line in desc.splitlines():
        low = line.strip().lower()
        if low.startswith(("submitted by", "*submitted by", "_submitted by")) or "also found by" in low:
            continue
        keep.append(line)
    return "\n".join(keep)


def report_code_blocks(desc: str) -> list[str]:
    """Solidity code blocks a report finding includes (often its own PoC)."""
    blocks = re.findall(r"```(?:solidity|sol)?\s*\n(.*?)```", desc, re.S)
    return [b for b in blocks if "function" in b or "contract" in b]


def claim_text(item: dict, with_report_poc: bool) -> str:
    parts = [f"TITLE: {item.get('title', '')}", f"SEVERITY: {item.get('severity', '')}"]
    if item.get("contract") or item.get("function"):
        parts.append(f"LOCATION: {item.get('contract', '?')}.{item.get('function', '?')}")
    raw = str(item.get("description", ""))
    desc = re.sub(r"```.*?```", " ", clean_report_text(raw), flags=re.S)
    parts.append("DESCRIPTION: " + re.sub(r"\s+", " ", desc)[:3500])
    if item.get("code_evidence"):
        parts.append(f"CODE EVIDENCE:\n{item['code_evidence']}")
    sc = item.get("attack_scenario")
    if sc:
        parts.append("SCENARIO:\n" + "\n".join(f"- {s}" for s in (sc if isinstance(sc, list) else [sc])))
    if with_report_poc:
        blocks = report_code_blocks(raw)
        if blocks:
            parts.append("THE REPORT'S OWN POC (written against a different harness: adapt the idea and the "
                         "calls, but use the parent test's variable names, not these):\n"
                         + "\n\n".join(b.strip()[:3500] for b in blocks[:2]))
    return "\n".join(parts)


def claim_idents(item: dict) -> set[str]:
    desc = clean_report_text(str(item.get("description", "") or ""))
    text = " ".join(str(item.get(k, "")) for k in ("title", "function", "code_evidence")) + " " + desc[:6000]
    idents = set(re.findall(r"`([A-Za-z_]\w{2,})(?:\(\))?`", text))
    idents |= set(re.findall(r"\b([A-Za-z_]\w{2,})\s*\(", text))
    idents |= set(re.findall(r"\b([A-Z][a-z0-9]+(?:[A-Z][A-Za-z0-9]*)+)\b", text))
    idents |= set(re.findall(r"\b([a-z]+[A-Z]\w*)\b", text))
    idents |= {item.get("function")} - {None, ""}
    idents -= {"require", "revert", "assert", "emit", "return", "function", "address", "uint256", "mapping"}
    return idents


def _functions(text: str):
    """(name, start, end) of every function in a Solidity file, by brace matching."""
    for m in re.finditer(r"\bfunction\s+(\w+)\s*\([^)]*\)[^{;]*\{", text):
        depth, i = 1, m.end()
        while i < len(text) and depth:
            depth += {"{": 1, "}": -1}.get(text[i], 0)
            i += 1
        yield m.group(1), m.start(), i


def strip_fences(text: str) -> str:
    text = text.strip()
    m = re.search(r"```(?:solidity|sol)?\s*\n(.*?)```", text, re.S)
    return (m.group(1) if m else text).strip() + "\n"


# ---------------------------------------------------------------- source under test

def find_source(root: Path, files: list[Path], item: dict) -> Path | None:
    desc = item.get("description", "") or ""
    linked = {}
    for path, a, b in LINK.findall(desc):
        f = resolve(path, files)
        if f and "/test/" not in f"/{f}":
            linked[f] = linked.get(f, 0) + 1
    if not linked:                   # plain github links without line numbers (.../tree/main/plaza-evm/src/Pool.sol)
        for m in re.finditer(r"github\.com/\S+?/(?:blob|tree)/[^/\s]+/(\S+?\.sol)", desc):
            parts = m.group(1).split("/")
            for k in range(len(parts)):
                cand = "/".join(parts[k:])
                hit = [f for f in files if str(f) == cand or str(f).endswith("/" + cand)]
                if hit:
                    if "/test/" not in f"/{hit[0]}":
                        linked[hit[0]] = linked.get(hit[0], 0) + 1
                    break
    if linked:                       # the file the report links MOST (ties: the first one), not just the first link
        order = list(linked)
        return max(order, key=lambda f: (linked[f], -order.index(f)))
    name = (item.get("contract") or "").split(".")[0]
    if name:
        for f in files:
            if re.search(rf"\b(contract|library|abstract contract)\s+{re.escape(name)}\b",
                         (root / f).read_text(errors="ignore")):
                return f
        for f in files:
            if f.stem == name:
                return f
    idents = claim_idents(item)
    if not idents:
        return None
    best, best_score = None, 0
    for f in files:
        if "/test/" in f"/{f}" or "mock" in f.name.lower():
            continue
        src = (root / f).read_text(errors="ignore")
        score = 0
        for i in idents:
            if re.search(rf"\b(contract|abstract contract|library|interface)\s+{re.escape(i)}\b", src):
                score += 3 if not f.name.startswith("I") else 1
            elif re.search(rf"\bfunction\s+{re.escape(i)}\s*\(", src):
                score += 2
        if score > best_score:
            best, best_score = f, score
    return best


def claim_functions(src_text: str, item: dict) -> set[str]:
    """State-changing functions of the source that the claim names (as code or as a plain word)."""
    defined = {m.group(1) for m in re.finditer(r"\bfunction\s+(\w+)\s*\([^)]*\)([^{;]*)", src_text)
               if not re.search(r"\b(view|pure)\b", m.group(2))}
    text = " ".join(str(item.get(k, "")) for k in ("title", "function", "code_evidence")) + " " + \
        clean_report_text(str(item.get("description", "") or ""))[:6000]
    words = set(re.findall(r"\b_?(\w+)\b", text))
    idents = claim_idents(item)
    return {d for d in defined if d.lstrip("_") in words or d in idents}


def focused_source(src_text: str, names: set[str], limit: int) -> str:
    """The whole file if it fits; otherwise the header (state, events, modifiers) + the claim's
    functions in full + one-line signatures of everything else."""
    if len(src_text) <= limit:
        return src_text
    fns = list(_functions(src_text))
    if not fns:
        return src_text[:limit]
    header = src_text[:fns[0][1]].rstrip()
    header = header[:limit // 3] + ("\n    // ... (header truncated)" if len(header) > limit // 3 else "")
    wanted = {n for n in names} | {n.lstrip("_") for n in names}
    budget = limit - len(header)
    full, sigs = [], []
    for name, s, e in fns:
        body = src_text[s:e]
        sig = "    " + " ".join(body.split("{", 1)[0].split()) + " { ... }"
        if (name in wanted or name.lstrip("_") in wanted) and len(body) <= budget:
            full.append((s, body))
            budget -= len(body)
        else:
            sigs.append((s, sig))
    kept, rest = [], []
    for s, sig in sigs:                       # signatures fill what is left, in file order
        if len(sig) + 1 <= budget:
            kept.append((s, sig))
            budget -= len(sig) + 1
        else:
            rest.append(sig)
    parts = sorted(full + kept, key=lambda x: x[0])
    out = header + "\n\n" + "\n\n".join(p for _, p in parts)
    if rest:
        out += f"\n\n    // ... {len(rest)} more functions omitted ..."
    return out + "\n}\n"


FN_SIG = re.compile(r"\bfunction\s+(\w+)\s*\(([^)]*)\)([^{;]*)", re.S)
DECL = re.compile(r"^\s*(abstract\s+contract|contract|interface|library)\s+(\w+)([^{]*)\{", re.M)


def api_summary(root: Path, files: list[Path], focus: Path | None, limit: int = 8000,
                must_have: set[str] = frozenset()) -> str:
    """Public/external signatures of project contracts. The file under test and the contracts the
    parent test's state variables are typed as (`must_have`) always come first: those are the
    contracts the PoC will call."""
    def entry(f: Path) -> str:
        text = re.sub(r"//[^\n]*|/\*.*?\*/", "", (root / f).read_text(errors="ignore"), flags=re.S)
        out = []
        decls = list(DECL.finditer(text))
        for i, d in enumerate(decls):
            body = text[d.end(): decls[i + 1].start() if i + 1 < len(decls) else len(text)]
            sigs = []
            for m in FN_SIG.finditer(body):
                tail = " ".join(m.group(3).split())
                if not re.search(r"\b(public|external)\b", tail):
                    continue
                ret = re.search(r"returns\s*\(([^)]*)\)", tail)
                mods = " ".join(w for w in ("view", "pure", "payable") if re.search(rf"\b{w}\b", tail))
                sigs.append(f"  {m.group(1)}({' '.join(m.group(2).split())})" + (f" {mods}" if mods else "")
                            + (f" returns ({' '.join(ret.group(1).split())})" if ret else ""))
            if sigs or d.group(1) != "interface":
                inherits = " ".join(d.group(3).split())[:80]
                out.append(f"{d.group(1)} {d.group(2)}" + (f" {inherits}" if inherits else "") + "\n" + "\n".join(sigs[:60]))
        return f"// {f}\n" + "\n".join(out) if out else ""

    def declares_needed(f: Path) -> bool:
        if not must_have:
            return False
        text = (root / f).read_text(errors="ignore")
        return any(re.search(rf"\b(contract|abstract contract|interface)\s+{re.escape(c)}\b", text) for c in must_have)

    def priority(f: Path):
        helper = any(k in f.name.lower() for k in ("mock", "faucet", "token", "erc20", "asset"))
        return (f != focus, not declares_needed(f), not helper, (root / f).stat().st_size)

    parts, size = [], 0
    for f in sorted(files, key=priority):
        e = entry(f)
        if e and size + len(e) <= limit:
            parts.append(e)
            size += len(e)
    return "\n\n".join(parts)


# ---------------------------------------------------------------- the parent test

def parse_test_file(path: Path):
    """Return (pragma line, import lines, [(contract_name, body_start, body_end, is_abstract)])."""
    text = path.read_text(errors="ignore")
    pragma = next((l for l in text.splitlines() if l.strip().startswith("pragma solidity")), "pragma solidity ^0.8.0;")
    imports = re.findall(r"^\s*import\b[^;]*;", text, re.M)
    contracts = []
    for m in re.finditer(r"^\s*(abstract\s+)?contract\s+(\w+)([^{]*)\{", text, re.M):
        depth, i = 1, m.end()
        while i < len(text) and depth:
            depth += {"{": 1, "}": -1}.get(text[i], 0)
            i += 1
        contracts.append((m.group(2), m.end(), i - 1, bool(m.group(1)), m.group(3)))
    return text, pragma, imports, contracts


def is_test_path(f: Path, test_dir: Path) -> bool:
    parts = f.parts
    return (f.name.endswith(".t.sol") or "test" in parts or "tests" in parts
            or str(f).startswith(test_dir.name + "/"))


def test_files(root: Path, test_dir: Path) -> list[Path]:
    """The project's *.t.sol files. Normally under the configured test dir; some projects keep
    them elsewhere (src/test/, tests/), so fall back to the whole repo minus dependencies."""
    found = [p for p in test_dir.rglob("*.t.sol") if p.is_file()] if test_dir.exists() else []
    if not found:
        found = [p for p in root.rglob("*.t.sol") if p.is_file()
                 and not any(part in ("lib", "node_modules", "out", "cache") for part in p.relative_to(root).parts)]
    # shared harnesses are often plain .sol files next to the tests (BaseMarketTest.sol, BaseTest.sol)
    seen = set(found)
    rest = []
    for p in (test_dir.rglob("*.sol") if test_dir.exists() else []):
        if p.is_file() and p not in seen and not p.name.startswith("PoC_"):
            try:
                head = p.read_text(errors="ignore")
            except Exception:  # noqa
                continue
            if re.search(r"\bfunction\s+setUp\s*\(|forge-std/Test\.sol|\bis\s+[^{]*\bTest\b", head):
                found.append(p)
            else:
                rest.append((p, head))
    # ... and plain .sol files whose contracts inherit from those, transitively
    # (FundTest is Checkers is TradingInit: only TradingInit.sol has the setUp)
    decl = r"^\s*(?:abstract\s+)?contract\s+(\w+)"
    names = set()
    for f in found:
        try:
            names |= set(re.findall(decl, f.read_text(errors="ignore"), re.M))
        except Exception:  # noqa
            pass
    changed = True
    while changed and rest:
        changed = False
        for item in list(rest):
            f, head = item
            bases = re.findall(r"\bcontract\s+\w+\s+is\s+([^{]*)\{", head)
            if any(set(re.findall(r"\w+", b)) & names for b in bases):
                found.append(f)
                rest.remove(item)
                names |= set(re.findall(decl, head, re.M))
                changed = True
    return found


_INHERIT_CACHE: dict[str, str] = {}


def _inherits(root: Path, file: str, contract: str, base: str) -> bool:
    key = f"{file}::{contract}"
    if key not in _INHERIT_CACHE:
        try:
            text = re.sub(r"//[^\n]*|/\*.*?\*/", "", (root / file).read_text(errors="ignore"), flags=re.S)
        except Exception:  # noqa
            text = ""
        m = re.search(rf"\bcontract\s+{re.escape(contract)}\s+is\s+([^{{]*)\{{", text)
        _INHERIT_CACHE[key] = m.group(1) if m else ""
    return bool(re.search(rf"\b{re.escape(base)}\b", _INHERIT_CACHE[key]))


def parent_candidates(root: Path, test_dir: Path, src: Path | None, item: dict, claim_fns: set[str],
                      preferred_files: set[str] = frozenset()):
    """Test contracts with a setUp(), ranked by how likely their setUp prepares the contract under
    test: imports it, deploys it, rich setup (keys/permits/KYC/roles), calls the claim's functions,
    few private variables (not inheritable), smaller files."""
    cands = []
    tfiles = sorted(test_files(root, test_dir))
    parsed = {}
    for p in tfiles:
        if p.name.startswith("PoC_") or not p.is_file():
            continue
        try:
            parsed[p] = parse_test_file(p)
        except Exception:  # noqa
            continue
    # which test contracts set up (own setUp/constructor), and which inherit such a one (transitively)
    SETUP_RE = r"\bfunction\s+setUp\s*\(|\bconstructor\s*\([^)]*\)\s*[^;{]*\{"
    by_name = {}
    for p, (text, pragma, imports, contracts) in parsed.items():
        for name, s_, e_, is_abstract, inherits in contracts:
            by_name[name] = (p, text, s_, e_, inherits)
    sets_up = {n for n, (p, text, s_, e_, inh) in by_name.items()
               if re.search(r"\bfunction\s+setUp\s*\(", text[s_:e_])
               # a constructor counts only for an actual test contract (not a Mock/Testable helper contract)
               or (re.search(SETUP_RE, text[s_:e_])
                   and (n.endswith("Test") or (p.name.endswith(".t.sol") and re.search(r"\bTest\b", inh))))}
    for _ in range(4):
        for n, (p, text, s_, e_, inh) in by_name.items():
            if n not in sets_up and any(re.search(rf"\b{re.escape(b)}\b", inh) for b in sets_up):
                sets_up.add(n)

    def bases_of(name: str, depth: int = 3) -> list[str]:
        out, todo = [], [name]
        while todo and depth:
            depth -= 1
            nxt = []
            for n in todo:
                if n in by_name:
                    for b in re.findall(r"\b[A-Za-z_]\w*\b", by_name[n][4]):
                        if b in by_name and b not in out and b != name:
                            out.append(b); nxt.append(b)
            todo = nxt
        return out

    def family_text(name: str) -> str:
        """The contract's body plus the bodies of its base test contracts (inherited setUp/helpers/vars)."""
        parts = [by_name[name][1][by_name[name][2]:by_name[name][3]]] if name in by_name else []
        for b in bases_of(name):
            p, text, s_, e_, _ = by_name[b]
            parts.append(text[s_:e_])
        return "\n".join(parts)

    # the report's own PoC: the helpers it calls and the harness it extends point at the right parent
    report_fns, report_base = set(), None
    for block in report_code_blocks(str(item.get("description", "") or "")):
        report_fns |= {m for m in re.findall(r"(?<![.\w])(_?[a-z]\w{3,})\s*\(", block)
                       if m not in ("function", "require", "assert", "revert", "emit", "return", "while", "if", "for")}
        bm = re.search(r"\bcontract\s+\w+\s+is\s+([^{]*)\{", block)
        if bm:
            for b in re.findall(r"\b[A-Za-z_]\w*\b", bm.group(1)):
                if b in by_name:
                    report_base = b
    # test files / contracts the report says its PoC goes in ("add to StakingManager.t.sol", --match-contract X)
    _desc = str(item.get("description", "") or "")
    named_tests = set(re.findall(r"\b(\w+)\.t\.sol\b", _desc)) | set(re.findall(r"--match-contract\s+(\w+)", _desc))
    # contracts that inherit from the one under test: a test deploying `InitialETHCrowdfund` is the right
    # harness for a bug in `ETHCrowdfundBase`
    derived = {n for n, defs in SYMBOLS.items() for d in defs
               if src is not None and d["kind"] in ("contract",) and d["container"] is None
               and n != src.stem and _inherits(root, d["file"], n, src.stem)} if src is not None else set()
    for p, (text, pragma, imports, contracts) in parsed.items():
        for name, s, e, is_abstract, inherits in contracts:
            if name not in sets_up:
                continue                     # no setUp/constructor of its own or inherited: not a harness
            body = family_text(name)         # own body + inherited bases: that is what the PoC gets
            score = 0
            fam_text = text + "".join(by_name[b][1] for b in bases_of(name))
            if report_base == name:
                score += 8                   # the report's PoC was written on top of exactly this contract
            elif report_base and report_base in bases_of(name):
                score += 5
            if name in named_tests or p.name.removesuffix(".t.sol") in named_tests:
                score += 8                   # the report names this test file/contract as where its PoC goes
            hits = {f for f in report_fns if re.search(rf"\bfunction\s+{re.escape(f)}\s*\(", body)}
            score += min(len(hits), 4) * 2   # helpers the report's PoC calls exist here
            if src is not None and re.search(rf"\b{re.escape(src.stem)}\b", fam_text):
                score += 4
                if re.search(rf"\bnew\s+{re.escape(src.stem)}\b|{re.escape(src.stem)}\s*\(\s*address\s*\(", fam_text):
                    score += 2
            elif derived and any(re.search(rf"\b{re.escape(dn)}\b", fam_text) for dn in derived):
                score += 3
                if any(re.search(rf"\bnew\s+{re.escape(dn)}\b", fam_text) for dn in derived):
                    score += 2
            own = text[s:e]
            base_setups = "".join(by_name[b][1][a:z] for b in bases_of(name)
                                  for fn, a, z in _functions(by_name[b][1][by_name[b][2]:by_name[b][3]]) if fn == "setUp")
            if re.search(r"fork", p.name + name, re.I) or re.search(r"vm\.envString\(|vm\.rpcUrl\(|createSelectFork|vm\.createFork|RPC_URL", own + base_setups):
                score -= 10                 # needs a live RPC: setUp will not run here
            score += sum(1 for k in ("makeAddrAndKey", "vm.sign", "permit(", "kyc", "grantRole", "whitelist",
                                     "setValidator", "ERC1967Proxy", "initialize") if k.lower() in body.lower())
            score += sum(1 for n in claim_fns if re.search(rf"\.{re.escape(n.lstrip('_'))}\s*\(", body))
            # private state is copied into a standalone PoC now, so it costs a little, not everything
            score -= min(6, 2 * len(re.findall(r"^\s*[\w\[\]]+\s+private\s+\w+", body, re.M)))
            if src is not None and (p.name.removesuffix(".t.sol") == src.stem or name == f"{src.stem}Test"):
                score += 6                   # Pool.t.sol / PoolTest for src/Pool.sol: the test written for this contract
            if p.name in preferred_files:       # this file holds the best demonstration of the claim's functions
                # ... which only means something if the file is about the contract under test (or a derived one):
                # `contribute` exists in every crowdfund family, so an unrelated family's test must not win on it
                related_family = src is None or re.search(rf"\b{re.escape(src.stem)}\b", fam_text) or \
                    any(re.search(rf"\b{re.escape(dn)}\b", fam_text) for dn in derived)
                score += 4 if related_family else 1
            score -= len(text) / 40000
            cands.append((score, p, name, pragma, imports, text, s, e,
                          [(by_name[b][1], by_name[b][2], by_name[b][3], b) for b in bases_of(name)]))
    cands.sort(key=lambda c: -c[0])
    return cands


def parent_context(text: str, s: int, e: int, limit: int = 9000) -> str:
    """State variables, setUp, modifiers and non-test helper functions of the parent contract
    (its test functions are dropped: they are noise and the related-tests section covers them)."""
    body = text[s:e]
    out, cut = [], 0
    for name, fs, fe in _functions(body):
        if name.lower().startswith("test") and name != "setUp":
            out.append(body[cut:fs])
            cut = fe
    out.append(body[cut:])
    ctx = "\n".join(l.rstrip() for l in "".join(out).splitlines())
    ctx = re.sub(r"\n{3,}", "\n\n", ctx).strip("\n")
    if len(ctx) > limit:
        # keep declarations + setUp first; helpers after, as far as they fit
        m = re.search(r"\bfunction\s+setUp\b|\bconstructor\s*\(", ctx)
        head = ctx[: (list(_functions("function " + ctx[m.start():]))[0][2] + m.start() - 9) if m else limit]
        ctx = head[:limit] if len(head) >= limit else head + "\n    // ... helper functions omitted ..." + ctx[len(head):][: limit - len(head)]
    return ctx


def related_tests(root: Path, test_dir: Path, claim_fns: set[str], parent: Path | None,
                  max_snippets: int = 3, max_lines: int = 55, limit: int = 5500) -> str:
    names = {n.lstrip("_") for n in claim_fns if len(n.lstrip("_")) > 3}
    if not names:
        return ""
    call = {n: re.compile(rf"\.{re.escape(n)}\s*\(") for n in names}
    scored = []
    for p in sorted(test_files(root, test_dir)):
        if p.name.startswith("PoC_"):
            continue
        text = p.read_text(errors="ignore")
        for fname, fs, fe in _functions(text):
            if not fname.lower().startswith("test"):
                continue
            body = text[fs:fe]
            hits = {n for n, rx in call.items() if rx.search(body)}
            if not hits:
                continue
            edge = bool(re.search(r"zero|revert|fail|invalid|unauthori[sz]ed|only|cannot|require|edge|"
                                  r"boundary|overflow|underflow|paused", fname, re.I))
            reverts = body.count("expectRevert")
            rich = sum(1 for k in ("vm.sign", "permit(", "makeAddrAndKey", "grantRole", "kyc", "approve(",
                                   "whitelist", "setValidator") if k.lower() in body.lower())
            same_parent = 1 if (parent is not None and p == parent) else 0
            scored.append((0 if (edge or reverts) else 1, same_parent, len(hits), rich, -len(body),
                           p.name, fname, body, sorted(hits)))
    scored.sort(reverse=True)
    out, size, used = [], 0, set()
    for *_, pname, fname, body, hits in scored:
        if fname in used or len(out) >= max_snippets:
            continue
        lines = body.splitlines()
        snippet = "\n".join(lines[:max_lines]) + ("\n    // ... (truncated)" if len(lines) > max_lines else "")
        block = f"// ----- {pname} :: {fname}  (calls: {', '.join(hits)}) -----\n{snippet}"
        if size + len(block) > limit:
            continue
        out.append(block)
        used.add(fname)
        size += len(block)
    return "\n\n".join(out)


# ---------------------------------------------------------------- forge output

def classify(rc: int, out: str) -> str:
    low = out.lower()
    if "compiler run failed" in low or re.search(r"^error(\[\d+\])?:", out, re.M | re.I) \
            or "parsererror" in low or "declarationerror" in low or "typeerror" in low:
        return "compile_error"
    if "no tests match" in low or "no tests to run" in low:
        return "no_test"                # compiled, but no test_PoC() was found (or the filter is wrong)
    if SETUP_FAIL.search(out):
        return "setup_error"
    if "[pass]" in low and rc == 0:
        return "pass"
    return "fail"


def api_index(root: Path, files: list[Path]) -> dict[str, list[str]]:
    """contract name -> public/external signatures, for targeted compile-error hints."""
    idx = {}
    for f in files:
        text = re.sub(r"//[^\n]*|/\*.*?\*/", "", (root / f).read_text(errors="ignore"), flags=re.S)
        decls = list(DECL.finditer(text))
        for i, d in enumerate(decls):
            body = text[d.end(): decls[i + 1].start() if i + 1 < len(decls) else len(text)]
            sigs = []
            for m in FN_SIG.finditer(body):
                tail = " ".join(m.group(3).split())
                if re.search(r"\b(public|external)\b", tail):
                    ret = re.search(r"returns\s*\(([^)]*)\)", tail)
                    sigs.append(f"{m.group(1)}({' '.join(m.group(2).split())})"
                                + (f" returns ({' '.join(ret.group(1).split())})" if ret else ""))
            if sigs:
                idx.setdefault(d.group(2), []).extend(sigs)
    return idx


PARENT_VAR_TYPES: dict[str, str] = {}


def parent_vars(ctx: str) -> tuple[list[str], list[str], set[str]]:
    """(accessible names, private names, contract types) of the parent test's state variables.
    The types tell us which contracts the PoC will call, so their APIs must be in the prompt.
    Also records each variable's type in PARENT_VAR_TYPES for the hints."""
    acc, priv, types = [], [], set()
    PARENT_VAR_TYPES.clear()
    # only contract-level declarations: cut function bodies first, so setUp/helper locals
    # (`address poolBeacon = ...;`) are not reported as state the PoC can use
    decl = ctx
    for _, fs, fe in sorted(_functions(ctx), key=lambda t: -t[1]):
        decl = decl[:fs] + decl[fe:]
    for m in re.finditer(r"^\s*([\w.]+)(?:\[\])*\s+((?:public|internal|private|immutable|constant|\s)*)\s*(\w+)\s*(?:=[^;]*)?;",
                         decl, re.M):
        typ, mods, name = m.group(1), m.group(2), m.group(3)
        if name in ("return", "emit", "revert", "delete", "break", "continue") or typ in ("return", "emit"):
            continue
        (priv if "private" in mods else acc).append(name)
        PARENT_VAR_TYPES[name] = typ
        if typ[0].isupper() and typ not in ("Test", "Vm"):
            types.add(typ.split(".")[-1])
    return acc, priv, types


ACCOUNT_NAME = re.compile(r"^(attacker|hacker|exploiter|adversary|malicious\w*|victim|alice|bob|carol|dave|"
                          r"eve|mallory|trent|user\d*|attacker\d*|stranger|someone|other|thirdParty|random\w*)$", re.I)

SYMBOLS: dict[str, list[dict]] = {}
PLANS: dict[str, dict] = {}          # finding id -> plan to follow (--plans)
CURRENT_PARENT = ""     # name -> [{"kind", "file", "container", "text"}] over the whole project


def symbol_index(root: Path, files: list[Path], test_dir: Path) -> dict[str, list[dict]]:
    """Where every contract/interface/library/struct/enum is defined (top-level or inside which contract),
    and every helper function of the project's test files with its body. Used to add missing imports
    automatically and to tell the model where an identifier it invented actually lives."""
    idx: dict[str, list[dict]] = {}
    for f in files:
        try:
            raw = (root / f).read_text(errors="ignore")
        except Exception:  # noqa
            continue
        text = re.sub(r"//[^\n]*|/\*.*?\*/", "", raw, flags=re.S)
        decls = [(m.group(1).split()[-1], m.group(2), m.start(), m.end()) for m in DECL.finditer(text)]
        for i, (kind, name, s, e) in enumerate(decls):
            idx.setdefault(name, []).append({"kind": kind, "file": str(f), "container": None, "text": ""})
            body = text[e: decls[i + 1][2] if i + 1 < len(decls) else len(text)]
            for m in re.finditer(r"\b(struct|enum)\s+(\w+)\s*\{([^}]*)\}", body):
                idx.setdefault(m.group(2), []).append({"kind": m.group(1), "file": str(f), "container": name,
                                                       "text": " ".join(m.group(3).split())[:300]})
            if is_test_path(f, test_dir):
                for fn, a, b in _functions(body):
                    if fn in ("setUp", "test") or fn.startswith("test"):
                        continue
                    sig_end = body.index("{", a)
                    idx.setdefault(fn, []).append({"kind": "function", "file": str(f), "container": name,
                                                   "private": bool(re.search(r"\bprivate\b", body[a:sig_end])),
                                                   "text": body[a:b]})
        # top-level structs / enums (file scope, outside any contract)
        head = text[: decls[0][2]] if decls else text
        for m in re.finditer(r"^\s*(struct|enum)\s+(\w+)\s*\{([^}]*)\}", head, re.M):
            idx.setdefault(m.group(2), []).append({"kind": m.group(1), "file": str(f), "container": None,
                                                   "text": " ".join(m.group(3).split())[:300]})
    return idx


def import_path(root: Path, target: str, poc_dir: Path) -> str:
    rel = Path(os.path.relpath(root / target, poc_dir)).as_posix()
    return rel if rel.startswith(".") else "./" + rel


def errors_at(out: str):
    """[(message, path, line, col)] for each compiler error."""
    return [(msg, path, int(ln), int(col)) for msg, path, ln, col in
            re.findall(r"(Error \(\d+\):[^\n]*)\n\s*-->\s*([^\s:]+):(\d+):(\d+)", out)]


def ident_at(code_line: str, col: int) -> str:
    m = re.match(r"\w+", code_line[col - 1:]) if 0 < col <= len(code_line) else None
    return m.group(0) if m else ""


FORGE_STD = {"stdError": "forge-std/StdError.sol", "stdStorage": "forge-std/StdStorage.sol",
             "StdStorage": "forge-std/StdStorage.sol", "stdMath": "forge-std/StdMath.sol",
             "console": "forge-std/console.sol", "console2": "forge-std/console2.sol"}
_LIB_CACHE: dict = {}


def _remappings(root) -> list:
    """(prefix, target) pairs from `forge remappings`, most specific target first (cached per project)."""
    key = ("remap", str(root))
    if key not in _LIB_CACHE:
        try:
            out = subprocess.run(["forge", "remappings"], cwd=str(root), capture_output=True, text=True,
                                 timeout=60).stdout
        except Exception:
            out = ""
        maps = []
        for l in out.splitlines():
            if "=" in l:
                a, b = l.split("=", 1)
                maps.append((a.split(":")[-1].strip(), b.strip()))
        maps.sort(key=lambda m: -len(m[1]))
        _LIB_CACHE[key] = maps
    return _LIB_CACHE[key]


def lib_import_path(root, name: str) -> str:
    """Import path for a type declared in lib/ or node_modules/ (files named <name>.sol), written the way the
    project's remappings expect it. "" if there is no such file (the name is made up)."""
    key = ("lib", str(root), name)
    if key in _LIB_CACHE:
        return _LIB_CACHE[key]
    root = Path(root)
    cands = []
    for base in ("lib", "node_modules"):
        d = root / base
        if not d.is_dir():
            continue
        for p in d.rglob(f"{name}.sol"):
            try:
                if re.search(rf"\b(interface|contract|library)\s+{re.escape(name)}\b", p.read_text(errors="ignore")):
                    cands.append(p)
            except OSError:
                pass
    res = ""
    if cands:
        rel = str(min(cands, key=lambda p: (len(p.parts), str(p))).relative_to(root))
        res = rel
        for prefix, target in _remappings(root):
            t = target.rstrip("/") + "/"
            if rel.startswith(t):
                res = prefix.rstrip("/") + "/" + rel[len(t):]
                break
    _LIB_CACHE[key] = res
    return res


def auto_repair(code: str, out: str, root: Path | None = None, poc_dir: Path | None = None) -> str | None:
    """Deterministic fixes that need no model round: declare account-like identifiers the model
    used but never declared (`attacker`, `victim`, `alice`) as makeAddr() state variables, and
    import project types (contracts, interfaces, libraries, file-level structs) it used but never imported."""
    lines = code.splitlines()
    missing, imports, helpers, renames, recasts = [], [], [], set(), []
    pm = re.search(r"contract\s+PoC_\d+\s+is\s+(\w+)", code)
    parent_name = pm.group(1) if pm else ""
    for msg, path, ln, col in errors_at(out):
        if "PoC_" not in path or not (0 < ln <= len(lines)):
            continue
        mnf = re.search(r'Member "(\w+)" not found[^"]*in contract (\w+)', msg)
        if mnf:
            meth, ctype = mnf.group(1), mnf.group(2)
            if ctype.startswith("I") and len(ctype) > 1 and ctype[1].isupper():
                concrete = ctype[1:]
                cdefs = [d for d in SYMBOLS.get(concrete, []) if d.get("kind") == "contract"]
                on_concrete = False
                if cdefs and root is not None:
                    try:
                        on_concrete = bool(re.search(rf"\bfunction\s+{re.escape(meth)}\b",
                                                      (root / cdefs[0]["file"]).read_text(errors="ignore")))
                    except Exception:
                        on_concrete = False
                if on_concrete:
                    rm = re.search(rf"(\w+)\s*\.\s*{re.escape(meth)}\s*\(", lines[ln - 1])
                    if rm and (rm.group(1), meth, concrete) not in recasts:
                        recasts.append((rm.group(1), meth, concrete))
            continue
        if not ("Undeclared identifier" in msg or "Identifier not found" in msg):
            continue
        name = ident_at(lines[ln - 1], col)
        if not name:
            continue
        # declared at contract level already? (a declaration inside another function doesn't count)
        at_contract_level = re.search(rf"^ {{0,4}}(address|uint\w*)\s+(public\s+|internal\s+)?{re.escape(name)}\b", code, re.M)
        if ACCOUNT_NAME.match(name) and name not in missing and not at_contract_level:
            missing.append(name)
        elif any(d["kind"] == "function" and d.get("private") and d["container"] == parent_name for d in SYMBOLS.get(name, [])):
            if not re.search(rf"\bfunction\s+{re.escape(name)}_?\s*\(", code):
                # a PRIVATE helper of the parent: not inherited, so copy it in (all overloads) under a new name -
                # the same name would count as an (illegal) override of the non-virtual base function
                for d in SYMBOLS[name]:
                    if d["kind"] == "function" and d.get("private") and d["container"] == parent_name:
                        t = re.sub(rf"\bfunction\s+{re.escape(name)}\s*\(", f"function {name}_(", d["text"], count=1)
                        if t not in helpers:
                            helpers.append(t)
                renames.add(name)
        elif root is not None and (name in FORGE_STD or (name[0].isupper() and not SYMBOLS.get(name))):
            # forge-std helpers and library types (OpenZeppelin...) live outside the project index
            path = FORGE_STD.get(name) or lib_import_path(root, name)
            if path and not re.search(rf"import\s*\{{[^}}]*\b{re.escape(name)}\b", code):
                imp = f'import {{{name}}} from "{path}";'
                if imp not in imports:
                    imports.append(imp)
        elif name[0].isupper() and root is not None and poc_dir is not None:
            defs = [d for d in SYMBOLS.get(name, []) if d["container"] is None and d["kind"] != "function"]
            if len({d["file"] for d in defs}) == 1 and not re.search(rf"import\s*\{{[^}}]*\b{re.escape(name)}\b", code):
                imp = f'import {{{name}}} from "{import_path(root, defs[0]["file"], poc_dir)}";'
                if imp not in imports:
                    imports.append(imp)
    if not missing and not imports and not helpers and not recasts:
        return None
    m = re.search(r"contract\s+PoC_\d+\s+is\s+\w+\s*\{", code)
    if not m:
        return None
    decl = "".join(f'\n    address {n} = makeAddr("{n}");' for n in missing)
    code = code[:m.end()] + decl + "\n" + code[m.end():]
    if helpers:
        end = code.rstrip().rfind("}")
        code = code[:end] + "\n    // copied from the parent (private there, so not inherited)\n    " + "\n\n    ".join(helpers) + "\n" + code[end:]
    for name in renames:
        code = re.sub(rf"(?<![\w.]){re.escape(name)}(\s*\()", rf"{name}_\1", code)   # call sites, incl. inside copied overloads
        code = re.sub(rf"\bfunction\s+{re.escape(name)}__\(", f"function {name}_(", code)
    if imports:
        last = list(re.finditer(r"^\s*import\b[^;]*;[ \t]*$", code, re.M))
        at = last[-1].end() if last else code.index("\n", code.index("pragma solidity")) + 1
        code = code[:at] + "\n" + "\n".join(imports) + code[at:]
    for recv, meth, concrete in recasts:
        code = re.sub(rf"\b{re.escape(recv)}\s*\.\s*{re.escape(meth)}\s*\(",
                      f"{concrete}(address({recv})).{meth}(", code)
    return code


def where_defined(name: str, not_unique: bool = False) -> str:
    """A hint for an identifier the model used that exists somewhere in the project, just not here."""
    defs = SYMBOLS.get(name, [])
    if not defs:
        return ""
    defs = sorted(defs, key=lambda d: d["container"] != CURRENT_PARENT)   # the parent's own definition first
    if not_unique:
        return (f"`{name}` is ambiguous here (defined in: " + ", ".join(f"{d['file']}" + (f" inside {d['container']}" if d["container"] else "") for d in defs[:4])
                + "). Qualify it (`Contract.{name}`) or import exactly one with `import {{{name}}} from \"...\";`.")
    d = defs[0]
    if d["kind"] == "function":
        if d.get("private"):
            return (f"`{name}` is a PRIVATE helper of {d['container']} ({d['file']}): private functions are not inherited, "
                    f"so COPY it into your contract under a new name (`{name}_`; the same name would be an illegal override). Its full body:\n    "
                    + "\n    ".join(d["text"].splitlines()[:80]))
        return (f"`{name}` is a helper of {d['container']} ({d['file']}), NOT of your parent test, so you cannot call it. "
                f"Either inline what it does, or use the parent's own helpers. Its body, for reference:\n    "
                + "\n    ".join(d["text"].splitlines()[:40]))
    if d["container"]:
        return f"`{name}` is a {d['kind']} defined inside `{d['container']}` ({d['file']}): write `{d['container']}.{name}`."
    return f"`{name}` is a {d['kind']} in {d['file']}: import it with `import {{{name}}} from \"<relative path to that file>\";`."


def compile_errors(out: str, code: str, acc_vars=(), priv_vars=(), api: dict | None = None, n: int = 5) -> str:
    """Compiler errors with the offending line quoted and, where we can, what to do instead."""
    lines = code.splitlines()
    res = []
    for msg, path, ln, col in errors_at(out)[:n]:
        src_line = lines[ln - 1].strip() if "PoC_" in path and 0 < ln <= len(lines) else ""
        hint = ""
        if "Undeclared identifier" in msg and src_line:
            name = ident_at(lines[ln - 1], col)
            admins = [v for v in acc_vars if PARENT_VAR_TYPES.get(v) == "address"
                      and re.search(r"owner|admin|manager|governor|operator|deployer|treasury|guardian", v, re.I)]
            if name in priv_vars:
                hint = f"`{name}` is a PRIVATE variable of the parent: not accessible. Re-derive it or use a public getter."
            elif re.match(r"(?i)^(owner|admin|governance|governor|manager|deployer)$", name) and admins:
                hint = (f"`{name}` does not exist in the parent test. The parent's privileged accounts are: "
                        f"{', '.join(admins)} - use one of those (do not makeAddr a new one: it would hold no role).")
            elif re.match(r"(?i)^(hype|eth|native|weth)$", name) or (name.isupper() and "token" in src_line.lower()):
                hint = (f"`{name}` is not a variable here. If this is the chain's NATIVE asset, there is no token "
                        f"contract: send it as `{{value: amount}}`, fund with `vm.deal(account, amount)`, read with "
                        f"`account.balance`. Tokens that do exist in the parent: "
                        + ", ".join(v for v in acc_vars if re.search(r"token|erc20|usdc|usdt|dai|asset|khype|share", v, re.I))[:200])
            elif name:
                hint = where_defined(name) or (
                    f"`{name}` does not exist in the parent test. Its variables are: {', '.join(acc_vars[:40])}. "
                    f"For a new account write `address {name} = makeAddr(\"{name}\");` as a state variable.")
        elif "Identifier not found" in msg and src_line:
            name = ident_at(lines[ln - 1], col)
            hint = where_defined(name, not_unique=len(SYMBOLS.get(name, [])) > 1) or f"`{name}` is not defined anywhere in the project: do not use it."
        if "struct constructor" in msg and src_line:
            sm = re.search(r"\b([A-Z]\w*)\s*\(", src_line)
            defs = [d for d in SYMBOLS.get(sm.group(1), []) if d["kind"] == "struct"] if sm else []
            if defs:
                hint = f"Struct `{sm.group(1)}` has exactly these fields, in this order: {defs[0]['text']}"
        if "Named argument" in msg and src_line and api:
            fm = re.search(r"\.(\w+)\s*\(\s*\{", src_line) or re.search(r"\b(\w+)\s*\(\s*\{", src_line)
            if fm:
                matches = [s for sigs in api.values() for s in sigs if s.startswith(fm.group(1) + "(")]
                if matches:
                    hint = f"Parameter names of `{fm.group(1)}`: " + "; ".join(sorted(set(matches))[:3])
        m = re.search(r'Member "(\w+)" not found[^"]*in contract (\w+)', msg)
        if m and api:
            fn, c = m.group(1), m.group(2)
            sigs = api.get(c, [])
            if fn.startswith("_"):
                pub = [s for s in sigs if s.lower().startswith(fn.lstrip("_").lower()[:6])]
                hint = (f"`{fn}` is internal/private storage of `{c}`: not callable from a test. "
                        + (f"Use the public getter: {'; '.join(pub[:3])}. " if pub else "")
                        + "If there is no getter, read it with `vm.load(address(c), slot)` / forge-std `stdstore`, "
                          "or assert on an observable effect (balances, events, a public view) instead.")
            else:
                hint = f"`{c}` has no function `{fn}`. Its public functions: " + ("; ".join(sigs[:30]) or "(none found)")
        if "Wrong argument count" in msg and src_line and api:
            fm = re.search(r"\.(\w+)\s*\(", src_line)
            if fm:
                matches = [s for sigs in api.values() for s in sigs if s.startswith(fm.group(1) + "(")]
                if matches:
                    hint = f"Correct signature(s) of `{fm.group(1)}`: " + "; ".join(sorted(set(matches))[:4])
        res.append(f"- {msg}\n  at {path}:{ln}" + (f"\n  line: {src_line}" if src_line else "") + (f"\n  fix: {hint}" if hint else ""))
    if not res:
        res = [l for l in out.splitlines() if not l.lstrip().startswith(("Warning", "-->", "|"))][-30:]
    return "\n".join(res)


_SOL_CACHE: dict = {}


def _project_sol(root) -> list:
    """Non-test .sol files of a project, project sources first, libraries after (cached)."""
    key = str(root)
    if key not in _SOL_CACHE:
        skip = {"test", "tests", "script", "scripts", "node_modules", "out", "cache"}
        files = [p for p in Path(root).rglob("*.sol")
                 if not (set(p.relative_to(root).parts) & skip) and not p.name.endswith((".t.sol", ".s.sol"))]
        files.sort(key=lambda p: ("lib" in p.relative_to(root).parts, str(p)))
        _SOL_CACHE[key] = files
    return _SOL_CACHE[key]


def revert_source(reason: str, root, limit: int = 3, trace: str = "") -> str:
    """The require/revert in the project source that produced this revert reason (custom error or string),
    with its condition, so the model sees WHAT must be true, not just the error's name. "" if not found."""
    if not reason or reason.startswith(("panic", "EvmError")) or "param mismatch" in reason:
        return ""
    m = re.match(r"\s*([A-Za-z_]\w*)\s*\(", reason)
    if m and m.group(1)[0].isupper():
        pat = re.compile(r"\b" + re.escape(m.group(1)) + r"\b")
    else:
        pat = re.compile(re.escape(reason.strip().strip('"')[:60]))
    cond = re.compile(r"\b(if|require)\s*\(")
    hits = []
    for f in _project_sol(root):
        try:
            lines = f.read_text(errors="ignore").splitlines()
        except OSError:
            continue
        for i, l in enumerate(lines):
            t = l.strip()
            if not pat.search(l) or t.startswith(("//", "*", "/*")) or re.match(r"(error|event)\b", t):
                continue
            if not (cond.search(l) or "revert" in l):
                continue
            start = i
            while start > max(0, i - 4) and not cond.search(lines[start]):
                start -= 1
            if not cond.search(lines[start]):
                start = i
            code = " ".join(x.strip() for x in lines[start:i + 1])
            hits.append(f"  {f.relative_to(root)}:{i + 1}: {code[:220]}")
            if len(hits) >= 12:
                break
        if len(hits) >= 12:
            break
    seen, ranked = set(), []
    for h in sorted(hits, key=lambda h: Path(h.strip().split(":")[0]).stem not in trace):
        code = h.split(": ", 1)[1] if ": " in h else h
        if code not in seen:
            seen.add(code)
            ranked.append(h)
    hits = ranked[:limit]
    if not hits:
        return ""
    return ("The check that failed, in the source. Make THIS condition true before the call "
            "(the right caller, role, balance, approval, time or state):\n" + "\n".join(hits) + "\n")


def failure_trace(out: str, before: int = 28, after: int = 4) -> str:
    """The part of the forge -vvv call trace around the (last) revert, with addresses shortened."""
    lines = out.splitlines()
    try:
        start = next(i for i, l in enumerate(lines) if l.strip().startswith("Traces:"))
    except StopIteration:
        # no call trace (e.g. the test contract's constructor reverted): show forge's own last lines instead
        tail = [l for l in lines if l.strip() and not l.startswith(("Compiling", "Solc ", "Compiler run"))][-25:]
        hint = ""
        if re.search(r"\[FAIL[^\]]*\]\s*(constructor|setUp)\(\)", out):
            hint = ("(the test contract couldn't be deployed or set up: its constructor, a state-variable initializer "
                    "or setUp() reverted. Often a fork-only address or a missing env var / RPC URL)\n")
        return hint + "(no call trace; last lines of forge output:)\n" + "\n".join(l[:200] for l in tail)
    block = []
    for l in lines[start + 1:]:
        if l.startswith("Suite result") or l.startswith("Ran "):
            break
        block.append(l)
    block = [l for l in block if l.strip()]
    revs = [i for i, l in enumerate(block) if "[Revert]" in l or "Revert" in l and "←" in l]
    if revs:
        i = revs[-1]
        block = block[max(0, i - before): i + after]
    else:
        block = block[-(before + after):]
    short = []
    for l in block:
        l = re.sub(r"0x[0-9a-fA-F]{40}", lambda m: m.group(0)[:8] + "…", l)
        l = re.sub(r"\b\d{22,}\b", lambda m: m.group(0)[:5] + "…(" + str(len(m.group(0))) + " digits)", l)
        short.append(l[:200])
    return "\n".join(short)


REVERT_HINTS = [
    (r"InvalidSigner|ECDSAInvalidSignature|invalid signature|BadSignature",
     "the signature was verified against a DIFFERENT signer than the key you signed with. Find in the "
     "PARENT TEST which private key the project's tests use for this (an admin/validator/operator key "
     "created with makeAddrAndKey) and sign with that key; keep nonces()/deadline/DOMAIN_SEPARATOR as they do."),
    (r"InsufficientAllowance\((0x[0-9a-fA-F]+)",
     "the allowance that was checked belongs to the first address in the error (the spender). Look at the "
     "trace for which contract consumed it and how the parent/related tests grant that exact allowance "
     "(it may be a permit or a self-approval, not a plain approve to the vault)."),
    (r"InsufficientBalance", "an account has no tokens: fund it the way the parent does, or with "
                             "forge-std `deal(address(token), account, amount)` before the step that needs them."),
    (r"Paused|EnforcedPause", "the contract is paused: unpause it as the admin first (see parent for who can)."),
    (r"Expired|Deadline|deadline", "a deadline passed: use `block.timestamp + 1 hours` for deadlines, or vm.warp."),
    (r"OwnableUnauthorized|AccessControlUnauthorized|Unauthorized|NotOwner|onlyOwner",
     "the caller lacks a role: vm.prank the account that holds it (see parent setUp for owner/admin)."),
    (r"arithmetic underflow or overflow", "an amount exceeded what exists (balance, supply, cap): use amounts "
                                          "the parent setUp actually funded, and read balances instead of assuming them."),
]


def revert_hint(reason: str) -> str:
    for pat, hint in REVERT_HINTS:
        if re.search(pat, reason or ""):
            return hint
    return ""


def fail_reason(out: str, fn: str = "test_PoC") -> str:
    m = re.search(rf"\[FAIL(?::\s*(.*?))?\]\s*{fn}\(\)", out)
    r = (m.group(1) or "").strip() if m else ""
    if m and not r:
        # old forge-std (DSTest-style asserts) doesn't revert: it logs "Error: a > b not satisfied [uint]"
        # plus "Value a"/"Value b" and marks the test failed, so forge gives no reason
        e = re.search(r'Error: ([^"\n]*not satisfied[^"\n]*)', out)
        if e:
            vals = re.findall(r'Value ([ab])(?:", val)?:\s*(-?\d[\w.]*)', out)[:2]
            r = f"assertion failed (old forge-std): {e.group(1).strip()}" + \
                (" (" + ", ".join(f"{k}={v}" for k, v in vals) + ")" if vals else "")
    return r


def progress(outcome: str, out: str) -> int:
    """How far an attempt got, so feedback goes to the most advanced candidate, not the last one.
    compile_error < no_test < setup_error < revert (deeper trace = further) < assertion failure."""
    base = {"compile_error": 0, "no_test": 100, "setup_error": 200, "fail": 1000}.get(outcome, 0)
    if outcome != "fail":
        return base
    reason = fail_reason(out)
    if "assert" in reason.lower():
        return base + 5000                      # ran to the end: only the assertions are wrong
    lines = out.splitlines()
    try:
        start = next(i for i, l in enumerate(lines) if l.strip().startswith("Traces:"))
    except StopIteration:
        return base
    calls = 0
    for l in lines[start + 1:]:
        if "[Revert]" in l:
            break
        if "::" in l and "←" not in l:
            calls += 1
    return base + min(calls, 3000)


# ---------------------------------------------------------------- the loop

COPY_THRESHOLD = 0.90     # a real PoC built on a happy-path test with one key change scored 0.80


def _norm_body(body: str) -> str:
    body = re.sub(r"//[^\n]*|/\*.*?\*/", "", body, flags=re.S)
    return re.sub(r"\s+", "", body)


def attack_block(code: str) -> str:
    m = re.search(r"ATTACK-START(.*?)ATTACK-END", code, re.S)
    return m.group(1) if m else ""


_NOT_CALLS = {"prank", "startPrank", "stopPrank", "deal", "warp", "roll", "expectRevert", "expectEmit", "label",
              "assume",
              # solidity keywords / builtins / casts
              "address", "payable", "require", "assert", "revert", "emit", "return", "if", "for", "while", "keccak256",
              "abi", "type", "bool", "string", "function", "mapping", "unchecked", "delete", "sha256", "ripemd160",
              "ecrecover", "blockhash", "gasleft", "selfdestruct", "addmod", "mulmod",
              # forge-std free functions
              "makeAddr", "makeAddrAndKey", "skip", "rewind", "hoax", "startHoax", "bound", "changePrank"}


def called_functions(text: str) -> set[str]:
    """Functions a block calls: member calls (`pool.redeem(`, `x.call{value: v}(`) AND plain calls to helpers
    (`announceAndExecuteLeverageOpen({...})`, `deposit(weth, id, vault, 1e18)`, `contextCanBeLiquidated()`)."""
    member = set(re.findall(r"\.\s*(\w+)\s*(?:\{[^}]*\})?\s*\(", text))
    plain = set(re.findall(r"(?<![\w.])([a-z_]\w*)\s*(?:\{[^}]*\})?\s*\(", text))
    plain = {f for f in plain if not re.fullmatch(r"u?int\d*|bytes\d*|assert\w*", f)}
    return {m.lstrip("_") for m in member | plain} - _NOT_CALLS


_TEST_BODIES: dict[str, list[tuple[str, str]]] = {}


def copied_project_test(code: str, root: Path, test_dir: Path) -> tuple[float, str]:
    """How close test_PoC is to an existing project test (0..1), and which one. A PoC that is just a
    project's own happy-path test with markers around the normal call is not a proof of anything."""
    import difflib
    key = str(root)
    if key not in _TEST_BODIES:
        bodies = []
        for f in test_files(root, test_dir):
            if f.name.startswith("PoC_"):
                continue
            try:
                text = f.read_text(errors="ignore")
            except Exception:  # noqa
                continue
            for name, a, b in _functions(text):
                if name.lower().startswith("test"):
                    nb = _norm_body(text[text.index("{", a) + 1: b])
                    if len(nb) > 80:
                        bodies.append((f"{f.relative_to(root)}::{name}", nb))
        _TEST_BODIES[key] = bodies
    mine = _norm_body(test_body(code))
    best, which = 0.0, ""
    for name, nb in _TEST_BODIES[key]:
        sm = difflib.SequenceMatcher(None, mine, nb, autojunk=False)
        if sm.real_quick_ratio() < best or sm.quick_ratio() < best:
            continue
        r = sm.ratio()
        if r > best:
            best, which = r, name
    return best, which


def test_body(code: str) -> str:
    m = re.search(r"function\s+test_PoC\s*\([^)]*\)[^{]*\{(.*)", code, re.S)
    return m.group(1) if m else code


def looks_inverted(code: str) -> bool:
    """A test that expects the attack to be blocked: expectRevert, try/catch that swallows the
    attack's revert, or 'should have reverted' / 'balance unchanged' style assertions."""
    body = test_body(code)
    return bool(re.search(r"expectRevert|\btry\s+\w[\w.]*\s*\.\s*\w+\s*\(|should (have )?revert|"
                          r"should not (have )?change|unchanged|has not changed|did not change|"
                          r"should (be )?restored|restored to|remains? (the same|unchanged|intact)|stays? the same|"
                          r"should (still )?(be|equal) (the )?(initial|original|previous|pre-)", body, re.I))


DECL_LINE = re.compile(r"^(\s*)([\w.\[\]]+(?:\s+(?:memory|storage|calldata))?)\s+(\w+)\s*=\s*[^;]*;\s*$")
TUPLE_DECL = re.compile(r"^(\s*)\(([^)]*)\)\s*=\s*[^;]*;\s*$")


def control_version(code: str, marker: str = "ATTACK") -> str | None:
    """The test with the <marker>-START..<marker>-END block(s) removed, or None if not marked.
    Variables declared inside the block are kept as uninitialised declarations (zero values), so the
    control still compiles and assertions that depended on the attack's result fail as they should."""
    def keep_decl(stmt: str) -> str | None:
        """For a (possibly multi-line) statement inside the block: the bare declaration to keep, or None."""
        one = " ".join(stmt.split())
        m = re.match(r"^([\w.\[\]]+(?:\s+(?:memory|storage|calldata))?)\s+(\w+)\s*=\s*.*;$", one)
        if m and m.group(1) not in ("return", "emit", "revert", "delete", "vm"):
            return f"{m.group(1)} {m.group(2)};"
        t = re.match(r"^\(([^)]*)\)\s*=\s*.*;$", one)
        if t:
            decls = [p.strip() for p in t.group(1).split(",") if " " in p.strip()]   # "uint8 v", not a bare name
            return " ".join(d + ";" for d in decls) if decls else None
        return None

    out, skipping, found = [], False, False
    stmt, indent = [], ""
    for l in code.splitlines():
        if f"{marker}-START" in l:
            skipping, found = True, True
            continue
        if f"{marker}-END" in l:
            skipping = False
            stmt = []
            continue
        if not skipping:
            out.append(l)
            continue
        if not stmt:
            indent = l[: len(l) - len(l.lstrip())]
        stmt.append(l.strip())
        joined = " ".join(stmt)
        if joined.endswith(";") and joined.count("(") <= joined.count(")"):   # statement complete
            d = keep_decl(joined)
            if d:
                out.append(indent + d)
            stmt = []
    return ("\n".join(out) + "\n") if found else None


# a project's foundry.toml may carry test filters (e.g. `no_match_path = ""`, which newer forge reads as
# "exclude everything"); override them so the PoC is always selected by --match-path/--match-test alone
FORGE_TEST_OVERRIDES = ["--no-match-path", "__poc_loop_never__", "--no-match-test", "__poc_loop_never__",
                        "--no-match-contract", "__poc_loop_never__",
                        "--skip", "*/invariants/*", "--skip", "*Crytic*", "--skip", "*.s.sol"]


def run_forge(root: Path, poc: Path, timeout: int):
    rel = str(poc.relative_to(root))
    # forge names the test "test_PoC()": an anchored "^test_PoC$" matches nothing
    rpc = load_rpc_env(root)
    fork = []                                  # projects meant to run with `forge test --fork-url ...` (rpc.env FORK_URL@...)
    if rpc.get("FORK_URL"):
        fork = ["--fork-url", rpc["FORK_URL"]] + (["--fork-block-number", rpc["FORK_BLOCK"]] if rpc.get("FORK_BLOCK") else [])
    return sh(["forge", "test", *FORGE_TEST_OVERRIDES, *fork, "--match-path", rel, "--match-test", r"^test_PoC\(", "-vvv"],
              root, timeout, env=forge_env(root))


def load_project(root: Path, leftover_glob: str = "PoC_*.t.sol"):
    """Layout, source files and the project-wide symbol index; removes leftover PoC files."""
    src_dir, test_dir, remaps = project_layout(root)
    for old in root.rglob(leftover_glob):
        # forge keeps compiled artifacts in out/<file>/ as DIRECTORIES of the same name: leave those
        if old.is_file() and not any(part in ("lib", "node_modules", "out", "cache") for part in old.relative_to(root).parts):
            print(f"[*] removing leftover {old.relative_to(root)}")
            old.unlink()
    files = [f for f in file_index(root) if f.suffix == ".sol" and not str(f).startswith(("lib/", "node_modules/"))]
    SYMBOLS.clear()
    _INHERIT_CACHE.clear()
    SYMBOLS.update(symbol_index(root, files + [t.relative_to(root) for t in test_files(root, test_dir)
                                                 if t.relative_to(root) not in files], test_dir))
    return src_dir, test_dir, files


def _gen_plan(args, user_prompt: str) -> str:
    """Autonomous planner: ask args.planner for a PLAN (JSON) from the build_prompt context."""
    import planner as _pl
    from audit_assist import llm_call
    return llm_call(backend=args.backend, system=_pl.PLANNER_SYSTEM,
                    user=_pl.to_planner_prompt(user_prompt), model=args.planner,
                    num_ctx=args.num_ctx, host=args.ollama_host, json_mode=False,
                    temperature=args.temperature)


def generate(args, prompt: str, k: int) -> list[str]:
    outs = []
    for i in range(k):
        temp = None if k == 1 else args.temperature
        resp = llm_call(args.backend, SYSTEM, prompt, args.model, args.num_ctx, args.ollama_host,
                        json_mode=False, temperature=temp)
        outs.append(strip_fences(resp))
    return outs


def prepare_item(item, root, test_dir, files, max_src: int, src_override=None):
    """Everything about a finding that does not depend on the parent: source file, claim functions,
    focused source, ranked parent candidates."""
    src = Path(src_override) if src_override else find_source(root, files, item)
    src_text = (root / src).read_text(errors="ignore") if src else ""
    claim_fns = claim_functions(src_text, item) if src else set()
    src_files = [f for f in files if not is_test_path(f, test_dir)]
    source_block = focused_source(src_text, claim_fns, max_src) if src else ""
    best_related = related_tests(root, test_dir, claim_fns, None, max_snippets=2)
    preferred = {l.split("// ----- ")[1].split(" :: ")[0] for l in best_related.splitlines() if l.startswith("// ----- ")}
    parents = parent_candidates(root, test_dir, src, item, claim_fns, preferred)
    return src, claim_fns, src_files, source_block, parents


_VIS = {"public", "external", "internal", "private", "view", "pure", "payable", "virtual", "override", "returns", "memory",
        "calldata", "storage"}


def _balanced(text: str, i: int) -> str:
    """The parenthesized text starting at text[i] == '('."""
    depth, j = 0, i
    while j < len(text):
        depth += {"(": 1, ")": -1}.get(text[j], 0)
        j += 1
        if depth == 0:
            break
    return text[i + 1: j - 1]


def _conditions(body: str) -> list[str]:
    out = []
    for m in re.finditer(r"\brequire\s*\(", body):
        out.append("require(" + " ".join(_balanced(body, m.end() - 1).split())[:160] + ")")
    for m in re.finditer(r"\bif\s*\(", body):
        cond = " ".join(_balanced(body, m.end() - 1).split())
        rest = body[m.end() - 1 + len(cond) + 2: m.end() + len(cond) + 120]
        r = re.match(r"\s*\{?\s*revert\s+(\w+)", rest)
        if r:
            out.append(f"if ({cond[:150]}) revert {r.group(1)}")
    return out


def precondition_hints(src_text: str, claim_fns: set[str], limit: int = 2500) -> str:
    """What the code requires on the path to the bug, extracted from the source (no model): per claim
    function its modifiers (and what they check), its require/revert conditions, one level into internal
    helpers it calls, and the lines that use msg.sender (whose state the call changes)."""
    clean = re.sub(r"//[^\n]*|/\*.*?\*/", "", src_text, flags=re.S)
    fns = {name: (a, b) for name, a, b in _functions(clean)}
    mods = {m.group(1): clean[m.end() - 1: m.end() - 1 + 1200]
            for m in re.finditer(r"\bmodifier\s+(\w+)\s*(?:\([^)]*\))?\s*\{", clean)}
    lines = []
    for name in sorted(claim_fns):
        if name not in fns:
            continue
        a, b = fns[name]
        head = clean[a: clean.index("{", a)]
        body = clean[clean.index("{", a): b]
        after = head[head.rfind(")") + 1:] if ")" in head else ""
        used_mods = [w for w in re.findall(r"\b([A-Za-z_]\w*)\b", after) if w not in _VIS and w in mods]
        entry = [f"{name}():"]
        for mname in used_mods:
            conds = _conditions(mods[mname])
            entry.append(f"  modifier {mname}: " + ("; ".join(conds[:3]) if conds else "(see source)"))
        entry += ["  " + c for c in _conditions(body)[:8]]
        for callee in sorted(set(re.findall(r"\b(_\w+)\s*\(", body)) & set(fns))[:4]:
            ca, cb = fns[callee]
            cc = _conditions(clean[clean.index("{", ca): cb])[:4]
            if cc:
                entry.append(f"  via {callee}(): " + "; ".join(cc))
        senders = [" ".join(l.split()) for l in body.splitlines() if "msg.sender" in l][:4]
        if senders:
            entry.append("  uses msg.sender (state of the CALLER changes; prank the right account): "
                         + " | ".join(x[:110] for x in senders))
        if len(entry) > 1:
            lines.append("\n".join(entry))
    text = "\n".join(lines)
    return text[:limit]


def plan_text(plan: dict) -> str:
    """A plan (extract_plans.py / plan_eval.py format) as numbered instructions for the PoC writer."""
    if not plan:
        return ""
    lines = [f"PoC type: {plan.get('poc_type') or 'direct_call'}"]
    setup = [s for s in plan.get("setup", []) if isinstance(s, dict)]
    if setup:
        lines.append("Setup (before the ATTACK block):")
        for i, st in enumerate(setup, 1):
            who = st.get("actor") or "?"
            lines.append(f"  {i}. " + (st["step"] if who in ("-", "?") else f"as {who}: {st.get('step')}"))
    lines.append("Attack (the only calls inside // ATTACK-START ... // ATTACK-END):")
    for st in plan.get("attack", []) or []:
        if isinstance(st, dict):
            who = st.get("actor") or "?"
            lines.append("  - " + (st.get("step", "") if who in ("-", "?", "test") else f"as {who}: {st.get('step')}"))
    checks = plan.get("asserts") or ([plan["assert"]] if plan.get("assert") else [])
    if checks:
        lines.append("Assert (the impact):")
        lines += [f"  - {c}" for c in checks[:4]]
    return "\n".join(lines)


def _impact_section(item) -> str:
    try:
        import impact_rules
        return impact_rules.section(str(item.get("title", "")), str(item.get("description", "") or ""))
    except Exception:  # noqa
        return ""


def _stuck_body(candidates):
    """STEP1 reads the stuck balance (pre-filled with the top candidate, menu in comments),
    STEP2 attack TODO, STEP3 the forced assert. restamp_stuck re-stamps STEP3 after generation."""
    if candidates:
        top = candidates[0]
        menu = "".join(f"        //   {c}\n" for c in candidates)
        step1 = (f"        // STEP 1 - record the balance that gets STRANDED by the bug, BEFORE the attack.\n"
                 f"        //   stuckBefore is pre-filled with the most likely expression. If another in this\n"
                 f"        //   list fits the finding better, use that one instead (they all compile):\n"
                 f"{menu}"
                 f"        uint256 stuckBefore = {top};\n")
        after_expr = top
    else:
        step1 = ("        // STEP 1 - record the balance that gets STRANDED by the bug, BEFORE the attack.\n"
                 "        //   e.g. token.balanceOf(address(theContract)).\n"
                 "        uint256 stuckBefore = /* FILL: the stuck-fund balance */ 0;\n")
        after_expr = "/* FILL: the same stuck-fund balance expression as stuckBefore */ 0"
    return (step1 +
        "\n        // STEP 2 - the attack: the call(s) that strand the funds (as the right actor). Fill this in.\n"
        "        // ATTACK-START\n        // FILL: the attacker's call(s)\n        // ATTACK-END\n\n"
        "        // STEP 3 - FORCED ASSERT - the harness re-stamps these two lines; they prove a STUCK bug\n"
        "        //   (funds still in the contract after the attack). Use the SAME expression as stuckBefore.\n"
        f"        uint256 stuckAfter = {after_expr};\n        assertGt(stuckAfter, 0);\n")


def skeleton_for(label, n, pname, pragma, imports, ppath, candidates=None):
    """Per-impact-class skeleton. For 'stuck' the correct assert SHAPE is pre-written and STEP 1 is
    pre-filled with the top candidate stuck-balance expression (menu in comments). Any other label
    (or None) returns the plain // TODO skeleton unchanged."""
    header = (f"// SPDX-License-Identifier: UNLICENSED\n{pragma}\n\n" + "\n".join(imports)
              + f"\nimport {{{pname}}} from \"./{ppath.name}\";\n\n"
              f"contract PoC_{n} is {pname} {{\n"
              f"    // setUp() is inherited from {pname}: everything it deploys/configures is ready.\n\n"
              f"    function test_PoC() public {{\n")
    if label == "stuck":
        body = _stuck_body(candidates or [])
    else:
        body = "        // TODO\n"
    return header + body + "    }}\n}}\n".replace("}}", "}")


def build_prompt(n, item, root, test_dir, src, claim_fns, src_files, source_block, parent, with_report_poc: bool,
                 hints: str = "", plan: dict | None = None):
    """The user prompt for one (finding, parent) pair, plus what the loop needs about the parent.
    Returns (user, skeleton, pctx, acc_vars, priv_vars, related)."""
    score, ppath, pname, pragma, imports, ptext, ps, pe, bases = parent
    global CURRENT_PARENT
    CURRENT_PARENT = pname
    pctx = parent_context(ptext, ps, pe)
    for btext, bs, be, bname in bases[:2]:          # inherited harness (BaseMarketTest): its vars/setUp/helpers too
        pctx = (f"// ----- inherited from {bname} -----\n" + parent_context(btext, bs, be, limit=6000)
                + f"\n// ----- end of {bname} -----\n\n" + pctx)
    acc_vars, priv_vars, var_types = parent_vars(pctx)
    priv_fns = re.findall(r"\bfunction\s+(\w+)\s*\([^)]*\)[^{;]*\bprivate\b", pctx)
    api = api_summary(root, src_files, src, must_have=var_types)
    related = related_tests(root, test_dir, claim_fns, ppath)
    try:
        import impact_rules
        _sk_label = impact_rules.label_of(str(item.get("title","")), str(item.get("description","") or ""))
    except Exception:
        _sk_label = None
    _sk_cands = None
    if _sk_label == "stuck":
        try:
            import assert_pass as _ap
            _sk_cands = _ap.stuck_candidates(dict(PARENT_VAR_TYPES),
                                             str(item.get("title","")) + " " + str(item.get("description","") or ""))
        except Exception:
            _sk_cands = None
    skeleton = skeleton_for(_sk_label, n, pname, pragma, imports, ppath, candidates=_sk_cands)
    user = (f"CLAIMED VULNERABILITY:\n{claim_text(item, with_report_poc)}\n\n"
            f"// ===== PARENT TEST (you inherit this; its setUp() runs before test_PoC; use these names) =====\n"
            f"// file: {ppath.relative_to(root)}\n{pctx}\n"
            + (f"// NOTE: private variables ({', '.join(priv_vars)}) are NOT accessible from your contract.\n" if priv_vars else "")
            + (f"// NOTE: private helper functions ({', '.join(priv_fns)}) are NOT inherited: to use one, copy its full body "
               f"into your contract under a new name (e.g. `{priv_fns[0]}_`) and call that.\n" if priv_fns else "")
            + "\n"
            + (f"// ===== RELATED TESTS (how the project's own tests call the claim's functions - copy "
               f"their precondition steps, NOT the whole test: a copy of an existing test proves nothing) =====\n{related}\n\n" if related else "")
            + (f"// ===== PLAN TO FOLLOW (implement exactly these steps, with these accounts, in this order; use "
               f"the parent test's real variable names) =====\n{plan_text(plan)}\n\n" if plan else "")
            + (f"// ===== WHAT THE CODE REQUIRES on the path to the bug (extracted from the source). Your test must "
               f"satisfy these to reach the vulnerable code; the ATTACK must be the step that breaks the security "
               f"property, not an ordinary successful call =====\n{hints}\n\n" if hints else "")
            + f"// ===== PROJECT API (public/external functions that exist) =====\n{api}\n\n"
            f"// ===== SOURCE UNDER TEST: {src or 'unknown'} =====\n{source_block}\n\n"
            + _impact_section(item)
            + f"// ===== SKELETON (fill in; keep header and imports) =====\n{skeleton}")
    return user, skeleton, pctx, acc_vars, priv_vars, related


def run_item(n, item, root, test_dir, files, args, outdir):
    src, claim_fns, src_files, source_block, parents = prepare_item(item, root, test_dir, files, args.max_src)
    record = {"n": n, "id": item.get("id"), "title": item.get("title"), "severity": item.get("severity"),
              "source": str(src) if src else None, "claim_functions": sorted(claim_fns),
              "parent": None, "related_tests": [], "tries": [], "outcome": None}
    api_idx = api_index(root, src_files)
    if not parents:
        record["outcome"] = "no_parent_test"
        return record
    parents = parents[:3]           # a parent whose setUp reverts (fork, env) -> next candidate

    for p_idx, parent in enumerate(parents):
        score, ppath, pname, pragma, imports, ptext, ps, pe, bases = parent
        record["parent"] = f"{ppath.relative_to(root)}::{pname}"
        user, skeleton, pctx, acc_vars, priv_vars, related = build_prompt(
            n, item, root, test_dir, src, claim_fns, src_files, source_block, parent, args.report_poc,
            hints=precondition_hints((root / src).read_text(errors="ignore"), claim_fns) if (args.hints and src) else "",
            plan=PLANS.get(item.get("id")))
        record["related_tests"] = [l.split(" :: ")[1].split("  (")[0] for l in related.splitlines() if l.startswith("// ----- ")]
        poc = ppath.parent / f"PoC_{n}.t.sol"
        prompt = user
        # kept for data generation: the exact prompt, plus the claim as it would read WITHOUT the report's PoC
        record["prompt"] = user
        record["claim_text"] = claim_text(item, args.report_poc)
        record["claim_text_bare"] = claim_text(item, False)
        used = {"inverted": False}
        done = False
        run_best = None   # best (progress, outcome, out, code) across ALL attempts
        for attempt in range(1, args.tries + 1):
            if args.assemble_plan and (args.planner or PLANS.get(item.get("id"))):
                import plan_assemble as _pa
                import assert_pass as _ap2, impact_rules as _ir2
                if args.planner:
                    import planner as _pl
                    _presp = _gen_plan(args, user)
                    _apl = _pl.parse_plan(_presp) or {}
                    if _apl:
                        _apl, _gr = _pl.ground_plan(_apl, user)
                        record["planner_grounded"] = _gr
                        # plan-level mechanical repair (actor rule etc.): fix the PLAN before
                        # assembly, so downstream assemble_test(_apl,...) uses the repaired actors.
                        if not getattr(args, "no_plan_repair", False):
                            try:
                                import plan_repair as _prp
                                def _asm(_pp): return _pa.assemble_test(_pp, n, pname, pragma, imports, ppath.name, known_names=set(PARENT_VAR_TYPES))
                                def _rn(_code):
                                    _poc = ppath.parent / ("PoC_%d_prep.t.sol" % n)
                                    for _st in _poc.parent.glob("PoC_*.t.sol"):
                                        if _st != _poc:
                                            try: _st.unlink()
                                            except OSError: pass
                                    _poc.write_text(_code)
                                    _rc, _o = run_forge(root, _poc, args.timeout)
                                    try: _poc.unlink()
                                    except OSError: pass
                                    return classify(_rc, _o), _o
                                _oc_pr, _c_pr, _apl, _plog = _prp.repair_plan(_apl, user, _asm, _rn)
                                if _plog:
                                    record["plan_repairs"] = _plog
                            except Exception as _e:
                                record["plan_repair_error"] = repr(_e)[:200]
                    if getattr(args, "plan_mix", None) and PLANS.get(item.get("id")):
                        _ora = PLANS[item.get("id")]
                        if args.plan_mix == "oracle-setup" and _ora.get("setup"):
                            _apl["setup"] = _ora["setup"]
                        if args.plan_mix == "oracle-attack" and _ora.get("attack"):
                            _apl["attack"] = _ora["attack"]
                        record["plan_mix"] = args.plan_mix
                    record["planner_raw"] = (_presp or "")[:3000]
                else:
                    _apl = PLANS[item.get("id")]
                _txt = str(item.get("title","")) + " " + str(item.get("description","") or "")
                _lab = _ir2.label_of(str(item.get("title","")), str(item.get("description","") or ""))
                _uc = _ap2.claimable_from_plan(_apl.get("asserts") or [])
                _st = _ap2.stuck_candidates(dict(PARENT_VAR_TYPES), _txt)
                # redeploy/standalone: if the plan references a PRIVATE parent var, `is Parent`
                # cannot see it -> rebuild the parent's state vars + setUp locally (test fns
                # stripped), inheriting the parent's own base instead of the parent test.
                _sa_scan = " ".join((_s.get("step", "") or "")
                                    for _k in ("setup", "attack") for _s in (_apl.get(_k) or [])) \
                           + " " + " ".join(_apl.get("asserts") or [])
                _sa = {}
                if any(re.search(rf"\b{re.escape(_v)}\b", _sa_scan) for _v in (priv_vars or [])):
                    _m_inh = re.search(rf"\bcontract\s+{re.escape(pname)}\b([^{{]*)\{{", ptext)
                    _inh = re.search(r"\bis\s+(.+)$", _m_inh.group(1).strip()) if _m_inh else None
                    _sa = dict(standalone_inherit=(_inh.group(1).strip() if _inh else "Test"),
                               standalone_shell=parent_context(ptext, ps, pe, limit=10**9))
                if _uc and _st:
                    cands = [_pa.assemble_test(_apl, n, pname, pragma, imports, ppath.name, force_assert_expr=_st[0], unclaimable_asserts=["assertEq(" + _uc + ", 0);"], known_names=set(PARENT_VAR_TYPES), **_sa)]
                elif _lab == "theft":
                    _atk = next((x.get("actor") for x in (_apl.get("attack") or []) if (x.get("actor") or "").strip() not in ("","-","test","this","address(this)")), "address(this)")
                    _tc = _ap2.theft_candidates(dict(PARENT_VAR_TYPES), _txt, _atk)
                    cands = [_pa.assemble_test(_apl, n, pname, pragma, imports, ppath.name, theft_expr=_tc[0], known_names=set(PARENT_VAR_TYPES), **_sa)] if _tc else [_pa.assemble_test(_apl, n, pname, pragma, imports, ppath.name, known_names=set(PARENT_VAR_TYPES), **_sa)]
                else:
                    cands = [_pa.assemble_test(_apl, n, pname, pragma, imports, ppath.name, known_names=set(PARENT_VAR_TYPES), **_sa)]
            else:
                cands = generate(args, prompt, args.samples)
            best = None                      # (progress, outcome, forge output, code)
            marker_retry_now = False
            for ci, code in enumerate(cands, 1):
                tag = f"PoC_{n}_p{p_idx + 1}_try{attempt}" + (f"_s{ci}" if args.samples > 1 else "")
                (outdir / f"{tag}.t.sol").write_text(code)
                if code.lstrip().startswith("// NOT_DEMONSTRABLE"):
                    if best is None:
                        best = (-1, "not_demonstrable", "", code, ci)
                    continue
                # option #2 enforcement: for a stuck-class finding, force the canonical assert
                # (uint256 stuckAfter = <model's stuckBefore expr>; assertGt(stuckAfter, 0)) no matter
                # what the model wrote. Model keeps attack + expression; harness owns the assert shape.
                try:
                    import impact_rules as _ir, assert_pass as _ap
                    if _ir.label_of(str(item.get("title", "")), str(item.get("description", "") or "")) == "stuck":
                        _cands = _ap.stuck_candidates(dict(PARENT_VAR_TYPES),
                                                      str(item.get("title", "")) + " " + str(item.get("description", "") or ""))
                        if _cands:
                            _plan = PLANS.get(item.get("id")) or {}
                            _unclaim = _ap.claimable_from_plan(_plan.get("asserts") or [])
                            code, _forced = _ap.force_stuck_assert(code, _cands[0], _unclaim)
                            if _forced:
                                record["forced_assert"] = True
                                record["forced_expr"] = _cands[0]
                                if _unclaim:
                                    record["forced_unclaimable"] = _unclaim
                except Exception:
                    pass
                for _stale in poc.parent.glob("PoC_*.t.sol"):
                    if _stale != poc:
                        try: _stale.unlink()
                        except OSError: pass
                poc.write_text(code)
                rc, out = run_forge(root, poc, args.timeout)
                outcome = classify(rc, out)
                for _ in range(3):           # declare `attacker`, import a missing type, ...: no model round needed
                    if outcome != "compile_error":
                        break
                    repaired = auto_repair(code, out, root, poc.parent)
                    if not repaired:
                        break
                    poc.write_text(repaired)
                    rc2, out2 = run_forge(root, poc, args.timeout)
                    if classify(rc2, out2) != "compile_error" or len(errors_at(out2)) < len(errors_at(out)):
                        code, rc, out, outcome = repaired, rc2, out2, classify(rc2, out2)
                        (outdir / f"{tag}_repaired.t.sol").write_text(code)
                        record["auto_repaired"] = record.get("auto_repaired", 0) + 1
                    else:
                        poc.write_text(code)
                        break
                code_lines = code.splitlines()
                record["tries"].append({"parent": p_idx + 1, "attempt": attempt, "sample": ci, "outcome": outcome,
                                        "reason": fail_reason(out) or fail_reason(out, "setUp"),
                                        "errors": [f"{msg} @ {ln}: {code_lines[ln - 1].strip() if 0 < ln <= len(code_lines) else ''}"
                                                   for msg, path, ln, col in errors_at(out)[:6] if "PoC_" in path],
                                        "forge_tail": out[-2500:]})
                if outcome == "pass" and looks_inverted(code):
                    outcome = "fail"                     # passed for the wrong reason: treat as a failure to rewrite
                    out += "\n[harness] test passed but expects the attack to be BLOCKED (inverted test)\n"
                if outcome == "pass":
                    if not HAS_ASSERT.search(code):
                        outcome = "no_assert"
                    else:
                        ctrl = control_version(code)
                        nested = ctrl is not None and markers_nested(code)
                        if ctrl is None or nested:
                            outcome = "pass_unverified"
                            record["tries"][-1]["outcome"] = outcome
                            record["tries"][-1]["reason"] = ("passed, but ATTACK and MALICIOUS-SETUP blocks overlap: knockouts not independent"
                                                             if nested else "passed, but no ATTACK markers: control run impossible")
                            if attempt < args.tries and not record.get("marker_retry"):
                                record["marker_retry"] = True      # ask once for the markers, then re-test
                                prompt = (user + "\n\n" + (NESTED_MARKERS if nested else NO_MARKERS)
                                          + "\n\nYOUR PREVIOUS FILE:\n" + code)
                                marker_retry_now = True
                                break
                        else:
                            poc.write_text(ctrl)
                            crc, cout = run_forge(root, poc, args.timeout)
                            c = classify(crc, cout)
                            record["control"] = c
                            outcome = {"pass": "pass_no_control", "fail": "pass"}.get(c, "pass_unverified")
                            # second knockout: without the malicious preparation the test must fail too
                            ctrl2 = control_version(code, "MALICIOUS-SETUP") if outcome == "pass" else None
                            rb = readback_asserts(code) if outcome == "pass" else []
                            if rb:
                                outcome = "pass_unverified"
                                record["tries"][-1]["outcome"] = outcome
                                record["tries"][-1]["reason"] = ("passed, but the assert only reads back a value the "
                                                                 "attack passed in: " + "; ".join(rb))[:300]
                            if outcome == "pass":
                                why = []
                                sv = same_value_failure(fail_reason(cout) or "")
                                if sv:
                                    why.append(f"without the attack the assert compares a value with itself ({sv}): nothing changed")
                                rt = own_funds_roundtrip(code)
                                if rt:
                                    why.append("the attack only takes back the test's own deposit: " + "; ".join(rt))
                                pg = attacker_granted_privilege(code)
                                if pg:
                                    why.append(pg[0])
                                pc = pure_computation_attack(code)
                                if pc:
                                    why.append(pc[0])
                                if why:
                                    outcome = "pass_unverified"
                                    record["tries"][-1]["outcome"] = outcome
                                    record["tries"][-1]["reason"] = ("passed, but " + "; ".join(why))[:300]
                            if outcome == "pass" and ctrl2 is None and needs_setup_markers(code, allowed=project_mocks(root)):
                                outcome = "pass_unverified"
                                record["tries"][-1]["outcome"] = outcome
                                record["tries"][-1]["reason"] = "passed, but deploys a malicious/mock contract without MALICIOUS-SETUP markers"
                                if attempt < args.tries and not record.get("setup_marker_retry"):
                                    record["setup_marker_retry"] = True
                                    record["outcome"] = outcome
                                    shutil.copy(poc, outdir / f"PoC_{n}.t.sol")
                                    prompt = user + "\n\n" + NO_SETUP_MARKERS + "\n\nYOUR PREVIOUS FILE:\n" + code
                                    marker_retry_now = True
                                    break
                            if ctrl2 is not None:
                                poc.write_text(ctrl2)
                                c2 = classify(*run_forge(root, poc, args.timeout))
                                record["control_setup"] = c2
                                if c2 == "pass":
                                    outcome = "pass_no_control"   # the malicious ingredient didn't matter
                                    out += "\n[harness] test also passes WITHOUT the malicious setup\n"
                            poc.write_text(code)
                    if outcome == "pass":
                        # the knockouts prove the assertion depends on the attack call, not that the call is a bug.
                        # Two cheap checks for the false passes seen in practice:
                        sim, twin = copied_project_test(code, root, test_dir)
                        attack_calls = called_functions(attack_block(code))
                        relevant = not claim_fns or bool(attack_calls & {f.lstrip("_") for f in claim_fns}) \
                            or bool(attack_calls & claim_idents(item))
                        record["similarity"] = round(sim, 3)
                        record["most_similar_test"] = twin
                        if sim >= COPY_THRESHOLD:
                            outcome = "pass_copied_test"     # an existing project test (a happy path) with markers added
                            record["copied_from"] = f"{twin} ({sim:.0%} similar)"
                        elif not relevant:
                            outcome = "pass_irrelevant"      # the attack never calls anything the finding is about
                            record["attack_calls"] = sorted(attack_calls)[:12]
                        if outcome == "pass":
                            import impact_rules as _ir, assert_pass as _ap
                            _precond = _ir.precondition_of(str(item.get("title", "")), str(item.get("description", "") or ""))
                            if _precond and not _ap.precondition_instantiated(code, _precond):
                                outcome = "pass_unverified"
                                record["precondition_missing"] = _precond
                                record["tries"][-1]["outcome"] = outcome
                                record["tries"][-1]["reason"] = (f"passed, but the finding needs a {_precond} precondition the "
                                                                 "setup never instantiates (ran against a benign token): happy path, not the bug")
                                if attempt < args.tries and not record.get("precondition_retry"):
                                    record["precondition_retry"] = True
                                    record["outcome"] = outcome
                                    shutil.copy(poc, outdir / f"PoC_{n}.t.sol")
                                    prompt = user + "\n\n" + NO_PRECONDITION.format(precond=_precond.replace("_", " ")) + "\n\nYOUR PREVIOUS FILE:\n" + code
                                    marker_retry_now = True
                                    break
                        if outcome == "pass":
                            import assert_pass as _apg
                            _find = str(item.get("title", "")) + " " + str(item.get("description", "") or "")
                            _gated, _hits = _apg.privileged_setup_in_attack(code, _find)
                            if _gated:
                                outcome = "pass_unverified"
                                record["privileged_setup"] = _hits
                                record["tries"][-1]["outcome"] = outcome
                                record["tries"][-1]["reason"] = ("passed, but the attack-enabling setup reconfigures the "
                                                                 "protocol or grants the attacker privilege (" + ", ".join(_hits) +
                                                                 ") the finding never mentions: fabricated green knockout, not the bug")
                                if attempt < args.tries and not record.get("privilege_retry"):
                                    record["privilege_retry"] = True
                                    record["outcome"] = outcome
                                    shutil.copy(poc, outdir / f"PoC_{n}.t.sol")
                                    prompt = user + "\n\n" + NO_PRIVILEGE.format(hits=", ".join(_hits)) + "\n\nYOUR PREVIOUS FILE:\n" + code
                                    marker_retry_now = True
                                    break
                        # soft read-prioritizer flags (do NOT change outcome): cheat/admin powers in
                        # ATTACK, and asserts whose shape does not match the finding impact class.
                        _impact = " ".join(str(item.get(k, "")) for k in ("title", "description"))
                        _flags = list(flag_powers(code)) + list(impact_mismatch(code, _impact))
                        if _flags:
                            record["flags"] = _flags
                            record["tries"][-1]["flags"] = _flags
                        if outcome != "pass":
                            record["tries"][-1]["outcome"] = outcome
                    if outcome == "pass" and record.get("flags") and attempt < args.tries and not record.get("assert_shape_retry"):
                        # a flagged pass: attack survived both knockouts, but the assert shape is wrong.
                        # one assert-only retry, handed the impact template. never changes the outcome if it fails.
                        try:
                            import impact_rules
                            _lab = impact_rules.label_of(str(item.get("title","")), str(item.get("description","") or ""))
                            _tpl = impact_rules.TEMPLATES.get(_lab) if _lab else None
                        except Exception:
                            _lab = _tpl = None
                        if _tpl:
                            record["assert_shape_retry"] = True
                            record["outcome"] = outcome            # kept if the retry does not improve on it
                            shutil.copy(poc, outdir / f"PoC_{n}.t.sol")
                            prompt = user + "\n\n" + ASSERT_SHAPE.format(label=_lab, template=_tpl) + "\n\nYOUR PREVIOUS FILE:\n" + code
                            marker_retry_now = True
                            break
                    if outcome == "pass_no_control" and attempt < args.tries and not record.get("no_control_retry"):
                        # the setup is right and the test runs: one round to make the assertion depend on the attack
                        record["no_control_retry"] = True
                        record["outcome"] = outcome            # kept if the retry does not improve on it
                        shutil.copy(poc, outdir / f"PoC_{n}.t.sol")
                        which = ("the malicious setup (MALICIOUS-SETUP block)" if record.get("control_setup") == "pass"
                                 else "the attack (ATTACK block)")
                        prompt = user + "\n\n" + NO_CONTROL.format(which=which) + "\n\nYOUR PREVIOUS FILE:\n" + code
                        marker_retry_now = True
                        break
                    shutil.copy(poc, outdir / f"PoC_{n}.t.sol")
                    record["outcome"] = outcome
                    done = True
                    break
                p = progress(outcome, out)
                record["tries"][-1]["progress"] = p
                if best is None or p > best[0]:
                    best = (p, outcome, out, code, ci)
            if done:
                break
            if marker_retry_now:
                if record["outcome"] is None:
                    record["outcome"] = "pass_unverified"   # kept if the marker round doesn't improve on it
                    shutil.copy(poc, outdir / f"PoC_{n}.t.sol")
                continue                                 # prompt already asks for the markers / a better assertion
            if best is None:
                continue
            _, outcome, out, code, best_ci = best
            if run_best is None or best[0] > run_best[0]:
                run_best = (best[0], outcome, out, code, best_ci)
            record.setdefault("fed_back", []).append({"attempt": attempt, "sample": best_ci, "parent": p_idx + 1,
                                                      "outcome": outcome, "reason": fail_reason(out)[:120]})
            if outcome == "not_demonstrable":
                record["outcome"] = "not_demonstrable"
                record["reason"] = code.strip().splitlines()[0][:300]
                done = True
                break
            if outcome == "setup_error":
                record.setdefault("setup_errors", []).append(fail_reason(out, "setUp"))
                break                                   # this parent can't run here: next parent
            if attempt == args.tries:
                record["outcome"] = outcome
                done = True
                break
            # feedback for the next round
            reason = fail_reason(out)
            if outcome == "compile_error":
                prompt = (user + "\n\n" + FIX.format(error=compile_errors(out, code, acc_vars, priv_vars, api_idx))
                          + "\n\nYOUR PREVIOUS FILE:\n" + code)
            elif outcome == "no_test":
                prompt = (user + "\n\nYour file compiled but contains no `function test_PoC() public`. "
                          "Add it (exactly that name) and output the COMPLETE file.\n\nYOUR PREVIOUS FILE:\n" + code)
            elif looks_inverted(code) and not used["inverted"]:
                used["inverted"] = True
                record["inverted_first"] = True
                prompt = user + "\n\n" + INVERTED.format(error=out[-1200:]) + "\n\nYOUR PREVIOUS FILE:\n" + code
            elif reason and "assert" in reason.lower():
                record.setdefault("assert_fails", []).append(reason)
                prompt = (user + "\n\n" + ASSERT_FAILED.format(reason=reason, trace=failure_trace(out))
                          + "\n\nYOUR PREVIOUS FILE:\n" + code)
            else:                                # a revert (or an unparsed failure): trace feedback, every round
                record.setdefault("test_reverts", []).append(reason or "(unknown)")
                h = revert_hint(reason)
                tr = failure_trace(out)
                src_hint = revert_source(reason or "", root, trace=tr)
                record.setdefault("revert_sources", []).append(bool(src_hint))
                prompt = (user + "\n\n" + REVERTED.format(reason=reason or "(see trace)", trace=tr,
                                                           hint=(f"What this usually means: {h}\n" if h else "") + src_hint)
                          + "\n\nYOUR PREVIOUS FILE:\n" + code)
            if prompt.startswith(user) and "\n\nYOUR PREVIOUS FILE:\n" in prompt:
                record["fed_back"][-1]["feedback"] = prompt[len(user):].split("\n\nYOUR PREVIOUS FILE:\n")[0].strip()
        if poc.exists():
            if not (outdir / f"PoC_{n}.t.sol").exists():
                shutil.copy(poc, outdir / f"PoC_{n}.t.sol")
            poc.unlink()
        if record.get("marker_retry") and record["outcome"] in ("fail", "compile_error", "no_test", None):
            record["outcome"] = "pass_unverified"        # the marker round made it worse: keep the honest label
        if record.get("assert_shape_retry") and record["outcome"] in ("fail", "compile_error", "no_test", "pass_unverified", None):
            record["outcome"] = "pass"                    # forced assert-shape retry regressed: keep the honest pass
        if record.get("no_control_retry") and record["outcome"] in ("fail", "compile_error", "no_test", "pass_unverified", None):
            record["outcome"] = "pass_no_control"        # same for the assertion round
        if record.get("setup_marker_retry") and record["outcome"] in ("fail", "compile_error", "no_test", None):
            record["outcome"] = "pass_unverified"
        if done or record["outcome"] is not None:
            break
    if record["outcome"] is None:
        record["outcome"] = "setup_error" if record.get("setup_errors") else "fail"
    # Don't let a later attempt's REGRESSION bury a better earlier one. If some attempt got
    # further (higher progress) than the reported outcome, promote that attempt's result and
    # keep its .sol as PoC_<n>. Never downgrades a pass-family verdict (those are set by the
    # control/knockout machinery, not by raw progress).
    try:
        if run_best is not None and record["outcome"] not in (
                "pass", "pass_no_control", "pass_unverified", "pass_irrelevant",
                "not_demonstrable", "setup_error"):
            rb_p, rb_oc, rb_out, rb_code, _ = run_best
            if progress(record["outcome"], "") < rb_p and rb_oc not in ("compile_error",):
                record["outcome"] = rb_oc
                record["promoted_from_best"] = True
                _final = outdir / f"PoC_{n}.t.sol"
                _final.write_text(rb_code)
    except Exception:
        pass
    return record


def main():
    ap = argparse.ArgumentParser(description="Model writes Foundry PoCs on top of the project's own tests; forge decides")
    ap.add_argument("repo", type=Path, help="Foundry project root (a built contest)")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--truth", help="Published report: try to prove the REAL findings (ceiling test)")
    g.add_argument("--hypotheses", help="findings.json from audit_assist: try to prove the top-N")
    ap.add_argument("--top", type=int, default=15)
    ap.add_argument("--only", nargs="+", help="Only these finding ids (truth mode), e.g. H-01 M-03")
    ap.add_argument("--tries", type=int, default=3, help="Feedback rounds per item")
    ap.add_argument("--samples", type=int, default=1, help="Candidates per round (first that passes wins)")
    ap.add_argument("--temperature", type=float, default=0.5, help="Used when --samples > 1")
    ap.add_argument("--plans", type=Path, help="JSON {finding id: plan}: put a plan to follow in the prompt")
    ap.add_argument("--assemble-plan", action="store_true", help="findings with a plan: assemble the test from the plan directly (bypass the model)")
    ap.add_argument("--planner", help="autonomous: generate the plan with THIS model, then assemble it (implies --assemble-plan)")
    ap.add_argument("--no-plan-repair", action="store_true", help="disable plan-level mechanical repair (plan_repair.repair_plan)")
    ap.add_argument("--plan-mix", choices=["oracle-setup","oracle-attack"], help="diagnostic: replace planner plan setup or attack with the oracle plan (needs --plans)")
    ap.add_argument("--hints", action="store_true",
                    help="Add extracted preconditions (modifiers, require/revert conditions, msg.sender use) to the prompt")
    ap.add_argument("--report-poc", action="store_true",
                    help="Truth mode: also show the report's own PoC code block (easier task; for data generation)")
    ap.add_argument("--need-report-poc", action="store_true",
                    help="Truth mode: skip findings whose report has no code block to port (data generation)")
    ap.add_argument("--backend", choices=BACKENDS, default="ollama")
    ap.add_argument("--model")
    ap.add_argument("--ollama-host", default="http://localhost:11434")
    ap.add_argument("--num-ctx", type=int, default=16384)
    ap.add_argument("--max-src", type=int, default=14000, help="Max chars of source in the prompt (focused on the claim's functions)")
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--out", type=Path, default=Path("poc_out"))
    args = ap.parse_args()
    if getattr(args, "planner", None):
        args.assemble_plan = True
    args.model = args.model or DEFAULT_MODEL[args.backend]
    if args.plans:
        _raw_plans = json.loads(args.plans.read_text())
        # plans are keyed "<contest> <id>" (e.g. "sherlock-2024-06-magicsea H-04");
        # poc_loop looks up PLANS.get(item["id"]) with the bare id ("H-04"). Re-key to
        # the bare finding id. poc_loop runs ONE contest per invocation, so bare ids are
        # unique *within a run* - but a multi-contest --plans file has colliding bare ids
        # (every contest has an M-01). Re-keying such a file silently runs the WRONG
        # contest's plan. Guard: if bare ids collide, keep only the plan(s) whose prefix
        # matches this run's finding ids (args.only), else refuse rather than clobber.
        from collections import Counter as _Ctr
        _bare = [k.rsplit(' ', 1)[-1] for k in _raw_plans]
        _dups = {b for b, c in _Ctr(_bare).items() if c > 1}
        if _dups:
            _only = set(getattr(args, "only", None) or [])
            _keep = {k: v for k, v in _raw_plans.items()
                     if k.rsplit(' ', 1)[-1] in _only} if _only else {}
            if _keep and len({k.rsplit(' ',1)[-1] for k in _keep}) == len(_keep):
                PLANS.update({k.rsplit(' ', 1)[-1]: v for k, v in _keep.items()})
            else:
                raise SystemExit(
                    "ERROR: --plans has colliding bare ids %s across contests. "
                    "Pass a single-contest plans file, or use --only to pick findings "
                    "with unique ids. Refusing to run the wrong plan." % sorted(_dups))
        else:
            PLANS.update({k.rsplit(' ', 1)[-1]: v for k, v in _raw_plans.items()})

    root = args.repo.resolve()
    if not (root / "foundry.toml").exists():
        sys.exit(f"[!] {root} has no foundry.toml (Hardhat projects are not supported yet)")
    if not shutil.which("forge"):
        sys.exit("[!] forge not found: curl -L https://foundry.paradigm.xyz | bash && foundryup")
    check_backend(args.backend, args.ollama_host, args.model)

    src_dir, test_dir, files = load_project(root)

    if args.truth:
        items = parse_truth(Path(args.truth))
        if args.only:
            items = [t for t in items if t["id"] in set(args.only)]
        if args.need_report_poc:
            n0 = len(items)
            items = [t for t in items if report_code_blocks(str(t.get("description", "")))]
            print(f"[*] {n0 - len(items)} finding(s) without a report PoC skipped")
        mode = "truth"
    else:
        items = json.loads(Path(args.hypotheses).read_text())[:args.top]
        for i, h in enumerate(items):
            h.setdefault("id", f"#{i + 1}")
        mode = "hypotheses"
    if not items:
        sys.exit("[!] nothing to try")

    args.out.mkdir(parents=True, exist_ok=True)
    print(f"[*] {len(items)} item(s) from {mode}, model {args.backend}:{args.model}, project {root.name} "
          f"(src={src_dir.name}, test={test_dir.name}), {args.samples} sample(s) x {args.tries} round(s)")
    print("[*] making sure the project compiles first (a big project's first build can take minutes) ...")
    rc, out = sh(["forge", "build", "--skip", "*/invariants/*", "--skip", "*Crytic*", "--skip", "*.s.sol"], root, args.timeout)
    if rc != 0:
        sys.exit("[!] forge build fails before we start:\n" + out[-1500:])

    results = []
    for n, item in enumerate(items, 1):
        print(f"\n[{n}/{len(items)}] {item.get('id')}: {str(item.get('title', ''))[:70]}")
        rec = run_item(n, item, root, test_dir, files, args, args.out)
        results.append(rec)
        extra = f", control: {rec['control']}" if rec.get("control") else ""
        print(f"    -> {rec['outcome']}  (source: {rec['source'] or '?'}, parent: {rec['parent'] or '-'}, "
              f"{len(rec['tries'])} forge run(s){extra})")
        (args.out / "results.json").write_text(json.dumps(results, indent=2))

    counts = {}
    for r in results:
        counts[r["outcome"]] = counts.get(r["outcome"], 0) + 1
    lines = [f"# PoC loop: {root.name} ({mode}, {args.model}, samples={args.samples})", "",
             "| # | id | outcome | parent | title |", "|---|---|---|---|---|"]
    for r in results:
        lines.append(f"| {r['n']} | {r['id']} | **{r['outcome']}** | {(r['parent'] or '-').split('::')[-1]} | {str(r['title'])[:60]} |")
    lines += ["", "**Totals:** " + ", ".join(f"{v} {k}" for k, v in sorted(counts.items(), key=lambda x: -x[1]))]
    (args.out / "summary.md").write_text("\n".join(lines) + "\n")
    print("\n" + lines[-1])
    print(f"[*] Details: {args.out}/summary.md, results.json, PoC_<n>*.t.sol")
    if counts.get("pass"):
        print("[*] 'pass' = passed and failed without the attack. Still read each one: it proves only what it asserts.")


if __name__ == "__main__":
    main()


NO_PRECONDITION = """Your test passed, but this finding only happens under a {precond} token, and your
test runs the attack against a normal token - so it proves the ordinary case, not the bug. Set up the
hostile precondition: deploy a {precond} token whose transfer ACTUALLY takes the fee / rebases, use THAT
token everywhere the finding's asset is used, then run the same attack. The proof is that the victim or
contract ends up with LESS than it should - assert the shortfall (a strict inequality), never an equality
to the full amount. Keep the ATTACK and MALICIOUS-SETUP markers. Output the COMPLETE file (Solidity only).
"""
