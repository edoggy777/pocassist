#!/usr/bin/env python3
"""
assert_pass.py - a focused "second pass" that rewrites ONLY the assertions of a PoC test that
already passes + survives both knockouts, but was read as a FALSE proof (wrong actor, asserting
normal behaviour, or admin/cheat powers). The control run structurally cannot catch these
(poc_loop fix-list #10): it only proves the assert depends on the attack, not that the assert
checks DAMAGE rather than normal behaviour.

This does two independent things, both cheap and offline-checkable:

  1. flag_powers(code)   - static scan of the ATTACK block for cheat/admin lines that make a
                           "pass" meaningless (vm.store, vm.mockCall on a target, deal/warp inside
                           ATTACK, or an onlyOwner-style call with no preceding non-admin prank).
                           Pure regex, no model, no network. Run this first - it's free.

  2. rewrite_assert(...) - ask the model to rewrite ONLY the asserts (and nothing else) so they
                           check the DAMAGE described in the finding's impact text. Returns the
                           new full file as a string. You then re-run + re-knockout it yourself.

NOTHING here is wired into poc_loop.py. Run it by hand on the three false passes first
(see the __main__ driver at the bottom), eyeball the output, and only then decide to wire it in.

Usage:
  python3 assert_pass.py <path/to/PoC_test.sol> --impact "<finding impact text>"           # rewrite
  python3 assert_pass.py <path/to/PoC_test.sol> --flags-only                                # scan only
  python3 assert_pass.py <path/to/PoC_test.sol> --impact "..." --model poc-7b-v6 --out new.sol
"""
import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from audit_assist import llm_call, DEFAULT_MODEL   # same backend poc_loop uses


# ---- 1. static power/cheat flags (no model) -------------------------------------------------

ADMIN_CALL = re.compile(r"\.(setOwner|transferOwnership|grantRole|setAdmin|setGovernance|"
                        r"setController|setMinter|setPauser|initialize|upgradeTo\w*|setImplementation)\s*\(")
PRANK = re.compile(r"vm\.(prank|startPrank)\s*\(\s*([^)]*?)\s*\)")


def attack_span(code: str) -> tuple[int, int]:
    s = code.find("ATTACK-START")
    e = code.find("ATTACK-END")
    return (s, e) if (s >= 0 and e > s) else (-1, -1)


def flag_powers(code: str) -> list[str]:
    """Lines inside the ATTACK block that make a pass prove nothing. Empty list = clean."""
    s, e = attack_span(code)
    if s < 0:
        return ["no ATTACK markers - cannot scan"]
    block = code[s:e]
    hits = []
    for ln in block.splitlines():
        t = ln.strip()
        if not t or t.startswith("//"):
            continue
        if "vm.store(" in t:
            hits.append(f"vm.store in ATTACK (writes storage directly): {t}")
        if re.search(r"vm\.mockCall\s*\(", t):
            hits.append(f"vm.mockCall in ATTACK (fakes a return value): {t}")
        if re.search(r"vm\.(deal|warp|roll|etch)\s*\(", t):
            hits.append(f"vm.{re.search(r'vm.(deal|warp|roll|etch)', t).group(1)} in ATTACK (should be setup, not attack): {t}")
        if ADMIN_CALL.search(t):
            # an admin call is only damning if no non-admin prank precedes it in the block
            before = block[:block.find(ln)]
            pranks = PRANK.findall(before)
            last = pranks[-1][1] if pranks else ""
            looks_admin_actor = any(w in last.lower() for w in ("owner", "admin", "gov", "deployer", "address(this)")) or not pranks
            if looks_admin_actor:
                hits.append(f"admin-only call with no attacker prank before it: {t}")
    return hits


def current_pranks(code: str) -> list[str]:
    s, e = attack_span(code)
    seg = code[s:e] if s >= 0 else code
    return [m.group(2) for m in PRANK.finditer(seg)]


# ---- impact-class warning (no model): does the assert SHAPE match the bug CLASS? ------------
# Not a reject - a flag for the human read. It cannot know semantics (whether `x==0` is the bug
# or is normal); it only notices when the asserts lack the shape the impact class needs.

STUCK = re.compile(r"\b(stuck|locked|frozen|trapped|forever|never be (?:redeem|withdraw)|"
                   r"cannot be (?:redeem|withdraw)|unable to (?:withdraw|redeem)|permanently)\b", re.I)
DRAIN = re.compile(r"\b(drain|steal|stolen|theft|attacker (?:gain|profit|receive)|"
                   r"siphon|loss of funds|lose funds)\b", re.I)
AFTER_BLOCK_ASSERTS = re.compile(r"\bassert(Eq|Gt|Ge|Lt|Le|True|False|NotEq|ApproxEq\w*)?\s*\(([^;]*)\)\s*;")


def _asserts_after_attack(code: str) -> list[str]:
    _, e = attack_span(code)
    tail = code[e:] if e >= 0 else code
    return [m.group(0) for m in AFTER_BLOCK_ASSERTS.finditer(tail)]


# A many-digit numeric literal pinned in an assertEq after the attack: the model recorded a value the
# attack just PRODUCED and asserted equality to it - a read-back the control run cannot catch
# (fix-list #11). The literal can be the bare rhs OR buried in a ternary (`x ? 123... : 456...`), so we
# scan the whole assert for any long digit-run not glued to an identifier (an address/hex is 0x..., a
# token amount is usually written `N ether` / `N * 1e18`, not a raw 18-digit integer).
ASSERT_EQ_LINE = re.compile(r"\bassertEq\w*\s*\(.*", re.S)
BIG_LITERAL = re.compile(r"(?<![\w.])(\d{6,})(?![\w.])")


def magic_constant_asserts(code: str) -> list[str]:
    """assertEq(..., <big numeric literal>) in the post-attack asserts: a produced-value read-back."""
    hits = []
    for a in _asserts_after_attack(code):
        if not a.lstrip().startswith("assertEq"):
            continue
        lits = [n for n in BIG_LITERAL.findall(a) if n not in ("0", "1")]
        if lits:
            hits.append(a.strip())
    return hits


def impact_mismatch(code: str, impact: str) -> list[str]:
    """Warn when the asserts don't have the shape the finding's impact class calls for."""
    asserts = _asserts_after_attack(code)
    joined = " ".join(asserts)
    warns = []
    # class-independent: a magic-constant read-back is wrong whatever the impact says, and fires
    # even with no impact text, so check it before the early return.
    for h in magic_constant_asserts(code):
        warns.append(f"assert pins a produced value to a hardcoded literal ({h}) - a read-back the "
                     f"control run can't catch, not a proof of damage. READ IT.")
    if not impact:
        return warns
    if STUCK.search(impact):
        # stuck-funds proof must show a balance that REMAINS > 0 (or unchanged) when it shouldn't
        # "funds remain" = assertGt(balance/reserve, 0...) OR balance asserted truly UNCHANGED
        # (before-value is the ENTIRE rhs, then ')': `assertEq(resAfter, resBefore)` - NOT
        # `resBefore - amountOut`, which is a normal decrease and must still warn).
        has_remains = ("assertGt" in joined and re.search(r"assertGt\s*\([^,]*(balance|reserve|amount|funds)", joined, re.I)) \
            or re.search(r"assertEq\s*\([^,]*(balance|reserve)[^,]*,\s*\w*(Before|Pre)\s*\)", joined, re.I)
        if not has_remains:
            warns.append("impact is a STUCK/LOCKED-funds bug, but no assert checks a balance/reserve "
                         "stays > 0 (or unchanged) after the attack - the proof likely asserts normal "
                         "behaviour (e.g. a value going to 0) instead of the funds being stuck. READ IT.")
    if DRAIN.search(impact):
        has_pair = bool(re.search(r"\w*(Before|Pre)\b", code)) and (
            "assertGt" in joined or "assertLt" in joined or re.search(r"assertEq\s*\([^,]*,\s*0\s*\)", joined))
        if not has_pair:
            warns.append("impact is a DRAIN/THEFT bug, but the asserts don't look like an attacker-gained / "
                         "victim-lost before-after comparison - READ IT.")
    return warns


# ---- 2. model rewrite of ONLY the asserts ---------------------------------------------------

SYSTEM = ("You are fixing a Foundry proof-of-concept test. The test already passes. Your ONLY job is "
          "to make its assertions check the real DAMAGE from the vulnerability, and to flag any attack "
          "line that uses cheat/admin powers. You change assertions only. You never change the attack "
          "logic, the setup, the imports, or the ATTACK / MALICIOUS-SETUP markers.")

REWRITE = """CLAIMED VULNERABILITY (what the attack is supposed to prove):
{impact}

THE TEST (it passes, but the assertions may be checking the wrong thing - wrong account, or a value
that is normal/unchanged, or an effect produced by cheat powers rather than the attack):
```solidity
{code}
```

{flags}
Rewrite the test so that:
- state that matters is recorded BEFORE the ATTACK block (a *Before variable), and the assertion
  compares it to the AFTER state - assert the DIFFERENCE the attack caused, never a value that was
  already true before the attack;
- the assertion is about the VICTIM losing or the ATTACKER gaining (the accounts named in the
  finding), not the attacker getting their own funds back and not the victim being the one pranked;
- you do NOT assert that normal behaviour happened (a call succeeding, a balance being what it
  should be) - only damage.
Change ONLY declarations of *Before variables and the assert lines. Do not touch the attack calls,
the setup, the pranks, or the markers. Keep the file compiling.
Output the COMPLETE corrected file, Solidity only, no prose and no code fence.
"""


def _strip_fence(t: str) -> str:
    t = t.strip()
    if t.startswith("```"):
        t = re.sub(r"^```[a-zA-Z]*\n", "", t)
        t = re.sub(r"\n```\s*$", "", t)
    return t.strip()


def rewrite_assert(code: str, impact: str, model: str = DEFAULT_MODEL,
                   host: str = "http://localhost:11434", num_ctx: int = 16384) -> str:
    """Return a new full test file with only the asserts rewritten. Does not run anything."""
    flags = flag_powers(code)
    flag_text = ""
    if flags and flags != ["no ATTACK markers - cannot scan"]:
        flag_text = ("These ATTACK lines look like cheat/admin powers - if any of them is what makes the\n"
                     "test pass, the proof is invalid. Do NOT remove them yourself, but make sure your\n"
                     "assertion would still hold from the attacker's real actions:\n"
                     + "\n".join(f"  - {h}" for h in flags) + "\n\n")
    user = REWRITE.format(impact=impact.strip()[:3500], code=code, flags=flag_text)
    out = llm_call(backend="ollama", system=SYSTEM, user=user, model=model,
                   num_ctx=num_ctx, host=host, json_mode=False)
    return _strip_fence(out)


# ---- driver ---------------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("test", help="path to a passing PoC test .sol")
    ap.add_argument("--impact", default="", help="the finding's impact / claim text")
    ap.add_argument("--model", default="poc-7b-v6")
    ap.add_argument("--host", default="http://localhost:11434")
    ap.add_argument("--flags-only", action="store_true", help="just run the static power scan")
    ap.add_argument("--lint", action="store_true", help="power scan + impact-class warning, no model (needs --impact)")
    ap.add_argument("--out", help="write the rewritten file here (default: <test>.assert.sol)")
    a = ap.parse_args()

    code = Path(a.test).read_text()

    flags = flag_powers(code)
    print("=== power/cheat scan ===")
    if flags:
        for h in flags:
            print("  [flag]", h)
    else:
        print("  clean")
    print("  current ATTACK pranks:", current_pranks(code) or "(none)")

    if a.impact or a.lint:
        warns = impact_mismatch(code, a.impact)
        print("\n=== impact-class check ===")
        if warns:
            for w in warns:
                print("  [warn]", w)
        else:
            print("  assert shape matches the impact class (or class unknown)")

    if a.flags_only or a.lint:
        return
    if not a.impact:
        print("\n[!] --impact is required to rewrite asserts (pass the finding's impact text)")
        sys.exit(2)

    print("\n=== asking model to rewrite asserts ===", flush=True)
    new = rewrite_assert(code, a.impact, model=a.model, host=a.host)
    out = Path(a.out) if a.out else Path(a.test).with_suffix(".assert.sol")
    out.write_text(new)
    print(f"wrote {out}  ({len(new)} bytes)")
    print("next: run it + knock out the ATTACK block, exactly as poc_loop does, and read the asserts.")


if __name__ == "__main__":
    main()


# ---- re-stamp: force the canonical stuck assert, whatever the model wrote (option #2 enforcement) ----
import re as _re

def restamp_stuck(code: str) -> tuple[str, bool]:
    """Overwrite the STEP 3 forced-assert lines of a stuck-class PoC back to canonical form:
        uint256 stuckAfter = <same expr the model used for stuckBefore>;
        assertGt(stuckAfter, 0);
    Keeps the model's stuckBefore expression (the contract-specific part), forces the assert shape.
    Returns (new_code, changed). No-op (changed=False) if there is no stuckBefore to anchor on."""
    m = _re.search(r"uint256\s+stuckBefore\s*=\s*(.+?);", code, _re.S)
    if not m:
        return code, False
    expr = m.group(1).strip()
    # a bare FILL placeholder / literal 0 means the model didn't fill it: don't restamp onto nothing
    if expr in ("0", "/* FILL: the stuck-fund balance */ 0") or "FILL" in expr:
        return code, False
    canonical = f"uint256 stuckAfter = {expr};\n        assertGt(stuckAfter, 0);"
    # replace everything from the stuckAfter declaration through its assertGt line
    pat = _re.compile(r"uint256\s+stuckAfter\s*=.*?assertGt\s*\([^;]*\)\s*;", _re.S)
    if not pat.search(code):
        return code, False
    new = pat.sub(canonical, code, count=1)
    return new, (new != code)


# ---- B: candidate stuck-balance expressions from the parent's declared vars (menu for the slot) ----
_TOKEN_TYPE = _re.compile(r"IERC20|ERC20|IERC4626|IERC721|IERC1155|MockERC\d+|token", _re.I)
_FIELD_HINT = _re.compile(r"reserve|balance|locked|stuck|pending|escrow|deposit", _re.I)
_SKIP_NAME  = _re.compile(r"^(vm|console|test|owner|admin|attacker|alice|bob|carol|user\d*)$", _re.I)

def stuck_candidates(var_types: dict, finding_text: str = "", limit: int = 8) -> list[str]:
    """Build in-scope expressions that could read the stuck balance, from {varname: type}.
    token.balanceOf(address(holder)) for each token x holder pair, plus holder.<field> reads.
    Ranked: names mentioned in the finding first. Every candidate uses only declared parent vars,
    so it compiles."""
    ft = (finding_text or "").lower()
    names = [n for n in var_types if not _SKIP_NAME.match(n)]
    tokens  = [n for n in names if _TOKEN_TYPE.search(var_types.get(n, ""))]
    holders = [n for n in names if n not in tokens and var_types.get(n, "")[:1].isupper()
               and "." not in var_types.get(n, "")]
    cands = []
    for tok in tokens:
        for h in holders:
            cands.append(f"{tok}.balanceOf(address({h}))")
        cands.append(f"{tok}.balanceOf(address(this))")
    # struct/state field reads on holders whose NAME suggests a balance field exists is unknown here,
    # so we only add holder.<name-looks-like-balance> when the holder var name itself hints it
    for h in holders:
        if _FIELD_HINT.search(h):
            cands.append(h)   # e.g. a `reserveBalance` style parent var
    # de-dup, then rank. Score each candidate by how often ITS vars are named in the finding
    # (frequency, not presence), minus a penalty for mock holders (a *Mock almost never holds the
    # real stuck funds - it's test scaffolding).
    def _count(name):
        return ft.count(name.lower())
    def score(c):
        sc = 0.0
        for n in names:
            if n in c:
                sc += _count(n)                                   # frequency of this var in the finding
                typ = var_types.get(n, "")
                if "mock" in n.lower() or "mock" in typ.lower():
                    sc -= 1000                                    # push mock holders to the bottom
        return sc
    ranked = [c for c in sorted(dict.fromkeys(cands), key=score, reverse=True)]
    return ranked[:limit]



# a view that should read 0 after a stuck-funds attack ("nothing left to claim"). With the attack
# removed (the control run), it is still positive, so this assertEq is what makes the knockout FAIL.
_CLAIMABLE = _re.compile(r"\b([A-Za-z_]\w*)\.(getPending\w*|pending\w*|getClaimable\w*|claimable\w*|earned\w*|getReward\w*|rewardsOf\w*|owed\w*|getWithdrawable\w*|withdrawable\w*|unclaimed\w*)\s*(\((?:[^;{}()]|\([^;{}()]*\))*\))")

def claimable_getter(code: str) -> str:
    """First pending/claimable/earned/owed getter CALL in the test, verbatim (receiver+args),
    skipping comment lines so it compiles. '' if none."""
    for ln in code.splitlines():
        if ln.strip().startswith("//"):
            continue
        m = _CLAIMABLE.search(ln)
        if m:
            return m.group(0)
    return ""



def claimable_from_plan(asserts) -> str:
    """The claimable/pending/earned getter named in the plan's assert strings, verbatim ('' if none).
    Plan-provided, so it does not depend on the model writing the getter itself."""
    for a in (asserts or []):
        m = _CLAIMABLE.search(str(a))
        if m:
            return m.group(0)
    return ""


def theft_candidates(var_types: dict, finding_text: str = "", attacker: str = "address(this)", limit: int = 6) -> list[str]:
    """<token>.balanceOf(address(<attacker>)) per in-scope token, ranked by how often the token name
    appears in the finding. The attacker's balance growing across the attack is the theft proof."""
    ft = (finding_text or "").lower()
    names = [n for n in var_types if not _SKIP_NAME.match(n)]
    tokens = [n for n in names if _TOKEN_TYPE.search(var_types.get(n, ""))]
    tokens.sort(key=lambda n: ft.count(n.lower()), reverse=True)
    atk = (attacker or "address(this)").strip()
    return [f"{t}.balanceOf(address({atk}))" for t in tokens][:limit]

# ---- the real forcing: strip the model's asserts, append the canonical stuck assert ----
# The 7B regenerates the whole test (won't fill a skeleton), but it KEEPS its setup+attack and the
# ATTACK markers. So we keep everything it wrote, delete its (wrong) assert lines, and append the
# mechanical stuck assert. The model owns setup+attack; the harness owns the assert. restamp is
# superseded by this for stuck.
def force_stuck_assert(code: str, top_candidate: str, unclaimable_expr: str = "") -> tuple[str, bool]:
    if not top_candidate:
        return code, False
    # locate the test_PoC function body (first { after the signature .. matching })
    sig = _re.search(r"function\s+test_PoC\s*\([^)]*\)\s*(?:public|external)?[^{]*\{", code)
    if not sig:
        return code, False
    i = sig.end() - 1            # at the opening {
    depth, j = 0, i
    while j < len(code):
        if code[j] == "{": depth += 1
        elif code[j] == "}":
            depth -= 1
            if depth == 0:
                break
        j += 1
    if depth != 0:
        return code, False
    body = code[i+1:j]
    out_lines = []
    for ln in body.splitlines():
        t = ln.strip()
        # drop the model's asserts, expectRevert (inverted asserts), and any stuck* scaffold it kept
        if _re.match(r"(assert\w*)\s*\(", t): continue
        if "vm.expectRevert" in t: continue
        if _re.match(r"uint256\s+stuck(Before|After)\b", t): continue
        out_lines.append(ln)
    # idempotent: drop any forced block a previous pass already appended, before re-appending
    kept = []
    skip = False
    for ln in out_lines:
        if "forced stuck assert (harness-owned)" in ln:
            skip = True; continue
        if skip and _re.match(r"(uint256\s+stuckAfter|assertGt)\b", ln.strip()):
            continue
        skip = False
        kept.append(ln)
    canonical = (f"\n        // forced stuck assert (harness-owned):\n"
                 f"        uint256 stuckAfter = {top_candidate};\n"
                 f"        assertGt(stuckAfter, 0);\n    ")
    unclaimable = unclaimable_expr or claimable_getter(code)
    if unclaimable:
        canonical = canonical.rstrip() + (f"\n        // ...and nobody can claim them (the control run fails here):\n"
                                          f"        assertEq({unclaimable}, 0);\n    ")
    new_body = "\n".join(kept).rstrip() + "\n" + canonical
    new = code[:i+1] + new_body + code[j:]
    return new, True


# ---- precondition check (no model): did setup INSTANTIATE the hostile token the finding needs? ----
# The ATTACK knockout proves the assert depends on the attack, never that the vulnerable PRECONDITION
# was established. A fee-on-transfer finding whose PoC runs the attack against a plain ERC20 tests the
# happy path and passes falsely (boost M-04: `contract MockERC20 is ERC20 {}`, no fee). This catches it:
# a fee_on_transfer finding must have a token in the PoC whose transfer actually deducts a fee.

# a transfer/_update/_transfer override whose body reduces the amount moved = fee-on-transfer behaviour
_FEE_BEHAVIOUR = _re.compile(
    r"\bfunction\s+(?:transfer|transferFrom|_transfer|_update)\b[^{]*\{"   # a transfer-family override
    r"(?:[^{}]|\{[^{}]*\})*?"                                              # its body (one nesting level)
    r"(?:\bamount\s*[-*]\s*\w"                       # amount - fee  /  amount * rate
    r"|\b_?fee\w*\b|\bfeeBps\b|\bfeeBasisPoints\b|\btax\w*\b"   # a fee/tax variable
    r"|\b_burn\s*\(|\.burn\s*\()",                   # burns part of the transfer (deflationary)
    _re.I | _re.S)

# a mock whose NAME alone announces fee-on-transfer / deflationary / rebasing behaviour
_FEE_NAME = _re.compile(r"\b(?:FeeOnTransfer\w*|FeeToken\w*|TaxToken\w*|Deflationary\w*|Rebasing\w*)\b", _re.I)


def _token_contracts(code: str) -> list[str]:
    """Each inline `contract X is ...ERC20... { ... }` block in the PoC, body included."""
    out = []
    for m in _re.finditer(r"\bcontract\s+\w+\b[^{]*\bis\b[^{]*ERC20[^{]*\{", code):
        depth, j = 0, m.end() - 1
        while j < len(code):
            if code[j] == "{": depth += 1
            elif code[j] == "}":
                depth -= 1
                if depth == 0: break
            j += 1
        out.append(code[m.start():j + 1])
    return out


def precondition_instantiated(code: str, precond: str) -> bool:
    """True if the PoC actually sets up the hostile precondition the finding needs. Conservative:
    only fee_on_transfer is modelled; any other precond returns True (never reject what we can't check).
    Limitation: a PoC that imports a hostile token without defining it inline and without a fee-y name
    is not detected -- acceptable for v1, since FoT PoCs almost always bring their own mock token."""
    if precond != "fee_on_transfer":
        return True
    if _FEE_NAME.search(code):
        return True
    return any(_FEE_BEHAVIOUR.search(b) for b in _token_contracts(code))


# ---- precondition check (no model): did setup INSTANTIATE the hostile token the finding needs? ----
# The ATTACK knockout proves the assert depends on the attack, never that the vulnerable PRECONDITION
# was established. A fee-on-transfer finding whose PoC runs the attack against a plain ERC20 tests the
# happy path and passes falsely (boost M-04: `contract MockERC20 is ERC20 {}`, no fee). This catches it:
# a fee_on_transfer finding must have a token in the PoC whose transfer actually deducts a fee.

# a transfer/_update/_transfer override whose body reduces the amount moved = fee-on-transfer behaviour
_FEE_BEHAVIOUR = _re.compile(
    r"\bfunction\s+(?:transfer|transferFrom|_transfer|_update)\b[^{]*\{"   # a transfer-family override
    r"(?:[^{}]|\{[^{}]*\})*?"                                              # its body (one nesting level)
    r"(?:\bamount\s*[-*]\s*\w"                       # amount - fee  /  amount * rate
    r"|\b_?fee\w*\b|\bfeeBps\b|\bfeeBasisPoints\b|\btax\w*\b"   # a fee/tax variable
    r"|\b_burn\s*\(|\.burn\s*\()",                   # burns part of the transfer (deflationary)
    _re.I | _re.S)

# a mock whose NAME alone announces fee-on-transfer / deflationary / rebasing behaviour
_FEE_NAME = _re.compile(r"\b(?:FeeOnTransfer\w*|FeeToken\w*|TaxToken\w*|Deflationary\w*|Rebasing\w*)\b", _re.I)


def _token_contracts(code: str) -> list[str]:
    """Each inline `contract X is ...ERC20... { ... }` block in the PoC, body included."""
    out = []
    for m in _re.finditer(r"\bcontract\s+\w+\b[^{]*\bis\b[^{]*ERC20[^{]*\{", code):
        depth, j = 0, m.end() - 1
        while j < len(code):
            if code[j] == "{": depth += 1
            elif code[j] == "}":
                depth -= 1
                if depth == 0: break
            j += 1
        out.append(code[m.start():j + 1])
    return out


def precondition_instantiated(code: str, precond: str) -> bool:
    """True if the PoC actually sets up the hostile precondition the finding needs. Conservative:
    only fee_on_transfer is modelled; any other precond returns True (never reject what we can't check).
    Limitation: a PoC that imports a hostile token without defining it inline and without a fee-y name
    is not detected -- acceptable for v1, since FoT PoCs almost always bring their own mock token."""
    if precond != "fee_on_transfer":
        return True
    if _FEE_NAME.search(code):
        return True
    return any(_FEE_BEHAVIOUR.search(b) for b in _token_contracts(code))


# --- privilege gate -------------------------------------------------------
# Rejects PoCs that fake a green knockout by reconfiguring the protocol or
# granting the attacker privileged power, when the finding does not call for it.
# Signature seen in 2023-04-party H-02 (globals.setBool + swapped-in
# TokenDistributor) and H-05 (addAuthority to self). The genuine single-check
# bugs (missing override, unchecked attribute, bad cast, off-by-one) never need
# this, so it separates real teacher proofs from fabricated ones.
#
# HARD = protocol reconfiguration a legit single-bug PoC never needs -> always gate.
# SOFT = role/authority grants that CAN be legitimate scenario -> gate only if the
#        finding text doesn't reference that kind of privilege.
# Tunable: move a pattern between the two lists if it over- or under-triggers.
_PRIV_HARD = [
    (re.compile(r'\bglobals?\s*\.\s*(setBool|setAddress|setUint256|setUint|setBytes32)\s*\('), 'globals-config-setter'),
    (re.compile(r'\.\s*setGlobals\s*\('),        'setGlobals'),
]
_PRIV_SOFT = [
    (re.compile(r'\baddAuthority\s*\('), 'addAuthority'),
    (re.compile(r'\bgrantRole\s*\('),    'grantRole'),
    (re.compile(r'\.\s*transferOwnership\s*\('), 'transferOwnership'),
    (re.compile(r'\.\s*set(Owner|Admin|Authority|Operator|Pauser|Guardian|Minter)\s*\('), 'set-privileged-role'),
]
_PRIV_ALLOW = re.compile(
    r'\b(owner|admin|governance|authorit|role|privileg|guardian|pauser|operator|minter|access ?control)\b',
    re.I,
)

def privileged_setup_in_attack(code, precond=""):
    """Return (flagged: bool, hits: list[str]).

    Scans the test_PoC body up to and including the ATTACK block -- the setup
    that *enables* the attack -- not post-attack assertions and not inherited
    setUp(). HARD hits always flag; SOFT hits flag unless the finding text
    legitimizes that privilege.
    """
    m = re.search(r'function\s+test_PoC\s*\([^)]*\)[^{]*\{', code)
    start = m.end() if m else 0
    end_m = re.search(r'ATTACK-END', code)
    region = code[start:(end_m.end() if end_m else len(code))]

    hits = [label for pat, label in _PRIV_HARD if pat.search(region)]
    if not _PRIV_ALLOW.search(precond or ""):
        hits += [label for pat, label in _PRIV_SOFT if pat.search(region)]
    return (bool(hits), sorted(set(hits)))
