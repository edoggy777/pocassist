#!/usr/bin/env python3
"""
plan_assemble.py - mechanical plan-enforcement: turn an oracle plan (JSON) directly into a
Foundry test_PoC body, instead of asking the model to follow the plan (it won't - it improvises).

Finding from the magicsea H-04 audit: the oracle plan IS the complete correct warden recipe, but the
7B ignores it and writes its own (wrong) setup/attack. So for a finding that HAS an oracle plan, the
model is not needed for the steps at all - assemble the test from the plan directly.

Plan shape (per finding id), as produced by extract_plans.py --full:
    {
      "poc_type": "...",
      "actors": [...],
      "setup":  [ {"actor": "<expr>|test|-", "step": "<solidity stmt incl ;>"}, ... ],
      "attack": [ {"actor": "...", "step": "..."}, ... ],
      "asserts": [ "<solidity assert incl ;>", ... ],
      "functions": [...]
    }

actor semantics:
  "test" or "-" or "" / "this" / "address(this)"  -> no prank (the test contract is msg.sender)
  anything else                                   -> vm.prank(<actor>) before that single step

The ATTACK steps are wrapped in // ATTACK-START / // ATTACK-END so the control-run knockout works.
The asserts are DROPPED and replaced by the forced stuck assert when force_assert_expr is given
(harness owns the assert); otherwise the plan's own asserts are emitted.
"""
import re

_NO_PRANK = {"", "-", "test", "this", "address(this)"}


def _needs_prank(actor: str) -> bool:
    return (actor or "").strip() not in _NO_PRANK


_CALL = re.compile(r"\b(\w+)\s*\.\s*\w+\s*(?:\{[^}]*\})?\s*\(")
# receivers whose calls are cheatcodes/logging and do NOT consume a prank
_NONCONSUMING_RECV = {"vm", "console", "console2", "stdstore", "stdError", "stdMath"}
def _has_call(step: str) -> bool:
    """True iff the step makes a REAL external obj.method(...) call that consumes a prank.
    vm.*/console.* cheatcodes, and free-function cheatcodes (skip/warp with no receiver), do not."""
    return any(m.group(1) not in _NONCONSUMING_RECV for m in _CALL.finditer(step))

# the model sometimes writes its own prank management inside a step; don't double it
_SELF_PRANK = re.compile(r"\bvm\.(?:prank|startPrank|stopPrank)\s*\(")


def _emit_step(actor: str, step: str, indent: str = "        ") -> list[str]:
    step = step.strip()
    if step and step[-1] not in ";{}":
        step = step + ";"
    lines = []
    if _needs_prank(actor) and _has_call(step) and not _SELF_PRANK.search(step):
        lines.append(f"{indent}vm.prank({actor.strip()});")
    lines.append(f"{indent}{step}")
    return lines


def assemble_body(plan: dict, force_assert_expr: str | None = None,
                  pre_attack_asserts: list | None = None, unclaimable_asserts: list | None = None,
                  theft_expr: str | None = None) -> str:
    """Inside of test_PoC() from the plan.
    - pre_attack_asserts: asserts that must run BEFORE the attack (e.g. assertEq(5e18, getPendingReward(1))
      for a stuck/claim bug - checks what SHOULD be claimable). Emitted just before // ATTACK-START.
    - force_assert_expr: if given, the post-attack assert is the STRONG stuck check built from it:
        uint256 stuckBefore = <expr>;  (recorded before the attack)
        ... attack ...
        uint256 stuckAfter = <expr>;
        assertGt(stuckAfter, 0);                 // funds remain
        assertGe(stuckAfter, stuckBefore / 2);   // the attack did NOT drain them as it should
      This is control-sensitive: without the attack there is no claim, so the comparison is meaningless
      and the knockout fails. If force_assert_expr is None, the plan's own asserts are used (after attack).
    """
    out = []
    out.append("        // ===== SETUP (assembled from oracle plan) =====")
    for s in plan.get("setup", []):
        out += _emit_step(s.get("actor", ""), s.get("step", ""))
    out.append("")
    # stuck baseline BEFORE the attack
    if force_assert_expr:
        out.append(f"        uint256 stuckBefore = {force_assert_expr};")
    if theft_expr:
        out.append(f"        uint256 gainBefore = {theft_expr};")
    # pre-attack asserts (position-sensitive: what should be claimable, checked before the claim)
    for a in (pre_attack_asserts or []):
        a = a.strip()
        if not a.endswith(";"): a += ";"
        out.append(f"        {a}   // pre-attack")
    out.append("")
    out.append("        // ATTACK-START")
    for s in plan.get("attack", []):
        out += _emit_step(s.get("actor", ""), s.get("step", ""))
    out.append("        // ATTACK-END")
    out.append("")
    if force_assert_expr:
        out.append("        // forced stuck assert (harness-owned): funds remain AND nothing is left to claim")
        out.append(f"        uint256 stuckAfter = {force_assert_expr};")
        out.append("        assertGt(stuckAfter, 0);   // funds still in the contract after the attack")
        for chk in (unclaimable_asserts or []):
            chk = chk.strip()
            if not chk.endswith(";"): chk += ";"
            out.append(f"        {chk}   // ...but nobody can get them (control-sensitive)")
    elif theft_expr:
        out.append("        // forced theft assert (harness-owned): the attacker gained")
        out.append(f"        uint256 gainAfter = {theft_expr};")
        out.append("        assertGt(gainAfter, gainBefore);   // attacker gained (no attack = no gain)")
    else:
        out.append("        // ===== ASSERTS (from plan) =====")
        for a in plan.get("asserts", []):
            a = a.strip()
            if not a.endswith(";"): a += ";"
            out.append(f"        {a}")
    return "\n".join(out)



# Solidity/cheatcode builtins and addressing wrappers that are never "actors to declare".
_ACTOR_SKIP = {"test", "this", "address", "msg", "tx", "block", "vm", "", "-"}
_BARE_IDENT = re.compile(r"^[a-z_]\w*$")

def _undeclared_actors(plan: dict, known: set) -> list:
    """Actor identifiers the plan USES (in an `actor` field or inside vm.prank(...)) that the
    parent test does NOT already declare. Only bare lowercase/_ idents (makeAddr targets);
    address(...) wrappers, builtins, and known parent vars are skipped. Returns sorted unique."""
    used = set()
    for key in ("setup", "attack"):
        for s in (plan.get(key) or []):
            a = (s.get("actor") or "").strip()
            if _BARE_IDENT.match(a):
                used.add(a)
            for m in re.findall(r"vm\.prank\(\s*([A-Za-z_]\w*)\s*\)", s.get("step", "") or ""):
                used.add(m)
    out = [a for a in used if a not in _ACTOR_SKIP and a not in known and _BARE_IDENT.match(a)]
    return sorted(set(out))

_PRANK_CHAIN = re.compile(
    r"vm\.(?:prank|startPrank)\([^;]*\);(\s*(?://[^\n]*\n\s*)*)(?=vm\.(?:prank|startPrank)\()")
def _strip_stacked_pranks(code: str) -> str:
    """Remove an unconsumed vm.prank/startPrank immediately followed by another prank/startPrank.
    The model sometimes emits back-to-back pranks with no call between, which reverts with
    'cannot overwrite a prank until it is applied at least once'. A prank followed by a real call
    is left alone (the call consumes it)."""
    prev = None
    while prev != code:
        prev = code
        code = _PRANK_CHAIN.sub(r"\1", code)
    return code


def assemble_test(plan: dict, n: int, pname: str, pragma: str, imports: list[str],
                  parent_file: str, force_assert_expr: str | None = None,
                  pre_attack_asserts: list | None = None, unclaimable_asserts: list | None = None,
                  theft_expr: str | None = None, known_names: set | None = None,
                  standalone_inherit: str | None = None, standalone_shell: str | None = None) -> str:
    """Full PoC_<n>.t.sol assembled from the plan (inherits the parent test's setUp).
    known_names: identifiers the parent already declares (e.g. PARENT_VAR_TYPES keys). Any
    actor the plan uses but the parent does not declare is given `address X = makeAddr("X");`
    so the model naming an actor like `attacker` no longer compile-errors on Undeclared id."""
    decls = _undeclared_actors(plan, set(known_names or ()))
    decl_lines = "".join(f'        address {a} = makeAddr("{a}");\n' for a in decls)
    if standalone_shell is not None:
        # redeploy/standalone: do NOT inherit the parent (its private state is invisible from
        # `is Parent`). Inherit the parent's own base and embed its state vars + setUp + helpers.
        header = (f"// SPDX-License-Identifier: UNLICENSED\n{pragma}\n\n"
                  + "\n".join(imports) + "\n\n"
                  + f"contract PoC_{n} is {standalone_inherit or 'Test'} {{\n"
                  + standalone_shell.rstrip() + "\n\n"
                  + "    function test_PoC() public {\n"
                  + decl_lines)
    else:
        header = (f"// SPDX-License-Identifier: UNLICENSED\n{pragma}\n\n"
                  + "\n".join(imports) + "\n"
                  + f'import {{{pname}}} from "./{parent_file}";\n\n'
                  + f"contract PoC_{n} is {pname} {{\n"
                  + f"    // setUp() is inherited from {pname}.\n\n"
                  + "    function test_PoC() public {\n"
                  + decl_lines)
    body = assemble_body(plan, force_assert_expr, pre_attack_asserts, unclaimable_asserts, theft_expr)
    return _strip_stacked_pranks(header + body + "\n    }\n}\n")


if __name__ == "__main__":
    import json, sys
    # self-test on the real magicsea H-04 plan
    plan = {
      "poc_type": "direct_call",
      "actors": ["address(_voterMock)", "alice"],
      "setup": [
        {"actor": "test", "step": "ERC20Mock(address(rewardToken)).mint(address(this), 10e18);"},
        {"actor": "test", "step": "ERC20Mock(address(rewardToken)).approve(address(rewarder), 10e18);"},
        {"actor": "test", "step": "rewarder.fundAndBribe(1, 1, 10e18);"},
        {"actor": "test", "step": "_voterMock.setCurrentPeriod(1);"},
        {"actor": "test", "step": "_voterMock.setStartAndEndTime(100, 200);"},
        {"actor": "-", "step": "vm.warp(150);"},
        {"actor": "address(_voterMock)", "step": "rewarder.deposit(1, 1, 1e18);"},
        {"actor": "-", "step": "vm.warp(200);"},
        {"actor": "test", "step": "_voterMock.setCurrentPeriod(2);"},
        {"actor": "test", "step": "_voterMock.setLatestFinishedPeriod(1);"},
      ],
      "attack": [{"actor": "alice", "step": "rewarder.claim(1);"}],
      "asserts": ["assertEq(5e18, rewarder.getPendingReward(1));",
                  "assertGt(rewardToken.balanceOf(address(rewarder)), 0);"],
      "functions": ["claim", "deposit", "fundAndBribe"],
    }
    print("=== assemble_body WITH forced stuck assert ===")
    print(assemble_body(plan, force_assert_expr="rewardToken.balanceOf(address(rewarder))"))
    print("\n=== full test (plan's own asserts) ===")
    print(assemble_test(plan, 1, "BribeRewarderTest", "pragma solidity ^0.8.19;",
                        ['import {Test} from "forge-std/Test.sol";'], "BribeRewarder.t.sol"))


def assemble_setup_only(plan, n, pname, pragma, imports, parent_file):
    """Just the SETUP steps (no attack), ending in assertTrue(true). It PASSES iff the inherited
    setUp + the plan's setup run without reverting - the 'did we reach a valid state' check."""
    header = (f"// SPDX-License-Identifier: UNLICENSED\n{pragma}\n\n"
              + "\n".join(imports) + "\n"
              + f'import {{{pname}}} from "./{parent_file}";\n\n'
              + f"contract PoC_{n} is {pname} {{\n    function test_PoC() public {{\n")
    out = ["        // ===== SETUP ONLY (no attack) ====="]
    for s in plan.get("setup", []):
        out += _emit_step(s.get("actor", ""), s.get("step", ""))
    out.append("        assertTrue(true);")
    return header + "\n".join(out) + "\n    }\n}\n"
