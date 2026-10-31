# PoC Assistant

You found a bug. Now you need a Foundry test that proves it, and that's the slow part:
finding the right test to build on, getting the imports and accounts right, fixing compile
errors, and then convincing yourself the test really proves the bug.

The PoC Assistant does the busy work and leaves the attack to you:

1. **`start`** reads your bug, finds the project's own test that already deploys everything,
   asks a local model for an attack plan, and writes a draft test that **compiles**.
2. You write or fix the attack.
3. **`check`** runs your test with `forge`, then runs it again **with the attack removed**.
   It only says **PROVED** if the test passes with the attack and fails without it.

Everything runs on your own computer, so the code you're hunting on stays private.
It works on local tests and on **mainnet-fork tests** (see [Fork tests](#fork-tests)).

## Why not let the model write the whole PoC?

We tried. On 37 real bugs from recent contests, local 7B models (base and fine-tuned) proved
**0** once each automatic "pass" was read by hand, even when we handed them the correct attack steps.
They usually understand the bug; they fail at turning it into a test that sets things up right
and asserts the real damage.

With the assistant and a person writing the attack, we proved 15 of the first 20 we tried
(the rest needed things like a missing feature or a fork we hadn't set up yet), usually in
2-4 checks each. A few are in [Case studies](#case-studies) below.

## What you need

- **[Foundry](https://getfoundry.sh)**: `curl -L https://foundry.paradigm.xyz | bash && foundryup`
- **[Ollama](https://ollama.com/download)** and a model: `ollama pull qwen2.5-coder:7b`
- **Python 3.11 or newer**
- **The project you're hunting on**, as a Foundry project that builds:

```bash
cd ~/targets/some-protocol      # the folder with foundry.toml in it
forge build                     # must finish without errors
```

- **This tool**:

```bash
git clone https://github.com/edoggy777/llm-contract-audit
cd llm-contract-audit
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

- **Only for fork tests:** an archive RPC URL for the chain (see [Fork tests](#fork-tests)).

## Step 1: Write down your bug

Make a file called `claims.json`:

```json
[
  {
    "title": "Anyone can front-run claim() with the user's own signature",
    "severity": "medium",
    "contract": "FluidLocker",
    "function": "claim",
    "description": "Alice calls claim() with a signed unit update. The attacker copies the signature from the mempool and calls EPProgramManager.updateUserUnits() directly first. The nonce is now used, so Alice's claim() reverts."
  }
]
```

Write the description as steps: who does what, in what order, and what goes wrong at the end.
The more it reads like the test, the better the plan. Name the contract and function if you can.

## Step 2: Start

```bash
python poc_assist.py start ~/targets/some-protocol --claims claims.json --id 1
```

| part | meaning |
|---|---|
| `~/targets/some-protocol` | the target's folder (the one with `foundry.toml`) |
| `--claims claims.json --id 1` | your bug file, and which bug in it (1 = the first) |
| `--name PoC_frontrun` | optional: a name for the test file (default `PoC_1`) |
| `--source src/Pool.sol` | optional: the file the bug is in, if it guessed wrong |
| `--parent-file test/Pool.t.sol` | optional: the test to build on (add `::PoolTest` to pick a contract), if it guessed wrong |
| `--parent 2` | optional: the 2nd suggested test instead of the 1st |
| `--planner qwen3-coder:30b` | optional: a bigger model for the plan, if your computer can run it |

It prints what it picked, the plan, and ends with something like:

```
[*] source: src/core/VaultManagerV2.sol   functions in the claim: deposit, withdraw
[*] parent test candidates (the PoC inherits its setUp):
    1. test/VaultManager.t.sol :: VaultManagerTest   <- using
[!] warning: the parent never mentions VaultManagerV2 but uses VaultManager (a different version) ...
[*] impact type: dos (from the claim's wording)
...
[*] test:   test/PoC_1.t.sol
[*] status: compiles and runs; it reverts: ...
```

Read those first lines before anything else:

- **source / parent**: if they're wrong, start again with `--source` / `--parent-file`.
- **"a different version" warning**: the project's tests deploy an older contract than the one
  with the bug. Deploy the right one inside your test (the parent's setup gives you everything else).
- **"standalone test"**: the parent keeps its setup in `private` variables, so the assistant
  copied its setup into your test instead of inheriting it.
- **impact type**: what kind of damage the claim describes (theft, accounting, dos, stuck funds,
  fee bypass, access) and how a PoC usually proves that kind. It's a guess from your wording: check it.

The test file is in the **target's** test folder, next to the test it builds on.
`PoC_1.plan.md` next to it has the plan, what the code requires on the way to the bug,
and which of the project's tests call the same functions (copy their setup steps).

**The plan is a starting point, not the answer.** The model often gets the shape of the bug
right and the details wrong: the wrong actor, the wrong function, an assert that's true anyway.
That's your part.

## Step 3: Write the attack

Open the test and make it look like this:

```solidity
function test_PoC() public {
    // setup: normal things that happen before the attack
    uint256 nonce = _programManager.getNextValidNonce(PROGRAM_0, ALICE);
    bytes memory sig = _helperGenerateSignature(signerPkey, ALICE, 1000, PROGRAM_0, nonce);

    // ATTACK-START
    vm.prank(attacker);
    _programManager.updateUserUnits(ALICE, PROGRAM_0, 1000, nonce, sig);
    // ATTACK-END

    // the damage: the victim's own call now fails, with this specific error
    vm.prank(ALICE);
    vm.expectRevert(IEPProgramManager.INVALID_SIGNATURE.selector);
    aliceLocker.claim(PROGRAM_0, 1000, nonce, sig);
}
```

The rules:

- Put the attacker's action, and **only** that, between `// ATTACK-START` and `// ATTACK-END`.
  Each marker on its own line.
- Declare variables **before** the attack block, not inside it.
- Then show the damage:
  - **theft**: balances before and after (attacker gained, victim lost)
  - **accounting**: a baseline of the number without the attack (`vm.snapshotState()` ... `vm.revertToState()`), then show the attack changes it
  - **DoS**: `vm.expectRevert(<the specific error>)` on the **victim's** call after the block; a bare `vm.expectRevert()` passes for any revert
  - **stuck funds**: the funds sit where nobody can get them, and the owner didn't receive them
- If the attack needs a hostile contract or crafted input, wrap that setup in
  `// MALICIOUS-SETUP-START` and `// MALICIOUS-SETUP-END`. It gets removed and tested separately too.
- Never put `vm.expectRevert()` on the attacker's own call. That tests that the code is safe.

**Tip:** editors like vim can mangle pasted code. Either type `:set paste` first, or write
the whole file in one go:

```bash
cat > ~/targets/some-protocol/test/PoC_1.t.sol <<'EOT'
...paste the whole file here...
EOT
```

## Step 4: Check, fix, repeat

```bash
python poc_assist.py check ~/targets/some-protocol test/PoC_1.t.sol --claims claims.json --id 1
```

Run it after every edit. It never changes your file (unless you add `--fix`).

| it says | what to do |
|---|---|
| `NOT YET: it does not compile` | each error with its line and what exists instead. `--fix` adds missing accounts and imports for you |
| `NOT YET: the test reverts ...` | a step before your assertions failed. The revert reason and the trace show which call, and why |
| `NOT YET: ... an assertion fails` | the attack ran but didn't do what you assert. Check the numbers, and which contract holds the balance |
| `NOT YET: the parent's setUp() fails` / `couldn't be deployed or set up` | the project's own setup doesn't run here: usually a fork test without its RPC URL (it tells you which variable) |
| `NOT PROVED: it ALSO passes without the attack` | what you assert is true anyway. Assert something only the attack causes |
| `NOT PROVED: ... expects the attacker's call to be BLOCKED` | the test is written backwards |
| `PASSES THE CONTROLS, BUT: ...` | read the warning (below) |
| **`PROVED`** | passes with the attack, fails without it. Read the reason it gives for failing without the attack, then read the test once as a judge would |

Warnings after a pass:

- **a copy of a project test**: a normal-use test with markers added proves nothing.
- **the attack block calls none of the claimed functions**: fine if it's something that happens
  anyway (time passing, a price moving), otherwise the attack may be unrelated to the bug.
- **deploys a mock/malicious contract without MALICIOUS-SETUP markers**: wrap it so it's tested too.
  (Mocks the project's own tests use, like a price feed, are fine: you get a note instead.)
- **an assert only reads back a value the attack passed in**: e.g. `grantRole(x, ts)` then
  `assertEq(lastTimestamp, ts)` is true for any normal call. Assert the damage instead.

## Fork tests

Many live protocols (and most Immunefi targets) are tested on a fork of the real chain. The
assistant passes your RPC URLs to `forge` from a private file, `rpc.env`, next to `poc_assist.py`:

```
# KEY=url, one per line. Use an ARCHIVE RPC: fork tests often pin an old block.
MAINNET_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY
ARBITRUM_RPC_URL=https://arb-mainnet.g.alchemy.com/v2/YOUR_KEY
# KEY@part=url applies only to projects whose path contains `part` (for generic names like RPC_URL)
RPC_URL@notional-v4=https://arb-mainnet.g.alchemy.com/v2/YOUR_KEY
```

- `start` and `check` tell you which variables a project reads (from `vm.envString(...)` in its
  tests and `${...}` in `foundry.toml`) and which you haven't set.
- Your URLs are replaced with `<ARBITRUM_RPC_URL>` in everything the assistant prints or saves.
- Keep `rpc.env` out of git (it's in `.gitignore`) and `chmod 600 rpc.env`.
- Free tiers (e.g. Alchemy) include archive access. Forge caches fork data when a block is
  pinned, so the control runs after the first are fast.

## What PROVED does and doesn't mean

It means the damage you assert happens **because of** the attack block. It doesn't check
whether the attack is realistic. Before you submit, ask yourself:

- Could a real attacker do every step? (No admin powers, no `vm.store` on the target, no
  `deal` the attacker couldn't get.)
- Is what you assert the impact you're claiming, with numbers that matter?
- Does any mock replace the contract you're attacking (e.g. code etched over it)?
- Does the control fail for the reason you expect (your assert), not because some unrelated
  step broke?

## Case studies

**Kinetiq H-03: the obvious assert proved nothing.** The report's PoC ends with a bare
`vm.expectRevert()` on the user's withdrawal. In this test setup that call reverts with or
without the bug, so `check` would have said NOT PROVED. The provable impact was the other one
in the report: the returned HYPE is restaked and kHYPE is minted to the system address.
Asserting that gave PROVED.

**Burve H-04: a test that passed anyway.** The model's draft asserted a swap balance, which
was true without the attack (`NOT PROVED: it ALSO passes`). The real bug is that a tax is
shared over a total that already includes the depositor, diluting existing LPs. We measured the
tax without editing the source (the same deposit with fees off, inside a snapshot) and asserted
the existing LP got less than half her fair share.

**Dyad H-04: the tests deployed the wrong contract.** Every project test deployed
`VaultManager`, but the bug is in `VaultManagerV2` (the assistant now warns about this). The PoC
deploys V2 itself. The attack: a fake vault with a fake token, so blocking a user's withdrawals
costs the attacker nothing.

**Notional wrapped-fCash H-02: a fork test.** On an Arbitrum fork, minting more fCash than the
market can lend takes a "lend at zero" path. The leftover comes back as native ETH, but the wrapper
only counts WETH, so about 1 ETH stays stuck in the wrapper and the user never gets it back.

## Trying it on known bugs

To practise, run it on a published Code4rena or Sherlock report instead of your own claim:

```bash
python poc_assist.py start ~/contests/wildcat --truth report.md --id H-01
```

`--truth` takes the report file; `--id` is the finding's id. Try writing the attack yourself
before reading the warden's PoC.
