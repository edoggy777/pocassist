# pocassist

A local, Foundry-based toolkit for **proving smart-contract findings mechanically**. You (or a model) write the attack; the harness writes the test around it and decides whether the test really proves the bug.

Everything runs on your own machine against models served by [Ollama](https://ollama.com), so unreported bugs never leave your box.

This repo contains the tool only. **It ships with no contest data, no findings, no third-party proofs-of-concept and no training sets.** You point it at a project you have cloned yourself.


---

## What it does

Writing an exploit PoC has three parts. Two of them are mechanical, and this tool does those for you:

| Part | Who does it | How |
|---|---|---|
| Pick the right parent test and inherit its setup | tool | scans the project's `test/` for the test that deploys the claimed contract |
| Decide **what to assert** (what "damage" looks like) | tool | classifies the finding into an impact class and stamps the matching assert into the test after generation, so the model can't write a wrong or trivially-true assert |
| Write the attack sequence | **you**, or a model | the only part that needs judgement |

Then the **verifier** runs the test three ways:

1. with the attack → must **pass**
2. with the `// ATTACK-START … // ATTACK-END` block removed → must **fail**
3. with the `// MALICIOUS-SETUP` block removed → must **fail**

Only a test that passes (1) and fails (2) and (3) is marked **PROVED**. Anything else gets a plain-language verdict (`NOT YET`, `NOT PROVED`) plus the reason the control run didn't fail: copied project test, assert that only reads back a value the attack just wrote, attack that grants itself admin powers, magic-constant asserts, and so on.

That control-run knockout is the core of the project. It is what stops a plausible-looking test from being counted as a proof.

## Honest status

- **Verifying works.** The knockout and the flag checks catch the false positives that fooled every model we tried, and catch the ones that fooled us on manual review too.
- **Assisted proving works.** With a human writing the attack and the tool handling setup, assert and verification, real findings from past public audits were proved in a few repair steps each.
- **Fully automatic proving does not work yet with a 7B model.** Across every variant we tested (base, fine-tuned, with hints, with the full attack recipe), a local 7B proved roughly zero held-out findings on its own. Larger local models (20B–30B) manage a handful. The wall is not compile errors; it is that the model asserts normal behaviour instead of damage, or writes an attack that runs and exploits nothing. The forced-assert design in this repo exists precisely because prose instructions did not fix that.

So: use this as an **assistant and verifier**, not as a button that writes exploits.

## Requirements

- Linux (tested on Ubuntu), Python 3.10+
- [Foundry](https://book.getfoundry.sh/getting-started/installation) (`forge` on your PATH)
- [Ollama](https://ollama.com) with at least one code model pulled, e.g.

  ```bash
  ollama pull qwen2.5-coder:7b
  ```

  A 7B fits a 12 GB GPU. `qwen3-coder:30b` is noticeably better at setup and compiles if you have ~20 GB of RAM+VRAM to split it across.
- A Foundry project you have cloned and built yourself:

  ```bash
  git clone <the project> ~/targets/myproject && cd ~/targets/myproject && forge build
  ```

Install:

```bash
git clone https://github.com/edoggy777/pocassist.git ~/pocassist
cd ~/pocassist
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

## Quick start: prove a finding you've found

**1. Start a session.** Give the project, the contract you think is vulnerable and a one-paragraph description of the bug. The tool finds the right parent test, has the model draft a plan, and writes a compiling test skeleton with the assert already filled in and the attack left as a `TODO`.

```bash
python poc_assist.py start ~/targets/myproject --source src/Vault.sol --id my-vault-bug
```

**2. Write the attack** inside the `// ATTACK-START` / `// ATTACK-END` markers in the generated `test/PoC_my-vault-bug.t.sol`. Put any attacker-controlled deployment (a malicious token, a reentrant contract) between `// MALICIOUS-SETUP-START` / `// MALICIOUS-SETUP-END`.

**3. Check it.**

```bash
python poc_assist.py check ~/targets/myproject --id my-vault-bug
```

You get one of:

- `PROVED` – passes with the attack, fails without it. Ready to submit.
- `NOT YET` – compile error or revert; the tool prints the forge trace and a hint about what the parent tests do differently.
- `NOT PROVED` – the test passes but the control run also passes, with the reason (e.g. "the assert compares a value the attack itself wrote").

Repeat 2–3 until `PROVED`. Every check is logged to `sessions/<project>/<test>/` so you can see what changed between attempts.

Before you submit, ask yourself: could a real attacker do every step (no `vm.store` on the target, no admin role, no `deal` they couldn't obtain)? Is the number you assert actually the impact you're claiming?

## Practising on published findings

To learn the tool, run it on a finding from a past audit you have cloned yourself. `--truth` takes the report file and `--id` the finding's identifier as it appears in that report:

```bash
python poc_assist.py start ~/targets/someaudit --truth ~/targets/someaudit/report.md --id H-01
```

Try to write the attack before reading the published PoC.

## Automatic mode (`poc_loop.py`)

`poc_loop.py` runs the whole loop with a model writing the attack: pick parent → classify impact → generate → force the assert → run forge → feed the error back → retry. Use it to see how far a model gets, or as a reward environment for training.

```bash
python poc_loop.py ~/targets/myproject --truth report.md --only H-01 \
    --model qwen2.5-coder:7b --samples 2 --tries 3 --out runs/myproject
```

If you have a step-by-step attack plan as JSON (the format is documented in `plan_assemble.py`), `plan_assemble.py` turns it straight into a test with no model involved, which is the most reliable way to reproduce a known exploit:

```bash
python plan_assemble.py --plan plan.json --project ~/targets/myproject --id H-01
```

## The pieces

| File | What it does |
|---|---|
| `poc_assist.py` | `start` / `check`: the human-in-the-loop workflow above |
| `poc_loop.py` | automatic generate → verify → repair loop; contains the control-run verifier and the false-positive demoters |
| `assert_pass.py` | post-generation checks and forcing: static scan for cheat-codes/admin powers in the attack block, magic-constant asserts, impact-class lint, and `force_stuck_assert` which stamps the canonical assert over whatever the model wrote |
| `impact_rules.py`, `build_impact.py` | classify a finding into theft / accounting / dos / stuck / access / fee_bypass and map each to an assert template |
| `plan_assemble.py` | build a test deterministically from a plan JSON |
| `plan_eval.py`, `run_eval.py`, `extract_plans.py` | scoring harness for comparing models on a held-out set you build yourself |
| `next_finding.py` | ranks findings in a report by how practisable they are (skips fork/RPC-dependent suites) |
| `export_sessions.py`, `build_dataset.py`, `purge_holdout.py` | turn logged sessions into training rows; `purge_holdout.py` strips anything from your held-out projects so you never train on your test set |
| `train_lora.py` | LoRA fine-tune on those rows (Unsloth, fits a 12 GB card) |
| `setup_contests.py` | batch-clone and build a list of projects you supply |

## Known limits

- Tests that need a mainnet fork (RPC URL, pinned block) are not yet supported; the control run is not fork-aware. Fork support is the top open item.
- The forced-assert path is complete for the `stuck` impact class and partial for the others.
- Parent-test selection can pick the wrong test when a project has V1/V2 variants of the same contract; `--parent-file` overrides it.
- The tool was built and tested on Code-style Foundry projects. Hardhat-only projects are out of scope.

## Data and licensing notes

- The repo contains **no audit reports, findings, PoCs or datasets** from any platform. Any such material you use with the tool is yours to obtain under that platform's terms.
- Nothing you run is sent anywhere; the only network calls are Ollama on localhost and `forge`'s dependency fetches.
- Model weights are a separate matter and are not part of this repo.

## License

See `LICENSE`.
