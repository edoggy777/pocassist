#!/usr/bin/env python3
"""
train_lora.py - QLoRA fine-tune of Qwen2.5-Coder on dataset/train.jsonl (from build_dataset.py),
then export a GGUF you can load in Ollama.

Run it in its own venv (venv-train), not the auditor's venv.

  python train_lora.py --check                  # CPU only: tokenize, show lengths, no training
  python train_lora.py                          # train 7B (default), ~1-2 h on an RTX 5070
  python train_lora.py --export runs_lora/v1    # adapter -> GGUF + Ollama Modelfile

PoC-writer (data from gen_pocs.py --collect; prompts are ~10-13k tokens, so --max-len 16384):
  python train_lora.py --jsonl dataset_poc/examples.jsonl --max-len 16384 --check
  python train_lora.py --jsonl dataset_poc/examples.jsonl --max-len 16384 --epochs 3 --grad-accum 4 --out runs_lora/poc1
  python train_lora.py --export runs_lora/poc1 && ollama create poc-7b-v1 -f runs_lora/poc1/gguf*/Modelfile

Then:
  ollama create audit-7b-v1 -f runs_lora/v1/gguf/Modelfile
  python eval_audit.py suite manifest_solidity_dev.json --audit-model audit-7b-v1 \
      --passes all --no-slither --drop-ungrounded --out runs_dev9_7b_ft

The loss is computed only on the assistant answer (the JSON), not on the prompt and code.
"""
import sys
import argparse
import json
import re
from pathlib import Path

BASE = {"7b": "Qwen/Qwen2.5-Coder-7B-Instruct", "14b": "Qwen/Qwen2.5-Coder-14B-Instruct"}


def load_rows(path: Path) -> list[dict]:
    return [{"messages": json.loads(l)["messages"]} for l in path.read_text().splitlines() if l.strip()]


def project_id(contest: str) -> str:
    """One key per contest for every split: 'sherlock-x--sub' and 'x+redo' map to the contest."""
    return contest.strip().split("+")[0].split("--")[0]


def label_of(r: dict) -> str:
    return r.get("label") or ("control_verified" if r.get("origin") == "loop" else "report_test_passes")


def load_poc_examples(args) -> tuple[list[dict], list[dict]]:
    """dataset_poc/examples.jsonl (from gen_pocs.py --collect): filter by variant / revert style,
    then split train/val BY CONTEST so the val PoCs come from projects the model never saw."""
    rows = [json.loads(l) for l in args.jsonl.read_text().splitlines() if l.strip()]
    variants = set(args.variants.split(","))
    rows = [r for r in rows if r.get("variant", "bare") in variants
            and (args.include_revert_style or not r.get("revert_style"))]
    keep = set(args.labels.split(","))
    n0 = len(rows)
    rows = [r for r in rows if label_of(r) in keep]
    print(f"[*] labels {sorted(keep)}: {len(rows)} of {n0} examples kept")
    excluded = set()
    if args.exclude_contests:
        excluded = {project_id(l) for l in args.exclude_contests.read_text().splitlines() if l.strip()}
        n0 = len(rows)
        rows = [r for r in rows if project_id(r["contest"]) not in excluded]
        print(f"[*] held-out test contests excluded: {len(excluded)} contests, {n0 - len(rows)} examples removed")
    args._audit = {"rows": rows, "excluded": excluded}
    # --- Holdout safety net (manifest-backed, unconditional) ---
    # Independent of --exclude-contests: no row flagged by purge_holdout.is_holdout may
    # survive into training. Guards against holdout_contests.txt and the manifest drifting.
    from purge_holdout import is_holdout
    _leaked = [r for r in rows if is_holdout(r)]
    if _leaked:
        _ids = sorted({r.get("contest") for r in _leaked})
        sys.exit(f"[FATAL] {len(_leaked)} held-out examples in training set: {_ids}. "
                 f"Aborting. Check that dataset_poc/holdout_contests.txt matches "
                 f"eval_set/manifest_holdout.json.")
    contests = sorted({project_id(r["contest"]) for r in rows})
    import random
    rng = random.Random(7)
    rng.shuffle(contests)
    n_val = max(1, round(len(contests) * args.val_frac)) if args.val_frac > 0 and len(contests) > 3 else 0
    val_c = set(contests[:n_val])
    tr = [{"messages": r["messages"]} for r in rows if project_id(r["contest"]) not in val_c]
    va = [{"messages": r["messages"]} for r in rows if project_id(r["contest"]) in val_c]
    args._audit.update({"val": val_c, "train": set(contests) - val_c, "repairs": []})
    if args.repairs and args.repairs.exists():
        reps = [json.loads(l) for l in args.repairs.read_text().splitlines() if l.strip()]
        reps = [r for r in reps if project_id(r["contest"]) not in val_c and project_id(r["contest"]) not in excluded]
        args._audit["repairs"] = reps
        rng.shuffle(reps)
        cap = min(len(reps), args.repairs_max if args.repairs_max else len(reps))
        tr += [{"messages": r["messages"]} for r in reps[:cap]]
        print(f"[*] + {cap} compile-repair examples (of {len(reps)}) in train only")
    by_origin = {}
    for r in rows:
        by_origin[r.get("origin", "?")] = by_origin.get(r.get("origin", "?"), 0) + 1
    print(f"[*] PoC examples: {len(rows)} ({', '.join(f'{v} {k}' for k, v in by_origin.items())}; "
          f"variants {sorted(variants)}; revert-style {'included' if args.include_revert_style else 'excluded'})")
    print(f"[*] split by contest: {len(tr)} train from {len(contests) - n_val} contests, "
          f"{len(va)} val from {sorted(val_c) or 'none'}")
    return tr, va


def data_splits(args):
    if args.jsonl:
        return load_poc_examples(args)
    return load_rows(args.data / "train.jsonl"), load_rows(args.data / "val.jsonl")


def fit(rows, tokenizer, max_len):
    """Render with the chat template; drop examples longer than max_len (never truncate the answer)."""
    out, dropped, lens = [], 0, []
    for r in rows:
        text = tokenizer.apply_chat_template(r["messages"], tokenize=False)
        n = len(tokenizer(text, add_special_tokens=False)["input_ids"])
        if n > max_len:
            dropped += 1
            continue
        lens.append(n)
        out.append({"text": text})
    return out, dropped, sorted(lens)


def check(args):
    from transformers import AutoTokenizer
    tok = AutoTokenizer.from_pretrained(BASE[args.size])
    tr, va = data_splits(args)
    for name, rows in (("train", tr), ("val", va)):
        kept, dropped, lens = fit(rows, tok, args.max_len)
        if lens:
            print(f"[*] {name}: {len(kept)} kept, {dropped} dropped (> {args.max_len} tokens); "
                  f"tokens median {lens[len(lens)//2]}, 90% {lens[int(len(lens)*.9)]}, max {lens[-1]}")
        elif rows:
            print(f"[*] {name}: all {len(rows)} dropped (> {args.max_len} tokens)")
    if not args.jsonl:
        neg = sum(1 for r in tr if json.loads(r["messages"][2]["content"]).get("hypotheses") == [])
        print(f"[*] train negatives (empty answers): {neg}")
        return
    # ---- dataset audit (PoC mode) ----
    a = args._audit
    from collections import Counter
    print("\n[audit] examples by label/origin/variant:")
    for (lab, org, var), n in sorted(Counter((label_of(r), r.get("origin"), r.get("variant")) for r in a["rows"]).items()):
        print(f"    {lab:20} {org:8} {var:16} {n}")
    for lab, n in sorted(Counter(label_of(r) for r in a["repairs"]).items()):
        print(f"    {lab:20} (repairs, train only) {n}")
    print(f"[audit] projects: {len(a['train'])} train, {len(a['val'])} val; "
          f"train/val overlap {len(a['train'] & a['val'])}, train/held-out overlap {len(a['train'] & a['excluded'])}")
    bad = [r for r in a["rows"] if not r["messages"][-1]["content"].strip()
           or not re.search(r"\bfunction\s+test", r["messages"][-1]["content"])]
    print(f"[audit] answers that are empty or have no test function: {len(bad)}")
    leaks = [r for r in a["rows"] if r.get("variant") == "bare" and "THE REPORT'S OWN POC" in r["messages"][1]["content"]]
    print(f"[audit] bare examples that still contain the report PoC: {len(leaks)}")
    # response masking depends on these markers appearing in the rendered chat
    text = tok.apply_chat_template(a["rows"][0]["messages"], tokenize=False) if a["rows"] else ""
    ok = text.count("<|im_start|>assistant\n") == 1 and "<|im_start|>user\n" in text
    print(f"[audit] chat template has the user/assistant markers loss masking relies on: {'yes' if ok else 'NO - masking would fail'}")


def train(args):
    from unsloth import FastLanguageModel                      # import first: it patches transformers
    from unsloth.chat_templates import train_on_responses_only
    from datasets import Dataset
    from trl import SFTConfig, SFTTrainer

    model, tok = FastLanguageModel.from_pretrained(BASE[args.size], max_seq_length=args.max_len,
                                                   load_in_4bit=True, dtype=None)
    model = FastLanguageModel.get_peft_model(
        model, r=args.rank, lora_alpha=args.rank, lora_dropout=0,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
        use_gradient_checkpointing="unsloth", random_state=7)

    tr0, va0 = data_splits(args)
    tr, d1, _ = fit(tr0, tok, args.max_len)
    va, d2, _ = fit(va0, tok, args.max_len)
    print(f"[*] {len(tr)} train / {len(va)} val examples ({d1 + d2} dropped as too long)")

    out = Path(args.out)
    trainer = SFTTrainer(
        model=model, tokenizer=tok,
        train_dataset=Dataset.from_list(tr), eval_dataset=Dataset.from_list(va) if va else None,
        args=SFTConfig(
            output_dir=str(out / "checkpoints"), dataset_text_field="text", max_seq_length=args.max_len,
            per_device_train_batch_size=1, gradient_accumulation_steps=args.grad_accum,
            num_train_epochs=args.epochs, learning_rate=args.lr, lr_scheduler_type="cosine",
            warmup_ratio=0.05, weight_decay=0.01, optim="adamw_8bit", bf16=True,
            logging_steps=5, eval_strategy="epoch" if (va and not args.no_eval) else "no", save_strategy="epoch",
            save_total_limit=2, seed=7, report_to="none"),
    )
    # learn only the answers: mask the system/user part of every example
    trainer = train_on_responses_only(trainer, instruction_part="<|im_start|>user\n",
                                      response_part="<|im_start|>assistant\n")
    trainer.train()
    model.save_pretrained(out / "adapter")
    tok.save_pretrained(out / "adapter")
    print(f"[*] Adapter saved to {out / 'adapter'}. Next: python train_lora.py --export {out}")


def export(args):
    from unsloth import FastLanguageModel
    run = Path(args.export)
    model, tok = FastLanguageModel.from_pretrained(str(run / "adapter"), max_seq_length=args.max_len,
                                                   load_in_4bit=True)
    model.save_pretrained_gguf(str(run / "gguf"), tok, quantization_method="q4_k_m")
    # some Unsloth versions write to "<dir>_gguf" instead of "<dir>"; look in both, prefer the 4-bit file
    files = [p for d in (run / "gguf", run / "gguf_gguf") if d.is_dir() for p in d.glob("*.gguf")]
    q4 = [p for p in files if "q4_k_m" in p.name.lower()] or files
    if not q4:
        raise SystemExit(f"[!] No .gguf written under {run}")
    gguf = min(q4, key=lambda p: p.stat().st_size)
    mf = gguf.parent / "Modelfile"
    import re
    # Unsloth usually writes a Modelfile with the right chat template but Qwen's default SYSTEM; fix it up
    text = mf.read_text() if mf.exists() else f"FROM ./{gguf.name}\nPARAMETER temperature 0.2\n"
    text = re.sub(r'^PARAMETER (num_ctx|num_predict) .*\n?', '', text, flags=re.M)
    if args.system_file:
        text = re.sub(r'SYSTEM """.*?"""\n?', '', text, flags=re.S)
        text = text.rstrip("\n") + '\n\nSYSTEM """' + args.system_file.read_text().strip() + '"""\n'
    text = text.rstrip("\n") + "\nPARAMETER num_ctx 16384\nPARAMETER num_predict 4096\n"
    mf.write_text(text)
    print(f"[*] GGUF: {gguf}\n[*] Load it: ollama create <name> -f {mf}   (e.g. audit-{args.size}-v1, poc-{args.size}-v1)")


def main():
    ap = argparse.ArgumentParser(description="QLoRA fine-tune for audit_assist")
    ap.add_argument("--data", type=Path, default=Path("dataset"))
    ap.add_argument("--jsonl", type=Path, help="Train on a PoC examples file instead (dataset_poc/examples.jsonl)")
    ap.add_argument("--variants", default="bare,with_report_poc", help="PoC example variants to use")
    ap.add_argument("--include-revert-style", action="store_true", help="Also train on expectRevert-style harvested PoCs")
    ap.add_argument("--val-frac", type=float, default=0.15, help="Fraction of CONTESTS held out as val (PoC mode)")
    ap.add_argument("--repairs", type=Path, help="Also train on compile-repair pairs (dataset_poc/repairs.jsonl)")
    ap.add_argument("--labels", default="control_verified,report_test_passes",
                    help="Label strengths to train on (default: both verified kinds; examples.jsonl never contains "
                         "weaker outcomes). control_verified alone = strongest, much smaller")
    ap.add_argument("--system-file", type=Path,
                    help="Export: put this system prompt in the Modelfile (PoC models: poc_system.txt)")
    ap.add_argument("--exclude-contests", type=Path,
                    help="Leave these contests out of training (the held-out test set: dataset_poc/holdout_contests.txt)")
    ap.add_argument("--repairs-max", type=int, default=60, help="Cap on repair examples (keep them a minority)")
    ap.add_argument("--grad-accum", type=int, default=8)
    ap.add_argument("--no-eval", action="store_true",
                    help="Skip the per-epoch validation pass (it runs without checkpointing and can OOM on long examples)")
    ap.add_argument("--size", choices=list(BASE), default="7b")
    ap.add_argument("--max-len", type=int, default=8192, help="Tokens per example; longer ones are dropped")
    ap.add_argument("--epochs", type=float, default=2)
    ap.add_argument("--lr", type=float, default=2e-4)
    ap.add_argument("--rank", type=int, default=16)
    ap.add_argument("--out", default="runs_lora/v1")
    ap.add_argument("--check", action="store_true", help="Only tokenize and report lengths (no GPU)")
    ap.add_argument("--export", help="Run folder to export to GGUF (e.g. runs_lora/v1)")
    args = ap.parse_args()
    if args.check:
        check(args)
    elif args.export:
        export(args)
    else:
        train(args)


if __name__ == "__main__":
    main()
