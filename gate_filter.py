#!/usr/bin/env python3
"""Retroactively apply the privilege gate to the collected PoC dataset.

Drops every record whose PoC reconfigures the protocol or grants the attacker
privilege the finding never mentions (same predicate the live harvest gate uses),
writes *.gated.jsonl + a dropped-report, and leaves the originals untouched so
you can review before promoting.
"""
import json
from pathlib import Path
from assert_pass import privileged_setup_in_attack

D = Path("dataset_poc")

def finding_text(rec):
    return (str(rec.get("title", "")) + " " +
            str(rec.get("claim_text_bare") or rec.get("claim_text") or ""))

# 1) pocs.jsonl -- authoritative per-finding decision
dropped, kept_pocs = {}, []
for line in (D / "pocs.jsonl").read_text().splitlines():
    if not line.strip():
        continue
    rec = json.loads(line)
    gated, hits = privileged_setup_in_attack(str(rec.get("poc", "")), finding_text(rec))
    if gated:
        dropped[(rec.get("contest"), rec.get("finding_id"))] = hits
    else:
        kept_pocs.append(line)
(D / "pocs.gated.jsonl").write_text("\n".join(kept_pocs) + ("\n" if kept_pocs else ""))

# 2) examples/repairs -- drop trajectories for any dropped finding
def filter_by_pair(fname):
    kept, drop = [], 0
    for line in (D / fname).read_text().splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        if (rec.get("contest"), rec.get("finding_id")) in dropped:
            drop += 1
        else:
            kept.append(line)
    (D / fname.replace(".jsonl", ".gated.jsonl")).write_text("\n".join(kept) + ("\n" if kept else ""))
    return len(kept), drop

ex_keep, ex_drop = filter_by_pair("examples.jsonl")
rp_keep, rp_drop = filter_by_pair("repairs.jsonl")

# 3) report
rep = ["dropped (contest, finding_id, hits):"]
for (c, fid), hits in sorted(dropped.items(), key=lambda x: (x[0][0] or "", x[0][1] or "")):
    rep.append(f"  {str(c):28} {str(fid):8} {hits}")
(D / "gated_dropped.txt").write_text("\n".join(rep) + "\n")

print(f"pocs:     kept {len(kept_pocs):4}  dropped {len(dropped)}")
print(f"examples: kept {ex_keep:4}  dropped {ex_drop}")
print(f"repairs:  kept {rp_keep:4}  dropped {rp_drop}")
print(f"report -> {D/'gated_dropped.txt'}")
