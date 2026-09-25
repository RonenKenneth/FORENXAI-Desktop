"""
tune_rules.py
-------------
Chooses the Tier 1 thresholds on labelled traffic and tests them on traffic
they were not chosen on.

    python tune_rules.py --pipeline <forenxai_binary dir> [--write]

Data: TII-SSRC-23 (data.csv) and CSE-CIC-IDS2018 (02-20-2018.csv), the two
labelled sources that keep real IP addresses and timestamps. TRUSTLab cannot
be used: its addresses and timestamps are anonymised (see validate_rules.py).

Split without leakage: every flow falls in a 60-second window, and the grouped
rules decide per window. Flows in even-numbered minutes are the TUNING half,
flows in odd-numbered minutes the TEST half. A window never straddles the two.

For each tunable rule, five candidate settings (the current one included) are
evaluated in one pass over the data. On the tuning half the setting with the
best F1 on the rule's own class is chosen among those whose false-alarm rate
on benign flows is at most MAX_BENIGN_FA; its figures on the test half are the
ones to report. --write stores the chosen values in app/rules/rules.json.

Slowloris, C2Beaconing and Exfiltration have no labelled attack flows in
either dataset, so their thresholds cannot be tuned here; their false-alarm
rate on benign traffic is still measured.
"""
from __future__ import annotations

import argparse
import copy
import json
import time
from collections import defaultdict
from pathlib import Path

import numpy as np
import pandas as pd

from app.services import rule_service as rs
from validate_rules import CHUNK, USECOLS, cicids_class, tii_class

MAX_BENIGN_FA = 0.01

# rule id -> candidate settings, the current value first
GRID = {
    "T1-PORTSCAN-01": [{"min_distinct_ports": v} for v in (20, 10, 15, 30, 50)],
    "T1-DDOS-01": [{"min_flooding_sources": a, "per_source_min_flows": b}
                   for a, b in ((3, 50), (2, 50), (3, 20), (3, 100), (5, 50))],
    "T1-DOS-01": [{"min_flows": v} for v in (100, 50, 200, 400, 800)],
    "T1-BRUTEFORCE-01": [{"min_attempts": a, "max_size_cv": b}
                         for a, b in ((10, 0.3), (5, 1.0), (10, 0.6), (10, 1.0), (20, 1.0))],
}
K = max(len(v) for v in GRID.values())


def configs():
    base = rs.load_config(sensitivity="medium")
    out = []
    for k in range(K):
        cfg = copy.deepcopy(base)
        for rid, options in GRID.items():
            cfg["rules"][rid].update(options[min(k, len(options) - 1)])
        out.append(cfg)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pipeline", required=True, type=Path)
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--out", type=Path, default=Path("rules_tuning.json"))
    args = ap.parse_args()

    raw = args.pipeline / "data" / "raw"
    sources = [(raw / "TII-SSRC-23" / "data.csv", ["Traffic Type", "Traffic Subtype"], tii_class),
               (raw / "CICIDS2018" / "02-20-2018.csv", ["Label"], cicids_class)]
    cfgs = configs()
    rule_class = {rid: r["class"] for rid, r in cfgs[0]["rules"].items()}
    totals = {s: defaultdict(int) for s in (0, 1)}                    # split -> class -> flows
    hits = {(k, s): defaultdict(lambda: defaultdict(int))              # (config, split) -> rule -> class
            for k in range(K) for s in (0, 1)}
    started = time.perf_counter()

    for path, label_cols, to_class in sources:
        wanted = USECOLS | set(label_cols)
        for chunk in pd.read_csv(path, usecols=lambda c: str(c).strip() in wanted,
                                 chunksize=CHUNK, low_memory=False):
            chunk = chunk.rename(columns=lambda c: str(c).strip())
            labels = to_class(chunk).to_numpy()
            ts = rs.normalise(chunk)["ts"]
            minute = (ts - pd.Timestamp(0)).dt.total_seconds() // 60
            split = np.where(minute.isna(), -1, minute.fillna(0) % 2).astype(int)
            for s in (0, 1):
                for label, n in zip(*np.unique(labels[split == s], return_counts=True)):
                    totals[s][label] += int(n)
            for k, cfg in enumerate(cfgs):
                for row, row_hits in enumerate(rs.evaluate_frame(chunk, cfg)):
                    s = split[row]
                    if s < 0:
                        continue
                    for rid in {h["rule_id"] for h in row_hits}:
                        hits[(k, s)][rid][labels[row]] += 1
            print(f"  {path.name}: {sum(totals[0].values()) + sum(totals[1].values()):,} flows, "
                  f"{time.perf_counter() - started:.0f} s", flush=True)

    def metrics(k, s, rid):
        target, counts = rule_class[rid], hits[(k, s)][rid]
        tp, flagged = counts[target], sum(counts.values())
        recall = tp / totals[s][target] if totals[s][target] else None
        precision = tp / flagged if flagged else None
        f1 = (2 * precision * recall / (precision + recall)
              if precision and recall else 0.0)
        fa = counts["Benign"] / totals[s]["Benign"] if totals[s]["Benign"] else None
        return {"recall": recall, "precision": precision, "f1": f1, "benign_fa": fa,
                "attack_flows_flagged": flagged - counts["Benign"]}

    report = {"max_benign_fa": MAX_BENIGN_FA, "flows": {s: dict(totals[s]) for s in (0, 1)},
              "seconds": round(time.perf_counter() - started, 1), "rules": {}}
    chosen = {}
    for rid in rule_class:
        options = GRID.get(rid, [{}])
        candidates = []
        for k in range(len(options)):
            tune = metrics(k, 0, rid)
            candidates.append({"setting": options[k], "tune": tune, "test": metrics(k, 1, rid)})
        admissible = [c for c in candidates
                      if c["tune"]["benign_fa"] is not None and c["tune"]["benign_fa"] <= MAX_BENIGN_FA]
        pick = (max(admissible, key=lambda c: c["tune"]["f1"]) if admissible
                else min(candidates, key=lambda c: c["tune"]["benign_fa"] or 0))
        chosen[rid] = pick["setting"]
        report["rules"][rid] = {"class": rule_class[rid], "tunable": rid in GRID,
                                "chosen": pick, "candidates": candidates}
    args.out.write_text(json.dumps(report, indent=2), encoding="utf-8")

    fmt = lambda v: "   --" if v is None else f"{v:.4f}"
    print(f"\nflows: tuning {sum(totals[0].values()):,}, test {sum(totals[1].values()):,}; "
          f"{report['seconds']} s")
    for rid, r in report["rules"].items():
        print(f"\n{rid} ({r['class']}){'' if r['tunable'] else '  -- not tunable: no labelled positives'}")
        for c in r["candidates"]:
            mark = "*" if c is r["chosen"] else " "
            t, e = c["tune"], c["test"]
            print(f"  {mark} {json.dumps(c['setting']):<52} tune F1 {fmt(t['f1'])} FA {fmt(t['benign_fa'])} | "
                  f"test recall {fmt(e['recall'])} precision {fmt(e['precision'])} F1 {fmt(e['f1'])} FA {fmt(e['benign_fa'])}")

    if args.write:
        path = rs.RULES_FILE
        cfg = json.loads(path.read_text(encoding="utf-8"))
        for rid, setting in chosen.items():
            cfg["rules"][rid].update(setting)
        cfg["tuning"] = {
            "method": "even-minute flows of TII-SSRC-23 and CSE-CIC-IDS2018 02-20 choose; "
                      "odd-minute flows test",
            "selection": f"best F1 on the rule's class with benign false alarms <= {MAX_BENIGN_FA:.0%}",
            "tuned_rules": sorted(GRID),
            "untuned_rules": sorted(set(rule_class) - set(GRID)),
            "report": "rules_tuning.json (tune_rules.py)",
        }
        cfg["version"] = "tier1-1.1"
        path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
        print(f"\nwrote tuned thresholds to {path}")


if __name__ == "__main__":
    main()
