"""
validate_rules.py
-----------------
Measures the Tier 1 rules on labelled flow records.

    python validate_rules.py --pipeline <forenxai_binary dir> [--out rules_validation.json]
                             [--datasets trustlab tii cicids]

Three labelled sources, all under <pipeline>/data/raw:

  trustlab   TRUSTLab, one capture per class, read with the pipeline's own
             reader (joins the split archives, recovers the truncated one).
             Its IP addresses and timestamps are anonymised -- every flow has
             its own source/destination pair and whole classes span one or two
             seconds -- so rules that group flows by host cannot fire here.
             It is kept in the report as that measured fact.
  tii        TII-SSRC-23 data.csv: real IPs and timestamps; Bruteforce, DoS,
             Information Gathering (scans), Mirai DDoS and a little benign.
  cicids     CSE-CIC-IDS2018 02-20-2018.csv, the one day exported with IPs:
             7.4 M benign flows and 576 k DDoS LOIC-HTTP -- the false-alarm test.

Large files are read in 1,000,000-row chunks with only the columns the rules
use, so memory stays bounded; a group that straddles a chunk boundary is
counted in two halves, which can only lower recall.

For each rule and sensitivity (low / medium / high):
  recall       share of its target class's flows it flags
  precision    share of the flows it flags whose label is its target class
  false alarm  share of benign flows it flags
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import defaultdict
from pathlib import Path

import pandas as pd

from app.services import rule_service as rs

USECOLS = {c for names in rs.ALIASES.values() for c in names}
LEVELS = ("low", "medium", "high")
CHUNK = 1_000_000


def tii_class(frame: pd.DataFrame) -> pd.Series:
    """TII-SSRC-23 labels mapped to the rule classes (others kept as-is)."""
    kind, sub = frame["Traffic Type"].astype(str), frame["Traffic Subtype"].astype(str)
    out = kind.copy()
    out[kind.isin(["Audio", "Background", "Text", "Video"])] = "Benign"
    out[kind == "Information Gathering"] = "PortScan"
    out[sub.str.startswith("Mirai DDoS")] = "DDoS"
    out[sub == "Mirai Scan Bruteforce"] = "Mirai scan/bruteforce"
    return out


def cicids_class(frame: pd.DataFrame) -> pd.Series:
    label = frame["Label"].astype(str)
    return label.where(label == "Benign", "DDoS")


class Tally:
    """Counts per sensitivity, rule and true class."""

    def __init__(self):
        self.totals = defaultdict(int)
        self.flagged = {lvl: defaultdict(lambda: defaultdict(int)) for lvl in LEVELS}
        self.any_flag = {lvl: defaultdict(int) for lvl in LEVELS}

    def add(self, frame: pd.DataFrame, labels, configs):
        labels = list(labels)
        for label in labels:
            self.totals[label] += 1
        for lvl in LEVELS:
            for label, hits in zip(labels, rs.evaluate_frame(frame, configs[lvl])):
                if hits:
                    self.any_flag[lvl][label] += 1
                for rid in {h["rule_id"] for h in hits}:
                    self.flagged[lvl][rid][label] += 1

    def report(self, rule_class):
        t = self.totals
        out = {"flows_per_class": dict(t), "by_sensitivity": {}}
        for lvl in LEVELS:
            rows = {}
            for rid, target in rule_class.items():
                counts = self.flagged[lvl][rid]
                hits_total = sum(counts.values())
                rows[rid] = {
                    "class": target,
                    "recall": counts[target] / t[target] if t[target] else None,
                    "precision": counts[target] / hits_total if hits_total else None,
                    "false_alarm_benign": counts["Benign"] / t["Benign"] if t["Benign"] else None,
                    "flagged": dict(counts),
                }
            out["by_sensitivity"][lvl] = {
                "rules": rows,
                "benign_flows_with_any_hit":
                    self.any_flag[lvl]["Benign"] / t["Benign"] if t["Benign"] else None,
            }
        return out


def chunks(path: Path, label_columns, to_class):
    wanted = USECOLS | set(label_columns)
    for chunk in pd.read_csv(path, usecols=lambda c: str(c).strip() in wanted,
                             chunksize=CHUNK, low_memory=False):
        chunk = chunk.rename(columns=lambda c: str(c).strip())
        yield chunk, to_class(chunk)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pipeline", required=True, type=Path,
                    help="forenxai_binary folder: holds src/trustlab_io.py and data/raw/")
    ap.add_argument("--datasets", nargs="+", default=["trustlab", "tii", "cicids"])
    ap.add_argument("--out", type=Path, default=Path("rules_validation.json"))
    args = ap.parse_args()

    configs = {lvl: rs.load_config(sensitivity=lvl) for lvl in LEVELS}
    rule_class = {rid: r["class"] for rid, r in configs["medium"]["rules"].items()}
    raw = args.pipeline / "data" / "raw"
    report = {"rules_version": configs["medium"]["version"], "datasets": {}}

    for name in args.datasets:
        started, tally = time.perf_counter(), Tally()
        if name == "trustlab":
            sys.path.insert(0, str(args.pipeline))
            from src import trustlab_io as tio                  # noqa: E402
            sources, problems, _ = tio.class_sources(raw / "TRUSTLab")
            for problem in problems:
                print("  PROBLEM:", problem)
            for label, paths in sorted(sources.items()):
                stream, _ = tio.open_class(paths)
                try:
                    frame = pd.read_csv(stream, usecols=lambda c: str(c).strip() in USECOLS,
                                        low_memory=False)
                finally:
                    stream.close()
                tally.add(frame, [label] * len(frame), configs)
                print(f"  trustlab {label:<15} {len(frame):>10,} flows", flush=True)
        elif name == "tii":
            for chunk, labels in chunks(raw / "TII-SSRC-23" / "data.csv",
                                        ["Traffic Type", "Traffic Subtype"], tii_class):
                tally.add(chunk, labels, configs)
                print(f"  tii      chunk {sum(tally.totals.values()):>12,} flows", flush=True)
        elif name == "cicids":
            for chunk, labels in chunks(raw / "CICIDS2018" / "02-20-2018.csv",
                                        ["Label"], cicids_class):
                tally.add(chunk, labels, configs)
                print(f"  cicids   chunk {sum(tally.totals.values()):>12,} flows", flush=True)
        result = tally.report(rule_class)
        result["seconds"] = round(time.perf_counter() - started, 1)
        report["datasets"][name] = result
        args.out.write_text(json.dumps(report, indent=2), encoding="utf-8")

    fmt = lambda v: "     --" if v is None else f"{v:.4f}"
    for name, result in report["datasets"].items():
        print(f"\n=== {name}: {sum(result['flows_per_class'].values()):,} flows, {result['seconds']} s")
        print("    classes:", {k: v for k, v in sorted(result["flows_per_class"].items())})
        for lvl in LEVELS:
            block = result["by_sensitivity"][lvl]
            print(f"  sensitivity {lvl}: benign flows with any hit {fmt(block['benign_flows_with_any_hit'])}")
            for rid, r in block["rules"].items():
                print(f"    {rid:<18}{r['class']:<13} recall {fmt(r['recall'])}  "
                      f"precision {fmt(r['precision'])}  benign FA {fmt(r['false_alarm_benign'])}")
    print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
