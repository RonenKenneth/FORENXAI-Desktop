"""
04_align_and_build.py
---------------------
Computes the feature set all three datasets share, then builds the training,
validation and external-test splits.

WHY ALIGNMENT GETS ITS OWN STEP
The shared feature list is the contract between training and evaluation. If
it drifts -- a column renamed, a file re-exported, a different TRUSTLab
subset used -- results stop being comparable. Computing it once and freezing
it to disk means every downstream script reads the same list rather than
recomputing and possibly disagreeing.

The ORDER is frozen too, not just the membership. Models consume feature
vectors positionally: a different column order produces silently wrong
predictions rather than an error.

THREE TRAINING ARMS
  combined      CICIDS2018 + TII-SSRC-23. The study.
  cicids_only   Control. Shows what benign-rich enterprise data alone gives.
  tii_only      Control. Expected to fail -- it has ~1,301 benign flows, so
                it demonstrates why combining was necessary rather than
                optional.

Running all three means the decision to combine is evidenced rather than
asserted.

Usage:
  python scripts/04_align_and_build.py
  python scripts/04_align_and_build.py --arms combined cicids_only
"""
import sys
import json
import argparse
from pathlib import Path

import numpy as np
import pandas as pd
import joblib

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config.settings import (INTERIM_DIR, PROCESSED_DIR, ARTIFACTS_DIR, SEED,
                             TRAIN_PER_CLASS, TRAINING_ARMS,
                             TRUSTLAB_PER_CLASS)
from src.common import (get_logger, banner, human, stratified_cap,
                        save_json)
from src.schema import (NON_FEATURES, ABSENT_FROM_TRUSTLAB,
                        DEGENERATE_IN_TRUSTLAB)

log = get_logger("04_align")

ap = argparse.ArgumentParser()
ap.add_argument("--arms", nargs="+", default=TRAINING_ARMS,
                choices=TRAINING_ARMS)
args = ap.parse_args()

need = {"cicids2018.parquet": "01_prepare_cicids2018.py",
        "tii_ssrc_23.parquet": "02_prepare_tii.py",
        "trustlab.parquet": "03_prepare_trustlab.py"}
for fn, script in need.items():
    if not (INTERIM_DIR / fn).exists():
        log.error(f"Missing {INTERIM_DIR/fn} -- run {script} first.")
        sys.exit(1)

cic = pd.read_parquet(INTERIM_DIR / "cicids2018.parquet")
tii = pd.read_parquet(INTERIM_DIR / "tii_ssrc_23.parquet")
tlb = pd.read_parquet(INTERIM_DIR / "trustlab.parquet")

# --------------------------------------------------------------------------
banner(log, "FEATURE INTERSECTION")
sets = {
    "CICIDS2018":  set(cic.columns) - NON_FEATURES,
    "TII-SSRC-23": set(tii.columns) - NON_FEATURES,
    "TRUSTLab":    set(tlb.columns) - NON_FEATURES,
}
for k, v in sets.items():
    log.info(f"  {k:<14} {len(v)} features")

shared = sorted(set.intersection(*sets.values()))   # sorted -> deterministic

# TRUSTLab exports the active/idle columns without populating them: four are
# identically zero and the rest are deterministic functions of Flow Duration.
# Both training sources populate them properly, so leaving them in means the
# models learn a real response to a feature that arrives as a copy of another
# feature at test time. See DEGENERATE_IN_TRUSTLAB in src/schema.py.
degenerate = [f for f in shared if f in DEGENERATE_IN_TRUSTLAB]
if degenerate:
    shared = [f for f in shared if f not in DEGENERATE_IN_TRUSTLAB]
    log.warning(f"\n  Dropped {len(degenerate)} columns TRUSTLab does not "
                f"populate: {', '.join(degenerate)}")
    log.warning("  They are real measurements in CICIDS2018 and TII-SSRC-23 "
                "but carry no information in TRUSTLab, so keeping them would "
                "corrupt the cross-dataset comparison.")

log.info(f"\n  SHARED: {len(shared)}")

for k, v in sets.items():
    lost = sorted(v - set(shared))
    if lost:
        log.info(f"\n  Dropped from {k} ({len(lost)}):")
        for f in lost:
            note = "   <- TRUSTLab does not export this" \
                if f in ABSENT_FROM_TRUSTLAB else ""
            log.info(f"      {f}{note}")

if len(shared) < 40:
    log.error(f"\nOnly {len(shared)} shared features. A rename is probably "
              f"missing from src/schema.py -- check the dropped lists above "
              f"for near-matching names.")
    sys.exit(1)

log.info(f"\nFrozen feature order ({len(shared)}):")
for i, f in enumerate(shared, 1):
    log.info(f"  {i:>3}. {f}")

joblib.dump(shared, ARTIFACTS_DIR / "shared_features.pkl")
with open(ARTIFACTS_DIR / "shared_features.json", "w", encoding="utf-8") as fh:
    json.dump({"n_features": len(shared), "features": shared,
               "dropped": {k: sorted(v - set(shared)) for k, v in sets.items()}},
              fh, indent=2)
log.info(f"\nSaved -> {ARTIFACTS_DIR/'shared_features.pkl'}")

# --------------------------------------------------------------------------
banner(log, "EXTERNAL TEST SET (TRUSTLab)")
keep = shared + ["binary_label", "folder_class", "source_dataset"]

# Script 03 sizes its output for the multiclass experiment, which asks for more
# rows per class than this one does. Cap back to TRUSTLAB_PER_CLASS so the
# binary test set stays the balanced 16 x TRUSTLAB_PER_CLASS design the
# baseline comparison in script 06 was written against -- otherwise Benign
# would arrive at MC_BENIGN_CAP and shift the benign-to-attack ratio, moving
# every aggregate metric for a reason unrelated to the models.
tlb_out = stratified_cap(tlb[keep], "folder_class", TRUSTLAB_PER_CLASS, SEED)
nb = int((tlb_out["binary_label"] == 0).sum())
na = int((tlb_out["binary_label"] == 1).sum())
log.info(f"Rows {human(len(tlb_out))}   benign {human(nb)}   attack {human(na)}"
         f"   ({human(TRUSTLAB_PER_CLASS)} per class, capped from "
         f"{human(len(tlb))})")
for c, n in tlb_out["folder_class"].value_counts().items():
    log.info(f"    {c:<16} {human(n):>9}")
tlb_out.to_parquet(PROCESSED_DIR / "test_trustlab.parquet")
log.info(f"Saved -> {PROCESSED_DIR/'test_trustlab.parquet'}")

# --------------------------------------------------------------------------
banner(log, "TRAINING SETS")
sources = {
    "combined":    pd.concat([cic[keep[:-1] + ["source_dataset"]],
                              tii[keep[:-1] + ["source_dataset"]]],
                             ignore_index=True),
    "cicids_only": cic[keep[:-1] + ["source_dataset"]],
    "tii_only":    tii[keep[:-1] + ["source_dataset"]],
}

for arm in args.arms:
    df = sources[arm]
    nb = int((df["binary_label"] == 0).sum())
    na = int((df["binary_label"] == 1).sum())
    log.info(f"\n--- {arm} ---")
    log.info(f"  available    benign {human(nb):>12}   attack {human(na):>12}"
             f"   ratio {nb/max(1,na):.3f}:1")

    capped = stratified_cap(df, "binary_label", TRAIN_PER_CLASS, SEED)
    cb = int((capped["binary_label"] == 0).sum())
    ca = int((capped["binary_label"] == 1).sum())
    log.info(f"  after cap    benign {human(cb):>12}   attack {human(ca):>12}"
             f"   ratio {cb/max(1,ca):.3f}:1")
    log.info(f"  total rows   {human(len(capped))}")

    if cb < 5_000:
        log.warning(f"  Only {human(cb)} benign rows. This arm cannot learn "
                    f"a useful representation of normal traffic; expect it "
                    f"to classify almost everything as attack.")
    if "source_dataset" in capped.columns:
        for s, n in capped["source_dataset"].value_counts().items():
            log.info(f"    from {s:<14} {human(n)}")

    # Record what each arm is actually made of. "combined" is not an even
    # blend: TII-SSRC-23 contributes 1,301 benign flows in total, so any
    # class-balanced sample is dominated by CICIDS2018 on the benign side.
    # That is inherent to the data, not a sampling choice, and it bounds what
    # a combined-vs-cicids_only comparison can show -- so the number belongs
    # in the results rather than in someone's memory of a log line.
    comp = {str(k): int(v)
            for k, v in capped["source_dataset"].value_counts().items()}
    save_json({"arm": arm, "rows": int(len(capped)),
               "benign": cb, "attack": ca,
               "source_composition": comp,
               "source_share": {k: round(v / len(capped), 4)
                                for k, v in comp.items()}},
              "arms", f"{arm}_composition.json")

    out = PROCESSED_DIR / f"train_{arm}.parquet"
    capped.to_parquet(out)
    log.info(f"  Saved -> {out}")

banner(log, "NEXT")
log.info("python scripts/05_train_binary.py --arm combined")
