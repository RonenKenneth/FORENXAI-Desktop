"""
08_build_multiclass.py
----------------------
Builds train / validation / test splits for sixteen-class classification,
entirely within TRUSTLab.

WHY THIS STAYS INSIDE ONE DATASET
Cross-dataset multiclass is not possible here. Six of TRUSTLab's sixteen
classes -- API, MITM, Evasion, TLSSSL, Exfiltration, C2Beaconing -- have no
counterpart in CICIDS2018 or TII-SSRC-23. A model predicting them on those
datasets would be wrong by construction, and a model trained on those
datasets could never predict them at all. The binary experiment (scripts
01-07) is where cross-dataset transfer is measured; multiclass is where
attack-type discrimination is measured.

TWO SPLIT STRATEGIES

  random    Stratified random at the flow level. This matches the protocol
            the TRUSTLab authors used, so results are directly comparable to
            their published per-class figures.
            Rows that share an identical feature vector are kept on the same
            side (LEAKAGE_SAFE_SPLITS in config/settings.py), so no test row
            has a copy in training. Class counts are within a few dozen of
            80/20 rather than exact.

  temporal  Within each class, the first 80% of rows become training and the
            last 20% become test. Flows sit in capture order within each
            file, so this separates different sessions rather than
            interleaving them.

The second is stricter. The TRUSTLab authors note in their own limitations
that flow-level random splitting is weaker than campaign-level splitting, and
that their modular file structure was designed to enable the latter. Running
both and reporting the difference quantifies how much the easier protocol
inflates results -- which is worth more than either number alone.

Set MC_SPLIT_STRATEGY in config/settings.py, or pass --strategy.

CLASS BALANCE
Benign holds roughly 2.57 million flows against about 100,000 per attack
class -- a 25:1 imbalance that would dominate training. Benign is capped
separately from the attack classes. Class weighting in script 09 handles what
remains.

Usage:
  python scripts/08_build_multiclass.py
  python scripts/08_build_multiclass.py --strategy temporal
  python scripts/08_build_multiclass.py --strategy both
"""
import sys
import argparse
from pathlib import Path

import numpy as np
import pandas as pd
import joblib

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config.settings import (INTERIM_DIR, PROCESSED_DIR, ARTIFACTS_DIR, SEED,
                             MC_PER_CLASS, MC_BENIGN_CAP, MC_TEST_FRACTION,
                             MC_SPLIT_STRATEGY, MC_HARD_CLASSES,
                             LEAKAGE_SAFE_SPLITS)
from src.common import (get_logger, banner, human, feature_ids, group_split,
                        check_no_leakage)
from src.schema import NON_FEATURES, DEGENERATE_IN_TRUSTLAB

log = get_logger("08_mc_build")

ap = argparse.ArgumentParser()
ap.add_argument("--strategy", choices=["random", "temporal", "both"],
                default=MC_SPLIT_STRATEGY)
args = ap.parse_args()
strategies = ["random", "temporal"] if args.strategy == "both" else [args.strategy]

src = INTERIM_DIR / "trustlab.parquet"
if not src.exists():
    log.error(f"Missing {src} -- run 03_prepare_trustlab.py first.")
    sys.exit(1)

df = pd.read_parquet(src)
log.info(f"Loaded {human(len(df))} rows")

# --------------------------------------------------------------------------
banner(log, "CLASS DISTRIBUTION AS LOADED")
counts = df["folder_class"].value_counts()
for c, n in counts.items():
    mark = "   <- hard class" if c in MC_HARD_CLASSES else ""
    log.info(f"  {c:<18} {human(n):>10}{mark}")
log.info(f"\n{len(counts)} classes, {human(len(df))} rows")

if len(counts) < 16:
    log.warning(f"Expected 16 classes, found {len(counts)}. Missing classes "
                f"cannot be evaluated -- check script 03's output for "
                f"truncated or unjoined files.")

# --------------------------------------------------------------------------
banner(log, "CAPPING")
log.info(f"Attack classes capped at {human(MC_PER_CLASS)}")
log.info(f"Benign capped at {human(MC_BENIGN_CAP)} (it is ~25x any attack "
         f"class in the full corpus)")

parts = []
for cls, grp in df.groupby("folder_class"):
    cap = MC_BENIGN_CAP if cls.lower() == "benign" else MC_PER_CLASS
    take = min(len(grp), cap)
    # head(), not sample() -- preserves capture order so the temporal split
    # below is meaningful
    parts.append(grp.head(take))
    if take < len(grp):
        log.info(f"  {cls:<18} {human(len(grp)):>10} -> {human(take):>10}")
    else:
        log.info(f"  {cls:<18} {human(len(grp)):>10}    (kept whole)")

data = pd.concat(parts, ignore_index=True)
del parts

log.info(f"\nAfter capping: {human(len(data))} rows")
ratio = data["folder_class"].value_counts()
log.info(f"Largest class / smallest class: "
         f"{ratio.max() / max(1, ratio.min()):.1f}x")

# The same exclusion script 04 applies to the binary contract. TRUSTLab does
# not populate the active/idle columns -- four are identically zero and the
# rest are deterministic functions of Flow Duration -- so inside TRUSTLab they
# are dead weight, and in script 13 they are worse than that: the external
# datasets DO populate them, so a model that learned a response to them here
# meets real, wildly different values when it is transferred out.
# See DEGENERATE_IN_TRUSTLAB in src/schema.py.
feats = sorted(set(data.columns) - NON_FEATURES - set(DEGENERATE_IN_TRUSTLAB))
log.info(f"Features: {len(feats)}")
joblib.dump(feats, ARTIFACTS_DIR / "mc_features.pkl")

classes = sorted(data["folder_class"].unique())
joblib.dump(classes, ARTIFACTS_DIR / "mc_classes.pkl")
log.info(f"Classes: {classes}")

# --------------------------------------------------------------------------
for strat in strategies:
    banner(log, f"SPLIT STRATEGY: {strat}")

    tr_parts, te_parts = [], []
    if strat == "random" and LEAKAGE_SAFE_SPLITS:
        # Rows sharing a feature vector go to the same side, so no test row
        # has a copy in training. Class shares are stratified but no longer
        # exactly 80/20 per class, because copies move together.
        ids_all = feature_ids(data, feats)
        itr, ite = group_split(data["folder_class"].values, ids_all,
                               MC_TEST_FRACTION)
        tr_parts, te_parts = [data.iloc[itr]], [data.iloc[ite]]
        groups = ()
    else:
        groups = data.groupby("folder_class")
    for cls, grp in groups:
        n_test = max(1, int(round(len(grp) * MC_TEST_FRACTION)))
        if strat == "random":
            g = grp.sample(frac=1, random_state=SEED)
            te_parts.append(g.iloc[:n_test])
            tr_parts.append(g.iloc[n_test:])
        else:
            # capture order preserved -> last portion is a later session
            te_parts.append(grp.iloc[-n_test:])
            tr_parts.append(grp.iloc[:-n_test])

    train = (pd.concat(tr_parts, ignore_index=True)
             .sample(frac=1, random_state=SEED).reset_index(drop=True))
    test = (pd.concat(te_parts, ignore_index=True)
            .sample(frac=1, random_state=SEED).reset_index(drop=True))
    del tr_parts, te_parts

    # Random splits must be clean (enforced). The temporal split follows
    # capture order, so copies across the boundary are reported, not removed.
    check_no_leakage(feature_ids(train, feats), feature_ids(test, feats), log,
                     f"{strat} train / test",
                     enforce=(strat == "random" and LEAKAGE_SAFE_SPLITS))

    log.info(f"Train {human(len(train))}   Test {human(len(test))}")
    log.info("\nPer class (train / test):")
    tc = train["folder_class"].value_counts()
    sc = test["folder_class"].value_counts()
    for c in classes:
        mark = "  <- hard" if c in MC_HARD_CLASSES else ""
        log.info(f"  {c:<18} {human(tc.get(c,0)):>9} / {human(sc.get(c,0)):>8}{mark}")

    keep = feats + ["folder_class", "binary_label", "source_dataset"]
    keep = [c for c in keep if c in train.columns]
    train[keep].to_parquet(PROCESSED_DIR / f"mc_train_{strat}.parquet")
    test[keep].to_parquet(PROCESSED_DIR / f"mc_test_{strat}.parquet")
    log.info(f"\nSaved -> mc_train_{strat}.parquet, mc_test_{strat}.parquet")

    if strat == "temporal":
        log.info("")
        log.info("Temporal split: test rows come from later in each capture "
                 "than training rows. Any drop against the random split "
                 "reflects within-session correlation that random splitting "
                 "conceals.")

banner(log, "NEXT")
log.info("python scripts/09_train_multiclass.py")
