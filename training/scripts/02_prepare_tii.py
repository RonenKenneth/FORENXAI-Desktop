"""
02_prepare_tii.py
-----------------
Loads TII-SSRC-23, normalises to V4 naming, and derives the binary label.

WHAT THIS DATASET CONTRIBUTES
Attack diversity. TII-SSRC-23 holds roughly 8.65 million malicious flows
across DoS, Bruteforce, Information Gathering and Mirai IoT botnet -- notably
including genuine IoT malware, which CICIDS2018 lacks entirely.

WHAT IT CANNOT CONTRIBUTE
Benign traffic. It contains only about 1,301 benign flows: Video (870), Text
(209), Audio (190) and Background (32). That is 0.015% of the dataset. A
binary model trained on TII-SSRC-23 alone would predict "attack"
unconditionally and score 99.98% accuracy while being useless.

This is why the study trains on both datasets together. CICIDS2018 supplies
the benign side; TII-SSRC-23 supplies attack variety.

DERIVING THE LABEL
The four benign Traffic Type values above were confirmed by cross-tabulating
Traffic Type against the dataset's own binary Label column -- not inferred
from the category names. That distinction matters: "Background" could
plausibly have meant background scanning rather than background traffic.

Every benign row is kept -- there are barely any. Attack rows are subsampled
during loading, because holding 8.65 million rows in memory is unnecessary
when script 04 will cap the class anyway. The subsample is a reservoir draw
over the whole file (src.common.Reservoir), so it does not depend on how many
chunks the file happens to split into, and the full Traffic Type distribution
is still counted from every row and reported below.

Usage:  python scripts/02_prepare_tii.py
"""
import sys
import argparse
import gc
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config.settings import (TII_CSV, INTERIM_DIR, SEED, CHUNK,
                             TII_BENIGN_TYPES, PREP_PER_CLASS)
from src.common import get_logger, banner, human, clean_block, Reservoir
from src.schema import normalise, NON_FEATURES

log = get_logger("02_tii")

# This script takes no options. Parsing anyway so that "--help" prints help
# and a mistyped flag is an error, rather than both being ignored and the
# job starting regardless -- which for a stage that rewrites an interim
# parquet at the end means a long accidental run.
argparse.ArgumentParser(
    description="Stream TII-SSRC-23 into one interim parquet. Takes no options.").parse_args()

if not TII_CSV.exists():
    log.error(f"Not found: {TII_CSV}")
    log.error("Place data.csv in data/raw/TII-SSRC-23/. See the guide.")
    sys.exit(1)

banner(log, "SCHEMA")
raw_cols = pd.read_csv(TII_CSV, nrows=0).columns.str.strip().tolist()
log.info(f"Columns in file: {len(raw_cols)}")

if "Traffic Type" not in raw_cols:
    log.error("'Traffic Type' column missing -- cannot derive benign labels.")
    log.error(f"Columns found: {raw_cols[:15]} ...")
    sys.exit(1)

# Drop identifiers at read time rather than after loading -- avoids carrying
# them across 8.65 million rows.
drop = [c for c in ("Flow ID", "Src IP", "Src Port", "Dst IP", "Timestamp")
        if c in raw_cols]
usecols = [c for c in raw_cols if c not in drop]
log.info(f"Dropping identifiers at read time: {drop}")
log.info(f"Reading {len(usecols)} columns")

# The feature list is fixed before a data row is read, so every chunk yields a
# matrix of the same width in the same order.
FEATURES = sorted(set(normalise(pd.DataFrame(columns=usecols)).columns)
                  - NON_FEATURES)
log.info(f"Feature columns: {len(FEATURES)}")

# --------------------------------------------------------------------------
banner(log, "LOADING")
log.info(f"Keeping every benign row; reservoir-sampling up to "
         f"{human(PREP_PER_CLASS)} attack rows (seed {SEED}).")

pool = {0: Reservoir(PREP_PER_CLASS, len(FEATURES), SEED, tags=True),
        1: Reservoir(PREP_PER_CLASS, len(FEATURES), SEED + 1, tags=True)}
total = junk = 0
type_counts = {}

for i, chunk in enumerate(pd.read_csv(TII_CSV, usecols=usecols,
                                      chunksize=CHUNK, low_memory=False)):
    total += len(chunk)
    chunk.columns = [c.strip() for c in chunk.columns]

    for t, n in chunk["Traffic Type"].value_counts().items():
        type_counts[t] = type_counts.get(t, 0) + int(n)

    chunk = normalise(chunk)
    types = chunk["Traffic Type"].astype(str).to_numpy()
    block, keep = clean_block(chunk, FEATURES)
    junk += int((~keep).sum())
    types = types[keep]
    if not len(block):
        continue

    is_benign = np.isin(types, TII_BENIGN_TYPES)
    for cls, mask in ((0, is_benign), (1, ~is_benign)):
        if mask.any():
            pool[cls].add(block[mask], types[mask])

    if i % 10 == 0:
        log.info(f"  chunk {i:>3}  rows so far {human(total):>12}")
    del chunk
    gc.collect()

if junk:
    log.warning(f"Dropped {human(junk)} rows in which no column parsed as a "
                f"number (embedded header lines).")

benign = pd.DataFrame(pool[0].rows, columns=FEATURES)
benign["Traffic Type"] = pool[0].tags
attack = pd.DataFrame(pool[1].rows, columns=FEATURES)
attack["Traffic Type"] = pool[1].tags
benign["binary_label"] = np.int8(0)
attack["binary_label"] = np.int8(1)

# --------------------------------------------------------------------------
banner(log, "TRAFFIC TYPE BREAKDOWN (full file)")
for t, n in sorted(type_counts.items(), key=lambda kv: -kv[1]):
    tag = "BENIGN" if t in TII_BENIGN_TYPES else "attack"
    log.info(f"  {t:<24} {human(n):>12}  [{tag}]")

n_benign_total = sum(v for k, v in type_counts.items()
                     if k in TII_BENIGN_TYPES)
log.info(f"\nRows scanned          : {human(total)}")
log.info(f"Benign in full file   : {human(n_benign_total)} "
         f"({n_benign_total/max(1,total)*100:.3f}%)")
log.info(f"Benign rows kept      : {human(len(benign))}")
log.info(f"Attack rows sampled   : {human(len(attack))}")

log.warning("")
log.warning("This dataset cannot support binary training on its own -- the "
            "benign class is roughly 0.015% of it. CICIDS2018 supplies the "
            "benign side; script 04 combines them.")

df = pd.concat([benign, attack], ignore_index=True)
df["source_dataset"] = "TII-SSRC-23"
df["folder_class"] = df["Traffic Type"]
df = df.drop(columns=[c for c in ("Label", "Traffic Type", "Traffic Subtype")
                      if c in df.columns])

feats = sorted(set(df.columns) - NON_FEATURES)
log.info(f"\nFeature columns: {len(feats)}")

out = INTERIM_DIR / "tii_ssrc_23.parquet"
df.to_parquet(out)
log.info(f"Saved -> {out}  ({out.stat().st_size/1e6:.0f} MB)")

banner(log, "NEXT")
log.info("python scripts/03_prepare_trustlab.py")
