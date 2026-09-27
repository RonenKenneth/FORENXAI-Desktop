"""
01_prepare_cicids2018.py
------------------------
Loads the ten CICIDS2018 day-files, normalises them to V4 naming, and derives
the binary label.

WHY CICIDS2018 IS IN THIS STUDY
It supplies the benign traffic. TII-SSRC-23 has roughly 1,301 benign flows
against 8.65 million malicious -- far too few to teach a model what normal
traffic looks like. CICIDS2018 contributes about 13.4 million benign flows,
which brings the combined corpus to roughly 1.18:1 benign-to-attack,
close to TRUSTLab's native 1.3:1.

FOUR KNOWN PROBLEMS WITH THIS DATASET, ALL HANDLED HERE

  1. Header inconsistency across day-files. One file (02-20-2018.csv) carries
     four extra identifier columns the others omit -- Flow ID, Src IP, Dst IP
     and Src Port. The script uses the intersection and reports what was
     dropped. None of the four would have been a feature anyway.

  2. Corrupted header rows embedded in the data. 59 rows across three files
     (02-16, 02-28, 03-01) contain the literal string "Label" in the label
     column -- header lines pasted in as data. Beyond being wrong, they force
     every numeric column in those files to parse as text, so they have to go
     before anything else can be trusted.

  3. Infinity values in the rate columns. Flow Bytes/s and Flow Packets/s
     divide by flow duration; when duration is zero the result is infinite.
     These are replaced with zero rather than dropped, matching how a
     deployed system must handle them -- a forensic tool cannot discard flows
     an investigator may need to see.

  4. Size. The ten files total 16,233,002 rows; 02-20-2018.csv alone is 7.9
     million. Holding all of them as float32 and concatenating needs about
     10 GB at the join, and another copy again to write the parquet. So this
     script streams: it counts the complete label distribution from every row,
     but retains only PREP_PER_CLASS rows per binary class, drawn as a uniform
     random sample of the whole dataset rather than as the first N rows.
     Script 04 caps at TRAIN_PER_CLASS anyway, so nothing downstream sees a
     difference -- except that the pool it samples from is no longer biased
     towards the earliest capture days.

Also note CICIDS2018 uses "CWE Flag Count", which is a CICFlowMeter typo for
the CWR (Congestion Window Reduced) TCP flag. src/schema.py corrects it.

Usage:  python scripts/01_prepare_cicids2018.py
"""
import sys
import argparse
import glob
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config.settings import (CICIDS_DIR, INTERIM_DIR, SEED, CHUNK,
                             PREP_PER_CLASS)
from src.common import get_logger, banner, human, clean_block, Reservoir
from src.schema import normalise, NON_FEATURES

log = get_logger("01_cicids")

# This script takes no options. Parsing anyway so that "--help" prints help
# and a mistyped flag is an error, rather than both being ignored and the
# job starting regardless -- which for a stage that rewrites an interim
# parquet at the end means a long accidental run.
argparse.ArgumentParser(
    description="Stream the ten CSE-CIC-IDS2018 day files into one interim parquet. Takes no options.").parse_args()

files = sorted(glob.glob(str(CICIDS_DIR / "*.csv")))
if not files:
    log.error(f"No CSV files in {CICIDS_DIR}")
    log.error("Place the ten CICIDS2018 day-files there. See the guide.")
    sys.exit(1)

log.info(f"Found {len(files)} files")

# --------------------------------------------------------------------------
banner(log, "HEADER SURVEY")
headers = {}
for f in files:
    h = tuple(pd.read_csv(f, nrows=0).columns.str.strip())
    headers.setdefault(h, []).append(Path(f).name)

log.info(f"Distinct headers: {len(headers)}")
for i, (h, names) in enumerate(headers.items(), 1):
    log.info(f"  schema {i}: {len(h)} columns, {len(names)} file(s)")
    for n in names:
        log.info(f"      {n}")

common = set.intersection(*[set(h) for h in headers])
log.info(f"\nColumns common to every file: {len(common)}")
extra = set().union(*[set(h) for h in headers]) - common
if extra:
    log.warning(f"Present in some files only, will be dropped: {sorted(extra)}")

if "Label" not in common:
    log.error("No 'Label' column common to every file -- cannot label rows.")
    sys.exit(1)

# The feature list is fixed here, before a single data row is read, so that
# every chunk produces a matrix of the same width in the same order.
FEATURES = sorted(set(normalise(pd.DataFrame(columns=sorted(common))).columns)
                  - NON_FEATURES)
log.info(f"Feature columns: {len(FEATURES)}")

# --------------------------------------------------------------------------
banner(log, "LOADING")
log.info(f"Retaining {human(PREP_PER_CLASS)} rows per binary class, sampled "
         f"uniformly across all {len(files)} files (seed {SEED})")

# One reservoir per binary class, so the benign and attack pools are capped
# independently -- a shared cap would fill up with whichever class the early
# files happen to contain.
pool = {0: Reservoir(PREP_PER_CLASS, len(FEATURES), SEED, tags=True),
        1: Reservoir(PREP_PER_CLASS, len(FEATURES), SEED + 1, tags=True)}

label_counts = {}
total_raw = total_kept = total_junk = 0

for f in files:
    name = Path(f).name
    raw_here = kept_here = junk_here = 0

    for chunk in pd.read_csv(f, chunksize=CHUNK, low_memory=False):
        raw_here += len(chunk)
        chunk.columns = [c.strip() for c in chunk.columns]
        chunk = chunk[[c for c in chunk.columns if c in common]]

        labels = chunk["Label"].astype(str).str.strip()

        # Embedded header rows, dropped before anything reads the numbers.
        real = (labels != "Label").to_numpy()
        junk_here += int((~real).sum())
        chunk, labels = chunk[real], labels[real]
        if not len(chunk):
            continue

        chunk = normalise(chunk)
        block, keep = clean_block(chunk, FEATURES)
        junk_here += int((~keep).sum())
        labels = labels.to_numpy()[keep]
        if not len(block):
            continue

        for lab, n in pd.Series(labels).value_counts().items():
            label_counts[lab] = label_counts.get(lab, 0) + int(n)

        benign = np.char.lower(labels.astype(str)) == "benign"
        for cls, mask in ((0, benign), (1, ~benign)):
            if mask.any():
                pool[cls].add(block[mask], labels[mask])

        kept_here += len(block)

    total_raw += raw_here
    total_kept += kept_here
    total_junk += junk_here
    log.info(f"  {name:<20} {human(raw_here):>12} -> {human(kept_here):>12}"
             + (f"   ({junk_here} junk rows dropped)" if junk_here else ""))

log.info(f"\nTotal: {human(total_raw)} rows read, {human(total_kept)} usable, "
         f"{human(total_junk)} dropped as non-data "
         f"({total_junk/max(1,total_raw)*100:.4f}%)")

# --------------------------------------------------------------------------
banner(log, "BINARY LABEL")
log.info("Raw label values across the FULL dataset:")
for lab, n in sorted(label_counts.items(), key=lambda kv: -kv[1]):
    log.info(f"  {lab:<32} {human(n):>12}")

full_b = sum(n for lab, n in label_counts.items() if lab.lower() == "benign")
full_a = total_kept - full_b
log.info(f"\nFull dataset: benign {human(full_b)}   attack {human(full_a)}   "
         f"ratio {full_b/max(1,full_a):.2f}:1 benign-to-attack")

parts = []
for cls, res in pool.items():
    if not res.filled:
        continue
    d = pd.DataFrame(res.rows, columns=FEATURES)
    d["folder_class"] = res.tags
    d["binary_label"] = np.int8(cls)
    parts.append(d)

if not parts:
    log.error("No rows survived loading. Nothing to write.")
    sys.exit(1)

cic = pd.concat(parts, ignore_index=True)
del parts
cic["source_dataset"] = "CICIDS2018"

nb = int((cic["binary_label"] == 0).sum())
na = int((cic["binary_label"] == 1).sum())
log.info(f"Retained    : benign {human(nb)}   attack {human(na)}   "
         f"ratio {nb/max(1,na):.2f}:1")
log.info("The retained pool is capped per class, so its ratio is not the "
         "dataset's. The line above it is. Script 04 caps again and reports "
         "both.")

log.info("\nRetained attack families:")
for lab, n in cic.loc[cic["binary_label"] == 1, "folder_class"] \
                 .value_counts().items():
    log.info(f"  {lab:<32} {human(n):>12}")

out = INTERIM_DIR / "cicids2018.parquet"
cic.to_parquet(out)
log.info(f"\nSaved -> {out}  ({out.stat().st_size/1e6:.0f} MB)")

banner(log, "NEXT")
log.info("python scripts/02_prepare_tii.py")
