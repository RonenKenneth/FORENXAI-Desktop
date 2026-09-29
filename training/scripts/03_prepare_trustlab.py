"""
03_prepare_trustlab.py
----------------------
Loads TRUSTLab's sixteen per-class files into one interim table.

TRUSTLab feeds two experiments, and they use it differently:

  binary (04-07)   TRUSTLab is the external test set and is never trained on,
                   so performance on it measures genuine transfer to an unseen
                   capture environment rather than memorisation.
  multiclass       Training and evaluation both happen inside TRUSTLab,
  (08-11)          because six of its classes have no counterpart in the other
                   two datasets.

FIVE PROBLEMS WITH THESE FILES

  1. THREE INTERNAL SCHEMAS. The sixteen files use three different layouts:
       A (79 cols)  eleven attack files, uses "CWR Flag Cnt"
       B (79 cols)  DDoS, DoS, PortScan, Slowloris -- uses "CWE Flag Count"
                    AND orders bulk/header columns differently at positions
                    57-64
       C (81 cols)  Benign only -- has BOTH "CWE Flag Count" and an appended
                    duplicate "CWR Flag Cnt", plus a "Source File" column
     Because schemas A and B share column NAMES but not POSITIONS, loading by
     index would put backward bulk-byte values into a forward bulk-packet
     column and raise no error. Everything here selects by name.

  2. THE CWE/CWR TYPO. The real TCP flag is CWR (Congestion Window Reduced);
     CWE is unrelated. Both spellings fold to "CWR Flag Count", and the
     duplicate that creates in the Benign file is dropped.

  3. SPLIT ARCHIVES, and 4. A TRUNCATED PORTSCAN ARCHIVE. Both are handled by
     src/trustlab_io.py -- see its header for what they are and why each one
     fails silently rather than loudly.

  5. THE LABEL COLUMN RESTATES THE FOLDER, INCONSISTENTLY CASED. Every file
     carries a Label column holding one value, which is its folder name in
     arbitrary case -- "benign", "ddos", "API", "portscan". It adds nothing
     the folder does not already say, and folding its casing would be one more
     place for a class name to drift, so the folder is the authority and the
     column is dropped with the other non-features.

HOW MUCH OF EACH CLASS IS KEPT
Per class, whichever cap is larger: TRUSTLAB_PER_CLASS for the binary test
set, or MC_BENIGN_CAP / MC_PER_CLASS for the multiclass experiment. Script 04
caps back down to TRUSTLAB_PER_CLASS for its own test set, so the binary study
is unaffected by the larger draw. See the note above TRUSTLAB_PER_CLASS in
config/settings.py.

SAMPLING, AND WHY ORDER IS PRESERVED
Each class is reservoir-sampled across the whole file rather than truncated to
its first N rows. Benign is 2,572,388 rows spanning eight capture sessions, so
a head-cap would draw a sample whose session mix is not the class's -- and
benign recall is the headline number of script 06.

The sample is then restored to capture order before it is written. Scripts 08
and 11 build a TEMPORAL split by taking the first 80% of each class for
training and the last 20% for test, to separate capture sessions. That is only
meaningful if the rows are still in the order they were captured; a sample
left in reservoir-slot order would turn the temporal split into a second
random split, and script 11 would then report "no session artifacts" for the
wrong reason.

One full pass over all sixteen classes costs about two minutes, and the draw
is seeded, so it is reproducible.

Usage:  python scripts/03_prepare_trustlab.py
"""
import sys
import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config.settings import (TRUSTLAB_DIR, INTERIM_DIR, ARTIFACTS_DIR,
                             SEED, CHUNK,
                             TRUSTLAB_PER_CLASS, MC_PER_CLASS, MC_BENIGN_CAP,
                             TRUSTLAB_PUBLISHED_TOTALS)
from src.common import get_logger, banner, human, clean_block, Reservoir
from src.schema import normalise, NON_FEATURES
from src.trustlab_io import (open_class, class_sources, read_header,
                             TRUNCATION_ERRORS)

log = get_logger("03_trustlab")

# This script takes no options. Parsing anyway so that "--help" prints help
# and a mistyped flag is an error, rather than both being ignored and the
# job starting regardless -- which for a stage that rewrites an interim
# parquet at the end means a long accidental run.
argparse.ArgumentParser(
    description="Read the sixteen TRUSTLab class archives into one interim parquet. Takes no options.").parse_args()


def cap_for(cls):
    """Rows to keep for one class -- the largest any downstream script asks for."""
    if cls.lower() == "benign":
        return max(TRUSTLAB_PER_CLASS, MC_BENIGN_CAP)
    return max(TRUSTLAB_PER_CLASS, MC_PER_CLASS)


def load_class(paths, cols, cap):
    """Reservoir-sample up to `cap` rows from one class, in one pass.

    Returns (rows, n_seen, n_junk, truncated), with rows back in capture order.
    """
    res = Reservoir(cap, len(cols), SEED)
    junk = 0
    stream, gunzip = open_class(paths)
    try:
        for chunk in pd.read_csv(stream, chunksize=CHUNK, low_memory=False):
            chunk.columns = [c.strip() for c in chunk.columns]
            chunk = normalise(chunk)
            block, keep = clean_block(chunk, cols)
            junk += int((~keep).sum())
            res.add(block)
    except TRUNCATION_ERRORS as e:
        # _TolerantGunzip normally absorbs these; this catches anything that
        # gets past it, e.g. damage in a plain .csv path.
        log.warning(f"    read ended early ({type(e).__name__}: {e})")
        rows, _ = res.rows_in_order()
        return rows, res.seen, junk, True
    finally:
        stream.close()

    rows, _ = res.rows_in_order()
    return rows, res.seen, junk, bool(gunzip is not None and gunzip.truncated)


# ==========================================================================
banner(log, "DISCOVERY")
if not TRUSTLAB_DIR.exists():
    log.error(f"Not found: {TRUSTLAB_DIR}")
    sys.exit(1)

sources, problems, notes = class_sources(TRUSTLAB_DIR)
for n in notes:
    log.info(f"  {n}")
for p in problems:
    log.error(f"  {p}")

if not sources:
    log.error(f"No readable class files under {TRUSTLAB_DIR}")
    log.error("Expected one folder per class, each holding NAME.csv.gz or "
              "NAME.csv.gz.001, .002, ...")
    sys.exit(1)

for cls, paths in sources.items():
    shape = (paths[0].name if len(paths) == 1
             else f"{paths[0].name} + {len(paths) - 1} more parts")
    log.info(f"  {cls:<16} {shape}")

log.info(f"\nFound {len(sources)} class files")
if len(sources) < 16:
    log.warning(f"Expected 16 classes, found {len(sources)}. Missing classes "
                f"reduce coverage of the binary validation set and cannot be "
                f"evaluated at all in the multiclass experiment.")

# --------------------------------------------------------------------------
banner(log, "SCHEMA SURVEY")
variants = {}
for cls, paths in sources.items():
    raw = read_header(paths)
    mapped = tuple(sorted(set(normalise(pd.DataFrame(columns=raw)).columns)))
    variants.setdefault(mapped, []).append((cls, len(raw)))

log.info(f"Distinct schemas after V4 normalisation: {len(variants)}")
for i, (cols, members) in enumerate(variants.items(), 1):
    log.info(f"\n  Schema {i}: {len(cols)} columns")
    for cls, n in members:
        log.info(f"      {cls:<16} (raw file: {n} cols)")

common = set.intersection(*[set(c) for c in variants])
log.info(f"\nColumns common to every file: {len(common)}")
partial = set().union(*[set(c) for c in variants]) - common
if partial:
    log.warning(f"Present in only some files, excluded: {sorted(partial)}")

# Identifiers are dropped here rather than after loading: they are text, they
# are not features, and carrying them through the reservoir costs memory for
# nothing. See NON_FEATURES in src/schema.py for why each one goes.
FEATURES = sorted(common - NON_FEATURES)
log.info(f"Dropped as identifiers/labels: {sorted(common & NON_FEATURES)}")
log.info(f"Feature columns: {len(FEATURES)}")
if not FEATURES:
    log.error("No feature columns survive the intersection -- check that the "
              "class folders really hold CICFlowMeter output.")
    sys.exit(1)

# --------------------------------------------------------------------------
banner(log, "LOADING")
log.info(f"Per-class cap: {human(max(TRUSTLAB_PER_CLASS, MC_PER_CLASS))} "
         f"attack, {human(max(TRUSTLAB_PER_CLASS, MC_BENIGN_CAP))} benign")
log.info(f"Reservoir-sampled over the whole file, then restored to capture "
         f"order (seed {SEED})")

collected, truncated, native = [], [], {}
for cls, paths in sources.items():
    rows, seen, junk, was_truncated = load_class(paths, FEATURES, cap_for(cls))
    native[cls] = seen

    if was_truncated:
        truncated.append(cls)
        log.warning(f"  {cls:<16} archive truncated -- recovered "
                    f"{human(seen)} rows before the break")
    if junk:
        log.warning(f"  {cls:<16} dropped {human(junk)} unparseable rows "
                    f"(embedded header lines)")
    if not len(rows):
        log.warning(f"  {cls:<16} no rows read, skipped")
        continue

    d = pd.DataFrame(rows, columns=FEATURES)
    d["folder_class"] = cls
    d["binary_label"] = np.int8(0 if cls.lower() == "benign" else 1)
    d["source_dataset"] = "TRUSTLab"
    collected.append(d)
    log.info(f"  {cls:<16} {human(len(d)):>10} kept "
             f"from {human(seen):>10} rows")

if not collected:
    log.error("Every class failed to load. Nothing to write.")
    sys.exit(1)

data = pd.concat(collected, ignore_index=True)
del collected

# --------------------------------------------------------------------------
banner(log, "INTERIM TABLE")
log.info(f"Total rows: {human(len(data))}")
log.info("\nBy class (kept / available in file):")
for c in sorted(native, key=lambda k: -native[k]):
    got = int((data["folder_class"] == c).sum())
    log.info(f"  {c:<16} {human(got):>10} / {human(native[c]):>12}")

nb = int((data["binary_label"] == 0).sum())
na = int((data["binary_label"] == 1).sum())
log.info(f"\nKept:       benign {human(nb)}   attack {human(na)}   "
         f"ratio {nb/max(1,na):.2f}:1")

fb = native.get("Benign", 0)
fa = sum(v for k, v in native.items() if k.lower() != "benign")
log.info(f"Full files: benign {human(fb)}   attack {human(fa)}   "
         f"ratio {fb/max(1,fa):.2f}:1")
log.warning("TRUSTLab's native ratio is about 1.3:1 benign-to-attack. Every "
            "class was capped, so the kept ratio differs. Script 04 caps "
            "again for the binary test set and reports its own figures; note "
            "the difference when comparing against the published baseline, "
            "which used the full distribution.")

# --------------------------------------------------------------------------
banner(log, "DOWNLOAD RECONCILIATION")
pub_b = TRUSTLAB_PUBLISHED_TOTALS["benign"]
pub_a = TRUSTLAB_PUBLISHED_TOTALS["attack"]
log.info(f"Against the totals published for the corpus:")
log.info(f"  benign   read {human(fb):>12}   published {human(pub_b):>12}   "
         f"{'exact match' if fb == pub_b else f'differs by {fb - pub_b:+,}'}")
log.info(f"  attack   read {human(fa):>12}   published {human(pub_a):>12}   "
         f"{'exact match' if fa == pub_a else f'differs by {fa - pub_a:+,}'}")
log.info(f"  {TRUSTLAB_PUBLISHED_TOTALS['source']}")

short = pub_a - fa
if truncated:
    log.warning(f"\nTruncated archives: {truncated}")
    if short > 0 and len(truncated) == 1:
        cls = truncated[0]
        got = native.get(cls, 0)
        true_n = got + short
        log.warning(
            f"Every other archive decompressed to its end, so the whole "
            f"{human(short)}-row shortfall belongs to {cls}: about "
            f"{human(true_n)} rows exist, {human(got)} were downloaded "
            f"({got / max(1, true_n) * 100:.1f}%).")
    elif short > 0:
        log.warning(f"{human(short)} rows short of the published attack "
                    f"total, spread across {truncated}.")
    log.warning(
        "Those bytes are not damaged, they were never downloaded, so no "
        "amount of decoding recovers them. What this costs is NOT sample "
        "size -- the per-class caps are still filled -- it is that the "
        "affected class is sampled from only the first part of its capture. "
        "The temporal split in scripts 08 and 11 is what that biases: its "
        "'late' rows for this class are mid-capture, not late.")
    log.warning(
        "To remove the limitation rather than record it, re-download the "
        "affected archive and re-run this script; the reconciliation above "
        "will then read 'exact match'. If you cannot, state the recovered "
        "percentage in the limitations and treat that class's temporal "
        "result as indicative only.")
elif short == 0 and fb == pub_b:
    log.info("\nEvery class is complete -- the corpus read here matches the "
             "published totals exactly.")

# Persist the per-class totals the full read just measured. Script 06 needs
# them to reweight its accuracy to TRUSTLab's real prevalence: the test set is
# capped to an equal number of rows per class, so it is 6% benign where the
# corpus is 57% benign, and an accuracy measured on the capped set is not
# comparable with a published figure measured on the real one. Writing them
# here rather than hardcoding a table keeps them correct if the data changes --
# re-download the truncated PortScan archive and this file updates itself.
counts_path = ARTIFACTS_DIR / "trustlab_native_counts.json"
with open(counts_path, "w", encoding="utf-8") as fh:
    json.dump({"counts": native,
               "total": int(sum(native.values())),
               # Which classes are short because their archive is truncated.
               # Script 06 reweights with and without these, so "the missing
               # rows do not change the conclusion" is a number it recomputes
               # every run rather than a claim in prose.
               "truncated": sorted(truncated),
               "note": ("rows present in each class archive, as read. Not the "
                        "number sampled into trustlab.parquet.")}, fh, indent=2)
log.info(f"Native class totals -> {counts_path}")

out = INTERIM_DIR / "trustlab.parquet"
data.to_parquet(out)
log.info(f"\nSaved -> {out}  ({out.stat().st_size/1e6:.0f} MB)")

banner(log, "NEXT")
log.info("python scripts/04_align_and_build.py")
