"""
00_verify_environment.py
------------------------
Run this FIRST. Nothing downstream will work if it reports failures.

WHAT IT CHECKS
  1. Every required package is installed, with its version
  2. Whether GPU acceleration is actually usable (not just present)
  3. All three datasets are where the configuration expects them
  4. Each dataset's schema, and whether the intersection is large enough
  5. Whether your own CICFlowMeter emits the same convention (optional)

The schema check matters most. "CICFlowMeter V4" is not one fixed thing --
the tool has changed repeatedly, and TRUSTLab's paper claims v4.0 while its
files use v3-style abbreviated names. Assuming compatibility rather than
verifying it is how silent data corruption happens.

Usage:  python scripts/00_verify_environment.py
"""
import sys
import glob
import platform
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config.settings import (CICIDS_DIR, TII_CSV, TRUSTLAB_DIR,
                             CICFLOW_SAMPLE, USE_GPU, PROJECT_ROOT)
from src.common import get_logger, banner
from src.schema import to_v4, NON_FEATURES, ABSENT_FROM_TRUSTLAB
from src.trustlab_io import class_sources, read_header

log = get_logger("00_verify")
problems = []

REQUIRED = ["pandas", "numpy", "sklearn", "pyarrow", "joblib",
            "torch", "xgboost", "matplotlib"]

# --------------------------------------------------------------------------
banner(log, "SYSTEM")
log.info(f"Python   {platform.python_version()}")
log.info(f"Platform {platform.platform()}")
import os
log.info(f"CPU cores {os.cpu_count()}")
try:
    import psutil
    log.info(f"RAM      {psutil.virtual_memory().total/1e9:.1f} GB")
except ImportError:
    log.info("RAM      (install psutil to report)")

# --------------------------------------------------------------------------
banner(log, "PACKAGES")
for pkg in REQUIRED:
    try:
        mod = __import__(pkg)
        log.info(f"  OK    {pkg:<12} {getattr(mod, '__version__', 'unknown')}")
    except ImportError:
        log.error(f"  MISS  {pkg}")
        problems.append(f"package '{pkg}' not installed")

# --------------------------------------------------------------------------
banner(log, "GPU")
if USE_GPU:
    try:
        import torch
        if torch.cuda.is_available():
            log.info(f"  CUDA available: {torch.cuda.get_device_name(0)}")
            log.info(f"  VRAM: {torch.cuda.get_device_properties(0).total_memory/1e9:.1f} GB")
            log.info(f"  torch {torch.__version__}, CUDA {torch.version.cuda}")
        else:
            log.warning("  torch installed but CUDA unavailable -- training "
                        "will run on CPU. This works but is much slower for "
                        "the deep models. Set USE_GPU=False to silence this.")
    except ImportError:
        problems.append("torch not installed")

    try:
        import xgboost as xgb, numpy as np
        d = xgb.DMatrix(np.random.rand(40, 4), label=np.random.randint(0, 2, 40))
        xgb.train({"device": "cuda", "tree_method": "hist"}, d, num_boost_round=2)
        log.info("  XGBoost GPU: OK")
    except Exception as e:
        log.warning(f"  XGBoost GPU unavailable ({str(e)[:80]})")
        log.warning("  -> set USE_GPU=False in config/settings.py if this persists")
else:
    log.info("  USE_GPU is False; everything runs on CPU")

# --------------------------------------------------------------------------
banner(log, "DATASETS")
schemas = {}

# ---- CICIDS2018 ----
cic_files = sorted(glob.glob(str(CICIDS_DIR / "*.csv")))
if not cic_files:
    log.error(f"  CICIDS2018: no CSV files in {CICIDS_DIR}")
    problems.append("CICIDS2018 missing")
else:
    total = sum(Path(f).stat().st_size for f in cic_files) / 1e9
    log.info(f"  CICIDS2018   {len(cic_files)} files, {total:.2f} GB")
    import pandas as pd
    heads = {}
    for f in cic_files:
        h = tuple(pd.read_csv(f, nrows=0).columns.str.strip())
        heads.setdefault(h, []).append(Path(f).name)
    log.info(f"    distinct headers: {len(heads)}")
    for h, names in heads.items():
        log.info(f"      {len(h)} cols -> {len(names)} file(s)")
        if len(heads) > 1:
            log.info(f"        {names}")
    if len(heads) > 1:
        log.warning("    Files disagree on columns. Script 01 uses the "
                    "intersection; check the report it prints.")
    schemas["CICIDS2018"] = set(to_v4(max(heads, key=len))) - NON_FEATURES

# ---- TII-SSRC-23 ----
if not TII_CSV.exists():
    log.error(f"  TII-SSRC-23: not found at {TII_CSV}")
    problems.append("TII-SSRC-23 missing")
else:
    import pandas as pd
    size = TII_CSV.stat().st_size / 1e9
    cols = pd.read_csv(TII_CSV, nrows=0).columns.str.strip().tolist()
    log.info(f"  TII-SSRC-23  {size:.2f} GB, {len(cols)} columns")
    if "Traffic Type" not in cols:
        log.error("    'Traffic Type' column absent -- benign labels cannot "
                  "be derived")
        problems.append("TII-SSRC-23 missing 'Traffic Type'")
    schemas["TII-SSRC-23"] = set(to_v4(cols)) - NON_FEATURES

# ---- TRUSTLab ----
# Discovery goes through src/trustlab_io so this check sees exactly what
# script 03 will see -- split archives read in place, no manual join step.
tl_sources, tl_problems, tl_notes = ({}, [], [])
if TRUSTLAB_DIR.exists():
    tl_sources, tl_problems, tl_notes = class_sources(TRUSTLAB_DIR)
for n in tl_notes:
    log.info(f"  TRUSTLab: {n}")
for pr in tl_problems:
    log.error(f"  TRUSTLab: {pr}")
    problems.append(f"TRUSTLab {pr}")

if not tl_sources:
    log.error(f"  TRUSTLab: no class files found under {TRUSTLAB_DIR}")
    problems.append("TRUSTLab missing")
else:
    import pandas as pd
    n_split = sum(1 for v in tl_sources.values() if len(v) > 1)
    log.info(f"  TRUSTLab     {len(tl_sources)} class files"
             + (f" ({n_split} stored as split archives, read in place)"
                if n_split else ""))
    if len(tl_sources) < 16:
        log.warning(f"    expected 16, found {len(tl_sources)}")
    variants, bad = {}, []
    for cls, paths in tl_sources.items():
        try:
            h = tuple(sorted(set(to_v4(read_header(paths)))))
            variants.setdefault(h, []).append(cls)
        except Exception as e:
            bad.append((cls, str(e)[:60]))
    log.info(f"    distinct schemas after V4 mapping: {len(variants)}")
    for i, (h, members) in enumerate(variants.items(), 1):
        log.info(f"      schema {i}: {len(h)} cols -> {members}")
    if bad:
        for cls, err in bad:
            log.warning(f"    {cls}: unreadable ({err})")
        log.warning("    Truncated files still yield most of their rows; "
                    "script 03 handles this, but re-downloading is cleaner.")
    if variants:
        schemas["TRUSTLab"] = set.intersection(
            *[set(h) for h in variants]) - NON_FEATURES

# --------------------------------------------------------------------------
banner(log, "SCHEMA INTERSECTION")
if len(schemas) == 3:
    for k, v in schemas.items():
        log.info(f"  {k:<14} {len(v)} features")
    shared = set.intersection(*schemas.values())
    log.info(f"\n  SHARED ACROSS ALL THREE: {len(shared)}")

    for k, v in schemas.items():
        lost = sorted(v - shared)
        if lost:
            log.info(f"\n  Dropped from {k} ({len(lost)}):")
            for f in lost:
                note = "  <- not exported by TRUSTLab" \
                    if f in ABSENT_FROM_TRUSTLAB else ""
                log.info(f"      {f}{note}")

    if len(shared) < 40:
        log.error(f"\n  Only {len(shared)} shared features. Too few -- a "
                  f"rename is probably missing from src/schema.py.")
        problems.append("shared feature count below 40")
    else:
        log.info(f"\n  {len(shared)} features is workable.")
else:
    log.warning("  Cannot compute -- not all datasets loaded")

# --------------------------------------------------------------------------
banner(log, "YOUR CICFLOWMETER (optional)")
if CICFLOW_SAMPLE.exists():
    import pandas as pd
    cols = pd.read_csv(CICFLOW_SAMPLE, nrows=0).columns.str.strip().tolist()
    log.info(f"  Sample has {len(cols)} columns")
    v3 = len({"Tot Fwd Pkts", "Flow Byts/s", "FIN Flag Cnt"} & set(cols))
    v4 = len({"Total Fwd Packet", "Flow Bytes/s", "FIN Flag Count"} & set(cols))
    log.info(f"  V3 markers {v3}/3, V4 markers {v4}/3")
    if "shared" in dir():
        emitted = set(to_v4(cols)) - NON_FEATURES
        miss = sorted(shared - emitted)
        if miss:
            log.warning(f"  Model would need these, but your tool does not "
                        f"emit them: {miss}")
            log.warning("  -> the trained model could not be deployed as-is")
        else:
            log.info("  Your tool emits every feature the model will use.")
else:
    log.info(f"  No sample at {CICFLOW_SAMPLE} -- skipping.")
    log.info("  To check deployment compatibility, generate one:")
    log.info("      sudo tcpdump -i any -w test.pcap -c 500")
    log.info("      cicflowmeter -f test.pcap -c cicflowmeter_sample.csv")
    log.info(f"  and place it at {CICFLOW_SAMPLE}")

# --------------------------------------------------------------------------
banner(log, "RESULT")
if problems:
    log.error(f"{len(problems)} problem(s):")
    for p in problems:
        log.error(f"  - {p}")
    sys.exit(1)
log.info("All checks passed.")
log.info("Next: python scripts/01_prepare_cicids2018.py")
