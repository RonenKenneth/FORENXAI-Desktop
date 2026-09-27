"""
Central configuration for the whole pipeline.

This is the ONLY file you should need to edit. Every script reads its paths
and settings from here, so nothing contains a hardcoded location.
"""
from pathlib import Path

# ==========================================================================
# PATHS
# Everything is relative to the project root, so the folder can be moved or
# renamed without breaking anything.
# ==========================================================================
PROJECT_ROOT = Path(__file__).resolve().parent.parent

RAW_DIR       = PROJECT_ROOT / "data" / "raw"
INTERIM_DIR   = PROJECT_ROOT / "data" / "interim"
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
ARTIFACTS_DIR = PROJECT_ROOT / "artifacts"
RESULTS_DIR   = PROJECT_ROOT / "results"
LOGS_DIR      = PROJECT_ROOT / "logs"

# Where each dataset lives. See the guide for what goes in each folder.
CICIDS_DIR   = RAW_DIR / "CICIDS2018"      # ten day CSV files
TII_CSV      = RAW_DIR / "TII-SSRC-23" / "data.csv"
TRUSTLAB_DIR = RAW_DIR / "TRUSTLab"        # sixteen per-class folders

# Optional: a sample from your own CICFlowMeter, used by script 00 to confirm
# the deployed tool emits the same schema the model will be trained on.
CICFLOW_SAMPLE = RAW_DIR / "cicflowmeter_sample.csv"

for _d in (INTERIM_DIR, PROCESSED_DIR, ARTIFACTS_DIR, RESULTS_DIR, LOGS_DIR):
    _d.mkdir(parents=True, exist_ok=True)

# ==========================================================================
# REPRODUCIBILITY
# Fixed seed everywhere. Re-running any script produces identical output.
# ==========================================================================
SEED = 42

# ==========================================================================
# THE EXPERIMENT
#
# Train on CICIDS2018 + TII-SSRC-23 combined, evaluate on TRUSTLab.
#
# Why combined rather than TII-SSRC-23 alone: TII-SSRC-23 contains only about
# 1,301 benign flows against 8.65 million malicious. A binary model trained on
# that learns to predict "attack" unconditionally. CICIDS2018 supplies
# 13.4 million benign flows, which brings the combined ratio to roughly 1.18:1
# benign-to-attack -- close to TRUSTLab's native 1.3:1.
#
# This also mirrors the protocol of the published baseline: Villafranca et al.
# trained their Phase-1 experts on four external datasets and transferred into
# TRUSTLab. Multi-source training is a closer replication of their setup than
# single-source would be.
# ==========================================================================

# Training arms. "combined" is the study; the other two are controls that
# reveal what each source contributes on its own.
TRAINING_ARMS = ["combined", "cicids_only", "tii_only"]
DEFAULT_ARM = "combined"

# Which binary detector script 12 puts in front of its Phase-2 stage. Named
# here rather than left to whichever model file sorts first, because that made
# the result depend on which models happened to exist: with only XGBoost
# trained it passed 27.5% of flows, and once an MLP existed it silently
# switched and passed 50.3%. A study decision belongs in the config, not in
# alphabetical order.
PHASE1_DETECTOR = "XGBoost"

# Rows sampled per class for the training set. Full data is ~24.8M rows, which
# is unnecessary for binary classification and slow to train on.
TRAIN_PER_CLASS = 400_000
VAL_FRACTION = 0.15          # carved out of training, for early stopping

# Rows scripts 01 and 02 retain per binary class while streaming the raw CSVs.
# The full sources are 16.2M rows (CICIDS2018) and 8.65M (TII-SSRC-23);
# concatenating either in memory as float32 needs about 10 GB at the join,
# which is more than most machines have spare, and buys nothing -- script 04
# caps at TRAIN_PER_CLASS regardless. The 2x headroom leaves script 04's own
# sampling something to choose from. Both loaders take a uniform random sample
# (src.common.Reservoir), not the first N rows, so the pool is representative
# of the whole file; the full label distribution is still counted and reported
# from the complete stream.
PREP_PER_CLASS = TRAIN_PER_CLASS * 2

# TII-SSRC-23 labels these four Traffic Types as benign. Confirmed by
# cross-tabulating Traffic Type against the binary Label column.
TII_BENIGN_TYPES = ["Video", "Text", "Audio", "Background"]

# ==========================================================================
# EXTERNAL VALIDATION
# ==========================================================================
# Row counts the TRUSTLab paper reports for the whole corpus. Script 03
# reconciles what it actually read against these, which is how an incomplete
# download gets caught and measured rather than guessed at. Benign matching
# to the row is what makes the attack-side shortfall attributable: if every
# archive but one passes a gzip integrity check, the whole difference belongs
# to that one.
TRUSTLAB_PUBLISHED_TOTALS = {
    "benign": 2_572_388,
    "attack": 1_992_871,
    "source": ("Villafranca, A., Tasic, I. & Cano, M.-D. (2026). TRUSTLab "
               "dataset. Frontiers in Computer Science 8:1803271."),
}

TRUSTLAB_PER_CLASS = 30_000  # cap per class file; 16 classes -> ~480k rows

# Script 03 writes ONE trustlab.parquet that two experiments read, and they
# want different amounts of it: the binary external test set takes
# TRUSTLAB_PER_CLASS per class, while the multiclass experiment takes
# MC_BENIGN_CAP / MC_PER_CLASS (defined below, and both larger). So 03 samples
# to whichever is bigger and script 04 caps back down to TRUSTLAB_PER_CLASS
# for its own test set. Sizing 03 to TRUSTLAB_PER_CLASS alone would silently
# starve script 08 -- every class would arrive already under its cap, the
# capping stage would report "kept whole" for all sixteen, and the multiclass
# experiment would quietly run on a third of the data it was configured for.

# The figure to compare against, from the TRUSTLab dataset paper.
TRUSTLAB_BASELINE = {
    "accuracy":        0.8963,
    "f2":              0.9350,
    "roc_auc":         0.9676,
    "attack_precision": 0.8802,
    "attack_recall":   0.9498,
    "benign_recall":   0.8229,
    "threshold":       0.445,
    "source": ("Villafranca, A., Tasic, I. & Cano, M.-D. (2026). TRUSTLab "
               "dataset. Frontiers in Computer Science 8:1803271, Table 2."),
    "protocol_note": (
        "Their Phase-1 detector used DNN experts pre-trained on CICIDS2017, "
        "UNSW-NB15, BoT-IoT and IoTID20, then transferred into TRUSTLab. "
        "This experiment uses the same protocol shape -- train elsewhere, "
        "test on TRUSTLab -- with different source datasets. That is what "
        "makes the comparison meaningful."),
}

# ==========================================================================
# MODELS
#
# Four deep architectures form the study. XGBoost is a non-deep control:
# TRUSTLab's own baseline used XGBoost, and without it there is no way to
# show the deep models are actually better. If it wins, that is a result.
# ==========================================================================
DL_MODELS = ["MLP", "CNN1D", "LSTM", "CNN_BiLSTM"]
CONTROL_MODELS = ["XGBoost"]
ALL_MODELS = DL_MODELS + CONTROL_MODELS

EPOCHS = 40
BATCH_SIZE = 512
LEARNING_RATE = 1e-3
EARLY_STOP_PATIENCE = 6

# ==========================================================================
# COMPUTE
# GPU accelerates the PyTorch models and XGBoost. Pandas and scikit-learn
# preprocessing are CPU-bound regardless.
# ==========================================================================
USE_GPU = True
CHUNK = 200_000              # rows per chunk when reading large CSVs


# ==========================================================================
# MULTICLASS EXPERIMENT (scripts 08-11)
#
# Trained and evaluated entirely within TRUSTLab. Cross-dataset multiclass is
# not possible: TRUSTLab has sixteen classes, six of which (API, MITM,
# Evasion, TLSSSL, Exfiltration, C2Beaconing) have no counterpart in either
# CICIDS2018 or TII-SSRC-23. A model predicting them on those datasets would
# be wrong by construction.
#
# The classes worth attention are the three the published baseline handles
# poorly: Slowloris (F1 0.68), DoS (0.74) and Exploitation (0.92). The other
# thirteen sit at 0.95 or above, so there is nothing to demonstrate on them.
# ==========================================================================

MC_PER_CLASS = 80_000        # cap per attack class
MC_BENIGN_CAP = 200_000      # Benign is ~2.57M; without a cap it dominates
MC_TEST_FRACTION = 0.20
MC_VAL_FRACTION = 0.15       # carved from the training portion

# Exact duplicate feature vectors are common in these datasets (about a quarter
# of the CSE-CIC-IDS2018 rows, one fifth of TRUSTLab's random test rows have a
# copy in training). A plain random split puts copies on both sides, so the
# held-out score partly measures memorisation. With this on, rows that share a
# feature vector are always assigned to the same side. Random splits only; the
# temporal split follows capture order and is left alone. Set False to
# reproduce the results produced before this was fixed.
LEAKAGE_SAFE_SPLITS = True

# Random stratified matches the published baseline's protocol and is directly
# comparable. Temporal is stricter: flows within each file are in capture
# order, so an early/late split separates different sessions and approximates
# the campaign-level split the TRUSTLab authors recommend but did not use.
MC_SPLIT_STRATEGY = "random"     # "random" or "temporal"

MC_EPOCHS = 50
MC_BATCH_SIZE = 512
MC_LEARNING_RATE = 1e-3
MC_EARLY_STOP_PATIENCE = 8

# Published per-class F1 from Villafranca et al. (2026), Table 3.
# IMPORTANT: these come from a Phase-2 refinement stage that only ever saw
# flows a Phase-1 detector had already flagged as malicious -- not from a
# standalone sixteen-class classifier. See the guide, section 2.
TRUSTLAB_MC_BASELINE = {
    "API":            {"precision": 1.00, "recall": 1.00, "f1": 1.00, "support": 41395},
    "Benign":         {"precision": 0.96, "recall": 0.94, "f1": 0.95, "support": 75515},
    "Bruteforce":     {"precision": 0.97, "recall": 0.98, "f1": 0.97, "support": 27444},
    "BufferOverflow": {"precision": 0.95, "recall": 0.98, "f1": 0.96, "support": 36019},
    "C2Beaconing":    {"precision": 1.00, "recall": 1.00, "f1": 1.00, "support": 34472},
    "DDoS":           {"precision": 0.99, "recall": 1.00, "f1": 1.00, "support": 56645},
    "DNS":            {"precision": 1.00, "recall": 1.00, "f1": 1.00, "support": 50429},
    "DoS":            {"precision": 0.77, "recall": 0.71, "f1": 0.74, "support": 44966},
    "Evasion":        {"precision": 1.00, "recall": 1.00, "f1": 1.00, "support": 25312},
    "Exfiltration":   {"precision": 1.00, "recall": 1.00, "f1": 1.00, "support": 32318},
    "Exploitation":   {"precision": 0.92, "recall": 0.92, "f1": 0.92, "support": 42838},
    "MITM":           {"precision": 1.00, "recall": 1.00, "f1": 1.00, "support": 31821},
    "PortScan":       {"precision": 1.00, "recall": 0.99, "f1": 0.99, "support": 41758},
    "Slowloris":      {"precision": 0.64, "recall": 0.71, "f1": 0.68, "support": 32635},
    "TLSSSL":         {"precision": 1.00, "recall": 1.00, "f1": 1.00, "support": 35073},
    "WebBased":       {"precision": 0.99, "recall": 0.99, "f1": 0.99, "support": 34719},
}

# The classes with real headroom. Everything else is already at 0.95+.
MC_HARD_CLASSES = ["Slowloris", "DoS", "Exploitation"]

# Confusions the authors documented, with their volumes. Worth checking
# whether they reproduce -- they occur on data with guaranteed clean labels,
# so they cannot be dismissed as annotation noise.
TRUSTLAB_KNOWN_CONFUSIONS = [
    ("Slowloris", "Benign", 9310, "quiet campaigns resemble slow legitimate connections"),
    ("DoS", "DDoS", 1306, "intermediate-rate vs high-rate flooding is threshold-dependent"),
    ("Exploitation", "WebBased", 870, "shared HTTP semantics"),
    ("Exploitation", "BufferOverflow", 142, "overlapping payload-size behaviour"),
]
