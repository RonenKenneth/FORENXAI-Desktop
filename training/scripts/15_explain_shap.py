"""
15_explain_shap.py
------------------
Attributes the multiclass model's decisions to individual features, and
packages everything a user interface needs into deploy/.

WHY THIS MODEL
artifacts/mc_random/XGBoost.pkl is the strongest classifier in the project
(accuracy 0.9313, macro F1 0.9267) AND a tree ensemble, so shap.TreeExplainer
computes EXACT Shapley values in minutes. The deep models would need
DeepExplainer -- far slower, approximate, and pointless when the tree model
already wins.

WHAT SHAP ANSWERS
predict_proba says "Slowloris, 0.81". SHAP says WHY: the flow lasted
unusually long (+0.31), packet gaps were wide (+0.22), byte count was low
(+0.14). Nothing is hand-waved, which is what makes an answer defensible in
a forensic report.

THE UNITS ARE LOG-ODDS, NOT PROBABILITY
This is the detail that gets misreported. For a softprob XGBoost model the
values sum to the raw MARGIN plus the base value, not to the probability:

    sv[row, :, k].sum() + expected_value[k] == model.predict(X, output_margin=True)[row, k]

Verified on this model to 9.4e-06. Against predict_proba the same sum is off
by more than 10. So a contribution of +2.49 means "pushed the log-odds score
up by 2.49", NOT "added 249% probability". An interface that labels these as
probability contributions is wrong, and wrong in a direction that flatters
the model: once a prediction is saturated, a large log-odds contribution
moves the probability barely at all.

Present them as relative evidence weights -- which feature mattered most,
and in which direction -- and never as percentage points.

WHICH TreeExplainer VARIANT, AND WHY
shap.TreeExplainer(model) with no background data runs
feature_perturbation="tree_path_dependent": the baseline is the training
distribution as recorded in the tree structure itself. The alternative,
interventional, needs a background sample and answers a subtly different
question about correlated features.

tree_path_dependent is chosen here deliberately: it is exact, needs no
background sample to ship in deploy/, and its baseline is the model's own
training distribution -- which is the right reference for "why did THIS
model say that". The cost is that heavily correlated features (and these are
heavily correlated -- packet length mean, max and std move together) split
credit along tree paths rather than by an interventional criterion. Say so
when reporting; do not claim a feature was unimportant because its
attribution was small.

SCALED INPUT, RAW DISPLAY
SHAP runs on the SAME scaled matrix the model was trained on; running it on
raw features would attribute a model that does not exist. The raw value is
carried alongside purely for display, because "Flow Duration 4.2 s" means
something to an investigator and "Flow Duration 3.87 (z-score)" does not.

SAMPLING
Exact TreeSHAP costs time per row per class. 400 trees x 16 classes over
280,000 test rows is hours for no extra insight, so global attributions are
computed on a stratified sample (--sample, default 8,000) and every output
records the sample size that produced it.

Usage:
  python scripts/15_explain_shap.py
  python scripts/15_explain_shap.py --sample 20000
  python scripts/15_explain_shap.py --strategy random --no-deploy
"""
import sys
import json
import shutil
import hashlib
import argparse
from pathlib import Path

import numpy as np
import pandas as pd
import joblib
import shap

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config.settings import ARTIFACTS_DIR, PROCESSED_DIR, RESULTS_DIR, SEED
from src.common import get_logger, banner, human, save_json, clean_features

log = get_logger("15_shap")

ap = argparse.ArgumentParser()
ap.add_argument("--strategy", choices=["random", "temporal"], default="random")
ap.add_argument("--sample", type=int, default=8000,
                help="rows for the global attribution estimate")
ap.add_argument("--show", type=int, default=6,
                help="features an interface displays per decision; only "
                     "affects the reported coverage share")
ap.add_argument("--top", type=int, default=12,
                help="features to record per class")
ap.add_argument("--deploy-dir", default="deploy",
                help="bundle folder under the project root (default: deploy)")
ap.add_argument("--no-deploy", action="store_true",
                help="skip writing the deploy/ bundle")
args = ap.parse_args()

PROJECT = Path(__file__).resolve().parent.parent
MODEL_DIR = ARTIFACTS_DIR / f"mc_{args.strategy}"
DEPLOY = PROJECT / args.deploy_dir

for f in ("XGBoost.pkl", "scaler.pkl", "features.pkl", "label_encoder.pkl"):
    if not (MODEL_DIR / f).exists():
        log.error(f"Missing {MODEL_DIR / f} -- run 09_train_multiclass.py "
                  f"--strategy {args.strategy} first.")
        sys.exit(1)

model = joblib.load(MODEL_DIR / "XGBoost.pkl")
scaler = joblib.load(MODEL_DIR / "scaler.pkl")
feats = list(joblib.load(MODEL_DIR / "features.pkl"))
le = joblib.load(MODEL_DIR / "label_encoder.pkl")
classes = [str(c) for c in le.classes_]

banner(log, f"SHAP -- mc_{args.strategy}/XGBoost")
log.info(f"Features {len(feats)}   classes {len(classes)}")

test = pd.read_parquet(PROCESSED_DIR / f"mc_test_{args.strategy}.parquet")
X_raw = clean_features(test, feats).values
X = scaler.transform(X_raw)                    # the space the model lives in
y = le.transform(test["folder_class"].values)
log.info(f"Test rows {human(len(y))}")

# Stratified sample: every class contributes proportionally, so no class is
# ever absent from the global estimate.
rng = np.random.default_rng(SEED)
per = max(1, args.sample // len(classes))
idx = np.concatenate([rng.choice(np.flatnonzero(y == k),
                                 size=min(per, int((y == k).sum())),
                                 replace=False)
                      for k in range(len(classes))])
rng.shuffle(idx)
log.info(f"Global estimate on {human(len(idx))} stratified rows "
         f"(~{per:,} per class)")

# tree_path_dependent -- see the header. Passing `data=` here would switch
# to the interventional estimator and require shipping a background sample.
explainer = shap.TreeExplainer(model)
# shap.TreeExplainer delegates to the booster, so the attribution runs on
# whatever device the booster carries -- and a model trained with
# device="cuda" keeps that setting through joblib. It is therefore the GPU
# here, not the CPU, and the difference is not cosmetic: 2.8 s against 71.6 s
# for 8,000 rows, about 26x, which on the full 280,063-row test set is three
# minutes against eighty-four. Logged rather than assumed, because the device
# is inherited silently and nothing else in this script would reveal it.
_dev = model.get_params().get("device", "cpu")
log.info(f"Explainer: feature_perturbation="
         f"{getattr(explainer, 'feature_perturbation', 'unknown')}   "
         f"attribution device={_dev}")
if _dev != "cuda":
    log.warning(f"  Attribution is running on {_dev}. TreeSHAP is about 26x "
                f"slower there; this is correct but slow.")
log.info("Computing exact TreeSHAP values...")
sv = explainer.shap_values(X[idx])

# shap returns (n, n_features, n_classes) on current versions and a list of
# per-class arrays on older ones. Normalise to the 3-D form so the rest of
# this script does not care which is installed.
if isinstance(sv, list):
    sv = np.stack(sv, axis=-1)
log.info(f"SHAP array {sv.shape}   (rows, features, classes)")
assert sv.shape[1] == len(feats) and sv.shape[2] == len(classes), \
    "SHAP array does not match the feature/class counts"

base = np.atleast_1d(np.asarray(explainer.expected_value, dtype=float))

# Additivity, checked rather than asserted. If this ever fails the values are
# not explaining this model and nothing downstream should be trusted.
_margin = model.predict(X[idx[:200]], output_margin=True)
_recon = sv[:200].sum(1) + base
_err = float(np.abs(_recon - _margin).max())
# The same check over the whole sample, not just the first 200 rows. The
# 200-row version is the cheap guard; the full one is what the write-up
# quotes, and quoting a number the script does not compute is how a
# verification table stops verifying anything.
_margin_all = model.predict(X[idx], output_margin=True)
_recon_all = sv.sum(1) + base
_err_all = float(np.abs(_recon_all - _margin_all).max())
log.info(f"Additivity check: max |sum(shap)+base - margin| = {_err:.2e} "
         f"on 200 rows, {_err_all:.2e} on all {len(idx):,}")
if _err > 1e-3:
    log.error("SHAP values do not reconstruct the model margin. Do not use "
              "these attributions.")
    sys.exit(1)

# Stronger than additivity: the reconstruction must pick the SAME class the
# model predicts. Values can sum correctly and still be sliced against the
# wrong class axis -- an off-by-one there produces attributions that look
# entirely reasonable and explain a decision that was never made.
_agree = float((_recon.argmax(1) == model.predict(X[idx[:200]])).mean())
_agree_all = float((_recon_all.argmax(1) == model.predict(X[idx])).mean())
log.info(f"Decision check  : argmax(reconstruction) == predict() = "
         f"{_agree:.4f} on 200 rows, {_agree_all:.4f} on all {len(idx):,}")
if _agree < 1.0:
    log.error("The reconstruction does not select the predicted class. The "
              "class axis is misaligned; these attributions explain a "
              "different decision than the model made.")
    sys.exit(1)
log.info("Units are LOG-ODDS (margin), not probability. An interface must "
         "not label these as percentage points.")

# Missingness: a feature never used as a split point must carry exactly zero
# attribution. An explainer that assigns influence to an unused feature is
# inventing the model's reasoning rather than recovering it.
_split = model.get_booster().get_score(importance_type="weight")
_used = {int(k[1:]) if k.startswith("f") and k[1:].isdigit() else feats.index(k)
         for k in _split}
_unused = [feats[i] for i in range(len(feats)) if i not in _used]
_worst = max((float(np.abs(sv[:, feats.index(f), :]).max()) for f in _unused),
             default=0.0)
log.info(f"Missingness     : {len(_unused)} of {len(feats)} features never "
         f"split on; max |SHAP| among them = {_worst:.1e}")
if _worst > 0:
    log.error("An unused feature carries non-zero attribution.")
    sys.exit(1)

# Coverage: the share of each decision's attribution mass carried by the
# features an interface actually shows. Quoted so a reader knows how much of
# the explanation the displayed rows account for.
_pred_cls = _recon_all.argmax(1)
_per_row = np.abs(sv[np.arange(len(idx)), :, _pred_cls])
_shown = float(np.sort(_per_row, axis=1)[:, ::-1][:, :args.show].sum()
               / _per_row.sum())
log.info(f"Coverage        : top {args.show} features carry "
         f"{_shown:.4f} of each decision's attribution mass")

# --------------------------------------------------------------------------
banner(log, "GLOBAL ATTRIBUTION -- what drives each class")
# TWO aggregations, because they answer different questions and only one of
# them is what a reader assumes.
#
#   per_class      mean |SHAP| for class k over EVERY sampled row. Fifteen of
#                  the sixteen classes in that sample are not k, so this is
#                  dominated by evidence for ruling k OUT. It is the right
#                  input to the pair matrix below -- that compares which
#                  features each class's score responds to, across all
#                  traffic -- and it is the wrong thing to print under the
#                  heading "what drives DoS".
#
#   per_class_own  the same average restricted to rows whose true class IS k.
#                  This is "what pushed these flows to this class", which is
#                  what the interface shows and what the write-up means.
#
# The magnitudes rank almost identically (Spearman 0.86-0.99 across the
# sixteen classes) so the pair matrix is unaffected, but the SIGN does not:
# the leading feature's mean signed value is negative for all sixteen classes
# under per_class and positive for all sixteen under per_class_own. Printing
# the first as though it were the second reads as "this feature argues
# against the class" about a feature that in fact identifies it.
# scripts/check_shap_aggregation.py reproduces the comparison.
_ys = y[idx]


def _profile(k, rows=None):
    """Top-`args.top` features for class k, over `rows` (all rows if None)."""
    a = sv if rows is None else sv[rows]
    mean_abs = np.abs(a[:, :, k]).mean(0)
    order = mean_abs.argsort()[::-1][:args.top]
    return order, [{"feature": feats[i],
                    "mean_abs_shap": round(float(mean_abs[i]), 6),
                    "mean_signed_shap": round(float(a[:, i, k].mean()), 6)}
                   for i in order]


global_top, own_top = {}, {}
for k, cls in enumerate(classes):
    order, global_top[cls] = _profile(k)
    own = np.flatnonzero(_ys == k)
    if not len(own):
        log.warning(f"  {cls}: no rows of this class in the sample")
        continue
    order_own, own_top[cls] = _profile(k, own)
    log.info(f"  {cls:<16} own rows {len(own):>5,}   "
             f"top: {', '.join(feats[i] for i in order_own[:3])}")
    if set(order[:3]) != set(order_own[:3]):
        log.info(f"  {'':<16} (all rows would say: "
                 f"{', '.join(feats[i] for i in order[:3])})")

save_json({"strategy": args.strategy, "model": "XGBoost",
           "n_sample": int(len(idx)), "n_features": len(feats),
           "base_values": [round(float(b), 6) for b in base],
           "units": "log-odds (margin), not probability",
           "feature_perturbation": getattr(explainer, "feature_perturbation",
                                           "tree_path_dependent"),
           "attribution_device": _dev,
           "additivity_max_error": round(_err, 10),
           "additivity_max_error_full_sample": round(_err_all, 10),
           "additivity_tolerance": 1e-3,
           "reconstruction_picks_predicted": round(_agree_all, 6),
           "unused_features": _unused,
           "shown_share_of_total": _shown,
           "note": ("mean_abs_shap over a stratified sample of the test set. "
                    "Computed on scaled features -- the space the model was "
                    "trained in. Values sum to the raw margin plus "
                    "base_values, NOT to predict_proba. TreeSHAP's "
                    "path-dependent estimator uses conditional expectations, "
                    "so attribution is shared among correlated features; read "
                    "these as evidence usage, not causal effect."),
           "aggregation": {
               "per_class": ("mean over EVERY sampled row -- dominated by "
                             "evidence for ruling the class out, since 15 of "
                             "16 classes in the sample are not it. Input to "
                             "the pair matrix."),
               "per_class_own": ("mean over rows whose TRUE class is this "
                                 "one -- what pushed these flows to this "
                                 "class. Use this for reporting and for the "
                                 "interface.")},
           "per_class": global_top,
           "per_class_own": own_top},
          "shap", f"global_{args.strategy}.json")

# --------------------------------------------------------------------------
# EVERY pair, not the one the finding is about.
#
# This block used to compute the importance correlation for Slowloris and DoS
# alone and conclude that sharing evidence is what makes a pair inseparable.
# Computed across all 120 pairs that conclusion does not survive: DDoS and
# PortScan share the most of any pair (0.959) and are confused in 0.9% of
# cases, while BufferOverflow and Exploitation are confused in 22% while
# sharing much less. High shared importance is therefore neither necessary
# nor sufficient for confusion, and a single pair could not have shown that.
#
# The matrix is cheap -- it is a correlation over numbers already computed --
# and it is what lets the write-up say where a pair sits among all of them
# rather than quoting one number with nothing to compare it against.
banner(log, "PAIRWISE EVIDENCE OVERLAP -- all class pairs")
imp = np.abs(sv).mean(0)                       # features x classes
C = np.corrcoef(imp.T)
pairs = []
for i in range(len(classes)):
    for j in range(i + 1, len(classes)):
        ti = set(np.argsort(imp[:, i])[::-1][:10])
        tj = set(np.argsort(imp[:, j])[::-1][:10])
        pairs.append({"a": classes[i], "b": classes[j],
                      "corr": round(float(C[i, j]), 6),
                      "shared_top10": len(ti & tj),
                      "shared": sorted(feats[k] for k in (ti & tj))})
pairs.sort(key=lambda p: -p["corr"])
log.info(f"  {len(pairs)} class pairs, ranked by importance correlation")
for r, p in enumerate(pairs[:5], 1):
    log.info(f"    {r}. {p['a']:<16}{p['b']:<16}corr {p['corr']:.3f}   "
             f"{p['shared_top10']}/10 shared")
log.info("  A high correlation says two classes are decided by the same "
         "features. It does NOT say they are confusable -- check the "
         "confusion matrix before drawing that conclusion.")
save_json({"n_sample": int(len(idx)), "classes": classes,
           "correlation": np.round(C, 6).tolist(), "pairs": pairs,
           "note": ("Pearson correlation between the per-feature mean |SHAP| "
                    "profiles of each class pair. Ranking a pair among all "
                    "120 is the only way to say whether its overlap is "
                    "unusual.")},
          "shap", f"pair_matrix_{args.strategy}.json")

# Kept under its own name because the write-up cites this pair directly.
if {"Slowloris", "DoS"} <= set(classes):
    p = next(x for x in pairs if {x["a"], x["b"]} == {"Slowloris", "DoS"})
    rank = pairs.index(p) + 1
    log.info(f"  Slowloris/DoS: corr {p['corr']:.4f}, rank {rank} of "
             f"{len(pairs)}, {p['shared_top10']}/10 shared")
    save_json({"pair": ["Slowloris", "DoS"],
               "importance_correlation": p["corr"],
               "shared_top10": p["shared"],
               "rank_among_all_pairs": rank, "n_pairs": len(pairs),
               "n_sample": int(len(idx))},
              "shap", f"pair_slowloris_dos_{args.strategy}.json")

# --------------------------------------------------------------------------
# One worked example per class, in the shape a report generator consumes.
banner(log, "WORKED EXAMPLES -- one correctly classified flow per class")
proba = model.predict_proba(X[idx])
pred = proba.argmax(1)
examples = {}
for k, cls in enumerate(classes):
    hits = np.flatnonzero((pred == k) & (y[idx] == k))
    if not len(hits):
        continue
    r = int(hits[np.argmax(proba[hits, k])])          # most confident
    order = np.abs(sv[r, :, k]).argsort()[::-1][:6]
    examples[cls] = {
        "confidence": round(float(proba[r, k]), 4),
        "top_features": [{"feature": feats[i],
                          "raw_value": round(float(X_raw[idx[r], i]), 4),
                          "scaled_value": round(float(X[idx[r], i]), 4),
                          "shap": round(float(sv[r, i, k]), 6),
                          "pushes": "toward" if sv[r, i, k] > 0 else "away"}
                         for i in order]}
save_json({"strategy": args.strategy, "examples": examples},
          "shap", f"examples_{args.strategy}.json")
log.info(f"  wrote {len(examples)} worked examples")

# --------------------------------------------------------------------------
banner(log, "DEPLOY BUNDLE")
if args.no_deploy:
    log.info("--no-deploy given, skipping.")
else:
    DEPLOY.mkdir(exist_ok=True)

    # The explainer is deliberately NOT pickled. joblib.dump(explainer)
    # writes 740 MB -- it serialises the whole tree structure again, plus
    # internal buffers -- and loading that back takes 1.29 s against 1.68 s
    # to rebuild it from XGBoost.pkl, which the bundle ships anyway. That is
    # 740 MB bought for 0.38 s, once, at process start. The UI calls
    # shap.TreeExplainer(model) at startup instead; see README.md.
    stale = DEPLOY / "shap_explainer.pkl"
    if stale.exists():
        stale.unlink()
        log.info("  removed shap_explainer.pkl (740 MB for 0.38 s -- rebuilt "
                 "from the model at startup instead)")

    for f in ("XGBoost.pkl", "scaler.pkl", "features.pkl", "label_encoder.pkl"):
        shutil.copy2(MODEL_DIR / f, DEPLOY / f)
    shutil.copy2(RESULTS_DIR / "shap" / f"global_{args.strategy}.json",
                 DEPLOY / "shap_global.json")

    def sha(p, n=16):
        h = hashlib.sha256()
        with open(p, "rb") as fh:
            for blk in iter(lambda: fh.read(1 << 20), b""):
                h.update(blk)
        return h.hexdigest()[:n]

    # The manifest cannot hash itself -- the digest would have to be known
    # before the file containing it exists. Everything else is covered.
    files = sorted(p for p in DEPLOY.iterdir()
                   if p.is_file() and p.suffix in (".pkl", ".json")
                   and p.name != "manifest.json")
    manifest = {
        "bundle": "forenxai-multiclass",
        "strategy": args.strategy,
        "classes": classes,
        "n_features": len(feats),
        "feature_order": feats,
        "trained_on": "TRUSTLab",
        "validated_on": "TRUSTLab held-out 20%",
        "scope_note": ("Validated on TRUSTLab only. Performance on other "
                       "capture environments is not established -- see the "
                       "binary experiment, scripts 05-07."),
        "versions": {"xgboost": __import__("xgboost").__version__,
                     "scikit-learn": __import__("sklearn").__version__,
                     "shap": shap.__version__,
                     "joblib": joblib.__version__,
                     "numpy": np.__version__},
        "files": {p.name: {"bytes": p.stat().st_size, "sha256_16": sha(p),
                           "sha256": sha(p, 64)}
                  for p in files},
    }
    with open(DEPLOY / "manifest.json", "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)

    total = sum(p.stat().st_size for p in DEPLOY.iterdir() if p.is_file())
    log.info(f"  deploy/  {len(list(DEPLOY.iterdir()))} files  "
             f"{total / 1e6:.1f} MB")
    for p in sorted(DEPLOY.iterdir()):
        if p.is_file():
            log.info(f"      {p.name:<24}{p.stat().st_size / 1e6:>8.2f} MB")

banner(log, "NEXT")
log.info("Read deploy/README.md for how a UI loads this bundle.")
