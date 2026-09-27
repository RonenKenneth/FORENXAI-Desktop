"""
14_tune_xgboost.py
------------------
Hyperparameter search for the sixteen-class XGBoost, scored on validation
macro F1. The test set is never read here.

Same data preparation as script 09: same parquet, same 66 features, same
leakage-safe 85/15 group split, same scaler fitted on the training part.
So the validation score of the current model and of every candidate is
measured on identical rows.

Search: Optuna TPE on a stratified 30% subsample of the training part, each
trial early-stopped on the full validation part. The best configuration is
then refitted on the whole training part, first with early stopping to find
the round count, then again with exactly that many rounds and no early
stopping, so the saved booster holds only the trees it predicts with and
SHAP's TreeExplainer sees the same model that predict() uses.

The tuned model replaces artifacts/mc_<strategy>/XGBoost.pkl only if it beats
the current one on validation macro F1. The current one is kept as
XGBoost_baseline.pkl.

Usage:
  python scripts/14_tune_xgboost.py --trials 30
Then: 10 (test), 15 (SHAP + bundle), decision layer (new_deploy_gpu/audit/build_decision_layer.py), 16 (tuning report).
"""
import sys
import json
import time
import shutil
import argparse
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import optuna
import xgboost as xgb
from sklearn.metrics import f1_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config.settings import (PROCESSED_DIR, ARTIFACTS_DIR, RESULTS_DIR, SEED,
                             MC_VAL_FRACTION, MC_HARD_CLASSES)
from src.common import (get_logger, banner, set_seed, clean_features,
                        save_json, feature_ids, group_split, check_no_leakage)
from src.models import device

log = get_logger("14_tune_xgb")
set_seed()

ap = argparse.ArgumentParser()
ap.add_argument("--strategy", choices=["random", "temporal"], default="random")
ap.add_argument("--trials", type=int, default=30)
ap.add_argument("--search-frac", type=float, default=0.30)
args = ap.parse_args()

out_dir = ARTIFACTS_DIR / f"mc_{args.strategy}"
feats = joblib.load(ARTIFACTS_DIR / "mc_features.pkl")
classes = joblib.load(ARTIFACTS_DIR / "mc_classes.pkl")
scaler = joblib.load(out_dir / "scaler.pkl")

df = pd.read_parquet(PROCESSED_DIR / f"mc_train_{args.strategy}.parquet")
X = clean_features(df, feats).values
le = LabelEncoder().fit(classes)
y = le.transform(df["folder_class"].values)
K = len(le.classes_)
ids = feature_ids(df, feats)
itr, iva = group_split(y, ids, MC_VAL_FRACTION)
check_no_leakage(ids[itr], ids[iva], log, "train / validation")
del df
Xtr, Xva = scaler.transform(X[itr]), scaler.transform(X[iva])
ytr, yva = y[itr], y[iva]
hard = [list(le.classes_).index(c) for c in
        MC_HARD_CLASSES + ["BufferOverflow"] if c in le.classes_]

banner(log, f"XGBOOST TUNING -- {args.strategy}")
log.info(f"train {len(ytr):,}  val {len(yva):,}  features {len(feats)}  "
         f"classes {K}  device {device()}")


def weights(y_arr, hard_boost):
    c = np.bincount(y_arr, minlength=K).astype(float)
    w = c.sum() / (K * np.maximum(c, 1))        # same balancing as script 09
    w[hard] *= hard_boost
    return w[y_arr]


def build(p, n_estimators, early_stopping=None):
    kw = {"tree_method": "hist"}
    if device().type == "cuda":
        kw["device"] = "cuda"
    return xgb.XGBClassifier(
        n_estimators=n_estimators, learning_rate=p["learning_rate"],
        max_depth=p["max_depth"], min_child_weight=p["min_child_weight"],
        subsample=p["subsample"], colsample_bytree=p["colsample_bytree"],
        gamma=p["gamma"], reg_lambda=p["reg_lambda"], reg_alpha=p["reg_alpha"],
        max_bin=p["max_bin"], objective="multi:softprob", num_class=K,
        eval_metric="mlogloss", early_stopping_rounds=early_stopping,
        random_state=SEED, n_jobs=-1, **kw)


def scores(model):
    pred = model.predict(Xva)
    per = f1_score(yva, pred, average=None, labels=range(K), zero_division=0)
    return float(per.mean()), {c: float(per[i]) for i, c in enumerate(le.classes_)}


# Current model, same validation rows.
base_model = joblib.load(out_dir / "XGBoost.pkl")
base_macro, base_per = scores(base_model)
log.info(f"current model  val macro F1 {base_macro:.4f}")

# Search subsample.
sub, _ = train_test_split(np.arange(len(ytr)), train_size=args.search_frac,
                          random_state=SEED, stratify=ytr)
Xs, ys = Xtr[sub], ytr[sub]


def objective(trial):
    p = {"learning_rate": trial.suggest_float("learning_rate", 0.03, 0.2, log=True),
         "max_depth": trial.suggest_int("max_depth", 6, 14),
         "min_child_weight": trial.suggest_float("min_child_weight", 1, 20, log=True),
         "subsample": trial.suggest_float("subsample", 0.6, 1.0),
         "colsample_bytree": trial.suggest_float("colsample_bytree", 0.5, 1.0),
         "gamma": trial.suggest_float("gamma", 0.0, 5.0),
         "reg_lambda": trial.suggest_float("reg_lambda", 0.5, 10, log=True),
         "reg_alpha": trial.suggest_float("reg_alpha", 1e-3, 2.0, log=True),
         "max_bin": trial.suggest_categorical("max_bin", [256, 512]),
         "hard_boost": trial.suggest_float("hard_boost", 1.0, 3.0)}
    m = build(p, 1500, early_stopping=50)
    m.fit(Xs, ys, sample_weight=weights(ys, p["hard_boost"]),
          eval_set=[(Xva, yva)], verbose=False)
    macro, _ = scores(m)
    trial.set_user_attr("best_iteration", int(m.best_iteration))
    log.info(f"  trial {trial.number:>2}  macro F1 {macro:.4f}  "
             f"rounds {m.best_iteration + 1}")
    return macro


study = optuna.create_study(direction="maximize",
                            sampler=optuna.samplers.TPESampler(seed=SEED))
# Trial 0 is the current configuration, so the search can only match or beat it.
study.enqueue_trial({"learning_rate": 0.08, "max_depth": 10,
                     "min_child_weight": 5, "subsample": 0.8,
                     "colsample_bytree": 0.8, "gamma": 0.0, "reg_lambda": 1.0,
                     "reg_alpha": 1e-3, "max_bin": 256, "hard_boost": 1.0})
optuna.logging.set_verbosity(optuna.logging.WARNING)
t0 = time.time()
study.optimize(objective, n_trials=args.trials)
log.info(f"search {time.time() - t0:.0f}s  best subsample macro F1 "
         f"{study.best_value:.4f}")
best = dict(study.best_params)

# Refit on the full training part: find the round count, then fit exactly that.
banner(log, "REFIT ON FULL TRAINING PART")
t0 = time.time()
m = build(best, 3000, early_stopping=50)
m.fit(Xtr, ytr, sample_weight=weights(ytr, best["hard_boost"]),
      eval_set=[(Xva, yva)], verbose=False)
rounds = int(m.best_iteration) + 1
final = build(best, rounds)
final.fit(Xtr, ytr, sample_weight=weights(ytr, best["hard_boost"]))
secs = time.time() - t0
macro, per = scores(final)
weighted = float(f1_score(yva, final.predict(Xva), average="weighted"))
log.info(f"tuned  val macro F1 {macro:.4f}  (current {base_macro:.4f})  "
         f"rounds {rounds}  {secs:.0f}s")
for c in MC_HARD_CLASSES + ["BufferOverflow"]:
    log.info(f"    {c:<16} {base_per[c]:.4f} -> {per[c]:.4f}")

accepted = macro > base_macro
report = {"strategy": args.strategy, "accepted": accepted,
          "selection_metric": "validation macro F1 (15% group split of train)",
          "baseline_params": {"n_estimators": 400, "learning_rate": 0.08,
                              "max_depth": 10, "min_child_weight": 5,
                              "subsample": 0.8, "colsample_bytree": 0.8,
                              "hard_boost": 1.0},
          "tuned_params": {**best, "n_estimators": rounds},
          "val_macro_f1": {"baseline": base_macro, "tuned": macro},
          "val_per_class_f1": {"baseline": base_per, "tuned": per},
          "trials": args.trials, "search_frac": args.search_frac,
          "refit_seconds": round(secs, 1)}
save_json(report, "finetune", f"xgb_tuning_{args.strategy}.json")
study.trials_dataframe().to_csv(
    RESULTS_DIR / "finetune" / f"xgb_trials_{args.strategy}.csv", index=False)

if not accepted:
    log.warning("Tuned model does not beat the current one on validation. "
                "XGBoost.pkl left unchanged.")
    sys.exit(0)

backup = out_dir / "XGBoost_baseline.pkl"
if not backup.exists():
    shutil.copy2(out_dir / "XGBoost.pkl", backup)
joblib.dump(final, out_dir / "XGBoost.pkl")
# Same file script 09 writes, so script 10 and the tables read the new run.
save_json({"strategy": args.strategy, "model": "XGBoost",
           "train_seconds": round(secs, 1), "n_train": int(len(ytr)),
           "n_features": len(feats), "n_classes": K,
           "val_macro_f1": macro, "val_weighted_f1": weighted,
           "val_per_class_f1": per, "tuned": True,
           "params": {**best, "n_estimators": rounds}},
          f"mc_{args.strategy}", "XGBoost_internal.json")
log.info(f"saved {out_dir / 'XGBoost.pkl'}  (old kept as {backup.name})")
