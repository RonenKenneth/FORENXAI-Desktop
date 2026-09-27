"""Does restricting to a class's own flows change its attribution profile?

Script 15 averages |SHAP| for class k over EVERY sampled row. The alternative
-- and what a reader usually assumes -- is to average only over rows whose
true class is k. Compute both and compare.
"""
import sys, json, warnings
from pathlib import Path
import numpy as np, pandas as pd, joblib, shap
from scipy.stats import spearmanr

warnings.filterwarnings("ignore")
ROOT = Path(r"C:\Users\HOME PC\Downloads\MULTI_CLASS_FORENXAI"
            r"\forenxai_pipeline_full\forenxai_binary")
sys.path.insert(0, str(ROOT))
from src.common import clean_features

md = ROOT / "artifacts" / "mc_random"
feats = list(joblib.load(md / "features.pkl"))
scaler = joblib.load(md / "scaler.pkl")
le = joblib.load(md / "label_encoder.pkl")
classes = [str(c) for c in le.classes_]
model = joblib.load(md / "XGBoost.pkl")

test = pd.read_parquet(ROOT / "data" / "processed" / "mc_test_random.parquet")
X = scaler.transform(clean_features(test, feats).values)
y = le.transform(test["folder_class"].values)

rng = np.random.default_rng(42)
per = 8000 // len(classes)
idx = np.concatenate([rng.choice(np.flatnonzero(y == k),
                                 size=min(per, int((y == k).sum())),
                                 replace=False)
                      for k in range(len(classes))])
rng.shuffle(idx)
ys = y[idx]

sv = np.array(shap.TreeExplainer(model).shap_values(X[idx]))
if sv.ndim == 3 and sv.shape[0] == len(classes):      # (K, n, F) -> (n, F, K)
    sv = np.transpose(sv, (1, 2, 0))
print("shap array", sv.shape, " rows", len(idx), " classes", len(classes))

rows = []
for k, cls in enumerate(classes):
    own = ys == k
    all_abs = np.abs(sv[:, :, k]).mean(0)          # script 15's quantity
    own_abs = np.abs(sv[own, :, k]).mean(0)        # class-conditional
    all_sgn = sv[:, :, k].mean(0)
    own_sgn = sv[own, :, k].mean(0)

    ta = set(np.argsort(all_abs)[::-1][:6])
    to = set(np.argsort(own_abs)[::-1][:6])
    rho = spearmanr(all_abs, own_abs).statistic
    rows.append(dict(cls=cls, shared=len(ta & to), rho=rho,
                     all_top=[feats[i] for i in np.argsort(all_abs)[::-1][:3]],
                     own_top=[feats[i] for i in np.argsort(own_abs)[::-1][:3]],
                     all_pos=int((all_sgn > 0).sum()),
                     own_pos=int((own_sgn > 0).sum()),
                     all_top1_sgn=float(all_sgn[np.argsort(all_abs)[::-1][0]]),
                     own_top1_sgn=float(own_sgn[np.argsort(own_abs)[::-1][0]])))

print(f"\n{'class':16s}{'top6 same':>10}{'rank rho':>10}"
      f"{'+ve feats all':>15}{'+ve feats own':>15}")
for r in rows:
    print(f"{r['cls']:16s}{r['shared']:>7d}/6{r['rho']:>10.3f}"
          f"{r['all_pos']:>13d}/66{r['own_pos']:>13d}/66")

print("\nTop-3 features, all rows vs the class's own rows")
for r in rows:
    same = "SAME" if r['all_top'] == r['own_top'] else "DIFFERENT"
    print(f"\n  {r['cls']}  [{same}]")
    print(f"    all rows : {', '.join(r['all_top'])}   (lead signed "
          f"{r['all_top1_sgn']:+.3f})")
    print(f"    own rows : {', '.join(r['own_top'])}   (lead signed "
          f"{r['own_top1_sgn']:+.3f})")

# Does the pair matrix conclusion survive the change?
imp_all = np.abs(sv).mean(0)
imp_own = np.stack([np.abs(sv[ys == k, :, k]).mean(0)
                    for k in range(len(classes))], axis=1)
C_all, C_own = np.corrcoef(imp_all.T), np.corrcoef(imp_own.T)
iu = np.triu_indices(len(classes), 1)
print(f"\nPair-similarity matrices: Pearson between the two versions' "
      f"120 pair values = {np.corrcoef(C_all[iu], C_own[iu])[0,1]:.3f}")
for name, C in (("all-row", C_all), ("own-row", C_own)):
    o = np.argsort(C[iu])[::-1][:3]
    print(f"  {name} top-3 pairs: " + "; ".join(
        f"{classes[iu[0][i]]}/{classes[iu[1][i]]} {C[iu][i]:.3f}" for i in o))
print(f"  DoS/Slowloris   all-row {C[classes.index('DoS'), classes.index('Slowloris')]:.3f}")
print(f"  DDoS/PortScan   own-row {C_own[classes.index('DDoS'), classes.index('PortScan')]:.3f}"
      f"   all-row {C_all[classes.index('DDoS'), classes.index('PortScan')]:.3f}")
print(f"  DoS/Slowloris   own-row {C_own[classes.index('DoS'), classes.index('Slowloris')]:.3f}"
      f"   all-row {C_all[classes.index('DoS'), classes.index('Slowloris')]:.3f}")
