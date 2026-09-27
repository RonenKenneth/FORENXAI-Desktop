"""
13_reverse_transfer.py
----------------------
Multiclass transfer OUT of TRUSTLab: do the five GPU-trained sixteen-class
models still work on other datasets?

WHY THIS EXISTS
Script 10 tests the five models on the TRUSTLab held-out split. That says how
well they fit TRUSTLab. It does not say whether they transfer to a different
capture environment, which is what a deployed forensic tool meets. This script
scores the SAME trained models, unchanged, on CSE-CIC-IDS2018 and TII-SSRC-23.

NOTHING IS RETRAINED
The models are the ones script 09 saved under artifacts/mc_random/ (the GPU
run). XGBoost.pkl there is byte-identical to new_deploy_gpu/XGBoost.pkl. Nothing
under artifacts/ or deploy*/ is written. Outputs go to
results/reverse_transfer_mc/.

WHAT IS COMPARABLE
TRUSTLab has sixteen classes; the public datasets share only some of them.
Only classes with a counterpart are scored; the rest are excluded and listed,
never forced into a class. For each external class:
  exact   the prediction must equal the mapped TRUSTLab class
  family  the prediction may be any class in the same family. DoS, DDoS and
          Slowloris form one family because this study already shows the
          models cannot reliably separate the slow-rate pair, and public
          datasets name the same behaviour differently.
The mapping is judgement, not fact. It is written in one place below so it
can be reviewed before anything is reported. Weak mappings are flagged.

External classes sharing a TRUSTLab counterpart are POOLED before scoring --
the three DDoS variants are one DDoS figure, the four benign traffic types
one Benign figure. Both sides of the comparison then weight each TRUSTLab
class once. The score is macro recall over the pooled classes holding at
least MIN_N rows, so a 10-row class cannot move it. The reference column is
the same models' macro recall on the TRUSTLab held-out split over exactly
those classes; the gap between the two is the result.

READ THE CONFOUNDS BEFORE THE NUMBERS
  * Duplicate rows. Several CSE-CIC-IDS2018 classes are about half exact
    duplicates (Bot, SSH-Bruteforce). They are dropped before scoring
    (--no-dedup keeps them), otherwise a class splits exactly 50/50 and looks
    like model behaviour.
  * Flow timeouts differ: CSE-CIC-IDS2018 and TII-SSRC-23 stop at exactly
    120 s, while TRUSTLab runs to 15,717 s, about 4.4 hours. Separately,
    CSE-CIC-IDS2018 writes -1 as a sentinel in the initial-window columns --
    17.3% of FWD Init Win Bytes and 52.1% of Bwd Init Win Bytes -- where
    TRUSTLab is never negative. TII-SSRC-23 does not do this. The shift
    diagnostic below reports both.
  * A low score cannot separate failure to generalise from feature
    incompatibility. Report it as a result, with this caveat.

Usage:
  python scripts/13_reverse_transfer.py
  python scripts/13_reverse_transfer.py --model-dir artifacts/mc_random
  python scripts/13_reverse_transfer.py --no-dedup
"""
import sys
import argparse
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
import joblib
import torch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config.settings import PROCESSED_DIR, ARTIFACTS_DIR, RESULTS_DIR, ALL_MODELS
from src.common import get_logger, banner, clean_features, save_json, human
from src.models import build, device, free_gpu

# XGBoost warns once per predict that the booster is on cuda while the input
# array is in host memory, so it builds a DMatrix instead of predicting in
# place. Filtered because this script predicts fifteen times and the message
# would bury the results, and benign because that path is the fast one:
# measured on 200,000 rows it takes 0.74 s against 4.26 s with the booster
# moved to the CPU, for identical predictions. It is NOT the cause of the
# slowdown that free_gpu() addresses in predict() below -- that one is
# PyTorch holding GPU memory, and the two are independent.
warnings.filterwarnings("ignore", message=".*mismatched devices.*")
log = get_logger("13_reverse")

ap = argparse.ArgumentParser()
ap.add_argument("--model-dir", type=Path,
                default=ARTIFACTS_DIR / "mc_random",
                help="folder with the five GPU-trained multiclass models "
                     "plus scaler.pkl, features.pkl, label_encoder.pkl")
ap.add_argument("--no-dedup", action="store_true",
                help="keep duplicate external rows")
args = ap.parse_args()

OUT = RESULTS_DIR / "reverse_transfer_mc"
OUT.mkdir(parents=True, exist_ok=True)
MIN_N = 100

# --------------------------------------------------------------------------
# CLASS MAPPING -- review before reporting.
# external label -> (exact set, family set), or None when TRUSTLab has no
# counterpart and the class is excluded.
DOS_FAMILY = {"DoS", "DDoS", "Slowloris"}
BENIGN = ({"Benign"}, {"Benign"})
CIC_MAP = {
    "Benign": BENIGN,
    "DDOS attack-HOIC": ({"DDoS"}, {"DDoS", "DoS"}),
    "DDoS attacks-LOIC-HTTP": ({"DDoS"}, {"DDoS", "DoS"}),
    "DDOS attack-LOIC-UDP": ({"DDoS"}, {"DDoS", "DoS"}),
    "DoS attacks-Hulk": ({"DoS"}, DOS_FAMILY),
    "DoS attacks-GoldenEye": ({"DoS"}, DOS_FAMILY),
    "DoS attacks-Slowloris": ({"Slowloris"}, {"Slowloris", "DoS"}),
    # Closest counterpart only: SlowHTTPTest is a slow-rate DoS tool, not
    # Slowloris itself.
    "DoS attacks-SlowHTTPTest": ({"Slowloris"}, {"Slowloris", "DoS"}),
    "FTP-BruteForce": ({"Bruteforce"}, {"Bruteforce"}),
    "SSH-Bruteforce": ({"Bruteforce"}, {"Bruteforce"}),
    "Brute Force -Web": ({"WebBased"}, {"WebBased", "Exploitation"}),
    "Brute Force -XSS": ({"WebBased"}, {"WebBased", "Exploitation"}),
    "SQL Injection": ({"WebBased"}, {"WebBased", "Exploitation"}),
    # Loose: a botnet is not the same behaviour as C2 beaconing.
    "Bot": ({"C2Beaconing"}, {"C2Beaconing"}),
    "Infilteration": None,
}
TII_MAP = {
    "DoS": ({"DoS"}, DOS_FAMILY),
    "Information Gathering": ({"PortScan"}, {"PortScan"}),
    "Bruteforce": ({"Bruteforce"}, {"Bruteforce"}),
    "Mirai": None,
    "Video": BENIGN, "Text": BENIGN, "Audio": BENIGN, "Background": BENIGN,
}
LOOSE = {"DoS attacks-SlowHTTPTest", "Bot"}   # weakest mappings, flagged
EXTERNAL = {
    "CSE-CIC-IDS2018": (PROCESSED_DIR / "train_cicids_only.parquet", CIC_MAP),
    "TII-SSRC-23": (PROCESSED_DIR / "train_tii_only.parquet", TII_MAP),
}
EXT_KEYS = [n.split("-")[0].lower() for n in EXTERNAL]   # column prefixes
# Two datasets whose names begin with the same token would silently share a
# column and overwrite each other's results.
assert len(set(EXT_KEYS)) == len(EXT_KEYS), f"column prefixes collide: {EXT_KEYS}"

# --------------------------------------------------------------------------
md = args.model_dir
need = ["scaler.pkl", "features.pkl", "label_encoder.pkl"]
for f in need:
    if not (md / f).exists():
        log.error(f"Missing {md / f} -- run 09_train_multiclass.py first.")
        sys.exit(1)
paths = {}
for m in ALL_MODELS:
    for suf in (".pkl", ".pt"):
        if (md / f"{m}{suf}").exists():
            paths[m] = md / f"{m}{suf}"
            break
missing = [m for m in ALL_MODELS if m not in paths]
if missing:
    log.error(f"Model files missing in {md}: {missing}")
    sys.exit(1)

scaler = joblib.load(md / "scaler.pkl")
feats = list(joblib.load(md / "features.pkl"))
le = joblib.load(md / "label_encoder.pkl")
classes = np.array([str(c) for c in le.classes_])
log.info(f"Model folder : {md}")
log.info(f"Device       : {device()}")
log.info(f"Models       : {', '.join(ALL_MODELS)}")


_loaded = {}


def predict(name, Xs, batch=8192):
    """Predicted class names for a scaled matrix.

    The model is loaded once and kept: this is called three times per model
    (the TRUSTLab reference and the two external sets), and re-reading a
    26 MB booster from disk each time buys nothing.
    """
    if paths[name].suffix == ".pkl":
        # Release torch's cached GPU memory first. The deep models above have
        # already run in this process and torch does not hand its allocator
        # blocks back, which is what made XGBoost crawl in scripts 05 and 09
        # -- see free_gpu in src/models.py. Cheap insurance here, where the
        # work is prediction rather than a fit.
        free_gpu()
        if name not in _loaded:
            _loaded[name] = joblib.load(paths[name])
        return classes[_loaded[name].predict(Xs)]
    if name not in _loaded:
        m = build(name, Xs.shape[1], n_classes=len(classes))
        m.load_state_dict(torch.load(paths[name], map_location=device()))
        m.eval()
        _loaded[name] = m
    m = _loaded[name]
    out = []
    with torch.no_grad():
        for i in range(0, len(Xs), batch):
            xb = torch.tensor(Xs[i:i + batch]).to(device())
            out.append(m(xb).argmax(1).cpu().numpy())
    return classes[np.concatenate(out)]


# --------------------------------------------------------------------------
banner(log, "DATA")
te = pd.read_parquet(PROCESSED_DIR / "mc_test_random.parquet")
Xs_ref = scaler.transform(clean_features(te, feats).values)
y_ref = te["folder_class"].astype(str).values

tr = pd.read_parquet(PROCESSED_DIR / "mc_train_random.parquet",
                     columns=feats)
# Cleaned, because the external side below is cleaned too: clean_features
# sends infinities and gaps to 0, so an uncleaned minimum can be -inf for a
# column whose real floor is 0, and the "never negative in TRUSTLab" check
# would then silently skip it.
train_min = clean_features(tr, feats).min()
del tr

ext = {}
for name, (path, cmap) in EXTERNAL.items():
    if not path.exists():
        log.error(f"Missing {path} -- run 04_align_and_build.py first.")
        sys.exit(1)
    df = pd.read_parquet(path)
    n0 = len(df)
    if not args.no_dedup:
        df = df.drop_duplicates(subset=feats + ["folder_class"]) \
               .reset_index(drop=True)
    log.info(f"{name}: {human(n0)} rows"
             + (f", {human(n0 - len(df))} exact duplicates dropped, "
                f"{human(len(df))} kept" if not args.no_dedup else ""))
    ext[name] = (df, scaler.transform(clean_features(df, feats).values), cmap)

banner(log, "SHIFT DIAGNOSTIC -- how far do the external features move?")
shift = {}
for name, (df, Xs, _cmap) in ext.items():
    n_shift = int((np.abs(Xs.mean(0)) > 3).sum())
    const = [feats[i] for i in range(len(feats))
             if float(Xs[:, i].std()) == 0.0]
    raw = clean_features(df, feats)
    neg = [f for f in feats
           if train_min[f] >= 0 and float((raw[f] < 0).mean()) > 0.01]
    shift[name] = {"features_shifted_over_3_sd": n_shift,
                   "constant_in_external": const,
                   "negative_values_absent_in_trustlab": neg}
    log.info(f"  {name}: {n_shift} of {len(feats)} features have a mean more "
             f"than 3 TRUSTLab SD from TRUSTLab's; {len(const)} constant")
    if const:
        log.info(f"      constant: {', '.join(const)}")
    if neg:
        log.info(f"      negative in >1% of rows, never negative in "
                 f"TRUSTLab: {', '.join(neg)}")
save_json(shift, "reverse_transfer_mc", "shift.json")

# Classes mapped in at least one external set, for the TRUSTLab reference.
mapped_tl = sorted({c for _n, (_p, cm) in EXTERNAL.items()
                    for spec in cm.values() if spec for c in spec[0]})

# --------------------------------------------------------------------------
recs, per_class, per_group = [], [], []
for name in ALL_MODELS:
    banner(log, f"MODEL: {name}")
    p_ref = predict(name, Xs_ref)
    ref_recall_all = float(np.mean([(p_ref[y_ref == c] == c).mean()
                                    for c in mapped_tl]))
    ref_acc = float((p_ref == y_ref).mean())
    log.info(f"  TRUSTLab held-out: accuracy {ref_acc:.4f}   macro recall on "
             f"all {len(mapped_tl)} mappable classes {ref_recall_all:.4f}")
    # Two different references, so they carry two different names: this one is
    # over every class either map mentions, the one added after the loop is
    # over the classes actually scored, which is the one the table compares.
    rec = {"model": name, "ref_accuracy": ref_acc,
           "ref_macro_recall_all_mapped": ref_recall_all}
    for ename, (df, Xs, cmap) in ext.items():
        pred = predict(name, Xs)
        fc = df["folder_class"].values

        # Pool the external classes that share a TRUSTLab counterpart before
        # averaging. CSE-CIC-IDS2018 names three DDoS variants and two DoS
        # ones; TII-SSRC-23 names four benign traffic types. A macro over
        # external class names therefore weights DDoS three times and Benign
        # once, while the TRUSTLab reference weights every class once -- so
        # part of the gap between them would be that difference in weighting
        # rather than anything the models did. Pooling also lets the three web
        # classes be scored: none of them reaches MIN_N alone, so on external
        # names WebBased was mapped but never actually measured.
        groups = {}
        for c in sorted(set(fc)):
            spec = cmap.get(c)
            if spec is None:
                continue
            g = groups.setdefault("/".join(sorted(spec[0])),
                                  {"mask": np.zeros(len(fc), bool),
                                   "exact": set(), "family": set(),
                                   "members": []})
            g["mask"] |= (fc == c)
            g["exact"] |= set(spec[0])
            g["family"] |= set(spec[1])
            g["members"].append(c)

        log.info(f"\n  {ename}")
        dropped = sorted(c for c in set(fc) if cmap.get(c) is None)
        if dropped:
            log.info(f"    no TRUSTLab counterpart, excluded: "
                     f"{', '.join(dropped)}")
        log.info(f"    {'external class':<26}{'n':>9}{'exact':>8}{'family':>8}"
                 f"   top predictions")
        for c in sorted(set(fc)):
            spec = cmap.get(c)
            if spec is None:
                continue
            mask = fc == c
            p = pred[mask]
            ex = float(np.isin(p, list(spec[0])).mean())
            fa = float(np.isin(p, list(spec[1])).mean())
            top = pd.Series(p).value_counts(normalize=True).head(3)
            tops = ", ".join(f"{k} {v:.0%}" for k, v in top.items())
            gk = "/".join(sorted(spec[0]))
            pooled = len(groups[gk]["members"]) > 1
            in_macro = int(groups[gk]["mask"].sum()) >= MIN_N
            log.info(f"    {c:<26}{int(mask.sum()):>9,}{ex:>8.3f}{fa:>8.3f}"
                     f"   {tops}"
                     + ("  (loose)" if c in LOOSE else "")
                     + (f"  (pooled as {gk})" if pooled else "")
                     + ("" if in_macro else "  (not in macro)"))
            per_class.append({"model": name, "test_set": ename,
                              "external_class": c, "n": int(mask.sum()),
                              "exact_recall": round(ex, 4),
                              "family_recall": round(fa, 4),
                              "mapped_to": gk,
                              "loose_mapping": c in LOOSE,
                              "in_macro": in_macro, "top_predictions": tops})

        ex_l, fa_l, ref_cls = [], [], set()
        log.info(f"    pooled by TRUSTLab class -- what the macro averages:")
        for gk, g in sorted(groups.items()):
            n = int(g["mask"].sum())
            p = pred[g["mask"]]
            ex = float(np.isin(p, list(g["exact"])).mean())
            fa = float(np.isin(p, list(g["family"])).mean())
            small = n < MIN_N
            log.info(f"      {gk:<24}{n:>9,}{ex:>8.3f}{fa:>8.3f}   "
                     f"from {', '.join(g['members'])}"
                     + (f"  (n<{MIN_N}, not in macro)" if small else ""))
            per_group.append({"model": name, "test_set": ename,
                              "trustlab_class": gk, "n": n,
                              "exact_recall": round(ex, 4),
                              "family_recall": round(fa, 4),
                              "external_classes": "; ".join(g["members"]),
                              "in_macro": not small})
            if not small:
                ex_l.append(ex)
                fa_l.append(fa)
                ref_cls.update(g["exact"])
        k = ename.split("-")[0].lower()
        rec[f"{k}_exact"] = float(np.mean(ex_l)) if ex_l else float("nan")
        rec[f"{k}_family"] = float(np.mean(fa_l)) if fa_l else float("nan")
        # Reference: the same models on TRUSTLab, over exactly the TRUSTLab
        # classes scored in this external set, each counted once -- the same
        # weighting the pooled external macro uses.
        rec[f"{k}_ref"] = float(np.mean([(p_ref[y_ref == c] == c).mean()
                                         for c in sorted(ref_cls)]))
        log.info(f"    macro over {len(ex_l)} TRUSTLab classes (n>={MIN_N}): "
                 f"exact {rec[f'{k}_exact']:.3f}   "
                 f"family {rec[f'{k}_family']:.3f}   "
                 f"TRUSTLab reference on the same classes "
                 f"{rec[f'{k}_ref']:.3f}")
    rec["ref_macro_recall_mapped"] = float(
        np.mean([rec[f"{k}_ref"] for k in EXT_KEYS]))
    rec["mean_ext_exact"] = float(
        np.mean([rec[f"{k}_exact"] for k in EXT_KEYS]))
    rec["mean_ext_family"] = float(
        np.mean([rec[f"{k}_family"] for k in EXT_KEYS]))
    rec["gap_exact"] = rec["ref_macro_recall_mapped"] - rec["mean_ext_exact"]
    recs.append(rec)
    free_gpu()

# --------------------------------------------------------------------------
banner(log, "RANKING -- five GPU-trained models on external data")
df = pd.DataFrame(recs).sort_values("mean_ext_exact", ascending=False)
df.to_csv(OUT / "ranking.csv", index=False)
pd.DataFrame(per_class).to_csv(OUT / "per_class.csv", index=False)
pd.DataFrame(per_group).to_csv(OUT / "per_trustlab_class.csv", index=False)
log.info("\n" + df[["model", "ref_macro_recall_mapped"]
                   + [f"{k}_exact" for k in EXT_KEYS]
                   + ["mean_ext_exact", "mean_ext_family", "gap_exact"]
                   ].round(3).to_string(index=False))
by_family = df.sort_values("mean_ext_family", ascending=False).iloc[0]["model"]
log.info(f"\n  Highest mean external exact recall : {df.iloc[0]['model']} "
         f"({df.iloc[0]['mean_ext_exact']:.3f})")
log.info(f"  Highest mean external family recall: {by_family}")
if by_family != df.iloc[0]["model"]:
    log.warning("  The two metrics disagree on the winner. Say which one you "
                "rank on and why.")
if df["mean_ext_exact"].max() < 0.5:
    log.warning("  No model reaches 0.5 exact recall externally. 'Winner' "
                "means least bad, not good.")
log.info("  Compare ref_macro_recall_mapped with the external columns: that "
         "gap is the finding.")
save_json({"models": recs, "mapped_trustlab_classes": mapped_tl,
           "min_n": MIN_N, "dedup": not args.no_dedup,
           "mapping_note": "Mappings are judgement; see the script header."},
          "reverse_transfer_mc", "reverse_transfer_mc.json")
log.info(f"\nOutputs -> {OUT}")
banner(log, "FOR THE WRITE-UP")
log.info("  * Same trained models as script 10, applied unchanged to other "
         "datasets.")
log.info("  * Only classes with a TRUSTLab counterpart are scored; state the "
         "mapping and that it is judgement.")
log.info("  * A low score mixes failure to generalise with feature "
         "incompatibility (timeouts, -1 sentinels). Say so.")
