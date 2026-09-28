# ForenXAI

Flow-level intrusion detection with explanation and grounded response guidance.
Two experiments, five architectures, three datasets, and an offline reporting
layer built on SHAP and a local language model.

**Headline result:** models that score 0.95–0.99 on their own data collapse to
below chance on a different capture environment. The mechanism is diagnosed,
not just observed.

---

## 1. What this study asks

Two questions, deliberately separated because they need different data.

| | Binary experiment | Multiclass experiment |
|---|---|---|
| Question | Does attack detection survive a change of network? | Can attack *types* be told apart? |
| Scripts | 01–07 | 08–12 |
| Trained on | CICIDS2018 + TII-SSRC-23 | TRUSTLab |
| Tested on | **TRUSTLab — never trained on** | TRUSTLab held-out 20% |
| Answer | **No** — mean ROC-AUC 0.4698 (10 of 15 detectors below 0.50) | Yes, within one environment — 0.9337 |

The multiclass experiment stays inside one dataset by necessity: six of
TRUSTLab's sixteen classes (API, MITM, Evasion, TLSSSL, Exfiltration,
C2Beaconing) have no counterpart in either comparison dataset, so a
cross-dataset multiclass score would be uninterpretable.

## 2. Datasets

| Dataset | Role | Rows used |
|---|---|---|
| **CICIDS2018** | training source | 800,000 (capped) |
| **TII-SSRC-23** | training source | 401,301 — only 1,301 benign |
| **TRUSTLab** | external test (binary) · train+test (multiclass) | 4,501,691 across 16 classes |

All three are CICFlowMeter-family flow exports. The 74 features used are the
**intersection of the three schemas, matched by name** — never by position,
because two of the datasets share column names but order them differently.

### A defect in the published TRUSTLab data

`PortScan.csv.gz` is truncated at source: the gzip stream ends mid-block with
no trailer at 33,361,601 bytes. Downloads repeated across separate networks
were byte-identical, so the fault is in the published archive rather than in
transfer.

**107,579 of approximately 171,147 flows (62.9%) are recoverable** and are
used. `src/trustlab_io.py` drives zlib directly rather than through
`gzip.GzipFile`, which discards already-decompressed bytes when it raises —
that alternative loses the entire class behind a warning that reads as minor.

Per-class caps are unaffected (every experiment needs at most 80,000 rows per
class). The cost is provenance, not sample size: the class is drawn from the
first 62.9% of its capture, so **its temporal-split result is indicative
only**. Accuracy recomputed with PortScan excluded from prevalence weighting
differs by at most **0.0146** across all fifteen binary models.

## 3. Methodology

### Splitting

| Experiment | Train | Validation | Test | Method |
|---|---|---|---|---|
| Binary | 85% | 15% | TRUSTLab, 100% | stratified random |
| Multiclass | 68% (952,000) | 12% (168,000) | 20% (280,000) | random **and** temporal |

TRUSTLab is never trained on in the binary experiment. Scalers are fitted on
the training portion alone and merely applied to validation and test.

The multiclass 80/20 is built **two ways**: `random` (shuffled, matching the
dataset authors' protocol) and `temporal` (the last 20% by capture order, so
test traffic was recorded after everything trained on). The difference between
them is itself a result.

### Models

Five architectures per arm — MLP, CNN1D, LSTM, CNN-BiLSTM, and XGBoost as a
non-deep control. Weighted cross-entropy for the deep models, `scale_pos_weight`
for XGBoost. Seed 42 throughout. 31.3 hours of CPU training in total.

### Evaluation

External validation is scored at threshold **0.445** — the operating point the
published baseline was measured at — so reported deltas reflect the models
rather than a mismatched cutoff. A full threshold sweep accompanies every
result. Accuracy is additionally reweighted to TRUSTLab's native class
prevalence, because the capped test set is ~6% benign where the corpus is ~57%.

---

## 4. Results

### Binary — transfer fails

```
mean external ROC-AUC   0.4698      (0.50 is a coin flip; 10 of 15 below it)
below chance            10 of 15
best external accuracy  0.6329      vs published baseline 0.8963
internal F1             0.95 – 0.99
```

ROC-AUC is threshold-independent, so no cutoff repairs this — the ranking
itself is wrong. `cicids_only/LSTM` calls 99.98% of traffic benign and catches
one attack in ten thousand.

### Why it fails — the mechanism

Name equivalence between schemas does not guarantee distributional
equivalence. Two concrete causes:

1. **Different flow timeouts.** Training flows cap at exactly 120,000,000 µs
   (120 s, the CICFlowMeter default). TRUSTLab flows extend to
   15,716,702,208 µs — **4.4 hours**. Twenty-one of the 74 features differ by
   more than three training standard deviations.
2. **Five dead features.** `Bwd PSH Flags`, `Bwd URG Flags`,
   `Fwd Bulk Rate Avg`, `Fwd Bytes/Bulk Avg`, `Fwd Packet/Bulk Avg` are
   constant zero throughout training but reach 1,250,659 in TRUSTLab. A
   scaler cannot rescale a constant, so these enter the models unscaled with
   untrained weights.

The reported figures therefore measure genuine failure to generalise *and*
feature-space incompatibility. The harmonisation run below separates the part
that can be repaired without retraining.

### Harmonisation check — how much of the gap is fixable at scoring time

`src/harmonise.py` repairs the three documented encoding differences on the
test side only (no model is retrained), and `--harmonise` in scripts 06 and 13
writes to `results/harmonised/<variant>/`; `17_harmonisation_report.py` builds
`results/tables/10_harmonisation_before_after.csv`. Macro recall (binary: mean
of attack and benign recall, chance 0.50; 16-class: mean recall on the eight
shared classes, chance about 0.06), mean of all models:

| Experiment | Original | Harmonised | Harmonised + flows ≤ 120 s |
|---|---|---|---|
| Binary → TRUSTLab, macro recall | 0.474 | 0.469 | 0.491 |
| Binary → TRUSTLab, ROC-AUC | 0.470 | 0.459 | 0.508 |
| 16-class TRUSTLab → others, macro recall | 0.165 | 0.165 | 0.165 |
| 16-class, TRUSTLab reference on the same classes | 0.869 | 0.869 | 0.863 |

XGBoost: binary combined arm 0.473 → 0.520 macro recall (ROC-AUC 0.487 →
0.554) on the timeout-matched subset; 16-class 0.203 in every variant.

What each repair showed:
- **Dead features** (set to their constant training value): no gain; the
  models were not being misled by them.
- **−1 sentinels** (set to 0): no prediction changed. After scaling, −1 and 0
  differ by 0.00003 SD, because Init Win Bytes has a spread of about 30,000.
- **Flow timeout** (only TRUSTLab flows ≤ 120 s, 412,971 of 480,000): the only
  repair with an effect, +0.02 to +0.05, still at chance. The 16-class
  reference barely moves (0.884 → 0.878), so long flows do not inflate it.

Conclusion: the documented encoding differences explain little of the gap.
What remains is feature definitions that differ between the exporters (a
domain classifier separates the datasets with AUC 1.0, mainly on Packet Length
Min) and genuinely different networks — both need retraining or a common
re-extraction to address, not scoring-time repair.

### Multiclass — five architectures converge

| Model | Accuracy | Macro F1 | DoS | Exploitation | Slowloris | Train time |
|---|---|---|---|---|---|---|
| **XGBoost** | **0.9337** | **0.9287** | 0.6703 | 0.7860 | 0.7593 | **388 s** |
| CNN1D | 0.9264 | 0.9208 | 0.6266 | 0.7754 | 0.7338 | 4,730 s |
| CNN-BiLSTM | 0.9263 | 0.9199 | 0.6204 | 0.7771 | 0.7539 | 27,781 s |
| LSTM | 0.9223 | 0.9174 | 0.6558 | 0.7665 | 0.7153 | 30,850 s |
| MLP | 0.9220 | 0.9164 | 0.6176 | 0.7662 | 0.7311 | 885 s |

Every deep model cost more time **and** scored lower. LSTM took 79× longer
than XGBoost for 0.0113 less macro F1. That negative result is the
architecture comparison the dataset paper did not run.

### Two distinct failure modes, separated by the split protocol

| Class | Random | Temporal | Errors land on | Reading |
|---|---|---|---|---|
| Slowloris | 0.756 | 0.330 | **DoS only**, 69.8% | genuine feature limit |
| DoS | 0.681 | 0.435 | **Slowloris only**, 52.8% | genuine feature limit |
| Exploitation | 0.795 | 0.682 | BufferOverflow, stable | genuine feature limit |
| **WebBased** | **0.994** | **0.532** | PortScan 25.5%, Exploitation 24.3%, Benign 7.8%, C2Beaconing 5.5% | **session memorisation** |

Consistent confusion with *one similar class* is a feature limit. Scattering
across *unrelated* classes is memorisation of the capture session — and it is
invisible under the random protocol the dataset authors used.

SHAP corroborates the first: Slowloris and DoS have a per-feature importance
correlation of **0.9040**, sharing six of their top ten features. Both classes
are decided by the same evidence.

### The published confusions did not reproduce

| Confusion | Published | Ours | Ratio |
|---|---|---|---|
| Slowloris → Benign | 28.53% | **0.00%** | 0.00× |
| DoS ↔ DDoS | 2.90% | **0.00%** | 0.00× |
| Exploitation → BufferOverflow | 0.33% | 4.87% | 14.69× |

Under a reconstruction of the authors' Phase-1 operating point (script 12,
`matched` rung) Slowloris→Benign remains absent at 0.01%, so the difference is
not an artifact of our protocol. This suggests the published confusion is
substantially a consequence of the two-stage design — where the Benign class
recovers Phase-1 false positives — rather than an inherent limit of flow-level
features.

### Session-artifact diagnostic

Removing the features most likely to encode capture conditions
(`FWD Init Win Bytes`, `Bwd Init Win Bytes`, `Flow IAT Min`, `Dst Port`)
changed macro F1 by **0.0002**. A clean positive result for TRUSTLab's
single-class capture methodology.

---

## 5. Explanation (script 15) and non-ML reporting (scripts_other/)

| Phase | Purpose | State |
|---|---|---|
| `15_explain_shap` | Exact TreeSHAP attributions; builds the `deploy/` bundle | ready |
| `rag_report` | Three panels: capture summary, SHAP explanation, grounded recommendations | needs documents |
| `eval_reports` | Scores whether the language model invented anything | needs more cases |

**SHAP units are log-odds, not probability.** Values sum to the raw margin
plus the base value — verified at 1.8e-05 against the margin and off by more
than 10 against `predict_proba`. Script 15 re-checks this on every run.

**Retrieval is vectorless.** The classifier has already named one of sixteen
classes, so `config/knowledge_map.py` maps class to document by dictionary
lookup. An unmapped class raises rather than returning the nearest wrong
chunk. Nothing to re-embed when a playbook is edited, and every citation is a
file and section.

**Inference is local by default.** A capture holds internal addressing and
service layout for a network the investigator is responsible for; sending it
out is a disclosure decision the tool should not make silently. Ollama for
development, `llama-cpp-python` for a packaged build (PyInstaller cannot
bundle a separate server process), Claude only on explicit opt-in. All three
sit behind one call signature.

---

## 6. Running it

```bash
python -m venv .venv && .venv\Scripts\activate     # Windows
pip install -r requirements.txt

python run_pipeline.py --skip-done                 # stages 01-12
python scripts/15_explain_shap.py                  # SHAP + deploy bundle
python scripts_other/rag_report.py --demo --call      # three panels, local model
python scripts_other/eval_reports.py --compare ollama llamacpp
```

Individual stages, resumable:

```bash
python scripts/05_train_binary.py --all-arms --resume
python scripts/09_train_multiclass.py --strategy random --resume
python snapshot.py --label before-changes          # copies artifacts/ results/ logs/
```

## 7. Repository layout

```
scripts/       00-16, the machine-learning pipeline, run in order; each writes its own log
scripts_other/ non-ML tools: RAG report and its evaluation, paper figures, architecture figures, paragraph checks, TRUSTLab conversion
config/        settings, knowledge map, feature glossary, LLM providers
src/           dataset readers, models, metrics, schema normalisation
knowledge/     retrieval corpus — see knowledge/INDEX.md for what to add
deploy/        the bundle a user interface loads (see deploy/README.md)
results/       every metric, table and confusion matrix
```

## 8. Limitations

- **Feature incompatibility is only partly resolved.** Scoring-time
  harmonisation (sentinels, dead features, flow timeout) recovers at most
  +0.05 macro recall; the rest needs retraining or a common re-extraction,
  which TRUSTLab's flow-only release does not allow.
- **Multiclass transfer covers eight of sixteen classes.** Script 13 scores
  only the TRUSTLab classes with a counterpart in the public datasets; the
  mapping is judgement and is written in the script. Recall is the only
  metric, because the external sets lack the other classes.
- **Temporal splitting was run with one architecture**, not five. The
  random-vs-temporal comparison uses XGBoost only.
- **PortScan is truncated at source** to 62.9%; its temporal result is
  indicative only.
- **One tool family.** All three datasets derive from CICFlowMeter-family
  extraction. Findings concern transfer between environments processed by
  related tooling.
- **The grounding eval is not yet trustworthy.** Five cases means one or two
  samples per check, and scores moved between consecutive runs.

## 9. Reproducibility

Seed 42 throughout. Every stage logs its git commit and warns when the working
tree is dirty. `run_pipeline.py` writes a per-run record with stage timings and
the commit that produced them. `snapshot.py` copies outputs alongside the code
state they came from.

## References

- Villafranca, A., Tasic, I. & Cano, M.-D. (2026). TRUSTLab dataset.
  *Frontiers in Computer Science* 8:1803271.
- Hossain, M. A. (2025). *EURASIP Journal on Information Security* 2025(28).
  Architecture set adapted from this work.
- Lundberg, S. & Lee, S.-I. (2017). A Unified Approach to Interpreting Model
  Predictions. *NeurIPS*.
- Lundberg, S. et al. (2020). From local explanations to global understanding
  with explainable AI for trees. *Nature Machine Intelligence* 2(1).
