# Thesis tables -- tuned XGBoost, 2026-09-25

Only XGBoost changed. The four deep models, the binary experiment (Tables 14, 16, 18),
the 66-feature contract, the scaler and the splits are untouched. Source: scripts/18_tune_xgboost.py,
results/finetune/xgb_tuning_random.json, results/finetune/xgb_test_comparison_random.json.

## NEW Table 17a -- XGBoost hyperparameters, baseline vs tuned

Search: Optuna TPE, 30 trials on a stratified 30% subsample of the training part, each
trial early-stopped (50 rounds) on the 15% leakage-safe validation split. Selection metric:
validation macro F1. The test split was not read during the search.

| Hyperparameter | Search range | Baseline | Tuned |
|---|---|---|---|
| n_estimators (boosting rounds) | early stopping, max 3000 | 400 (fixed) | 132 (early stopping) |
| learning_rate | 0.03 - 0.2 (log) | 0.08 | 0.1291 |
| max_depth | 6 - 14 | 10 | 13 |
| min_child_weight | 1 - 20 (log) | 5 | 3.587 |
| subsample | 0.6 - 1.0 | 0.8 | 0.918 |
| colsample_bytree | 0.5 - 1.0 | 0.8 | 0.643 |
| gamma | 0 - 5 | 0 | 1.400 |
| reg_lambda (L2) | 0.5 - 10 (log) | 1 | 0.712 |
| reg_alpha (L1) | 0.001 - 2 (log) | 0 | 1.571 |
| max_bin | 256, 512 | 256 | 512 |
| Extra weight on DoS, Slowloris, Exploitation, BufferOverflow | 1.0 - 3.0 | 1.0 | 1.711 |
| Class weighting | fixed | balanced | balanced x extra weight |
| Objective / eval metric | fixed | multi:softprob / mlogloss | multi:softprob / mlogloss |

| Metric | Baseline | Tuned | Change |
|---|---|---|---|
| Validation macro F1 | 0.9206 | 0.9299 | +0.0092 |
| Test accuracy | 0.9313 | 0.9351 | +0.0038 |
| Test macro F1 | 0.9267 | 0.9305 | +0.0038 (95% bootstrap CI +0.0033 to +0.0044) |

McNemar on the 280,063 test flows: baseline right / tuned wrong 1,871; baseline wrong / tuned right 2,936; p = 1.4e-53.
The gain is statistically significant but small (+0.4 pp). DoS / Slowloris and Exploitation / BufferOverflow remain the hard pairs: flow statistics alone do not separate them well.

## Table 15 -- XGBoost row (replace)

| Model | Seconds | Training records | Macro F1 (validation) |
|---|---|---|---|
| XGBoost (tuned) | 53.9 (refit; search 692 s extra) | 951,944 | 0.9299 |

Relative cost column: divide each deep model's seconds by the new XGBoost seconds, or keep 77.3 s as reference and footnote it.

## Table 17 -- XGBoost row (replace)

| Model | Training unit | Maximum configured | Actual run |
|---|---|---|---|
| XGBoost | Boosting rounds (trees) | 3000 | 132 (early stopping, patience 50) |

## Table 19 -- multiclass per-class results, XGBoost (tuned)

| Attack Class | Precision | Recall | F1-Score | Support |
|---|---|---|---|---|
| API | 0.999 | 1.000 | 0.999 | 16,000 |
| Benign | 0.999 | 0.976 | 0.987 | 40,004 |
| Bruteforce | 0.959 | 0.931 | 0.945 | 15,996 |
| BufferOverflow | 0.845 | 0.763 | 0.802 | 16,000 |
| C2Beaconing | 1.000 | 0.911 | 0.953 | 15,999 |
| DDoS | 0.993 | 0.996 | 0.995 | 16,007 |
| DNS | 1.000 | 1.000 | 1.000 | 16,000 |
| DoS | 0.825 | 0.587 | 0.686 | 16,024 |
| Evasion | 0.998 | 0.999 | 0.998 | 16,003 |
| Exfiltration | 1.000 | 0.999 | 0.999 | 16,008 |
| Exploitation | 0.702 | 0.902 | 0.790 | 16,004 |
| MITM | 0.999 | 0.998 | 0.998 | 16,050 |
| PortScan | 0.991 | 0.992 | 0.992 | 15,989 |
| Slowloris | 0.679 | 0.875 | 0.765 | 15,979 |
| TLSSSL | 0.992 | 0.978 | 0.985 | 16,000 |
| WebBased | 0.995 | 0.993 | 0.994 | 16,000 |
| Accuracy (micro avg) | 0.9351 | 0.9351 | 0.9351 | 280,063 |
| Macro avg | | | 0.9305 | |
| Weighted avg | | | 0.9354 | |

## Table 24 -- multiclass model comparison

| Model | Accuracy | Macro F1 | Weighted F1 | Rank |
|---|---|---|---|---|
| XGBoost | 0.9351 | 0.9305 | 0.9354 | 1 |
| CNN-BiLSTM | 0.9258 | 0.9207 | 0.9261 | 2 |
| CNN1D | 0.9258 | 0.9202 | 0.9258 | 3 |
| MLP | 0.9204 | 0.9151 | 0.9207 | 4 |
| LSTM | 0.9109 | 0.9083 | 0.9113 | 5 |

## Reverse transfer of the multiclass models

| Model | TRUSTLab Reference | CSE-CIC-IDS2018 Exact | TII-SSRC-23 Exact | Mean External Exact | Mean External Family | Gap |
|---|---|---|---|---|---|---|
| CNN1D | 0.866 | 0.103 | 0.342 | 0.223 | 0.231 | 0.643 |
| XGBoost | 0.884 | 0.208 | 0.199 | 0.203 | 0.243 | 0.680 |
| MLP | 0.866 | 0.167 | 0.149 | 0.158 | 0.241 | 0.708 |
| CNN-BiLSTM | 0.874 | 0.204 | 0.102 | 0.153 | 0.160 | 0.721 |
| LSTM | 0.853 | 0.113 | 0.061 | 0.087 | 0.185 | 0.766 |

External transfer is still far below the TRUSTLab reference for every model; tuning does not change that conclusion.

## Table 28 -- per-class attribution, six leading features (tuned model)

Mean |SHAP| in log-odds, over the flows whose TRUE class is the row's class.

| Class | 1 | 2 | 3 | 4 | 5 | 6 |
|---|---|---|---|---|---|---|
| API | Bwd Bulk Rate Avg (2.96) | FIN Flag Count (1.34) | Packet Length Max (0.77) | Bwd Packet/Bulk Avg (0.61) | Packet Length Variance (0.52) | Fwd Packet Length Max (0.49) |
| Benign | Fwd Bytes/Bulk Avg (1.18) | Dst Port (0.73) | Down/Up Ratio (0.63) | Bwd Bytes/Bulk Avg (0.42) | Packet Length Max (0.37) | Packet Length Min (0.33) |
| Bruteforce | Bwd Packet Length Max (0.80) | Down/Up Ratio (0.76) | Bwd Bulk Rate Avg (0.61) | Packet Length Max (0.60) | Fwd Packet Length Max (0.53) | Fwd Packet Length Std (0.49) |
| BufferOverflow | Bwd Packet Length Std (2.62) | Bwd Packet Length Max (0.91) | Bwd Packet Length Mean (0.71) | Bwd Segment Size Avg (0.35) | Down/Up Ratio (0.34) | Average Packet Size (0.21) |
| C2Beaconing | Bwd PSH Flags (1.12) | Bwd Bulk Rate Avg (0.70) | Bwd Bytes/Bulk Avg (0.69) | Bwd Init Win Bytes (0.58) | PSH Flag Count (0.36) | Average Packet Size (0.34) |
| DDoS | Bwd Packet Length Max (3.53) | Bwd Packet Length Mean (1.07) | SYN Flag Count (0.86) | Flow Bytes/s (0.79) | Dst Port (0.45) | Bwd Packet Length Min (0.44) |
| DNS | Fwd Packet Length Min (5.96) | Packet Length Min (2.57) | Bwd Packet Length Min (0.95) | Dst Port (0.26) | Bwd Packet/Bulk Avg (0.26) | Packet Length Mean (0.22) |
| DoS | Fwd Packet Length Max (1.09) | Bwd Header Length (0.85) | Fwd Packet Length Mean (0.48) | Subflow Bwd Bytes (0.25) | Fwd Segment Size Avg (0.20) | Dst Port (0.20) |
| Evasion | Dst Port (4.91) | Fwd Bytes/Bulk Avg (1.29) | RST Flag Count (0.63) | Average Packet Size (0.54) | Bwd Bytes/Bulk Avg (0.36) | Fwd Bulk Rate Avg (0.23) |
| Exfiltration | Fwd Packet/Bulk Avg (2.62) | Dst Port (2.08) | Fwd Packet Length Mean (0.70) | Average Packet Size (0.66) | Packet Length Min (0.61) | Bwd Bulk Rate Avg (0.42) |
| Exploitation | Down/Up Ratio (0.50) | RST Flag Count (0.36) | Bwd Packet Length Min (0.29) | Fwd Bytes/Bulk Avg (0.22) | Bwd Packet Length Max (0.15) | Fwd Bulk Rate Avg (0.14) |
| MITM | Bwd Bytes/Bulk Avg (3.93) | Dst Port (1.36) | Packet Length Min (0.82) | Fwd Packet Length Max (0.53) | Fwd Packet Length Mean (0.34) | Bwd Header Length (0.32) |
| PortScan | Bwd Packet Length Max (3.50) | Bwd Packet Length Mean (1.02) | Dst Port (0.64) | RST Flag Count (0.24) | Flow Bytes/s (0.23) | Bwd Packet Length Min (0.21) |
| Slowloris | Fwd Packet Length Max (1.47) | Subflow Bwd Bytes (0.24) | Bwd Bulk Rate Avg (0.19) | Dst Port (0.16) | Flow IAT Min (0.14) | Subflow Fwd Packets (0.11) |
| TLSSSL | Bwd Packet Length Std (1.44) | Bwd Bulk Rate Avg (1.18) | Bwd Packet Length Max (1.16) | Packet Length Max (0.50) | Fwd Packet Length Max (0.37) | Fwd Packet/Bulk Avg (0.37) |
| WebBased | Fwd Packet Length Max (1.81) | Fwd Packet Length Std (1.37) | Subflow Fwd Bytes (0.65) | Bwd Packet Length Max (0.42) | Dst Port (0.37) | Fwd Header Length (0.33) |

## Table 30 -- attribution overlap and observed confusion (tuned model)

| Similarity rank (of 120) | Class pair | Importance correlation | Shared top-10 | Confusion |
|---|---|---|---|---|
| 2 | DoS / Slowloris | 0.897 | 8 / 10 | 41.3% |
| 54 | BufferOverflow / Exploitation | 0.191 | 5 / 10 | 23.7% |
| 40 | C2Beaconing / Exploitation | 0.249 | 7 / 10 | 5.3% |
| 9 | Bruteforce / Exploitation | 0.461 | 5 / 10 | 3.9% |
| 16 | BufferOverflow / C2Beaconing | 0.414 | 5 / 10 | 3.6% |
| 48 | Bruteforce / BufferOverflow | 0.225 | 4 / 10 | 2.5% |
| 6 | Benign / Exploitation | 0.606 | 3 / 10 | 1.5% |
| 19 | Bruteforce / TLSSSL | 0.408 | 6 / 10 | 1.2% |
| 1 | DDoS / PortScan | 0.971 | 7 / 10 | 0.7% |

Of the 120 pairs, 92 are never confused. Pairs listed: confusion above 1%, plus the most similar pair.
