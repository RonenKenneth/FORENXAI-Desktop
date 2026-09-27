# Thesis tables -- 66-feature rerun, 2026-09-21

All numbers below are from the 66-feature pipeline. The eight Active/Idle
columns TRUSTLab exports without populating were removed from the shared
feature contract and all twenty models retrained. The 74-feature versions of
these tables are archived in new_deploy_gpu_74feat/.

Numbering note: this file numbers the tables 14 to 24; the thesis numbers the
same tables 16 to 26. This file's Table 14 is the thesis's Table 16.

## Table 14 -- binary training time and internal validation

| Configuration of Dataset | Model | Seconds | Training records | Accuracy | F1 | F2 | Benign recall |
|---|---|---|---|---|---|---|---|
| Combined | XGBoost | 4.0 | 679,999 | 0.9882 | 0.9881 | 0.9828 | 0.9971 |
| Combined | MLP | 251.5 | 679,999 | 0.9831 | 0.9830 | 0.9778 | 0.9919 |
| Combined | CNN1D | 317.5 | 679,999 | 0.9852 | 0.9851 | 0.9807 | 0.9928 |
| Combined | CNN-BiLSTM | 606.8 | 679,999 | 0.9839 | 0.9838 | 0.9777 | 0.9941 |
| Combined | LSTM | 1,167.1 | 679,999 | 0.9827 | 0.9825 | 0.9773 | 0.9915 |
| CSE-CIC-IDS2018 | XGBoost | 4.0 | 680,000 | 0.9743 | 0.9738 | 0.9624 | 0.9937 |
| CSE-CIC-IDS2018 | MLP | 346.0 | 680,000 | 0.9690 | 0.9683 | 0.9563 | 0.9895 |
| CSE-CIC-IDS2018 | CNN1D | 374.5 | 680,000 | 0.9721 | 0.9715 | 0.9585 | 0.9942 |
| CSE-CIC-IDS2018 | CNN-BiLSTM | 334.6 | 680,000 | 0.9686 | 0.9678 | 0.9550 | 0.9905 |
| CSE-CIC-IDS2018 | LSTM | 1,158.9 | 680,000 | 0.9680 | 0.9673 | 0.9554 | 0.9883 |
| TII-SSRC-23 | XGBoost | 1.6 | 341,106 | 0.9949 | 0.9974 | 0.9959 | 1.0000 |
| TII-SSRC-23 | MLP | 71.4 | 341,106 | 0.9970 | 0.9985 | 0.9976 | 0.9949 |
| TII-SSRC-23 | CNN1D | 205.2 | 341,106 | 0.9989 | 0.9994 | 0.9991 | 0.9949 |
| TII-SSRC-23 | CNN-BiLSTM | 171.9 | 341,106 | 0.9955 | 0.9977 | 0.9964 | 0.9949 |
| TII-SSRC-23 | LSTM | 125.3 | 341,106 | 0.8386 | 0.9119 | 0.8664 | 0.8718 |

Subtotals: Combined 2,346.9 s, CSE-CIC-IDS2018 2,218.0 s, TII-SSRC-23 575.4 s; binary total 5,140.3 s.
Validation is on each configuration's own held-out 15% at threshold 0.5, not on TRUSTLab.

NOTE on the Seconds column. The chain that produced this run trained all five
models inside one process per arm, and every model that ran after four PyTorch
models was slowed sharply: the three binary XGBoosts took 98.2, 75.9 and 10.5
seconds, the multiclass XGBoost 2,002.8, and the TII-SSRC-23 LSTM 1,048.3. Each
was retrained on its own afterwards and returned to normal -- 4.0, 4.0, 1.3,
77.3 and 119.8 seconds respectively -- with metrics identical to the last
decimal and, for the multiclass XGBoost, a byte-identical model file. The cause
is PyTorch's caching allocator holding GPU memory after each model finishes,
which leaves XGBoost unable to obtain clean GPU memory; releasing it before
XGBoost runs restores the normal time, which is how the cause was confirmed. The
figures in the tables are the clean standalone timings. The eleven other neural
models were within 20 percent of their 74-feature per-epoch rates and were left
as measured.

Subtotals: Combined 2,346.9 s, CSE-CIC-IDS2018 2,218.0 s, TII-SSRC-23 575.4 s; binary total 5,140.3 s.
Grand total across both experiments 9,215.1 s = 2.56 h, of which the four
XGBoost models are 86.9 s (0.94 percent).

TII-SSRC-23 LSTM is the one model whose validation changed materially
(accuracy 0.9841 to 0.8386, benign recall 0.9897 to 0.8718). It early-stopped at
epoch 8. Retraining reproduced every metric exactly, so the figure is
deterministic and quotable. The loss trace shows overfitting, not a premature
stop: validation loss bottomed at 0.3267 and was worse at epoch 6 than at epoch
1 while training loss kept falling. The combined arm's LSTM reached 0.0196 under
the same contract, because it has 400,000 benign rows against this arm's 1,301 --
which is the control result this arm exists to produce.

## Table 15 -- multiclass training time

| Model | Seconds | h:mm:ss | Training records | Relative cost (XGBoost = 1.0) | Macro F1 (validation) |
|---|---|---|---|---|---|
| XGBoost | 77.3 | 0:01:17 | 951,944 | 1.0x | 0.9206 |
| MLP | 340.9 | 0:05:41 | 951,944 | 4.4x | 0.9155 |
| CNN1D | 500.4 | 0:08:20 | 951,944 | 6.5x | 0.9202 |
| CNN-BiLSTM | 1,129.3 | 0:18:49 | 951,944 | 14.6x | 0.9204 |
| LSTM | 2,026.9 | 0:33:47 | 951,944 | 26.2x | 0.9080 |
| Total | 4,074.8 | 1:07:55 | - | - | - |


## Table 16 -- early stopping, binary experiment

| Configuration of Dataset | Model | Training unit | Maximum configured | Actual run |
|---|---|---|---|---|
| Combined | XGBoost | Boosting rounds (trees) | 300 | 300 (no early stopping) |
| Combined | MLP | Epochs | 40 | 31 |
| Combined | CNN1D | Epochs | 40 | 35 |
| Combined | LSTM | Epochs | 40 | 40 (maximum reached) |
| Combined | CNN-BiLSTM | Epochs | 40 | 26 |
| CSE-CIC-IDS2018 | XGBoost | Boosting rounds (trees) | 300 | 300 (no early stopping) |
| CSE-CIC-IDS2018 | MLP | Epochs | 40 | 39 |
| CSE-CIC-IDS2018 | CNN1D | Epochs | 40 | 39 |
| CSE-CIC-IDS2018 | LSTM | Epochs | 40 | 39 |
| CSE-CIC-IDS2018 | CNN-BiLSTM | Epochs | 40 | 16 |
| TII-SSRC-23 | XGBoost | Boosting rounds (trees) | 300 | 300 (no early stopping) |
| TII-SSRC-23 | MLP | Epochs | 40 | 20 |
| TII-SSRC-23 | CNN1D | Epochs | 40 | 40 |
| TII-SSRC-23 | LSTM | Epochs | 40 | 8 |
| TII-SSRC-23 | CNN-BiLSTM | Epochs | 40 | 15 |

## Table 17 -- early stopping, multiclass experiment

| Model | Training unit | Maximum configured | Actual run |
|---|---|---|---|
| XGBoost | Boosting rounds (trees) | 400 | 400 (no early stopping) |
| MLP | Epochs | 50 | 36 |
| CNN1D | Epochs | 50 | 40 |
| LSTM | Epochs | 50 | 50 (maximum reached) |
| CNN-BiLSTM | Epochs | 50 | 39 |

## Table 18 -- external validation of the binary detectors on TRUSTLab

| Configuration | Model | Acc (Capped) | Prev-Adj Acc | Diff vs Baseline | F1 (Capped) | Prev-Adj F1 | F2 (Capped) | Prev-Adj F2 | ROC-AUC | Attack Recall | Benign Recall |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Combined | MLP | 0.4248 | 0.4951 | -0.4012 | 0.5764 | 0.4278 | 0.4692 | 0.4352 | 0.4685 | 0.4174 | 0.5361 |
| Combined | CNN1D | 0.4140 | 0.4730 | -0.4233 | 0.5653 | 0.3941 | 0.4579 | 0.3976 | 0.4908 | 0.4065 | 0.5277 |
| Combined | LSTM | 0.6657 | 0.4546 | -0.4417 | 0.7954 | 0.5317 | 0.7307 | 0.6318 | 0.5119 | 0.6932 | 0.2537 |
| Combined | CNN-BiLSTM | 0.6306 | 0.4831 | -0.4132 | 0.7668 | 0.5109 | 0.6907 | 0.5762 | 0.5162 | 0.6478 | 0.3730 |
| Combined | XGBoost | 0.3007 | 0.5073 | -0.3890 | 0.4253 | 0.3364 | 0.3212 | 0.3078 | 0.4869 | 0.2761 | 0.6693 |
| CSE-CIC-IDS2018 | MLP | 0.1345 | 0.5560 | -0.3403 | 0.1508 | 0.1170 | 0.1003 | 0.0822 | 0.3931 | 0.0820 | 0.9215 |
| CSE-CIC-IDS2018 | CNN1D | 0.1291 | 0.5449 | -0.3514 | 0.1429 | 0.1091 | 0.0948 | 0.0775 | 0.4188 | 0.0774 | 0.9049 |
| CSE-CIC-IDS2018 | LSTM | 0.1682 | 0.5852 | -0.3111 | 0.2071 | 0.1644 | 0.1406 | 0.1145 | 0.5084 | 0.1159 | 0.9527 |
| CSE-CIC-IDS2018 | CNN-BiLSTM | 0.0662 | 0.5655 | -0.3308 | 0.0099 | 0.0129 | 0.0062 | 0.0082 | 0.5801 | 0.0050 | 0.9847 |
| CSE-CIC-IDS2018 | XGBoost | 0.0880 | 0.5285 | -0.3678 | 0.0656 | 0.0651 | 0.0422 | 0.0459 | 0.4844 | 0.0341 | 0.8961 |
| TII-SSRC-23 | MLP | 0.3736 | 0.4544 | -0.4419 | 0.5215 | 0.3690 | 0.4141 | 0.3709 | 0.4429 | 0.3641 | 0.5162 |
| TII-SSRC-23 | CNN1D | 0.1045 | 0.3700 | -0.5263 | 0.1325 | 0.1138 | 0.0890 | 0.1013 | 0.3236 | 0.0730 | 0.5767 |
| TII-SSRC-23 | LSTM | 0.4213 | 0.5000 | -0.3963 | 0.5718 | 0.4187 | 0.4639 | 0.4196 | 0.4776 | 0.4121 | 0.5599 |
| TII-SSRC-23 | CNN-BiLSTM | 0.5295 | 0.4962 | -0.4001 | 0.6799 | 0.4702 | 0.5834 | 0.4997 | 0.5350 | 0.5330 | 0.4772 |
| TII-SSRC-23 | XGBoost | 0.1537 | 0.5222 | -0.3741 | 0.1944 | 0.1754 | 0.1322 | 0.1362 | 0.4085 | 0.1089 | 0.8250 |

Best: LSTM (CSE-CIC-IDS2018) at 0.5852 prevalence-adjusted accuracy, -0.3111 against the published 0.8963.
Mean ROC-AUC 0.4698; 10 of 15 at or below 0.5.
A trivial always-benign classifier scores 0.5714 at native prevalence; 1 of 15 detectors exceed it.

At 74 features the best was MLP (CSE-CIC-IDS2018) at 0.6364 and 4 of 15 beat the
trivial classifier. Removing the eight degenerate columns made external transfer
WORSE, not better: the neural detectors lost 0.07 to 0.08 prevalence-adjusted
accuracy while XGBoost gained 0.01 to 0.02. The removed columns were acting as a
duplicate duration channel the networks leaned on, so part of the earlier score
was an artefact rather than transferable signal.

## Table 19 -- multiclass per-class results, XGBoost

| Attack Class | Precision | Recall | F1-Score | Support |
|---|---|---|---|---|
| API | 0.999 | 0.999 | 0.999 | 16,000 |
| Benign | 0.979 | 0.978 | 0.979 | 40,004 |
| Bruteforce | 0.952 | 0.936 | 0.944 | 15,996 |
| BufferOverflow | 0.831 | 0.774 | 0.802 | 16,000 |
| C2Beaconing | 0.987 | 0.915 | 0.950 | 15,999 |
| DDoS | 0.991 | 0.996 | 0.993 | 16,007 |
| DNS | 1.000 | 1.000 | 1.000 | 16,000 |
| DoS | 0.837 | 0.560 | 0.671 | 16,024 |
| Evasion | 0.998 | 0.999 | 0.998 | 16,003 |
| Exfiltration | 1.000 | 0.999 | 1.000 | 16,008 |
| Exploitation | 0.715 | 0.867 | 0.784 | 16,004 |
| MITM | 0.999 | 0.998 | 0.998 | 16,050 |
| PortScan | 0.993 | 0.942 | 0.967 | 15,989 |
| Slowloris | 0.669 | 0.891 | 0.764 | 15,979 |
| TLSSSL | 0.986 | 0.980 | 0.983 | 16,000 |
| WebBased | 0.995 | 0.996 | 0.995 | 16,000 |
| Accuracy (micro avg) | 0.9313 | 0.9313 | 0.9313 | 280,063 |
| Macro avg | | | 0.9267 | |
| Weighted avg | | | 0.9311 | |

## Table 20 -- multiclass per-class results, CNN-BiLSTM

| Attack Class | Precision | Recall | F1-Score | Support |
|---|---|---|---|---|
| API | 0.996 | 1.000 | 0.998 | 16,000 |
| Benign | 0.996 | 0.972 | 0.984 | 40,004 |
| Bruteforce | 0.913 | 0.943 | 0.928 | 15,996 |
| BufferOverflow | 0.866 | 0.739 | 0.798 | 16,000 |
| C2Beaconing | 0.999 | 0.911 | 0.953 | 15,999 |
| DDoS | 0.958 | 0.996 | 0.977 | 16,007 |
| DNS | 0.999 | 0.998 | 0.999 | 16,000 |
| DoS | 0.762 | 0.574 | 0.655 | 16,024 |
| Evasion | 0.997 | 1.000 | 0.998 | 16,003 |
| Exfiltration | 0.999 | 0.999 | 0.999 | 16,008 |
| Exploitation | 0.691 | 0.879 | 0.774 | 16,004 |
| MITM | 1.000 | 0.997 | 0.998 | 16,050 |
| PortScan | 0.993 | 0.954 | 0.973 | 15,989 |
| Slowloris | 0.658 | 0.820 | 0.730 | 15,979 |
| TLSSSL | 0.999 | 0.970 | 0.984 | 16,000 |
| WebBased | 0.976 | 0.990 | 0.983 | 16,000 |
| Accuracy (micro avg) | 0.9258 | 0.9258 | 0.9258 | 280,063 |
| Macro avg | | | 0.9207 | |
| Weighted avg | | | 0.9261 | |

## Table 21 -- multiclass per-class results, CNN1D

| Attack Class | Precision | Recall | F1-Score | Support |
|---|---|---|---|---|
| API | 0.998 | 1.000 | 0.999 | 16,000 |
| Benign | 0.996 | 0.974 | 0.985 | 40,004 |
| Bruteforce | 0.925 | 0.938 | 0.932 | 15,996 |
| BufferOverflow | 0.865 | 0.742 | 0.798 | 16,000 |
| C2Beaconing | 0.999 | 0.906 | 0.950 | 15,999 |
| DDoS | 0.969 | 0.996 | 0.982 | 16,007 |
| DNS | 1.000 | 0.998 | 0.999 | 16,000 |
| DoS | 0.785 | 0.520 | 0.625 | 16,024 |
| Evasion | 0.997 | 0.999 | 0.998 | 16,003 |
| Exfiltration | 0.999 | 0.999 | 0.999 | 16,008 |
| Exploitation | 0.687 | 0.894 | 0.777 | 16,004 |
| MITM | 0.999 | 0.997 | 0.998 | 16,050 |
| PortScan | 0.990 | 0.967 | 0.978 | 15,989 |
| Slowloris | 0.640 | 0.857 | 0.733 | 15,979 |
| TLSSSL | 0.998 | 0.970 | 0.984 | 16,000 |
| WebBased | 0.987 | 0.984 | 0.985 | 16,000 |
| Accuracy (micro avg) | 0.9258 | 0.9258 | 0.9258 | 280,063 |
| Macro avg | | | 0.9202 | |
| Weighted avg | | | 0.9258 | |

## Table 22 -- multiclass per-class results, LSTM

| Attack Class | Precision | Recall | F1-Score | Support |
|---|---|---|---|---|
| API | 0.971 | 0.996 | 0.983 | 16,000 |
| Benign | 0.976 | 0.912 | 0.943 | 40,004 |
| Bruteforce | 0.879 | 0.920 | 0.899 | 15,996 |
| BufferOverflow | 0.839 | 0.754 | 0.794 | 16,000 |
| C2Beaconing | 0.981 | 0.891 | 0.934 | 15,999 |
| DDoS | 0.991 | 1.000 | 0.995 | 16,007 |
| DNS | 0.951 | 0.988 | 0.969 | 16,000 |
| DoS | 0.762 | 0.544 | 0.635 | 16,024 |
| Evasion | 0.999 | 0.994 | 0.996 | 16,003 |
| Exfiltration | 0.996 | 0.996 | 0.996 | 16,008 |
| Exploitation | 0.659 | 0.836 | 0.737 | 16,004 |
| MITM | 0.994 | 1.000 | 0.997 | 16,050 |
| PortScan | 0.988 | 0.991 | 0.989 | 15,989 |
| Slowloris | 0.645 | 0.830 | 0.726 | 15,979 |
| TLSSSL | 0.989 | 0.962 | 0.976 | 16,000 |
| WebBased | 0.968 | 0.957 | 0.963 | 16,000 |
| Accuracy (micro avg) | 0.9109 | 0.9109 | 0.9109 | 280,063 |
| Macro avg | | | 0.9083 | |
| Weighted avg | | | 0.9113 | |

## Table 23 -- multiclass per-class results, MLP

| Attack Class | Precision | Recall | F1-Score | Support |
|---|---|---|---|---|
| API | 0.990 | 1.000 | 0.995 | 16,000 |
| Benign | 0.995 | 0.966 | 0.980 | 40,004 |
| Bruteforce | 0.910 | 0.933 | 0.921 | 15,996 |
| BufferOverflow | 0.792 | 0.811 | 0.801 | 16,000 |
| C2Beaconing | 0.997 | 0.906 | 0.949 | 15,999 |
| DDoS | 0.946 | 0.996 | 0.970 | 16,007 |
| DNS | 1.000 | 0.998 | 0.999 | 16,000 |
| DoS | 0.736 | 0.575 | 0.646 | 16,024 |
| Evasion | 0.996 | 1.000 | 0.998 | 16,003 |
| Exfiltration | 0.996 | 0.999 | 0.998 | 16,008 |
| Exploitation | 0.710 | 0.782 | 0.744 | 16,004 |
| MITM | 1.000 | 0.996 | 0.998 | 16,050 |
| PortScan | 0.986 | 0.942 | 0.964 | 15,989 |
| Slowloris | 0.650 | 0.793 | 0.715 | 15,979 |
| TLSSSL | 0.985 | 0.978 | 0.982 | 16,000 |
| WebBased | 0.982 | 0.984 | 0.983 | 16,000 |
| Accuracy (micro avg) | 0.9204 | 0.9204 | 0.9204 | 280,063 |
| Macro avg | | | 0.9151 | |
| Weighted avg | | | 0.9207 | |

## Table 24 -- multiclass model comparison

| Model | Accuracy | Macro F1 | Weighted F1 | Rank |
|---|---|---|---|---|
| XGBoost | 0.9313 | 0.9267 | 0.9311 | 1 |
| CNN-BiLSTM | 0.9258 | 0.9207 | 0.9261 | 2 |
| CNN1D | 0.9258 | 0.9202 | 0.9258 | 3 |
| MLP | 0.9204 | 0.9151 | 0.9207 | 4 |
| LSTM | 0.9109 | 0.9083 | 0.9113 | 5 |

At 74 features XGBoost led at 0.9341 accuracy / 0.9293 macro F1. The ordering is
unchanged and the values moved by under 0.01, which is the expected result: the
removed columns had zero SHAP contribution inside TRUSTLab, so dropping them could
not affect intra-TRUSTLab performance.

## Reverse transfer of the multiclass models

| Model | TRUSTLab Reference | CSE-CIC-IDS2018 Exact | TII-SSRC-23 Exact | Mean External Exact | Mean External Family | Gap |
|---|---|---|---|---|---|---|
| CNN1D | 0.866 | 0.103 | 0.342 | 0.223 | 0.231 | 0.643 |
| MLP | 0.866 | 0.167 | 0.149 | 0.158 | 0.241 | 0.708 |
| CNN-BiLSTM | 0.874 | 0.204 | 0.102 | 0.153 | 0.160 | 0.721 |
| XGBoost | 0.875 | 0.134 | 0.160 | 0.147 | 0.217 | 0.728 |
| LSTM | 0.853 | 0.113 | 0.061 | 0.087 | 0.185 | 0.766 |

## Diagnostics behind Table 18 (66 features)

Why the binary detectors lose accuracy on TRUSTLab. Every figure here is
reproducible from external_shift_diagnostic.json and clip_diagnostic.csv.

| Diagnostic | Question | Result at 66 features |
|---|---|---|
| ROC-AUC | Calibration, or no signal? | Mean 0.4698; 10 of 15 at or below 0.5 |
| Target topline | Are the features adequate for TRUSTLab? | Same 66 features trained on TRUSTLab reach 0.9313 accuracy (Table 24) |
| Domain classifier | How far apart are the domains? | Separation AUC 1.0000, proxy A-distance 2.000, the maximum |
| Feature attribution | Which features separate them? | Packet Length Min 0.83, Dst Port 0.12 |
| Attack semantics | Does familiarity help? | Families present in training 0.2757, absent 0.2896 -- no advantage |
| Range clipping | Out-of-range input? | Mean weighted ROC-AUC 0.4706 to 0.4909 when clipped to plus or minus 5 training SD |
| Failure shape | One axis or two classes? | corr(benign recall, mean attack detection) = -0.917 |

Feature shift under each arm's own scaler, TRUSTLab against training:
Combined 17 of 66 features beyond 3 training SD
(10 beyond 10), CSE-CIC-IDS2018
25 (17),
TII-SSRC-23 21 (15).

The domain classifier still separates the two corpora perfectly after the eight
degenerate columns are removed, so that defect was never the cause of the
transfer failure -- only a contaminant on top of it. Clipping moves the mean
ROC-AUC toward 0.5 rather than away from it, which is what removing a weak
anti-correlated contribution looks like, not the recovery of signal.


## Attribution formulation -- the four equations

Methodology, not a result: these belong with the TreeSHAP configuration table
in Chapter 3, not beside Table 30.

| Eq. | Expression | Defines |
|---|---|---|
| (1) | phi_j = SUM over S subset of F\{j} of [ \|S\|! (p-\|S\|-1)! / p! ] * [ val(S union {j}) - val(S) ] | The Shapley value: a feature's average marginal contribution across all orderings |
| (2) | f_k(x) = phi_0k + SUM over j=1..66 of phi_jk(x) | The additivity identity verified on this model, in margin space |
| (3) | I_jk(R) = (1/\|R\|) SUM over i in R of \| phi_jk(i) \| ,  R_k = { i : y_i = k } | The global profile and the scope it is computed over |
| (4) | O(T L 2^M) -> O(T L D^2) | The complexity reduction that makes exact computation tractable |

F is the feature set, p = 66; S a coalition of known features; val() the value
function under the path-dependent estimator; f_k the raw margin for class k;
phi_0k the base value; y_i the true class of flow i; T trees, L maximum
leaves, D maximum depth, M features.

Equation (1) establishes that the attribution is uniquely determined -- the
only allocation satisfying efficiency, symmetry, dummy and additivity, which
is the reason for preferring it to the gain-based importance XGBoost provides
at no cost. Equation (2) forecloses the most common misreading by stating that
contributions sum to the class margin, not to the predicted probability, the
softmax transformation being non-linear. Equation (3) makes the aggregation
scope an explicit design decision rather than an implementation detail:
profiles are reported over R_k, the flows whose true class is k, because the
unrestricted set is dominated by evidence for excluding the class rather than
identifying it. Equation (4) reconciles exactness with tractability at 66
features.

Applied to the deployed classifier over a stratified sample of 8,000 test
flows, the procedure yields attributions satisfying (2) to a maximum deviation
of 1.55e-05 against a tolerance of 1e-03, a reconstruction recovering the
predicted class in 1.0000 of rows, exactly zero attribution for the five
features on which no tree splits, and a displayed set of six features per
class carrying 0.7275 of total attribution mass -- computed in 2.8 seconds
rather than the 3.7e19 terms per flow per class that direct evaluation of (1)
would require.


## Table 28 -- per-class attribution, six leading features

Mean |SHAP| in log-odds, over the flows whose TRUE class is the row's class.
Stratified sample of 8,000 test flows, 500 per class.

| Class | 1 | 2 | 3 | 4 | 5 | 6 |
|---|---|---|---|---|---|---|
| API | Bwd Bulk Rate Avg (3.45) | FIN Flag Count (1.47) | Packet Length Max (1.30) | Fwd Bulk Rate Avg (0.84) | Fwd Packet Length Max (0.80) | Bwd Packet Length Max (0.72) |
| Benign | Fwd Bytes/Bulk Avg (0.97) | Dst Port (0.95) | Bwd Bytes/Bulk Avg (0.81) | Down/Up Ratio (0.80) | Packet Length Max (0.59) | Average Packet Size (0.39) |
| Bruteforce | Bwd Packet Length Max (0.89) | Down/Up Ratio (0.77) | Fwd Packet Length Max (0.73) | Packet Length Max (0.60) | Fwd Packet Length Std (0.56) | Bwd Bulk Rate Avg (0.51) |
| BufferOverflow | Bwd Packet Length Std (3.56) | Bwd Packet Length Max (0.75) | Down/Up Ratio (0.54) | Bwd Packet Length Mean (0.47) | Average Packet Size (0.37) | Fwd Bytes/Bulk Avg (0.32) |
| C2Beaconing | Bwd Bulk Rate Avg (1.00) | Bwd PSH Flags (0.91) | Bwd Init Win Bytes (0.62) | Bwd Bytes/Bulk Avg (0.60) | PSH Flag Count (0.51) | Down/Up Ratio (0.40) |
| DDoS | Bwd Packet Length Max (4.41) | Flow Bytes/s (1.80) | SYN Flag Count (0.99) | Dst Port (0.90) | Bwd Packet Length Mean (0.45) | Average Packet Size (0.44) |
| DNS | Fwd Packet Length Min (6.53) | Packet Length Min (2.48) | Bwd Packet Length Min (0.76) | Dst Port (0.36) | Fwd Packet/Bulk Avg (0.35) | Average Packet Size (0.34) |
| DoS | Fwd Packet Length Max (1.71) | Bwd Header Length (1.12) | Bwd Bulk Rate Avg (0.35) | Dst Port (0.21) | Fwd Packet Length Mean (0.20) | Subflow Bwd Bytes (0.15) |
| Evasion | Dst Port (5.54) | Fwd Bytes/Bulk Avg (1.97) | RST Flag Count (0.32) | Down/Up Ratio (0.29) | Bwd Bytes/Bulk Avg (0.23) | Average Packet Size (0.23) |
| Exfiltration | Fwd Packet/Bulk Avg (3.06) | Dst Port (2.66) | Average Packet Size (0.81) | Fwd Packet Length Mean (0.58) | Packet Length Min (0.47) | Fwd Packet Length Min (0.40) |
| Exploitation | Down/Up Ratio (0.80) | RST Flag Count (0.25) | Fwd Bytes/Bulk Avg (0.22) | Bwd Packet Length Min (0.19) | Fwd Bulk Rate Avg (0.15) | Bwd Packet Length Max (0.15) |
| MITM | Bwd Bytes/Bulk Avg (4.60) | Dst Port (1.47) | Fwd Packet Length Max (0.71) | SYN Flag Count (0.67) | Average Packet Size (0.64) | Packet Length Min (0.51) |
| PortScan | Bwd Packet Length Max (3.80) | Dst Port (1.15) | Bwd Packet Length Mean (0.65) | ACK Flag Count (0.31) | RST Flag Count (0.28) | SYN Flag Count (0.25) |
| Slowloris | Fwd Packet Length Max (1.70) | Bwd Bulk Rate Avg (0.29) | Subflow Bwd Bytes (0.23) | Flow IAT Min (0.19) | Dst Port (0.17) | Fwd Packet Length Mean (0.17) |
| TLSSSL | Bwd Packet Length Max (1.78) | Bwd Packet Length Std (1.76) | Bwd Bulk Rate Avg (1.05) | Fwd Packet Length Max (0.53) | Packet Length Max (0.50) | Fwd Packet/Bulk Avg (0.39) |
| WebBased | Fwd Packet Length Std (1.74) | Fwd Packet Length Max (1.37) | Subflow Fwd Bytes (0.94) | Bwd Packet Length Max (0.75) | Dst Port (0.66) | Fwd Bytes/Bulk Avg (0.57) |

### Which rows are averaged, and why it matters

For class k the model produces a margin, and TreeSHAP splits that margin across
the 66 features. Averaging those splits over EVERY sampled flow answers "which
features move the class-k score across all traffic" -- and since 15 of the 16
classes in the sample are not k, that average is dominated by evidence for
ruling k out. Restricting the average to the flows that ARE class k answers
"what pushed these flows to this class", which is what this table reports and
what the interface displays.

Both are written to shap_global.json, as `per_class_own` (this table) and
`per_class` (all rows, the input to Table 30). The difference is not cosmetic:

| | All rows | The class's own rows |
|---|---|---|
| Features with positive mean signed SHAP | 2 to 18 of 66 | 23 to 55 of 66 |
| Sign of the leading feature | negative for all 16 classes | positive for all 16 classes |
| Top three features identical | -- | changed for 13 of 16 classes |
| Spearman rank correlation of the full 66-feature profile | 0.857 to 0.991 | |

DoS is the clearest case. Fwd Packet Length Max carries mean signed -2.0846
over all flows and +1.7110 over DoS flows: the same feature, the same run, and
opposite readings. The first is true of traffic in general and says the feature
rules DoS out; the second says it is what identifies DoS. Only the second
belongs under a heading that names the class.

Because the magnitude ranking is preserved (Spearman 0.86 to 0.99), Table 30 is
computed from the all-row profile and is unchanged: DDoS/PortScan remains the
most similar pair at 0.959 and DoS/Slowloris second at 0.916.
scripts/check_shap_aggregation.py reproduces the comparison in full.


## Table 30 -- attribution overlap and observed confusion

Ten class pairs: the nine confused above 1%, and the most similar pair of all
120 for contrast.

| Similarity rank (of 120) | Class pair | Importance correlation | Shared top-10 | Confusion |
|---|---|---|---|---|
| 2 | DoS / Slowloris | 0.916 | 7 / 10 | 44.0% |
| 27 | BufferOverflow / Exploitation | 0.337 | 4 / 10 | 21.9% |
| 30 | C2Beaconing / Exploitation | 0.326 | 4 / 10 | 5.0% |
| 56 | Benign / PortScan | 0.199 | 5 / 10 | 4.9% |
| 14 | BufferOverflow / C2Beaconing | 0.472 | 5 / 10 | 3.4% |
| 6 | Bruteforce / Exploitation | 0.594 | 7 / 10 | 3.2% |
| 35 | Bruteforce / BufferOverflow | 0.307 | 6 / 10 | 2.1% |
| 31 | Bruteforce / TLSSSL | 0.324 | 6 / 10 | 1.5% |
| 12 | Benign / Exploitation | 0.499 | 4 / 10 | 1.4% |
| 1 | DDoS / PortScan | 0.959 | 7 / 10 | 0.9% |

Of the 120 pairs, 93 are never confused and the median confusion is 0.0%.
Similarity is the Pearson correlation between the classes' per-feature mean
|SHAP| vectors; confusion is the larger of the two directions as a share of
the true class. Complete matrix in shap/pair_matrix_random.json.

### Purpose

The per-class attributions allow one further question: are the classes the
model confuses the same ones it decides using the same features? Each class is
summarised by an attribution profile -- its mean |SHAP| across the 66 features
-- and the similarity of two classes is the Pearson correlation between their
profiles. This was computed for all 120 class pairs, so any single pair can be
read against the rest rather than on its own. Because these profiles are
dominated by a few large attributions, every result was rechecked with
Spearman rank correlation, which gives all 66 features equal weight. Table 30
lists the nine pairs confused above 1%, plus the most similar pair of all 120
for contrast.

### Results

Similarity and confusion turn out to be largely unrelated. Across the 120
pairs they correlate at only 0.35 (Pearson) and 0.26 (Spearman), and the nine
confused pairs occupy similarity ranks from second to fifty-sixth. The
clearest case is DDoS and PortScan: the most similar pair in the model at
0.959, sharing seven of their ten leading features, yet confused in just 0.9%
of cases. In the other direction, BufferOverflow and Exploitation are confused
in 21.9% of cases while ranking outside the ten most similar pairs under
either measure -- twenty-seventh under Pearson, fifteenth under Spearman. DoS
and Slowloris, at 0.916 with seven shared features and 44.0% confusion, are
the only pair where high similarity and high confusion occur together.

### Why, and what this does not show

This is the expected behaviour of the measure rather than a surprise, and it
marks the limit of what attribution analysis can establish. A mean |SHAP|
profile records which features a class is decided by, but discards the sign of
each contribution and the region of the feature range in which it applies. Two
classes can therefore depend on exactly the same features and still be
perfectly separable if they sit at opposite ends of them -- which is the case
for DDoS and PortScan, both driven by packet-length and bulk-rate features,
one at high volume and the other at minimal payload. Confusability depends
instead on whether the class-conditional distributions overlap in the regions
the decision boundary separates, so shared feature usage is a necessary
condition for confusion but not a sufficient one. The high overlap between DoS
and Slowloris is consistent with their difficulty, since both are
denial-of-service traffic distinguished mainly by rate and so share both the
features and the range, but the overlap alone does not account for the 44.0%
figure. The confusion between BufferOverflow and Exploitation arises from a
distributional overlap that attribution profiles do not capture at all, and
identifying it would require comparing the classes in feature space rather
than in attribution space.

### Structure of the confusion

Confusion is rare and concentrated: 93 of the 120 pairs are never confused,
the median is 0.0%, and only two pairs exceed 10%. It is also of two kinds.
DoS and Slowloris form a closed pair, each confused principally with the
other, whereas Exploitation appears in four of the nine confused pairs and
BufferOverflow and Bruteforce in three each -- classes that are diffusely
confusable across several counterparts rather than tied to a single partner.
