## Table 24a -- XGBoost before and after hyperparameter tuning

Initial = the model reported in Tables 19 and 24. Tuned = the deployed model.
Same 66 features, same leakage-safe splits, same 280,063 test flows.

| Class / Metric | Initial | Tuned | Change |
|---|---|---|---|
| API | 0.999 | 0.999 | -0.000 |
| Benign | 0.979 | 0.987 | +0.009 |
| Bruteforce | 0.944 | 0.945 | +0.001 |
| BufferOverflow | 0.802 | 0.802 | +0.000 |
| C2Beaconing | 0.950 | 0.953 | +0.003 |
| DDoS | 0.993 | 0.995 | +0.001 |
| DNS | 1.000 | 1.000 | +0.000 |
| DoS | 0.671 | 0.686 | +0.015 |
| Evasion | 0.998 | 0.998 | -0.000 |
| Exfiltration | 1.000 | 0.999 | -0.000 |
| Exploitation | 0.784 | 0.790 | +0.006 |
| MITM | 0.998 | 0.998 | +0.000 |
| PortScan | 0.967 | 0.992 | +0.025 |
| Slowloris | 0.764 | 0.765 | +0.001 |
| TLSSSL | 0.983 | 0.985 | +0.002 |
| WebBased | 0.995 | 0.994 | -0.001 |
| **Accuracy** | 0.9313 | 0.9351 | +0.0038 |
| **Macro F1** | 0.9267 | 0.9305 | +0.0038 |
| **Weighted F1** | 0.9311 | 0.9354 | +0.0042 |
| **External transfer, mean exact** | 0.147 | 0.203 | +0.056 |

Tuning: Optuna, 30 trials, selected on validation macro F1 (15% leakage-safe split of the training data); the test set was used once, after selection. Changed hyperparameters (initial -> tuned): boosting rounds 400 -> 132 (early stopping), max_depth 10 -> 13, learning_rate 0.08 -> 0.129, min_child_weight 5 -> 3.59, subsample 0.8 -> 0.92, colsample_bytree 0.8 -> 0.64, gamma 0 -> 1.40, reg_alpha 0 -> 1.57, reg_lambda 1 -> 0.71, max_bin 256 -> 512, extra class weight on DoS, Slowloris, Exploitation and BufferOverflow 1.0 -> 1.71.

Macro-F1 gain 95% bootstrap CI +0.0033 to +0.0044; McNemar p = 1.4e-53 (2,936 flows corrected, 1,871 newly wrong). The gain is significant but small; DoS/Slowloris and Exploitation/BufferOverflow remain the hard pairs.
