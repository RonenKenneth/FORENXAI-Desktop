"""
harmonise.py
------------
Scoring-time feature harmonisation for the external validations (scripts 06
and 13). Nothing here retrains a model or changes a training set: it makes the
TEST data speak the training data's dialect where the two datasets are known
to encode the same thing differently, so what remains of the transfer gap can
be attributed to the traffic rather than to the exporters.

Three documented incompatibilities (see script 13's header):

  sentinels   CSE-CIC-IDS2018 writes -1 in the initial-window columns
              (17.3% of FWD Init Win Bytes, 52.1% of Bwd Init Win Bytes)
              where TRUSTLab is never negative. A feature that is never
              negative in the training data has its negative test values set
              to 0.
  constants   Several bulk-transfer features are constant (all zero) in the
              public datasets but vary in TRUSTLab. A model cannot have
              learned anything from a feature that never varied in training,
              so on the test side it is set to the training value. Trees
              already ignore such a feature; the neural models do not,
              because StandardScaler leaves a zero-variance column unscaled.
  timeouts    CSE-CIC-IDS2018 and TII-SSRC-23 end every flow at 120 s;
              TRUSTLab's run to 15,717 s. Flows longer than the shorter
              timeout have no counterpart on the other side, so a
              timeout-matched subset keeps only flows of at most 120 s.

What is NOT attempted, because it needs retraining: dropping features that
separate the datasets (Packet Length Min alone carries 0.83 of a domain
classifier's importance), and re-extracting every dataset with one
CICFlowMeter build. Clipping to the training range was already measured
(results/clip_diagnostic.csv) and did not help, so it is not repeated.
"""
from __future__ import annotations

from typing import Dict, List, Tuple

import numpy as np
import pandas as pd

TIMEOUT_US = 120 * 1_000_000          # CICFlowMeter reports Flow Duration in microseconds
DURATION = "Flow Duration"


def training_profile(train: pd.DataFrame) -> Dict[str, object]:
    """What the training data looked like: per-feature minimum, and the
    features that never varied with the value they held."""
    std = train.std(ddof=0)
    constant = {c: float(train[c].iloc[0]) for c in train.columns if float(std[c]) == 0.0}
    return {"min": train.min(), "constant": constant}


def harmonise(test: pd.DataFrame, profile: Dict[str, object]) -> Tuple[pd.DataFrame, Dict[str, object]]:
    """Cleaned test features -> harmonised copy, and a record of what changed."""
    out = test.copy()
    changed: Dict[str, object] = {"sentinels": {}, "constants": {}}
    train_min = profile["min"]
    for c in out.columns:
        if c in profile["constant"]:
            differs = float((out[c] != profile["constant"][c]).mean())
            if differs > 0:
                changed["constants"][c] = round(differs, 4)
            out[c] = profile["constant"][c]
        elif float(train_min[c]) >= 0:
            negative = out[c] < 0
            if negative.any():
                changed["sentinels"][c] = round(float(negative.mean()), 4)
                out.loc[negative, c] = 0.0
    # Keep the input's dtypes (float32 from clean_features): the neural models
    # reject float64 input, and a column overwritten with a Python float
    # would otherwise come back as float64.
    return out.astype(test.dtypes.to_dict()), changed


def timeout_mask(frame: pd.DataFrame) -> np.ndarray:
    """Rows whose flow ended within the public datasets' 120 s timeout."""
    duration = pd.to_numeric(frame[DURATION], errors="coerce").fillna(0)
    return (duration <= TIMEOUT_US).to_numpy()


def describe(changed: Dict[str, object]) -> List[str]:
    lines = []
    if changed["sentinels"]:
        lines.append("negative values set to 0 (never negative in training): "
                     + ", ".join(f"{k} {v:.1%}" for k, v in changed["sentinels"].items()))
    if changed["constants"]:
        lines.append("set to the training constant (never varied in training): "
                     + ", ".join(f"{k} ({v:.1%} of rows differed)" for k, v in changed["constants"].items()))
    return lines or ["nothing to harmonise"]
