from pathlib import Path

import joblib
import numpy as np
import pandas as pd


BASE_DIR = Path(__file__).resolve().parent

MODEL_DIR = (
    BASE_DIR
    / "models"
    / "forenxai"
)

CSV_PATH = Path(
    r"C:\Tools\CICFlowMeter"
    r"\CICFlowMeter-master"
    r"\data"
    r"\out"
    r"\testtest.pcap_Flow.csv"
)


FEATURES_PATH = (
    MODEL_DIR
    / "features.pkl"
)

SCALER_PATH = (
    MODEL_DIR
    / "scaler.pkl"
)

MODEL_PATH = (
    MODEL_DIR
    / "XGBoost.pkl"
)

LABEL_ENCODER_PATH = (
    MODEL_DIR
    / "label_encoder.pkl"
)


print(
    "\n=============================="
)

print(
    "FORENXAI CLASSIFIER TEST"
)

print(
    "=============================="
)


# --------------------------------
# Load model bundle
# --------------------------------

print(
    "\n[1] Loading model bundle..."
)


features = joblib.load(
    FEATURES_PATH
)

scaler = joblib.load(
    SCALER_PATH
)

model = joblib.load(
    MODEL_PATH
)

label_encoder = joblib.load(
    LABEL_ENCODER_PATH
)


print(
    "[OK] Model bundle loaded"
)


# --------------------------------
# Load CICFlowMeter CSV
# --------------------------------

print(
    "\n[2] Loading CICFlowMeter CSV..."
)


df = pd.read_csv(
    CSV_PATH
)


df.columns = [
    str(column).strip()
    for column in df.columns
]


print(
    f"[OK] Loaded {len(df)} flows"
)


# --------------------------------
# Select model features
# --------------------------------

print(
    "\n[3] Selecting model features..."
)


missing_features = [
    feature
    for feature in features
    if feature not in df.columns
]


if missing_features:

    raise ValueError(
        "Missing model features: "
        + ", ".join(missing_features)
    )


X = df[
    features
].copy()


print(
    f"[OK] Input shape: "
    f"{X.shape}"
)


# --------------------------------
# Convert values to numeric
# --------------------------------

print(
    "\n[4] Cleaning numeric values..."
)


for column in X.columns:

    X[column] = pd.to_numeric(
        X[column],
        errors="coerce"
    )


X = X.replace(
    [np.inf, -np.inf],
    np.nan
)


nan_count = int(
    X.isna().sum().sum()
)


print(
    f"NaN/Inf values found: "
    f"{nan_count}"
)


if nan_count > 0:

    print(
        "[INFO] Replacing invalid values "
        "with 0 for this test."
    )

    X = X.fillna(
        0
    )


# --------------------------------
# Scale input
# --------------------------------

print(
    "\n[5] Applying scaler..."
)


X_scaled = scaler.transform(
    X
)


print(
    f"[OK] Scaled shape: "
    f"{X_scaled.shape}"
)


# --------------------------------
# Predict encoded classes
# --------------------------------

print(
    "\n[6] Running XGBoost..."
)


encoded_predictions = model.predict(
    X_scaled
)


probabilities = model.predict_proba(
    X_scaled
)


print(
    "[OK] Predictions complete"
)


# --------------------------------
# Decode classes
# --------------------------------

decoded_predictions = (
    label_encoder.inverse_transform(
        encoded_predictions.astype(int)
    )
)


# --------------------------------
# Display results
# --------------------------------

print(
    "\n------------------------------"
)

print(
    "FLOW PREDICTIONS"
)

print(
    "------------------------------"
)


results = []


for index, predicted_class in enumerate(
    decoded_predictions
):

    confidence = float(
        np.max(
            probabilities[index]
        )
    )

    result = {
        "flow_index":
            int(index),

        "predicted_class":
            str(predicted_class),

        "confidence":
            confidence,

        "is_threat":
            str(predicted_class)
            != "Benign"
    }

    results.append(
        result
    )

    print(
        f"Flow {index + 1:02d}: "
        f"{predicted_class:<15} "
        f"confidence={confidence:.4f}"
    )


# --------------------------------
# Summary
# --------------------------------

total_flows = len(
    results
)


benign_count = sum(
    1
    for result in results
    if not result["is_threat"]
)


threat_count = (
    total_flows
    -
    benign_count
)


print(
    "\n------------------------------"
)

print(
    "SUMMARY"
)

print(
    "------------------------------"
)


print(
    f"Total flows: "
    f"{total_flows}"
)

print(
    f"Benign flows: "
    f"{benign_count}"
)

print(
    f"Threat flows: "
    f"{threat_count}"
)


print(
    "\nClass counts:"
)


class_counts = (
    pd.Series(
        decoded_predictions
    )
    .value_counts()
)


for class_name, count in class_counts.items():

    print(
        f"- {class_name}: "
        f"{count}"
    )


print(
    "\n=============================="
)

print(
    "CLASSIFIER TEST COMPLETE"
)

print(
    "=============================="
)