from pathlib import Path

import joblib
import pandas as pd


BASE_DIR = Path(__file__).resolve().parent

FEATURES_PATH = (
    BASE_DIR
    / "models"
    / "forenxai"
    / "features.pkl"
)

CSV_PATH = Path(
    r"C:\Tools\CICFlowMeter"
    r"\CICFlowMeter-master"
    r"\data"
    r"\out"
    r"\testtest.pcap_Flow.csv"
)


print(
    "\n=============================="
)

print(
    "FORENXAI FEATURE ALIGNMENT"
)

print(
    "=============================="
)


# --------------------------------
# Load model feature list
# --------------------------------

features = joblib.load(
    FEATURES_PATH
)


print(
    f"\nModel required features: "
    f"{len(features)}"
)


# --------------------------------
# Load CICFlowMeter CSV
# --------------------------------

df = pd.read_csv(
    CSV_PATH
)


# Remove accidental whitespace
# around column names.
df.columns = [
    str(column).strip()
    for column in df.columns
]


csv_columns = list(
    df.columns
)


print(
    f"CICFlowMeter columns: "
    f"{len(csv_columns)}"
)


print(
    f"CICFlowMeter rows: "
    f"{len(df)}"
)


# --------------------------------
# Compare
# --------------------------------

missing_features = [
    feature
    for feature in features
    if feature not in csv_columns
]


extra_columns = [
    column
    for column in csv_columns
    if column not in features
]


available_features = [
    feature
    for feature in features
    if feature in csv_columns
]


print(
    "\n------------------------------"
)

print(
    "FEATURE MATCH"
)

print(
    "------------------------------"
)


print(
    f"Required: "
    f"{len(features)}"
)

print(
    f"Available: "
    f"{len(available_features)}"
)

print(
    f"Missing: "
    f"{len(missing_features)}"
)


if missing_features:

    print(
        "\nMISSING MODEL FEATURES:"
    )

    for feature in missing_features:

        print(
            f"- {feature}"
        )

else:

    print(
        "\n[OK] All model features "
        "exist in the CSV."
    )


print(
    "\n------------------------------"
)

print(
    "NON-MODEL CSV COLUMNS"
)

print(
    "------------------------------"
)


for column in extra_columns:

    print(
        f"- {column}"
    )


# --------------------------------
# Verify model ordering
# --------------------------------

if not missing_features:

    model_input = df[
        features
    ]

    print(
        "\n------------------------------"
    )

    print(
        "ORDERED MODEL INPUT"
    )

    print(
        "------------------------------"
    )

    print(
        f"Rows: "
        f"{model_input.shape[0]}"
    )

    print(
        f"Columns: "
        f"{model_input.shape[1]}"
    )


    print(
        "\nFirst 10 ordered features:"
    )

    for index, column in enumerate(
        model_input.columns[:10],
        start=1
    ):

        print(
            f"{index:02d}. {column}"
        )


print(
    "\n=============================="
)

print(
    "FEATURE CHECK COMPLETE"
)

print(
    "=============================="
)