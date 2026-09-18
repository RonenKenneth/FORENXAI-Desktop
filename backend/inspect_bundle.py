from pathlib import Path
import json
import joblib


BASE_DIR = Path(__file__).resolve().parent

MODEL_DIR = (
    BASE_DIR
    / "models"
    / "forenxai"
)


MODEL_PATH = (
    MODEL_DIR
    / "XGBoost.pkl"
)

SCALER_PATH = (
    MODEL_DIR
    / "scaler.pkl"
)

LABEL_ENCODER_PATH = (
    MODEL_DIR
    / "label_encoder.pkl"
)

FEATURES_PATH = (
    MODEL_DIR
    / "features.pkl"
)

MANIFEST_PATH = (
    MODEL_DIR
    / "manifest.json"
)

SHAP_GLOBAL_PATH = (
    MODEL_DIR
    / "shap_global.json"
)


print(
    "\n=============================="
)

print(
    "FORENXAI MODEL BUNDLE CHECK"
)

print(
    "=============================="
)


# --------------------------------
# Check that all files exist
# --------------------------------

required_files = [
    MODEL_PATH,
    SCALER_PATH,
    LABEL_ENCODER_PATH,
    FEATURES_PATH,
    MANIFEST_PATH,
    SHAP_GLOBAL_PATH
]


print(
    "\n[1] Checking required files..."
)


missing_files = []


for file_path in required_files:

    if file_path.exists():

        print(
            f"[OK] {file_path.name}"
        )

    else:

        print(
            f"[MISSING] {file_path.name}"
        )

        missing_files.append(
            file_path
        )


if missing_files:

    raise FileNotFoundError(
        "One or more bundle files are missing."
    )


# --------------------------------
# Load manifest
# --------------------------------

print(
    "\n[2] Loading manifest.json..."
)


with MANIFEST_PATH.open(
    "r",
    encoding="utf-8"
) as file:

    manifest = json.load(
        file
    )


print(
    "[OK] manifest.json loaded"
)


print(
    f"Manifest type: {type(manifest)}"
)


# --------------------------------
# Load feature list
# --------------------------------

print(
    "\n[3] Loading features.pkl..."
)


features = joblib.load(
    FEATURES_PATH
)


print(
    "[OK] features.pkl loaded"
)


print(
    f"Feature container type: "
    f"{type(features)}"
)


print(
    f"Feature count: "
    f"{len(features)}"
)


print(
    "\nFEATURE ORDER:"
)


for index, feature in enumerate(
    features,
    start=1
):

    print(
        f"{index:02d}. {feature}"
    )


# --------------------------------
# Load scaler
# --------------------------------

print(
    "\n[4] Loading scaler.pkl..."
)


scaler = joblib.load(
    SCALER_PATH
)


print(
    "[OK] scaler.pkl loaded"
)


print(
    f"Scaler type: "
    f"{type(scaler)}"
)


if hasattr(
    scaler,
    "n_features_in_"
):

    print(
        f"Scaler expects: "
        f"{scaler.n_features_in_} features"
    )


# --------------------------------
# Load label encoder
# --------------------------------

print(
    "\n[5] Loading label_encoder.pkl..."
)


label_encoder = joblib.load(
    LABEL_ENCODER_PATH
)


print(
    "[OK] label_encoder.pkl loaded"
)


print(
    f"Label encoder type: "
    f"{type(label_encoder)}"
)


if hasattr(
    label_encoder,
    "classes_"
):

    classes = list(
        label_encoder.classes_
    )

    print(
        f"Class count: "
        f"{len(classes)}"
    )

    print(
        "\nCLASSES:"
    )

    for index, class_name in enumerate(
        classes,
        start=1
    ):

        print(
            f"{index:02d}. {class_name}"
        )


# --------------------------------
# Load XGBoost model
# --------------------------------

print(
    "\n[6] Loading XGBoost.pkl..."
)


model = joblib.load(
    MODEL_PATH
)


print(
    "[OK] XGBoost.pkl loaded"
)


print(
    f"Model type: "
    f"{type(model)}"
)


if hasattr(
    model,
    "n_features_in_"
):

    print(
        f"Model expects: "
        f"{model.n_features_in_} features"
    )


if hasattr(
    model,
    "classes_"
):

    print(
        f"Model class count: "
        f"{len(model.classes_)}"
    )


# --------------------------------
# Compare feature counts
# --------------------------------

print(
    "\n[7] Comparing feature counts..."
)


feature_count = len(
    features
)


scaler_feature_count = getattr(
    scaler,
    "n_features_in_",
    None
)


model_feature_count = getattr(
    model,
    "n_features_in_",
    None
)


print(
    f"features.pkl : "
    f"{feature_count}"
)

print(
    f"scaler.pkl   : "
    f"{scaler_feature_count}"
)

print(
    f"XGBoost.pkl  : "
    f"{model_feature_count}"
)


if (
    scaler_feature_count is not None
    and
    scaler_feature_count != feature_count
):

    print(
        "[WARNING] Scaler feature count "
        "does not match features.pkl"
    )


if (
    model_feature_count is not None
    and
    model_feature_count != feature_count
):

    print(
        "[WARNING] Model feature count "
        "does not match features.pkl"
    )


# --------------------------------
# Final result
# --------------------------------

print(
    "\n=============================="
)

print(
    "BUNDLE INSPECTION COMPLETE"
)

print(
    "=============================="
)