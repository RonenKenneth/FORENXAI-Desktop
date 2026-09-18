from pathlib import Path

import numpy as np
import pandas as pd
import shap

from app.services.model_service import (
    load_model_bundle,
    prepare_model_input
)


CSV_PATH = Path(
    r"C:\Tools\CICFlowMeter"
    r"\CICFlowMeter-master"
    r"\data"
    r"\out"
    r"\testtest.pcap_Flow.csv"
)


TOP_FEATURES = 10


print(
    "\n=============================="
)

print(
    "FORENXAI SHAP TEST"
)

print(
    "=============================="
)


# ==================================
# Load model bundle
# ==================================

print(
    "\n[1] Loading model bundle..."
)

(
    model,
    scaler,
    label_encoder,
    features
) = load_model_bundle()


print(
    "[OK] Model bundle loaded."
)


# ==================================
# Load CICFlowMeter data
# ==================================

print(
    "\n[2] Loading CICFlowMeter CSV..."
)

flow_dataframe = pd.read_csv(
    CSV_PATH
)

flow_dataframe.columns = [
    str(column).strip()
    for column in flow_dataframe.columns
]


print(
    f"[OK] Loaded "
    f"{len(flow_dataframe)} flows."
)


# ==================================
# Prepare exact model matrix
# ==================================

print(
    "\n[3] Preparing 74-feature matrix..."
)

(
    cleaned_dataframe,
    X_scaled
) = prepare_model_input(
    flow_dataframe
)


print(
    f"[OK] Scaled matrix shape: "
    f"{X_scaled.shape}"
)


# ==================================
# Model prediction
# ==================================

print(
    "\n[4] Running predictions..."
)

encoded_predictions = model.predict(
    X_scaled
)

probabilities = model.predict_proba(
    X_scaled
)

decoded_predictions = (
    label_encoder.inverse_transform(
        encoded_predictions.astype(int)
    )
)


print(
    "[OK] Predictions complete."
)


# ==================================
# Create TreeSHAP explainer
# ==================================

print(
    "\n[5] Creating TreeSHAP explainer..."
)

explainer = shap.TreeExplainer(
    model,
    feature_perturbation=(
        "tree_path_dependent"
    )
)


print(
    "[OK] TreeSHAP explainer created."
)


# ==================================
# Calculate SHAP
# ==================================

print(
    "\n[6] Calculating SHAP values..."
)

shap_result = explainer(
    X_scaled,
    check_additivity=True
)


print(
    "[OK] SHAP calculation complete."
)


print(
    "\nSHAP values shape:",
    np.asarray(
        shap_result.values
    ).shape
)


print(
    "Base values shape:",
    np.asarray(
        shap_result.base_values
    ).shape
)


# ==================================
# Helper:
# obtain SHAP values for one
# flow and its predicted class
# ==================================

def get_class_shap_values(
    shap_values,
    flow_index,
    class_index,
    feature_count
):

    values = np.asarray(
        shap_values
    )

    # Common multiclass SHAP layout:
    #
    # samples × features × classes
    #
    if (
        values.ndim == 3
        and
        values.shape[1]
        == feature_count
    ):

        return values[
            flow_index,
            :,
            class_index
        ]

    # Alternative:
    #
    # samples × classes × features
    #
    if (
        values.ndim == 3
        and
        values.shape[2]
        == feature_count
    ):

        return values[
            flow_index,
            class_index,
            :
        ]

    # Binary/single-output fallback.
    if (
        values.ndim == 2
        and
        values.shape[1]
        == feature_count
    ):

        return values[
            flow_index,
            :
        ]

    raise ValueError(
        "Unexpected SHAP output shape: "
        f"{values.shape}"
    )


# ==================================
# Display first five explanations
# ==================================

print(
    "\n=============================="
)

print(
    "SHAP EXPLANATIONS"
)

print(
    "=============================="
)


number_to_display = min(
    5,
    len(cleaned_dataframe)
)


for flow_index in range(
    number_to_display
):

    predicted_class_index = int(
        encoded_predictions[
            flow_index
        ]
    )

    predicted_class = str(
        decoded_predictions[
            flow_index
        ]
    )

    confidence = float(
        np.max(
            probabilities[
                flow_index
            ]
        )
    )

    class_shap_values = (
        get_class_shap_values(
            shap_result.values,
            flow_index,
            predicted_class_index,
            len(features)
        )
    )

    # Sort by absolute contribution.
    top_indices = np.argsort(
        np.abs(
            class_shap_values
        )
    )[::-1][:TOP_FEATURES]


    print(
        "\n------------------------------"
    )

    print(
        f"FLOW {flow_index + 1}"
    )

    print(
        "------------------------------"
    )

    print(
        f"Prediction: "
        f"{predicted_class}"
    )

    print(
        f"Confidence: "
        f"{confidence:.4f}"
    )


    if "Flow ID" in cleaned_dataframe.columns:

        print(
            f"Flow ID: "
            f"{cleaned_dataframe.iloc[flow_index]['Flow ID']}"
        )


    print(
        "\nTop SHAP contributors:"
    )


    for rank, feature_index in enumerate(
        top_indices,
        start=1
    ):

        feature_name = str(
            features[
                feature_index
            ]
        )

        shap_value = float(
            class_shap_values[
                feature_index
            ]
        )

        raw_value = (
            cleaned_dataframe.iloc[
                flow_index
            ][
                feature_name
            ]
        )

        if shap_value > 0:

            direction = (
                "supports prediction"
            )

        elif shap_value < 0:

            direction = (
                "opposes prediction"
            )

        else:

            direction = (
                "neutral"
            )


        print(
            f"{rank:02d}. "
            f"{feature_name}"
        )

        print(
            f"    Raw value: "
            f"{raw_value}"
        )

        print(
            f"    SHAP: "
            f"{shap_value:.6f}"
        )

        print(
            f"    Direction: "
            f"{direction}"
        )


print(
    "\n=============================="
)

print(
    "SHAP TEST COMPLETE"
)

print(
    "=============================="
)