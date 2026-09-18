from pathlib import Path

import numpy as np
import pandas as pd
import shap

from app.services.model_service import (
    load_model_bundle,
    prepare_model_input
)


DEFAULT_TOP_FEATURES = 10

_explainer = None

# ==================================
# SHAP EXPLAINER
# ==================================

def generate_shap_explanations(
    ml_result: dict,
    top_n: int = 5
) -> dict:
    """
    Generate TreeSHAP explanations for each classified flow.

    Expected ml_result structure:
        ml_result["_feature_frame"]
        ml_result["_scaled_matrix"]
        ml_result["findings"]

    Returns:
        {
            "total_flows": ...,
            "top_features_per_flow": ...,
            "explanations": [...]
        }
    """

    if ml_result is None:
        raise ValueError(
            "ML result was not provided to SHAP."
        )

    if "_feature_frame" not in ml_result:
        raise ValueError(
            "ML result does not contain "
            "'_feature_frame'."
        )

    if "_scaled_matrix" not in ml_result:
        raise ValueError(
            "ML result does not contain "
            "'_scaled_matrix'."
        )

    if "findings" not in ml_result:
        raise ValueError(
            "ML result does not contain "
            "'findings'."
        )

    # ==================================
    # LOAD MODEL BUNDLE
    # ==================================

    bundle = load_model_bundle()

    model = bundle["model"]
    scaler = bundle["scaler"]
    label_encoder = bundle["label_encoder"]
    features = list(
        bundle["features"]
    )
    classes = [
        str(value)
        for value in bundle["classes"]
    ]

    # These are intentionally retained here because
    # SHAP must explain the same model/scaler/schema
    # used for classification.
    _ = scaler
    _ = label_encoder

    # ==================================
    # GET MODEL INPUT
    # ==================================

    feature_frame = ml_result[
        "_feature_frame"
    ]

    scaled_matrix = ml_result[
        "_scaled_matrix"
    ]

    findings = ml_result[
        "findings"
    ]

    if feature_frame is None:
        raise ValueError(
            "SHAP feature frame is missing."
        )

    if scaled_matrix is None:
        raise ValueError(
            "SHAP scaled matrix is missing."
        )

    scaled_matrix = np.asarray(
        scaled_matrix,
        dtype=np.float64
    )

    # ==================================
    # VALIDATE MATRIX
    # ==================================

    if scaled_matrix.ndim != 2:
        raise ValueError(
            "SHAP expected a 2-D model input "
            f"but received shape "
            f"{scaled_matrix.shape}."
        )

    if scaled_matrix.shape[1] != len(
        features
    ):
        raise ValueError(
            "SHAP feature count mismatch.\n"
            f"Model expects {len(features)} "
            f"features but matrix contains "
            f"{scaled_matrix.shape[1]}."
        )

    if scaled_matrix.shape[0] != len(
        findings
    ):
        raise ValueError(
            "SHAP row count does not match "
            "ML finding count."
        )

    if not np.isfinite(
        scaled_matrix
    ).all():
        raise ValueError(
            "SHAP model input contains "
            "NaN or Infinity values."
        )

    # ==================================
    # CREATE TREE EXPLAINER
    # ==================================

    print(
        "[FORENXAI] Building TreeSHAP explainer...",
        flush=True
    )

    explainer = shap.TreeExplainer(
        model,
        feature_perturbation=
            "tree_path_dependent"
    )

    # ==================================
    # CALCULATE SHAP VALUES
    # ==================================

    print(
        "[FORENXAI] Calculating SHAP values...",
        flush=True
    )

    shap_output = explainer(
        scaled_matrix
    )

    shap_values = np.asarray(
        shap_output.values
    )

    base_values = np.asarray(
        shap_output.base_values
    )

    print(
        "[FORENXAI] SHAP values shape: "
        f"{shap_values.shape}",
        flush=True
    )

    print(
        "[FORENXAI] SHAP base values shape: "
        f"{base_values.shape}",
        flush=True
    )

    # ==================================
    # NORMALIZE MULTICLASS SHAP SHAPE
    # ==================================

    #
    # Current expected XGBoost multiclass format:
    #
    #     samples x features x classes
    #
    # Example:
    #
    #     (8, 74, 16)
    #
    # Older SHAP releases can return other layouts,
    # so handle the known alternatives explicitly.
    #

    number_of_rows = scaled_matrix.shape[0]
    number_of_features = len(
        features
    )
    number_of_classes = len(
        classes
    )

    normalized_values = None

    if (
        shap_values.ndim == 3
        and shap_values.shape
        == (
            number_of_rows,
            number_of_features,
            number_of_classes
        )
    ):
        normalized_values = shap_values

    elif (
        shap_values.ndim == 3
        and shap_values.shape
        == (
            number_of_classes,
            number_of_rows,
            number_of_features
        )
    ):
        normalized_values = np.transpose(
            shap_values,
            (
                1,
                2,
                0
            )
        )

    elif (
        shap_values.ndim == 2
        and number_of_classes == 1
    ):
        normalized_values = (
            shap_values[
                :,
                :,
                np.newaxis
            ]
        )

    else:
        raise ValueError(
            "Unsupported SHAP output shape.\n"
            f"Received: {shap_values.shape}\n"
            "Expected either "
            "(samples, features, classes) "
            "or "
            "(classes, samples, features)."
        )

    # ==================================
    # NORMALIZE BASE VALUES
    # ==================================

    if base_values.ndim == 1:

        if (
            len(base_values)
            == number_of_classes
        ):
            normalized_base_values = np.tile(
                base_values,
                (
                    number_of_rows,
                    1
                )
            )

        elif (
            len(base_values)
            == number_of_rows
            and number_of_classes == 1
        ):
            normalized_base_values = (
                base_values.reshape(
                    -1,
                    1
                )
            )

        else:
            normalized_base_values = None

    elif (
        base_values.ndim == 2
        and base_values.shape
        == (
            number_of_rows,
            number_of_classes
        )
    ):
        normalized_base_values = (
            base_values
        )

    else:
        normalized_base_values = None

    # ==================================
    # BUILD FLOW EXPLANATIONS
    # ==================================

    explanations = []

    top_features_per_flow = {}

    for row_index, finding in enumerate(
        findings
    ):

        predicted_class = str(
            finding.get(
                "predicted_class",
                ""
            )
        )

        confidence = float(
            finding.get(
                "confidence",
                0.0
            )
        )

        flow_index = int(
            finding.get(
                "flow_index",
                row_index
            )
        )

        metadata = finding.get(
            "metadata",
            {}
        )

        flow_id = str(
            metadata.get(
                "Flow ID",
                ""
            )
        )

        # ==================================
        # FIND PREDICTED CLASS INDEX
        # ==================================

        if predicted_class not in classes:
            raise ValueError(
                "Predicted class returned by "
                "XGBoost does not exist in "
                "label_encoder classes:\n"
                f"{predicted_class}"
            )

        class_index = classes.index(
            predicted_class
        )

        # ==================================
        # GET SHAP VALUES FOR THIS FLOW
        # AND THIS PREDICTED CLASS
        # ==================================

        flow_shap_values = (
            normalized_values[
                row_index,
                :,
                class_index
            ]
        )

        if len(
            flow_shap_values
        ) != number_of_features:
            raise ValueError(
                "SHAP feature vector length "
                "does not match the model "
                "feature schema."
            )

        # ==================================
        # GET RAW FEATURE VALUES
        # ==================================

        raw_feature_values = (
            feature_frame
            .iloc[
                row_index
            ]
        )

        # ==================================
        # BUILD ALL CONTRIBUTORS
        # ==================================

        contributors = []

        for feature_index, feature_name in enumerate(
            features
        ):

            shap_value = float(
                flow_shap_values[
                    feature_index
                ]
            )

            raw_value = (
                raw_feature_values[
                    feature_name
                ]
            )

            # Convert raw value to JSON-safe number.
            try:
                raw_value = float(
                    raw_value
                )

                if not np.isfinite(
                    raw_value
                ):
                    raw_value = 0.0

            except (
                TypeError,
                ValueError
            ):
                raw_value = 0.0

            # ==================================
            # DIRECTION
            # ==================================

            if shap_value > 0:
                direction = (
                    "supports_prediction"
                )

            elif shap_value < 0:
                direction = (
                    "opposes_prediction"
                )

            else:
                direction = "neutral"

            contributors.append(
                {
                    "feature":
                        feature_name,

                    "raw_value":
                        raw_value,

                    "shap_value":
                        shap_value,

                    "direction":
                        direction,
                }
            )

        # ==================================
        # SORT BY ABSOLUTE SHAP MAGNITUDE
        # ==================================

        contributors.sort(
            key=lambda item: abs(
                item["shap_value"]
            ),
            reverse=True
        )

        top_contributors = (
            contributors[
                :top_n
            ]
        )

        # Add rank after sorting.
        ranked_contributors = []

        for rank, contributor in enumerate(
            top_contributors,
            start=1
        ):

            ranked_contributors.append(
                {
                    "rank":
                        rank,

                    "feature":
                        contributor[
                            "feature"
                        ],

                    "raw_value":
                        contributor[
                            "raw_value"
                        ],

                    "shap_value":
                        contributor[
                            "shap_value"
                        ],

                    "direction":
                        contributor[
                            "direction"
                        ],
                }
            )

        # ==================================
        # OPTIONAL BASE VALUE
        # ==================================

        base_value = None

        if (
            normalized_base_values
            is not None
        ):

            try:

                base_value = float(
                    normalized_base_values[
                        row_index,
                        class_index
                    ]
                )

                if not np.isfinite(
                    base_value
                ):
                    base_value = None

            except (
                IndexError,
                TypeError,
                ValueError
            ):
                base_value = None

        # ==================================
        # SAVE EXPLANATION
        # ==================================

        explanation = {
            "flow_index":
                flow_index,

            "flow_id":
                flow_id,

            "predicted_class":
                predicted_class,

            "confidence":
                confidence,

            "contributors":
                ranked_contributors,
        }

        if base_value is not None:
            explanation[
                "base_value"
            ] = base_value

        explanations.append(
            explanation
        )

        top_features_per_flow[
            str(flow_index)
        ] = ranked_contributors

    # ==================================
    # COMPLETE
    # ==================================

    print(
        "[FORENXAI] SHAP explanations generated "
        f"for {len(explanations)} flow(s).",
        flush=True
    )

    return {
        "total_flows":
            len(explanations),

        "top_features_per_flow":
            top_features_per_flow,

        "explanations":
            explanations,
    }


# ==================================
# COMPATIBILITY ALIAS
# ==================================

def explain_predictions(
    ml_result: dict,
    top_n: int = 5
) -> dict:
    """
    Compatibility alias.
    """

    return generate_shap_explanations(
        ml_result=ml_result,
        top_n=top_n
    )
    
# ==================================
# ANALYSIS.PY COMPATIBILITY ENTRY
# ==================================

def explain_flow_csv(
    ml_result: dict,
    top_n: int = 5
) -> dict:
    """
    Compatibility entry point used by analysis.py.

    Delegates to the main SHAP explanation function.
    """

    return generate_shap_explanations(
        ml_result=ml_result,
        top_n=top_n
    )