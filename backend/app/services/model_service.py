from __future__ import annotations

# ============================================================
# IMPORTS
# ============================================================

from pathlib import Path
from typing import Any

import hashlib
import json

import joblib
import numpy as np
import pandas as pd
import xgboost


# ============================================================
# PATH CONFIGURATION
# ============================================================

# This file:
# backend/app/services/model_service.py
#
# parents[0] = services
# parents[1] = app
# parents[2] = backend

BACKEND_DIRECTORY = (
    Path(__file__)
    .resolve()
    .parents[2]
)

MODEL_DIRECTORY = (
    BACKEND_DIRECTORY
    / "models"
    / "forenxai"
)


MODEL_FILE = (
    MODEL_DIRECTORY
    / "XGBoost.pkl"
)

SCALER_FILE = (
    MODEL_DIRECTORY
    / "scaler.pkl"
)

LABEL_ENCODER_FILE = (
    MODEL_DIRECTORY
    / "label_encoder.pkl"
)

FEATURES_FILE = (
    MODEL_DIRECTORY
    / "features.pkl"
)

SHAP_GLOBAL_FILE = (
    MODEL_DIRECTORY
    / "shap_global.json"
)

MANIFEST_FILE = (
    MODEL_DIRECTORY
    / "manifest.json"
)


# ============================================================
# EXPECTED MODEL ARTIFACTS
# ============================================================

REQUIRED_MODEL_FILES = [
    FEATURES_FILE,
    LABEL_ENCODER_FILE,
    SCALER_FILE,
    SHAP_GLOBAL_FILE,
    MODEL_FILE,
]


# ============================================================
# MODEL CACHE
# ============================================================

_cached_bundle: dict[str, Any] | None = None


# ============================================================
# FILE HASH
# ============================================================

def _calculate_sha256(
    file_path: Path
) -> str:
    """
    Calculate SHA-256 for a file.
    """

    hasher = hashlib.sha256()

    with file_path.open("rb") as file:

        while True:

            chunk = file.read(
                1024 * 1024
            )

            if not chunk:
                break

            hasher.update(
                chunk
            )

    return hasher.hexdigest().lower()


# ============================================================
# MANIFEST HELPERS
# ============================================================

def _get_manifest_entry(
    manifest: dict[str, Any],
    file_name: str
) -> dict[str, Any] | None:
    """
    Find an artifact entry in different possible manifest layouts.
    """

    # --------------------------------------------------------
    # Format:
    #
    # {
    #     "files": {
    #         "XGBoost.pkl": {
    #             "sha256": "...",
    #             "size": 123
    #         }
    #     }
    # }
    # --------------------------------------------------------

    files_section = manifest.get(
        "files"
    )

    if isinstance(
        files_section,
        dict
    ):

        entry = files_section.get(
            file_name
        )

        if isinstance(
            entry,
            dict
        ):
            return entry


    # --------------------------------------------------------
    # Format:
    #
    # {
    #     "artifacts": {
    #         "XGBoost.pkl": {...}
    #     }
    # }
    # --------------------------------------------------------

    artifacts_section = manifest.get(
        "artifacts"
    )

    if isinstance(
        artifacts_section,
        dict
    ):

        entry = artifacts_section.get(
            file_name
        )

        if isinstance(
            entry,
            dict
        ):
            return entry


    # --------------------------------------------------------
    # Format:
    #
    # {
    #     "artifacts": [
    #         {
    #             "name": "XGBoost.pkl",
    #             ...
    #         }
    #     ]
    # }
    # --------------------------------------------------------

    if isinstance(
        artifacts_section,
        list
    ):

        for entry in artifacts_section:

            if not isinstance(
                entry,
                dict
            ):
                continue

            name = (
                entry.get("name")
                or entry.get("file")
                or entry.get("filename")
            )

            if name == file_name:
                return entry


    # --------------------------------------------------------
    # Format:
    #
    # {
    #     "XGBoost.pkl": {
    #         "sha256": "...",
    #         ...
    #     }
    # }
    # --------------------------------------------------------

    direct_entry = manifest.get(
        file_name
    )

    if isinstance(
        direct_entry,
        dict
    ):
        return direct_entry


    return None


def _manifest_feature_count() -> int | None:
    """
    How many features the shipped bundle declares, or None.

    Read from manifest.json rather than fixed in this file. The shared
    feature contract went from 74 to 66 when the eight Active/Idle columns
    TRUSTLab never populates were dropped, and a constant here turns a
    legitimate bundle swap into a crash at load time instead of a check
    that still does its job.
    """

    if not MANIFEST_FILE.exists():
        return None

    try:

        with MANIFEST_FILE.open(
            "r",
            encoding="utf-8"
        ) as manifest_file:

            manifest = json.load(
                manifest_file
            )

        count = manifest.get(
            "n_features"
        )

        return int(count) if count else None

    except (OSError, ValueError, TypeError):

        return None


# ============================================================
# VERIFY MODEL BUNDLE
# ============================================================

def verify_model_bundle() -> None:
    """
    Verify that all model artifacts exist and, when the manifest
    contains hashes/sizes, verify those values before unpickling.
    """

    print(
        "[FORENXAI] Verifying model bundle...",
        flush=True
    )


    if not MODEL_DIRECTORY.exists():

        raise FileNotFoundError(
            "FORENXAI model directory was not found:\n"
            f"{MODEL_DIRECTORY}"
        )


    if not MANIFEST_FILE.exists():

        raise FileNotFoundError(
            "Model manifest was not found:\n"
            f"{MANIFEST_FILE}"
        )


    for file_path in REQUIRED_MODEL_FILES:

        if not file_path.exists():

            raise FileNotFoundError(
                "Required model artifact was not found:\n"
                f"{file_path}"
            )

        if file_path.stat().st_size <= 0:

            raise RuntimeError(
                "Required model artifact is empty:\n"
                f"{file_path}"
            )


    with MANIFEST_FILE.open(
        "r",
        encoding="utf-8"
    ) as file:

        manifest = json.load(
            file
        )


    for file_path in REQUIRED_MODEL_FILES:

        entry = _get_manifest_entry(
            manifest,
            file_path.name
        )


        # If this manifest version does not contain per-file
        # metadata, existence verification still succeeds.
        if entry is None:

            print(
                f"[OK] {file_path.name}",
                flush=True
            )

            continue


        # ----------------------------------------------------
        # Verify size if available
        # ----------------------------------------------------

        expected_size = (
            entry.get("size")
            or entry.get("size_bytes")
            or entry.get("bytes")
        )

        if expected_size is not None:

            expected_size = int(
                expected_size
            )

            actual_size = (
                file_path
                .stat()
                .st_size
            )

            if actual_size != expected_size:

                raise RuntimeError(
                    "Model artifact size mismatch:\n\n"
                    f"File: {file_path.name}\n"
                    f"Expected: {expected_size}\n"
                    f"Actual: {actual_size}"
                )


        # ----------------------------------------------------
        # Verify SHA-256 if available
        # ----------------------------------------------------

        expected_hash = (
            entry.get("sha256")
            or entry.get("hash")
            or entry.get("checksum")
        )

        if expected_hash:

            expected_hash = (
                str(expected_hash)
                .strip()
                .lower()
            )

            actual_hash = _calculate_sha256(
                file_path
            )

            if actual_hash != expected_hash:

                raise RuntimeError(
                    "Model artifact SHA-256 mismatch:\n\n"
                    f"File: {file_path.name}\n"
                    f"Expected: {expected_hash}\n"
                    f"Actual: {actual_hash}"
                )


        print(
            f"[OK] {file_path.name}",
            flush=True
        )


    print(
        "[FORENXAI] Bundle integrity verified.",
        flush=True
    )


# ============================================================
# LOAD MODEL BUNDLE
# ============================================================

def load_model_bundle() -> dict[str, Any]:
    """
    Load and cache the FORENXAI multiclass XGBoost bundle.
    """

    global _cached_bundle


    if _cached_bundle is not None:

        return _cached_bundle


    print(
        "[FORENXAI] Loading model bundle...",
        flush=True
    )


    # --------------------------------------------------------
    # IMPORTANT:
    # Verify files BEFORE loading pickle/joblib objects.
    # --------------------------------------------------------

    verify_model_bundle()


    model = joblib.load(
        MODEL_FILE
    )

    scaler = joblib.load(
        SCALER_FILE
    )

    label_encoder = joblib.load(
        LABEL_ENCODER_FILE
    )

    features = joblib.load(
        FEATURES_FILE
    )


    if not isinstance(
        features,
        (list, tuple, np.ndarray)
    ):

        raise RuntimeError(
            "features.pkl does not contain "
            "a valid feature sequence."
        )


    features = [
        str(feature)
        for feature
        in features
    ]


    expected_feature_count = (
        _manifest_feature_count()
    )

    if (
        expected_feature_count is not None
        and len(features) != expected_feature_count
    ):

        raise RuntimeError(
            "FORENXAI model feature schema is invalid.\n"
            f"manifest.json declares {expected_feature_count} features "
            f"but features.pkl holds {len(features)}."
        )


    if not features:

        raise RuntimeError(
            "FORENXAI model feature schema is empty."
        )


    if len(
        set(features)
    ) != len(features):

        raise RuntimeError(
            "features.pkl contains duplicate "
            "feature names."
        )


    # The contract, not just the shape: a 74-feature list would pass
    # every check above and then be fed real Active/Idle values the
    # model has never seen.
    assert_feature_contract(
        features
    )


    classes = list(
        label_encoder.classes_
    )


    if len(classes) != 16:

        raise RuntimeError(
            "FORENXAI class schema is invalid.\n"
            f"Expected 16 classes but found "
            f"{len(classes)}."
        )


    _cached_bundle = {
        "model": model,
        "scaler": scaler,
        "label_encoder": label_encoder,
        "features": features,
        "classes": classes,
    }


    print(
        "[FORENXAI] Model bundle loaded successfully.",
        flush=True
    )


    return _cached_bundle


# ============================================================
# COMPATIBILITY ALIAS
# ============================================================

def load_bundle() -> dict[str, Any]:
    """
    Compatibility alias for other FORENXAI services.
    """

    return load_model_bundle()


# ============================================================
# GET BUNDLE
# ============================================================

def get_model_bundle() -> dict[str, Any]:
    """
    Public helper for SHAP or other services.
    """

    return load_model_bundle()


# ============================================================
# GET EXPECTED FEATURES
# ============================================================

def get_expected_features() -> list[str]:
    """
    Return the frozen model feature schema, as shipped in the bundle.
    """

    bundle = load_model_bundle()

    return list(
        bundle["features"]
    )


# ============================================================
# NORMALIZE CSV COLUMN NAMES
# ============================================================

def _normalize_columns(
    dataframe: pd.DataFrame
) -> pd.DataFrame:
    """
    Remove accidental whitespace/BOM characters from CSV headers.
    """

    dataframe = dataframe.copy()

    dataframe.columns = [
        str(column)
        .replace("\ufeff", "")
        .strip()
        for column
        in dataframe.columns
    ]

    return dataframe


# ============================================================
# WHAT CICFLOWMETER EMITS THAT THE MODEL DOES NOT USE
#
# CICFlowMeter writes 84 columns. The model was trained on 66.
# The 18 it does not use are not an accident, and they are not all
# the same kind of thing, so they are named here rather than left
# to be worked out by subtraction.
# ============================================================

# Identity, not behaviour. These say WHICH flow this is. They are
# shown beside a prediction and must never be fed to the model:
# training on a source address teaches the machine the lab, not the
# attack. Dst Port and Protocol are NOT in this list -- they are
# features, and they are in the 66, because they describe the
# service rather than the host.
IDENTITY_COLUMNS = (
    "Flow ID",
    "Src IP",
    "Src Port",
    "Dst IP",
    "Timestamp",
    "Label",
)

# Removed from the feature contract in the 74 -> 66 rebuild.
# TRUSTLab exports these eight without populating them: four are
# identically zero across all 1,400,000 rows, Active Max equals
# Idle Max in every row, Active Mean is exactly half of Active Max,
# and Active Max equals Flow Duration / 1e6.
#
# CICFlowMeter fills them properly from a real capture, and that is
# precisely why they must stay dropped: the deployed model has only
# ever seen zeros here. Feeding it real values would be feeding it
# a distribution it never trained on.
EXCLUDED_DEGENERATE_COLUMNS = (
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
)


def describe_extra_columns(
    dataframe: pd.DataFrame
) -> dict[str, list[str]]:
    """
    Classify the CICFlowMeter columns the model will not consume.

    Set arithmetic over the header only -- no row access -- so it is
    cheap enough to log on every run.

    The third group is the one worth reading. It is whatever the
    capture provides that is neither identity nor deliberately
    excluded: a real flow feature the model was simply not trained
    on, because the 66 are the intersection of what all three source
    datasets export. Anything appearing there is a candidate for a
    future retrain, not a bug to fix at inference time.
    """
    expected = set(get_expected_features())

    present = [
        str(column).replace("﻿", "").strip()
        for column in dataframe.columns
    ]

    unused = [
        column for column in present
        if column not in expected
    ]

    return {
        "identity": [
            column for column in unused
            if column in IDENTITY_COLUMNS
        ],
        "excluded_degenerate": [
            column for column in unused
            if column in EXCLUDED_DEGENERATE_COLUMNS
        ],
        "untrained": [
            column for column in unused
            if column not in IDENTITY_COLUMNS
            and column not in EXCLUDED_DEGENERATE_COLUMNS
        ],
    }


def assert_feature_contract(
    features: list[str]
) -> None:
    """
    Refuse a feature list that reintroduces the degenerate columns.

    This guards a failure that is otherwise silent. Drop a
    74-feature features.pkl into this bundle and every existing
    check still passes -- those columns ARE present in CICFlowMeter
    output, full of plausible numbers -- while the model is handed
    real Active and Idle values where it only ever saw zeros.
    Nothing would raise. The predictions would just be wrong.
    """
    reintroduced = [
        feature for feature in features
        if feature in EXCLUDED_DEGENERATE_COLUMNS
    ]

    if reintroduced:
        raise RuntimeError(
            "features.pkl lists "
            f"{len(reintroduced)} column(s) removed from the feature "
            "contract in the 74 -> 66 rebuild:\n\n"
            + "\n".join(reintroduced)
            + "\n\nTRUSTLab never populates these, so the deployed "
            "model has only ever seen zeros in them, while a real "
            "capture fills them with real values. This bundle is a "
            "74-feature model or a mixed one, and must not be used "
            "for inference."
        )


# ============================================================
# SCHEMA VALIDATION
# ============================================================

def validate_model_schema(
    dataframe: pd.DataFrame
) -> list[str]:
    """
    Return required model features missing from a CICFlowMeter CSV.
    """

    expected_features = (
        get_expected_features()
    )

    available_columns = set(
        dataframe.columns
    )

    missing_features = [
        feature
        for feature
        in expected_features
        if feature not in available_columns
    ]

    return missing_features


# ============================================================
# SANITIZE MODEL FEATURES
# ============================================================

def sanitize_model_input(
    feature_frame: pd.DataFrame
) -> pd.DataFrame:
    """
    Convert the selected model features to numeric values and
    replace NaN / +Infinity / -Infinity before model inference.
    """

    cleaned = feature_frame.copy()

    # Convert every selected feature to numeric.
    for column in cleaned.columns:
        cleaned[column] = pd.to_numeric(
            cleaned[column],
            errors="coerce"
        )

    # Inspect invalid values before cleaning.
    raw_values = cleaned.to_numpy(
        dtype=np.float64,
        copy=True
    )

    invalid_mask = ~np.isfinite(
        raw_values
    )

    invalid_count = int(
        invalid_mask.sum()
    )

    if invalid_count > 0:

        print(
            f"[FORENXAI] Found "
            f"{invalid_count} invalid numeric "
            f"value(s) before model inference.",
            flush=True
        )

        row_indexes, column_indexes = np.where(
            invalid_mask
        )

        for row_index, column_index in zip(
            row_indexes,
            column_indexes
        ):

            feature_name = cleaned.columns[
                column_index
            ]

            bad_value = cleaned.iloc[
                row_index,
                column_index
            ]

            print(
                f"[FORENXAI] Sanitizing flow "
                f"{row_index + 1}, "
                f"feature '{feature_name}', "
                f"value={bad_value}",
                flush=True
            )

    # Replace +/- infinity with NaN.
    cleaned.replace(
        [
            np.inf,
            -np.inf
        ],
        np.nan,
        inplace=True
    )

    # Replace all remaining NaN values.
    cleaned.fillna(
        0.0,
        inplace=True
    )

    cleaned = cleaned.astype(
        np.float64
    )

    # Final safety validation.
    final_values = cleaned.to_numpy(
        dtype=np.float64,
        copy=False
    )

    remaining_invalid = int(
        (
            ~np.isfinite(
                final_values
            )
        ).sum()
    )

    if remaining_invalid > 0:
        raise ValueError(
            "Model input still contains "
            f"{remaining_invalid} invalid numeric "
            "value(s) after sanitization."
        )

    print(
        "[FORENXAI] Numeric model input "
        "validated successfully.",
        flush=True
    )

    return cleaned


# ============================================================
# PREPARE MODEL INPUT
# ============================================================

def prepare_model_input(
    dataframe: pd.DataFrame
) -> tuple[
    pd.DataFrame,
    np.ndarray
]:
    """
    Select the frozen feature set, sanitize it, and apply the
    training-time scaler.

    Returns:
        raw_feature_frame
        scaled_matrix
    """

    bundle = load_model_bundle()

    scaler = bundle["scaler"]

    expected_features = list(
        bundle["features"]
    )


    dataframe = _normalize_columns(
        dataframe
    )


    # --------------------------------------------------------
    # Verify required columns
    # --------------------------------------------------------

    missing_features = [
        feature
        for feature
        in expected_features
        if feature not in dataframe.columns
    ]


    if missing_features:

        raise ValueError(
            "CICFlowMeter output is missing "
            f"{len(missing_features)} required "
            "model feature(s):\n\n"
            + "\n".join(
                missing_features
            )
        )


    # --------------------------------------------------------
    # Say what is being dropped, once, before dropping it
    #
    # CICFlowMeter gives 84 columns and the model consumes 66.
    # Selecting by name below discards the other 18 silently, so
    # they are reported here: identity columns that were never
    # features, the eight Active/Idle columns excluded by the
    # feature contract, and anything else -- which would be a real
    # feature this model was not trained on.
    # --------------------------------------------------------

    unused = describe_extra_columns(
        dataframe
    )

    print(
        f"[FORENXAI] Features: {len(expected_features)} used, "
        f"{sum(len(v) for v in unused.values())} not used "
        f"({len(unused['identity'])} identity, "
        f"{len(unused['excluded_degenerate'])} excluded by contract, "
        f"{len(unused['untrained'])} untrained)",
        flush=True
    )

    if unused["untrained"]:
        print(
            "[FORENXAI] Not trained on: "
            + ", ".join(unused["untrained"]),
            flush=True
        )


    # --------------------------------------------------------
    # CRITICAL:
    # Preserve EXACT feature order from features.pkl.
    #
    # dataframe[expected_features] selects those columns, in that
    # order, and drops every other column. This single line IS the
    # answer to "what happens to the extra CICFlowMeter columns":
    # they are not reordered, imputed or averaged in -- they are
    # left out, because the scaler and the booster were both fitted
    # on exactly these 66 in exactly this order.
    # --------------------------------------------------------

    feature_frame = dataframe[
        expected_features
    ].copy()


    # --------------------------------------------------------
    # SANITIZE BEFORE validation/scaling
    # --------------------------------------------------------

    feature_frame = sanitize_model_input(
        feature_frame
    )


    if list(
        feature_frame.columns
    ) != expected_features:

        raise RuntimeError(
            "Model feature order changed unexpectedly."
        )


    # --------------------------------------------------------
    # Scale using the scaler from training
    # --------------------------------------------------------

    # .to_numpy() rather than the DataFrame: the scaler was fitted on
    # an unnamed array, so handing it a named frame makes scikit-learn
    # warn that the feature names are unrecognised. Column ORDER is
    # what the scaler actually relies on, and that was fixed and
    # checked above -- the names were never carrying the contract.
    scaled_matrix = scaler.transform(
        feature_frame.to_numpy()
    )


    scaled_matrix = np.asarray(
        scaled_matrix,
        dtype=np.float64
    )


    # --------------------------------------------------------
    # Validate scaled matrix too
    # --------------------------------------------------------

    scaled_invalid_count = int(
        (
            ~np.isfinite(
                scaled_matrix
            )
        ).sum()
    )


    if scaled_invalid_count > 0:

        raise ValueError(
            "Scaled model input contains "
            f"{scaled_invalid_count} invalid "
            "numeric value(s)."
        )


    print(
        "[FORENXAI] Model input scaling complete.",
        flush=True
    )


    return (
        feature_frame,
        scaled_matrix
    )


# ============================================================
# METADATA VALUE HELPERS
# ============================================================

def _safe_string(
    value: Any
) -> str:

    if value is None:
        return ""

    try:

        if pd.isna(value):
            return ""

    except Exception:
        pass

    return str(value)


def _safe_int(
    value: Any
) -> int:

    try:

        if pd.isna(value):
            return 0

        return int(
            float(value)
        )

    except (
        TypeError,
        ValueError
    ):

        return 0


def _json_number(
    value: Any
) -> float | int | None:
    """
    Convert a numeric value into a JSON-safe finite number.
    """

    try:

        number = float(
            value
        )

    except (
        TypeError,
        ValueError
    ):

        return None


    if not np.isfinite(
        number
    ):

        return None


    if number.is_integer():

        return int(
            number
        )


    return number


# ============================================================
# EXTRACT FLOW METADATA
# ============================================================

def _extract_metadata(
    row: pd.Series
) -> dict[str, Any]:

    return {
        "Flow ID": _safe_string(
            row.get(
                "Flow ID",
                ""
            )
        ),

        "Src IP": _safe_string(
            row.get(
                "Src IP",
                ""
            )
        ),

        "Src Port": _safe_int(
            row.get(
                "Src Port",
                0
            )
        ),

        "Dst IP": _safe_string(
            row.get(
                "Dst IP",
                ""
            )
        ),

        "Dst Port": _safe_int(
            row.get(
                "Dst Port",
                0
            )
        ),

        "Protocol": _safe_int(
            row.get(
                "Protocol",
                0
            )
        ),

        "Timestamp": _safe_string(
            row.get(
                "Timestamp",
                ""
            )
        ),
    }


# ============================================================
# CLASSIFY DATAFRAME
# ============================================================

def classify_dataframe(
    dataframe: pd.DataFrame
) -> dict[str, Any]:
    """
    Run the 16-class FORENXAI XGBoost classifier on a
    CICFlowMeter dataframe.
    """

    if dataframe is None:

        raise ValueError(
            "No flow dataframe was provided."
        )


    if dataframe.empty:

        raise ValueError(
            "CICFlowMeter produced no flow rows."
        )


    dataframe = _normalize_columns(
        dataframe
    )


    bundle = load_model_bundle()

    model = bundle["model"]
    label_encoder = bundle[
        "label_encoder"
    ]
    class_names = [
        str(value)
        for value
        in bundle["classes"]
    ]


    # --------------------------------------------------------
    # Prepare / sanitize / scale
    # --------------------------------------------------------

    (
        feature_frame,
        scaled_matrix
    ) = prepare_model_input(
        dataframe
    )


    # --------------------------------------------------------
    # Prediction
    # --------------------------------------------------------

    print(
        "[FORENXAI] Running XGBoost prediction...",
        flush=True
    )


    # --------------------------------------------------------
    # One pass, on the device the booster is already on
    #
    # The obvious code calls model.predict() for the class and
    # model.predict_proba() for the confidence. For a multi:softprob
    # booster those are the same computation: predict() IS
    # predict_proba() followed by argmax, so calling both walks all
    # 400 trees twice. Measured on this model: 2.0x slower at every
    # size tried, 500 to 50,000 rows.
    #
    # Building the DMatrix explicitly also removes the "mismatched
    # devices" warning. That warning fires because the booster was
    # saved on cuda while the input array is in host memory, so
    # inplace_predict falls back to building a DMatrix -- which is
    # what this line now does openly. The warning's own suggestion,
    # moving the booster to the CPU, was measured at 4.26 s against
    # 0.74 s on 200,000 rows: six times slower for identical output.
    # Verified byte-identical to the previous path, max probability
    # difference 0.000e+00.
    # --------------------------------------------------------

    booster = model.get_booster()

    probabilities = booster.predict(
        xgboost.DMatrix(scaled_matrix)
    )


    probabilities = np.asarray(
        probabilities,
        dtype=np.float64
    )


    # multi:softprob returns one row of 16 class probabilities per
    # flow; the predicted class is the argmax of that row, which is
    # exactly what model.predict() would have returned.
    encoded_predictions = (
        probabilities
        .argmax(axis=1)
        .astype(int)
    )


    predicted_classes = (
        label_encoder
        .inverse_transform(
            encoded_predictions
        )
    )


    # --------------------------------------------------------
    # Probabilities
    # --------------------------------------------------------

    # Probabilities were produced above, in the same pass that gave
    # the class. Nothing to recompute.


    if probabilities.ndim != 2:

        raise RuntimeError(
            "XGBoost probability output "
            "has an unexpected shape."
        )


    if probabilities.shape[0] != len(
        dataframe
    ):

        raise RuntimeError(
            "Prediction row count does not "
            "match CICFlowMeter row count."
        )


    if probabilities.shape[1] != len(
        class_names
    ):

        raise RuntimeError(
            "XGBoost probability class count "
            "does not match label_encoder.pkl."
        )


    if not np.isfinite(
        probabilities
    ).all():

        raise ValueError(
            "XGBoost returned invalid "
            "probability values."
        )


    # --------------------------------------------------------
    # Build per-flow findings
    # --------------------------------------------------------

    findings: list[
        dict[str, Any]
    ] = []


    class_counts: dict[
        str,
        int
    ] = {}


    benign_flows = 0
    threat_flows = 0


    for row_index in range(
        len(dataframe)
    ):

        predicted_class = str(
            predicted_classes[
                row_index
            ]
        )


        encoded_class = int(
            encoded_predictions[
                row_index
            ]
        )


        confidence = float(
            probabilities[
                row_index,
                encoded_class
            ]
        )


        is_threat = (
            predicted_class
            .strip()
            .lower()
            != "benign"
        )


        if is_threat:
            threat_flows += 1
        else:
            benign_flows += 1


        class_counts[
            predicted_class
        ] = (
            class_counts.get(
                predicted_class,
                0
            )
            + 1
        )


        probability_map = {
            class_names[class_index]:
                float(
                    probabilities[
                        row_index,
                        class_index
                    ]
                )

            for class_index
            in range(
                len(class_names)
            )
        }


        metadata = _extract_metadata(
            dataframe.iloc[
                row_index
            ]
        )


        findings.append(
            {
                "flow_index": row_index,

                "predicted_class":
                    predicted_class,

                "confidence":
                    confidence,

                "is_threat":
                    is_threat,

                "probabilities":
                    probability_map,

                "metadata":
                    metadata,
            }
        )


    total_flows = len(
        findings
    )


    if total_flows > 0:

        threat_percentage = (
            threat_flows
            / total_flows
            * 100.0
        )

    else:

        threat_percentage = 0.0


    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    summary = {
        "total_flows":
            total_flows,

        "benign_flows":
            benign_flows,

        "threat_flows":
            threat_flows,

        "threat_percentage":
            round(
                threat_percentage,
                2
            ),

        "class_counts":
            class_counts,
    }


    print(
        "[FORENXAI] XGBoost classification complete.",
        flush=True
    )

    print(
        f"[FORENXAI] ML flows: {total_flows}",
        flush=True
    )

    print(
        f"[FORENXAI] Benign: {benign_flows}",
        flush=True
    )

    print(
        f"[FORENXAI] Threats: {threat_flows}",
        flush=True
    )

    print(
        "[FORENXAI] Threat percentage: "
        f"{threat_percentage:.2f}%",
        flush=True
    )


    return {
        "summary": summary,
        "findings": findings,

        # Internal values used by SHAP.
        # These objects are NOT intended to be JSON serialized.
        "_feature_frame":
            feature_frame,

        "_scaled_matrix":
            scaled_matrix,
    }


# ============================================================
# CLASSIFY CICFLOWMETER CSV
# ============================================================

def classify_flow_csv(
    flow_csv: Path | str
) -> dict[str, Any]:
    """
    Read a CICFlowMeter CSV and classify all flows.

    This is the main entry point recommended for analysis.py.
    """

    flow_csv = Path(
        flow_csv
    ).resolve()


    if not flow_csv.exists():

        raise FileNotFoundError(
            "CICFlowMeter CSV was not found:\n"
            f"{flow_csv}"
        )


    if not flow_csv.is_file():

        raise ValueError(
            "CICFlowMeter path is not a file:\n"
            f"{flow_csv}"
        )


    if flow_csv.stat().st_size <= 0:

        raise ValueError(
            "CICFlowMeter CSV is empty:\n"
            f"{flow_csv}"
        )


    print(
        "[FORENXAI] Reading CICFlowMeter CSV...",
        flush=True
    )

    print(
        f"[FORENXAI] Flow CSV: {flow_csv}",
        flush=True
    )


    dataframe = pd.read_csv(
        flow_csv,
        low_memory=False
    )


    dataframe = _normalize_columns(
        dataframe
    )


    print(
        "[FORENXAI] CICFlowMeter rows: "
        f"{len(dataframe)}",
        flush=True
    )

    print(
        "[FORENXAI] CICFlowMeter columns: "
        f"{len(dataframe.columns)}",
        flush=True
    )


    result = classify_dataframe(
        dataframe
    )


    # Store the CSV path as JSON-friendly text.
    result["flow_csv"] = str(
        flow_csv
    )


    return result


# ============================================================
# BACKWARD-COMPATIBLE ENTRY POINTS
# ============================================================

def classify_csv(
    flow_csv: Path | str
) -> dict[str, Any]:

    return classify_flow_csv(
        flow_csv
    )


def run_classification(
    flow_csv: Path | str
) -> dict[str, Any]:

    return classify_flow_csv(
        flow_csv
    )


def predict_flow_csv(
    flow_csv: Path | str
) -> dict[str, Any]:

    return classify_flow_csv(
        flow_csv
    )


# ============================================================
# JSON-SAFE RESULT
# ============================================================

def make_json_safe_result(
    result: dict[str, Any]
) -> dict[str, Any]:
    """
    Remove internal pandas/NumPy objects before analysis.json
    serialization.

    SHAP should consume the internal matrix before this function
    is called.
    """

    return {
        key: value
        for key, value
        in result.items()
        if not key.startswith("_")
    }