# ============================================================
# FORENXAI
# Local XAI Narration Service
#
# Purpose:
#   Convert XGBoost + TreeSHAP results into a grounded,
#   human-readable explanation using the local Qwen model.
#
# Important:
#   - XGBoost performs classification.
#   - TreeSHAP calculates feature contributions.
#   - Qwen only explains those existing results.
#   - Qwen is NOT allowed to change the classification.
# ============================================================

from typing import Any

from app.services.llm_provider import (
    get_llm,
)


# ============================================================
# SETTINGS
# ============================================================

MAX_FEATURES = 5

MAX_TOKENS = 220

TEMPERATURE = 0.1

TOP_P = 0.9


# ============================================================
# SAFE VALUE FORMATTER
# ============================================================

def _format_value(
    value: Any
) -> str:
    """
    Convert model values into readable text without
    failing on None, strings, integers, or floats.
    """

    if value is None:
        return "N/A"

    if isinstance(
        value,
        float
    ):

        return f"{value:.6g}"

    return str(
        value
    )


# ============================================================
# FIND PREDICTED CLASS
# ============================================================

def _get_predicted_class(
    finding: dict
) -> str:
    """
    Support the field names currently used by different
    FORENXAI components.
    """

    return (
        finding.get(
            "predicted_class"
        )
        or finding.get(
            "prediction"
        )
        or finding.get(
            "class"
        )
        or "Unknown"
    )


# ============================================================
# FIND CONFIDENCE
# ============================================================

def _get_confidence(
    finding: dict
):
    """
    Read confidence if it is available.

    The narration service does not invent confidence values.
    """

    return (
        finding.get(
            "confidence"
        )
        or finding.get(
            "prediction_confidence"
        )
        or finding.get(
            "probability"
        )
    )


# ============================================================
# FIND SHAP FEATURES
# ============================================================

def _get_top_features(
    shap_explanation: dict
) -> list:
    """
    Retrieve the existing TreeSHAP feature contributions.

    Different FORENXAI versions may use slightly different
    container names, so this function checks known forms.
    """

    possible_keys = [
        "top_features",
        "features",
        "contributors",
        "top_contributors",
    ]

    for key in possible_keys:

        value = shap_explanation.get(
            key
        )

        if isinstance(
            value,
            list
        ):

            return value

    return []


# ============================================================
# NORMALIZE ONE SHAP FEATURE
# ============================================================

def _normalize_feature(
    feature: dict
) -> dict:
    """
    Convert one SHAP feature object into a predictable format.
    """

    feature_name = (
        feature.get(
            "feature"
        )
        or feature.get(
            "feature_name"
        )
        or feature.get(
            "name"
        )
        or "Unknown feature"
    )

    feature_value = (
        feature.get(
            "raw_value"
        )
        if "raw_value" in feature
        else (
            feature.get(
                "feature_value"
            )
            if "feature_value" in feature
            else feature.get(
                "value"
            )
        )
    )


    shap_value = (
        feature.get(
            "shap_value"
        )
        if "shap_value" in feature
        else feature.get(
            "contribution",
            0
        )
    )


    try:

        shap_value = float(
            shap_value
        )

    except (
        TypeError,
        ValueError
    ):

        shap_value = 0.0


    direction = (
        "supports"
        if shap_value > 0
        else (
            "opposes"
            if shap_value < 0
            else "neutral"
        )
    )


    return {

        "feature":
            feature_name,

        "feature_value":
            feature_value,

        "shap_value":
            shap_value,

        "direction":
            direction,
    }


# ============================================================
# BUILD DETERMINISTIC FALLBACK
# ============================================================

def _build_fallback_explanation(
    predicted_class: str,
    normalized_features: list
) -> str:
    """
    Produce a deterministic explanation if the local LLM
    cannot run.

    This ensures the XAI panel still works without Qwen.
    """

    if not normalized_features:

        return (
            f"The XGBoost classifier predicted "
            f"'{predicted_class}'. "
            "No TreeSHAP feature contributions were "
            "available for natural-language explanation."
        )


    supporting = [
        feature
        for feature
        in normalized_features
        if feature[
            "shap_value"
        ] > 0
    ]


    opposing = [
        feature
        for feature
        in normalized_features
        if feature[
            "shap_value"
        ] < 0
    ]


    parts = [

        f"The XGBoost classifier predicted "
        f"'{predicted_class}'."
    ]


    if supporting:

        names = ", ".join(

            feature[
                "feature"
            ]

            for feature
            in supporting[:3]
        )


        parts.append(
            "The strongest TreeSHAP features "
            f"supporting this prediction were {names}."
        )


    if opposing:

        names = ", ".join(

            feature[
                "feature"
            ]

            for feature
            in opposing[:2]
        )


        parts.append(
            "Features that opposed the prediction "
            f"included {names}."
        )


    return " ".join(
        parts
    )


# ============================================================
# BUILD QWEN PROMPT
# ============================================================

def _build_prompt(
    finding: dict,
    shap_explanation: dict,
    normalized_features: list
) -> str:
    """
    Build a strictly grounded prompt.

    Qwen receives only model outputs that were already
    calculated by FORENXAI.
    """

    flow_index = finding.get(
        "flow_index",
        shap_explanation.get(
            "flow_index",
            -1
        )
    )


    predicted_class = (
        _get_predicted_class(
            finding
        )
    )


    confidence = (
        _get_confidence(
            finding
        )
    )


    if confidence is None:

        confidence_text = (
            "Not provided"
        )

    else:

        confidence_text = (
            _format_value(
                confidence
            )
        )


    feature_lines = []


    for feature in (
        normalized_features[
            :MAX_FEATURES
        ]
    ):

        feature_lines.append(

            "- "
            f"{feature['feature']}: "
            f"value="
            f"{_format_value(feature['feature_value'])}, "
            f"SHAP="
            f"{feature['shap_value']:+.6f}, "
            f"direction="
            f"{feature['direction']}"
        )


    if feature_lines:

        feature_text = "\n".join(
            feature_lines
        )

    else:

        feature_text = (
            "No TreeSHAP feature "
            "contributions were available."
        )


    prompt = f"""
You are the explanation component of a network forensic
application named FORENXAI.

You are describing an EXISTING machine-learning result.

STRICT RULES:

1. XGBoost performed the classification.
2. TreeSHAP calculated the feature contributions.
3. You did NOT classify the traffic.
4. Never change the predicted class.
5. Use ONLY the evidence supplied below.
6. Do not infer packet contents.
7. Do not infer IP addresses.
8. Do not infer ports or protocols.
9. Do not infer attacker intent.
10. Do not describe a feature as malicious or benign.
11. Do not explain what a feature generally means unless that
    meaning is explicitly provided in the evidence.
12. Do not claim that a value is high, low, unusual, suspicious,
    normal, or abnormal unless such a comparison is explicitly
    supplied.
13. Positive SHAP values support the model's predicted class.
14. Negative SHAP values oppose the model's predicted class.
15. Mention the actual feature value and SHAP contribution.
16. Do not provide remediation advice.
17. Write one concise paragraph only.
18. Do not introduce cybersecurity facts that are absent from
    the evidence.

FORENXAI EVIDENCE

Flow index:
{flow_index}

XGBoost predicted class:
{predicted_class}

Model confidence:
{confidence_text}

TreeSHAP contributions:
{feature_text}

Write a factual explanation of the model decision using only
the evidence above.

A correct style is:

"The XGBoost classifier predicted [class]. Feature A, with a
value of X and SHAP contribution of +Y, supported the
prediction. Feature B, with a SHAP contribution of -Z,
opposed the prediction."

Do not add an interpretation beyond those supplied facts.
""".strip()

    return prompt


# ============================================================
# GENERATE NARRATION
# ============================================================

def generate_flow_narration(
    finding: dict,
    shap_explanation: dict
) -> dict:
    """
    Generate one grounded explanation for one flow.
    """

    predicted_class = (
        _get_predicted_class(
            finding
        )
    )


    raw_features = (
        _get_top_features(
            shap_explanation
        )
    )


    normalized_features = []


    for feature in raw_features:

        if not isinstance(
            feature,
            dict
        ):
            continue


        normalized_features.append(

            _normalize_feature(
                feature
            )
        )


    # Sort by absolute SHAP magnitude.
    normalized_features.sort(

        key=lambda item:
            abs(
                item[
                    "shap_value"
                ]
            ),

        reverse=True
    )


    fallback_text = (
        _build_fallback_explanation(
            predicted_class,
            normalized_features
        )
    )


    prompt = (
        _build_prompt(
            finding,
            shap_explanation,
            normalized_features
        )
    )


    try:

        llm = get_llm()


        result = llm(
            prompt,
            max_tokens=MAX_TOKENS,
            temperature=TEMPERATURE,
            top_p=TOP_P,
            echo=False
        )


        generated_text = (
            result[
                "choices"
            ][0][
                "text"
            ]
            .strip()
        )


        if not generated_text:

            raise RuntimeError(
                "Qwen returned an empty response."
            )


        return {

            "available":
                True,

            "provider":
                "llama-cpp-python",

            "model":
                "qwen2.5-3b-q4.gguf",

            "predicted_class":
                predicted_class,

            "text":
                generated_text,

            "fallback_used":
                False,

            "features_used":
                normalized_features[
                    :MAX_FEATURES
                ],
        }


    except Exception as error:

        print(
            "[FORENXAI LLM WARNING] "
            f"{type(error).__name__}: "
            f"{error}",
            flush=True
        )


        return {

            "available":
                False,

            "provider":
                "deterministic_fallback",

            "model":
                "qwen2.5-3b-q4.gguf",

            "predicted_class":
                predicted_class,

            "text":
                fallback_text,

            "fallback_used":
                True,

            "features_used":
                normalized_features[
                    :MAX_FEATURES
                ],

            "error":
                (
                    f"{type(error).__name__}: "
                    f"{error}"
                ),
        }