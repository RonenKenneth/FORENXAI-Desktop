# ============================================================
# FORENXAI
# Local XAI Narration Service
#
# Purpose:
#   Convert XGBoost + TreeSHAP results into a grounded,
#   human-readable explanation.
#
# Important:
#   - XGBoost performs classification.
#   - TreeSHAP calculates feature contributions.
#   - The explanation only describes those existing results.
#   - Nothing here is allowed to change the classification.
#
# WHERE THE WORDS COME FROM
#   This service used to build its own prompt and call Qwen a
#   second time, once per flow, at temperature 0.1. That made
#   the panel an examiner reads the one part of the pipeline
#   that was neither cited nor reproducible: the same flow
#   could be described two ways on two runs, and none of the
#   wording could be traced to a document.
#
#   It now renders what the recommendation stage already
#   produced for the class. That stage retrieves by dictionary
#   lookup through rag/config/knowledge_map.py, reads the
#   playbooks and detection profiles under rag/knowledge/, and
#   cites them through rag/_sources/manifest.json, dropping any
#   sentence it cannot trace back to the passage it came from.
#   Its answer is cached per class, so narration costs no
#   generation at all: the text was written once, for the
#   class, and verified before it was stored.
#
#   What stays per flow is the only thing that is per flow --
#   the TreeSHAP drivers and the confidence. Those are
#   formatted here, from the numbers, with no model involved.
# ============================================================

from typing import Any

from app.services.recommendation_service import (
    get_recommendation,
)


# ============================================================
# SETTINGS
# ============================================================

MAX_FEATURES = 5

# How many of the recommendation's actions the explanation
# shows. The recommendation stage returns up to six; listing
# all of them turns the explanation into the recommendations
# panel a second time.
MAX_ACTIONS_SHOWN = 3


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



    # The recommendation stage owns retrieval, verification and
    # citation. Ask it for this class and render what comes back. Its
    # answer is cached per class, so the first flow of a class pays for
    # it and every later flow of that class is free.
    try:

        recommendation = (
            get_recommendation(
                predicted_class,
                normalized_features,
                _get_confidence(
                    finding
                ),
                finding.get(
                    "probabilities"
                ),
            )
        )

    except Exception as error:                      # noqa: BLE001

        # Retrieval failed: a missing knowledge map, or a class the map
        # does not know. The panel still explains the TreeSHAP result,
        # and says plainly that it did so without the documents.
        print(
            "[FORENXAI NARRATION WARNING] "
            f"{type(error).__name__}: {error}",
            flush=True
        )

        return {

            "available":
                False,

            "provider":
                "deterministic_fallback",

            "model":
                "treeshap",

            "predicted_class":
                predicted_class,

            "text":
                _build_fallback_explanation(
                    predicted_class,
                    normalized_features
                ),

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


    return {

        "available":
            True,

        "provider":
            "deterministic_rag",

        # Which stage wrote the wording of the actions: the model when
        # every sentence traced back to a passage, "extraction" when
        # they did not and the passages were quoted instead.
        "model":
            recommendation.get(
                "generator",
                "extraction"
            ),

        "predicted_class":
            predicted_class,

        "text":
            _compose(
                predicted_class,
                _get_confidence(
                    finding
                ),
                normalized_features,
                recommendation
            ),

        "fallback_used":
            False,

        "features_used":
            normalized_features[
                :MAX_FEATURES
            ],

        # Provenance, for the report and for anyone who asks on whose
        # authority an action is being suggested. The panel is free to
        # ignore these; a reader is not.
        "references":
            recommendation.get(
                "references",
                []
            ),

        "standards_grounded":
            recommendation.get(
                "standards_grounded",
                False
            ),

        "verified":
            recommendation.get(
                "verified",
                False
            ),
    }


# ============================================================
# COMPOSE THE EXPLANATION
# ============================================================

def _compose(
    predicted_class: str,
    confidence: Any,
    normalized_features: list,
    recommendation: dict
) -> str:
    """Place the retrieved guidance beside this flow's own drivers.

    Deterministic by construction. Every line is either read from the
    recommendation, which was already verified against the passage it
    came from, or formatted from a TreeSHAP number. Two runs of one
    case produce the same paragraph, and two flows of one class differ
    only where their SHAP values differ -- which is the only way they
    do differ.
    """
    opening = _build_fallback_explanation(
        predicted_class,
        normalized_features
    )

    if confidence is not None:

        try:
            opening = (
                f"{opening.rstrip()} "
                f"Confidence {float(confidence):.1%}."
            )

        except (TypeError, ValueError):
            # A confidence that will not parse is left out rather than
            # printed raw. It is not worth failing an explanation over.
            pass


    lines = [opening]


    summary = str(
        recommendation.get(
            "summary"
        )
        or ""
    ).strip()


    if summary:
        lines.append(summary)


    # actions_cited carries the in-text marker, actions does not, so the
    # cited form is preferred: it lets a reader follow one claim to one
    # page instead of to a bibliography.
    actions = (
        recommendation.get(
            "actions_cited"
        )
        or recommendation.get(
            "actions"
        )
        or []
    )


    if actions:

        lines.append(
            "Indicated response:"
        )

        lines.extend(
            f"- {action}"
            for action
            in actions[:MAX_ACTIONS_SHOWN]
        )


    references = (
        recommendation.get(
            "references"
        )
        or []
    )


    if references:

        lines.append(
            "Sources:"
        )

        lines.extend(
            (
                f"[{reference.get('number')}] "
                f"{reference.get('acm', '')}"
            ).rstrip()
            for reference
            in references
        )


    # Said out loud rather than left to be inferred from an absence.
    # The detection profiles describe how a class looks in this
    # dataset, which is ours to assert; what to do about it is not.
    if not recommendation.get(
        "standards_grounded"
    ):
        lines.append(
            "These actions rest on the project's own detection "
            "profiles rather than on a published standard."
        )


    return "\n".join(
        lines
    )
