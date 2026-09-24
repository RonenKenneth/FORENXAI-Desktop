# ============================================================
# FORENXAI
# Narration comes from the deterministic RAG, not from a prompt
#
# Run:  backend\.venv\Scripts\python.exe test_narration_rag.py
#
# What this protects:
#   The explanation panel must render what the recommendation
#   stage retrieved and verified, and must never generate
#   wording of its own. These checks fail if someone puts a
#   second model call back into narration_service, or if the
#   composed text stops being reproducible.
#
# Deliberately cheap: _compose is a pure function, so nothing
# here loads the 1.8 GB Qwen weights. The generation path
# belongs to recommendation_service and is covered by
# test_recommendations_all_classes.py.
# ============================================================

from app.services import narration_service
from app.services.narration_service import (
    _compose,
    generate_flow_narration,
)


FEATURES = [
    {
        "feature": "Flow_IAT_Mean",
        "feature_value": 12.5,
        "shap_value": 1.42,
        "direction": "supports",
    },
    {
        "feature": "Fwd_Packet_Length_Max",
        "feature_value": 1460,
        "shap_value": 0.88,
        "direction": "supports",
    },
    {
        "feature": "Total_Fwd_Packets",
        "feature_value": 3,
        "shap_value": -0.31,
        "direction": "opposes",
    },
]


RECOMMENDATION = {
    "summary": "Sustained request volume from one source.",
    "actions": [
        "Rate-limit the source address at the boundary",
        "Preserve the flow records for the affected window",
    ],
    "actions_cited": [
        "Rate-limit the source address at the boundary [1, SC-5].",
        "Preserve the flow records for the affected window [2, Sec. 3.1, p. 26].",
    ],
    "references": [
        {"number": 1, "doc_id": "NIST.SP.800-53r5", "acm": "NIST. 2020. SP 800-53r5."},
        {"number": 2, "doc_id": "NIST.SP.800-86", "acm": "Kent et al. 2006. SP 800-86."},
    ],
    "standards_grounded": True,
    "verified": True,
    "generator": "qwen2.5-3b-q4.gguf",
}


def test_no_model_call_in_narration():
    """The module must not hold a handle to the LLM any more."""
    source = open(
        narration_service.__file__,
        encoding="utf-8"
    ).read()

    assert "get_llm" not in source, (
        "narration_service calls the LLM again; the explanation "
        "must come from the recommendation stage"
    )

    assert "_build_prompt" not in source, (
        "narration_service still builds its own prompt"
    )

    assert not hasattr(narration_service, "TEMPERATURE"), (
        "a sampling temperature in narration_service means "
        "something there is still generating"
    )

    print("[PASS] no model call left in narration_service")


def test_compose_is_deterministic():
    first = _compose("DDoS", 0.93, FEATURES, RECOMMENDATION)
    second = _compose("DDoS", 0.93, FEATURES, RECOMMENDATION)

    assert first == second, "the same inputs produced two paragraphs"
    assert len(first) > 80, "the explanation is suspiciously short"

    print("[PASS] compose is deterministic")


def test_compose_carries_the_provenance():
    text = _compose("DDoS", 0.93, FEATURES, RECOMMENDATION)

    assert "DDoS" in text
    assert "Confidence 93.0%" in text, "confidence is missing"
    assert "Flow_IAT_Mean" in text, "the top SHAP driver is missing"
    assert RECOMMENDATION["summary"] in text, "the retrieved summary is missing"
    assert "[1, SC-5]" in text, "the in-text citation was dropped"
    assert "SP 800-86" in text, "the reference list was dropped"

    # An answer built only from the internal corpus has to say so.
    ungrounded = dict(RECOMMENDATION, standards_grounded=False)
    note = "own detection profiles"

    assert note in _compose("DDoS", 0.9, FEATURES, ungrounded)
    assert note not in text

    print("[PASS] compose carries summary, drivers, citations, references")


def test_compose_survives_a_bad_confidence():
    text = _compose("DDoS", "not-a-number", FEATURES, RECOMMENDATION)

    assert "Confidence" not in text, "an unparsable confidence was printed"
    assert "DDoS" in text, "the explanation was lost with the confidence"

    print("[PASS] an unparsable confidence is left out, not raised")


def test_unknown_class_falls_back_without_raising():
    """Retrieval raises KeyError for a class the map does not know."""
    result = generate_flow_narration(
        {"predicted_class": "NotAClass", "confidence": 0.5},
        {"top_features": FEATURES},
    )

    assert result["fallback_used"] is True
    assert result["available"] is False
    assert result["provider"] == "deterministic_fallback"
    assert "NotAClass" in result["text"]
    assert result["error"], "the failure was swallowed without a reason"

    print("[PASS] an unknown class falls back and says why")


if __name__ == "__main__":
    test_no_model_call_in_narration()
    test_compose_is_deterministic()
    test_compose_carries_the_provenance()
    test_compose_survives_a_bad_confidence()
    test_unknown_class_falls_back_without_raising()

    print("\nALL CHECKS PASSED")
