# ============================================================
# FORENXAI
# The AI-generated summary restates facts; it never adds any
#
# Run:  backend\.venv\Scripts\python.exe test_narration_rag.py
#
# What this protects:
#   Qwen may write the sentences of the summary panel, but only
#   as a rewording of facts the pipeline already established:
#   the prediction, its SHAP drivers and the rule result. These
#   checks fail if a sentence can bring in a number, a class, a
#   feature or a judgement that is not in the facts, merge two
#   facts into a wrong one, or if a fact can go missing.
#
# Cheap: Qwen is replaced by fixed answers, so the 1.8 GB model
# is never loaded.
# ============================================================

import json

from app.services import narration_service as ns


FINDING = {
    "predicted_class": "DoS",
    "confidence": 0.393,
    "probabilities": {"DoS": 0.393, "Slowloris": 0.391, "PortScan": 0.094},
    "rule_findings": None,
}
SHAP = {"contributors": [
    {"feature": "Fwd Packet Length Max", "raw_value": 0.0, "shap_value": 0.932},
    {"feature": "Fwd Packet Length Mean", "raw_value": 0.0, "shap_value": 0.406},
    {"feature": "Dst Port", "raw_value": 256, "shap_value": -0.335},
]}


def run(sentences):
    """Summary for FINDING with Qwen replaced by a fixed JSON answer."""
    real = ns._generate
    ns._generate = lambda prompt, count: (
        None if sentences is None else json.dumps({"sentences": sentences}))
    ns._cache.clear()
    try:
        return ns.generate_flow_narration(FINDING, SHAP)
    finally:
        ns._generate = real


def facts():
    return ns._facts(FINDING, [ns._normalize_feature(f) for f in SHAP["contributors"]])


def test_facts_are_deterministic_and_complete():
    a, b = facts(), facts()
    assert a == b
    text = " ".join(a)
    for needed in ("DoS", "39.3%", "Slowloris at 39.1%", "Fwd Packet Length Max",
                   "+0.932", "away from DoS", "not evaluated"):
        assert needed in text, needed
    print("[PASS] facts are deterministic and carry prediction, SHAP and rules")


def test_faithful_rewording_is_kept():
    f = facts()
    reworded = [
        "The XGBoost classifier assigned this flow to the DoS class with 39.3% confidence.",
        "The Fwd Packet Length Max was 0, and its SHAP value of +0.932 pushed the decision toward DoS.",
    ]
    result = run(reworded)
    assert result["provider"] == "qwen_verified", result
    assert result["sentences_kept"] == 2
    for sentence in reworded:
        assert sentence in result["text"]
    # the facts Qwen did not reword are still there, as recorded
    assert result["facts_shown_verbatim"] == len(f) - 2
    assert "Rule-based detection was not evaluated" in result["text"]
    print("[PASS] faithful sentences kept; every other fact still shown")


def test_additions_are_dropped():
    cases = {
        "a number not in the facts":
            "The XGBoost classifier assigned this flow to the DoS class with 97.0% confidence.",
        "combines figures from different facts":
            "The flow was DoS at 39.3% confidence and its F1 score is 0.686.",
        "mixes in wording from another fact":
            "The XGBoost classifier assigned this flow to the DoS class with 39.3% confidence on held-out test data.",
        "speculative or prescriptive wording":
            "The attacker assigned this flow to the DoS class.",
        "names DDoS, which is not in the facts":
            "The XGBoost classifier assigned this flow to the DDoS class.",
    }
    good = "The next most probable classes were Slowloris at 39.1% and PortScan at 9.4%."
    result = run(list(cases.values()) + [good, "Rule-based detection was not evaluated for this flow."])
    reasons = [d["reason"] for d in result["dropped_sentences"]]
    for reason in cases:
        assert any(r.startswith(reason) for r in reasons), (reason, reasons)
    for sentence in cases.values():
        assert sentence not in result["text"], sentence
    print("[PASS] invented numbers, merged facts, speculation and unlisted names are dropped")


def test_feature_names_inside_longer_names_are_not_false_alarms():
    sentence = "Fwd Packet Length Max was 0, and its SHAP value of +0.932 pushed the decision toward DoS."
    reason, _ = ns._check(sentence, facts(), {"DoS", "Fwd Packet Length Max"},
                          {"Packet Length Max", "Fwd Packet Length Max", "DoS", "DDoS"})
    assert reason is None, reason
    print("[PASS] 'Packet Length Max' inside 'Fwd Packet Length Max' is not flagged")


def test_no_model_means_facts_as_recorded():
    result = run(None)
    assert result["fallback_used"] is True
    assert result["provider"] == "deterministic_facts"
    assert result["text"] == " ".join(facts())
    print("[PASS] without Qwen the facts are shown as recorded")


def test_unknown_class_does_not_raise():
    real = ns._generate
    ns._generate = lambda prompt, count: None
    ns._cache.clear()
    try:
        result = ns.generate_flow_narration({"predicted_class": "NotAClass", "confidence": 0.5}, SHAP)
    finally:
        ns._generate = real
    assert "NotAClass" in result["text"]
    print("[PASS] an unknown class still produces its facts")


if __name__ == "__main__":
    test_facts_are_deterministic_and_complete()
    test_faithful_rewording_is_kept()
    test_additions_are_dropped()
    test_feature_names_inside_longer_names_are_not_false_alarms()
    test_no_model_means_facts_as_recorded()
    test_unknown_class_does_not_raise()
    print("\nALL CHECKS PASSED")
