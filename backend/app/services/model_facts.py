# ============================================================
# FORENXAI
# Measured facts about the deployed classifier
#
# Purpose:
#   Answer "how good is this class", "what is it confused
#   with", "do these two classes share evidence" from the
#   evaluation that produced the shipped model, not from a
#   number typed into a document.
#
# WHY THIS EXISTS
#   Figures were written into the knowledge corpus as prose --
#   "confused in 8.7% of cases", "correlates at 0.9159". Two
#   problems follow. The first is that prose does not get
#   recomputed: retrain the model and every figure silently
#   becomes a claim about a model that no longer exists. The
#   second is direction. 8.7% was the Exploitation-to-
#   BufferOverflow rate, written into the BufferOverflow file,
#   where the true rate is 21.9% -- two and a half times higher.
#   A confusion matrix is not symmetric and prose does not
#   record which way round it was read.
#
#   model_facts.json is written by the evaluation pipeline and
#   shipped with the model it describes. If it disagrees with
#   the model it is beside, both are wrong together, which is
#   the only failure mode worth having.
# ============================================================

from __future__ import annotations

import json
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Optional, Tuple

FACTS_FILE = (
    Path(__file__).resolve().parents[2]
    / "models" / "forenxai" / "model_facts.json"
)


# A class is worth flagging as uncertain below this test F1. Set from the
# gap in the per-class results rather than picked: twelve classes sit above
# 0.94 and four below 0.81, so anything in between separates them.
LOW_F1 = 0.90

# A confusion rate worth telling an analyst about.
CONFUSION_FLOOR = 0.03

# A predicted probability worth treating as a live alternative.
ALTERNATIVE_FLOOR = 0.15

# How far below the top probability a runner-up may sit and still be
# considered a live alternative.
ALTERNATIVE_MARGIN = 0.45

MAX_ALTERNATIVES = 2


_facts: Optional[Dict[str, Any]] = None
_lock = Lock()


def facts() -> Dict[str, Any]:
    """The evaluation figures for the shipped model, or {} when absent."""
    global _facts

    if _facts is not None:
        return _facts

    with _lock:

        if _facts is not None:
            return _facts

        if not FACTS_FILE.is_file():
            print(
                f"[FORENXAI] model_facts.json not found at {FACTS_FILE}; "
                f"recommendations will omit measured confusion figures.",
                flush=True
            )
            _facts = {}
            return _facts

        try:
            _facts = json.loads(
                FACTS_FILE.read_text(encoding="utf-8")
            )
        except (OSError, ValueError) as error:
            print(
                f"[FORENXAI] model_facts.json unreadable "
                f"({type(error).__name__}); continuing without it.",
                flush=True
            )
            _facts = {}

        return _facts


def available() -> bool:
    return bool(facts())


def class_f1(predicted_class: str) -> Optional[float]:
    """Test F1 for one class, from the evaluation that shipped the model."""
    return facts().get("per_class_f1", {}).get(predicted_class)


def is_low_confidence_class(predicted_class: str) -> bool:
    score = class_f1(predicted_class)
    return score is not None and score < LOW_F1


def confusion(from_class: str, to_class: str) -> Optional[float]:
    """Share of `from_class` flows the model predicts as `to_class`.

    Directional. confusion(A, B) is not confusion(B, A), which is the
    mistake the prose version made.
    """
    row = facts().get("confusion_rownorm", {}).get(from_class)

    if not row:
        return None

    return row.get(to_class)


def confused_with(predicted_class: str,
                  floor: float = CONFUSION_FLOOR) -> List[Tuple[str, float]]:
    """Classes this one is misread as, worst first."""
    row = facts().get("confusion_rownorm", {}).get(predicted_class, {})

    pairs = [
        (other, rate)
        for other, rate in row.items()
        if other != predicted_class and rate >= floor
    ]

    return sorted(pairs, key=lambda item: -item[1])


def pair_similarity(a: str, b: str) -> Optional[Dict[str, Any]]:
    """How far two classes rest on the same features, and its rank."""
    table = facts().get("pair_similarity", {})

    return table.get(f"{a}|{b}") or table.get(f"{b}|{a}")


def alternatives(predicted_class: str,
                 probabilities: Optional[Dict[str, float]] = None,
                 confidence: Optional[float] = None) -> List[Dict[str, Any]]:
    """Classes this flow might be instead, worst case first.

    Two sources, in order of strength:

      probabilities  what the model said about THIS flow. A runner-up
                     close to the top is a live alternative for this
                     flow specifically, which is the thing an analyst
                     actually needs.

      confusion      what the model does to this class in general,
                     used when no per-flow distribution is available.
                     Weaker, because it describes the class rather
                     than the flow.

    Returns [] when the prediction is confident and the class is not one
    the evaluation flags -- there is nothing useful to say, and saying
    something anyway trains an analyst to ignore the field.
    """
    found: List[Dict[str, Any]] = []

    if probabilities:

        ranked = sorted(
            (
                (name, value)
                for name, value in probabilities.items()
                if name != predicted_class
            ),
            key=lambda item: -item[1],
        )

        top = max(probabilities.values()) if probabilities else 1.0

        for name, value in ranked[:MAX_ALTERNATIVES]:

            if value < ALTERNATIVE_FLOOR:
                continue

            if top - value > ALTERNATIVE_MARGIN:
                continue

            found.append({
                "class": name,
                "probability": round(float(value), 4),
                "basis": "this flow's predicted distribution",
                "confusion": confusion(predicted_class, name),
            })

    if not found and (
        (confidence is not None and confidence < 0.80)
        or is_low_confidence_class(predicted_class)
    ):
        for name, rate in confused_with(predicted_class)[:MAX_ALTERNATIVES]:
            found.append({
                "class": name,
                "probability": None,
                "basis": "how often this class is misread in testing",
                "confusion": rate,
            })

    return found


def describe(predicted_class: str,
             probabilities: Optional[Dict[str, float]] = None,
             confidence: Optional[float] = None) -> Dict[str, Any]:
    """Everything measured that bears on trusting this prediction."""
    alts = alternatives(predicted_class, probabilities, confidence)

    notes: List[str] = []

    score = class_f1(predicted_class)

    if score is not None:
        notes.append(
            f"Test F1 for {predicted_class} is {score:.4f}."
        )

    for alternative in alts:

        rate = alternative["confusion"]

        if rate:
            notes.append(
                f"{rate * 100:.1f}% of {predicted_class} flows are "
                f"predicted as {alternative['class']} in testing."
            )

        similarity = pair_similarity(
            predicted_class, alternative["class"]
        )

        if similarity:
            notes.append(
                f"{predicted_class} and {alternative['class']} share "
                f"{similarity['shared_top10']} of their ten leading "
                f"features (rank {similarity['rank']} of "
                f"{facts().get('n_pairs', 120)} pairs by attribution "
                f"similarity)."
            )

    return {
        "available": available(),
        "class_f1": score,
        "low_confidence_class": is_low_confidence_class(predicted_class),
        "confidence": confidence,
        "alternatives": alts,
        "notes": notes,
    }
