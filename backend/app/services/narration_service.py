# ============================================================
# FORENXAI
# AI-generated summary of one flow
#
# Purpose:
#   Turn what the pipeline already established about a flow --
#   the XGBoost prediction, its TreeSHAP drivers and the
#   rule-based result -- into a few readable sentences.
#
# The rule for this panel:
#   Qwen writes sentences. It does not decide anything.
#
#   1. The facts are assembled here, deterministically, from
#      the finding and its SHAP explanation, with each feature
#      explained from rag/knowledge/features/glossary.md.
#   2. Qwen is asked to restate those facts as prose, and only
#      those facts.
#   3. Every sentence it writes is checked before it is shown:
#        - it restates ONE fact: its numbers all come from that
#          fact, so two facts cannot be merged into a wrong one
#          ("39.3% confidence on held-out test data"),
#        - every class and feature it names is in the facts,
#        - it uses no speculative or prescriptive language the
#          facts do not (will, intends, should, compromise ...),
#        - at least half its wording comes from that fact.
#      A sentence that fails is dropped, with its reason.
#   4. If fewer than two sentences survive, or Qwen is not
#      available, the facts themselves are shown.
#
#   Response actions are not here: they belong to the
#   recommendations panel, which has its own retrieval and
#   verification.
# ============================================================

from __future__ import annotations

import json
import re
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Optional, Tuple

from app.services import model_facts
from app.utils.runtime_paths import get_rag_directory


# ============================================================
# SETTINGS
# ============================================================

MAX_FEATURES = 5          # SHAP drivers passed through to the caller
FEATURES_IN_FACTS = 3     # SHAP drivers the summary is written from
MIN_SENTENCES = 2
MAX_SENTENCES = 8
MAX_TOKENS = 320
TERM_COVERAGE = 0.5

# Words that would turn a summary into a claim: intent, prediction of what
# happens next, advice, or a verdict the pipeline did not reach. A sentence
# may use one only if the facts themselves do.
SPECULATIVE = (
    "will", "would", "intend", "intends", "intended", "attempt", "attempting",
    "trying", "probably", "possibly", "presumably", "suspect", "suspicious",
    "compromise", "compromised", "breach", "malicious", "attacker", "attackers",
    "should", "must", "recommend", "recommended", "immediately", "urgent",
    "confirms", "proves", "definitely", "certainly", "clearly",
)

_WORD = re.compile(r"[a-z][a-z/\-]{2,}")
_FIGURE = re.compile(r"\d+(?:[.,:]\d+)*")
_STOP = {
    "the", "and", "for", "was", "were", "this", "that", "with", "from", "its",
    "has", "had", "are", "into", "than", "which", "flow", "flows", "value",
}


# ============================================================
# INPUT HELPERS
# ============================================================

def _get_predicted_class(finding: dict) -> str:
    return (finding.get("predicted_class") or finding.get("prediction")
            or finding.get("class") or "Unknown")


def _get_confidence(finding: dict):
    """Confidence if the finding carries one. Never invented."""
    return (finding.get("confidence") or finding.get("prediction_confidence")
            or finding.get("probability"))


def _get_top_features(shap_explanation: dict) -> list:
    for key in ("top_features", "features", "contributors", "top_contributors"):
        value = (shap_explanation or {}).get(key)
        if isinstance(value, list):
            return value
    return []


def _normalize_feature(feature: dict) -> dict:
    name = (feature.get("feature") or feature.get("feature_name")
            or feature.get("name") or "Unknown feature")
    if "raw_value" in feature:
        value = feature.get("raw_value")
    elif "feature_value" in feature:
        value = feature.get("feature_value")
    else:
        value = feature.get("value")
    shap_value = feature.get("shap_value") if "shap_value" in feature \
        else feature.get("contribution", 0)
    try:
        shap_value = float(shap_value)
    except (TypeError, ValueError):
        shap_value = 0.0
    return {
        "feature": name,
        "feature_value": value,
        "shap_value": shap_value,
        "direction": "supports" if shap_value > 0 else (
            "opposes" if shap_value < 0 else "neutral"),
    }


def _format_value(value: Any) -> str:
    if value is None:
        return "N/A"
    try:
        number = float(value)
    except (TypeError, ValueError):
        return str(value)
    if number == int(number) and abs(number) < 1e15:
        return f"{int(number):,}"
    return f"{number:,.2f}" if abs(number) >= 1 else f"{number:.4g}"


# ============================================================
# FEATURE GLOSSARY
# ============================================================

_glossary: Optional[Dict[str, str]] = None
_glossary_lock = Lock()
_ROW = re.compile(r"^\|\s*`([^`]+)`\s*\|\s*(.+?)\s*\|\s*$")


def _feature_meaning(name: str) -> str:
    """Plain-English meaning of a model feature, from the glossary file."""
    global _glossary
    if _glossary is None:
        with _glossary_lock:
            if _glossary is None:
                table: Dict[str, str] = {}
                path = get_rag_directory() / "knowledge" / "features" / "glossary.md"
                try:
                    for line in Path(path).read_text(encoding="utf-8").splitlines():
                        match = _ROW.match(line)
                        if match:
                            table[match.group(1)] = match.group(2).split(" -- ")[0].strip()
                except OSError:
                    pass
                _glossary = table
    return _glossary.get(name, "")


# ============================================================
# FACTS
# ============================================================

def _facts(finding: dict, features: List[dict]) -> List[str]:
    """What the pipeline established about this flow, as plain sentences."""
    cls = _get_predicted_class(finding)
    facts = []

    confidence = _get_confidence(finding)
    try:
        facts.append(
            f"The XGBoost classifier assigned this flow to the {cls} class "
            f"with {float(confidence):.1%} confidence.")
    except (TypeError, ValueError):
        facts.append(f"The XGBoost classifier assigned this flow to the {cls} class.")

    f1 = model_facts.class_f1(cls) if model_facts.available() else None
    if f1 is not None:
        facts.append(f"On held-out test data the classifier's F1 score for {cls} is {f1:.3f}.")

    probabilities = finding.get("probabilities") or {}
    others = sorted(((c, p) for c, p in probabilities.items() if c != cls),
                    key=lambda item: -item[1])[:2]
    others = [(c, p) for c, p in others if p >= 0.05]
    if others:
        facts.append(
            "The next most probable classes were "
            + " and ".join(f"{c} at {p:.1%}" for c, p in others) + ".")

    for feature in features[:FEATURES_IN_FACTS]:
        name = feature["feature"]
        meaning = _feature_meaning(name)
        toward = "toward" if feature["shap_value"] > 0 else "away from"
        facts.append(
            f"{name}"
            + (f" ({meaning})" if meaning else "")
            + f" was {_format_value(feature['feature_value'])}, and its SHAP value of "
            f"{feature['shap_value']:+.3f} pushed the decision {toward} {cls}.")

    rules = finding.get("rule_findings")
    if rules is None:
        facts.append("Rule-based detection was not evaluated for this flow.")
    elif not rules:
        facts.append("Rule-based detection ran and no rule fired for this flow.")
    else:
        for hit in rules[:2]:
            facts.append(
                f"Rule {hit.get('rule_id', '?')} flagged {hit.get('class', '?')}: "
                f"{str(hit.get('evidence', '')).rstrip('.')}.")
    return facts


# ============================================================
# SENTENCE CHECK
# ============================================================

def _figures(text: str) -> set:
    return {f.replace(",", "") for f in _FIGURE.findall(text)}


def _terms(text: str) -> set:
    return {w for w in _WORD.findall(text.lower()) if w not in _STOP}


def _check(sentence: str, facts: List[str], allowed_names: set,
           known_names: set) -> Tuple[Optional[str], int]:
    """(None, fact index) when the sentence restates one fact; else (why not, index)."""
    facts_text = " ".join(facts)
    figures = _figures(sentence)
    terms = _terms(sentence)
    index = max(range(len(facts)),
                key=lambda i: (len(terms & _terms(facts[i])), len(figures & _figures(facts[i]))))
    fact = facts[index]
    reason = _check_against(sentence, fact, facts, facts_text, figures, terms,
                            allowed_names, known_names)
    return reason, index


def _check_against(sentence, fact, facts, facts_text, figures, terms,
                   allowed_names, known_names) -> Optional[str]:
    if figures - _figures(facts_text):
        return "a number not in the facts"
    if figures - _figures(fact):
        return "combines figures from different facts"

    # Wording that belongs only to another fact moves that fact's meaning
    # into this one ("39.3% confidence on held-out test data").
    elsewhere = set().union(*(_terms(f) for f in facts if f is not fact)) - _terms(fact)
    if len(terms & elsewhere) >= 2:
        return "mixes in wording from another fact"

    # Names the facts use are blanked first, so "Packet Length Max" is not
    # mistaken for an unlisted feature inside "Fwd Packet Length Max".
    lowered = sentence.lower()
    # Whole names only: blanking "DoS" must not hollow out "DDoS".
    for name in sorted(allowed_names, key=len, reverse=True):
        if name:
            lowered = re.sub(
                rf"(?<![A-Za-z/]){re.escape(name.lower())}(?![A-Za-z/])", " ", lowered)
    for name in known_names - allowed_names:
        if re.search(rf"(?<![A-Za-z/]){re.escape(name.lower())}(?![A-Za-z/])", lowered):
            return f"names {name}, which is not in the facts"
    facts_lower = facts_text.lower()
    for word in SPECULATIVE:
        pattern = rf"\b{word}\b"
        if re.search(pattern, lowered) and not re.search(pattern, facts_lower):
            return f"speculative or prescriptive wording ('{word}')"
    if len(terms) < 3:
        return "too short to carry a fact"
    if len(terms & _terms(fact)) / len(terms) < TERM_COVERAGE:
        return "wording not drawn from the fact it restates"
    return None


def _known_names() -> set:
    names = set(model_facts.facts().get("classes", [])) if model_facts.available() else set()
    _feature_meaning("")                    # load the glossary
    names |= set(_glossary or {})
    return names


# ============================================================
# GENERATION
# ============================================================

_SCHEMA = {
    "type": "object",
    "properties": {
        "sentences": {
            "type": "array", "minItems": MIN_SENTENCES, "maxItems": MAX_SENTENCES,
            "items": {"type": "string"},
        },
    },
    "required": ["sentences"],
}


def _schema(count: int) -> dict:
    schema = json.loads(json.dumps(_SCHEMA))
    schema["properties"]["sentences"]["minItems"] = min(count, MIN_SENTENCES)
    schema["properties"]["sentences"]["maxItems"] = count
    return schema


def _prompt(facts: List[str]) -> str:
    listing = "\n".join(f"- {fact}" for fact in facts)
    return f"""You write the summary paragraph of a network forensic report.

FACTS about one network flow:
{listing}

Rewrite each fact as one clear sentence for an analyst, in the same order:
one sentence per fact, never two facts in one sentence. Keep every number and
every name exactly as written. Do not add causes, intentions, consequences,
severity, advice or any new judgement. Reply with JSON: an object whose
"sentences" list holds the sentences.
"""


def _generate(prompt: str, count: int) -> Optional[str]:
    try:
        from llama_cpp import LlamaGrammar
        from app.services.llm_provider import generation_lock, get_llm

        llm = get_llm()
        grammar = LlamaGrammar.from_json_schema(json.dumps(_schema(count)), verbose=False)
        with generation_lock:
            result = llm(prompt, max_tokens=MAX_TOKENS, temperature=0.0,
                         top_p=1.0, top_k=1, echo=False, grammar=grammar)
        return result["choices"][0]["text"]
    except Exception as error:                          # noqa: BLE001
        print(f"[FORENXAI] Summary generation unavailable "
              f"({type(error).__name__}: {error}); showing the facts.", flush=True)
        return None


def _sentences(generated: Optional[str]) -> List[str]:
    if not generated:
        return []
    try:
        data = json.loads(generated)
        items = data.get("sentences") if isinstance(data, dict) else None
        if isinstance(items, list):
            return [" ".join(str(s).split()) for s in items if str(s).strip()]
    except ValueError:
        pass
    return [s for s in re.findall(r'"((?:[^"\\]|\\.){20,})"', generated)]


# Same flow, same facts, same answer: generation is greedy, so it is cached.
_cache: Dict[Tuple[str, ...], dict] = {}
_cache_lock = Lock()


# ============================================================
# PUBLIC ENTRY POINT
# ============================================================

def generate_flow_narration(finding: dict, shap_explanation: dict) -> dict:
    """Readable sentences about one flow, restating only established facts."""
    predicted_class = _get_predicted_class(finding)

    features = [_normalize_feature(f) for f in _get_top_features(shap_explanation)
                if isinstance(f, dict)]
    features.sort(key=lambda item: abs(item["shap_value"]), reverse=True)

    facts = _facts(finding, features)
    key = tuple(facts)

    with _cache_lock:
        if key in _cache:
            return dict(_cache[key])

    facts_text = " ".join(facts)
    allowed = {predicted_class}
    allowed |= {c for c in (finding.get("probabilities") or {}) if c in facts_text}
    allowed |= {f["feature"] for f in features[:FEATURES_IN_FACTS]}
    allowed |= {h.get("class", "") for h in (finding.get("rule_findings") or [])}
    known = _known_names()

    written: Dict[int, str] = {}
    dropped = []
    for sentence in _sentences(_generate(_prompt(facts), len(facts)))[:MAX_SENTENCES]:
        if not sentence.endswith((".", "!", "?")):
            sentence += "."
        reason, index = _check(sentence, facts, allowed, known)
        if reason:
            dropped.append({"sentence": sentence, "reason": reason})
        elif index not in written:
            written[index] = sentence

    # Every fact appears, in order: in Qwen's wording where that sentence
    # passed, as written where it did not. Nothing is lost and nothing
    # unverified is shown.
    fallback = len(written) < MIN_SENTENCES
    lines = [facts[i] if fallback or i not in written else written[i]
             for i in range(len(facts))]
    result = {
        "available": not fallback,
        "provider": "deterministic_facts" if fallback else "qwen_verified",
        "model": "facts" if fallback else "qwen2.5-3b-q4.gguf",
        "predicted_class": predicted_class,
        "text": " ".join(lines),
        "fallback_used": fallback,
        "features_used": features[:MAX_FEATURES],
        "facts": facts,
        "sentences_kept": 0 if fallback else len(written),
        "facts_shown_verbatim": len(facts) if fallback else len(facts) - len(written),
        "dropped_sentences": dropped,
    }

    with _cache_lock:
        _cache[key] = result
    return dict(result)
