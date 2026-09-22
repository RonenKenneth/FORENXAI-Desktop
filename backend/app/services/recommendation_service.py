# ============================================================
# FORENXAI
# Deterministic RAG -- response recommendations
#
# Purpose:
#   Turn the class XGBoost has already named into response
#   actions that are traceable to a document on disk.
#
# Important:
#   - XGBoost performs classification. Nothing here changes it.
#   - Retrieval is a dictionary lookup, not a similarity search.
#   - Qwen writes the wording, and only from the retrieved text.
#   - Every action is checked back against that text before it
#     is returned. An action that cannot be traced is dropped.
#
# WHY RETRIEVAL IS DETERMINISTIC
#   A vector store exists because a system does not know in
#   advance what it is looking for. This one does: the
#   classifier has just named exactly one of sixteen classes,
#   so retrieval is rag/config/knowledge_map.py -- a lookup
#   that raises on an unknown key instead of silently returning
#   the nearest neighbour. A recommendation attached to the
#   wrong playbook is worse than no recommendation.
#
#   The same input therefore selects the same documents every
#   time, and Qwen runs greedily (temperature 0, top_k 1), so
#   the same case produces the same report. For forensic work
#   that is a requirement, not a preference.
# ============================================================

from __future__ import annotations

import importlib.util
import re
from threading import Lock
from typing import Any, Dict, List, Optional

from app.utils.runtime_paths import (
    get_knowledge_map_path,
)


# ============================================================
# SETTINGS
# ============================================================

# Per-document character budget. The context window is 4096
# tokens, and a playbook plus an attack profile plus the three
# always-loaded notes will exceed it. Truncation is head-first
# and fixed, so it is reproducible, and the cut is reported in
# the response rather than hidden.
DOC_CHAR_BUDGET = 2600

ALWAYS_CHAR_BUDGET = 900

MAX_ACTIONS = 6

MAX_TOKENS = 320

# Greedy decoding. Not a tuning choice -- it is what makes two
# runs of the same case produce the same text.
TEMPERATURE = 0.0

TOP_P = 1.0

TOP_K = 1

# An action must share this many distinctive words with the
# retrieved text to count as grounded.
GROUNDING_MIN_TERMS = 2

_STOPWORDS = {
    "the", "and", "for", "are", "was", "were", "this", "that",
    "with", "from", "into", "have", "has", "had", "not", "any",
    "all", "its", "it", "a", "an", "of", "to", "in", "on", "or",
    "be", "is", "as", "at", "by", "if", "no", "which", "whether",
    "check", "review", "identify", "inspect", "verify", "record",
    "confirm", "preserve", "establish", "determine", "collect",
}


# ============================================================
# KNOWLEDGE MAP -- loaded once, by path
# ============================================================

_km = None
_km_lock = Lock()


def _knowledge_map():
    """Import rag/config/knowledge_map.py from its resolved path.

    It is not an installed package and it does not live inside the
    backend tree, so it is loaded by file location. A failure to load
    is raised, never swallowed: without it there is no retrieval step,
    and anything produced would be ungrounded.
    """
    global _km

    if _km is not None:
        return _km

    with _km_lock:

        if _km is not None:
            return _km

        path = get_knowledge_map_path()

        if not path.is_file():
            raise FileNotFoundError(
                f"Knowledge map not found: {path}. The recommendation "
                f"panel cannot produce grounded output without it. Set "
                f"FORENXAI_RAG_DIR if the assets live elsewhere."
            )

        spec = importlib.util.spec_from_file_location(
            "forenxai_knowledge_map",
            path
        )

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        _km = module

        print(
            f"[FORENXAI] Knowledge map loaded: {path}",
            flush=True
        )

        return _km


# ============================================================
# RETRIEVAL
# ============================================================

def _clip(text: Optional[str], budget: int):
    """Head-truncate to a fixed budget. Returns (text, was_cut)."""
    if not text:
        return "", False
    if len(text) <= budget:
        return text, False
    return text[:budget], True


def retrieve(predicted_class: str) -> Dict[str, Any]:
    """Every document the recommendation stage may use for one class.

    Raises KeyError for an unknown class rather than substituting a
    similar one.
    """
    km = _knowledge_map()

    context = km.context_for(predicted_class)

    passages: List[Dict[str, Any]] = []
    truncated: List[str] = []

    for role in ("attack", "response"):

        document = context["documents"].get(role)

        if not document:
            continue

        text, was_cut = _clip(
            document["text"],
            DOC_CHAR_BUDGET
        )

        passages.append({
            "role": role,
            "path": f"knowledge/{document['path']}",
            "text": text
        })

        if was_cut:
            truncated.append(document["path"])

    for relative_path in getattr(km, "ALWAYS_LOAD", []):

        text = km.load(relative_path)

        if not text:
            continue

        clipped, was_cut = _clip(text, ALWAYS_CHAR_BUDGET)

        passages.append({
            "role": "always",
            "path": f"knowledge/{relative_path}",
            "text": clipped
        })

        if was_cut:
            truncated.append(relative_path)

    low_confidence = getattr(
        km,
        "LOW_CONFIDENCE_CLASSES",
        {}
    )

    ambiguous = [
        pair for pair in getattr(km, "AMBIGUOUS_PAIRS", [])
        if predicted_class in pair.get("classes", ())
    ]

    return {
        "predicted_class": predicted_class,
        "summary": context["summary"],
        "mitre": context["mitre"],
        "controls": context["controls"],
        "passages": passages,
        "citations": [p["path"] for p in passages],
        "missing": context["missing"],
        "truncated": truncated,
        "low_confidence_f1": low_confidence.get(predicted_class),
        "ambiguous_with": [
            {
                "classes": list(pair["classes"]),
                "note": pair.get("note", "")
            }
            for pair in ambiguous
        ],
    }


# ============================================================
# GROUNDING CHECK
# ============================================================

def _terms(text: str) -> set:
    return {
        word
        for word in re.findall(r"[a-z]{3,}", text.lower())
        if word not in _STOPWORDS
    }


def _is_grounded(action: str, corpus_terms: set) -> bool:
    """An action counts as grounded when it reuses the corpus vocabulary.

    Deliberately crude. It will not catch a fluent paraphrase that
    inverts a meaning, and it is no substitute for reading the cited
    file. What it does catch is the failure that matters here: an
    action invented wholesale, which shares almost no distinctive
    vocabulary with anything that was retrieved.
    """
    overlap = _terms(action) & corpus_terms
    return len(overlap) >= GROUNDING_MIN_TERMS


# ============================================================
# DETERMINISTIC FALLBACK -- extraction, not invention
# ============================================================

_BULLET = re.compile(r"^\s*(?:[-*]|\d+[.)])\s+(.+)$")

_SENTENCE = re.compile(r"(?<=[.!?])\s+")

# Verbs the playbooks use to open an instruction. Matching on these
# keeps the extraction to actionable sentences and drops the
# descriptive ones, without needing a model to make the judgement.
_IMPERATIVES = (
    "record", "establish", "distinguish", "apply", "identify",
    "review", "check", "inspect", "verify", "preserve", "collect",
    "correlate", "isolate", "block", "restrict", "capture",
    "confirm", "determine", "document", "compare", "trace",
    "rotate", "patch", "disable", "enable", "monitor", "retain",
    "escalate", "notify", "contain", "quarantine", "validate",
)


def _reflow(text: str) -> List[str]:
    """Join hard-wrapped lines back into blocks.

    The shipped playbooks wrap prose at column 74, so a line is not a
    unit of meaning. Splitting on lines produces half sentences; this
    rebuilds paragraphs and list items first. Blank lines, headings
    and the placeholder banner end a block.
    """
    blocks: List[str] = []
    current: List[str] = []

    def flush():
        if current:
            blocks.append(" ".join(current).strip())
            current.clear()

    for raw in text.splitlines():

        line = raw.strip()

        if not line or line.startswith("#") or line.startswith(">"):
            flush()
            continue

        bullet = _BULLET.match(line)

        if bullet:
            flush()
            current.append(bullet.group(1).strip())
        else:
            current.append(line)

    flush()

    return blocks


def _extract_actions(passages: List[Dict[str, Any]]) -> List[str]:
    """Quote action sentences straight out of the response playbook.

    Used when the language model is unavailable, or when its output
    does not survive the grounding check. The result is quotation
    rather than generation, so it is always traceable, and it is
    stable because the corpus is.
    """
    actions: List[str] = []
    seen = set()

    for passage in passages:

        if passage["role"] != "response":
            continue

        for block in _reflow(passage["text"]):

            for sentence in _SENTENCE.split(block):

                sentence = sentence.strip()

                if not (25 <= len(sentence) <= 300):
                    continue

                first = sentence.split(" ", 1)[0].lower().strip(",")

                if first not in _IMPERATIVES:
                    continue

                if not sentence.endswith("."):
                    sentence += "."

                key = sentence.lower()

                if key in seen:
                    continue

                seen.add(key)
                actions.append(sentence)

    return actions[:MAX_ACTIONS]


# ============================================================
# PROMPT
# ============================================================

def _build_prompt(retrieved: Dict[str, Any]) -> str:

    blocks = [
        f"[{passage['path']}]\n{passage['text']}"
        for passage in retrieved["passages"]
    ]

    sources = "\n\n".join(blocks)

    caveat = ""

    if retrieved["low_confidence_f1"] is not None:
        caveat = (
            f"\nThe classifier's test F1 for this class is "
            f"{retrieved['low_confidence_f1']:.4f}. Write the actions so "
            f"they remain sensible if the class is wrong."
        )

    for pair in retrieved["ambiguous_with"]:
        caveat += f"\n{pair['note']}"

    mitre = ", ".join(retrieved["mitre"]) or "none recorded"
    controls = ", ".join(retrieved["controls"]) or "none recorded"

    return f"""You are writing the response section of a network forensic report.

The classifier has determined the class. You do not change it, question it, or
add a different one. You write the analyst's next actions and nothing else.

SOURCE DOCUMENTS -- the only material you may use:

{sources}

CLASS: {retrieved['predicted_class']}
SUMMARY: {retrieved['summary']}
MITRE: {mitre}
CONTROLS: {controls}{caveat}

Write between three and {MAX_ACTIONS} response actions, drawn only from the
source documents above. One action per line, each beginning with "- ".
Each must be a single imperative sentence an analyst can carry out.
Do not number them, do not add a heading, do not add commentary, and do not
state anything the source documents do not support.

ACTIONS:
"""


# ============================================================
# GENERATION
# ============================================================

def _generate(prompt: str) -> Optional[str]:
    """Run Qwen greedily. Returns None when it is unavailable."""
    try:
        from app.services.llm_provider import get_llm

        llm = get_llm()

        result = llm(
            prompt,
            max_tokens=MAX_TOKENS,
            temperature=TEMPERATURE,
            top_p=TOP_P,
            top_k=TOP_K,
            echo=False
        )

        return result["choices"][0]["text"].strip()

    except Exception as error:                      # noqa: BLE001

        print(
            f"[FORENXAI] Recommendation generation unavailable "
            f"({type(error).__name__}: {error}); falling back to "
            f"extraction from the retrieved playbook.",
            flush=True
        )

        return None


# A 3B model does not reliably stop after the list. It appends a code
# fence, restates the instruction, or repeats the whole list. None of
# that is a grounding failure -- the words still come from the sources,
# so the overlap check passes -- which is why it is removed here rather
# than left to _is_grounded.
_FENCE = re.compile(r"`{2,}\s*\w*")

_META = re.compile(
    r"(here are the|to ensure the|guidelines provided|as an ai|"
    r"in summary|the above actions|these actions|i hope this|"
    r"let me know|based on the source)",
    re.IGNORECASE
)


def _parse_actions(generated: str) -> List[str]:

    actions: List[str] = []
    seen = set()

    for line in generated.splitlines():

        stripped = line.strip()

        if not stripped:
            continue

        # A fence ends the list; everything after it is commentary.
        if _FENCE.search(stripped):
            stripped = _FENCE.split(stripped)[0].strip()
            if len(stripped) < 15:
                break

        stripped = re.sub(r"^\s*(?:[-*]|\d+[.)])\s*", "", stripped)

        # Commentary can begin mid-line. Keep what precedes it.
        meta = _META.search(stripped)

        if meta:
            stripped = stripped[:meta.start()].strip()
            if len(stripped) < 15:
                break

        if len(stripped) < 15:
            continue

        if stripped.lower().startswith(("actions", "note", "source",
                                        "class:", "mitre", "controls")):
            continue

        if not stripped.endswith("."):
            stripped += "."

        key = stripped.lower()

        if key in seen:
            # The model has started repeating; the list is finished.
            break

        seen.add(key)
        actions.append(stripped)

    return actions[:MAX_ACTIONS]


# ============================================================
# PUBLIC ENTRY POINT
# ============================================================

_cache: Dict[str, Dict[str, Any]] = {}
_cache_lock = Lock()

_BENIGN_ACTIONS = [
    "Retain the flow as part of the forensic case record.",
    "Correlate it with surrounding flows if it bears on the incident "
    "timeline.",
    "Do not treat the classification alone as proof that the activity is "
    "harmless.",
]


def get_recommendation(predicted_class: str) -> Dict[str, Any]:
    """Grounded response recommendation for one predicted class.

    The return shape keeps `predicted_class`, `summary` and `actions`, so
    existing callers are unaffected; the remaining keys carry the
    provenance a forensic report needs.
    """
    if not predicted_class:
        raise KeyError(
            "No predicted class was supplied to the recommendation stage."
        )

    with _cache_lock:

        if predicted_class in _cache:
            return dict(_cache[predicted_class])

    retrieved = retrieve(predicted_class)

    has_playbook = any(
        p["role"] == "response"
        for p in retrieved["passages"]
    )

    def _finish(actions: List[str], generator: str,
                rejected: Optional[List[str]] = None) -> Dict[str, Any]:

        result = {
            "predicted_class": predicted_class,
            "summary": retrieved["summary"],
            "actions": actions,
            "generator": generator,
            "grounded": True,
            "citations": retrieved["citations"],
            "mitre": retrieved["mitre"],
            "controls": retrieved["controls"],
            "missing_documents": retrieved["missing"],
            "truncated_documents": retrieved["truncated"],
            "low_confidence_f1": retrieved["low_confidence_f1"],
            "ambiguous_with": retrieved["ambiguous_with"],
            "rejected_ungrounded": rejected or [],
        }

        with _cache_lock:
            _cache[predicted_class] = result

        return dict(result)

    # Benign has no playbook by design, not by omission.
    if not has_playbook:
        return _finish(_BENIGN_ACTIONS, "none")

    corpus_terms = _terms(
        " ".join(p["text"] for p in retrieved["passages"])
    )

    generated = _generate(
        _build_prompt(retrieved)
    )

    actions: List[str] = []
    rejected: List[str] = []
    generator = "extraction"

    if generated:

        for action in _parse_actions(generated):

            if _is_grounded(action, corpus_terms):
                actions.append(action)
            else:
                rejected.append(action)

        if len(actions) >= 3:
            generator = "qwen2.5-3b-q4.gguf"
        else:
            # Too little survived the check to be worth returning.
            rejected.extend(actions)
            actions = []

    if not actions:
        actions = _extract_actions(retrieved["passages"])

    return _finish(actions, generator, rejected)


def audit() -> Dict[str, Any]:
    """Which classes can currently produce a grounded recommendation."""
    km = _knowledge_map()

    rows = []

    for cls in km.KNOWLEDGE_MAP:

        try:
            retrieved = retrieve(cls)
            rows.append({
                "class": cls,
                "citations": retrieved["citations"],
                "missing": retrieved["missing"],
            })
        except Exception as error:                  # noqa: BLE001
            rows.append({
                "class": cls,
                "citations": [],
                "missing": [str(error)],
            })

    return {
        "classes": len(rows),
        "complete": sum(1 for r in rows if not r["missing"]),
        "rows": rows,
    }


if __name__ == "__main__":
    report = audit()
    print(f"{report['complete']}/{report['classes']} classes have every "
          f"document present\n")
    for row in report["rows"]:
        mark = "OK " if not row["missing"] else "-- "
        print(f"  {mark}{row['class']:<16}{len(row['citations'])} citations")
        for missing in row["missing"]:
            print(f"       missing: {missing}")
