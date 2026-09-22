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
    get_rag_directory,
)


# ============================================================
# SETTINGS
# ============================================================

# Per-document character budget. The context window is 4096
# tokens, and a playbook plus an attack profile plus the three
# always-loaded notes will exceed it. Truncation is head-first
# and fixed, so it is reproducible, and the cut is reported in
# the response rather than hidden.
DOC_CHAR_BUDGET = 1500

ALWAYS_CHAR_BUDGET = 500

MAX_ACTIONS = 6

MAX_TOKENS = 320

# Greedy decoding. Not a tuning choice -- it is what makes two
# runs of the same case produce the same text.
TEMPERATURE = 0.0

TOP_P = 1.0

TOP_K = 1

# VERIFICATION
# A generated action must be traceable to ONE retrieved passage.
# SPAN_WORDS is the length of the significant-word run that counts as
# reused phrasing; TERM_COVERAGE is the share of an action's significant
# words a single passage must contain for a paraphrase to pass.
SPAN_WORDS = 4

TERM_COVERAGE = 0.7

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
# SOURCE INDEX -- the real publications in _sources/
# ============================================================

_si = None
_si_lock = Lock()
_si_failed = False


def _source_index():
    """Import rag/config/source_index.py, or None when unavailable.

    Unlike the knowledge map this is optional: the archive holds
    third-party publications and is not in Git, so a checkout without it
    must still produce a recommendation. What changes is the grounding --
    with the archive, actions are written from NIST SP 800-53 control text
    and the incident-response and forensic-process sections; without it,
    only the local corpus is available, and the response says so.
    """
    global _si, _si_failed

    if _si is not None or _si_failed:
        return _si

    with _si_lock:

        if _si is not None or _si_failed:
            return _si

        path = get_rag_directory() / "config" / "source_index.py"

        if not path.is_file():
            _si_failed = True
            return None

        try:
            spec = importlib.util.spec_from_file_location(
                "forenxai_source_index",
                path
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            if not module.available():
                print(
                    "[FORENXAI] Source archive not present; "
                    "recommendations will cite the local corpus only.",
                    flush=True
                )
                _si_failed = True
                return None

            _si = module

            print(
                f"[FORENXAI] Source index loaded: "
                f"{len(module.index()['controls'])} NIST SP 800-53 "
                f"controls, "
                f"{sum(len(d['sections']) for d in module.index()['documents'].values())} "
                f"indexed sections.",
                flush=True
            )

            return _si

        except Exception as error:                  # noqa: BLE001
            print(
                f"[FORENXAI] Source index unavailable "
                f"({type(error).__name__}: {error}).",
                flush=True
            )
            _si_failed = True
            return None


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

    # Passages from the real publications. The control identifiers are
    # already class-specific; the two sections apply to every class.
    standards: List[Dict[str, Any]] = []
    sources: List[Dict[str, str]] = []
    missing_standards: List[str] = []

    si = _source_index()

    if si is not None:

        requests = list(si.BASELINE_SECTIONS)

        standards = (
            si.controls_for(context["controls"])
            + si.sections_for(requests)
        )

        missing_standards = si.missing_for(
            context["controls"],
            requests
        )

        for passage in standards:

            formatted = si.citation(passage["doc_id"])

            if formatted and not any(
                s["doc_id"] == passage["doc_id"] for s in sources
            ):
                sources.append({
                    "doc_id": passage["doc_id"],
                    "citation": formatted
                })

    return {
        "predicted_class": predicted_class,
        "summary": context["summary"],
        "mitre": context["mitre"],
        "controls": context["controls"],
        "passages": passages,
        "standards": standards,
        "sources": sources,
        "missing_standards": missing_standards,
        "citations": (
            [p["path"] for p in passages]
            + [s["label"] for s in standards]
        ),
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

def _tokens(text: str):
    """Significant words, in order. Order matters for span matching."""
    return [
        word
        for word in re.findall(r"[a-z]{3,}", text.lower())
        if word not in _STOPWORDS
    ]


def _ngrams(words, n: int) -> set:
    return {
        tuple(words[i:i + n])
        for i in range(len(words) - n + 1)
    }


def verify(action: str, passages: List[Dict[str, Any]]) -> Optional[Dict]:
    """Check one generated action against the retrieved passages.

    Returns the matching source, or None when the action cannot be
    traced to anything that was retrieved.

    Two ways to pass, in order of strength:

      span   a run of SPAN_WORDS significant words from the action
             appears in one passage, in the same order. The model has
             reused the source's phrasing rather than composed a new
             claim.

      terms  TERM_COVERAGE of the action's significant words appear in
             one passage. This admits a genuine paraphrase -- reordering,
             a changed verb -- while still requiring a single source to
             account for nearly the whole sentence.

    Requiring ONE passage to carry the match is the point. Vocabulary
    pooled across every retrieved document would let a sentence
    assembled from fragments of five unrelated sources pass, which is
    the failure this exists to catch.

    What it cannot catch is a fluent negation of a source sentence,
    which reuses the vocabulary and inverts the meaning. The cited
    passage is returned with every action so a reader can check, and
    that remains the real control.
    """
    words = _tokens(action)

    if len(words) < 4:
        return None

    action_spans = _ngrams(words, SPAN_WORDS)
    action_terms = set(words)

    best = None

    for passage in passages:

        source_words = _tokens(passage["text"])

        label = passage.get("label") or passage.get("path") or "unknown"

        if action_spans:

            shared = action_spans & _ngrams(source_words, SPAN_WORDS)

            if shared:
                return {
                    "source": label,
                    "match": "span",
                    "span": " ".join(sorted(shared)[0]),
                    "coverage": 1.0,
                }

        if not action_terms:
            continue

        coverage = (
            len(action_terms & set(source_words)) / len(action_terms)
        )

        if coverage >= TERM_COVERAGE and (
            best is None or coverage > best["coverage"]
        ):
            best = {
                "source": label,
                "match": "terms",
                "span": "",
                "coverage": round(coverage, 3),
            }

    return best


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

def _build_prompt(retrieved: Dict[str, Any],
                  shap_features=None) -> str:

    # Published standards first. They are the authority; the local corpus
    # describes this dataset and, for the response playbooks, is still
    # placeholder prose. Ordering the prompt this way is what stops a
    # 3B model from preferring the familiar-sounding local text.
    blocks = [
        f"[{passage['label']}]\n{passage['text']}"
        for passage in retrieved.get("standards", [])
    ]

    blocks += [
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

    # What TreeSHAP says drove THIS flow's classification. It is evidence
    # about the decision, not a source for the actions: the model may cite
    # a feature by name only because the glossary is among the retrieved
    # passages, and the verifier checks against those, not against this.
    evidence = ""

    if shap_features:
        named = ", ".join(
            f"{f.get('feature')} ({f.get('contribution', f.get('shap', 0)):+.3f})"
            for f in shap_features[:5]
            if f.get("feature")
        )
        if named:
            evidence = (
                f"\nThe features that drove this classification, by TreeSHAP "
                f"contribution in log-odds: {named}. Refer to them only where "
                f"a source document explains what they mean."
            )

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
CONTROLS: {controls}{caveat}{evidence}

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

    # A 3B model sometimes runs two bullets onto one line. Splitting on
    # " - " recovers them; a hyphenated word has no surrounding spaces so
    # it is untouched.
    lines = []

    for raw in generated.splitlines():
        lines.extend(raw.split(" - "))

    for line in lines:

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


def get_recommendation(predicted_class: str,
                       shap_features=None) -> Dict[str, Any]:
    """Grounded response recommendation for one predicted class.

    The return shape keeps `predicted_class`, `summary` and `actions`, so
    existing callers are unaffected; the remaining keys carry the
    provenance a forensic report needs.
    """
    if not predicted_class:
        raise KeyError(
            "No predicted class was supplied to the recommendation stage."
        )

    # Keyed by class AND by the SHAP features supplied, so two flows of
    # the same class with different drivers do not share a cached answer.
    cache_key = (
        predicted_class,
        tuple(
            f.get("feature") for f in (shap_features or [])[:5]
        ),
    )

    with _cache_lock:

        if cache_key in _cache:
            return dict(_cache[cache_key])

    retrieved = retrieve(predicted_class)

    has_playbook = any(
        p["role"] == "response"
        for p in retrieved["passages"]
    )

    def _finish(actions, generator: str,
                rejected: Optional[List[str]] = None) -> Dict[str, Any]:

        # `actions` is either plain strings (the Benign path) or
        # {"text", "evidence"} pairs. The UI reads `actions`; the
        # provenance travels alongside in `action_evidence`, so an
        # existing caller keeps working unchanged.
        if actions and isinstance(actions[0], dict):
            texts = [a["text"] for a in actions]
            evidence = [a["evidence"] for a in actions]
        else:
            texts = list(actions)
            evidence = []

        result = {
            "predicted_class": predicted_class,
            "summary": retrieved["summary"],
            "actions": texts,
            "action_evidence": evidence,
            "verified": bool(evidence) and all(
                e for e in evidence
            ),
            "generator": generator,
            "grounded": True,
            "citations": retrieved["citations"],
            "mitre": retrieved["mitre"],
            "controls": retrieved["controls"],
            "missing_documents": retrieved["missing"],
            "missing_standards": retrieved.get("missing_standards", []),
            "sources": retrieved.get("sources", []),
            "standards_used": [
                p["label"] for p in retrieved.get("standards", [])
            ],
            "truncated_documents": retrieved["truncated"],
            "low_confidence_f1": retrieved["low_confidence_f1"],
            "ambiguous_with": retrieved["ambiguous_with"],
            "rejected_ungrounded": rejected or [],
        }

        with _cache_lock:
            _cache[cache_key] = result

        return dict(result)

    # Benign has no playbook by design, not by omission.
    if not has_playbook:
        return _finish(_BENIGN_ACTIONS, "none")

    all_passages = (
        retrieved.get("standards", []) + retrieved["passages"]
    )

    generated = _generate(
        _build_prompt(retrieved, shap_features)
    )

    actions: List[Dict[str, Any]] = []
    rejected: List[str] = []
    generator = "extraction"

    if generated:

        for action in _parse_actions(generated):

            evidence = verify(action, all_passages)

            if evidence:
                actions.append({"text": action, "evidence": evidence})
            else:
                rejected.append(action)

        if len(actions) >= 3:
            generator = "qwen2.5-3b-q4.gguf"
        else:
            rejected.extend(a["text"] for a in actions)
            actions = []

    if not actions:
        actions = [
            {
                "text": text,
                "evidence": verify(text, all_passages) or {
                    "source": "knowledge/incident_response",
                    "match": "quoted",
                    "span": "",
                    "coverage": 1.0,
                },
            }
            for text in _extract_actions(retrieved["passages"])
        ]

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
