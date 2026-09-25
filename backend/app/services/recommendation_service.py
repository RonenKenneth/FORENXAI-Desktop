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
#   - Retrieval is a dictionary lookup plus a deterministic
#     term search over a prebuilt index (rag/config/rag_index.py).
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
import json
import os
import re
import time
from threading import Lock, Thread
from typing import Any, Dict, List, Optional, Tuple

from app.services import model_facts
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
DOC_CHAR_BUDGET = 3000

ALWAYS_CHAR_BUDGET = 500

# An alternative class contributes its detection profile only -- enough
# to describe what else this flow could be, without displacing the
# predicted class's own guidance.
ALTERNATIVE_CHAR_BUDGET = 900

# How many sections the archive search may contribute. Two is enough
# to bring in the document that actually covers the class without
# crowding out the standards asked for by name.
SEARCHED_SECTIONS = 2

# Passages of published literature offered beside a recommendation. Two,
# for the same reason as above: a panel is read, not scrolled.
LITERATURE_SECTIONS = 2

MAX_ACTIONS = 5

# Fewer verified actions than this are topped up with quoted playbook lines.
MIN_ACTIONS = 3

# Enough for five ~30-word actions in JSON; a cut-off answer is salvaged.
MAX_TOKENS = 360

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
# RAG INDEX -- prepared once, reused across launches
# ============================================================
#
# rag/config/rag_index.py parses knowledge/ and the source archive once and
# writes rag/.rag_index.json. Here it is opened, not rebuilt: startup reads
# the index file and compares its recorded knowledge version with a cheap
# fingerprint of the corpus. Only a changed corpus triggers a rebuild.
#
# start_rag_warmup() does this on a background thread when the backend
# starts, so the first analysis does not pay for it. Every caller that needs
# the index goes through _rag(), which waits on the same lock, so the index
# is never built twice.

_rag_module = None
_rag_index: Optional[Dict[str, Any]] = None
_rag_lock = Lock()
_rag_status: Dict[str, Any] = {"state": "not started"}
_warmup_thread: Optional[Thread] = None


def _rag_index_module():
    global _rag_module

    if _rag_module is None:
        path = get_rag_directory() / "config" / "rag_index.py"

        if not path.is_file():
            raise FileNotFoundError(
                f"RAG index builder not found: {path}"
            )

        spec = importlib.util.spec_from_file_location(
            "forenxai_rag_index", path
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _rag_module = module

    return _rag_module


def _rag() -> Dict[str, Any]:
    """The loaded index. Opens it on first use; rebuilds only if stale."""
    global _rag_index

    if _rag_index is not None:
        return _rag_index

    with _rag_lock:

        if _rag_index is not None:
            return _rag_index

        _rag_status["state"] = "loading"
        started = time.perf_counter()

        index, how = _rag_index_module().load_rag_index()

        _rag_status.update({
            "state": "ready",
            "how": how,
            "version": index["version"],
            "load_ms": round((time.perf_counter() - started) * 1000, 1),
            "archive_present": index["archive_present"],
            "integrity": index["integrity"]["status"],
        })

        print(
            f"[FORENXAI] RAG index {how} in {_rag_status['load_ms']} ms: "
            f"{len(index['classes'])} classes, {len(index['pool'])} "
            f"searchable sections, version {index['version']}"
            + ("" if index["archive_present"]
               else " (source archive absent: local corpus only)"),
            flush=True
        )

        if index["integrity"]["status"] not in ("ok", "archive not present"):
            print(
                f"[FORENXAI] Source integrity: {index['integrity']['status']} "
                f"-- {index['integrity']['mismatch'] + index['integrity']['missing']} "
                f"do not match rag/_sources/SHA256SUMS.txt.",
                flush=True
            )

        _rag_index = index

        return index


def rag_ready(wait: bool = False) -> bool:
    """Whether the index is open. With wait=True, open it now if needed."""
    if wait:
        if _warmup_thread is not None:
            _warmup_thread.join()
        _rag()
    return _rag_index is not None


def rag_status() -> Dict[str, Any]:
    return dict(_rag_status)


def start_rag_warmup(preload_llm: Optional[bool] = None) -> None:
    """Open the index, then load Qwen, on a background thread.

    Called once at backend startup. Nothing waits for it: an analysis that
    starts before it finishes simply waits on the same lock. Loading Qwen
    here moves its load time off the first recommendation; set
    FORENXAI_PRELOAD_LLM=0 to skip that on a machine short of memory.
    """
    global _warmup_thread

    if _warmup_thread is not None:
        return

    if preload_llm is None:
        preload_llm = os.environ.get("FORENXAI_PRELOAD_LLM", "1") != "0"

    def work():
        try:
            _rag()
        except Exception as error:                      # noqa: BLE001
            _rag_status.update({"state": "failed", "error": str(error)})
            print(f"[FORENXAI] RAG index unavailable: {error}", flush=True)
            return

        if preload_llm:
            try:
                from app.services.llm_provider import get_llm
                get_llm()
            except Exception as error:                  # noqa: BLE001
                print(f"[FORENXAI] Qwen preload skipped: {error}", flush=True)

    _warmup_thread = Thread(target=work, name="rag-warmup", daemon=True)
    _warmup_thread.start()


# ============================================================
# RETRIEVAL
# ============================================================

def _class_bundle(predicted_class: str) -> Dict[str, Any]:
    """The prepared per-class entry. Unknown classes raise, never fall back."""
    bundle = _rag()["classes"].get(predicted_class)

    if bundle is None:
        raise KeyError(
            f"{predicted_class!r} has no entry in KNOWLEDGE_MAP. Add one "
            f"rather than falling back to a similar class -- a "
            f"recommendation attached to the wrong playbook is worse than "
            f"none."
        )

    return bundle


# (knowledge_version, class, terms, top_k) -> retrieved passages. The version
# is part of the key, so a rebuilt index can never be served an old answer.
_retrieval_cache: Dict[Any, List[Dict[str, Any]]] = {}
_retrieval_lock = Lock()


def retrieve_supporting_passages(predicted_class: str,
                                 query_context: Optional[str] = None,
                                 top_k: int = SEARCHED_SECTIONS
                                 ) -> List[Dict[str, Any]]:
    """Runtime retrieval over the indexed archive, conditioned on the class.

    The query is built deterministically -- the class name, its summary and
    its MITRE techniques, as knowledge_map.py records them -- plus any extra
    `query_context`. No model is involved before retrieval. The search runs
    through the index's postings, so only sections that contain a query term
    are scored; rarer terms weigh more, fewer than two matched terms is not
    a match, and ties break on document and section identifier. At most
    `top_k` passages come back; a weak match is not padded in.
    """
    index = _rag()
    bundle = _class_bundle(predicted_class)

    terms = list(bundle["terms"])

    if query_context:
        extra = _rag_index_module().source_index()
        if extra is not None:
            for term in extra.terms_of(query_context):
                if term not in terms:
                    terms.append(term)

    key = (index["version"], predicted_class, tuple(terms), top_k)

    with _retrieval_lock:
        cached = _retrieval_cache.get(key)

    if cached is not None:
        return [dict(p) for p in cached]

    found = _rag_index_module().search(
        index,
        terms,
        limit=top_k,
        exclude=[tuple(r) for r in index["baseline_requests"]],
    )

    with _retrieval_lock:
        # Entries for any other knowledge version are dead; drop them.
        for stale in [k for k in _retrieval_cache if k[0] != index["version"]]:
            del _retrieval_cache[stale]
        _retrieval_cache[key] = found

    return [dict(p) for p in found]


def retrieve(predicted_class: str,
             probabilities: Optional[Dict[str, float]] = None,
             confidence: Optional[float] = None) -> Dict[str, Any]:
    """Every document the recommendation stage may use for one class.

    Assembled from the prepared index: no knowledge file is opened and the
    archive is not parsed here. Raises KeyError for an unknown class rather
    than substituting a similar one. The return shape is unchanged, so the
    interface and the report read it as before.
    """
    index = _rag()
    bundle = _class_bundle(predicted_class)

    passages: List[Dict[str, Any]] = []
    truncated: List[str] = []

    for role in ("attack", "response"):

        document = bundle["documents"].get(role)

        if not document:
            continue

        passages.append({
            "role": role,
            "doc_id": "FORENXAI.corpus",
            "path": f"knowledge/{document['path']}",
            "text": document["text"],
        })

        if document["truncated"]:
            truncated.append(document["path"])

    for note in index["always"]:

        passages.append({
            "role": "always",
            "doc_id": "FORENXAI.corpus",
            "path": f"knowledge/{note['path']}",
            "text": note["text"],
        })

        if note["truncated"]:
            truncated.append(note["path"])

    # What the evaluation measured about this prediction, from
    # model_facts.json, so a retrain updates it.
    measured = model_facts.describe(
        predicted_class,
        probabilities,
        confidence
    )

    # A live alternative earns its detection profile. An analyst told the
    # flow might be DoS or Slowloris needs both, not one and a warning.
    for alternative in measured["alternatives"]:

        other = index["classes"].get(alternative["class"])
        profile = other and other.get("alternative_profile")

        if not profile:
            continue

        passages.append({
            "role": "alternative",
            "doc_id": "FORENXAI.corpus",
            "path": f"knowledge/{profile['path']}",
            "text": profile["text"],
        })

        if profile["truncated"]:
            truncated.append(profile["path"])

    ambiguous = [
        pair for pair in index["ambiguous_pairs"]
        if predicted_class in pair["classes"]
    ]

    # Fixed sources, resolved once at index build: the class's NIST SP
    # 800-53 controls by exact identifier, and the two baseline sections.
    # Then runtime retrieval for the supporting passages.
    standards = (
        [dict(p) for p in bundle["control_passages"]]
        + [dict(p) for p in index["baselines"]]
        + retrieve_supporting_passages(predicted_class)
    )

    literature = [dict(p) for p in bundle["literature"]]

    sources: List[Dict[str, str]] = []

    for passage in standards + literature:

        formatted = (
            index["citations"].get(passage["doc_id"], {}).get("citation")
        )

        if formatted and not any(
            s["doc_id"] == passage["doc_id"] for s in sources
        ):
            sources.append({
                "doc_id": passage["doc_id"],
                "citation": formatted
            })

    return {
        "predicted_class": predicted_class,
        "summary": bundle["summary"],
        "mitre": bundle["mitre"],
        "controls": bundle["controls"],
        "passages": passages,
        "standards": standards,
        "literature": literature,
        "sources": sources,
        "missing_standards": bundle["missing_standards"],
        "citations": (
            [p["path"] for p in passages]
            + [s["label"] for s in standards]
        ),
        "missing": bundle["missing"],
        "truncated": truncated,
        "low_confidence_f1": (
            measured["class_f1"]
            if measured["low_confidence_class"] else None
        ),
        "measured": measured,
        "ambiguous_with": [
            {
                "classes": list(pair["classes"]),
                "note": pair.get("note", "")
            }
            for pair in ambiguous
        ],
        "knowledge_version": index["version"],
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


# A compiled playbook line ends with the publication it was taken from:
#   "- Begin recovery procedures ... (NIST SP 800-61r3, RC.RP-01 R1, p. 42)"
# Matching such a line should credit NIST, not the file that collected it.
_INLINE_SOURCE = re.compile(
    r"\((NIST SP [0-9A-Za-z.\-]+)(?:,\s*([^)]+))?\)\s*$"
)

_DOC_ID_OF = {
    "NIST SP 800-53r5": "NIST.SP.800-53r5",
    "NIST SP 800-61r3": "NIST.SP.800-61r3",
    "NIST SP 800-86": "NIST.SP.800-86",
}


def _candidates(passages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Passages to match against, split where a line names its own source.

    A retrieved playbook is one file, but its lines are quotations from
    several publications. Treating the file as a single unit would credit
    every action to the file; splitting on the trailing marker credits the
    publication the line actually came from, which is what a reader needs
    to check it.
    """
    out: List[Dict[str, Any]] = []

    for passage in passages:

        lines = [
            line.strip()
            for line in passage["text"].splitlines()
            if line.strip().startswith("- ")
        ]

        marked = 0

        for line in lines:

            found = _INLINE_SOURCE.search(line)

            if not found:
                continue

            publication = found.group(1)
            locator = (found.group(2) or "").strip()

            doc_id = _DOC_ID_OF.get(publication)

            if not doc_id:
                continue

            marked += 1

            out.append({
                "text": line[:found.start()].lstrip("- ").strip(),
                "doc_id": doc_id,
                "label": (
                    f"{publication}, {locator}" if locator else publication
                ),
                "role": passage.get("role", "response"),
            })

        # Keep the whole passage too: its prose outside the bullets is
        # still legitimate context, and a passage with no markers (an
        # attack profile, the glossary) has nothing to split on.
        if marked == 0 or passage.get("role") != "response":
            out.append(passage)

    return out


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

    for passage in _candidates(passages):

        source_words = _tokens(passage["text"])

        label = passage.get("label") or passage.get("path") or "unknown"

        doc_id = passage.get("doc_id", "FORENXAI.corpus")

        if action_spans:

            shared = action_spans & _ngrams(source_words, SPAN_WORDS)

            if shared:
                return {
                    "source": label,
                    "doc_id": doc_id,
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
                "doc_id": doc_id,
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
# INPUTS -- prediction, SHAP and rule-based result
# ============================================================

SHAP_FEATURES_SHOWN = 3


def _rule_signature(rule_findings) -> Any:
    """What about the rule result changes the answer: which classes fired."""
    if rule_findings is None:
        return "not_evaluated"
    return tuple(sorted({h.get("class", "") for h in rule_findings}))


def _aggregate_shap(per_flow: List[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """The drivers most often in a flow's top five, across a group of flows."""
    if not per_flow:
        return []
    if len(per_flow) == 1:
        return per_flow[0]
    tally: Dict[str, Dict[str, Any]] = {}
    for contributors in per_flow:
        for c in (contributors or [])[:5]:
            name = c.get("feature")
            if not name:
                continue
            row = tally.setdefault(name, {"feature": name, "count": 0, "total": 0.0,
                                          "raw_value": c.get("raw_value"),
                                          "direction": c.get("direction")})
            row["count"] += 1
            row["total"] += float(c.get("shap_value") or 0.0)
    ranked = sorted(tally.values(), key=lambda r: (-r["count"], -abs(r["total"]), r["feature"]))
    return [{
        "feature": r["feature"],
        "shap_value": r["total"] / r["count"],
        "raw_value": r["raw_value"],
        "direction": r["direction"],
        "flows": r["count"],
    } for r in ranked[:5]]


def _fmt_value(value) -> str:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return str(value)
    return f"{number:,.0f}" if abs(number) >= 100 else f"{number:.3g}"


def _recommendation_inputs(predicted_class: str,
                           confidence: Optional[float],
                           measured: Dict[str, Any],
                           shap_features,
                           rule_findings) -> Dict[str, Any]:
    """Model, SHAP and rule result, summarised once for prompt and display."""
    evidence: List[Dict[str, str]] = []

    f1 = measured.get("class_f1")
    model_text = (
        f"XGBoost classified this traffic as {predicted_class}"
        + (f" with confidence in the {confidence:.0%} band" if confidence is not None else "")
        + (f"; the class's test F1 is {f1:.3f}" if f1 is not None else "")
        + "."
    )
    evidence.append({"source_id": "CASE:model", "label": "Model prediction",
                     "text": model_text})

    drivers = []
    for c in (shap_features or [])[:SHAP_FEATURES_SHOWN]:
        name = c.get("feature")
        if not name:
            continue
        value = c.get("shap_value", c.get("contribution", c.get("shap", 0.0)))
        try:
            value = float(value)
        except (TypeError, ValueError):
            value = 0.0
        drivers.append({
            "feature": name,
            "raw_value": c.get("raw_value"),
            "shap_value": round(value, 4),
            "toward_prediction": value > 0,
        })
    if drivers:
        evidence.append({
            "source_id": "CASE:shap",
            "label": "SHAP drivers",
            "text": "The features that most influenced this classification were "
                    + "; ".join(
                        f"{d['feature']} = {_fmt_value(d['raw_value'])} "
                        f"({'toward' if d['toward_prediction'] else 'against'} "
                        f"{predicted_class}, SHAP {d['shap_value']:+.3f})"
                        for d in drivers) + ".",
        })

    if rule_findings is None:
        rules = {"status": "not_evaluated", "hits": [], "agreement": "not_evaluated",
                 "agreement_note": ""}
    else:
        classes = sorted({h.get("class", "") for h in rule_findings if h.get("class")})
        if not rule_findings:
            agreement, note = "no_rule_fired", (
                "No detection rule fired for this traffic; the classification "
                "rests on the model alone.")
        elif predicted_class in classes:
            agreement, note = "agree", (
                f"The rule-based detector independently flagged {predicted_class}.")
        else:
            agreement, note = "conflict", (
                f"The rule-based detector flagged {', '.join(classes)}, not "
                f"{predicted_class}; write actions that hold for both.")
        for i, hit in enumerate(rule_findings[:3], start=1):
            evidence.append({
                "source_id": f"CASE:rule:{hit.get('rule_id', i)}",
                "label": f"Rule {hit.get('rule_id', i)} ({hit.get('class', '?')})",
                "text": str(hit.get("evidence", "")),
            })
        rules = {"status": "evaluated", "hits": list(rule_findings),
                 "agreement": agreement, "agreement_note": note}

    return {
        "model": {"predicted_class": predicted_class, "confidence_band": confidence,
                  "class_f1": f1},
        "shap": drivers,
        "rules": rules,
        "evidence": evidence,
    }


# ============================================================
# PROMPT -- compact, numbered, source-linked
# ============================================================
#
# Prompt length is what the recommendation panel waits on: Qwen processes
# the prompt at roughly 76 tokens per second on this CPU, and the previous
# prompt -- two whole documents, three always-loaded notes, alternatives,
# full control text -- was about 3,200 tokens, 42 seconds before the first
# output token. The context below carries only what an action can be written
# from, each piece once, under a short identifier the model cites:
#
#   the class and its summary, one line on alternatives and ambiguity
#   the detection profile, as one citable passage
#   every sourced line of the response playbook (NIST 800-61r3 / 800-86)
#   the class's NIST SP 800-53 controls, resolved by exact identifier
#   the two baseline sections, SP 800-61r3 3.2 and SP 800-86 3.1
#   0-2 retrieved supporting passages
#
# SHAP features are no longer sent: generating with two disjoint feature
# sets was measured to give identical actions, so they cost tokens and
# changed nothing. The glossary, caveats and scope notes are not sent either;
# they are shown with the recommendation, not used to write it.

def _short(text: str, budget: int) -> str:
    text = " ".join(str(text).split())
    if len(text) <= budget:
        return text
    cut = text[:budget].rsplit(" ", 1)[0]
    return cut.rstrip(",;:") + " ..."


def build_generation_context(predicted_class: str,
                             retrieved: Dict[str, Any],
                             inputs: Optional[Dict[str, Any]] = None
                             ) -> Tuple[str, Dict[str, Dict[str, Any]]]:
    """The Qwen prompt and the sources it may cite.

    Returns (prompt, sources) where sources maps each prompt identifier
    ("S1", "S2", ...) to its provenance: the canonical source_id, document,
    label and the exact text shown to the model. verify_actions() accepts an
    action only if it cites one of these identifiers.
    """
    rag_budget = _rag_index_module()
    bundle = _class_bundle(predicted_class)

    entries: List[Dict[str, Any]] = []

    def add(source_id, doc_id, label, text, budget, kind):
        shown = _short(text, budget)
        if not shown:
            return
        entries.append({
            "source_id": source_id,
            "doc_id": doc_id,
            "label": label,
            "text": shown,
            "kind": kind,
        })

    # What was observed about this finding, citable like any source: an
    # action may point the analyst at the rule's evidence or the SHAP
    # drivers, but only by restating what is written here.
    for item in (inputs or {}).get("evidence", []):
        add(item["source_id"], "FORENXAI.case", item["label"], item["text"],
            400, "evidence")

    for passage in retrieved.get("standards", []):
        kind = "control" if passage.get("kind") == "control" else "section"
        if passage.get("score") is not None:
            kind = "retrieved"
        budget = {
            "control": rag_budget.CONTROL_CHARS,
            "section": rag_budget.BASELINE_CHARS,
            "retrieved": rag_budget.PASSAGE_CHARS,
        }[kind]
        add(
            passage.get("source_id") or passage["label"],
            passage["doc_id"],
            passage["label"],
            passage["text"],
            budget,
            kind,
        )

    for line in bundle["playbook_lines"]:
        add(line["source_id"], line["doc_id"], line["label"], line["text"],
            rag_budget.PLAYBOOK_LINE_CHARS, "playbook")

    profile = bundle["documents"].get("attack")
    if profile and bundle["profile_summary"]:
        add(f"FORENXAI:{profile['path'].rsplit('/', 1)[-1].rsplit('.', 1)[0]}",
            "FORENXAI.corpus", f"knowledge/{profile['path']}",
            bundle["profile_summary"], rag_budget.PROFILE_CHARS, "profile")

    # One identifier per distinct source; a repeated source_id keeps the
    # first, so every prompt identifier resolves to exactly one source.
    sources: Dict[str, Dict[str, Any]] = {}
    seen = set()
    for entry in entries:
        if entry["source_id"] in seen:
            continue
        seen.add(entry["source_id"])
        sources[f"S{len(sources) + 1}"] = entry

    notes = []
    measured = retrieved.get("measured", {})
    alternatives = [a["class"] for a in measured.get("alternatives", [])]
    if alternatives:
        notes.append(
            f"This flow may instead be {', '.join(alternatives)}; write "
            f"actions that hold for either."
        )
    for pair in retrieved.get("ambiguous_with", []):
        notes.append(_short(pair["note"], 200))

    agreement = (inputs or {}).get("rules", {}).get("agreement_note")
    if agreement:
        notes.append(agreement)

    listing = "\n".join(
        f"[{ref}] {entry['label'] if entry['kind'] != 'profile' else 'Detection profile'}: "
        f"{entry['text']}"
        for ref, entry in sources.items()
    )

    note_text = ("\nNOTE: " + " ".join(notes)) if notes else ""

    prompt = f"""You write the response actions of a network forensic report.
The classifier has decided the class. Do not change or question it.

CLASS: {predicted_class} -- {retrieved['summary']}{note_text}

SOURCES (the only material you may use):
{listing}

TASK: Write 3 to {MAX_ACTIONS} response actions for this {predicted_class} finding.
Each action is one imperative sentence (at most 30 words) that an analyst can
carry out, reuses the wording of ONE source above, and gives that source's
bracketed id as source_id. Prefer the playbook and control sources; where the
model, SHAP or rule evidence names what to examine, one action may cite it. Reply with
a JSON object whose "actions" list holds objects with "text" and "source_id".
"""

    return prompt, sources


def _build_prompt(retrieved: Dict[str, Any], shap_features=None) -> str:
    """The prompt alone, for callers of the previous interface."""
    return build_generation_context(
        retrieved["predicted_class"], retrieved
    )[0]


# ============================================================
# GENERATION -- structured, constrained, greedy
# ============================================================

def _action_schema(source_refs: List[str]) -> Dict[str, Any]:
    """JSON schema the output is constrained to.

    source_id is an enum of the identifiers in the prompt, so Qwen cannot
    emit a source that was not supplied; verify_actions() still checks,
    because the grammar is a generation aid and the verifier is the rule.
    """
    return {
        "type": "object",
        "properties": {
            "actions": {
                "type": "array",
                "minItems": 3,
                "maxItems": MAX_ACTIONS,
                "items": {
                    "type": "object",
                    "properties": {
                        "text": {"type": "string"},
                        "source_id": {"type": "string", "enum": source_refs},
                    },
                    "required": ["text", "source_id"],
                },
            },
        },
        "required": ["actions"],
    }


def _generate(prompt: str,
              source_refs: Optional[List[str]] = None) -> Optional[str]:
    """Run Qwen greedily. Returns None when it is unavailable."""
    try:
        from app.services.llm_provider import get_llm

        llm = get_llm()

        grammar = None

        if source_refs:
            try:
                from llama_cpp import LlamaGrammar
                grammar = LlamaGrammar.from_json_schema(
                    json.dumps(_action_schema(source_refs)),
                    verbose=False,
                )
            except Exception:                           # noqa: BLE001
                grammar = None

        result = llm(
            prompt,
            max_tokens=MAX_TOKENS,
            temperature=TEMPERATURE,
            top_p=TOP_P,
            top_k=TOP_K,
            echo=False,
            grammar=grammar,
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


_ACTION_OBJECT = re.compile(
    r'\{\s*"text"\s*:\s*"((?:[^"\\]|\\.)*)"\s*,\s*'
    r'"source_id"\s*:\s*("(?:[^"\\]|\\.)*"|\[[^\]]*\])\s*\}'
)


def _parse_structured(generated: Optional[str]) -> Tuple[List[Any], str]:
    """Actions from Qwen's JSON. Returns (actions, status).

    status is "ok", "salvaged" (the JSON was cut off, usually by the token
    limit, and the complete action objects were recovered from it) or
    "malformed" (nothing usable). Each action is returned as Qwen wrote it;
    judging it is verify_actions()'s job.
    """
    if not generated:
        return [], "empty"

    try:
        data = json.loads(generated)
        actions = data.get("actions") if isinstance(data, dict) else None
        if isinstance(actions, list):
            return actions, "ok"
    except ValueError:
        pass

    salvaged = []
    for text, source in _ACTION_OBJECT.findall(generated):
        try:
            salvaged.append({
                "text": json.loads(f'"{text}"'),
                "source_id": json.loads(source),
            })
        except ValueError:
            continue

    return salvaged, ("salvaged" if salvaged else "malformed")


# Playbook sections in the order a responder needs them when quoting.
_QUOTE_ORDER = ("4.3", "4.5", "4.4", "4.2")


def _quoted_playbook_actions(predicted_class: str, used, needed: int
                             ) -> List[Dict[str, Any]]:
    """Playbook lines quoted verbatim, each under its own source_id."""
    lines = sorted(
        _class_bundle(predicted_class)["playbook_lines"],
        key=lambda line: (
            _QUOTE_ORDER.index(line["section"])
            if line["section"] in _QUOTE_ORDER else len(_QUOTE_ORDER)
        ),
    )
    quoted = []
    for line in lines:
        if len(quoted) >= needed:
            break
        if line["source_id"] in used:
            continue
        used.add(line["source_id"])
        text = line["text"] if line["text"].endswith(".") else line["text"] + "."
        quoted.append({
            "text": text,
            "evidence": {
                "source": line["label"],
                "doc_id": line["doc_id"],
                "match": "quoted",
                "span": "",
                "coverage": 1.0,
                "source_id": line["source_id"],
                "kind": "playbook",
            },
        })
    return quoted


_FIGURE = re.compile(r"\d+(?:[.:]\d+)*")


def _evidence_supports(text: str, source: Dict[str, Any]) -> Optional[Dict]:
    """Grounding check for case evidence (model, SHAP, rule hits).

    Evidence is mostly figures -- counts, addresses, ports, SHAP values --
    which the word-level check ignores. Here every figure in the action must
    appear in the cited evidence (no invented numbers), and TERM_COVERAGE of
    the action's words and figures together must come from it.
    """
    figures = set(_FIGURE.findall(text))
    source_figures = set(_FIGURE.findall(source["text"]))
    if figures - source_figures:
        return None
    terms = set(_tokens(text)) | figures
    if len(terms) < 3:
        return None
    covered = terms & (set(_tokens(source["text"])) | source_figures)
    coverage = len(covered) / len(terms)
    if coverage < TERM_COVERAGE:
        return None
    return {"source": source["label"], "doc_id": source["doc_id"],
            "match": "evidence", "span": "", "coverage": round(coverage, 3)}


def _supports(text: str, source: Dict[str, Any]) -> Optional[Dict]:
    """Whether one supplied source accounts for an action's wording."""
    if source["kind"] == "evidence":
        return _evidence_supports(text, source)
    return verify(text, [{
        "text": source["text"],
        "doc_id": source["doc_id"],
        "label": source["label"],
        "role": source["kind"],
    }])


def verify_actions(actions: List[Any],
                   sources: Dict[str, Dict[str, Any]]
                   ) -> Dict[str, Any]:
    """Deterministic check of generated actions against the supplied sources.

    An action is kept only when all of these hold:
      - it is an object with non-empty text
      - it carries exactly one source_id (a list or "S1, S2" is rejected)
      - that source_id was supplied in the prompt
      - it resolves to exactly one source
      - the cited source itself accounts for the action's wording
        (verify(): a shared run of SPAN_WORDS words, or TERM_COVERAGE of
        its significant words), so a real citation on an invented sentence
        still fails. When it does not, but exactly one other supplied source
        does, the action is re-attributed to that source and the original
        citation is kept in `cited_as` and counted in citation_corrected
    No model is involved. Every dropped action carries its reason.
    """
    verified: List[Dict[str, Any]] = []
    dropped: List[Dict[str, Any]] = []
    corrected = 0
    seen_text = set()

    for position, action in enumerate(actions, start=1):

        def drop(reason, text=""):
            dropped.append({"action_id": f"a{position}", "text": text,
                            "source_id": None, "reason": reason})

        if not isinstance(action, dict):
            drop("malformed action", str(action)[:200])
            continue

        text = " ".join(str(action.get("text") or "").split())
        ref = action.get("source_id")

        if not text:
            drop("empty action text")
            continue

        if not text.endswith("."):
            text += "."

        if ref is None or (isinstance(ref, str) and not ref.strip()):
            drop("missing source_id", text)
            continue

        if isinstance(ref, (list, tuple)) or not isinstance(ref, str) or \
                len(re.findall(r"S\d+", ref)) > 1 or "," in ref:
            drop("more than one source_id", text)
            dropped[-1]["source_id"] = ref
            continue

        ref = ref.strip().strip("[]")

        matches = [r for r in sources if r == ref]

        if not matches:
            drop("source_id not in the supplied context", text)
            dropped[-1]["source_id"] = ref
            continue

        if len(matches) != 1:
            drop("source_id does not resolve to one source", text)
            dropped[-1]["source_id"] = ref
            continue

        source = sources[ref]
        evidence = _supports(text, source)
        corrected_from = None

        if evidence is None:
            # A 3B model often copies one line and cites its neighbour.
            # If exactly one OTHER supplied source supports the sentence,
            # attribute it there and record the correction; if none or
            # several do, the action cannot be traced and is dropped.
            others = [
                (r, e) for r, e in (
                    (r, _supports(text, s))
                    for r, s in sources.items() if r != ref
                ) if e is not None
            ]
            if len(others) != 1:
                drop("not supported by the cited source", text)
                dropped[-1]["source_id"] = source["source_id"]
                continue
            corrected_from = source["source_id"]
            ref, evidence = others[0]
            source = sources[ref]

        if text.lower() in seen_text:
            drop("duplicate action", text)
            dropped[-1]["source_id"] = source["source_id"]
            continue

        seen_text.add(text.lower())

        evidence.update({
            "source_id": source["source_id"],
            "source_ref": ref,
            "kind": source["kind"],
        })
        if corrected_from:
            evidence["cited_as"] = corrected_from
            corrected += 1

        verified.append({
            "action_id": f"a{position}",
            "text": text,
            "source_id": source["source_id"],
            "evidence": evidence,
        })

    reasons: Dict[str, int] = {}
    for item in dropped:
        reasons[item["reason"]] = reasons.get(item["reason"], 0) + 1

    return {
        "verified_actions": verified,
        "dropped_actions": dropped,
        "verification_summary": {
            "generated": len(actions),
            "verified": len(verified),
            "dropped": len(dropped),
            "citation_corrected": corrected,
            "reasons": reasons,
        },
    }


# ============================================================
# REFERENCES -- ACM Reference Format, with in-text citations
# ============================================================

_LOCATOR_CONTROL = re.compile(r"NIST SP 800-53r5 ([A-Z]{2}-\d+)")

_LOCATOR_SECTION = re.compile(r"section ([\d.]+).*?\(p\.(\d+)\)")


def _locator(label: str) -> str:
    """The precise place inside a document, for an in-text citation.

    ACM permits a locator beside the number -- [1, SC-5], [2, Sec. 3.2,
    p. 31]. In a forensic report that matters: a reader checking an
    action should not have to search a 48-page publication for the
    sentence it came from.
    """
    control = _LOCATOR_CONTROL.search(label)

    if control:
        return control.group(1)

    section = _LOCATOR_SECTION.search(label)

    if section:
        return f"Sec. {section.group(1)}, p. {section.group(2)}"

    if label.startswith("knowledge/"):
        # The folder is already named in the reference entry; the file
        # name alone keeps an in-text citation short enough to read.
        return label.rsplit("/", 1)[-1]

    return ""


def _manifest_acm(doc_id: str) -> Optional[str]:
    """ACM citation for a manifest entry, from the prepared index."""
    entry = _rag()["citations"].get(doc_id) or {}
    return entry.get("acm") or entry.get("citation")


def _build_references(evidence: List[Dict[str, Any]],
                      standards: List[Dict[str, Any]]):
    """Number every document the displayed actions actually rest on.

    Only documents an action was traced to are numbered. A publication
    that was retrieved but that nothing ended up citing is not listed,
    because a reference list is a record of what was used, not of what
    was available.
    """
    order: List[str] = []

    for item in evidence:

        doc_id = item.get("doc_id", "FORENXAI.corpus")

        if doc_id not in order:
            order.append(doc_id)

    # Published standards before the internal corpus: a reader checks
    # the authority first.
    order.sort(key=lambda d: (d.startswith("FORENXAI."), d))

    references = []
    number_of = {}

    for position, doc_id in enumerate(order, start=1):

        number_of[doc_id] = position

        if doc_id == "FORENXAI.case":
            acm = (
                "FORENXAI. 2026. Case evidence: the XGBoost prediction, its "
                "TreeSHAP attribution and the rule-based detection result for "
                "the analysed capture."
            )
        elif doc_id == "FORENXAI.corpus":
            acm = (
                "FORENXAI. 2026. Detection profiles for the sixteen "
                "TRUSTLab classes. Internal knowledge base, "
                "rag/knowledge/detection/. Describes how each class "
                "appears in this dataset; the response guidance is "
                "compiled from the publications cited above."
            )
        else:
            # manifest.json ships with the repository even though the PDFs
            # it describes do not, so a citation resolves on a fresh clone
            # where the archive is absent. Falling back to the bare
            # document id there would print "NIST.SP.800-53r5" as if it
            # were a reference.
            acm = _manifest_acm(doc_id) or doc_id

        references.append({
            "number": position,
            "doc_id": doc_id,
            "acm": acm,
        })

    return references, number_of


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


# Confidence bands. The panel's guidance changes at the point where a
# prediction stops being safe to act on alone, not at every third decimal
# place, and a band is what the cache can share across flows. Each band is
# represented by one value, which is what reaches both the prompt and the
# key -- the flow's own exact confidence is still displayed beside it,
# from the finding, not from here.
CONFIDENCE_BANDS = (
    (0.60, 0.50),      # below 0.60 -> treated as 0.50, "uncertain"
    (0.85, 0.75),      # 0.60-0.85  -> treated as 0.75, "moderate"
    (1.01, 0.95),      # above 0.85 -> treated as 0.95, "confident"
)


def _confidence_band(
    confidence: Optional[float]
) -> Optional[float]:
    """Collapse a confidence to its band's representative value."""
    if confidence is None:
        return None

    try:
        value = float(confidence)
    except (TypeError, ValueError):
        return None

    for ceiling, representative in CONFIDENCE_BANDS:
        if value < ceiling:
            return representative

    return CONFIDENCE_BANDS[-1][1]


def plan_recommendations(
    findings: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Group findings by the answer they will share.

    A capture of two hundred flows is not two hundred different
    questions. The recommendation depends on the class, the confidence
    band and the alternative classes that band brings with it, so every
    flow that agrees on those three gets the same answer. This returns
    one entry per distinct answer, largest group first, so the caller
    knows before it starts how much work there is -- which is what makes
    a progress indicator possible instead of a long silence.
    """
    groups: Dict[Any, Dict[str, Any]] = {}

    for finding in findings:

        predicted = finding.get("predicted_class")

        if not predicted:
            continue

        band = _confidence_band(finding.get("confidence"))

        measured = model_facts.describe(
            predicted,
            finding.get("probabilities"),
            band,
        )

        rules = finding.get("rule_findings")

        key = (
            predicted,
            band,
            tuple(a["class"] for a in measured["alternatives"]),
            _rule_signature(rules),
        )

        entry = groups.get(key)

        if entry is None:
            entry = groups[key] = {
                "predicted_class": predicted,
                "confidence": band,
                "probabilities": finding.get("probabilities"),
                "shap_per_flow": [],
                "rule_findings": None if rules is None else [],
                "flows": 0,
            }

        entry["flows"] += 1

        if finding.get("top_features"):
            entry["shap_per_flow"].append(finding["top_features"])

        if rules:
            known = {h.get("rule_id") for h in entry["rule_findings"]}
            entry["rule_findings"].extend(
                h for h in rules if h.get("rule_id") not in known
            )

    plan = sorted(
        groups.values(),
        key=lambda entry: -entry["flows"],
    )

    for entry in plan:
        entry["shap_features"] = _aggregate_shap(entry.pop("shap_per_flow"))

    return plan


def warm_recommendations(
    findings: List[Dict[str, Any]],
    progress=None
) -> int:
    """Generate each distinct recommendation once, before the flow loop.

    Without this the first flow of every class pays the full generation
    cost inside the loop, invisibly: the analysis simply appears to hang,
    and nothing can say how long is left. Doing it here makes the cost
    countable and reportable, and the flow loop afterwards is pure cache
    hits.

    Returns the number generated. Safe to call twice -- the second call
    finds everything cached.
    """
    plan = plan_recommendations(findings)

    for position, entry in enumerate(plan, start=1):

        if progress is not None:
            progress(position, len(plan), entry)
        else:
            print(
                f"[FORENXAI] Recommendation {position}/{len(plan)}: "
                f"{entry['predicted_class']} "
                f"({entry['flows']} flow"
                f"{'' if entry['flows'] == 1 else 's'})",
                flush=True
            )

        get_recommendation(
            entry["predicted_class"],
            entry["shap_features"],
            entry["confidence"],
            entry["probabilities"],
            entry["rule_findings"],
        )

    return len(plan)


def get_recommendation(predicted_class: str,
                       shap_features=None,
                       confidence: Optional[float] = None,
                       probabilities: Optional[Dict[str, float]] = None,
                       rule_findings: Optional[List[Dict[str, Any]]] = None
                       ) -> Dict[str, Any]:
    """Grounded response recommendation for one predicted class.

    The return shape keeps `predicted_class`, `summary` and `actions`, so
    existing callers are unaffected; the remaining keys carry the
    provenance a forensic report needs.
    """
    if not predicted_class:
        raise KeyError(
            "No predicted class was supplied to the recommendation stage."
        )

    # Quantise the confidence BEFORE anything reads it, so the prompt and
    # the cache key cannot disagree. A cached answer written for "0.62"
    # must not be served to a flow the prompt would have told "0.75".
    confidence = _confidence_band(confidence)

    _measured = model_facts.describe(
        predicted_class, probabilities, confidence
    )

    # WHY THE SHAP FEATURES ARE NOT IN THIS KEY
    #
    # They used to be, as an exact five-tuple, together with confidence
    # rounded to two decimals. Every flow then had its own key and the
    # cache never hit: 200 flows across five classes produced 200 distinct
    # keys, so the panel generated 200 times. At the measured 136 s per
    # generation that is over seven hours for one capture.
    #
    # The five-tuple was not earning that. Generating for the same class
    # with two entirely disjoint SHAP feature sets returns byte-identical
    # actions -- measured, not assumed. The actions are grounded in the
    # retrieved documents and filtered by the verifier, and neither of
    # those depends on which features happened to rank highest for one
    # flow. SHAP still reaches the prompt for emphasis; it simply is not
    # part of what makes an answer different.
    #
    # What IS left in the key is what genuinely changes the retrieval:
    # the class, the confidence band, and the alternative classes the
    # band brings with it. Same capture, same five classes: at most
    # fifteen generations instead of two hundred, and usually five.
    # The rule outcome changes the answer (agreement, conflict, the
    # evidence Qwen may cite), so it is part of the key. SHAP is not: the
    # group's aggregated drivers reach the prompt through warm_recommendations,
    # and a per-flow key would make the cache miss on every flow again.
    cache_key = (
        predicted_class,
        confidence,
        tuple(a["class"] for a in _measured["alternatives"]),
        _rule_signature(rule_findings),
    )

    with _cache_lock:

        if cache_key in _cache:
            return dict(_cache[cache_key])

    retrieved = retrieve(predicted_class, probabilities, confidence)

    inputs = _recommendation_inputs(
        predicted_class, confidence, retrieved.get("measured", {}),
        shap_features, rule_findings,
    )

    verification: Dict[str, Any] = {
        "verified_actions": [], "dropped_actions": [],
        "verification_summary": {"generated": 0, "verified": 0,
                                 "dropped": 0, "reasons": {}},
    }

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

        references, number_of = _build_references(
            evidence,
            retrieved.get("standards", [])
        )

        # The action text with its in-text citation appended, ready to
        # render or paste into a report.
        #
        # Benign is the one class with no retrieved playbook, by design:
        # its three actions are fixed policy text, neither generated nor
        # quoted, so they carry no citation. They still belong in
        # actions_cited so the field always lines up with actions and the
        # caller never has to decide which list to read.
        cited = []

        if not evidence:
            cited = list(texts)

        for text, item in zip(texts, evidence):

            number = number_of.get(
                item.get("doc_id", "FORENXAI.corpus")
            )

            if not number:
                cited.append(text)
                continue

            locator = _locator(item.get("source", ""))

            item["reference_number"] = number
            item["locator"] = locator

            marker = (
                f"[{number}, {locator}]" if locator else f"[{number}]"
            )

            cited.append(
                f"{text.rstrip('.')} {marker}."
            )

        # Whether any displayed action rests on a published standard, as
        # opposed to the internal corpus alone. The detection profiles
        # describe how a class looks in this dataset, which is ours to
        # assert; what to do about it is not, so an answer built only from
        # them is grounded in less than it looks.
        standards_grounded = any(
            not item.get("doc_id", "FORENXAI.corpus").startswith("FORENXAI.")
            for item in evidence
        )

        result = {
            "predicted_class": predicted_class,
            "summary": retrieved["summary"],
            "actions": texts,
            "actions_cited": cited,
            "references": references,
            "standards_grounded": standards_grounded,
            "action_evidence": evidence,
            # True when every action that was generated traced back to a
            # source. Benign generates nothing, so there is nothing to
            # verify and the answer is vacuously true -- reporting False
            # there would read as a failed check rather than an absent
            # one. An action that failed verification is never in this
            # list; it is in rejected_ungrounded.
            "verified": all(evidence),
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
            "measured": retrieved.get("measured", {}),
            "ambiguous_with": retrieved["ambiguous_with"],
            "rejected_ungrounded": rejected or [],
            # The shared recommendation object. The interface reads the
            # fields above as before; these carry the structured record
            # the report and the verification view read.
            "retrieved_sources": [
                {
                    "source_id": p.get("source_id") or p["label"],
                    "doc_id": p["doc_id"],
                    "label": p["label"],
                    "kind": "retrieved" if p.get("score") is not None
                    else p.get("kind", "section"),
                    "score": p.get("score"),
                }
                for p in retrieved.get("standards", [])
            ],
            "generated_actions": (
                verification["verification_summary"]["generated"]
            ),
            "verified_actions": [
                {
                    "action_id": f"a{i}",
                    "text": t,
                    "source_id": (e or {}).get("source_id"),
                    "label": (e or {}).get("source"),
                    "doc_id": (e or {}).get("doc_id"),
                }
                for i, (t, e) in enumerate(
                    zip(texts, evidence or [None] * len(texts)), start=1)
            ],
            "dropped_actions": verification["dropped_actions"],
            "verification_summary": verification["verification_summary"],
            "verification": {
                k: v for k, v in verification.items()
                if k not in ("verified_actions", "dropped_actions",
                             "verification_summary")
            },
            "knowledge_version": retrieved.get("knowledge_version"),
            # What the recommendation was built from: the classifier's
            # prediction, the SHAP drivers and the rule-based result, with
            # whether the rules agree with the model.
            "inputs": inputs,
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

    prompt, supplied = build_generation_context(
        predicted_class, retrieved, inputs
    )

    generated = _generate(prompt, list(supplied))

    raw_actions, parse_status = _parse_structured(generated)

    checked = verify_actions(raw_actions, supplied)

    verification.update(checked)
    verification["parse_status"] = parse_status if generated else "generator unavailable"
    verification["supplied_sources"] = {
        ref: {k: v for k, v in entry.items() if k != "text"}
        for ref, entry in supplied.items()
    }

    actions: List[Dict[str, Any]] = [
        {"text": a["text"], "evidence": a["evidence"]}
        for a in checked["verified_actions"]
    ]
    rejected: List[str] = [
        d["text"] for d in checked["dropped_actions"] if d["text"]
    ]
    generator = "qwen2.5-3b-q4.gguf" if actions else "extraction"

    if len(actions) < MIN_ACTIONS:
        # Too few verified actions to present alone. Top up with playbook
        # lines quoted verbatim under their own source identifier --
        # quotation, not generation, so nothing unsourced is added.
        quoted = _quoted_playbook_actions(
            predicted_class,
            used={a["evidence"].get("source_id") for a in actions},
            needed=MIN_ACTIONS - len(actions),
        )
        if quoted:
            actions.extend(quoted)
            verification["topped_up_with_quotes"] = len(quoted)

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
