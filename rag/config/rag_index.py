"""
rag_index.py
------------
The prepared form of the retrieval corpus: built once, reused on every launch.

WHY THIS EXISTS
The recommendation stage used to assemble its evidence per request: read the
class's detection profile and playbook from knowledge/, read the three
always-loaded notes, open the source index, resolve the controls and the two
baseline sections, then scan all 814 archive sections for the class's terms.
Each of those steps is cheap; together they were repeated for every request
and every launch, and the scan grew with the archive.

This module does that work once, when the corpus changes, and writes the
result to rag/.rag_index.json:

    per class   profile, playbook split into sourced lines, controls and the
                two baseline sections resolved by identifier, the class's
                retrieval terms, literature passages, citations
    pool        the 814-section search pool, each section with its identifier
    postings    term -> sections containing it, for every term a class query
                can contain, so a query touches only matching sections

WHAT IT DOES NOT CHANGE
knowledge/, knowledge_map.py, _sources/manifest.json and SHA256SUMS.txt stay
the source of truth. This file is derived and untracked; delete it and it is
rebuilt. Retrieval semantics are exactly source_index.search(): a term
matches a section when it occurs in the section's lower-cased text, rarer
terms weigh more (log N/df), terms in more than 40% of sections are ignored,
fewer than two matched terms is not a match, ties break on document and
section identifier. The test suite checks the two return the same passages
for all sixteen classes.

VERSIONING
knowledge_version() hashes knowledge/, knowledge_map.py, manifest.json,
SHA256SUMS.txt and the source index fingerprint. It costs a few milliseconds.
The index is used only when its recorded version matches; otherwise it is
rebuilt, and every retrieval cache keyed on the old version stops matching.

    python rag/config/rag_index.py            # build if stale, report
    python rag/config/rag_index.py --force    # rebuild
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import math
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

CONFIG_DIR = Path(__file__).resolve().parent
RAG_DIR = CONFIG_DIR.parent
KNOWLEDGE_DIR = RAG_DIR / "knowledge"
SOURCES_DIR = RAG_DIR / "_sources"
MANIFEST_FILE = SOURCES_DIR / "manifest.json"
SHA256SUMS_FILE = SOURCES_DIR / "SHA256SUMS.txt"
INDEX_FILE = RAG_DIR / ".rag_index.json"

# Bump when the layout of .rag_index.json changes.
SCHEMA = 3

# Character budgets for the compact generation context. They bound what one
# source can contribute to the Qwen prompt; the full text stays in the corpus.
PROFILE_CHARS = 600
PLAYBOOK_LINE_CHARS = 260
CONTROL_CHARS = 320
BASELINE_CHARS = 520
PASSAGE_CHARS = 420
FOCUS_CHARS = 700

# Same budgets as the previous retrieve(), kept for the fields the interface
# and the report already display.
DOC_CHAR_BUDGET = 3000
ALWAYS_CHAR_BUDGET = 500
ALTERNATIVE_CHAR_BUDGET = 900
SEARCH_CHAR_BUDGET = 700
LITERATURE_SECTIONS = 2

# A playbook line ends with "(NIST SP 800-61r3, DE.AE-02 R1, p. 33)".
INLINE_SOURCE = re.compile(r"\((NIST SP [0-9A-Za-z.\-]+)(?:,\s*([^)]+))?\)\s*$")
DOC_ID_OF = {
    "NIST SP 800-53r5": "NIST.SP.800-53r5",
    "NIST SP 800-61r3": "NIST.SP.800-61r3",
    "NIST SP 800-86": "NIST.SP.800-86",
}
SHORT_DOC = {
    "NIST.SP.800-53r5": "SP800-53r5",
    "NIST.SP.800-61r3": "SP800-61r3",
    "NIST.SP.800-86": "SP800-86",
}


# ------------------------------------------------------------------
# loading the two configuration modules by path
# ------------------------------------------------------------------

_modules: Dict[str, Any] = {}


def _load(name: str):
    if name not in _modules:
        path = CONFIG_DIR / f"{name}.py"
        spec = importlib.util.spec_from_file_location(f"forenxai_{name}", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _modules[name] = module
    return _modules[name]


def knowledge_map():
    return _load("knowledge_map")


def source_index():
    """The archive index, or None when the archive is not present."""
    if "source_index" not in _modules:
        try:
            module = _load("source_index")
            if not module.available():
                _modules["source_index"] = None
        except Exception:                                   # noqa: BLE001
            _modules["source_index"] = None
    return _modules.get("source_index")


# ------------------------------------------------------------------
# version
# ------------------------------------------------------------------

def _file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else "absent"


def knowledge_version() -> str:
    """Fingerprint of everything the index is derived from. A few ms."""
    h = hashlib.sha256()
    h.update(f"schema={SCHEMA}".encode())
    for path in sorted(KNOWLEDGE_DIR.rglob("*")):
        if path.is_file():
            h.update(path.relative_to(RAG_DIR).as_posix().encode())
            h.update(path.read_bytes())
    # The builder itself too: a change to how the index is built makes the
    # old index stale just as a change to the corpus does.
    for path in (CONFIG_DIR / "knowledge_map.py", CONFIG_DIR / "rag_index.py",
                 MANIFEST_FILE, SHA256SUMS_FILE):
        h.update(path.name.encode())
        h.update(_file_digest(path).encode())
    # The archive's own fingerprint, so re-extracting a source rebuilds.
    stamp = SOURCES_DIR.parent / "_extracted" / ".extracted.json"
    h.update(_file_digest(stamp).encode())
    pdfs = sorted(p.name for p in SOURCES_DIR.glob("*") if p.is_file())
    h.update("|".join(pdfs).encode())
    return h.hexdigest()[:20]


# ------------------------------------------------------------------
# integrity
# ------------------------------------------------------------------

def verify_sources() -> Dict[str, Any]:
    """Check the archive against SHA256SUMS.txt. Build time only."""
    if not SHA256SUMS_FILE.is_file():
        return {"checked": 0, "ok": 0, "missing": [], "mismatch": [], "status": "no SHA256SUMS.txt"}
    ok, missing, mismatch = 0, [], []
    for line in SHA256SUMS_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        digest, _, name = line.partition("  ")
        name = name.lstrip("*").strip()
        path = SOURCES_DIR / name
        if not path.is_file():
            missing.append(name)
        elif _file_digest(path) != digest.strip():
            mismatch.append(name)
        else:
            ok += 1
    status = "ok" if not mismatch and not missing else (
        "mismatch" if mismatch else "archive not present")
    return {"checked": ok + len(missing) + len(mismatch), "ok": ok,
            "missing": missing, "mismatch": mismatch, "status": status}


# ------------------------------------------------------------------
# parsing the knowledge files
# ------------------------------------------------------------------

def _read(rel: Optional[str]) -> Optional[str]:
    if not rel:
        return None
    path = KNOWLEDGE_DIR / rel
    return path.read_text(encoding="utf-8", errors="replace") if path.is_file() else None


def _profile_summary(text: str) -> str:
    """The profile's own content: numbered sections, no provenance banner."""
    keep, current = [], None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(">") or stripped.startswith("# "):
            continue
        if stripped.startswith("## "):
            current = stripped[3:]
            keep.append(current + ":")
            continue
        if current and stripped:
            keep.append(stripped)
    return " ".join(keep)[:PROFILE_CHARS].strip()


def _playbook_lines(text: str) -> List[Dict[str, Any]]:
    """Every bullet that names its publication, as its own source.

    Section 4.1 restates the class's controls, which are supplied from the
    CPRT catalogue by identifier, so it is left out here to avoid giving the
    model the same control twice.
    """
    lines, section = [], ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped.startswith("## "):
            section = stripped[3:].split(" ", 1)[0]
            continue
        if not stripped.startswith("- ") or section == "4.1":
            continue
        found = INLINE_SOURCE.search(stripped)
        if not found:
            continue
        publication, locator = found.group(1), (found.group(2) or "").strip()
        doc_id = DOC_ID_OF.get(publication)
        if not doc_id:
            continue
        body = stripped[2:found.start()].strip()
        clause = locator.split(",")[0].replace("Sec. ", "").strip()
        lines.append({
            "source_id": f"{SHORT_DOC[doc_id]}:{clause}",
            "doc_id": doc_id,
            "label": f"{publication}, {locator}" if locator else publication,
            "text": body,
            "section": section,
        })
    return lines


def _clip(text: Optional[str], budget: int) -> Tuple[str, bool]:
    if not text:
        return "", False
    return (text, False) if len(text) <= budget else (text[:budget], True)


# ------------------------------------------------------------------
# build
# ------------------------------------------------------------------

def _pool(si) -> List[Dict[str, Any]]:
    """The free-text search pool, identical to source_index._all_sections()."""
    if si is None:
        return []
    return [{
        "doc_id": s["doc_id"], "number": str(s["number"]), "title": s["title"],
        "page": s["page"], "text": s["text"][:SEARCH_CHAR_BUDGET].strip(),
        "folded": s["folded"],
    } for s in si._all_sections()]


_PREVENT = re.compile(r"how to prevent", re.I)


def _focus_passages(si, requests) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Class-specific sections by exact identifier, from their guidance part.

    Where a section has a "How to prevent" part (the OWASP entries) the
    passage starts there, because that is the part an action can be written
    from; the background before it describes the risk, not the response.
    """
    if si is None:
        return [], [f"{d} {n}" for d, n in requests]
    documents = si.index()["documents"]
    found, missing = [], []
    for doc_id, number in requests:
        section = next((s for s in documents.get(doc_id, {}).get("sections", [])
                        if str(s["number"]) == str(number)), None)
        if section is None:
            missing.append(f"{doc_id} {number}")
            continue
        text = section["text"]
        heading = f"{section['number']} {section['title']}"
        if text.startswith(heading):
            text = text[len(heading):].lstrip(" .")
        at = _PREVENT.search(text)
        if at:
            text = text[at.start():]
        where = f" (p.{section['page']})" if section.get("page") else ""
        found.append({
            "kind": "focus",
            "doc_id": doc_id,
            "ref": f"{number} {section['title']}",
            "label": f"{doc_id} section {number} {section['title']}{where}",
            "text": text[:1500].strip(),
            "source_id": f"{SHORT_DOC.get(doc_id, doc_id)}:{number}",
        })
    return found, missing


_SELECTION = re.compile(r"\[Selection[^:]*:\s*([^;\]]+)[^\]]*\]")
_ASSIGNMENT = re.compile(r"\[Assignment:\s*([^\]]+)\]")
_MODAL = re.compile(r"\b(shall|should|must|necessary|recommended|block|drop|deny|validate|enforce|use)\b", re.I)


def _control_sentence(text: str) -> str:
    """A control's first requirement, with CPRT placeholders made readable.

    "[Selection (one): Protect against; Limit]" becomes its first option and
    "[Assignment: organization-defined X]" becomes "organization-defined X";
    nothing else is changed, so the quote still reads as the catalogue does.
    """
    text = _ASSIGNMENT.sub(lambda m: m.group(1).strip(), _SELECTION.sub(lambda m: m.group(1).strip(), text))
    first = re.split(r";\s+|(?<=\.)\s+", text, maxsplit=1)[0]
    return first.strip().rstrip(":;,. ") + "."


def _guidance_sentences(text: str, limit: int = 3) -> List[str]:
    """Actionable sentences of a publication section, verbatim.

    Bullets when the section has them (OWASP "How to prevent"), otherwise
    sentences that state a requirement or a countermeasure.
    """
    body = re.sub(r"^how to prevent\.?\s*", "", text.strip(), flags=re.I)
    if " * " in body or body.startswith("* "):
        parts = [b.strip() for b in re.split(r"(?:^|\s)\*\s+", body) if b.strip()]
    else:
        parts = [t.strip() for t in re.split(r"(?<=[.!?])\s+(?=[A-Z])", body)
                 if _MODAL.search(t)]
    out = []
    for part in parts:
        part = re.sub(r"\*\*[^*]+\*\*", "", part).strip()
        sentence = re.split(r"(?<=[.!?])\s+", part)[0].strip()
        # A lead-in ("... requires the following:") introduces a list; it is
        # not itself something to do.
        if sentence.rstrip().endswith(":"):
            continue
        if 30 <= len(sentence) <= 260:
            out.append(sentence.rstrip(". ") + ".")
        if len(out) >= limit:
            break
    return out


def _quotable(controls, focus) -> List[Dict[str, Any]]:
    """Class-specific sentences that can be quoted as actions, in order."""
    units = []
    for passage in focus:
        for sentence in _guidance_sentences(passage["text"]):
            units.append({"source_id": passage["source_id"], "doc_id": passage["doc_id"],
                          "label": passage["label"], "text": sentence, "kind": "focus"})
    for passage in controls:
        units.append({"source_id": passage["source_id"], "doc_id": passage["doc_id"],
                      "label": passage["label"], "text": _control_sentence(passage["text"]),
                      "kind": "control"})
    return units


def _query_terms(si, cls: str, entry: Dict[str, Any]) -> List[str]:
    if si is None:
        return []
    return si.terms_of(cls, entry["summary"], " ".join(entry.get("mitre") or []))


def build_rag_index(force: bool = False) -> Dict[str, Any]:
    """Parse the corpus once and persist the prepared index."""
    version = knowledge_version()
    if not force:
        current = _read_index()
        if current and current.get("version") == version:
            return current

    started = time.perf_counter()
    km = knowledge_map()
    si = source_index()

    pool = _pool(si)
    folded = [s.pop("folded") for s in pool]
    baselines_req = list(getattr(si, "BASELINE_SECTIONS", [])) if si else []
    baselines = si.sections_for(baselines_req) if si else []
    for (doc_id, number), passage in zip(baselines_req, baselines):
        passage["source_id"] = f"{SHORT_DOC.get(doc_id, doc_id)}:{number}"

    always = []
    for rel in getattr(km, "ALWAYS_LOAD", []):
        text = _read(rel)
        if text:
            clipped, cut = _clip(text, ALWAYS_CHAR_BUDGET)
            always.append({"path": rel, "text": clipped, "truncated": cut})

    classes: Dict[str, Any] = {}
    all_terms: set = set()
    citations: Dict[str, Dict[str, Optional[str]]] = {}

    for cls, entry in km.KNOWLEDGE_MAP.items():
        docs, missing = {}, []
        for role in ("attack", "response"):
            rel = entry.get(role)
            if not rel:
                continue
            text = _read(rel)
            if text is None:
                missing.append(rel)
                continue
            clipped, cut = _clip(text, DOC_CHAR_BUDGET)
            docs[role] = {"path": rel, "text": clipped, "truncated": cut}

        attack_text = _read(entry.get("attack")) or ""
        response_text = _read(entry.get("response")) or ""
        alternative_text, alt_cut = _clip(attack_text, ALTERNATIVE_CHAR_BUDGET)

        controls = si.controls_for(entry["controls"]) if si else []
        for control in controls:
            control["source_id"] = f"SP800-53r5:{control['ref']}"

        terms = _query_terms(si, cls, entry)
        all_terms.update(terms)

        literature = []
        if si is not None and callable(getattr(si, "literature_for", None)):
            try:
                literature = si.literature_for(
                    si.terms_of(cls, entry["summary"]), limit=LITERATURE_SECTIONS)
            except Exception:                                   # noqa: BLE001
                literature = []

        missing_standards = si.missing_for(entry["controls"], baselines_req) if si else []

        focus, focus_missing = _focus_passages(
            si, getattr(km, "FOCUS_SECTIONS", {}).get(cls, []))
        missing_standards = missing_standards + focus_missing

        classes[cls] = {
            "summary": entry["summary"],
            "mitre": list(entry.get("mitre") or []),
            "controls": list(entry.get("controls") or []),
            "documents": docs,
            "missing": missing,
            "alternative_profile": {"path": entry.get("attack"), "text": alternative_text,
                                    "truncated": alt_cut} if entry.get("attack") else None,
            "profile_summary": _profile_summary(attack_text) if attack_text else "",
            "playbook_lines": _playbook_lines(response_text) if response_text else [],
            "control_passages": controls,
            "focus_passages": focus,
            "quotable": _quotable(controls, focus),
            "terms": terms,
            "literature": literature,
            "missing_standards": missing_standards,
        }

    # Postings for every term a class query can contain. A query term that
    # is not here (a caller adding its own) is resolved by a scan and memoised.
    postings: Dict[str, List[int]] = {}
    for term in sorted(all_terms):
        postings[term] = [i for i, text in enumerate(folded) if term in text]

    if si is not None:
        manifest = si.manifest()
        for doc_id in manifest:
            citations[doc_id] = {"citation": si.citation(doc_id), "acm": si.acm_citation(doc_id)}
    elif MANIFEST_FILE.is_file():
        for doc_id, entry in json.loads(MANIFEST_FILE.read_text(encoding="utf-8")).items():
            if isinstance(entry, dict):
                citations[doc_id] = {"citation": entry.get("citation"),
                                     "acm": entry.get("acm") or entry.get("citation")}

    index = {
        "schema": SCHEMA,
        "version": version,
        "built_seconds": 0.0,
        "archive_present": si is not None,
        "integrity": verify_sources(),
        "always": always,
        "ambiguous_pairs": [
            {"classes": list(p["classes"]), "note": p.get("note", "")}
            for p in getattr(km, "AMBIGUOUS_PAIRS", [])
        ],
        "baselines": baselines,
        "baseline_requests": [list(r) for r in baselines_req],
        "classes": classes,
        "pool": pool,
        "folded": folded,
        "postings": postings,
        "common_term_share": getattr(si, "COMMON_TERM_SHARE", 0.4) if si else 0.4,
        "citations": citations,
    }
    index["built_seconds"] = round(time.perf_counter() - started, 3)
    tmp = INDEX_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(index), encoding="utf-8")
    tmp.replace(INDEX_FILE)
    return index


def _read_index() -> Optional[Dict[str, Any]]:
    try:
        data = json.loads(INDEX_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if data.get("schema") == SCHEMA else None


def load_rag_index() -> Tuple[Dict[str, Any], str]:
    """Open the persisted index; rebuild only when the corpus changed.

    Returns (index, how) where how is "reused" or "rebuilt".
    """
    version = knowledge_version()
    current = _read_index()
    if current and current.get("version") == version:
        return current, "reused"
    return build_rag_index(force=True), "rebuilt"


# ------------------------------------------------------------------
# retrieval
# ------------------------------------------------------------------

def search(index: Dict[str, Any], terms: List[str], limit: int = 2,
           exclude=()) -> List[Dict[str, Any]]:
    """source_index.search() over the prepared pool, through postings."""
    pool, folded, postings = index["pool"], index["folded"], index["postings"]
    if not pool or not terms:
        return []
    total = len(pool)
    ceiling = total * index["common_term_share"]
    already = {(d, str(n)) for d, n in exclude}

    weighted = []
    for term in terms:
        hits = postings.get(term)
        if hits is None:
            hits = [i for i, text in enumerate(folded) if term in text]
            postings[term] = hits
        if not hits or len(hits) > ceiling:
            continue
        weighted.append((term, math.log(total / len(hits)), set(hits)))
    if not weighted:
        return []

    candidates = set().union(*(h for _, _, h in weighted))
    scored = []
    for i in candidates:
        section = pool[i]
        if (section["doc_id"], section["number"]) in already:
            continue
        # Summed in term order, as source_index.search() does, so the float
        # score -- and therefore the ranking -- is bit-identical.
        score = sum(w for _, w, h in weighted if i in h)
        matched = sum(1 for _, _, h in weighted if i in h)
        if matched < 2:
            continue
        scored.append((-score, section["doc_id"], section["number"], i))
    scored.sort(key=lambda row: row[:3])

    found = []
    for negative, doc_id, number, i in scored[:limit]:
        section = pool[i]
        where = f" (p.{section['page']})" if section["page"] else ""
        found.append({
            "kind": "section",
            "doc_id": doc_id,
            "ref": f"{number} {section['title']}",
            "label": f"{doc_id} section {number} {section['title']}{where}",
            "text": section["text"],
            "score": round(-negative, 3),
            "source_id": f"{SHORT_DOC.get(doc_id, doc_id)}:{number}",
        })
    return found


if __name__ == "__main__":
    t = time.perf_counter()
    idx = build_rag_index(force="--force" in sys.argv)
    took = time.perf_counter() - t
    print(f"version       {idx['version']}")
    print(f"classes       {len(idx['classes'])}")
    print(f"pool          {len(idx['pool'])} sections")
    print(f"postings      {len(idx['postings'])} terms")
    print(f"archive       {'present' if idx['archive_present'] else 'absent'}")
    print(f"integrity     {idx['integrity']['status']} "
          f"({idx['integrity']['ok']}/{idx['integrity']['checked']} files match SHA256SUMS.txt)")
    print(f"size          {INDEX_FILE.stat().st_size / 1e6:.2f} MB")
    print(f"this call     {took * 1000:.0f} ms (build took {idx['built_seconds']} s)")
