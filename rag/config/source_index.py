"""
source_index.py
---------------
Retrieval from the real publications in _sources/, not from prose we wrote.

WHY THIS EXISTS
The playbooks under knowledge/incident_response/ once carried a PLACEHOLDER
banner: prose written to exercise the citation path. A recommendation grounded
in them was grounded in nothing, and the retrieval step made that worse rather
than better, because it presented invented prose with the confidence of a
citation. build_playbooks.py now compiles them from the archive instead.

The archive already holds the documents those playbooks were standing in for:
NIST SP 800-61r3, SP 800-53r5 (with a machine-readable catalogue), SP 800-86,
the CISA federal response playbooks and the OWASP Top 10. This module pulls
the relevant passages out of them, so a recommendation cites a control
identifier or a section and page of a public standard.

WHAT MAKES IT DETERMINISTIC
Nothing here searches. A class already carries its NIST SP 800-53 control
identifiers in knowledge_map.py; those resolve to exact catalogue entries by
identifier. Section retrieval is by section number, fixed per class. Two runs
over the same archive return the same passages, and a passage that cannot be
found is reported rather than approximated.

BUILD AND CACHE
The index is derived from _sources/, which is not in Git because it holds
third-party publications. The cache is therefore written beside the archive
and is untracked too. It is rebuilt when the archive's manifest changes.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

SOURCES_DIR = Path(__file__).resolve().parent.parent / "_sources"

INDEX_FILE = SOURCES_DIR / ".source_index.json"

MANIFEST_FILE = SOURCES_DIR / "manifest.json"

# NIST 800-53 in CPRT form. Control text keyed by identifier, so no PDF
# parsing is involved and the lookup is exact.
CPRT_FILE = SOURCES_DIR / "cprt_SP_800_53_5_2_0_09-08-2026.json"

# Documents whose numbered sections are extracted. A document is added by
# putting it here; nothing else changes.
SECTION_DOCUMENTS = {
    "NIST.SP.800-61r3": "NIST.SP.800-61r3.pdf",
    "NIST.SP.800-86": "NIST.SP.800-86.pdf",
}

# The CISA federal playbooks are in the archive and are relevant, but they
# number their footnotes and not their sections, so the heading extractor
# returns footnote text. Quoting that would be worse than not quoting it,
# so the document is cited in the source list and not section-indexed.
# Add it here once a reliable anchor for its headings exists.

# Passages every class receives: the response functions of the incident
# response profile, and the evidence-collection step of the forensic
# process. Class-specific grounding comes from the NIST SP 800-53 control
# identifiers already recorded per class in knowledge_map.py.
BASELINE_SECTIONS = [
    ("NIST.SP.800-61r3", "3.2"),
    ("NIST.SP.800-86", "3.1"),
]

# Front matter carries page numbers and addresses that look like headings.
FIRST_CONTENT_PAGE = 6

_HEADING = re.compile(r"^(\d{1,2}(?:\.\d{1,2}){0,2})\.?\s+([A-Z][^\n]{4,80})$")

_TAG = re.compile(r"<[^>]+>")

_CONTROL_ID = re.compile(r"^([A-Z]{2})-(\d+)(\(\d+\))?$")

_SPLIT_CAPITAL = re.compile(r"\b([A-Z]) ([a-z]{2,})")


# ------------------------------------------------------------------
# helpers
# ------------------------------------------------------------------

def _clean(html: Optional[str]) -> str:
    """CPRT discussion text is HTML fragments."""
    if not html:
        return ""
    text = _TAG.sub(" ", html)
    text = text.replace("&nbsp;", " ").replace("&amp;", "&")
    text = text.replace("&lt;", "<").replace("&gt;", ">")
    return " ".join(text.split())


def normalise_control_id(control_id: str) -> str:
    """SC-5 -> SC-05. The catalogue zero-pads; knowledge_map.py does not."""
    match = _CONTROL_ID.match(control_id.strip().upper())
    if not match:
        return control_id.strip().upper()
    family, number, enhancement = match.groups()
    return f"{family}-{int(number):02d}{enhancement or ''}"


def manifest() -> Dict[str, Any]:
    if not MANIFEST_FILE.is_file():
        return {}
    return json.loads(
        MANIFEST_FILE.read_text(encoding="utf-8")
    )


def citation(doc_id: str) -> Optional[str]:
    """The formatted citation the archive records for a document."""
    entry = manifest().get(doc_id)
    if not entry:
        return None
    return entry.get("citation")


def acm_citation(doc_id: str) -> Optional[str]:
    """The ACM Reference Format citation, when one is recorded.

    Falls back to the IEEE form the archive already holds rather than
    attempting a conversion: expanding author initials into the full
    names ACM wants cannot be done reliably from the string alone.
    """
    entry = manifest().get(doc_id)
    if not entry:
        return None
    return entry.get("acm") or entry.get("citation")


# ------------------------------------------------------------------
# extraction
# ------------------------------------------------------------------

def _extract_controls() -> Dict[str, Any]:
    """Control identifier -> title, statement, discussion.

    Straight out of the CPRT catalogue. Statement parts are the base
    control (CST-XX-NN and its lettered children); parenthesised
    identifiers are enhancements and are left out, because a
    recommendation should quote the control, not every variation of it.
    """
    if not CPRT_FILE.is_file():
        return {}

    payload = json.loads(
        CPRT_FILE.read_text(encoding="utf-8")
    )

    elements = (
        payload["response"]["elements"]["elements"]
    )

    by_identifier: Dict[str, List[dict]] = {}

    for element in elements:
        by_identifier.setdefault(
            element["element_identifier"], []
        ).append(element)

    controls: Dict[str, Any] = {}

    for element in elements:

        if element["element_type"] != "control":
            continue

        identifier = element["element_identifier"]

        statement_parts = []

        for key in sorted(by_identifier):

            if not key.startswith(f"CST-{identifier}"):
                continue

            # CST-SC-05, CST-SC-05-a ... but not CST-SC-05(01)
            tail = key[len(f"CST-{identifier}"):]

            if tail and not tail.startswith("-"):
                continue

            text = _clean(by_identifier[key][0].get("text"))

            if text and text.lower() != "withdrawn":
                statement_parts.append(text)

        discussion = by_identifier.get(f"D-{identifier}")

        controls[identifier] = {
            "id": identifier,
            "title": (element.get("title") or "").strip(),
            "statement": statement_parts,
            "discussion": _clean(
                discussion[0].get("text")
            ) if discussion else "",
        }

    return controls


def _extract_sections() -> Dict[str, Any]:
    """Numbered sections with their page numbers, per document.

    Section text runs from one heading to the next. Page numbers are
    the PDF page, which is what a reader needs to check the quote.
    """
    try:
        import pypdf
    except ImportError:
        return {}

    documents: Dict[str, Any] = {}

    for doc_id, file_name in SECTION_DOCUMENTS.items():

        path = SOURCES_DIR / file_name

        if not path.is_file():
            continue

        try:
            reader = pypdf.PdfReader(str(path))
        except Exception:                            # noqa: BLE001
            continue

        pages = [
            (index + 1, page.extract_text() or "")
            for index, page in enumerate(reader.pages)
        ]

        sections: List[Dict[str, Any]] = []

        for page_number, page_text in pages:

            if page_number < FIRST_CONTENT_PAGE:
                continue

            for line in page_text.splitlines():

                match = _HEADING.match(line.strip())

                if not match:
                    continue

                number, title = match.group(1), match.group(2).strip()

                if any(s["number"] == number for s in sections):
                    continue

                # pypdf separates a dropped capital from its word on
                # some NIST layouts: "D ata Collection", "A udience".
                title = _SPLIT_CAPITAL.sub(r"\1\2", title)

                sections.append({
                    "number": number,
                    "title": title,
                    "page": page_number,
                    "text": "",
                })

        # Body text: from a heading to the next one. The search starts at
        # the offset of the page the heading was found on -- a bare title
        # such as "Incident Response" also occurs on the cover, and
        # anchoring on the first match returns the title page instead of
        # the section.
        whole = ""
        page_offset = {}

        for page_number, page_text in pages:
            page_offset[page_number] = len(whole)
            whole += page_text + "\n"

        def _anchor(section: Dict[str, Any]) -> int:
            """Offset of a section's heading, searched from its own page."""
            base = page_offset.get(section["page"], 0)

            for candidate in (
                f"{section['number']}. {section['title']}",
                f"{section['number']} {section['title']}",
                section["title"],
            ):
                found = whole.find(candidate, base)
                if found >= 0:
                    return found

            return -1

        for position, section in enumerate(sections):

            start = _anchor(section)

            if start < 0:
                continue

            end = start + 4000

            if position + 1 < len(sections):
                next_start = _anchor(sections[position + 1])
                if start < next_start < end:
                    end = next_start

            section["text"] = " ".join(
                whole[start:end].split()
            )

        documents[doc_id] = {
            "file": file_name,
            "sections": [s for s in sections if s["text"]],
        }

    return documents


# ------------------------------------------------------------------
# build / load
# ------------------------------------------------------------------

def _archive_fingerprint() -> str:
    """Cheap change detector: the manifest's own bytes."""
    if not MANIFEST_FILE.is_file():
        return "absent"
    import hashlib
    return hashlib.sha256(
        MANIFEST_FILE.read_bytes()
    ).hexdigest()[:16]


def build(force: bool = False) -> Dict[str, Any]:
    """Parse the archive and cache the result beside it."""
    fingerprint = _archive_fingerprint()

    if not force and INDEX_FILE.is_file():
        try:
            cached = json.loads(
                INDEX_FILE.read_text(encoding="utf-8")
            )
            if cached.get("fingerprint") == fingerprint:
                return cached
        except (OSError, ValueError):
            pass

    index = {
        "fingerprint": fingerprint,
        "controls": _extract_controls(),
        "documents": _extract_sections(),
    }

    try:
        INDEX_FILE.write_text(
            json.dumps(index),
            encoding="utf-8"
        )
    except OSError:
        pass

    return index


_index: Optional[Dict[str, Any]] = None


def index() -> Dict[str, Any]:
    global _index
    if _index is None:
        _index = build()
    return _index


def available() -> bool:
    """Whether the archive is present and parsed."""
    data = index()
    return bool(data["controls"]) or bool(data["documents"])


# ------------------------------------------------------------------
# retrieval
# ------------------------------------------------------------------

CONTROL_CHAR_BUDGET = 700

SECTION_CHAR_BUDGET = 1200


def controls_for(control_ids: List[str]) -> List[Dict[str, Any]]:
    """Official text for each NIST SP 800-53 control identifier.

    A control that is not in the catalogue is reported as missing rather
    than replaced with a neighbouring one.
    """
    catalogue = index()["controls"]

    found = []

    for raw_id in control_ids:

        entry = catalogue.get(
            normalise_control_id(raw_id)
        )

        if not entry:
            continue

        body = " ".join(entry["statement"])

        if entry["discussion"]:
            body = f"{body} {entry['discussion']}"

        found.append({
            "kind": "control",
            "doc_id": "NIST.SP.800-53r5",
            "ref": raw_id,
            "label": f"NIST SP 800-53r5 {raw_id} {entry['title']}",
            "text": body[:CONTROL_CHAR_BUDGET].strip(),
        })

    return found


def sections_for(requests: List[Any]) -> List[Dict[str, Any]]:
    """Named sections of a document, by number.

    `requests` is a list of (doc_id, section_number) pairs.
    """
    documents = index()["documents"]

    found = []

    for doc_id, number in requests:

        document = documents.get(doc_id)

        if not document:
            continue

        for section in document["sections"]:

            if section["number"] != str(number):
                continue

            found.append({
                "kind": "section",
                "doc_id": doc_id,
                "ref": f"{number} {section['title']}",
                "label": (
                    f"{doc_id} section {number} "
                    f"{section['title']} (p.{section['page']})"
                ),
                "text": section["text"][:SECTION_CHAR_BUDGET].strip(),
            })

            break

    return found


def missing_for(control_ids: List[str], requests: List[Any]) -> List[str]:
    """Which requested passages the archive could not supply."""
    catalogue = index()["controls"]
    documents = index()["documents"]

    gaps = []

    for raw_id in control_ids:
        if normalise_control_id(raw_id) not in catalogue:
            gaps.append(f"NIST SP 800-53r5 {raw_id}")

    for doc_id, number in requests:
        document = documents.get(doc_id)
        if not document or not any(
            s["number"] == str(number) for s in document["sections"]
        ):
            gaps.append(f"{doc_id} section {number}")

    return gaps


if __name__ == "__main__":
    data = build(force=True)
    print(f"controls indexed : {len(data['controls'])}")
    for doc_id, document in data["documents"].items():
        print(f"sections indexed : {doc_id:<22}"
              f"{len(document['sections'])}")
    print()
    for passage in controls_for(["SC-5", "AC-7"]):
        print(f"  {passage['label']}")
        print(f"    {passage['text'][:140]}...")
    for passage in sections_for([("NIST.SP.800-61r3", "3.2")]):
        print(f"  {passage['label']}")
        print(f"    {passage['text'][:140]}...")
