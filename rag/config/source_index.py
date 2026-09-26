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
import math
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

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
    # NIST.SP.800-53r5 is deliberately absent: its controls come from
    # the CPRT catalogue below, which is exact, and its numbered
    # footnotes are indistinguishable from its section headings.
    "NIST.SP.800-52r2": "NIST.SP.800-52r2.pdf",
    "NIST.SP.800-18r2": "NIST.SP.800-18r2.pdf",
    "NIST.AI.100-1": "NIST.AI.100-1.pdf",
    "Chen.xgboost": "Chen.xgboost.pdf",
    "Arp.cacm": "Arp.cacm.pdf",
    "Arslan.mits": "Arslan.mits.pdf",
    "Iyengar.aip": "Iyengar.aip.pdf",
}

# Extracted text, written by extract_sources.py, one file per manifest
# entry. It is the reader of last resort: any cited document that no
# extractor above covers is read from here, so a source is readable or it
# is absent and there is no third state. A page of extracted text is one
# section, because the page is what a reader checks a quotation against.
EXTRACTED_DIR = SOURCES_DIR.parent / "_extracted"

# Extracted pages join the free-text pool that supports a recommendation
# only when this is on. It is off because of a measured effect: the pool
# would gain over a thousand page-sized sections, most of them front
# matter, appendices and control tables that outscore a containment
# procedure on shared vocabulary. Everything stays retrievable by name
# either way, through sections_for() and passages_of().
EXTRACTED_SEARCHABLE = False

# A page shorter than this is a cover, a running header or a blank.
MIN_EXTRACTED_CHARS = 400

# The peer-reviewed comparators this study is written against. They are
# not incident-response guidance and they do not ground a recommendation:
# they answer "what does the published literature report for this task",
# which the interface is asked and previously could not source at all.
#
# They are kept in their own registry rather than added to
# SECTION_DOCUMENTS because of a measured effect, not a preference. With
# them in the free-text pool, methodology prose displaces response
# guidance -- a paper's "Dataset and Preprocessing" outscores a
# containment procedure on the terms a class is described in, because the
# vocabulary of a class description is the vocabulary of a methods
# section. LITERATURE_SEARCHABLE controls that, and defaults off; the
# documents stay indexed and stay retrievable by name either way.
LITERATURE_DOCUMENTS = {
    "Catillo.transferability": "02_Catillo_2022_SQJ_transferability.pdf",
    "Cosar.cseciids2018": "04_Cosar_2024_AITA_cseciids2018.pdf",
    "Gombar.triage": "07_Gombar_2026_Electronics_triage.pdf",
    "Bilal.federated": "08_SciRep_2026_federated_iot.pdf",
    "Villafranca.trustlab": "09_Villafranca_2026_FrontCompSci_TRUSTLab.pdf",
    "Sharafaldin.cicids": "10_Sharafaldin_2018_ICISSP_CICIDS.pdf",
}

LITERATURE_SEARCHABLE = False

# The CISA federal playbooks number their footnotes and not their sections,
# so the numbered-heading extractor returns footnote text. Their headings
# are plain title-cased lines instead, and naming them is more honest than
# guessing at a pattern: a wrong section label on a correct quotation is
# still a wrong citation.
TITLE_DOCUMENTS = {
    "CISA.playbooks": (
        "CISA.playbooks.pdf",
        [
            "Incident Response Process",
            "Preparation",
            "Detection & Analysis",
            "Containment",
            "Eradication & Recovery",
            "Post-Incident Activities",
            "Coordination",
            "Vulnerability Response Process",
        ],
    ),
}

# Plain-text RFCs. Their sections are numbered at column zero, which is a
# cleaner anchor than anything a PDF gives.
TEXT_DOCUMENTS = {
    "RFC9424": "RFC9424.txt",
    "RFC1858": "RFC1858.txt",
    "RFC3128": "RFC3128.txt",
}

# The OWASP Top 10 ships as one Markdown file per risk. Each file is one
# section: splitting it further separates a finding from the risk it
# belongs to, and the risk is the part worth citing.
MARKDOWN_DOCUMENTS = {
    "OWASP.Top10.2025": "OWASP_Top10_2025_FULL",
}

# A heading whose body is shorter than this is a table-of-contents line,
# not a section. Extracting them added entries such as "Introduction 1"
# with sixteen characters of text.
MIN_SECTION_CHARS = 250

# Bumped when the extractors change, so a cached index built by an older
# version is rebuilt rather than trusted.
INDEX_SCHEMA = 5

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

_CONTENTS_LINE = re.compile(r"\s\d{1,3}$")

_HEADING = re.compile(r"^(\d{1,2}(?:\.\d{1,2}){0,2})\.?\s+([A-Z][^\n]{4,80})$")

# Journals do not number their sections the way a standard does. Three
# styles cover every paper in the archive, and each is anchored tightly
# enough not to match a table row or a sentence that happens to start
# with a numeral:
#   IEEE and JAIT    "I. INTRODUCTION", "V. RESULTS AND DISCUSSION"
#   Nature, Frontiers "Methodology", "Results and analysis" on their own line
# The numbered form is still tried first, because Frontiers and Electronics
# do number theirs.
_ROMAN_HEADING = re.compile(
    r"^((?:X{0,2})(?:IX|IV|V?I{0,3}))\.\s+([A-Z][A-Z0-9 \-,:&/().]{3,79})$"
)

_NAMED_SECTIONS = (
    "abstract", "introduction", "background", "related work",
    "related works", "literature review", "methodology", "methods",
    "materials and methods", "experimental setup", "experiments",
    "results", "results and analysis", "results and discussion",
    "evaluation", "discussion", "limitations", "conclusion",
    "conclusions", "conclusion and future work", "future work",
    "data availability", "references",
)

_NAMED_HEADING = re.compile(
    r"^(" + "|".join(re.escape(n) for n in _NAMED_SECTIONS) + r")$",
    re.I,
)

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


def _literature_heading(line: str):
    """(number, title) for a journal heading, or None.

    Numbered first, then roman-numeral, then a bare section name. The
    roman form returns the numeral as the locator because that is what
    the paper prints and what a reader would look for.
    """
    match = _HEADING.match(line)
    if match:
        return match.group(1), match.group(2).strip()

    # Titles are kept exactly as the paper prints them. Re-casing an
    # all-caps heading to title case breaks the body-text anchor, which
    # searches for the heading string itself -- the section then indexes
    # with no text and is dropped for being too short.
    match = _ROMAN_HEADING.match(line)
    if match and match.group(1):
        return match.group(1), match.group(2).strip()

    match = _NAMED_HEADING.match(line)
    if match:
        title = match.group(1).strip()
        return title, title

    return None


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

    wanted = [(d, f, False) for d, f in SECTION_DOCUMENTS.items()]
    wanted += [(d, f, True) for d, f in LITERATURE_DOCUMENTS.items()]

    for doc_id, file_name, is_literature in wanted:

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

        # Front matter is worth skipping in a specification with a cover,
        # a notice page and a contents page. A six-page FAQ has none of
        # that, and skipping five pages of it left nothing at all.
        # A paper has no cover or notice page: its abstract is on page one
        # and skipping it would drop the part most worth quoting.
        first_page = 1 if is_literature else min(
            FIRST_CONTENT_PAGE,
            max(2, len(pages) // 6)
        )

        for page_number, page_text in pages:

            if page_number < first_page:
                continue

            for line in page_text.splitlines():

                if is_literature:
                    parsed = _literature_heading(line.strip())
                else:
                    found_heading = _HEADING.match(line.strip())
                    parsed = (
                        (found_heading.group(1),
                         found_heading.group(2).strip())
                        if found_heading else None
                    )

                if not parsed:
                    continue

                number, title = parsed

                # A table-of-contents line carries the page number after
                # the title. Recording it would both quote the contents
                # page and hide the real heading behind a duplicate.
                if _CONTENTS_LINE.search(title):
                    continue

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
            "literature": is_literature,
            "sections": [
                s for s in sections
                if len(s["text"]) >= MIN_SECTION_CHARS
            ],
        }

    return documents


def _extract_titled() -> Dict[str, Any]:
    """Sections of a document whose headings are named, not numbered."""
    try:
        import pypdf
    except ImportError:
        return {}

    documents: Dict[str, Any] = {}

    for doc_id, (file_name, titles) in TITLE_DOCUMENTS.items():

        path = SOURCES_DIR / file_name

        if not path.is_file():
            continue

        try:
            reader = pypdf.PdfReader(str(path))
        except Exception:                            # noqa: BLE001
            continue

        whole = ""
        page_of = {}

        for number, page in enumerate(reader.pages, start=1):
            page_of[len(whole)] = number
            whole += (page.extract_text() or "") + "\n"

        def _page_at(offset: int) -> int:
            starts = [o for o in page_of if o <= offset]
            return page_of[max(starts)] if starts else 1

        # A heading on its own line, not the same words inside a sentence
        # or in the table of contents.
        hits = []

        for title in titles:
            pattern = re.compile(
                r"^[ \t]*" + re.escape(title) + r"[ \t]*$",
                re.M
            )
            found = [m.start() for m in pattern.finditer(whole)]

            if len(found) < 2:
                # One occurrence is the contents page; a real heading is
                # listed there and again where the section begins.
                continue

            hits.append((found[-1], title))

        hits.sort()

        sections = []

        for position, (start, title) in enumerate(hits):

            end = (
                hits[position + 1][0]
                if position + 1 < len(hits)
                else start + 4000
            )

            text = " ".join(whole[start:end].split())

            if len(text) < MIN_SECTION_CHARS:
                continue

            sections.append({
                "number": title,
                "title": title,
                "page": _page_at(start),
                "text": text[:4000],
            })

        documents[doc_id] = {"file": file_name, "sections": sections}

    return documents


def _extract_text_documents() -> Dict[str, Any]:
    """Numbered sections of a plain-text RFC."""
    heading = re.compile(r"^(\d+(?:\.\d+)*)\.?\s+(\S.{2,90})$")

    documents: Dict[str, Any] = {}

    for doc_id, file_name in TEXT_DOCUMENTS.items():

        path = SOURCES_DIR / file_name

        if not path.is_file():
            continue

        try:
            body = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        lines = body.splitlines()

        marks = []

        for position, line in enumerate(lines):

            match = heading.match(line)

            if not match:
                continue

            number = match.group(1)

            if any(m[1] == number for m in marks):
                continue

            marks.append((position, number, match.group(2).strip()))

        sections = []

        for position, (line_number, number, title) in enumerate(marks):

            end = (
                marks[position + 1][0]
                if position + 1 < len(marks)
                else len(lines)
            )

            text = " ".join(" ".join(lines[line_number:end]).split())

            if len(text) < MIN_SECTION_CHARS:
                continue

            sections.append({
                "number": number,
                "title": title,
                # A text file has no pages. The section number is the
                # locator a reader needs.
                "page": 0,
                "text": text[:4000],
            })

        documents[doc_id] = {"file": file_name, "sections": sections}

    return documents


def _extract_markdown() -> Dict[str, Any]:
    """One section per Markdown file in a directory."""
    documents: Dict[str, Any] = {}

    for doc_id, directory in MARKDOWN_DOCUMENTS.items():

        folder = SOURCES_DIR / directory

        if not folder.is_dir():
            continue

        sections = []

        for path in sorted(folder.glob("*.md")):

            try:
                body = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            title_line = next(
                (
                    line[2:].strip()
                    for line in body.splitlines()
                    if line.startswith("# ")
                ),
                path.stem
            )

            # The image and style markup that follows an OWASP heading is
            # not worth carrying into a prompt.
            title = re.sub(r"!\[.*", "", title_line).strip()

            number = path.stem.split("_")[0]

            body = re.sub(r"<table>.*?</table>", " ", body, flags=re.S)
            body = re.sub(r"!\[[^\]]*\]\([^)]*\)[^\n]*", " ", body)

            body = re.sub(r"^#{1,6}\s*", "", body, flags=re.M)

            text = " ".join(body.split())

            if len(text) < MIN_SECTION_CHARS:
                continue

            sections.append({
                "number": number,
                "title": title,
                "page": 0,
                "text": text[:4000],
            })

        documents[doc_id] = {
            "file": directory,
            "sections": sections,
        }

    return documents


# ------------------------------------------------------------------
# build / load
# ------------------------------------------------------------------

_PART_MARKER = re.compile(r"^<!--\s*(.+?)\s*-->$", re.M)


def _extract_from_text(already: Iterable[str]) -> Dict[str, Any]:
    """Cited documents that no other extractor covers, from _extracted/.

    One section per extracted part -- a PDF page, a Markdown file, a
    control identifier -- keyed by that part's label, which is the
    locator a reader needs to find the passage again.
    """
    if not EXTRACTED_DIR.is_dir():
        return {}

    covered = set(already)

    documents: Dict[str, Any] = {}

    for doc_id, entry in sorted(manifest().items()):

        if doc_id in covered:
            continue

        path = EXTRACTED_DIR / f"{doc_id}.md"

        if not path.is_file():
            continue

        try:
            body = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        marks = list(_PART_MARKER.finditer(body))

        if not marks:
            continue

        sections = []

        for position, mark in enumerate(marks):

            end = (
                marks[position + 1].start()
                if position + 1 < len(marks)
                else len(body)
            )

            text = " ".join(body[mark.end():end].split())

            if len(text) < MIN_EXTRACTED_CHARS:
                continue

            label = mark.group(1)

            number = (
                label.split()[-1] if label.startswith("page ") else label
            )

            sections.append({
                "number": number,
                "title": label,
                "page": int(number) if number.isdigit() else 0,
                "text": text[:4000],
            })

        documents[doc_id] = {
            "file": entry.get("file", ""),
            "extracted": True,
            "sections": sections,
        }

    return documents


def _archive_fingerprint() -> str:
    """Cheap change detector: the manifest's own bytes."""
    if not MANIFEST_FILE.is_file():
        return "absent"
    import hashlib
    digest = hashlib.sha256(
        MANIFEST_FILE.read_bytes()
    ).hexdigest()[:16]

    # The extraction stamp too, so re-extracting a source rebuilds the
    # index rather than leaving it reading an older copy.
    stamp = EXTRACTED_DIR / ".extracted.json"

    extracted = hashlib.sha256(
        stamp.read_bytes()
    ).hexdigest()[:8] if stamp.is_file() else "none"

    return f"{INDEX_SCHEMA}.{digest}.{extracted}"


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

    documents = _extract_sections()
    documents.update(_extract_titled())
    documents.update(_extract_text_documents())
    documents.update(_extract_markdown())

    controls = _extract_controls()

    # Last: whatever is cited and still has no reader. The CPRT catalogue
    # counts as a reader for SP 800-53r5, so it is passed in as covered.
    covered = set(documents)

    if controls:
        covered.add("NIST.SP.800-53r5")

    documents.update(_extract_from_text(covered))

    index = {
        "fingerprint": fingerprint,
        "controls": controls,
        "documents": documents,
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


# A section retrieved by search is quoted more briefly than one asked for
# by name: it is a supporting passage, not the requested authority.
SEARCH_CHAR_BUDGET = 700

# A term in more than this share of sections describes the archive rather
# than the query. "security" is in most of it and separates nothing.
COMMON_TERM_SHARE = 0.4

# Words that carry no topic. Kept short on purpose: the frequency rule
# above removes most of what a longer list would.
_STOPWORDS = frozenset("""
about above after also amid among analysis approach based because been
before being between both cannot could data during each either from
further have here into itself less many more most much must
none only other over same should since some such than that their them
then there these they this those three through thus under until upon
used uses using very what when where which while will with within
without would your
""".split())

_WORD = re.compile(r"[a-z][a-z0-9\-]{3,}")

# CamelCase class names carry two terms: BufferOverflow is a buffer and
# an overflow, and neither half is in the documents spelled as one word.
_CAMEL = re.compile(r"(?<=[a-z])(?=[A-Z])")

_sections_cache: Optional[List[Dict[str, Any]]] = None


def _all_sections() -> List[Dict[str, Any]]:
    """Every indexed section, flattened once, with a folded copy to match."""
    global _sections_cache

    if _sections_cache is not None:
        return _sections_cache

    flat = []

    for doc_id, document in sorted(index()["documents"].items()):

        # Literature is indexed either way, but it only joins the
        # free-text pool that supports a recommendation when it is
        # switched on. See LITERATURE_DOCUMENTS for the measurement
        # behind the default.
        if document.get("literature") and not LITERATURE_SEARCHABLE:
            continue

        if document.get("extracted") and not EXTRACTED_SEARCHABLE:
            continue

        for section in document["sections"]:

            flat.append({
                "doc_id": doc_id,
                "number": section["number"],
                "title": section["title"],
                "page": section["page"],
                "text": section["text"],
                "folded": section["text"].lower(),
            })

    _sections_cache = flat

    return flat


def terms_of(*phrases: str) -> List[str]:
    """Search terms from free text: folded, split on case, deduplicated."""
    collected: List[str] = []

    for phrase in phrases:

        if not phrase:
            continue

        spaced = _CAMEL.sub(" ", str(phrase))

        for word in _WORD.findall(spaced.lower()):

            if word in _STOPWORDS or word in collected:
                continue

            collected.append(word)

    return collected


def search(terms: List[str],
           limit: int = 2,
           exclude: Iterable[Any] = ()) -> List[Dict[str, Any]]:
    """Indexed sections that share the most distinctive terms with `terms`.

    Deterministic by construction: a term either occurs in a section or it
    does not, rarer terms weigh more, and ties break on the document and
    section identifier. The same prediction retrieves the same passages on
    every run and on every machine, which a vector search would not
    guarantee and which the citations depend on.
    """
    sections = _all_sections()

    if not sections or not terms:
        return []

    already = {
        (doc_id, str(number)) for doc_id, number in exclude
    }

    total = len(sections)
    ceiling = total * COMMON_TERM_SHARE

    weighted = []

    for term in terms:

        frequency = sum(
            1 for section in sections if term in section["folded"]
        )

        if not frequency or frequency > ceiling:
            continue

        # Rarer term, heavier weight. The logarithm keeps a term that
        # appears in one section from outweighing four that appear in
        # twenty.
        weighted.append((term, math.log(total / frequency)))

    if not weighted:
        return []

    scored = []

    for section in sections:

        if (section["doc_id"], str(section["number"])) in already:
            continue

        score = sum(
            weight for term, weight in weighted
            if term in section["folded"]
        )

        matched = sum(
            1 for term, _ in weighted if term in section["folded"]
        )

        # One rare word in common is a coincidence often enough to be
        # worth ignoring.
        if matched < 2:
            continue

        scored.append((-score, section["doc_id"],
                       str(section["number"]), section))

    scored.sort(key=lambda row: row[:3])

    found = []

    for negative_score, doc_id, number, section in scored[:limit]:

        where = (
            f" (p.{section['page']})" if section["page"] else ""
        )

        found.append({
            "kind": "section",
            "doc_id": doc_id,
            "ref": f"{number} {section['title']}",
            "label": (
                f"{doc_id} section {number} "
                f"{section['title']}{where}"
            ),
            "text": section["text"][:SEARCH_CHAR_BUDGET].strip(),
            "score": round(-negative_score, 3),
        })

    return found


def literature_for(terms: List[str],
                   limit: int = 2,
                   doc_ids: Optional[Iterable[str]] = None,
                   one_per_paper: bool = True
                   ) -> List[Dict[str, Any]]:
    """Passages from the peer-reviewed comparators, by term.

    Separate from `search()` on purpose. `search()` answers "what guidance
    supports this recommendation" and must stay operational; this answers
    "what has been published about this task", where a methods section is
    the right answer rather than a distraction. `doc_ids` narrows it to
    named papers, which is how a question about one study is served.

    Deterministic on the same terms: identical scoring to `search()`,
    ties broken on document and section identifier.
    """
    documents = index()["documents"]

    pool = []

    for doc_id, document in sorted(documents.items()):

        if not document.get("literature"):
            continue

        if doc_ids is not None and doc_id not in set(doc_ids):
            continue

        for section in document["sections"]:
            pool.append({
                "doc_id": doc_id,
                "number": section["number"],
                "title": section["title"],
                "page": section["page"],
                "text": section["text"],
                "folded": section["text"].lower(),
            })

    if not pool or not terms:
        return []

    total = len(pool)
    ceiling = total * COMMON_TERM_SHARE

    weighted = []

    for term in terms:
        frequency = sum(1 for s in pool if term in s["folded"])
        if not frequency or frequency > ceiling:
            continue
        weighted.append((term, math.log(total / frequency)))

    if not weighted:
        return []

    scored = []

    for section in pool:

        score = sum(
            weight for term, weight in weighted
            if term in section["folded"]
        )

        matched = sum(
            1 for term, _ in weighted if term in section["folded"]
        )

        if matched < 2:
            continue

        scored.append((-score, section["doc_id"],
                       str(section["number"]), section))

    scored.sort(key=lambda row: row[:3])

    # One passage per paper by default. The dataset's own paper describes
    # every class in this taxonomy, so on raw score it takes both slots for
    # most classes and the other eight comparators are never seen. Two
    # papers saying something is worth more to a reader than one paper
    # saying it twice.
    if one_per_paper:
        best_of_each = []
        taken = set()
        for row in scored:
            if row[1] in taken:
                continue
            taken.add(row[1])
            best_of_each.append(row)
        scored = best_of_each

    found = []

    for negative_score, doc_id, number, section in scored[:limit]:

        where = f" (p.{section['page']})" if section["page"] else ""

        found.append({
            "kind": "literature",
            "doc_id": doc_id,
            "ref": f"{number} {section['title']}",
            "label": (
                f"{doc_id} section {number} "
                f"{section['title']}{where}"
            ),
            "text": section["text"][:SEARCH_CHAR_BUDGET].strip(),
            "score": round(-negative_score, 3),
        })

    return found


def unreadable() -> List[Dict[str, str]]:
    """Manifest entries the archive cites but cannot quote from.

    A citation with no passage behind it is the failure this module was
    written to prevent, so it is reported rather than left to be noticed
    when a recommendation comes back thin.
    """
    indexed = index()["documents"]
    catalogue = index()["controls"]

    gaps = []

    for doc_id, entry in sorted(manifest().items()):

        file_name = entry.get("file") or ""
        path = SOURCES_DIR / file_name if file_name else None

        present = bool(file_name) and path is not None and (
            path.is_file() or path.is_dir()
        )

        if not present:
            gaps.append({
                "doc_id": doc_id,
                "file": file_name,
                "reason": "cited in the manifest, file not in the archive",
            })
            continue

        document = indexed.get(doc_id)

        if document is not None and document["sections"]:
            continue

        # SP 800-53r5 is quotable through its control catalogue rather
        # than as sections, which is the exact form, not a lesser one.
        if doc_id == "NIST.SP.800-53r5" and catalogue:
            continue

        if not (EXTRACTED_DIR / f"{doc_id}.md").is_file():
            gaps.append({
                "doc_id": doc_id,
                "file": file_name,
                "reason": "present, but never extracted -- run "
                          "config/extract_sources.py",
            })
            continue

        gaps.append({
            "doc_id": doc_id,
            "file": file_name,
            "reason": "extracted, but no part long enough to quote",
        })

    return gaps


def passages_of(doc_id: str, limit: int = 0) -> List[Dict[str, Any]]:
    """Every indexed passage of one document, in order.

    The way to reach a source by name rather than by search: a cited
    document is quotable whether or not it competes for a place in the
    free-text pool.
    """
    document = index()["documents"].get(doc_id)

    if not document:
        return []

    found = []

    for section in document["sections"]:

        where = f" (p.{section['page']})" if section["page"] else ""

        found.append({
            "kind": "section",
            "doc_id": doc_id,
            "ref": f"{section['number']} {section['title']}".strip(),
            "label": (
                f"{doc_id} section {section['number']} "
                f"{section['title']}{where}"
            ).replace("  ", " "),
            "text": section["text"][:SECTION_CHAR_BUDGET].strip(),
        })

        if limit and len(found) >= limit:
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
        tag = ""
        if document.get("literature"):
            tag = "  [literature]"
        elif document.get("extracted"):
            tag = "  [extracted]"
        print(f"sections indexed : {doc_id:<26}"
              f"{len(document['sections']):>4}{tag}")

    print()
    print(f"cited documents  : {len(manifest())}")
    print(f"searchable       : {len(_all_sections())} sections")

    gaps = unreadable()
    print()
    if gaps:
        print(f"UNREADABLE ({len(gaps)}) -- cited but not quotable:")
        for gap in gaps:
            print(f"  {gap['doc_id']:<28} {gap['reason']}")
    else:
        print("every cited document is readable")
    print()
    for passage in controls_for(["SC-5", "AC-7"]):
        print(f"  {passage['label']}")
        print(f"    {passage['text'][:140]}...")
    for passage in sections_for([("NIST.SP.800-61r3", "3.2")]):
        print(f"  {passage['label']}")
        print(f"    {passage['text'][:140]}...")
