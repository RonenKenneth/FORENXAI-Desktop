"""
extract_sources.py
------------------
Extracts every document in _sources/ to plain text in _extracted/, one file
per source, each carrying its citation.

WHY THIS EXISTS
Retrieval used to depend on whether a document's headings happened to match
a regular expression. A PDF whose sections were numbered was readable; a
release-delta table, a rendered HTML page and a paper that numbers its
sections in roman numerals were not. Those were quietly excused as "covered
elsewhere", which is the same failure this archive was built to avoid: a
citation the retrieval step cannot support.

So nothing is excused here. Every file listed in manifest.json is extracted,
and the extraction is the fallback reader for anything that has no better
one. A source is readable or it is absent -- there is no third state.

WHAT AN EXTRACTED FILE LOOKS LIKE
Markdown, not PDF. The point of the folder is to be read: by source_index.py,
by grep, and by a human checking a quotation. Re-rendering the text back into
a PDF would make all three harder and would add a writer dependency for no
gain. The citation is in the file, so a passage carries its source wherever
it is copied to.

    # NIST.SP.800-86
    > NIST SP 800-86, Guide to Integrating Forensic Techniques ...
    > source: NIST.SP.800-86.pdf (2,752,585 bytes, sha256 ea7eb645...)
    > extracted: 2026-09-23T04:12:00 by extract_sources.py

    <!-- page 1 -->
    ...text...

    <!-- page 2 -->

Page markers are HTML comments so they survive a Markdown render and are
trivial to strip. A reader checking a quote needs the page; a model reading
the text does not, and a comment is invisible to it either way.

RUN
    python config/extract_sources.py            # only what is missing or stale
    python config/extract_sources.py --force    # everything again
"""
from __future__ import annotations

import datetime
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

RAG_DIR = Path(__file__).resolve().parent.parent

SOURCES_DIR = RAG_DIR / "_sources"

EXTRACTED_DIR = RAG_DIR / "_extracted"

MANIFEST_FILE = SOURCES_DIR / "manifest.json"

STAMP_FILE = EXTRACTED_DIR / ".extracted.json"

# Bumped when the extractors change, so a stale extraction is redone.
EXTRACT_SCHEMA = 2

# Where a manifest entry names the wrong copy. OWASP.Top10.2025 is recorded
# against the rendered index page, which is a navigation menu: 2 KB of link
# text. The archive also holds the Markdown edition of the whole Top 10, and
# that is what the citation means, so that is what gets extracted.
CANONICAL_PATH = {
    "OWASP.Top10.2025": "OWASP_Top10_2025_FULL",
}

_TAG = re.compile(r"(?s)<[^>]+>")

_DROP_BLOCK = re.compile(
    r"(?is)<(script|style|nav|header|footer|noscript)[^>]*>.*?</\1>"
)

_ENTITIES = {
    "&nbsp;": " ", "&amp;": "&", "&lt;": "<", "&gt;": ">",
    "&quot;": '"', "&#39;": "'", "&apos;": "'", "&mdash;": "--",
    "&ndash;": "-", "&hellip;": "...", "&rsquo;": "'", "&lsquo;": "'",
    "&rdquo;": '"', "&ldquo;": '"',
}

# pypdf separates a dropped capital from its word on some NIST layouts:
# "D ata Collection", "A udience".
_SPLIT_CAPITAL = re.compile(r"\b([A-Z]) ([a-z]{2,})")


def _tidy(text: str) -> str:
    """Collapse whitespace without losing paragraph breaks."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = _SPLIT_CAPITAL.sub(r"\1\2", text)
    return text.strip()


def _unescape(text: str) -> str:
    for entity, plain in _ENTITIES.items():
        text = text.replace(entity, plain)
    return re.sub(r"&#\d+;", " ", text)


# ------------------------------------------------------------------
# per-format extraction -> [(page_label, text), ...]
# ------------------------------------------------------------------

def _from_pdf(path: Path) -> List[Tuple[str, str]]:
    try:
        import pypdf
    except ImportError:
        return []

    try:
        reader = pypdf.PdfReader(str(path))
    except Exception:                                    # noqa: BLE001
        return []

    pages = []

    for number, page in enumerate(reader.pages, start=1):
        try:
            body = page.extract_text() or ""
        except Exception:                                # noqa: BLE001
            body = ""
        body = _tidy(body)
        if body:
            pages.append((str(number), body))

    return pages


def _from_html(path: Path) -> List[Tuple[str, str]]:
    raw = path.read_text(encoding="utf-8", errors="replace")
    raw = _DROP_BLOCK.sub(" ", raw)

    # A documentation site puts its whole table of contents in the markup
    # before the article. Left in, a quotation from the page opens with
    # "Skip to content A02 Security Misconfiguration A03 ..." -- the menu,
    # not the risk. The article starts at its own <h1>.
    heading = re.search(r"(?is)<h1[^>]*>", raw)

    if heading:
        raw = raw[heading.start():]

    # Keep block boundaries as newlines so the text does not run together.
    raw = re.sub(r"(?i)</(p|div|li|h[1-6]|tr|section)>", "\n", raw)
    raw = re.sub(r"(?i)<br\s*/?>", "\n", raw)

    text = _tidy(_unescape(_TAG.sub(" ", raw)))

    return [("", text)] if text else []


def _from_text(path: Path) -> List[Tuple[str, str]]:
    text = _tidy(path.read_text(encoding="utf-8", errors="replace"))
    return [("", text)] if text else []


def _from_markdown_dir(path: Path) -> List[Tuple[str, str]]:
    """A directory of Markdown files: one part per file, named by its stem."""
    parts = []

    for child in sorted(path.glob("*.md")):
        body = child.read_text(encoding="utf-8", errors="replace")
        body = re.sub(r"(?s)<table>.*?</table>", " ", body)
        body = re.sub(r"!\[[^\]]*\]\([^)]*\)[^\n]*", " ", body)
        body = _tidy(body)
        if body:
            parts.append((child.stem, body))

    return parts


def _from_cprt_json(path: Path) -> List[Tuple[str, str]]:
    """The SP 800-53 catalogue: one part per control, identifier first.

    Extracted as text as well as read structurally by source_index, so the
    catalogue is greppable and quotable like every other source.
    """
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        elements = payload["response"]["elements"]["elements"]
    except (OSError, ValueError, KeyError):
        return []

    by_identifier: Dict[str, List[dict]] = {}

    for element in elements:
        by_identifier.setdefault(
            element["element_identifier"], []
        ).append(element)

    parts = []

    for element in elements:

        if element.get("element_type") != "control":
            continue

        identifier = element["element_identifier"]
        title = (element.get("title") or "").strip()

        chunks = []

        for key in sorted(by_identifier):
            if not key.startswith(f"CST-{identifier}"):
                continue
            tail = key[len(f"CST-{identifier}"):]
            if tail and not tail.startswith("-"):
                continue
            body = _tidy(_unescape(_TAG.sub(" ", by_identifier[key][0].get("text") or "")))
            if body and body.lower() != "withdrawn":
                chunks.append(body)

        discussion = by_identifier.get(f"D-{identifier}")

        if discussion:
            body = _tidy(_unescape(_TAG.sub(" ", discussion[0].get("text") or "")))
            if body:
                chunks.append(body)

        if not chunks:
            continue

        parts.append((identifier, f"{identifier} {title}\n\n" + "\n\n".join(chunks)))

    return parts


def _extract(path: Path) -> List[Tuple[str, str]]:
    if path.is_dir():
        return _from_markdown_dir(path)

    suffix = path.suffix.lower()

    if suffix == ".pdf":
        return _from_pdf(path)
    if suffix in (".html", ".htm"):
        return _from_html(path)
    if suffix == ".json":
        return _from_cprt_json(path)
    if suffix in (".txt", ".md", ".text"):
        return _from_text(path)

    return _from_text(path)


# ------------------------------------------------------------------
# writing
# ------------------------------------------------------------------

def _header(doc_id: str,
            entry: dict,
            path: Path,
            when: str) -> str:
    """Citation and provenance, as Markdown blockquote lines."""
    digest = entry.get("sha256") or hashlib.sha256(
        path.read_bytes() if path.is_file() else b""
    ).hexdigest()

    size = entry.get("bytes")

    if size is None and path.is_file():
        size = path.stat().st_size

    lines = [f"# {doc_id}", ""]

    citation = entry.get("citation")

    if citation:
        lines.append(f"> {citation}")

    for label, key in (("url", "url"), ("landing", "landing")):
        if entry.get(key):
            lines.append(f"> {label}: {entry[key]}")

    lines.append(
        f"> source: {path.name}"
        + (f" ({size:,} bytes)" if size else "")
        + (f", sha256 {digest[:16]}" if digest else "")
    )

    lines.append(f"> extracted: {when} by extract_sources.py")
    lines.append("")

    return "\n".join(lines)


def extract_all(force: bool = False) -> Dict[str, dict]:
    """Extract every manifest source. Returns a record per document."""
    EXTRACTED_DIR.mkdir(exist_ok=True)

    manifest = json.loads(MANIFEST_FILE.read_text(encoding="utf-8"))

    previous: Dict[str, dict] = {}

    if STAMP_FILE.is_file() and not force:
        try:
            stamp = json.loads(STAMP_FILE.read_text(encoding="utf-8"))
            if stamp.get("schema") == EXTRACT_SCHEMA:
                previous = stamp.get("documents", {})
        except (OSError, ValueError):
            previous = {}

    when = datetime.datetime.now().replace(microsecond=0).isoformat()

    records: Dict[str, dict] = {}

    for doc_id in sorted(manifest):

        entry = manifest[doc_id]
        file_name = CANONICAL_PATH.get(doc_id) or entry.get("file") or ""
        path = SOURCES_DIR / file_name if file_name else None

        if not file_name or path is None or not (
            path.is_file() or path.is_dir()
        ):
            records[doc_id] = {
                "file": file_name,
                "status": "absent",
                "parts": 0,
                "chars": 0,
            }
            continue

        out = EXTRACTED_DIR / f"{doc_id}.md"

        fingerprint = entry.get("sha256", "")[:16]

        earlier = previous.get(doc_id)

        if (
            not force
            and out.is_file()
            and earlier
            and earlier.get("fingerprint") == fingerprint
            and earlier.get("status") == "ok"
        ):
            records[doc_id] = earlier
            continue

        parts = _extract(path)

        if not parts:
            records[doc_id] = {
                "file": file_name,
                "status": "empty",
                "parts": 0,
                "chars": 0,
                "fingerprint": fingerprint,
            }
            continue

        body = [_header(doc_id, entry, path, when)]

        for label, text in parts:
            marker = f"page {label}" if label.isdigit() else (label or "body")
            body.append(f"<!-- {marker} -->\n\n{text}\n")

        out.write_text("\n".join(body), encoding="utf-8")

        records[doc_id] = {
            "file": file_name,
            "status": "ok",
            "parts": len(parts),
            "chars": sum(len(t) for _, t in parts),
            "fingerprint": fingerprint,
        }

    STAMP_FILE.write_text(
        json.dumps({"schema": EXTRACT_SCHEMA,
                    "at": when,
                    "documents": records}, indent=1),
        encoding="utf-8",
    )

    _write_index(manifest, records, when)

    return records


def _write_index(manifest: dict, records: dict, when: str) -> None:
    """A human-readable contents page for the folder."""
    ok = [d for d, r in records.items() if r["status"] == "ok"]
    bad = [d for d, r in records.items() if r["status"] != "ok"]

    lines = [
        "# Extracted sources",
        "",
        "Plain text for every document in `_sources/manifest.json`, one file",
        "per source, each carrying its citation. Generated by",
        "`config/extract_sources.py`; do not edit by hand.",
        "",
        f"Generated {when}. {len(ok)} of {len(records)} sources extracted.",
        "",
        "| Document | Parts | Characters | Source file |",
        "|---|---:|---:|---|",
    ]

    for doc_id in sorted(ok):
        record = records[doc_id]
        lines.append(
            f"| [{doc_id}]({doc_id}.md) | {record['parts']} "
            f"| {record['chars']:,} | `{record['file']}` |"
        )

    if bad:
        lines += ["", "## Not extracted", ""]
        for doc_id in sorted(bad):
            record = records[doc_id]
            reason = (
                "file not in the archive" if record["status"] == "absent"
                else "no text could be extracted"
            )
            lines.append(f"- **{doc_id}** — {reason} (`{record['file']}`)")

    lines += [
        "",
        "## Citations",
        "",
    ]

    for doc_id in sorted(records):
        citation = manifest.get(doc_id, {}).get("citation")
        if citation:
            lines.append(f"- **{doc_id}** — {citation}")

    (EXTRACTED_DIR / "INDEX.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )


def text_of(doc_id: str) -> Optional[str]:
    """The extracted text of one document, header stripped."""
    path = EXTRACTED_DIR / f"{doc_id}.md"

    if not path.is_file():
        return None

    body = path.read_text(encoding="utf-8", errors="replace")

    # Everything after the citation block.
    parts = body.split("\n<!-- ", 1)

    return ("<!-- " + parts[1]) if len(parts) == 2 else body


if __name__ == "__main__":
    force = "--force" in sys.argv

    records = extract_all(force=force)

    ok = sum(1 for r in records.values() if r["status"] == "ok")

    for doc_id in sorted(records):
        record = records[doc_id]
        flag = "" if record["status"] == "ok" else f"  <- {record['status'].upper()}"
        print(f"{doc_id:<28}{record['parts']:>5} parts "
              f"{record['chars']:>9,} chars{flag}")

    print()
    print(f"{ok} of {len(records)} sources extracted "
          f"into {EXTRACTED_DIR.name}/")

    missing = [d for d, r in records.items() if r["status"] != "ok"]

    if missing:
        print("NOT EXTRACTED: " + ", ".join(sorted(missing)))
