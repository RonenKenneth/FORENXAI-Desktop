"""
build_playbooks.py
------------------
Generate knowledge/incident_response/*.md from the real publications.

WHY
The playbooks these files replace carried a PLACEHOLDER banner: prose written
to exercise the citation path, not sourced from any standard. Retrieval then
presented that prose with the confidence of a citation, which is worse than
having no playbook at all.

Writing replacements by hand would reintroduce the same problem -- text a
reader cannot trace. So the playbooks are compiled instead, from documents
already in _sources/:

  NIST SP 800-61r3   the CSF 2.0 Community Profile for incident response.
                     36 subcategories across Detect, Respond and Recover,
                     each with numbered recommendations.
  NIST SP 800-86     the forensic process: data collection, examination,
                     analysis, reporting.
  NIST SP 800-53r5   the control statements for the classes each playbook
                     serves, from the CPRT catalogue.

Every line carries the identifier and page it came from, so an analyst can
check it against the publication.

WHAT THIS DOES NOT DO
It does not make the guidance attack-specific beyond the control set. NIST's
incident response lifecycle is deliberately generic; what differs between a
brute-force and a denial-of-service incident is the controls that apply and
the evidence you collect, not the shape of the response. Presenting the same
lifecycle under eleven headings and calling it eleven playbooks would be
dressing one document up as eleven. The class-specific part is section 4.1.

An organisation's own runbook still belongs here. This gets the file to
"sourced and checkable", not to "complete".

Run:  python rag/config/build_playbooks.py [--check]
      --check reports what would change without writing.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCES = HERE.parent / "_sources"
OUT_DIR = HERE.parent / "knowledge" / "incident_response"

sys.path.insert(0, str(HERE))

import source_index as si                           # noqa: E402

PROFILE_PDF = SOURCES / "NIST.SP.800-61r3.pdf"
FORENSIC_PDF = SOURCES / "NIST.SP.800-86.pdf"

# Longest quoted item. Past this a recommendation stops being one sentence
# an analyst can act on and starts being a paragraph to read.
ITEM_CHARS = 420

_SUBCAT = re.compile(r"\b((?:GV|ID|PR|DE|RS|RC)\.[A-Z]{2}-\d\d)\b")

_ITEM = re.compile(r"\b([RNC]\d+):\s*(.+?)(?=\s+[RNC]\d+:|$)")

# A CSF function header starting the next table row.
_BLEED = re.compile(
    r"\s(?:GV|ID|PR|DE|RS|RC)\s*\((?:Govern|Identify|Protect|Detect|Respond|Recover)\)"
)

# Which CSF functions belong under which heading, and how many items each
# heading gets.
#
# The cap is not cosmetic. Retrieval truncates a document head-first at a
# fixed budget, so an uncapped file is mostly discarded before the model
# sees it -- and the part discarded is whatever sits at the end. That is
# also why the controls come first: they are the only part that differs
# between playbooks, so they are the part that must survive truncation.
SECTIONS = [
    ("4.2 Detection and analysis", ("DE.AE", "RS.AN"), 4),
    ("4.3 Containment", ("RS.MI", "RS.MA"), 4),
    ("4.4 Eradication and recovery", ("RC.RP", "RC.CO"), 4),
]

# Longest control statement quoted in section 4.1.
CONTROL_CHARS = 300

# file stem -> (title, the classes it serves)
PLAYBOOKS = {
    "command_and_control": ("Command and control", ["C2Beaconing"]),
    "credential_attack": ("Credential attack", ["Bruteforce"]),
    "crypto_weakness": ("Cryptographic weakness", ["TLSSSL"]),
    "data_exfiltration": ("Data exfiltration", ["Exfiltration"]),
    "denial_of_service": ("Denial of service", ["DoS", "DDoS", "Slowloris"]),
    "dns_abuse": ("DNS abuse", ["DNS"]),
    "evasion": ("Evasion", ["Evasion"]),
    "exploitation": ("Exploitation", ["Exploitation", "BufferOverflow"]),
    "mitm": ("Man in the middle", ["MITM"]),
    "reconnaissance": ("Reconnaissance", ["PortScan"]),
    "web_application": ("Web and API attack", ["WebBased", "API"]),
}


# ------------------------------------------------------------------
# extraction
# ------------------------------------------------------------------

def _trim(text: str, limit: int) -> str:
    """Shorten to a sentence boundary, or failing that a word boundary.

    A quotation cut mid-word ("...organizational netwo") reads as a
    transcription error and undermines the citation beside it.
    """
    text = " ".join((text or "").split())

    if len(text) <= limit:
        return text

    window = text[:limit]

    cut = window.rfind(". ")

    if cut > limit // 3:
        return window[:cut + 1]

    cut = window.rfind(" ")

    return (window[:cut] if cut > 0 else window).rstrip(" ,;:") + " ..."


def _pages(pdf_path: Path):
    import pypdf

    reader = pypdf.PdfReader(str(pdf_path))

    return [
        (index + 1, " ".join((page.extract_text() or "").split()))
        for index, page in enumerate(reader.pages)
    ]


def _flatten(pages):
    """One string, plus a way to get back to a page number."""
    whole = ""
    starts = []

    for number, text in pages:
        starts.append((len(whole), number))
        whole += text + " "

    def page_at(position: int) -> int:
        found = 1
        for start, number in starts:
            if start <= position:
                found = number
        return found

    return whole, page_at


def csf_profile():
    """CSF subcategory -> its numbered recommendations, with pages."""
    whole, page_at = _flatten(_pages(PROFILE_PDF))

    hits = list(_SUBCAT.finditer(whole))

    blocks = {}
    seen = set()

    for position, match in enumerate(hits):

        code = match.group(1)

        if code in seen:
            continue

        seen.add(code)

        start = match.start()
        end = len(whole)

        for later in hits[position + 1:]:
            if later.group(1) != code:
                end = later.start()
                break

        items = []

        for tag, text in _ITEM.findall(whole[start:end]):

            text = text.strip()

            # The profile is a table. Extracted linearly, the next row's
            # function header runs on to the end of this cell --
            # "...eradication measures. RC (Recover) Assets and operations
            # affected by a cybersecurity incident are restored High".
            # Cut at that header rather than quote another row's text.
            bleed = _BLEED.search(text)

            if bleed and bleed.start() > 40:
                text = text[:bleed.start()].strip()

            items.append((tag, _trim(text, ITEM_CHARS)))

        if items:
            blocks[code] = {
                "page": page_at(start),
                "items": items,
            }

    return blocks


def forensic_recommendations():
    """NIST SP 800-86 section 3.5, the forensic process recommendations."""
    whole, page_at = _flatten(_pages(FORENSIC_PDF))

    # 3.1.3 is the incident-response-specific part of the forensic
    # process; 3.5 is a summary aimed at programme design and yields
    # advice about surveying physical areas, which is not what a network
    # forensic case needs.
    # rfind, not find: the first occurrence of any heading is its table of
    # contents entry, whose "body" is a run of dots and a page number. The
    # body of the section is the last occurrence.
    start = -1

    for heading in (
        "3.1.3 Incident Response Considerations",
        "3.5 Re commendations",
        "3.5 Recommendations",
    ):
        start = whole.rfind(heading)
        if start >= 0:
            break

    if start < 0:
        return []

    body = whole[start:start + 4200]
    page = page_at(start)

    items = []

    # The section is a run of sentences beginning with an imperative.
    for sentence in re.split(r"(?<=[.])\s+", body):

        sentence = sentence.strip()

        if not (40 <= len(sentence) <= ITEM_CHARS):
            continue

        first = sentence.split(" ", 1)[0].rstrip(",").lower()

        if first in {
            "organizations", "analysts", "perform", "acquire", "collect",
            "use", "document", "preserve", "verify", "consider", "review",
            "establish", "maintain", "keep", "record", "capture", "identify",
            "if", "when", "the", "data", "before", "after", "during",
        }:
            items.append((sentence, page))

    return items[:6]


# ------------------------------------------------------------------
# rendering
# ------------------------------------------------------------------

def _controls_for(classes):
    """The 800-53 control statements for the classes a playbook serves."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "forenxai_km", HERE / "knowledge_map.py"
    )
    km = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(km)

    wanted = []

    for cls in classes:
        entry = km.KNOWLEDGE_MAP.get(cls, {})
        for control_id in entry.get("controls", []):
            if control_id not in wanted:
                wanted.append(control_id)

    return si.controls_for(wanted)


def render(stem: str, title: str, classes, profile, forensic) -> str:
    lines = [
        f"# {title} — response",
        "",
        "> Compiled from the publications in `_sources/` by",
        "> `rag/config/build_playbooks.py`. Every line carries the",
        "> identifier and page it came from. Regenerate rather than edit:",
        "> a hand edit cannot be traced to a source, which is the failure",
        "> this file exists to avoid.",
        ">",
        "> Sections 4.2 to 4.5 are NIST's generic incident response",
        "> lifecycle and read the same in every playbook, because that is",
        "> what the publication says. Section 4.1 is what differs by",
        "> incident type. Your organisation's own runbook still belongs",
        "> here and is not replaced by this.",
        "",
    ]

    # ---- 4.1, the class-specific part, first so it survives truncation
    lines.append("## 4.1 Controls that apply to this incident type")
    lines.append("")
    lines.append(f"Serving: {', '.join(classes)}.")
    lines.append("")

    controls = _controls_for(classes)

    if controls:
        for control in controls:

            # label is "NIST SP 800-53r5 SC-5 DENIAL-OF-SERVICE PROTECTION";
            # the identifier is printed separately, so take the name only.
            name = control["label"].split(control["ref"], 1)[-1].strip()

            lines.append(
                f"- **{control['ref']} {name}** — "
                f"{_trim(control['text'], CONTROL_CHARS)} "
                f"(NIST SP 800-53r5, {control['ref']})"
            )
    else:
        lines.append(
            "- The control catalogue was not readable when this file was "
            "built."
        )

    lines.append("")

    # ---- the generic lifecycle
    for heading, prefixes, cap in SECTIONS:

        lines.append(f"## {heading}")
        lines.append("")

        written = 0

        # Iterate the prefixes in the order SECTIONS declares them, not in
        # alphabetical order of the codes. RS.MI (mitigation) is what
        # containment means; sorting alphabetically put RS.MA (management)
        # first and filled the section with reporting steps instead.
        ordered = [
            code
            for prefix in prefixes
            for code in sorted(profile)
            if code.startswith(prefix)
        ]

        for code in ordered:

            if written >= cap:
                break

            block = profile[code]

            for tag, text in block["items"]:

                if written >= cap:
                    break

                # Recommendations only. Notes and considerations are
                # context for a reader, not instructions for a responder.
                if tag[0] != "R":
                    continue

                lines.append(
                    f"- {text} "
                    f"(NIST SP 800-61r3, {code} {tag}, p. {block['page']})"
                )
                written += 1

        if written == 0:
            lines.append(
                "- No recommendation in the CSF 2.0 Community Profile maps "
                "to this phase. See the publication directly."
            )

        lines.append("")

    # ---- evidence handling
    lines.append("## 4.5 Evidence handling")
    lines.append("")

    if forensic:
        for sentence, page in forensic:
            lines.append(
                f"- {sentence} (NIST SP 800-86, Sec. 3.1.3, p. {page})"
            )
    else:
        lines.append(
            "- NIST SP 800-86 was not readable when this file was built."
        )

    lines.append("")

    return "\n".join(lines)


# ------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="report what would change without writing",
    )
    args = parser.parse_args()

    if not si.available():
        print("Source archive not present. Copy it to rag/_sources/ first.")
        return 1

    print("Reading NIST SP 800-61r3 ...")
    profile = csf_profile()
    print(f"  {len(profile)} CSF subcategories with recommendations")

    print("Reading NIST SP 800-86 ...")
    forensic = forensic_recommendations()
    print(f"  {len(forensic)} forensic process recommendations")

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    changed = 0

    for stem, (title, classes) in PLAYBOOKS.items():

        text = render(stem, title, classes, profile, forensic)
        path = OUT_DIR / f"{stem}.md"

        before = (
            path.read_text(encoding="utf-8") if path.is_file() else ""
        )

        if before == text:
            continue

        changed += 1

        if args.check:
            print(f"  would rewrite {path.name} "
                  f"({len(before)} -> {len(text)} chars)")
        else:
            path.write_text(text, encoding="utf-8", newline="\n")
            print(f"  wrote {path.name} ({len(text)} chars)")

    print(f"\n{changed}/{len(PLAYBOOKS)} playbooks "
          f"{'would change' if args.check else 'written'}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
