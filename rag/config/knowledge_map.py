"""
knowledge_map.py
----------------
Class -> documents. This IS the retrieval step.

WHY THERE IS NO VECTOR STORE
Standard RAG embeds document fragments and searches by similarity because it
does not know in advance what it is looking for. Here we always do: the
classifier has just named exactly one of sixteen classes. Retrieval is a
dictionary lookup.

  vector search              this
  ----------------------    ----------------------
  approximate, can miss     exact by construction
  re-embed after an edit    nothing to rebuild
  cites a chunk id          cites a file and section
  returns the nearest       raises when a key is absent
  wrong chunk silently

The last row is the important one. A recommendation attached to the wrong
playbook section is worse than no recommendation, and a similarity search
has no way to tell you it guessed.

You would need embeddings if the corpus grew to hundreds of pages of
unstructured prose, or if queries were free text rather than a class label.
Neither is true here, and building the simple version is also the more
defensible choice at a defence.

MITRE MAPPINGS NEED YOUR REVIEW
The technique IDs below are a starting point, not an authority. Mapping an
attack class to ATT&CK is a domain judgement -- TRUSTLab's class definitions
and ATT&CK's technique boundaries were not drawn to line up. Read the class
descriptions in the dataset paper against the technique pages and correct
these before anything ships. They are wrong until a human has checked them.
"""
from pathlib import Path

KNOWLEDGE_DIR = Path(__file__).resolve().parent.parent / "knowledge"

# Read by every panel regardless of class. Stable across requests, so it sits
# in the cached prompt prefix; see scripts/14_rag_report.py.
ALWAYS_LOAD = [
    "interpretability/caveats.md",     # how far a SHAP attribution can be pushed
    "features/glossary.md",            # feature name -> plain English
    "datasets/scope.md",               # the claim boundary
]

# One entry per class. `attack` and `response` are file paths under
# knowledge/; `mitre` and `controls` are identifiers quoted in the output.
KNOWLEDGE_MAP = {
    "API": {
        "attack": "detection/attack_api.md",
        "response": "incident_response/web_application.md",
        "mitre": ["T1190"],
        "controls": ["SI-4", "SC-7", "SI-10"],
        "summary": "Abuse of REST/GraphQL/SOAP endpoints -- mass assignment, "
                   "injection, XXE.",
    },
    "Benign": {
        "attack": None,
        "response": None,
        "mitre": [],
        "controls": [],
        "summary": "Normal traffic. No action.",
    },
    "Bruteforce": {
        "attack": "detection/attack_bruteforce.md",
        "response": "incident_response/credential_attack.md",
        "mitre": ["T1110"],
        "controls": ["AC-7", "IA-5", "SI-4"],
        "summary": "Repeated authentication attempts against a service.",
    },
    "BufferOverflow": {
        "attack": "detection/attack_bufferoverflow.md",
        "response": "incident_response/exploitation.md",
        "mitre": ["T1203", "T1068"],
        "controls": ["SI-2", "SI-16", "RA-5"],
        "summary": "Memory-corruption exploitation against a listening "
                   "service.",
    },
    "C2Beaconing": {
        "attack": "detection/attack_c2.md",
        "response": "incident_response/command_and_control.md",
        "mitre": ["T1071", "T1571", "T1568.002"],
        "controls": ["SI-4", "SC-7", "AC-4"],
        "summary": "Periodic callbacks to a controller -- HTTP/S, DNS, IRC, "
                   "MQTT, WebSocket.",
    },
    "DDoS": {
        "attack": "detection/attack_ddos.md",
        "response": "incident_response/denial_of_service.md",
        "mitre": ["T1498"],
        "controls": ["SC-5", "SC-7", "CP-2"],
        "summary": "High-rate distributed flooding from many sources.",
    },
    "DNS": {
        "attack": "detection/attack_dns.md",
        "response": "incident_response/dns_abuse.md",
        "mitre": ["T1071.004", "T1568"],
        "controls": ["SC-20", "SC-21", "SI-4"],
        "summary": "DNS protocol abuse -- tunnelling, amplification, "
                   "poisoning.",
    },
    "DoS": {
        "attack": "detection/attack_dos.md",
        "response": "incident_response/denial_of_service.md",
        "mitre": ["T1499"],
        "controls": ["SC-5", "SC-7"],
        "summary": "Single-source resource exhaustion at intermediate rate.",
        # See AMBIGUOUS_PAIRS below -- never present this alone at low margin.
    },
    "Evasion": {
        "attack": "detection/attack_evasion.md",
        "response": "incident_response/evasion.md",
        "mitre": ["T1205", "T1027"],
        "controls": ["SI-4", "SC-7"],
        "summary": "Detection avoidance -- fragment overlap, TTL manipulation.",
    },
    "Exfiltration": {
        "attack": "detection/attack_exfiltration.md",
        "response": "incident_response/data_exfiltration.md",
        "mitre": ["T1041", "T1048"],
        "controls": ["AC-4", "SC-7", "SI-4"],
        "summary": "Data leaving over DNS, ICMP, SMTP or chunked HTTP.",
    },
    "Exploitation": {
        "attack": "detection/attack_exploitation.md",
        "response": "incident_response/exploitation.md",
        "mitre": ["T1190"],
        "controls": ["SI-2", "RA-5", "SI-4"],
        "summary": "Exploitation of a public-facing application.",
    },
    "MITM": {
        "attack": "detection/attack_mitm.md",
        "response": "incident_response/mitm.md",
        "mitre": ["T1557", "T1557.001"],
        "controls": ["SC-8", "SC-23", "SI-4"],
        "summary": "Adversary in the middle -- ARP/LLMNR poisoning, TCP "
                   "hijack, SSL stripping.",
    },
    "PortScan": {
        "attack": "detection/attack_portscan.md",
        "response": "incident_response/reconnaissance.md",
        "mitre": ["T1046"],
        "controls": ["SI-4", "SC-7"],
        "summary": "Network service discovery -- reconnaissance, usually a "
                   "precursor.",
    },
    "Slowloris": {
        "attack": "detection/attack_slowloris.md",
        "response": "incident_response/denial_of_service.md",
        "mitre": ["T1499.002"],
        "controls": ["SC-5", "SC-7"],
        "summary": "Low-and-slow connection exhaustion -- many half-open "
                   "requests held for a long time.",
        # See AMBIGUOUS_PAIRS below.
    },
    "TLSSSL": {
        "attack": "detection/attack_tls.md",
        "response": "incident_response/crypto_weakness.md",
        "mitre": ["T1573"],
        "controls": ["SC-8", "SC-13", "SI-2"],
        "summary": "TLS/SSL weakness or abuse -- Heartbleed, POODLE, BEAST, "
                   "certificate anomalies.",
    },
    "WebBased": {
        "attack": "detection/attack_webbased.md",
        "response": "incident_response/web_application.md",
        "mitre": ["T1190", "T1059.007"],
        "controls": ["SI-10", "SC-7", "SI-4"],
        "summary": "Web application attack -- injection, XSS, traversal.",
    },
}

# Pairs this model provably cannot separate, with the evidence.
#
# SHAP measured the per-feature importance correlation between Slowloris and
# DoS at 0.9159, sharing seven of their top ten features
# (results/shap/pair_slowloris_dos_random.json). Both classes are decided by
# the same evidence, so a confident single answer between them misrepresents
# what the model knows. When the runner-up is one of these and its
# probability clears `margin`, both playbooks are retrieved and the report
# says the pair is indistinguishable.
AMBIGUOUS_PAIRS = [
    {
        "classes": ("Slowloris", "DoS"),
        "margin": 0.25,
        "evidence": "results/shap/pair_slowloris_dos_random.json",
        "note": ("Slow-rate denial-of-service. This model cannot reliably "
                 "separate Slowloris from DoS: per-feature SHAP importance "
                 "correlates at 0.92 and seven of the top ten features are "
                 "shared. Treat as one finding with two candidate "
                 "sub-types."),
        # Section titles doc_tree.search() must return for this pair whether
        # or not the model selects them. Without the section that compares
        # the sub-types, the report presents one playbook for a pair the
        # evidence says is inseparable.
        "sections": ["distinguishing slow-rate"],
    },
    {
        "classes": ("Exploitation", "BufferOverflow"),
        "margin": 0.30,
        "evidence": "results/mc_random/XGBoost_confusion.csv",
        "note": ("Exploitation is confused with BufferOverflow in 8.7% of "
                 "cases. Both are exploitation of a listening service; the "
                 "response overlaps substantially."),
        "sections": ["distinguishing a successful exploit"],
    },
]

# Classes whose test F1 is low enough that confidence should be shown with a
# caveat. Figures from results/mc_per_class_random.csv, XGBoost, random split.
LOW_CONFIDENCE_CLASSES = {
    "DoS": 0.6714,
    "Exploitation": 0.7838,
    "Slowloris": 0.7639,
    "BufferOverflow": 0.8017,
}


def load(rel_path):
    """Read one knowledge file, or None when it is absent.

    Absence is reported by the caller and never filled in by the model. A
    recommendation with no source is the failure this whole design exists to
    prevent.
    """
    if not rel_path:
        return None
    p = KNOWLEDGE_DIR / rel_path
    if not p.is_file():
        return None
    return p.read_text(encoding="utf-8", errors="replace")


def context_for(cls):
    """Everything the recommendation stage should read for one class."""
    entry = KNOWLEDGE_MAP.get(cls)
    if entry is None:
        raise KeyError(
            f"{cls!r} has no entry in KNOWLEDGE_MAP. Add one rather than "
            f"falling back to a similar class -- a recommendation attached "
            f"to the wrong playbook is worse than none.")
    docs, missing = {}, []
    for role in ("attack", "response"):
        rel = entry.get(role)
        if not rel:
            continue
        text = load(rel)
        if text:
            docs[role] = {"path": rel, "text": text}
        else:
            missing.append(rel)
    return {"class": cls, "summary": entry["summary"],
            "mitre": entry["mitre"], "controls": entry["controls"],
            "documents": docs, "missing": missing}


def audit():
    """Which knowledge files exist. Run before trusting any recommendation."""
    rows = []
    for cls, e in KNOWLEDGE_MAP.items():
        for role in ("attack", "response"):
            rel = e.get(role)
            if rel:
                rows.append((cls, role, rel,
                             (KNOWLEDGE_DIR / rel).is_file()))
    for rel in ALWAYS_LOAD:
        rows.append(("*", "always", rel, (KNOWLEDGE_DIR / rel).is_file()))
    return rows


if __name__ == "__main__":
    rows = audit()
    have = sum(1 for *_, ok in rows if ok)
    print(f"{have}/{len(rows)} knowledge files present\n")
    for cls, role, rel, ok in rows:
        print(f"  {'OK ' if ok else '-- '}{cls:<16}{role:<9}{rel}")
    if have < len(rows):
        print("\nMissing files are reported in the output, never invented. "
              "See knowledge/INDEX.md for where to get them.")
