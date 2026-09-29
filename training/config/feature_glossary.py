"""
feature_glossary.py
-------------------
Flow feature -> plain English. One source of truth for every consumer.

WHY THIS IS A DICT AND NOT JUST THE MARKDOWN FILE
knowledge/features/glossary.md is what the retrieval stage reads, but it
cannot be checked against the model. This can: `verify()` asserts that every
name here exists in artifacts/mc_<strategy>/features.pkl and that every
feature the model was trained on has a definition. A glossary that has
drifted from the model silently mislabels an attribution, which is worse
than no glossary -- the investigator has no way to tell.

The Markdown file is GENERATED from this dict (`--write-md`). Edit here, not
there, or the two will disagree.

DIRECTION CONVENTION
Forward (Fwd) is client -> server, the direction that opened the connection.
Backward (Bwd) is server -> client. Reversing this inverts the meaning of
about half these definitions, so it is stated in the generated file too.

UNITS
Times are microseconds. Lengths are bytes. `Flow Duration` at 4,200,000
means 4.2 seconds.

Usage:
  python config/feature_glossary.py            # coverage report
  python config/feature_glossary.py --write-md # regenerate the Markdown
"""
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
GLOSSARY_MD = PROJECT / "knowledge" / "features" / "glossary.md"

# Grouped for the generated Markdown; flattened by FEATURE_PLAIN below.
GROUPS = {
    "Identity": {
        "Dst Port":
            "destination port -- effectively which service was contacted "
            "(22 SSH, 80 HTTP, 443 HTTPS, 53 DNS)",
        "Protocol":
            "transport protocol number (6 TCP, 17 UDP, 1 ICMP)",
    },
    "Duration and rate": {
        "Flow Duration":
            "how long the conversation lasted",
        "Flow Bytes/s":
            "throughput -- bytes per second across the whole conversation",
        "Flow Packets/s":
            "packets per second across the whole conversation",
        "Down/Up Ratio":
            "downloaded bytes over uploaded bytes -- high means the server "
            "sent far more than it received, low is what exfiltration looks "
            "like",
    },
    "Volume": {
        "Total Fwd Packet":
            "number of packets the client sent",
        "Total Bwd packets":
            "number of packets the server sent",
        "Total Length of Fwd Packet":
            "total bytes the client sent",
        "Total Length of Bwd Packet":
            "total bytes the server sent",
        "Subflow Fwd Packets":
            "average packets per outbound burst",
        "Subflow Bwd Packets":
            "average packets per inbound burst",
        "Subflow Fwd Bytes":
            "average bytes per outbound burst -- the client's typical burst "
            "size",
        "Subflow Bwd Bytes":
            "average bytes per inbound burst",
    },
    "Packet size": {
        "Average Packet Size":
            "mean size of every packet in the conversation",
        "Packet Length Mean":
            "average packet size in either direction (computed slightly "
            "differently from Average Packet Size, which is why both exist)",
        "Packet Length Min":
            "smallest packet in either direction",
        "Packet Length Max":
            "largest packet in either direction",
        "Packet Length Std":
            "how much packet sizes varied -- low means uniform, "
            "machine-generated traffic",
        "Packet Length Variance":
            "spread of packet sizes across the connection",
        "Fwd Packet Length Min":
            "smallest outbound packet",
        "Fwd Packet Length Max":
            "largest outbound packet",
        "Fwd Packet Length Mean":
            "average outbound packet size",
        "Fwd Packet Length Std":
            "how much outbound packet sizes varied",
        "Bwd Packet Length Min":
            "smallest inbound packet",
        "Bwd Packet Length Max":
            "largest inbound packet -- a large value means the server "
            "returned something substantial",
        "Bwd Packet Length Mean":
            "average inbound packet size",
        "Bwd Packet Length Std":
            "how much inbound packet sizes varied",
    },
    "Timing between packets": {
        "Flow IAT Mean":
            "average gap between packets in either direction",
        "Flow IAT Std":
            "how irregular the packet gaps were",
        "Flow IAT Max":
            "longest gap between any two packets -- a large value means the "
            "connection sat idle, characteristic of one held open "
            "deliberately",
        "Flow IAT Min":
            "shortest gap between any two packets",
        "Fwd IAT Total":
            "total time spanned by the client's packets",
        "Fwd IAT Mean":
            "average gap between outbound packets",
        "Fwd IAT Std":
            "how irregular the gaps between outbound packets were",
        "Fwd IAT Max":
            "longest pause between outbound packets",
        "Fwd IAT Min":
            "shortest gap between outbound packets -- near zero means "
            "packets sent back to back, typically automated",
        "Bwd IAT Total":
            "total idle time in the inbound direction",
        "Bwd IAT Mean":
            "average gap between inbound packets",
        "Bwd IAT Std":
            "how irregular the gaps between inbound packets were -- very low "
            "is a hallmark of beaconing, a machine answering on a schedule",
        "Bwd IAT Max":
            "longest pause between inbound packets",
        "Bwd IAT Min":
            "shortest gap between inbound packets",
    },
    "Active and idle periods": {
        "Active Mean":
            "average length of a continuous burst of transmission",
        "Active Std":
            "how much burst lengths varied",
        "Active Max":
            "longest continuous burst of transmission",
        "Active Min":
            "shortest burst of transmission",
        "Idle Mean":
            "average length of a quiet period",
        "Idle Std":
            "how much idle period lengths varied",
        "Idle Max":
            "longest period the connection sat idle",
        "Idle Min":
            "shortest idle period",
    },
    "TCP flags": {
        "SYN Flag Count":
            "connection-open requests -- many with few completions indicates "
            "scanning or SYN flooding",
        "FIN Flag Count":
            "orderly connection closes",
        "RST Flag Count":
            "abrupt resets -- high counts mean connections refused or "
            "dropped, typical of scanning a closed port",
        "ACK Flag Count":
            "acknowledgements",
        "PSH Flag Count":
            "pushes requesting immediate delivery rather than buffering",
        "URG Flag Count":
            "urgent-data markers -- rare in normal traffic",
        "CWR Flag Count":
            "congestion window reduced -- the sender slowing down after "
            "congestion (spelled CWE in some source files; folded to CWR "
            "here)",
        "ECE Flag Count":
            "network congestion notifications",
        "Fwd PSH Flags":
            "client pushes requesting immediate delivery",
        "Bwd PSH Flags":
            "server pushes requesting immediate delivery",
        "Fwd URG Flags":
            "urgent markers set by the client",
        "Bwd URG Flags":
            "urgent markers set by the server",
    },
    "Headers and windows": {
        "Fwd Header Length":
            "total header bytes in outbound packets -- large relative to "
            "payload suggests many small packets",
        "Bwd Header Length":
            "total header bytes in inbound packets",
        "Fwd Segment Size Avg":
            "average outbound payload segment size",
        "Bwd Segment Size Avg":
            "average inbound payload segment size",
        "FWD Init Win Bytes":
            "TCP receive window the client advertised at connection open -- "
            "partly an operating-system fingerprint",
        "Bwd Init Win Bytes":
            "TCP receive window the server advertised at connection open",
        # Fwd Act Data Pkts and Fwd Seg Size Min are CICFlowMeter features
        # that did NOT survive the three-dataset intersection in phase 04.
        # Defining them here would make verify() report an extra and would
        # never be shown, so they are deliberately absent.
    },
    "Bulk transfer": {
        # Zero for flows with no sustained transfer, which makes a non-zero
        # value informative on its own.
        "Fwd Bulk Rate Avg":
            "how fast the client moved data during sustained bursts",
        "Bwd Bulk Rate Avg":
            "how fast the server moved data during sustained bursts",
        "Fwd Bytes/Bulk Avg":
            "average bytes per outbound burst",
        "Bwd Bytes/Bulk Avg":
            "average bytes per inbound burst",
        "Fwd Packet/Bulk Avg":
            "average packets per outbound burst",
        "Bwd Packet/Bulk Avg":
            "average packets per inbound burst",
    },
}

FEATURE_PLAIN = {name: text
                 for group in GROUPS.values()
                 for name, text in group.items()}

# Features that carry a warning as well as a definition. The interface should
# show these alongside the attribution, not bury them.
FEATURE_NOTES = {
    "Dst Port":
        "Often the strongest single signal, and worth suspicion for that "
        "reason: a model leaning on port number may have learned the lab's "
        "service layout rather than the attack.",
    "FWD Init Win Bytes":
        "Partly an OS fingerprint. Phase 11 ablated it to test whether the "
        "model was recognising the capture host; removing it changed macro "
        "F1 by 0.0002, so it is not carrying the result.",
    "Bwd Init Win Bytes":
        "See FWD Init Win Bytes.",
    "Bwd PSH Flags":
        "Constant zero throughout the binary training data but non-zero in "
        "TRUSTLab, so it enters those models unscaled. See "
        "knowledge/datasets/scope.md.",
    "Bwd URG Flags":
        "Constant zero in the binary training data. See Bwd PSH Flags.",
    "Fwd Bulk Rate Avg":
        "Constant zero in the binary training data. See Bwd PSH Flags.",
    "Fwd Bytes/Bulk Avg":
        "Constant zero in the binary training data. See Bwd PSH Flags.",
    "Fwd Packet/Bulk Avg":
        "Constant zero in the binary training data. See Bwd PSH Flags.",
    "Flow Duration":
        "Capped by the extractor's flow timeout. Training data stops at "
        "120 s; TRUSTLab runs to 15,717 s. A mismatch here invalidates every "
        "timing feature -- see deploy/README.md section 3.",
}


def describe(feature):
    """Plain-English text for one feature, or the name itself when unknown.

    Returning the raw name is deliberate: an undefined feature should read as
    itself, never as a plausible-sounding guess.
    """
    return FEATURE_PLAIN.get(feature, feature)


def verify(strategy="random"):
    """Check this glossary against the features the model was trained on.

    Returns (missing, extra): features the model uses that have no
    definition, and definitions for features the model does not use.
    """
    import joblib
    feats = list(joblib.load(
        PROJECT / "artifacts" / f"mc_{strategy}" / "features.pkl"))
    missing = [f for f in feats if f not in FEATURE_PLAIN]
    extra = [f for f in FEATURE_PLAIN if f not in feats]
    return missing, extra, feats


def to_markdown(strategy="random"):
    """Render the Markdown the retrieval stage reads."""
    missing, extra, feats = verify(strategy)
    order = {f: i for i, f in enumerate(feats)}
    lines = [
        "# Flow feature glossary",
        "",
        "Plain-English definitions for every feature "
        f"`artifacts/mc_{strategy}/XGBoost.pkl` was trained on.",
        "",
        "**Generated from `config/feature_glossary.py` — edit there, not "
        "here.** That file is checked against `features.pkl`, so a "
        "definition cannot drift away from the model without the check "
        "failing.",
        "",
        "**Direction.** *Forward* (Fwd) is client → server, the direction "
        "that opened the connection. *Backward* (Bwd) is server → client. "
        "Reversing this inverts about half these definitions.",
        "",
        "**Units.** Times are microseconds, lengths are bytes. "
        "`Flow Duration` of 4,200,000 is 4.2 seconds.",
        "",
    ]
    for group, entries in GROUPS.items():
        present = {k: v for k, v in entries.items() if k in order}
        if not present:
            continue
        lines += [f"## {group}", "", "| Feature | Plain English |",
                  "|---|---|"]
        for name in sorted(present, key=lambda n: order[n]):
            lines.append(f"| `{name}` | {present[name]} |")
        lines.append("")

    lines += ["## Features that need a warning shown with them", ""]
    for name, note in FEATURE_NOTES.items():
        if name in order:
            lines.append(f"- **`{name}`** — {note}")
    lines += [
        "",
        "---",
        "",
        "## Reading these honestly",
        "",
        "A high attribution means the model weighted the feature, not that "
        "the feature caused the behaviour. Several of these move together — "
        "`Packet Length Mean`, `Max` and `Std` are not independent — so "
        "credit is shared between them in ways that look arbitrary. See "
        "`interpretability/caveats.md`.",
        "",
        f"Covers {len(feats) - len(missing)} of {len(feats)} features.",
        "",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    missing, extra, feats = verify()
    print(f"Covered: {len(feats) - len(missing)} of {len(feats)}")
    if missing:
        print("Still missing:", missing)
    if extra:
        print("Defined but not used by the model:", extra)

    if "--write-md" in sys.argv:
        if missing:
            print("\nRefusing to write: define the missing features first. "
                  "A partial glossary silently drops the explanation for "
                  "whichever feature is absent.")
            sys.exit(1)
        GLOSSARY_MD.parent.mkdir(parents=True, exist_ok=True)
        GLOSSARY_MD.write_text(to_markdown(), encoding="utf-8")
        print(f"\nWrote {GLOSSARY_MD.relative_to(PROJECT)}")
    elif not missing and not extra:
        print("Glossary matches the model exactly.")
