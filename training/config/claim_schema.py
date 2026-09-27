"""
claim_schema.py
---------------
Makes the recommendations panel verifiable instead of merely readable.

THE PROBLEM WITH PROSE
A paragraph cannot be checked. Every sentence in it looks equally sourced,
and an invented recommendation reads exactly like one lifted from a playbook.
The first local run made the point: qwen2.5:3b, given no documentation at
all, produced four confident actions and cited "(CAPTURE CONTEXT)" and
"(FINDING)" -- headings from the prompt, not documents.

THE FIX, IN TWO PARTS
1. Constrain the output to a schema where every action must carry a source
   path and a verbatim quote. There is no field for an unsourced action, so
   the model cannot smuggle one in as a sentence.
2. Check each quote actually appears in the document it names. That is an
   exact substring test after whitespace normalisation -- deterministic, no
   judge, no second model. A quote that is not in the document did not come
   from it.

Actions failing the check are SUPPRESSED, not flagged and shown. A reader who
sees a plausible action next to a small warning icon will act on the action.

WHAT THIS BUYS BEYOND HONESTY
Constraining a small model to a schema improves adherence: it cannot ramble
into invention when the structure has no field for it. The two failures the
eval found are now schema fields -- `confidence_assessment` and
`ambiguous_with` must be filled, and a field the model must fill is followed
far more reliably than an instruction it must remember.
"""
import re

# One object per statement. `source` and `quote` are required on every
# action, which is the whole point: the schema has no shape for an action
# without evidence.
RECOMMENDATION_SCHEMA = {
    "type": "object",
    "properties": {
        "what_was_found": {
            "type": "string",
            "description": "Two sentences, plain language, no jargon. "
                           "Include how many flows.",
        },
        "confidence_assessment": {
            "type": "string",
            "description": "How much to trust this, given the model's "
                           "confidence and this class's measured "
                           "reliability. Be direct about doubt.",
        },
        "ambiguous_with": {
            "type": ["string", "null"],
            "description": "The class this may actually be, when the model "
                           "could not separate them. null if unambiguous.",
        },
        "actions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "action": {"type": "string",
                               "description": "One step to take."},
                    "source": {"type": "string",
                               "description": "The document path this came "
                                              "from, exactly as given."},
                    "quote": {"type": "string",
                              "description": "The sentence from that "
                                             "document that prescribes it, "
                                             "copied verbatim."},
                },
                "required": ["action", "source", "quote"],
            },
        },
        "false_positive_conditions": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Concrete conditions an investigator can check.",
        },
        "not_covered": {
            "type": "array",
            "items": {"type": "string"},
            "description": "What the situation needs that the supplied "
                           "documentation does not address.",
        },
    },
    # `ambiguous_with` is required, not optional. Left optional, qwen2.5:3b
    # omitted it on a finding the knowledge map flags as inseparable from
    # DoS, so render() emitted null and the panel read as unambiguous while
    # the ambiguity note sat beside it. A field the model must fill is
    # followed far more reliably than an instruction it must remember.
    "required": ["what_was_found", "confidence_assessment", "ambiguous_with",
                 "actions", "false_positive_conditions", "not_covered"],
}


def _norm(text):
    """Collapse whitespace so a reflowed quote still matches.

    Models rewrap text. Comparing raw strings would reject a quote that is
    word-for-word correct but broken across different lines, which would
    suppress good actions and teach nobody anything.
    """
    return re.sub(r"\s+", " ", (text or "")).strip().lower()


# ==========================================================================
# Panel 2 -- the same idea applied to the explanation panel
# ==========================================================================
# Panel 3 is safe because the model cannot emit an action without a source
# and a quote, and the quote is checked. Panel 2 was free prose over the same
# kind of structured input, and it failed the same way every run: it called a
# feature marked "argues against" typical of the class, wrote "nearly
# undecided" on a 0.9998-versus-0.0001 row, quoted the other row's runner-up
# number, and reported a flow as having no features typical of its class
# while the field listing them sat in its input.
#
# Two rounds of prompt instructions did not hold at 3B. So the model no
# longer states any of it. Direction, raw value, caution, class fit and the
# undecided line are rendered from the detection dict by render_explanation()
# below; the model supplies only the plain-English reading of each feature,
# which is the one thing here it is actually good at. A fact it never emits
# is a fact it cannot invert.
EXPLANATION_SCHEMA = {
    "type": "object",
    "properties": {
        "decisions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "row": {"type": "integer",
                            "description": "The row number, copied exactly."},
                    "summary": {
                        "type": "string",
                        "description": "One sentence naming what was "
                                       "detected. No numbers.",
                    },
                    "readings": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "feature": {
                                    "type": "string",
                                    "description": "The feature name, copied "
                                                   "exactly from the input.",
                                },
                                "reading": {
                                    "type": "string",
                                    "description": "What this value means as "
                                                   "observable network "
                                                   "behaviour. Never say "
                                                   "whether it supports or "
                                                   "argues against the "
                                                   "class.",
                                },
                            },
                            "required": ["feature", "reading"],
                        },
                    },
                },
                "required": ["row", "summary", "readings"],
            },
        },
    },
    "required": ["decisions"],
}

# A reading is a description of behaviour, not a verdict. The verdict is the
# `direction` field, which the code writes. A reading that reaches for one
# anyway is dropped rather than shown next to a direction it contradicts.
VERDICT_LANGUAGE = re.compile(
    r"\b(support|supports|supporting|argues?|against|indicat\w*|"
    r"typical|atypical|unusual|consistent with|hallmark|characteristic|"
    r"suggest\w*|confirm\w*|proves?|evidence (?:of|for))\b", re.I)


# Times in the CICFlowMeter feature set are microseconds -- see the Units
# note in knowledge/features/glossary.md. Rendering the seconds alongside is
# the one genuinely useful thing the dropped prose was doing, and it is
# arithmetic, so it belongs here rather than in a prompt.
TIME_FEATURE = re.compile(r"\b(IAT|Duration|Active|Idle)\b")


def _value_text(feature, raw):
    if TIME_FEATURE.search(feature) and abs(raw) >= 1000:
        return f"{raw:,.0f} us ({raw / 1e6:,.3f} s)"
    return f"{raw:,}"


def render_explanation(payload, detections):
    """Merge the model's readings into the detection facts.

    Everything an investigator could act on wrongly -- direction, raw value,
    caution, whether the decision was close -- comes from `detections`. The
    model contributes prose and nothing else, and a reading is dropped when
    it names a feature that is not in that row or reaches for a verdict.
    """
    by_row = {int(d["row"]): d for d in detections}
    said = {int(x.get("row", -1)): x
            for x in (payload.get("decisions") or [])
            if isinstance(x, dict)}

    out, dropped = [], []
    for row, det in by_row.items():
        spoken = said.get(row, {})
        readings = {}
        for r in (spoken.get("readings") or []):
            name, text = (r.get("feature") or "").strip(), r.get("reading") or ""
            if not any(a["feature"] == name for a in det["attributions"]):
                dropped.append({"row": row, "feature": name,
                                "reason": "not an attribution of this row"})
            elif VERDICT_LANGUAGE.search(text):
                dropped.append({"row": row, "feature": name,
                                "reason": "reading states a verdict rather "
                                          "than an observation"})
            else:
                readings[name] = text

        # The summary is prose too, and it failed the same way the readings
        # did -- "unusually short gaps" for a 1.2-second minimum inter-arrival
        # time, on a row the model was not close on. Same filter, and a
        # rendered sentence when it does not pass, so the panel always has a
        # heading and never a wrong one.
        summary = (spoken.get("summary") or "").strip()
        if not summary or VERDICT_LANGUAGE.search(summary):
            if summary:
                dropped.append({"row": row, "feature": "(summary)",
                                "reason": "summary states a verdict rather "
                                          "than an observation"})
            summary = (f"{det['predicted']} at confidence "
                       f"{det['confidence']:.4f}; the next most likely class "
                       f"was {det['runner_up']} at "
                       f"{det['runner_up_confidence']:.4f}.")

        out.append({
            "row": row,
            "summary": summary,
            "predicted": det["predicted"],
            "confidence": det["confidence"],
            "runner_up": det["runner_up"],
            "runner_up_confidence": det["runner_up_confidence"],
            # Written here, never by the model.
            "nearly_undecided": bool(det.get("nearly_undecided")),
            "class_fit": (
                "Driven by " + ", ".join(det["features_typical_for_class"])
                + ", which the model leans on for this class generally."
                if det.get("features_typical_for_class")
                else "None of this flow's top features are ones the model "
                     "leans on for this class generally, so it is unusual "
                     "for its class."),
            "evidence": [
                {"feature": a["feature"],
                 "plain": a["plain"],
                 "raw_value": a["raw_value"],
                 "value_text": _value_text(a["feature"], a["raw_value"]),
                 "contribution": a["contribution"],
                 "direction": a["direction"],
                 "caution": a["caution"],
                 "reading": readings.get(a["feature"])}
                for a in det["attributions"]],
        })

    kept = sum(len([e for e in d["evidence"] if e["reading"]]) for d in out)
    return {"decisions": out,
            "dropped_readings": dropped,
            "provenance": (
                f"{kept} of {kept + len(dropped)} model sentences kept; "
                f"class, confidence, direction, values and cautions are read "
                f"from the detection itself, not written by the language "
                f"model."
                + (f" {len(dropped)} dropped for stating a verdict the "
                   f"attribution does not support." if dropped else ""))}


NUMBER = re.compile(r"-?\d[\d,]*\.?\d*")


def unsupported_numbers(narrative, facts):
    """Figures in a prose panel that are not in the facts it was given.

    Panels 1 and 2 have no citation to check -- their evidence is a dict of
    numbers, not a document -- so this is the equivalent test: every figure in
    the prose must be derivable from the input. A number that is not is either
    a miscopy or an invention, and both are wrong on an evidence panel.

    Percentages are matched against the fraction as well (0.8735 -> 87.35),
    and years and small ordinals are ignored because "three or four sentences"
    and "step 2" are prose, not claims about the capture.
    """
    pool = set()

    def collect(v):
        if isinstance(v, bool):
            return
        if isinstance(v, (int, float)):
            for x in (v, v * 100, round(float(v), 2), round(float(v) * 100, 2)):
                pool.add(f"{float(x):.4f}".rstrip("0").rstrip("."))
        elif isinstance(v, dict):
            for x in v.values():
                collect(x)
        elif isinstance(v, (list, tuple)):
            for x in v:
                collect(x)

    collect(facts)
    bad = []
    for raw in NUMBER.findall(narrative or ""):
        token = raw.replace(",", "")
        try:
            val = float(token)
        except ValueError:
            continue
        if abs(val) <= 10:            # ordinals, list numbering, "one or two"
            continue
        key = f"{val:.4f}".rstrip("0").rstrip(".")
        if key not in pool:
            bad.append(raw)
    return bad


def verify_claims(payload, documents, min_quote_chars=25):
    """Check every action's quote against the document it names.

    `documents` maps path -> full text, exactly as supplied to the model.

    Returns (verified, suppressed, stats). Suppressed actions carry a reason
    so the interface can say how many were dropped and why, without showing
    the text itself.
    """
    norm_docs = {p: _norm(t) for p, t in documents.items()}
    verified, suppressed = [], []

    for a in payload.get("actions", []) or []:
        src, quote = (a.get("source") or "").strip(), a.get("quote") or ""
        reason = None

        if not src or not quote:
            reason = "no source or quote given"
        elif src not in documents:
            # Naming a document that was never supplied is the exact failure
            # seen on the first run, where prompt headings were cited.
            reason = f"cites {src!r}, which was not supplied"
        elif len(quote.strip()) < min_quote_chars:
            # A three-word fragment matches almost anything; it is not
            # evidence that a specific instruction exists.
            reason = f"quote too short to be evidence ({len(quote.strip())} chars)"
        elif _norm(quote) not in norm_docs[src]:
            reason = "quote does not appear in the cited document"

        (suppressed if reason else verified).append(
            dict(a, suppression_reason=reason) if reason else a)

    stats = {
        "actions_returned": len(payload.get("actions", []) or []),
        "verified": len(verified),
        "suppressed": len(suppressed),
        "documents_supplied": len(documents),
    }
    return verified, suppressed, stats


def render(payload, verified, suppressed, stats):
    """The dict the interface renders. Only verified actions reach it.

    [UI CONNECTION: `actions` -> the numbered list, each row linking to
     `source`. `provenance` -> the line under the heading, e.g.
     "3 of 4 actions verified against source; 1 suppressed".]
    """
    if stats["documents_supplied"] == 0:
        line = ("No documentation was retrieved, so no action could be "
                "sourced.")
    elif stats["suppressed"]:
        line = (f"{stats['verified']} of {stats['actions_returned']} actions "
                f"verified against source; {stats['suppressed']} suppressed "
                f"as unverifiable.")
    else:
        line = (f"All {stats['verified']} actions verified against source.")

    return {
        "what_was_found": payload.get("what_was_found"),
        "confidence_assessment": payload.get("confidence_assessment"),
        "ambiguous_with": payload.get("ambiguous_with"),
        "actions": verified,
        "false_positive_conditions": payload.get(
            "false_positive_conditions", []),
        "not_covered": payload.get("not_covered", []),
        "provenance": line,
        "verification": stats,
        # Kept for an audit trail, never rendered as guidance.
        "suppressed_actions": suppressed,
    }


def demo():
    """Self-check for both verification paths."""
    docs = {"ir/dos.md": "Apply rate limiting at the perimeter for the "
                         "identified source addresses."}
    v, s, st = verify_claims({"actions": [
        {"action": "rate limit", "source": "ir/dos.md",
         "quote": "Apply rate limiting at the perimeter for the identified "
                  "source addresses."},
        {"action": "buy a WAF", "source": "(FINDING)", "quote": "x" * 30},
        {"action": "reboot", "source": "ir/dos.md",
         "quote": "Reboot every affected host immediately."},
        {"action": "short", "source": "ir/dos.md", "quote": "Apply it."},
    ]}, docs)
    assert st == {"actions_returned": 4, "verified": 1, "suppressed": 3,
                  "documents_supplied": 1}, st
    assert "was not supplied" in s[0]["suppression_reason"]
    assert s[1]["suppression_reason"] == "quote does not appear in the cited document"
    assert "too short" in s[2]["suppression_reason"]

    # Panel 2: the model's verdicts must not survive, and the deterministic
    # fields must come from the detection whatever the model said.
    det = [{"row": 79, "predicted": "Slowloris", "confidence": 0.9998,
            "runner_up": "DoS", "runner_up_confidence": 0.0001,
            "features_typical_for_class": ["Fwd Packet Length Max"],
            "attributions": [
                {"feature": "Flow IAT Min", "plain": "shortest gap",
                 "raw_value": 1198734.0, "contribution": 3.6,
                 "direction": "supports", "caution": None},
                {"feature": "Subflow Bwd Bytes", "plain": "bytes per burst",
                 "raw_value": 120.0, "contribution": -1.4,
                 "direction": "argues against", "caution": "watch this"},
            ]}]
    rep = render_explanation({"decisions": [{
        "row": 79,
        "summary": "Short gaps, consistent with Slowloris.",
        "readings": [
            {"feature": "Flow IAT Min",
             "reading": "the smallest gap between packets was 1.2 seconds."},
            {"feature": "Subflow Bwd Bytes",
             "reading": "indicative of a Slowloris attack."},
            {"feature": "Bogus Feature", "reading": "invented."},
        ]}]}, det)
    d = rep["decisions"][0]
    assert d["nearly_undecided"] is False, "0.9998 vs 0.0001 is not close"
    assert d["evidence"][1]["direction"] == "argues against"
    assert d["evidence"][1]["reading"] is None, "verdict reading must be dropped"
    assert d["evidence"][0]["reading"], "neutral reading must survive"
    assert d["evidence"][0]["value_text"] == "1,198,734 us (1.199 s)"
    assert d["evidence"][1]["caution"] == "watch this"
    assert "Fwd Packet Length Max" in d["class_fit"]
    assert "consistent with" not in d["summary"], "verdict summary replaced"
    assert "Slowloris at confidence 0.9998" in d["summary"]
    reasons = {x["feature"] for x in rep["dropped_readings"]}
    assert reasons == {"Subflow Bwd Bytes", "Bogus Feature", "(summary)"}, reasons

    assert unsupported_numbers("2000 flows, 87.35% attack",
                               {"total_flows": 2000,
                                "attack_share": 0.8735}) == []
    assert unsupported_numbers("4096 flows", {"total_flows": 2000}) == ["4096"]
    print("claim_schema self-check passed")


if __name__ == "__main__":
    demo()
