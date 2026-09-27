"""
test_rag_pipeline.py
--------------------
Tests for the prepared RAG index, retrieval, generation parsing and
verification.

    python test_rag_pipeline.py            # no language model needed
    python test_rag_pipeline.py --live     # also one real Qwen generation

Exit status is the number of failed checks.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.services import recommendation_service as rs      # noqa: E402

FAILED = []


def check(name, condition, detail=""):
    print(f"  [{'PASS' if condition else 'FAIL'}] {name}  {detail}")
    if not condition:
        FAILED.append(name)


# Fields the WPF interface deserialises (Models/AnalysisModels.cs,
# RecommendationData) and the type each must keep.
UI_FIELDS = {
    "predicted_class": str, "summary": str, "actions": list,
    "generator": str, "verified": bool, "action_evidence": list,
    "citations": list, "standards_used": list, "sources": list,
    "mitre": list, "controls": list, "rejected_ungrounded": list,
    "actions_cited": list, "references": list,
    "standards_grounded": bool, "measured": dict,
}
SHARED_FIELDS = ("predicted_class", "retrieved_sources", "generated_actions",
                 "verified_actions", "dropped_actions",
                 "verification_summary", "references")


def fake_generation(payload):
    """Replace Qwen with a fixed answer, or one computed from the prompt."""
    real = rs._generate
    rs._generate = lambda prompt, refs=None: (
        payload(prompt) if callable(payload) else payload)
    return real


_LINE = re.compile(r"^\[(S\d+)\] ([^:]+): (.+)$", re.M)


def from_prompt(playbook=3, extra=(), cite_label=None):
    """Answer as a faithful model would: restate lines, cite their own ids."""
    def answer(prompt):
        lines = _LINE.findall(prompt)
        actions = [{"text": text, "source_id": ref}
                   for ref, label, text in lines
                   if label.startswith("NIST SP 800-61r3,")][:playbook]
        for ref, label, text in lines:
            if cite_label and label.startswith(cite_label):
                actions.append({"text": text, "source_id": ref})
        actions.extend(extra)
        return json.dumps({"actions": actions})
    return answer


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true")
    args = ap.parse_args()

    ri = rs._rag_index_module()
    km = ri.knowledge_map()
    si = ri.source_index()

    print("\n1. index: creation, reuse, staleness")
    t = time.perf_counter()
    index, how = ri.load_rag_index()
    check("index loads", bool(index), f"{how} in {(time.perf_counter() - t) * 1000:.0f} ms")
    _, how2 = ri.load_rag_index()
    check("index reused when corpus unchanged", how2 == "reused")
    t = time.perf_counter()
    version = ri.knowledge_version()
    check("version check is cheap", (time.perf_counter() - t) < 0.2,
          f"{(time.perf_counter() - t) * 1000:.1f} ms")
    check("recorded version matches corpus", index["version"] == version)

    with tempfile.TemporaryDirectory() as tmp:
        copy_rag = Path(tmp) / "rag"
        shutil.copytree(ri.KNOWLEDGE_DIR, copy_rag / "knowledge")
        shutil.copytree(ri.CONFIG_DIR, copy_rag / "config",
                        ignore=shutil.ignore_patterns("__pycache__"))
        (copy_rag / "_sources").mkdir()
        saved = {k: getattr(ri, k) for k in ("CONFIG_DIR", "RAG_DIR", "KNOWLEDGE_DIR",
                                             "SOURCES_DIR", "MANIFEST_FILE",
                                             "SHA256SUMS_FILE", "INDEX_FILE")}
        saved_modules = dict(ri._modules)
        try:
            ri.CONFIG_DIR, ri.RAG_DIR = copy_rag / "config", copy_rag
            ri.KNOWLEDGE_DIR, ri.SOURCES_DIR = copy_rag / "knowledge", copy_rag / "_sources"
            ri.MANIFEST_FILE = ri.SOURCES_DIR / "manifest.json"
            ri.SHA256SUMS_FILE = ri.SOURCES_DIR / "SHA256SUMS.txt"
            ri.INDEX_FILE = copy_rag / ".rag_index.json"
            ri._modules.clear()
            ri._modules["knowledge_map"] = km
            ri._modules["source_index"] = None
            built = ri.build_rag_index(force=True)
            check("index file is created", ri.INDEX_FILE.is_file())
            _, how = ri.load_rag_index()
            check("second load reuses it", how == "reused")
            target = copy_rag / "knowledge" / "detection" / "attack_dos.md"
            target.write_text(target.read_text(encoding="utf-8") + "\nedit\n", encoding="utf-8")
            rebuilt, how = ri.load_rag_index()
            check("edited corpus makes the index stale and rebuilds it",
                  how == "rebuilt" and rebuilt["version"] != built["version"])
            check("archive absent: local corpus still indexed",
                  not rebuilt["archive_present"] and len(rebuilt["classes"]) == 16)
        finally:
            for k, v in saved.items():
                setattr(ri, k, v)
            ri._modules.clear()
            ri._modules.update(saved_modules)

    print("\n2. class routing")
    check("16 classes indexed", len(index["classes"]) == 16)
    check("index classes match knowledge_map.py",
          set(index["classes"]) == set(km.KNOWLEDGE_MAP))
    for cls, entry in km.KNOWLEDGE_MAP.items():
        bundle = index["classes"][cls]
        ok = (bundle["controls"] == list(entry["controls"])
              and bundle["summary"] == entry["summary"]
              and (entry["response"] is None or bundle["playbook_lines"]))
        check(f"{cls}: routing matches the map", ok)
    try:
        rs.retrieve("NotAClass")
        check("unknown class raises", False)
    except KeyError:
        check("unknown class raises", True)

    print("\n2b. class-specific coverage, all 15 attack classes")
    focus_map = getattr(km, "FOCUS_SECTIONS", {})
    check("every class has a FOCUS_SECTIONS entry", set(focus_map) == set(km.KNOWLEDGE_MAP))
    for cls in km.KNOWLEDGE_MAP:
        if cls == "Benign":
            continue
        bundle = index["classes"][cls]
        got = [p["source_id"] for p in bundle["focus_passages"]]
        wanted = len(focus_map.get(cls, []))
        check(f"{cls}: focus sections resolved ({len(got)}/{wanted})",
              si is None or len(got) == wanted)
        r = rs.retrieve(cls, None, 0.95)
        _, srcs = rs.build_generation_context(cls, r, None)
        specific = [s for s in srcs.values() if s["kind"] in rs.CLASS_SPECIFIC_KINDS]
        check(f"{cls}: at least 3 class-specific sources in the prompt",
              len(specific) >= 3, f"{len(specific)}")
        check(f"{cls}: generic detection / recovery lines not sent",
              not any(s["kind"] == "playbook" and (":DE." in s["source_id"] or ":RC." in s["source_id"])
                      for s in srcs.values()))
    web = index["classes"]["WebBased"]["focus_passages"]
    check("OWASP guidance starts at 'How to prevent'",
          si is None or web[0]["text"].lower().startswith("how to prevent"))

    print("\n3. fixed sources")
    baseline_ids = [b["source_id"] for b in index["baselines"]]
    check("SP 800-61r3 section 3.2 present", "SP800-61r3:3.2" in baseline_ids)
    check("SP 800-86 section 3.1 present", "SP800-86:3.1" in baseline_ids)
    for cls, entry in km.KNOWLEDGE_MAP.items():
        resolved = [p["ref"] for p in index["classes"][cls]["control_passages"]]
        exact = all(r in entry["controls"] for r in resolved)
        check(f"{cls}: controls resolved by exact identifier",
              exact and len(resolved) == len(entry["controls"]),
              f"{resolved}")

    print("\n4. retrieval: parity, top-k, determinism, cache")
    if si is not None:
        exclude = si.BASELINE_SECTIONS
        for cls, bundle in index["classes"].items():
            old = si.search(bundle["terms"], limit=2, exclude=exclude)
            new = ri.search(index, bundle["terms"], limit=2, exclude=exclude)
            check(f"{cls}: same passages as the previous search",
                  [(o["doc_id"], o["ref"], o["score"]) for o in old]
                  == [(n["doc_id"], n["ref"], n["score"]) for n in new])
    else:
        print("  (source archive absent: parity checks skipped)")
    for cls in index["classes"]:
        got = rs.retrieve_supporting_passages(cls)
        check(f"{cls}: at most 2 passages, each with an id",
              len(got) <= 2 and all(p.get("source_id") for p in got))
    a = rs.retrieve_supporting_passages("PortScan")
    rs._retrieval_cache.clear()
    b = rs.retrieve_supporting_passages("PortScan")
    check("retrieval is deterministic", a == b)
    t = time.perf_counter()
    rs.retrieve_supporting_passages("PortScan")
    hit = (time.perf_counter() - t) * 1000
    check("repeated retrieval served from cache",
          any(k[1] == "PortScan" for k in rs._retrieval_cache), f"{hit:.3f} ms")
    rs._retrieval_cache[("old-version", "PortScan", ("x",), 2)] = []
    real_index = rs._rag_index
    rs._retrieval_cache.clear()
    rs._retrieval_cache[("old-version", "PortScan", ("x",), 2)] = []
    rs.retrieve_supporting_passages("DoS")
    check("entries from another knowledge version are dropped",
          not any(k[0] == "old-version" for k in rs._retrieval_cache))
    rs._rag_index = real_index

    print("\n5. generation context")
    retrieved = rs.retrieve("DoS", None, 0.95)
    prompt, sources = rs.build_generation_context("DoS", retrieved)
    ids = [s["source_id"] for s in sources.values()]
    check("every prompt source has a unique id", len(ids) == len(set(ids)))
    check("controls, baselines and playbook are in the context",
          "SP800-53r5:SC-5" in ids and "SP800-61r3:3.2" in ids
          and any(i.startswith("SP800-61r3:RS.") for i in ids))
    check("no always-load notes or glossary in the prompt",
          "glossary" not in prompt.lower() and "caveats" not in prompt.lower())
    retrieved_ids = [p["source_id"] for p in retrieved["standards"] if p.get("score") is not None]
    check("0-2 retrieved passages in the prompt", len(retrieved_ids) <= 2)
    check("context is compact", len(prompt) < 8000, f"{len(prompt)} chars")

    print("\n6. structured output and verification")
    ref_ok = next(r for r, s in sources.items() if s["source_id"] == "SP800-61r3:RS.MI-02 R1")
    good = {"text": "Identify all affected hosts and services within the organization "
                    "so that all flaws and weaknesses can be remediated.",
            "source_id": ref_ok}
    parsed, status = rs._parse_structured(json.dumps({"actions": [good]}))
    check("valid JSON parses", status == "ok" and parsed == [good])
    parsed, status = rs._parse_structured('{"actions": [' + json.dumps(good) + ', {"text": "Cut')
    check("truncated JSON: complete actions salvaged", status == "salvaged" and len(parsed) == 1)
    parsed, status = rs._parse_structured("not json at all")
    check("malformed output yields nothing", status == "malformed" and parsed == [])

    cases = {
        "missing source_id": {"text": good["text"]},
        "more than one source_id": {"text": good["text"], "source_id": [ref_ok, "S1"]},
        "more than one source_id ": {"text": good["text"], "source_id": f"{ref_ok}, S1"},
        "source_id not in the supplied context": {"text": good["text"], "source_id": "S999"},
        "not supported by the cited source": {
            "text": "Reboot every domain controller and rotate the krbtgt password twice.",
            "source_id": ref_ok},
        "malformed action": "just a string",
    }
    result = rs.verify_actions([good] + list(cases.values()), sources)
    check("the supported action is kept with provenance",
          len(result["verified_actions"]) == 1
          and result["verified_actions"][0]["source_id"] == "SP800-61r3:RS.MI-02 R1")
    reasons = [d["reason"] for d in result["dropped_actions"]]
    for reason in cases:
        check(f"dropped: {reason.strip()}", reason.strip() in reasons)
    wrong_ref = next(r for r, s in sources.items() if r != ref_ok and s["kind"] == "control")
    moved = rs.verify_actions([{"text": good["text"], "source_id": wrong_ref}], sources)
    kept = moved["verified_actions"]
    check("a mis-cited action is re-attributed to the one source that supports it",
          len(kept) == 1 and kept[0]["source_id"] == "SP800-61r3:RS.MI-02 R1"
          and kept[0]["evidence"]["cited_as"] == sources[wrong_ref]["source_id"]
          and moved["verification_summary"]["citation_corrected"] == 1)
    reworded = [
        {"text": "Implement positive server-side input validation for all inputs.", "source_id": ref_ok},
        {"text": "Use positive server-side input validation for all inputs.", "source_id": ref_ok},
    ]
    near = rs.verify_actions(reworded, {ref_ok: dict(sources[ref_ok], text=
        "Implement positive server-side input validation for all inputs. Use positive server-side input validation for all inputs.")})
    check("a reworded duplicate is dropped", near["verification_summary"]["verified"] == 1
          and near["dropped_actions"][0]["reason"] == "duplicate action")
    check("summary counts add up",
          result["verification_summary"]["generated"] == 7
          and result["verification_summary"]["verified"] == 1
          and result["verification_summary"]["dropped"] == 6)

    print("\n7. recommendation object (UI and reports)")
    invented = {"text": cases["not supported by the cited source"]["text"],
                "source_id": "S1"}
    real = fake_generation(from_prompt(3, [invented]))
    rs._cache.clear()
    try:
        rec = rs.get_recommendation("DoS", None, 0.95, None)
    finally:
        rs._generate = real
    for field, kind in UI_FIELDS.items():
        check(f"UI field {field} kept as {kind.__name__}",
              isinstance(rec.get(field), kind))
    check("only verified or quoted actions are displayed",
          "krbtgt" not in " ".join(rec["actions"])
          and all(e.get("match") in ("span", "terms", "evidence", "quoted")
                  for e in rec["action_evidence"]))
    check("at least 2 class-specific actions, topped up by quotation",
          sum(1 for e in rec["action_evidence"] if e.get("kind") in rs.CLASS_SPECIFIC_KINDS) >= 2
          and len(rec["actions"]) <= rs.MAX_ACTIONS)
    check("dropped action is reported with its reason",
          rec["verification_summary"]["dropped"] == 1
          and rec["dropped_actions"][0]["reason"] == "not supported by the cited source")
    check("every displayed action keeps its source_id",
          all(a.get("source_id") for a in rec["verified_actions"]))
    cited_docs = {e["doc_id"] for e in rec["action_evidence"]}
    check("references list only sources used by displayed actions",
          {r["doc_id"] for r in rec["references"]} == cited_docs)
    for field in SHARED_FIELDS:
        check(f"shared object carries {field}", field in rec)
    check("report consumer: object survives JSON round trip",
          json.loads(json.dumps(rec))["verified_actions"] == rec["verified_actions"])
    from app.services import report_service
    check("report_service builds with this object",
          callable(getattr(report_service, "build_case_report", None)))

    real = fake_generation("garbage")
    rs._cache.clear()
    try:
        rec = rs.get_recommendation("WebBased", None, 0.95, None)
    finally:
        rs._generate = real
    check("malformed Qwen output never yields invented actions",
          rec["actions"] and all(e.get("match") in ("quoted", "span", "terms")
                                 for e in rec["action_evidence"]),
          f"generator={rec['generator']}")
    check("Qwen failure keeps the result usable",
          rec["predicted_class"] == "WebBased" and len(rec["actions"]) >= 1)

    real = fake_generation(None)
    rs._cache.clear()
    try:
        rec = rs.get_recommendation("Benign", None, 0.95, None)
    finally:
        rs._generate = real
    check("Benign keeps its fixed policy actions", rec["generator"] == "none")

    print("\n8. model, SHAP and rule-based inputs")
    shap = [{"feature": "Fwd Packet Length Max", "raw_value": 1500.0,
             "shap_value": 2.31, "direction": "toward"},
            {"feature": "Bwd Header Length", "raw_value": 40.0,
             "shap_value": -0.4, "direction": "against"}]
    hit = {"rule_id": "T1-DOS-01", "class": "DoS", "tier": 1,
           "evidence": "143 flows from 10.0.0.5 to 10.0.0.20:80 in 60 s, threshold 100.",
           "measured": 143, "threshold": 100, "severity": "high"}
    other = {"rule_id": "T1-PORTSCAN-01", "class": "PortScan", "tier": 1,
             "evidence": "25 distinct ports from 10.0.0.5 to 10.0.0.20 in 60 s, threshold 20.",
             "measured": 25, "threshold": 20, "severity": "medium"}
    for expected, rules in {"not_evaluated": None, "no_rule_fired": [],
                            "agree": [hit], "conflict": [other]}.items():
        inputs = rs._recommendation_inputs("DoS", 0.95, {"class_f1": 0.686}, shap, rules)
        check(f"rules: {expected}", inputs["rules"]["agreement"] == expected)
    inputs = rs._recommendation_inputs("DoS", 0.95, {"class_f1": 0.686}, shap, [hit])
    prompt, sources = rs.build_generation_context("DoS", retrieved, inputs)
    ids = {s["source_id"]: r for r, s in sources.items()}
    check("SHAP and rule evidence are citable sources",
          {"CASE:shap", "CASE:rule:T1-DOS-01"} <= set(ids))
    check("the model prediction is context, not a citable source",
          "CASE:model" not in ids and "XGBoost classified this traffic as DoS" in prompt)
    check("SHAP drivers appear in the prompt", "Fwd Packet Length Max" in prompt)
    check("rule agreement appears in the prompt", "independently flagged DoS" in prompt)
    cite_rule = {"text": "Investigate the 143 flows from 10.0.0.5 to 10.0.0.20:80 in 60 s.",
                 "source_id": ids["CASE:rule:T1-DOS-01"]}
    checked = rs.verify_actions([cite_rule], sources)
    check("an action citing rule evidence verifies",
          checked["verification_summary"]["verified"] == 1)
    invented_figure = dict(cite_rule, text=cite_rule["text"].replace("143", "999"))
    checked = rs.verify_actions([invented_figure], sources)
    check("an invented figure in a rule-evidence action is dropped",
          checked["verification_summary"]["dropped"] == 1)

    real = fake_generation(from_prompt(3, cite_label="Rule T1-DOS-01"))
    rs._cache.clear()
    try:
        rec = rs.get_recommendation("DoS", shap, 0.95, None, [hit])
    finally:
        rs._generate = real
    check("recommendation records its inputs",
          rec["inputs"]["rules"]["agreement"] == "agree" and len(rec["inputs"]["shap"]) == 2)
    check("rule-evidence action kept and referenced as case evidence",
          any(e.get("kind") == "evidence" for e in rec["action_evidence"])
          and any(r["doc_id"] == "FORENXAI.case" and "Case evidence" in r["acm"]
                  for r in rec["references"]))
    check("a heading echo is dropped, not displayed",
          rs.verify_actions([{"text": "NIST SP 800-53r5 SC-5 DENIAL-OF-SERVICE PROTECTION (class-specific): Protect against the effects.",
                              "source_id": "S1"}], sources)["dropped_actions"][0]["reason"]
          == "restates a source heading, not an action")
    check("case evidence does not count as a published standard",
          rec["standards_grounded"])
    rs._cache.clear()
    real = fake_generation(from_prompt(3))
    try:
        a = rs.get_recommendation("DoS", shap, 0.95, None, None)
        b = rs.get_recommendation("DoS", shap, 0.95, None, [hit])
    finally:
        rs._generate = real
    check("a different rule outcome is a different answer",
          a["inputs"]["rules"]["agreement"] == "not_evaluated"
          and b["inputs"]["rules"]["agreement"] == "agree")

    findings = [
        {"predicted_class": "DoS", "confidence": 0.97, "probabilities": None,
         "top_features": shap, "rule_findings": [hit]},
        {"predicted_class": "DoS", "confidence": 0.99, "probabilities": None,
         "top_features": shap[:1], "rule_findings": [hit]},
        {"predicted_class": "DoS", "confidence": 0.98, "probabilities": None,
         "top_features": shap, "rule_findings": None},
    ]
    plan = rs.plan_recommendations(findings)
    check("flows grouped by rule outcome", len(plan) == 2)
    top = next(p for p in plan if p["flows"] == 2)
    check("SHAP aggregated across the group",
          top["shap_features"][0]["feature"] == "Fwd Packet Length Max"
          and top["shap_features"][0]["flows"] == 2)

    print("\n9. startup")
    t = time.perf_counter()
    rs.start_rag_warmup(preload_llm=False)
    check("warmup returns immediately", (time.perf_counter() - t) < 0.5)
    check("index ready after warmup", rs.rag_ready(wait=True))

    if args.live:
        print("\n10. live generation")
        rs._cache.clear()
        t = time.perf_counter()
        rec = rs.get_recommendation("DoS", None, 0.95, None)
        took = time.perf_counter() - t
        check("live: at least 3 displayed actions", len(rec["actions"]) >= 3,
              f"{took:.1f} s, generator={rec['generator']}, "
              f"{rec['verification_summary']}")
        check("live: all displayed actions carry a source_id",
              all(a.get("source_id") for a in rec["verified_actions"]))

    print(f"\n{'ALL CHECKS PASSED' if not FAILED else f'{len(FAILED)} FAILED: {FAILED}'}")
    return len(FAILED)


if __name__ == "__main__":
    sys.exit(main())
