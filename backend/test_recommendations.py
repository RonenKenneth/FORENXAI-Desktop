"""
test_recommendations.py
-----------------------
Check the recommendation panel end to end, and say plainly what is missing.

Run:  cd backend && .venv/Scripts/python test_recommendations.py
      add --fast to skip the language model and test retrieval only.

WHAT IT CHECKS

  1  every class the model can emit has a knowledge-map entry
  2  every class retrieves its documents, with nothing missing
  3  every response playbook is compiled, not hand-written
  4  the verifier rejects an action that is not in any source
  5  a real recommendation comes back cited and verified

WHAT IT TOLERATES

Two large files are deliberately not in Git: the source archive
(rag/_sources/, ~99 MiB of third-party publications) and the Qwen weights
(backend/models/llm/qwen2.5-3b-q4.gguf, ~1.8 GiB). The panel is built to work
without either -- the playbooks already carry the quoted standard text, and
the extraction path writes actions without a model. This script reports which
are present so a failure is never mistaken for a missing file.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import joblib                                        # noqa: E402

from app.services import model_facts                 # noqa: E402
from app.services.recommendation_service import (    # noqa: E402
    get_recommendation,
    retrieve,
    verify,
)
from app.utils.runtime_paths import (                # noqa: E402
    get_knowledge_directory,
    get_llm_model_path,
    get_rag_directory,
)

MODEL_DIR = Path(__file__).resolve().parent / "models" / "forenxai"

# An action no source supports. If the verifier ever accepts this, the
# grounding check is not doing its job and every other result is suspect.
INVENTED = (
    "Reboot the domain controller and disable all antivirus software "
    "immediately across the estate."
)

passed = 0
failed = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global passed, failed
    if ok:
        passed += 1
        print(f"  [PASS] {name}" + (f"  {detail}" if detail else ""))
    else:
        failed += 1
        print(f"  [FAIL] {name}" + (f"  {detail}" if detail else ""))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--fast",
        action="store_true",
        help="skip the language model; test retrieval and verification only",
    )
    args = parser.parse_args()

    print("=" * 66)
    print("FORENXAI recommendation panel")
    print("=" * 66)

    # ---------------------------------------------------------- inventory
    rag = get_rag_directory()
    archive = rag / "_sources"
    pdfs = len(list(archive.glob("*.pdf"))) if archive.is_dir() else 0
    weights = get_llm_model_path()

    print(f"\nrag directory     {rag}")
    print(f"knowledge         {get_knowledge_directory()}")
    print(f"source archive    {pdfs} PDFs"
          + ("" if pdfs else "  (not present -- optional)"))
    print(f"Qwen weights      "
          + ("present" if weights.is_file() else
             "not present -- the extraction path will be used"))

    # ------------------------------------------------- 1. class coverage
    print("\n1. class coverage")

    classes = [
        str(c) for c in
        joblib.load(MODEL_DIR / "label_encoder.pkl").classes_
    ]

    unmapped = []

    for cls in classes:
        try:
            retrieve(cls)
        except KeyError:
            unmapped.append(cls)

    check(
        "every class the model emits is mapped",
        not unmapped,
        f"{len(classes)} classes"
        + (f", unmapped: {unmapped}" if unmapped else ""),
    )

    # --------------------------------------------------- 2. retrieval
    print("\n2. retrieval")

    incomplete = []

    for cls in classes:
        found = retrieve(cls)
        if found["missing"]:
            incomplete.append((cls, found["missing"]))

    check(
        "no class is missing a document",
        not incomplete,
        str(incomplete) if incomplete else "",
    )

    # ------------------------------------------- 3. compiled playbooks
    print("\n3. playbooks are compiled, not written")

    knowledge = get_knowledge_directory()
    handwritten = []
    uncited = []

    for path in sorted((knowledge / "incident_response").glob("*.md")):

        text = path.read_text(encoding="utf-8")

        if "PLACEHOLDER" in text or "build_playbooks.py" not in text:
            handwritten.append(path.name)

        cited = sum(
            1 for line in text.splitlines()
            if line.startswith("- ") and "(NIST SP" in line
        )

        if cited < 5:
            uncited.append(f"{path.name}:{cited}")

    check(
        "no playbook is hand-written or a placeholder",
        not handwritten,
        str(handwritten) if handwritten else "",
    )
    check(
        "every playbook carries cited lines",
        not uncited,
        str(uncited) if uncited else "",
    )

    # ------------------------------------------------- 4. the verifier
    print("\n4. verification rejects what no source supports")

    found = retrieve("DoS")
    passages = found["standards"] + found["passages"]

    check(
        "an invented action is rejected",
        verify(INVENTED, passages) is None,
        "control case",
    )

    quoted = next(
        (
            line.lstrip("- ").split(" (NIST")[0]
            for line in found["passages"][-1]["text"].splitlines()
            if line.startswith("- ") and len(line) > 60
        ),
        None,
    )

    if quoted:
        evidence = verify(quoted, passages)
        check(
            "a line quoted from a source is accepted",
            evidence is not None,
            f"matched {evidence['source'][:44]}" if evidence else "",
        )

    # ------------------------------------------ 5. measured facts
    print("\n5. measured facts, not figures written into documents")

    check(
        "model_facts.json ships with the model",
        model_facts.available(),
        "per-class F1, confusion matrix, 120 pair similarities",
    )

    if model_facts.available():

        forward = model_facts.confusion("BufferOverflow", "Exploitation")
        reverse = model_facts.confusion("Exploitation", "BufferOverflow")

        check(
            "confusion is directional",
            forward is not None
            and reverse is not None
            and abs(forward - reverse) > 0.05,
            f"BufferOverflow->Exploitation {forward:.1%}, "
            f"reverse {reverse:.1%}",
        )

    # the corpus must not carry evaluation figures: they go stale silently
    import re

    stale = []

    for path in sorted(get_knowledge_directory().rglob("*.md")):

        for number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), 1
        ):
            if "NIST SP" in line:
                continue
            if re.search(r"\b0\.\d{3,}\b|\b\d{1,2}\.\d% of\b", line):
                stale.append(f"{path.name}:{number}")

    check(
        "no evaluation figure is hardcoded in the corpus",
        not stale,
        str(stale[:4]) if stale else "figures come from model_facts.json",
    )

    # ------------------------------------ 6. confidence changes retrieval
    print("\n6. retrieval responds to confidence, not only to the class")

    confident = retrieve(
        "DDoS", {"DDoS": 0.99, "PortScan": 0.005}, 0.99
    )
    uncertain = retrieve(
        "DoS", {"DoS": 0.52, "Slowloris": 0.44, "DDoS": 0.02}, 0.52
    )

    check(
        "a confident prediction offers no alternative",
        not confident["measured"]["alternatives"],
        "DDoS at 99%",
    )
    check(
        "an uncertain prediction names the alternative",
        [a["class"] for a in uncertain["measured"]["alternatives"]]
        == ["Slowloris"],
        "DoS at 52%, Slowloris at 44%",
    )
    check(
        "the alternative's profile is retrieved too",
        any(
            p["role"] == "alternative"
            for p in uncertain["passages"]
        ),
        "so the guidance can hold either way",
    )

    # --------------------------------------------- 7. a real response
    if args.fast:
        print("\n7. generation  (skipped, --fast)")
    else:
        print("\n7. generation")

        result = get_recommendation("DoS")

        check(
            "actions were returned",
            len(result["actions"]) >= 3,
            f"{len(result['actions'])} actions, "
            f"generator {result['generator']}",
        )
        check(
            "every action is verified",
            result["verified"],
            f"{len(result['rejected_ungrounded'])} rejected",
        )
        check(
            "citations line up with actions",
            len(result["actions_cited"]) == len(result["actions"]),
        )
        check(
            "references are in ACM format, not bare identifiers",
            all(
                len(r["acm"]) > 40 and ". " in r["acm"]
                for r in result["references"]
            ),
            f"{len(result['references'])} references",
        )

        print("\n  sample:")
        for action in result["actions_cited"][:3]:
            print(f"    - {action[:96]}")
        for reference in result["references"]:
            print(f"    [{reference['number']}] {reference['acm'][:90]}")

    # ------------------------------------------------------------ result
    print("\n" + "=" * 66)
    print(f"{passed} passed, {failed} failed")
    print("=" * 66)

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
