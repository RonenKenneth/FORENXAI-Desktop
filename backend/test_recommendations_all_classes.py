"""
test_recommendations_all_classes.py
-----------------------------------
Runs the recommendation panel for EVERY class the model can emit, with the
language model in the loop, and reports per class.

test_recommendations.py proves the panel works. It generates for one class,
which is the right trade for a test that runs in a minute. This one answers a
different question: does the panel hold for all sixteen, or only for the one
that happened to be tested? A class whose playbook is thin, whose controls are
unmapped, or whose retrieved text the verifier rejects everything against, is
invisible until every class is tried.

Run:  cd backend && .venv/Scripts/python test_recommendations_all_classes.py
      --fast          retrieval only, no generation
      --repeat N      run each class N times and require identical output
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.services.recommendation_service import (      # noqa: E402
    get_recommendation,
    retrieve,
)


def _ascii(text: str) -> str:
    return str(text).encode("ascii", "replace").decode("ascii")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fast", action="store_true")
    parser.add_argument("--repeat", type=int, default=1)
    args = parser.parse_args()

    import importlib.util
    from app.utils.runtime_paths import get_knowledge_map_path

    spec = importlib.util.spec_from_file_location(
        "km_for_test", get_knowledge_map_path()
    )
    km = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(km)

    classes = sorted(km.KNOWLEDGE_MAP)

    print("=" * 78)
    print(f"recommendation panel, all {len(classes)} classes"
          f"{'  (retrieval only)' if args.fast else ''}")
    print("=" * 78)
    print()

    failures: list[str] = []

    header = (
        f"{'class':<16}{'std':>4}{'lit':>4}{'src':>4}"
        f"{'miss':>5}  " + ("" if args.fast else f"{'acts':>5}{'rej':>4}  ")
        + "notes"
    )
    print(header)
    print("-" * 78)

    for predicted in classes:

        result = retrieve(predicted, confidence=0.85)

        standards = result.get("standards") or []
        literature = result.get("literature") or []
        sources = result.get("sources") or []
        missing = (result.get("missing") or []) + (
            result.get("missing_standards") or []
        )

        notes = []

        if not result.get("passages"):
            failures.append(f"{predicted}: no documents retrieved")
            notes.append("NO DOCUMENTS")

        if not standards:
            failures.append(f"{predicted}: no standard passages")
            notes.append("NO STANDARDS")

        if not sources:
            failures.append(f"{predicted}: nothing citable")
            notes.append("NO CITATIONS")

        if missing:
            notes.append("missing: " + ", ".join(map(str, missing[:2])))

        line = (
            f"{predicted:<16}{len(standards):>4}{len(literature):>4}"
            f"{len(sources):>4}{len(missing):>5}  "
        )

        if not args.fast:

            seen = set()
            actions = []
            rejected = 0

            for _ in range(max(1, args.repeat)):

                generated = get_recommendation(
                    predicted, confidence=0.85
                )

                actions = generated.get("actions") or []
                rejected = len(
                    generated.get("rejected_ungrounded") or []
                )
                references = generated.get("references") or []

                # actions are plain strings; the citation list is separate
                seen.add(tuple(str(x) for x in actions))

            # Benign is the documented exception. It returns three fixed
            # lines about what a benign classification does and does not
            # mean -- written by the app, not generated and not quoted --
            # so standards_grounded is False and there is nothing to put
            # in a reference list. Measured: 3 actions, 3 cited, 0
            # references, verified True.
            grounded = generated.get("standards_grounded", True)

            if not actions:
                failures.append(f"{predicted}: no actions generated")
                notes.append("NO ACTIONS")

            if not generated.get("verified", False):
                failures.append(
                    f"{predicted}: an action failed verification"
                )
                notes.append("UNVERIFIED")

            # A reference list is required only where the actions were
            # written from the standards. Where they were not, an empty
            # list is the honest answer rather than a missing one.
            if actions and grounded and not references:
                failures.append(
                    f"{predicted}: actions written from the standards "
                    f"but no reference list"
                )
                notes.append("NO REFERENCES")

            if actions and not grounded:
                notes.append("not standards-grounded (own guidance)")

            if args.repeat > 1 and len(seen) > 1:
                failures.append(
                    f"{predicted}: output differs across {args.repeat} runs"
                )
                notes.append("NOT DETERMINISTIC")

            line += f"{len(actions):>5}{rejected:>4}  "

        print(_ascii(line + ("; ".join(notes) if notes else "ok")))

    print()
    print("=" * 78)

    if failures:
        print(f"{len(failures)} FAILURES")
        for failure in failures:
            print("  " + _ascii(failure))
        return 1

    print(f"all {len(classes)} classes passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
