"""
bench_recommendations.py
------------------------
Stage-by-stage timing of the recommendation pipeline, measured, not estimated.

    python bench_recommendations.py --classes DoS WebBased PortScan --out bench.json
    python bench_recommendations.py --no-llm          # everything except Qwen

Each stage is timed by wrapping the module's own functions, so the same
script measures whichever implementation is checked out. Run it once on the
old commit and once on the new one and compare the two JSON files with
--compare old.json new.json.

Startup is measured in a fresh interpreter (subprocess), cold and warm.
"""
from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import time
from pathlib import Path

BACKEND = Path(__file__).resolve().parent
sys.path.insert(0, str(BACKEND))

STARTUP_SNIPPET = r"""
import time, sys
sys.path.insert(0, {backend!r})
t0 = time.perf_counter()
from app.services import recommendation_service as rs
t1 = time.perf_counter()
ready = getattr(rs, "rag_ready", None)
if callable(ready):
    ready(wait=True)
else:
    rs.retrieve("DoS")
t2 = time.perf_counter()
print(f"{{(t1-t0)*1000:.1f}} {{(t2-t1)*1000:.1f}}")
"""


def startup(runs: int):
    """Import time and time-to-first-retrieval-ready, fresh process each run."""
    rows = []
    for _ in range(runs):
        out = subprocess.run(
            [sys.executable, "-c", STARTUP_SNIPPET.format(backend=str(BACKEND))],
            capture_output=True, text=True, cwd=BACKEND)
        line = [l for l in out.stdout.splitlines() if l and l[0].isdigit()]
        if not line:
            raise RuntimeError(out.stderr[-2000:])
        imp, ready = map(float, line[-1].split())
        rows.append({"import_ms": imp, "rag_ready_ms": ready})
    return rows


class Timer:
    def __init__(self):
        self.t = {}

    def wrap(self, module, name, label=None):
        fn = getattr(module, name, None)
        if not callable(fn):
            return
        label = label or name

        def timed(*a, **k):
            s = time.perf_counter()
            try:
                return fn(*a, **k)
            finally:
                self.t.setdefault(label, []).append((time.perf_counter() - s) * 1000)
        setattr(module, name, timed)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--classes", nargs="+", default=["DoS", "WebBased", "PortScan"])
    ap.add_argument("--no-llm", action="store_true")
    ap.add_argument("--startup-runs", type=int, default=3)
    ap.add_argument("--out")
    ap.add_argument("--compare", nargs=2)
    args = ap.parse_args()

    if args.compare:
        return compare(*args.compare)

    result = {"startup": startup(args.startup_runs)}

    from app.services import recommendation_service as rs

    timer = Timer()
    for name in ("retrieve", "retrieve_supporting_passages", "_build_prompt",
                 "build_generation_context", "_generate", "verify_actions"):
        timer.wrap(rs, name)

    # Prompt size and Qwen prefill are measured on the exact prompt the
    # service builds, captured at the generation call.
    prompts = {}
    real_generate = rs._generate

    def capture(prompt, *a, **k):
        prompts[current] = prompt
        if args.no_llm:
            return None
        return real_generate(prompt, *a, **k)
    rs._generate = capture

    llm = None
    if not args.no_llm:
        from app.services.llm_provider import get_llm
        s = time.perf_counter()
        llm = get_llm()
        result["qwen_load_ms"] = (time.perf_counter() - s) * 1000

    per_class = {}
    for current in args.classes:
        timer.t.clear()
        rs._cache.clear()
        getattr(rs, "_retrieval_cache", {}).clear()
        s = time.perf_counter()
        rec = rs.get_recommendation(current, None, 0.95, None)
        total = (time.perf_counter() - s) * 1000
        row = {k: round(sum(v), 2) for k, v in timer.t.items()}

        # second retrieval of the same class: warm path
        s = time.perf_counter()
        rs.retrieve(current, None, 0.95)
        warm_retrieve = (time.perf_counter() - s) * 1000

        # cache hit on the whole recommendation
        s = time.perf_counter()
        rs.get_recommendation(current, None, 0.95, None)
        cache_hit = (time.perf_counter() - s) * 1000

        row.update({
            "total_ms": round(total, 1),
            "warm_retrieve_ms": round(warm_retrieve, 2),
            "recommendation_cache_hit_ms": round(cache_hit, 3),
            "prompt_chars": len(prompts.get(current, "")),
            "actions": len(rec.get("actions", [])),
            "generator": rec.get("generator"),
            "rejected": len(rec.get("rejected_ungrounded", [])),
        })
        if llm is not None and current in prompts:
            toks = llm.tokenize(prompts[current].encode("utf-8"))
            row["prompt_tokens"] = len(toks)
            llm.reset()
            s = time.perf_counter()
            llm(prompts[current], max_tokens=1, temperature=0.0, top_k=1)
            row["qwen_prefill_ms"] = round((time.perf_counter() - s) * 1000, 1)
            row["qwen_decode_ms"] = round(row.get("_generate", 0) - row["qwen_prefill_ms"], 1)
        per_class[current] = row
        print(current, json.dumps(row), flush=True)

    result["per_class"] = per_class
    text = json.dumps(result, indent=2)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    print(text)


def compare(before_path, after_path):
    b = json.loads(Path(before_path).read_text(encoding="utf-8"))
    a = json.loads(Path(after_path).read_text(encoding="utf-8"))

    def med(rows, key):
        vals = [r[key] for r in rows if key in r]
        return statistics.median(vals) if vals else None

    def cls_med(res, *keys):
        vals = []
        for row in res.get("per_class", {}).values():
            v = next((row[k] for k in keys if k in row), None)
            if v is not None:
                vals.append(v)
        return statistics.median(vals) if vals else None

    rows = [
        ("Cold startup: import (ms)", med(b["startup"][:1], "import_ms"), med(a["startup"][:1], "import_ms")),
        ("Warm startup: import (ms)", med(b["startup"][1:], "import_ms"), med(a["startup"][1:], "import_ms")),
        ("RAG ready after import (ms)", med(b["startup"], "rag_ready_ms"), med(a["startup"], "rag_ready_ms")),
        ("First retrieval (ms)", cls_med(b, "retrieve"), cls_med(a, "retrieve")),
        ("Warm retrieval (ms)", cls_med(b, "warm_retrieve_ms"), cls_med(a, "warm_retrieve_ms")),
        ("Context construction (ms)", cls_med(b, "_build_prompt", "build_generation_context"),
         cls_med(a, "build_generation_context", "_build_prompt")),
        ("Prompt characters", cls_med(b, "prompt_chars"), cls_med(a, "prompt_chars")),
        ("Prompt tokens", cls_med(b, "prompt_tokens"), cls_med(a, "prompt_tokens")),
        ("Qwen prompt processing (ms)", cls_med(b, "qwen_prefill_ms"), cls_med(a, "qwen_prefill_ms")),
        ("Qwen generation total (ms)", cls_med(b, "_generate"), cls_med(a, "_generate")),
        ("Verification (ms)", cls_med(b, "verify_actions"), cls_med(a, "verify_actions")),
        ("Total recommendation (ms)", cls_med(b, "total_ms"), cls_med(a, "total_ms")),
        ("Recommendation cache hit (ms)", cls_med(b, "recommendation_cache_hit_ms"), cls_med(a, "recommendation_cache_hit_ms")),
    ]
    print(f"{'Metric':<34}{'Before':>14}{'After':>14}")
    for name, x, y in rows:
        fx = "--" if x is None else f"{x:,.1f}"
        fy = "--" if y is None else f"{y:,.1f}"
        print(f"{name:<34}{fx:>14}{fy:>14}")


if __name__ == "__main__":
    main()
