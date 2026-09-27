"""
run_pipeline.py
---------------
Runs every stage in scripts/ in order, with the arguments each one needs.

Each stage is a separate process, so a stage that dies cannot corrupt the
next one's memory, and the driver stops at the first failure rather than
carrying a broken artifact forward -- a half-written parquet feeding into
training is much worse than an early exit.

The stages already write their own timestamped logs to logs/, so this does
not duplicate them. It streams their output live and records what passed,
what failed, and how long each took.

RESUMING
The pipeline takes hours, most of it in the two training stages, so it is
built to be re-entered rather than restarted:

    --from 08        start at stage 08 and run to the end
    --only 03 04     run just these
    --skip 01 02     run everything except these
    --skip-done      skip any stage whose outputs already exist

--skip-done compares each stage's `consumes` against its `produces` by mtime,
so a stage whose inputs changed is re-run rather than skipped. Retraining
stage 05 therefore no longer leaves stage 06's metrics table describing models
that are gone.

It is a staleness check, not a build system: it compares timestamps, not
content, and it does not know that editing a SCRIPT invalidates that script's
outputs. After changing code, re-run the affected stages explicitly with
--from or --only.

ABOUT --quick
The default arguments are the ones the study calls for: five models across
three arms in stage 05, five models in stage 09. On a CPU-only machine the
two LSTM architectures dominate that by a wide margin and the full run takes
many hours. --quick substitutes MLP and XGBoost for the deep set and one arm
for three, which exercises every stage end to end in minutes. It produces a
PARTIAL experiment -- fine for checking the pipeline works, not for results.

Usage:
    python run_pipeline.py                 # the full study
    python run_pipeline.py --quick         # fast smoke run, partial results
    python run_pipeline.py --from 08       # resume from the multiclass half
    python run_pipeline.py --list          # show the plan and exit
    python run_pipeline.py --dry-run       # print the commands, run nothing
"""
import sys
import json
import time
import argparse
import subprocess
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
SCRIPTS = PROJECT_ROOT / "scripts"


def _git():
    """Commit and dirty flag, so a manifest points at the code that ran."""
    try:
        r = subprocess.run(["git", "rev-parse", "HEAD"], cwd=PROJECT_ROOT,
                           capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            return None
        st = subprocess.run(["git", "status", "--porcelain"],
                            cwd=PROJECT_ROOT, capture_output=True,
                            text=True, timeout=10)
        return {"commit": r.stdout.strip(),
                "dirty": bool(st.stdout.strip())}
    except Exception:
        return None


def _mtime(p):
    """Newest mtime at this path, recursing into directories."""
    p = Path(p)
    if p.is_dir():
        times = [f.stat().st_mtime for f in p.rglob("*") if f.is_file()]
        return max(times) if times else p.stat().st_mtime
    return p.stat().st_mtime


class Stage:
    def __init__(self, script, args=(), quick_args=None, produces=(),
                 consumes=(), note=""):
        self.script = script
        self.args = list(args)
        self.quick_args = None if quick_args is None else list(quick_args)
        self.produces = list(produces)
        self.consumes = list(consumes)
        self.note = note

    @property
    def key(self):
        return self.script.split("_")[0]

    # Stages that understand --resume: skip finished models, pick a
    # half-trained one up at its next epoch.
    RESUMABLE = ("05", "09", "12")

    def argv(self, quick, resume=False):
        a = list(self.quick_args if (quick and self.quick_args is not None)
                 else self.args)
        # --skip-done already means "carry on from where this left off", so
        # for the training stages it should mean that INSIDE a model too, not
        # only between models. Without it a Ctrl+C during a four-hour LSTM
        # costs the whole four hours on restart.
        if resume and self.key in self.RESUMABLE and "--resume" not in a:
            a.append("--resume")
        return a

    def done(self):
        """Outputs exist AND none of the inputs is newer than them.

        Existence alone is not enough. Retrain stage 05 and
        results/external_validation.csv still exists, so an existence check
        skips stage 06 and leaves a metrics table describing models that are
        no longer on disk -- silently, since nothing compares the two. Newest
        input against oldest output catches that.

        This is a staleness check, not a build system: it compares mtimes, not
        content, and it does not know that editing a script invalidates its
        outputs. After changing code, re-run the affected stages explicitly.
        """
        if not self.produces:
            return False
        outs = [PROJECT_ROOT / p for p in self.produces]
        if not all(o.exists() for o in outs):
            return False
        ins = [PROJECT_ROOT / c for c in self.consumes]
        ins = [i for i in ins if i.exists()]
        if not ins:
            return True
        return max(_mtime(i) for i in ins) <= min(_mtime(o) for o in outs)

    def stale_inputs(self):
        """Inputs newer than the oldest output, for the message."""
        outs = [PROJECT_ROOT / p for p in self.produces]
        if not self.produces or not all(o.exists() for o in outs):
            return []
        cut = min(_mtime(o) for o in outs)
        return [c for c in self.consumes
                if (PROJECT_ROOT / c).exists()
                and _mtime(PROJECT_ROOT / c) > cut]


# The order is a data dependency chain, not a preference: 04 needs all three
# interim parquets, 05 needs 04's frozen feature list, 06 needs 05's models,
# 08 needs 03's interim table, and 12 needs a detector from 05 as well as the
# splits from 08.
STAGES = [
    Stage("00_verify_environment.py",
          note="packages, GPU, datasets, schema intersection"),
    Stage("01_prepare_cicids2018.py",
          produces=["data/interim/cicids2018.parquet"],
          consumes=["data/raw/CICIDS2018"],
          note="ten day-files -> parquet (~4 min, reads 16.2M rows)"),
    Stage("02_prepare_tii.py",
          produces=["data/interim/tii_ssrc_23.parquet"],
          consumes=["data/raw/TII-SSRC-23"],
          note="data.csv -> parquet (~1.5 min, reads 8.7M rows)"),
    Stage("03_prepare_trustlab.py",
          produces=["data/interim/trustlab.parquet"],
          consumes=["data/raw/TRUSTLab"],
          note="sixteen class archives -> parquet (~2 min)"),
    Stage("04_align_and_build.py",
          produces=["artifacts/shared_features.pkl",
                    "data/processed/test_trustlab.parquet",
                    "data/processed/train_combined.parquet",
                    "data/processed/train_cicids_only.parquet",
                    "data/processed/train_tii_only.parquet"],
          consumes=["data/interim/cicids2018.parquet",
                    "data/interim/tii_ssrc_23.parquet",
                    "data/interim/trustlab.parquet"],
          note="freeze the shared feature list, build the splits"),
    Stage("05_train_binary.py", ["--all-arms"],
          quick_args=["--arm", "combined", "--models", "MLP", "XGBoost"],
          produces=["artifacts/combined/scaler.pkl"],
          consumes=["data/processed/train_combined.parquet",
                    "artifacts/shared_features.pkl"],
          note="binary models; the long one on CPU"),
    Stage("06_validate_external.py", ["--threshold-sweep"],
          produces=["results/external_validation.csv"],
          # All three arms: script 06 scores every arm it finds, so a model
          # added to any of them makes this table stale.
          consumes=["artifacts/combined", "artifacts/cicids_only",
                    "artifacts/tii_only",
                    "data/processed/test_trustlab.parquet"],
          note="apply every binary model to TRUSTLab"),
    Stage("07_aggregate_results.py",
          produces=["results/tables"],
          consumes=["results/external_validation.csv"],
          note="comparison tables for the results chapter"),
    Stage("08_build_multiclass.py", ["--strategy", "both"],
          produces=["data/processed/mc_train_random.parquet",
                    "data/processed/mc_test_random.parquet",
                    "data/processed/mc_train_temporal.parquet",
                    "data/processed/mc_test_temporal.parquet"],
          consumes=["data/interim/trustlab.parquet"],
          note="sixteen-class splits, random and temporal"),
    Stage("09_train_multiclass.py", ["--strategy", "random"],
          quick_args=["--strategy", "random", "--models", "XGBoost"],
          produces=["artifacts/mc_random/scaler.pkl"],
          consumes=["data/processed/mc_train_random.parquet"],
          note="sixteen-class models; the other long one"),
    Stage("10_evaluate_multiclass.py", ["--strategy", "random"],
          produces=["results/mc_summary_random.csv"],
          consumes=["artifacts/mc_random",
                    "data/processed/mc_test_random.parquet"],
          note="per-class results vs the published figures"),
    Stage("11_session_artifact_test.py",
          produces=["results/session_artifact_analysis.json"],
          consumes=["data/processed/mc_train_temporal.parquet",
                    "data/processed/mc_train_random.parquet"],
          note="random vs temporal split; needs both splits from 08"),
    Stage("12_phase2_protocol.py", ["--phase1", "all"],
          quick_args=["--phase1", "matched", "learned"],
          produces=["results/phase2_random/phase1_matched.json"],
          consumes=["artifacts/combined",
                    "data/processed/mc_train_random.parquet"],
          note="matched-protocol comparison; needs 05 and 08"),
]

# Deliberately not in the chain. TRUSTLab's split archives and its one
# truncated archive are handled in place by src/trustlab_io.py, so converting
# is never required to run the pipeline. Run it by hand if you want a
# canonical copy for other tools.
OPTIONAL = []   # convert_trustlab.py moved to scripts_other/


def main():
    ap = argparse.ArgumentParser(
        description="Run every pipeline stage in order.")
    ap.add_argument("--quick", action="store_true",
                    help="lighter model sets; PARTIAL results, for checking "
                         "the pipeline runs")
    ap.add_argument("--from", dest="start", metavar="NN",
                    help="start at this stage number and continue")
    ap.add_argument("--only", nargs="+", metavar="NN",
                    help="run only these stage numbers")
    ap.add_argument("--skip", nargs="+", default=[], metavar="NN",
                    help="skip these stage numbers")
    ap.add_argument("--skip-done", action="store_true",
                    help="skip stages whose outputs already exist")
    ap.add_argument("--continue-on-error", action="store_true",
                    help="keep going after a stage fails (default: stop)")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the commands without running them")
    ap.add_argument("--list", action="store_true",
                    help="show the plan and exit")
    args = ap.parse_args()

    missing = [s.script for s in STAGES if not (SCRIPTS / s.script).exists()]
    if missing:
        print(f"Missing from {SCRIPTS}: {missing}", file=sys.stderr)
        return 2

    plan = list(STAGES)
    if args.only:
        want = set(args.only)
        plan = [s for s in plan if s.key in want]
    elif args.start:
        keys = [s.key for s in plan]
        if args.start not in keys:
            print(f"--from {args.start}: no such stage. "
                  f"Stages are {keys}", file=sys.stderr)
            return 2
        plan = plan[keys.index(args.start):]
    plan = [s for s in plan if s.key not in set(args.skip)]

    if args.list or args.dry_run:
        print(f"{'stage':<30}{'args':<44}{'status'}")
        for s in plan:
            if args.skip_done and s.key in Stage.RESUMABLE:
                state = "run (self-skips finished models)"
            elif args.skip_done and s.done():
                state = "would skip (up to date)"
            elif args.skip_done and s.stale_inputs():
                state = f"run (stale: {', '.join(s.stale_inputs())})"
            else:
                state = "run"
            print(f"  {s.script:<28}"
                  f"{' '.join(s.argv(args.quick, args.skip_done)):<44}{state}")
            if s.note:
                print(f"      {s.note}")
        print(f"\nNot run automatically: {OPTIONAL}")
        if args.quick:
            print("\n--quick is on: stages 05, 09 and 12 use reduced "
                  "settings and the results are PARTIAL.")
        return 0

    if args.quick:
        print("=" * 72)
        print("--quick: stages 05, 09 and 12 run reduced model sets.")
        print("This checks that the pipeline runs. It does NOT produce the "
              "study's results.")
        print("=" * 72)

    results, failed, cmds = [], [], []
    t_all = time.time()
    for i, s in enumerate(plan, 1):
        head = f"[{i}/{len(plan)}] {s.script}"
        # A resumable stage is never skipped by the driver, because the
        # driver cannot see inside it. Stage 05 declares one scaler file
        # as its output, so an existence check calls it done while
        # tii_only/CNN_BiLSTM is still missing. The script knows exactly
        # which models exist; with --resume it skips the finished ones
        # itself in seconds and trains only what is absent. Let it decide.
        if args.skip_done and s.done() and s.key not in Stage.RESUMABLE:
            print(f"\n{'=' * 72}\n{head}  -- SKIPPED, outputs already exist"
                  f"\n{'=' * 72}", flush=True)
            results.append((s.script, "skipped", 0.0))
            cmds.append(s.argv(args.quick, args.skip_done))
            continue

        cmd = [sys.executable, str(SCRIPTS / s.script),
               *s.argv(args.quick, args.skip_done)]
        print(f"\n{'=' * 72}\n{head}\n  {' '.join(cmd[1:])}\n{'=' * 72}",
              flush=True)
        t0 = time.time()
        try:
            # Output is inherited rather than captured: the stages already
            # write their own logs to logs/, and streaming live matters more
            # than a second transcript on a run this long.
            rc = subprocess.run(cmd, cwd=PROJECT_ROOT).returncode
        except KeyboardInterrupt:
            secs = time.time() - t0
            print(f"\nInterrupted during {s.script} after {secs:.0f}s.")
            print(f"Resume with:  python run_pipeline.py --from {s.key}")
            return 130
        secs = time.time() - t0

        if rc == 0:
            print(f"-- {s.script} ok ({secs:.0f}s)")
            results.append((s.script, "ok", secs))
            cmds.append(cmd[2:])
        else:
            print(f"-- {s.script} FAILED (exit {rc}, {secs:.0f}s)")
            results.append((s.script, f"failed({rc})", secs))
            cmds.append(cmd[2:])
            failed.append(s)
            if not args.continue_on_error:
                print(f"\nStopping. Later stages consume this one's output, "
                      f"so running them now would build on nothing.")
                print(f"Fix it, then resume with:  "
                      f"python run_pipeline.py --from {s.key}")
                break

    # Machine-readable record of the run. The per-stage logs say what each
    # stage did; this says which stages ran, in what order, with which
    # arguments, and whether they succeeded -- what you need months later to
    # attribute a number in the write-up to a specific execution.
    manifest = {"started": datetime.fromtimestamp(t_all).isoformat(timespec="seconds"),
                "finished": datetime.now().isoformat(timespec="seconds"),
                "total_seconds": round(time.time() - t_all, 1),
                "python": sys.version.split()[0],
                "git": _git(),
                "quick": bool(args.quick), "skip_done": bool(args.skip_done),
                "stages": [{"script": n, "status": st, "seconds": round(sec, 1),
                            "args": a}
                           for (n, st, sec), a in zip(results, cmds)]}
    try:
        import importlib.metadata as md
        manifest["packages"] = {k: md.version(k) for k in (
            "pandas", "numpy", "scikit-learn", "torch", "xgboost", "pyarrow")}
    except Exception:
        pass
    run_dir = PROJECT_ROOT / "results" / "runs"
    run_dir.mkdir(parents=True, exist_ok=True)
    mpath = run_dir / ("run_" + manifest["started"].replace(":", "").replace("-", "") + ".json")
    with open(mpath, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)

    print(f"\n{'=' * 72}\nSUMMARY  ({time.time() - t_all:.0f}s total)"
          f"\n{'=' * 72}")
    for name, state, secs in results:
        print(f"  {name:<32}{state:<14}{secs:>8.0f}s")
    print(f"\nManifest -> {mpath}")
    if failed:
        print(f"\n{len(failed)} stage(s) failed: "
              f"{[s.script for s in failed]}")
        print("Their own logs in logs/ carry the detail.")
        return 1
    ran = [r for r in results if r[1] == "ok"]
    print(f"\nAll {len(ran)} stage(s) that ran completed.")
    if args.quick:
        print("Reduced settings were used -- these are not the study's "
              "results. Re-run without --quick for those.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
