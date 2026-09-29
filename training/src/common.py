"""Shared helpers: logging, seeding, cleaning, results IO."""
import sys
import json
import random
import logging
from pathlib import Path
from datetime import datetime

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config.settings import LOGS_DIR, RESULTS_DIR, SEED


def get_logger(name):
    """Console + timestamped file logging, so every run leaves a record."""
    log = logging.getLogger(name)
    if log.handlers:
        return log
    log.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s | %(levelname)-7s | %(message)s",
                            datefmt="%H:%M:%S")
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    log.addHandler(sh)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = LOGS_DIR / f"{name}_{stamp}.log"
    fh = logging.FileHandler(path, encoding="utf-8")
    fh.setFormatter(fmt)
    log.addHandler(fh)
    _log_provenance(log, path)
    return log


def _git_state():
    """Commit the code was at, and whether it had uncommitted edits.

    A result is only attributable if you can get back to the code that made
    it. "dirty" is the important half: it means the working tree differed
    from the commit, so the hash alone will not reproduce this run.
    """
    import subprocess
    try:
        root = Path(__file__).resolve().parent.parent
        rev = subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                             cwd=root, capture_output=True, text=True,
                             timeout=10)
        if rev.returncode != 0:
            return "not a git repository"
        st = subprocess.run(["git", "status", "--porcelain"], cwd=root,
                            capture_output=True, text=True, timeout=10)
        dirty = bool(st.stdout.strip())
        return (f"{rev.stdout.strip()}"
                + ("  DIRTY -- uncommitted changes, this run is not "
                   "reproducible from the hash alone" if dirty else " (clean)"))
    except Exception as e:
        return f"unavailable ({type(e).__name__})"


def _log_provenance(log, path):
    """Record what produced this log, at the top of it.

    Timestamps on the lines below carry no date, and nothing else recorded
    which arguments, package versions or seed were in force. Months later
    that is the difference between a result you can attribute and a file of
    numbers. It goes in get_logger because every script already calls that,
    so no stage can forget to do it.
    """
    import importlib.metadata as md
    vers = []
    for pkg in ("pandas", "numpy", "scikit-learn", "torch", "xgboost",
                "pyarrow", "joblib"):
        try:
            vers.append(f"{pkg} {md.version(pkg)}")
        except Exception:
            pass
    log.info("=" * 72)
    log.info(f"RUN  {datetime.now().isoformat(timespec='seconds')}")
    log.info(f"  command : {sys.executable} {' '.join(sys.argv)}")
    log.info(f"  cwd     : {Path.cwd()}")
    log.info(f"  python  : {sys.version.split()[0]}")
    log.info(f"  packages: {', '.join(vers)}")
    log.info(f"  seed    : {SEED}")
    log.info(f"  code    : {_git_state()}")
    log.info(f"  log file: {path}")
    log.info("=" * 72)


def banner(log, text):
    log.info("=" * 72)
    log.info(text)
    log.info("=" * 72)


def set_seed(seed=SEED):
    """
    Seed every source of randomness. cuDNN is set to deterministic mode, which
    costs a little speed but makes GPU results repeatable -- necessary if the
    numbers are going into a thesis.
    """
    random.seed(seed)
    np.random.seed(seed)
    try:
        import torch
        torch.manual_seed(seed)
        torch.cuda.manual_seed_all(seed)
        torch.backends.cudnn.deterministic = True
        torch.backends.cudnn.benchmark = False
    except ImportError:
        pass


def clean_features(df, feature_cols):
    """
    Coerce to numeric, replace infinities, fill gaps, cast to float32.

    Infinities arise in CICFlowMeter's rate columns (Flow Bytes/s, Flow
    Packets/s) whenever flow duration is zero. Filling with 0 rather than
    dropping the row is deliberate: at inference a forensic tool cannot
    discard flows an investigator may need to see, so training should reflect
    the same handling.
    """
    X = df[feature_cols].apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    return X.astype("float32")


def clean_block(df, feature_cols):
    """
    Chunk -> (float32 matrix over `feature_cols`, boolean mask of rows kept).

    The same cleaning as clean_features, in the form the streaming loaders
    need: a matrix they can put straight into a Reservoir, and a mask so the
    labels they carry alongside stay aligned.

    Rows where nothing at all parsed as a number are dropped rather than
    filled with zeros. Those are embedded header lines -- CICIDS2018 has 59 of
    them pasted in as data -- and a header row filled with zeros is a fake
    flow the model would train on.
    """
    d = df[feature_cols].apply(pd.to_numeric, errors="coerce")
    d = d.replace([np.inf, -np.inf], np.nan)
    keep = d.notna().any(axis=1).to_numpy()
    return d.to_numpy(dtype=np.float32, na_value=0.0)[keep], keep


class Reservoir:
    """
    A uniform random sample of fixed size from a stream of unknown length.

    Algorithm R, fed a block of rows at a time: the first `cap` rows fill the
    reservoir, then row i (zero-based) replaces a uniformly chosen slot with
    probability cap/(i+1). Every row the stream produced is equally likely to
    survive, in one pass and fixed memory.

    This is what lets the loaders read files they cannot hold. CICIDS2018 is
    16.2 million rows -- about 10 GB once concatenated as float32, on top of
    whatever the machine is already using -- and TRUSTLab's Benign class is
    2.6 million. Both are capped long before a model sees them, so the only
    question is whether the rows that survive are a fair draw or just the
    first ones in the file. Taking the head is not a fair draw: TRUSTLab's
    Benign file is ordered by capture session, and CICIDS2018's day-files are
    ordered by time.

    Pass tags=True to carry a per-row string alongside the numbers, which is
    how the original attack-family label follows a sampled row.

    Every retained row also keeps the position it held in the stream, so
    rows_in_order() can hand the sample back in the order it was read. That
    matters wherever row order carries meaning. TRUSTLab's files are in
    capture order, and the multiclass temporal split (scripts 08 and 11) puts
    early flows in train and late flows in test to separate capture sessions.
    A sample left in reservoir-slot order looks shuffled, and that split would
    quietly become a second random split -- reporting "no session artifacts"
    for the wrong reason, which is worse than reporting nothing.
    """

    def __init__(self, cap, n_cols, seed=SEED, tags=False):
        self.cap = cap
        self.seen = 0
        self.filled = 0
        self._rows = np.empty((cap, n_cols), dtype=np.float32)
        self._tags = np.empty(cap, dtype=object) if tags else None
        self._pos = np.empty(cap, dtype=np.int64)
        self._rng = np.random.default_rng(seed)

    def add(self, block, tags=None):
        """Offer a block of rows (and optionally their tags) to the sample."""
        if self.filled < self.cap and len(block):
            take = min(self.cap - self.filled, len(block))
            self._rows[self.filled:self.filled + take] = block[:take]
            if self._tags is not None:
                self._tags[self.filled:self.filled + take] = tags[:take]
            self._pos[self.filled:self.filled + take] = np.arange(
                self.seen, self.seen + take)
            self.filled += take
            self.seen += take
            block = block[take:]
            if tags is not None:
                tags = tags[take:]

        if len(block):
            idx = np.arange(self.seen, self.seen + len(block))
            slot = self._rng.integers(0, idx + 1)
            hit = slot < self.cap
            if hit.any():
                # Where a slot is drawn twice in one block, the last write
                # wins -- the same answer row-at-a-time Algorithm R gives.
                self._rows[slot[hit]] = block[hit]
                self._pos[slot[hit]] = idx[hit]
                if self._tags is not None:
                    self._tags[slot[hit]] = tags[hit]
            self.seen += len(block)

    @property
    def rows(self):
        return self._rows[:self.filled]

    @property
    def tags(self):
        return None if self._tags is None else self._tags[:self.filled]

    def rows_in_order(self):
        """(rows, tags) restored to the order the stream produced them in."""
        order = np.argsort(self._pos[:self.filled], kind="stable")
        tags = None if self._tags is None else self._tags[:self.filled][order]
        return self._rows[:self.filled][order], tags


def feature_ids(df, feature_cols):
    """One id per distinct feature vector. Rows with equal ids are copies."""
    return pd.util.hash_pandas_object(clean_features(df, feature_cols),
                                      index=False).values


def group_split(y, groups, test_size, seed=SEED):
    """
    Stratified split that never separates rows sharing a group id.

    A random split of data with exact duplicates puts copies on both sides, so
    the held-out score partly measures memorisation. Grouping by feature
    vector (see feature_ids) closes that gap. Returns (train_idx, test_idx).

    Within each class, whole groups are shuffled and moved to the test side
    until it holds test_size of that class's rows (to within one group).
    sklearn's StratifiedGroupKFold does the same job but takes tens of minutes
    at a million distinct groups.
    """
    y = np.asarray(y)
    df = pd.DataFrame({"g": groups, "y": y})
    # One label per group. Copies that carry conflicting labels stay together;
    # the first row's label decides which class's quota they count toward.
    per = df.groupby("g", sort=False).agg(y=("y", "first"), n=("y", "size"))
    rng = np.random.default_rng(seed)
    test_groups = []
    for _cls, sub in per.groupby("y", sort=False):
        order = rng.permutation(len(sub))
        n = sub["n"].values[order]
        cum = np.cumsum(n)
        target = test_size * n.sum()
        k = int(np.searchsorted(cum, target))
        if k >= len(cum):
            k = len(cum) - 1
        elif k > 0 and abs(cum[k - 1] - target) <= abs(cum[k] - target):
            k -= 1
        test_groups.append(sub.index.values[order][:k + 1])
    is_test = np.isin(df["g"].values, np.concatenate(test_groups))
    return np.flatnonzero(~is_test), np.flatnonzero(is_test)


def check_no_leakage(ids_a, ids_b, log, label, enforce=True):
    """Count rows of b whose feature vector also occurs in a."""
    n = int(np.isin(ids_b, ids_a).sum())
    msg = (f"Leakage check ({label}): {n:,} of {len(ids_b):,} rows have an "
           f"exact copy on the other side")
    if n and enforce:
        log.error(msg)
        raise SystemExit(1)
    log.info(msg)
    return n


def stratified_cap(df, label_col, cap, seed=SEED):
    """Take at most `cap` rows per class. Classes below the cap are kept whole."""
    parts = [g.sample(n=min(len(g), cap), random_state=seed)
             for _, g in df.groupby(label_col)]
    return (pd.concat(parts, ignore_index=True)
              .sample(frac=1, random_state=seed)
              .reset_index(drop=True))


def save_json(payload, *parts):
    path = RESULTS_DIR.joinpath(*parts)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str)
    return path


def load_json(*parts):
    path = RESULTS_DIR.joinpath(*parts)
    if not path.exists():
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def human(n):
    return f"{n:,}"
