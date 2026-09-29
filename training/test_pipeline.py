"""
test_pipeline.py
----------------
Plain asserts over the three pieces of logic in this repo that are non-obvious
enough to break silently. No framework, no fixtures:  python test_pipeline.py

Covers, and only covers, what would fail quietly rather than loudly:

  Reservoir          a biased sample still returns the right NUMBER of rows,
                     and a shuffled one still returns the right rows -- so a
                     regression shows up as a slightly different result, not
                     an error.
  per_class_f1_ci    a wrong interval is still an interval.
  trustlab_io        the reader that lost data depending on the CALLER's read
                     size. Two callers, two row counts, no exception anywhere.

Everything else in the pipeline fails loudly and needs no guard here.
"""
import io
import gzip
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from src.common import Reservoir, clean_block
from src.metrics import per_class_f1_ci
from src.trustlab_io import _JoinedParts, _TolerantGunzip, open_class


def test_reservoir_samples_uniformly():
    """Sample mean tracks stream mean. A head-biased sample would not."""
    n, cap = 200_000, 2_000
    r = Reservoir(cap, 1, seed=1)
    for i in range(0, n, 7_000):
        blk = np.arange(i, min(i + 7_000, n), dtype=np.float32).reshape(-1, 1)
        r.add(blk)
    v = r.rows[:, 0]
    assert r.filled == cap, r.filled
    assert r.seen == n, r.seen
    # Uniform over 0..n-1 has mean (n-1)/2. Head bias would sit far below.
    assert abs(v.mean() - (n - 1) / 2) < n * 0.02, v.mean()
    assert v.min() < n * 0.05 and v.max() > n * 0.95, (v.min(), v.max())


def test_reservoir_keeps_everything_below_cap():
    r = Reservoir(1_000, 1, seed=1)
    r.add(np.arange(400, dtype=np.float32).reshape(-1, 1))
    assert r.filled == 400 and r.seen == 400
    assert np.array_equal(r.rows[:, 0], np.arange(400, dtype=np.float32))


def test_reservoir_restores_capture_order():
    """Scripts 08 and 11 split on row order. Slot order would look shuffled."""
    n, cap = 50_000, 500
    r = Reservoir(cap, 1, seed=2, tags=True)
    for i in range(0, n, 3_000):
        blk = np.arange(i, min(i + 3_000, n), dtype=np.float32).reshape(-1, 1)
        tags = np.array([f"t{int(x)}" for x in blk[:, 0]], dtype=object)
        r.add(blk, tags)
    rows, tags = r.rows_in_order()
    v = rows[:, 0]
    assert np.all(np.diff(v) > 0), "rows_in_order must be strictly increasing"
    assert all(t == f"t{int(x)}" for t, x in zip(tags, v)), "tags misaligned"


def test_clean_block_drops_header_rows_and_infinities():
    df = pd.DataFrame({"a": ["1", "x", "3"], "b": ["2", "y", np.inf]})
    m, keep = clean_block(df, ["a", "b"])
    assert keep.tolist() == [True, False, True], keep
    assert m.shape == (2, 2) and m.dtype == np.float32
    assert m[1, 1] == 0.0, "infinity should become 0, not stay inf"


def test_ci_widens_as_support_shrinks():
    rng = np.random.default_rng(0)
    widths = []
    for n in (40, 400, 40_000):
        y = rng.integers(0, 2, n)
        p = np.where(rng.random(n) < 0.8, y, 1 - y)
        c = per_class_f1_ci(y, p, 2, n_boot=500, seed=3)["per_class"][1]
        assert c["ci_low"] <= c["ci_high"]
        widths.append(c["ci_width"])
    assert widths[0] > widths[1] > widths[2], widths


def test_ci_is_degenerate_on_a_perfect_small_sample():
    """Why script 12 needs MIN_SUPPORT as well as a width test: with no errors
    to resample, the bootstrap reports zero uncertainty on 11 rows."""
    y = np.ones(11, dtype=int)
    c = per_class_f1_ci(y, y.copy(), 2, n_boot=200, seed=4)["per_class"][1]
    assert c["ci_width"] == 0.0, c
    assert c["support"] == 11


def _gz(payload):
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as fh:
        fh.write(payload)
    return buf.getvalue()


def test_joined_parts_concatenates_byte_exactly():
    blob = bytes(range(256)) * 5_000
    parts = [blob[i:i + 7_777] for i in range(0, len(blob), 7_777)]
    tmp = Path(__file__).parent / "_t_parts"
    tmp.mkdir(exist_ok=True)
    paths = []
    for i, p in enumerate(parts, 1):
        f = tmp / f"x.csv.gz.{i:03d}"
        f.write_bytes(p)
        paths.append(f)
    try:
        got = io.BufferedReader(_JoinedParts(paths)).read()
        assert got == blob, (len(got), len(blob))
    finally:
        for f in paths:
            f.unlink()
        tmp.rmdir()


def test_truncated_gzip_is_read_the_same_at_every_read_size():
    """The regression that mattered: GzipFile.read(n) discards already
    decompressed bytes when it raises, so the recovered row count depended on
    how much the caller asked for. Small reads lost nothing, 4 MB reads lost
    about 2 MB, and nothing raised."""
    body = b"".join(b"%d,%d,%d\r\n" % (i, i * 2, i * 3) for i in range(200_000))
    cut = _gz(b"a,b,c\r\n" + body)[:-400]        # drop the trailer and some data

    lengths, flags = set(), set()
    for size in (4_096, 1 << 20, 1 << 22, 1 << 24):
        s = _TolerantGunzip(io.BytesIO(cut))
        out, n = io.BufferedReader(s), 0
        while True:
            b = out.read(size)
            if not b:
                break
            n += len(b)
        lengths.add(n)
        flags.add(s.truncated)
    assert len(lengths) == 1, f"read size changed the output: {lengths}"
    assert flags == {True}, "truncation must be reported"
    n = lengths.pop()
    assert n > 0, "a truncated archive must still yield its readable prefix"
    # The partial final line is dropped, so what survives ends cleanly.
    s = _TolerantGunzip(io.BytesIO(cut))
    assert io.BufferedReader(s).read().endswith(b"\n")


def test_intact_gzip_is_not_flagged_truncated():
    raw = b"a,b\r\n" + b"".join(b"%d,%d\r\n" % (i, i) for i in range(10_000))
    s = _TolerantGunzip(io.BytesIO(_gz(raw)))
    got = io.BufferedReader(s).read()
    assert got == raw, (len(got), len(raw))
    assert s.truncated is False


def test_real_portscan_still_yields_its_known_row_count():
    """Optional: pins the recovered count if the data is present."""
    from config.settings import TRUSTLAB_DIR
    from src.trustlab_io import class_sources
    if not TRUSTLAB_DIR.exists():
        return "skipped (no data)"
    src, _, _ = class_sources(TRUSTLAB_DIR)
    if "PortScan" not in src:
        return "skipped (no PortScan)"
    stream, gz = open_class(src["PortScan"])
    rows = sum(len(c) for c in pd.read_csv(stream, chunksize=200_000,
                                           low_memory=False))
    stream.close()
    assert gz.truncated is True
    assert rows == 107_579, f"PortScan recovered {rows:,}, expected 107,579"
    return None


def test_driver_detects_stale_inputs():
    """The guard that stops a metrics table describing models that changed."""
    import os, time
    import run_pipeline as rp
    tmp = Path(__file__).parent / "_t_stale"
    tmp.mkdir(exist_ok=True)
    src, out = tmp / "in.txt", tmp / "out.txt"
    try:
        src.write_text("x")
        out.write_text("y")
        st = rp.Stage("x.py", produces=[str(out.relative_to(rp.PROJECT_ROOT))],
                      consumes=[str(src.relative_to(rp.PROJECT_ROOT))])
        assert st.done(), "output newer than input must count as up to date"
        assert st.stale_inputs() == []
        time.sleep(0.01)
        os.utime(src, None)                    # input touched after the output
        assert not st.done(), "a newer input must make the stage stale"
        assert st.stale_inputs(), "the stale input should be named"
    finally:
        for f in (src, out):
            if f.exists():
                f.unlink()
        tmp.rmdir()


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for t in tests:
        try:
            note = t()
            print(f"  ok    {t.__name__}" + (f"  -- {note}" if note else ""))
        except AssertionError as e:
            failed += 1
            print(f"  FAIL  {t.__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
