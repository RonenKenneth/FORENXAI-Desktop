"""
Reading TRUSTLab's archives.

Two things about these files break a plain pd.read_csv, and both are silent
rather than loud, so they live here where every script that touches TRUSTLab
picks up the same handling.

SPLIT ARCHIVES
API, Benign, TLSSSL and WebBased ship as 24 MiB parts -- NAME.csv.gz.001,
.002, and so on, seventeen of them for Benign. They are a raw byte split of
one gzip stream, not independent archives: only .001 carries the gzip magic
(1f 8b), and the rest begin mid-deflate-block. Handing a part to gzip fails,
and globbing "*.csv.gz" skips those four folders entirely -- which silently
drops Benign, the only class the binary experiment scores benign recall on.
_JoinedParts feeds the parts to one decompressor in order, which is what
`cat NAME.csv.gz.* > NAME.csv.gz` produces, without the manual step and
without a second 640 MB copy on disk.

A TRUNCATED ARCHIVE
PortScan.csv.gz fails `gzip -t`: the deflate stream ends mid-block with no
trailer. Read through gzip's own reader that surfaces as an EOFError partway
in, and letting it propagate out of pd.read_csv(chunksize=...) loses the WHOLE
class rather than just the tail -- the error arrives while the first
200,000-row chunk is still being filled, and PortScan holds only ~107,600
rows, so no chunk is ever yielded and the class disappears from the run behind
a warning that reads like a small problem. _TolerantGunzip ends the stream at
the break instead, discards the half-written final line (60 bytes), and
recovers the 107,579 rows that did decompress -- 33,361,541 of the
33,361,601 bytes that survive in the archive.
"""
import io
import zlib

# gzip.BadGzipFile subclasses OSError; zlib.error subclasses neither. Callers
# catch this as a belt-and-braces measure -- _TolerantGunzip does not raise on
# truncation itself.
TRUNCATION_ERRORS = (EOFError, OSError, zlib.error)

# Buffer size for the BufferedReader wrappers, large enough that the
# whole-line buffering below copies once per megabyte, not once per 8 KB read.
BUF = 1 << 20

# Compressed bytes pulled from disk per decompress step.
READ_BYTES = 1 << 18

NEWLINE = b"\n"


class _JoinedParts(io.RawIOBase):
    """The numbered parts of one archive, read back to back as one stream."""

    def __init__(self, paths):
        self._paths = list(paths)
        self._i = 0
        self._fh = open(self._paths[0], "rb")

    def readable(self):
        return True

    def readinto(self, buf):
        while self._fh is not None:
            n = self._fh.readinto(buf)
            if n:
                return n
            self._fh.close()             # this part is spent, move to the next
            self._i += 1
            self._fh = (open(self._paths[self._i], "rb")
                        if self._i < len(self._paths) else None)
        return 0

    def close(self):
        try:
            if self._fh is not None and not self._fh.closed:
                self._fh.close()
        finally:
            self._fh = None
            super().close()


class _TolerantGunzip(io.RawIOBase):
    """Decompress a gzip stream, stopping cleanly if it is truncated.

    This drives zlib directly rather than going through gzip.GzipFile, and the
    reason is worth writing down. GzipFile.read(n) raises EOFError when it runs
    off the end of a truncated member, and the bytes it had already
    decompressed during that same call are lost with the exception. How much
    that costs depends entirely on who is reading: pandas reads in small pieces
    and loses nothing, a bulk reader asking for 4 MB at a time loses about
    2 MB, and one asking for 16 MB loses 14 MB. Same file, same code, a
    different row count depending on the caller, and no error anywhere -- which
    is how two parts of this pipeline came to disagree about how much of
    PortScan survived.

    A decompressobj has no such failure mode. Truncation is not an exception to
    it, just the input running out before the trailer arrives, and every byte
    that decompressed is already in hand. `truncated` records that it happened.

    While the stream is still open only complete lines are handed out, so the
    half-written final line of a truncated file can be dropped rather than
    parsed into a row of misaligned values.
    """

    def __init__(self, fileobj):
        self._raw = fileobj
        self._d = zlib.decompressobj(31)      # 31 = expect a gzip wrapper
        self._buf = b""
        self._exhausted = False
        self.truncated = False

    def readable(self):
        return True

    def _pump(self):
        """Decompress the next block, or return b'' once the input is spent."""
        while not self._exhausted:
            chunk = self._raw.read(READ_BYTES)
            if not chunk:
                # Input ended. A member that never reached its trailer was cut
                # short somewhere upstream of us.
                if not self._d.eof:
                    self.truncated = True
                self._exhausted = True
                return b""
            try:
                out = self._d.decompress(chunk)
                if self._d.eof and self._d.unused_data.strip(b"\x00"):
                    # Concatenated members: start the next on the leftovers.
                    rest = self._d.unused_data
                    self._d = zlib.decompressobj(31)
                    out += self._d.decompress(rest)
            except zlib.error:
                self.truncated = True
                self._exhausted = True
                return b""
            if out:
                return out
        return b""

    def _fill(self, want):
        while not self._exhausted and (len(self._buf) < want
                                       or NEWLINE not in self._buf):
            piece = self._pump()
            if not piece:
                break
            self._buf += piece
        if self.truncated:
            # Drop the partial final line. Idempotent: once cut, the buffer
            # ends on a newline and later calls find nothing to remove.
            cut = self._buf.rfind(NEWLINE)
            self._buf = self._buf[:cut + 1]

    def readinto(self, buf):
        want = len(buf)
        self._fill(want)
        avail = (len(self._buf) if self._exhausted
                 else self._buf.rfind(NEWLINE) + 1)
        n = min(want, avail)
        buf[:n] = self._buf[:n]
        self._buf = self._buf[n:]
        return n

    def close(self):
        try:
            self._raw.close()
        finally:
            super().close()


def open_class(paths):
    """Open one class as decompressed bytes. Returns (stream, gunzip_or_None).

    The second value exposes `.truncated` once the read is finished.
    """
    paths = list(paths)
    if paths[0].suffix == ".csv":
        return open(paths[0], "rb"), None
    raw = (open(paths[0], "rb") if len(paths) == 1
           else io.BufferedReader(_JoinedParts(paths), buffer_size=BUF))
    gunzip = _TolerantGunzip(raw)
    return io.BufferedReader(gunzip, buffer_size=BUF), gunzip


def class_sources(root):
    """Map each class folder to its ordered file list, plus any problems found.

    A joined NAME.csv.gz wins over the parts it was made from, so a folder
    someone already joined by hand still works. Otherwise the numbered parts
    are used in order, and a gap in the numbering is fatal for that class: a
    missing part corrupts the deflate stream silently rather than loudly,
    which is worse than not loading the class at all.
    """
    found, problems, notes = {}, [], []
    for folder in sorted(p for p in root.iterdir() if p.is_dir()):
        whole = sorted(folder.glob("*.csv.gz")) + sorted(folder.glob("*.csv"))
        parts = sorted(folder.glob("*.csv.gz.[0-9][0-9][0-9]"))
        if whole:
            found[folder.name] = whole[:1]
            if parts:
                notes.append(f"{folder.name}: using joined {whole[0].name} "
                             f"({len(parts)} parts also present, ignored)")
        elif parts:
            stem = parts[0].name[:-3]
            expected = [f"{stem}{i:03d}" for i in range(1, len(parts) + 1)]
            if [p.name for p in parts] != expected:
                problems.append(
                    f"{folder.name}: parts are not a contiguous 001..."
                    f"{len(parts):03d} sequence -- found "
                    f"{[p.name for p in parts]}")
                continue
            found[folder.name] = parts
        else:
            problems.append(f"{folder.name}: no .csv.gz, .csv or .csv.gz.NNN "
                            f"files in {folder}")
    return found, problems, notes


def read_header(paths):
    """The stripped column names of one class, without reading its data."""
    import pandas as pd
    stream, _ = open_class(paths)
    try:
        return pd.read_csv(stream, nrows=0).columns.str.strip().tolist()
    finally:
        stream.close()
