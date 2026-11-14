#!/usr/bin/env python3
"""Read AInception release zips on Zenodo with HTTP range requests (no full download).

  ls  <zip-name> [--grep REGEX]           list members (size raw / compressed)
  get <zip-name> --grep REGEX --out DIR   extract only matching members into DIR (keeps zip paths)
  get <zip-name> --grep REGEX --out DIR --local PATH   same selection from a zip already on disk

Zenodo answers Range requests with 206, so zipfile can seek over the network: only the central
directory (end of file) and the selected members are transferred.
"""
from __future__ import annotations

import argparse
import io
import re
import struct
import sys
import time
import urllib.error
import urllib.request
import zipfile
import zlib
from pathlib import Path

BASE = "https://zenodo.org/records/17659656/files/{}?download=1"
BLOCK = 1 << 20
_next_ok = 0.0          # Zenodo allows 133 requests/min per IP; wait here before the next request when nearly used up


def _wait_seconds(headers, default):
    try:
        w = float(headers.get("x-ratelimit-reset")) - time.time() + 1
        if 0 < w < 600:
            return w
    except (TypeError, ValueError):
        pass
    try:
        return float(headers.get("retry-after"))
    except (TypeError, ValueError):
        return default


def urlopen_limited(req, tries=8):
    """urlopen that respects x-ratelimit-* and retries 429/5xx and dropped connections."""
    global _next_ok
    for k in range(tries):
        if time.time() < _next_ok:
            time.sleep(_next_ok - time.time())
        try:
            r = urllib.request.urlopen(req, timeout=120)
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503, 504) and k < tries - 1:
                w = _wait_seconds(e.headers, 30 * (k + 1))
                print(f"# HTTP {e.code}, waiting {w:.0f}s", file=sys.stderr, flush=True)
                _next_ok = time.time() + w
                continue
            raise
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            if k < tries - 1:
                print(f"# {e!r}, retrying", file=sys.stderr, flush=True)
                _next_ok = time.time() + 10 * (k + 1)
                continue
            raise
        rem = r.headers.get("x-ratelimit-remaining")
        if rem is not None and int(rem) <= 3:
            _next_ok = time.time() + _wait_seconds(r.headers, 60)
        return r
    raise IOError("unreachable")


def _read_exact(r, n):
    out = b""
    while len(out) < n:
        chunk = r.read(n - len(out))
        if not chunk:
            raise IOError("short read")
        out += chunk
    return out


class HttpRangeFile(io.RawIOBase):
    def __init__(self, url):
        self.url, self.pos, self.cache, self.fetched = url, 0, {}, 0
        req = urllib.request.Request(url, method="HEAD")
        with urlopen_limited(req) as r:
            self.size = int(r.headers["Content-Length"])

    def seekable(self):
        return True

    def readable(self):
        return True

    def tell(self):
        return self.pos

    def seek(self, off, whence=0):
        self.pos = off if whence == 0 else (self.pos + off if whence == 1 else self.size + off)
        return self.pos

    def _range(self, a, b):
        req = urllib.request.Request(self.url, headers={"Range": f"bytes={a}-{b}"})
        with urlopen_limited(req) as r:
            if r.status != 206:
                raise IOError(f"server ignored Range (HTTP {r.status})")
            data = r.read()
        self.fetched += len(data)
        return data

    def read(self, n=-1):
        if n is None or n < 0:
            n = self.size - self.pos
        n = min(n, self.size - self.pos)
        if n <= 0:
            return b""
        if len(self.cache) > 64:                # only the central directory is read through here
            self.cache.clear()
        out, p, end = [], self.pos, self.pos + n
        while p < end:
            b = p // BLOCK
            if b not in self.cache:
                self.cache[b] = self._range(b * BLOCK, min(self.size, (b + 1) * BLOCK) - 1)
            blk = self.cache[b]
            take = blk[p - b * BLOCK: min(len(blk), end - b * BLOCK)]
            out.append(take)
            p += len(take)
        data = b"".join(out)
        self.pos += len(data)
        return data

    def readinto(self, buf):
        data = self.read(len(buf))
        buf[:len(data)] = data
        return len(data)


def stream_member(url, info, dst):
    """Fetch one member (local header + compressed bytes) in a single ranged request, inflate, check CRC."""
    if info.compress_type not in (zipfile.ZIP_DEFLATED, zipfile.ZIP_STORED):
        raise IOError(f"unsupported compression {info.compress_type} for {info.filename}")
    slack = 30 + len(info.filename.encode("utf-8")) + len(info.extra) + 512   # local extra field may differ
    end = info.header_offset + slack + info.compress_size - 1
    req = urllib.request.Request(url, headers={"Range": f"bytes={info.header_offset}-{end}"})
    dec = zlib.decompressobj(-15) if info.compress_type == zipfile.ZIP_DEFLATED else None
    tmp = dst.with_name(dst.name + ".part")
    crc = 0
    with urlopen_limited(req) as r:
        hdr = _read_exact(r, 30)
        if struct.unpack("<I", hdr[:4])[0] != 0x04034B50:
            raise IOError(f"bad local header for {info.filename}")
        nlen, xlen = struct.unpack("<HH", hdr[26:30])
        if 30 + nlen + xlen > slack:
            raise IOError(f"local header of {info.filename} larger than requested slack")
        _read_exact(r, nlen + xlen)
        left = info.compress_size
        with open(tmp, "wb") as fh:
            while left > 0:
                chunk = r.read(min(left, BLOCK * 8))
                if not chunk:
                    raise IOError(f"short read in {info.filename}")
                left -= len(chunk)
                data = dec.decompress(chunk) if dec else chunk
                crc = zlib.crc32(data, crc)
                fh.write(data)
            if dec:
                tail = dec.flush()
                crc = zlib.crc32(tail, crc)
                fh.write(tail)
    if crc != info.CRC:
        raise IOError(f"CRC mismatch for {info.filename}")
    tmp.replace(dst)
    return info.compress_size


def open_remote(name):
    f = HttpRangeFile(BASE.format(name))
    return f, zipfile.ZipFile(io.BufferedReader(f, buffer_size=BLOCK))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["ls", "get"])
    ap.add_argument("zip")
    ap.add_argument("--grep", default="")
    ap.add_argument("--out")
    ap.add_argument("--skip-existing", action="store_true", help="get: skip members already on disk with the right size")
    ap.add_argument("--local", help="read this local copy of the zip instead of Zenodo (same --grep selection)")
    a = ap.parse_args()
    if a.local:
        z, out = zipfile.ZipFile(a.local), Path(a.out)
        rx = re.compile(a.grep) if a.grep else None
        for i in z.infolist():
            if i.is_dir() or (rx and not rx.search(i.filename)):
                continue
            dst = out / i.filename
            if a.skip_existing and dst.exists() and dst.stat().st_size == i.file_size:
                print(f"{'skip':>12s} {dst}", flush=True)
                continue
            dst.parent.mkdir(parents=True, exist_ok=True)
            tmp = dst.with_name(dst.name + ".part")
            with z.open(i) as src, open(tmp, "wb") as fh:  # zipfile checks the CRC at end of stream
                while chunk := src.read(BLOCK * 8):
                    fh.write(chunk)
            tmp.replace(dst)
            print(f"{i.compress_size / 1e6:9.1f} MB zip -> {dst} (local, CRC ok)", flush=True)
        return
    f, z = open_remote(a.zip)
    rx = re.compile(a.grep) if a.grep else None
    members = [i for i in z.infolist() if not i.is_dir() and (rx is None or rx.search(i.filename))]
    if a.cmd == "ls":
        for i in members:
            print(f"{i.file_size}\t{i.compress_size}\t{i.filename}")
        print(f"# {len(members)} members, central directory fetch {f.fetched / 1e6:.1f} MB", file=sys.stderr)
        return
    out, total = Path(a.out), 0
    for i in members:
        dst = out / i.filename
        if a.skip_existing and dst.exists() and dst.stat().st_size == i.file_size:
            print(f"{'skip':>12s} {dst}", flush=True)
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        for k in range(5):                      # dropped connection / short read / CRC error: refetch the member
            try:
                total += stream_member(f.url, i, dst)
                break
            except OSError as e:
                if k == 4:
                    raise
                print(f"# {i.filename}: {e!r}, retry {k + 1}", file=sys.stderr, flush=True)
                time.sleep(10 * (k + 1))
        print(f"{i.compress_size / 1e6:9.1f} MB zip -> {dst} (CRC ok)", flush=True)
    print(f"# fetched {(total + f.fetched) / 1e9:.2f} GB of {f.size / 1e9:.2f} GB", file=sys.stderr)


if __name__ == "__main__":
    main()
