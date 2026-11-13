"""Online grouping of raw /var/log/audit/audit.log lines into events.

Training (AInception SL700) grouped the records of a whole file by msg=audit(<sec>.<ms>:<serial>) and built one event
per group with `build_audit_event` (vendored `ainception_adapters`), then processed events in (ts, serial) order.
Online:
  * completion: auditd writes the records of one event contiguously, so a group is complete when a line of another
    event follows it (or an EOE record closes it, or flush() is called when the input is idle). Audit time cannot be
    used for this: an event is stamped when its syscall starts and written when it ends, so a blocking connect() is
    written seconds after younger events;
  * order: complete groups wait in a reorder buffer and are emitted in (ts, serial) order once the newest audit time
    seen is `reorder_us` past them, which restores the training order for every event that blocked less than that;
  * a line of a group that is complete but not yet emitted reopens it (tolerates interleaving inside the buffer).
`build_audit_event` gets the same arguments as offline, so a complete group yields the identical event dict.
"""
from __future__ import annotations

import heapq
import re

from ._vendor.ainception_adapters import _HDR, build_audit_event

_KEY = re.compile(r'\bkey=(?:"([^"]+)"|([0-9A-Fa-f]+)\b)')


class AuditStream:
    def __init__(self, host: str, reorder_us: int = 10_000_000, max_open: int = 100_000):
        self.host = host
        self.reorder_us = reorder_us
        self.max_open = max_open
        self.groups: dict[tuple[int, int], list] = {}      # records of every not-yet-emitted group
        self.first_ts: dict[tuple[int, int], int] = {}
        self.refs: dict[tuple[int, int], list] = {}
        self.keys: dict[tuple[int, int], set] = {}
        self.open: set[tuple[int, int]] = set()
        self.ready: set[tuple[int, int]] = set()
        self.heap: list[tuple[int, int, tuple[int, int]]] = []   # (ts, serial, key) of ready groups (lazy)
        self.last_key = None
        self.max_ts = 0
        self.malformed = 0
        self.reopened = 0

    def feed(self, line: str, ref=None, coarse=None) -> list[dict]:
        """Add one raw line (`ref`: caller's id of the line, returned in event["refs"]); return emitted events."""
        m = _HDR.match(line.strip())
        if not m:
            self.malformed += 1
            return []
        typ, sec, ms, serial, body = m.groups()
        key = (int(sec), int(serial))
        ts = int(sec) * 1_000_000 + int(ms.ljust(3, "0")[:3]) * 1000
        if self.last_key is not None and self.last_key != key and self.last_key in self.open:
            self._close(self.last_key)
        if key in self.ready:                      # interleaved record of a buffered group
            self.ready.discard(key)
            self.reopened += 1
        if key not in self.groups:
            self.groups[key], self.refs[key], self.keys[key] = [], [], set()
            self.first_ts[key] = ts
        self.open.add(key)
        self.last_key = key
        self.groups[key].append((typ, ts, body, coarse))
        if ref is not None:
            self.refs[key].append(ref)
        if typ == "SYSCALL":                       # audit rule key (MITRE technique names in auditd-attack rules)
            k = _KEY.search(body)
            if k and k.group(1):
                self.keys[key].add(k.group(1))
            elif k and k.group(2):                 # several keys are hex-encoded and \x01-separated
                try:
                    self.keys[key].update(x for x in bytes.fromhex(k.group(2)).decode("utf-8", "replace").split("\x01") if x)
                except ValueError:
                    pass
        if typ == "EOE":
            self._close(key)
        self.max_ts = max(self.max_ts, ts)
        if len(self.open) > self.max_open:
            for k in list(self.open):
                self._close(k)
        return self._emit(force=False)

    def flush(self) -> list[dict]:
        for k in list(self.open):
            self._close(k)
        return self._emit(force=True)

    def _close(self, key):
        self.open.discard(key)
        self.ready.add(key)
        heapq.heappush(self.heap, (self.first_ts[key], key[1], key))

    def _emit(self, force: bool) -> list[dict]:
        out = []
        while self.heap:
            ts, _serial, key = self.heap[0]
            if key not in self.ready:              # stale entry (group reopened, or already emitted)
                heapq.heappop(self.heap)
                continue
            if not force and self.max_ts - ts < self.reorder_us:
                break
            heapq.heappop(self.heap)
            self.ready.discard(key)
            event = build_audit_event(key, self.groups.pop(key), self.host)
            self.first_ts.pop(key)
            event["refs"] = self.refs.pop(key)
            event["rule_keys"] = sorted(self.keys.pop(key))
            out.append(event)
        return out

    @property
    def pending(self) -> int:
        return len(self.groups)

    def oldest_ref(self):
        """Caller id of the first line of the oldest group still held (durable resume point)."""
        if not self.groups:
            return None
        key = min(self.groups, key=lambda k: (self.first_ts[k], k[1]))
        return self.refs[key][0] if self.refs[key] else None
