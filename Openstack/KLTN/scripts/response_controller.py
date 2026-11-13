#!/usr/bin/env python3
"""Response Service + Infra Controller (General Architecture): executes APPROVED response requests only.

Actions
  quarantine_network  swap every port of the victim VM to the Terraform-managed security group `kltn-quarantine`
                      (no default egress; only central telemetry 18443 out and SSH/WinRM/ICMP in from the central
                      host) after snapshotting the original groups; verified after the change, rolled back on error.
  release_network     restore the groups recorded by the most recent completed quarantine of that host.
  collect_evidence    passive, central-side: export the alert's raw records and host events (incident window
                      +- 30 min) to runtime/evidence/<alert>/<request>.jsonl.gz with a sha256, registered in
                      evidence_exports. Nothing is executed on the VM.
Safety: network actions need a `confirmed` alert and an explicit approval (API policy KLTN_APPROVAL_POLICY: two_person,
or single_operator in the closed research lab, recorded in execution.approval); the quarantine group
must exist and contain no rule other than the allowed ones, otherwise the controller refuses to use it.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "central/app"))
from common import db_connect  # noqa: E402
from psycopg.types.json import Jsonb  # noqa: E402

QUARANTINE_SG = "kltn-quarantine"
ALLOWED_RULES = {("egress", "tcp", 18443, 18443), ("ingress", "tcp", 22, 22), ("ingress", "tcp", 5986, 5986),
                 ("ingress", "icmp", None, None)}
EVIDENCE = ROOT / "runtime/evidence"


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


class OpenStackExecutor:
    def __init__(self, openrc: Path = Path("/etc/kolla/admin-openrc.sh"), simulation: bool = False,
                 cli: str = os.environ.get("KLTN_OPENSTACK_CLI", str(Path.home() / "venvs/kolla-2026.1/bin/openstack"))):
        self.simulation, self.cli = simulation, cli
        self.env = dict(os.environ)
        if openrc.is_file():
            for line in openrc.read_text().splitlines():
                line = line.strip()
                if line.startswith("export OS_"):
                    k, v = line[len("export "):].split("=", 1)
                    self.env[k] = v.strip().strip("'\"")
        self.sim_ports: dict[str, list[str]] = {}

    def os(self, *args) -> Any:
        out = subprocess.run([self.cli, *args, "-f", "json"], env=self.env, capture_output=True, text=True, check=True).stdout
        return json.loads(out) if out.strip() else {}

    def ports(self, server_id: str) -> list[str]:
        if self.simulation:
            return [f"port-{server_id[:8]}"]
        return [p["ID"] for p in self.os("port", "list", "--server", server_id)]

    def groups(self, port_id: str) -> list[str]:
        if self.simulation:
            return self.sim_ports.get(port_id, ["sg-default", "sg-kltn-node"])
        return sorted(self.os("port", "show", port_id)["security_group_ids"])

    def set_groups(self, port_id: str, groups: list[str]):
        if self.simulation:
            self.sim_ports[port_id] = sorted(groups)
            return
        args = ["port", "set", port_id, "--no-security-group"]
        for g in groups:
            args += ["--security-group", g]
        subprocess.run([self.cli, *args], env=self.env, capture_output=True, text=True, check=True)

    def quarantine_group(self) -> str:
        if self.simulation:
            return "sg-quarantine"
        sg = self.os("security", "group", "show", QUARANTINE_SG)
        rules = self.os("security", "group", "rule", "list", sg["id"], "--long")
        seen = set()
        for r in rules:
            proto = (r.get("IP Protocol") or "").lower() or None
            pr = r.get("Port Range") or ""
            lo, hi = (int(x) for x in pr.split(":")) if ":" in pr else (None, None)
            key = (r.get("Direction"), proto, lo, hi)
            if key not in ALLOWED_RULES:
                raise RuntimeError(f"quarantine group has a non-allowed rule {key}; refusing to use it")
            seen.add(key)
        if ("egress", "tcp", 18443, 18443) not in seen:
            raise RuntimeError("quarantine group lacks the telemetry egress rule; refusing to cut the evidence path")
        return sg["id"]

    def quarantine(self, server_id: str) -> dict:
        qsg = self.quarantine_group()
        snap = {p: self.groups(p) for p in self.ports(server_id)}
        if not snap:
            raise RuntimeError(f"no ports for server {server_id}")
        done = []
        try:
            for p in snap:
                self.set_groups(p, [qsg])
                done.append(p)
                if self.groups(p) != [qsg]:
                    raise RuntimeError(f"verification failed on port {p}")
        except Exception as exc:
            for p in done:
                self.set_groups(p, snap[p])
            raise RuntimeError(f"quarantine rolled back: {exc}") from exc
        return {"status": "quarantined", "quarantine_group": qsg, "initial_state": snap, "at": now()}

    def release(self, server_id: str, snapshot: dict[str, list[str]]) -> dict:
        if not snapshot:
            raise RuntimeError("no quarantine snapshot to restore")
        for p, groups in snapshot.items():
            self.set_groups(p, groups)
            if sorted(self.groups(p)) != sorted(groups):
                raise RuntimeError(f"release verification failed on port {p}")
        return {"status": "released", "restored": snapshot, "at": now()}


def export_evidence(conn, alert_id: str, host_id: str, request_id: str) -> dict:
    a = conn.execute("SELECT first_seen, last_seen, evidence FROM alerts WHERE alert_id=%s", (alert_id,)).fetchone()
    lo, hi = a[0] - timedelta(minutes=30), a[1] + timedelta(minutes=30)
    out = EVIDENCE / alert_id
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"{request_id}.jsonl.gz"
    rows = 0
    with gzip.open(path, "wt") as fh:
        fh.write(json.dumps({"type": "alert", "alert_id": alert_id, "host_id": host_id, "window": [lo.isoformat(), hi.isoformat()],
                             "evidence": a[2]}, default=str) + "\n")
        for r in conn.execute('''SELECT event_key, ts, kind, event, raw_refs FROM host_events WHERE host_id=%s AND ts BETWEEN %s AND %s
          ORDER BY ts_us''', (host_id, lo, hi)):
            fh.write(json.dumps({"type": "host_event", "event_key": r[0], "ts": r[1].isoformat(), "kind": r[2], "event": r[3],
                                 "raw_refs": r[4]}, default=str) + "\n")
            rows += 1
        for r in conn.execute('''SELECT event_id, source, received_at, payload FROM events WHERE host_id=%s AND received_at
          BETWEEN %s AND %s ORDER BY seq''', (host_id, lo, hi + timedelta(minutes=10))):
            fh.write(json.dumps({"type": "raw", "event_id": r[0], "source": r[1], "received_at": r[2].isoformat(),
                                 "payload": r[3]}, default=str) + "\n")
            rows += 1
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    os.chmod(path, 0o440)
    conn.execute('''INSERT INTO evidence_exports(export_id,alert_id,host_id,path,sha256,rows,details) VALUES (%s,%s,%s,%s,%s,%s,%s)
      ON CONFLICT(export_id) DO NOTHING''', (request_id, alert_id, host_id, str(path), digest, rows,
                                             Jsonb({"window": [lo.isoformat(), hi.isoformat()]})))
    return {"status": "exported", "path": str(path), "sha256": digest, "rows": rows, "at": now()}


class Controller:
    def __init__(self, executor: OpenStackExecutor, controller_id: str = "kltn-response-controller"):
        self.x, self.id = executor, controller_id

    def claim(self, conn) -> dict | None:
        row = conn.execute('''SELECT r.request_id, r.alert_id, r.host_id, r.action, a.state FROM response_requests r
          JOIN alerts a ON a.alert_id=r.alert_id WHERE r.state='approved' ORDER BY r.created_at LIMIT 1 FOR UPDATE OF r SKIP LOCKED''').fetchone()
        if not row:
            return None
        conn.execute('''UPDATE response_requests SET state='executing', execution=jsonb_set(execution,'{claimed_by}',%s),
          updated_at=now() WHERE request_id=%s''', (Jsonb(self.id), row[0]))
        return dict(zip(("request_id", "alert_id", "host_id", "action", "alert_state"), row))

    def process(self, req: dict) -> dict:
        if req["action"] in ("quarantine_network", "release_network") and req["alert_state"] != "confirmed":
            raise PermissionError(f"alert is {req['alert_state']}: network actions require a confirmed alert")
        if req["action"] == "quarantine_network":
            return self.x.quarantine(req["host_id"])
        if req["action"] == "release_network":
            with db_connect() as conn:
                snap = conn.execute('''SELECT execution->'initial_state' FROM response_requests WHERE host_id=%s
                  AND action='quarantine_network' AND state='completed' ORDER BY updated_at DESC LIMIT 1''', (req["host_id"],)).fetchone()
            return self.x.release(req["host_id"], snap[0] if snap else None)
        if req["action"] == "collect_evidence":
            with db_connect() as conn:
                return export_evidence(conn, req["alert_id"], req["host_id"], req["request_id"])
        raise ValueError(f"unknown action {req['action']}")

    def run_once(self) -> int:
        with db_connect() as conn:
            req = self.claim(conn)
        if req is None:
            return 0
        try:
            result = self.process(req)
            state = "completed"
        except PermissionError as exc:
            result, state = {"error": str(exc), "at": now()}, "rejected"
        except Exception as exc:
            result, state = {"error": f"{type(exc).__name__}: {exc}"[:1000], "at": now()}, "failed"
        with db_connect() as conn:
            conn.execute("UPDATE response_requests SET state=%s, execution=execution || %s, updated_at=now() WHERE request_id=%s",
                         (state, Jsonb(result), req["request_id"]))
        print(json.dumps({"request_id": req["request_id"], "action": req["action"], "state": state}), flush=True)
        return 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--daemon", action="store_true")
    ap.add_argument("--interval", type=int, default=10)
    ap.add_argument("--simulation", action="store_true", help="no cloud change (tests)")
    a = ap.parse_args()
    ctrl = Controller(OpenStackExecutor(simulation=a.simulation))
    while True:
        try:
            n = ctrl.run_once()
        except Exception as exc:
            print(json.dumps({"error": f"{type(exc).__name__}: {exc}"[:500]}), flush=True)
            n = 0
        if not a.daemon:
            break
        if n == 0:
            time.sleep(a.interval)


if __name__ == "__main__":
    main()
