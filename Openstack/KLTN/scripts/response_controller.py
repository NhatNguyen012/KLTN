#!/usr/bin/env python3
"""Decoupled OpenStack Response Controller for KLTN.

Executes network isolation (quarantine) and restoration (release) actions
approved by SOC analysts for confirmed security incidents:
  - Strict safety precondition: rejects unconfirmed or shadow alerts
  - Pre-execution snapshot: saves original port security groups and state
  - Atomic quarantine: applies restricted isolation security group
  - Post-isolation verification: validates port configuration
  - Clean restoration: restores original network state on release
  - Automatic rollback on execution failure with durable audit trail.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parents[1]

sys.path.insert(0, str(ROOT / 'central/app'))
from common import db_connect
from framework import RESPONSE_ACTIONS, canonical_hash

QUARANTINE_SECGROUP_NAME = "kltn-quarantine-secgroup"


class OpenStackResponseExecutor:
    def __init__(self, openrc_path: Path | None = None, simulation: bool = False):
        self.openrc_path = openrc_path or Path("/etc/kolla/admin-openrc.sh")
        self.simulation = simulation
        self._env = None

    def env(self) -> dict[str, str]:
        if self._env is not None:
            return self._env
        env = dict(os.environ)
        if self.openrc_path.is_file():
            try:
                # Parse OS_* variables from openrc
                for line in self.openrc_path.read_text(encoding='utf-8').splitlines():
                    line = line.strip()
                    if line.startswith("export OS_"):
                        key, val = line.replace("export ", "").split("=", 1)
                        env[key.strip()] = val.strip().strip("'\"")
            except Exception as e:
                print(f"Warning: could not parse {self.openrc_path}: {e}", file=sys.stderr)
        self._env = env
        return self._env

    def run_openstack(self, args: list[str]) -> str:
        if self.simulation:
            print(f"  [SIMULATION] openstack {' '.join(args)}")
            return "{}"
        # Execute via docker container or local openstack binary
        cmd = ["openstack"] + args
        try:
            res = subprocess.run(cmd, env=self.env(), stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True, check=True)
            return res.stdout
        except (subprocess.SubprocessError, FileNotFoundError):
            # Fallback to docker exec kolla_toolbox
            docker_cmd = [
                "docker", "exec",
                "-e", f"OS_AUTH_URL={self.env().get('OS_AUTH_URL', '')}",
                "-e", f"OS_USERNAME={self.env().get('OS_USERNAME', '')}",
                "-e", f"OS_PASSWORD={self.env().get('OS_PASSWORD', '')}",
                "-e", f"OS_PROJECT_NAME={self.env().get('OS_PROJECT_NAME', '')}",
                "-e", f"OS_PROJECT_DOMAIN_NAME={self.env().get('OS_PROJECT_DOMAIN_NAME', 'Default')}",
                "-e", f"OS_USER_DOMAIN_NAME={self.env().get('OS_USER_DOMAIN_NAME', 'Default')}",
                "-e", "OS_IDENTITY_API_VERSION=3",
                "-e", "OS_INTERFACE=internal",
                "kolla_toolbox", "openstack"
            ] + args
            res = subprocess.run(docker_cmd, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True, check=True)
            return res.stdout

    def get_server_port_id(self, host_id: str) -> str | None:
        """Finds primary Neutron port for Nova server host_id."""
        if self.simulation:
            return f"port-{host_id[:8]}"
        try:
            out = self.run_openstack(["port", "list", "--server", host_id, "-f", "json"])
            ports = json.loads(out)
            return ports[0]["ID"] if ports else None
        except Exception as e:
            print(f"Error querying port for server {host_id}: {e}", file=sys.stderr)
            return None

    def snapshot_port(self, port_id: str) -> dict[str, Any]:
        """Snapshots current port configuration before applying response action."""
        if self.simulation:
            return {
                "port_id": port_id,
                "security_group_ids": ["secgroup-default", "secgroup-allow-ssh"],
                "admin_state_up": True,
            }
        out = self.run_openstack(["port", "show", port_id, "-f", "json"])
        data = json.loads(out)
        return {
            "port_id": port_id,
            "security_group_ids": data.get("security_group_ids", []),
            "admin_state_up": data.get("admin_state_up", True),
            "mac_address": data.get("mac_address"),
            "fixed_ips": data.get("fixed_ips"),
        }

    def ensure_quarantine_secgroup(self) -> str:
        """Ensures quarantine security group exists (drops all traffic)."""
        if self.simulation:
            return "secgroup-kltn-quarantine"
        try:
            out = self.run_openstack(["security", "group", "show", QUARANTINE_SECGROUP_NAME, "-f", "json"])
            return json.loads(out)["id"]
        except Exception:
            # Create quarantine security group
            out = self.run_openstack(["security", "group", "create", QUARANTINE_SECGROUP_NAME,
                                      "--description", "KLTN Emergency Isolation Quarantine", "-f", "json"])
            return json.loads(out)["id"]

    def apply_quarantine(self, host_id: str) -> dict[str, Any]:
        port_id = self.get_server_port_id(host_id)
        if not port_id:
            raise RuntimeError(f"Could not locate Neutron port for instance {host_id}")

        # 1. Snapshot initial state
        initial_state = self.snapshot_port(port_id)
        q_secgroup_id = self.ensure_quarantine_secgroup()

        # 2. Apply quarantine secgroup
        try:
            if not self.simulation:
                self.run_openstack(["port", "set", port_id, "--no-security-group", "--security-group", q_secgroup_id])
                # 3. Post-isolation verification
                verified = self.snapshot_port(port_id)
                if verified["security_group_ids"] != [q_secgroup_id]:
                    raise RuntimeError(f"Port verification failed: expected {[q_secgroup_id]}, got {verified['security_group_ids']}")
        except Exception as e:
            # Automatic Rollback on failure
            print(f"Quarantine failed: {e}. Executing automatic rollback to initial state...", file=sys.stderr)
            if not self.simulation:
                rollback_args = ["port", "set", port_id, "--no-security-group"]
                for sg in initial_state["security_group_ids"]:
                    rollback_args.extend(["--security-group", sg])
                self.run_openstack(rollback_args)
            raise RuntimeError(f"Quarantine aborted and rolled back: {e}") from e

        return {
            "status": "quarantined",
            "port_id": port_id,
            "applied_secgroup": q_secgroup_id,
            "initial_state": initial_state,
            "isolated_at": datetime.now(timezone.utc).isoformat(),
        }

    def apply_release(self, host_id: str, saved_initial_state: dict[str, Any] | None) -> dict[str, Any]:
        port_id = self.get_server_port_id(host_id)
        if not port_id:
            raise RuntimeError(f"Could not locate Neutron port for instance {host_id}")

        original_secgroups = (saved_initial_state or {}).get("security_group_ids", [])
        if not original_secgroups:
            raise RuntimeError("Cannot release: no previous security group snapshot available")

        # Restore original secgroups
        if not self.simulation:
            restore_args = ["port", "set", port_id, "--no-security-group"]
            for sg in original_secgroups:
                restore_args.extend(["--security-group", sg])
            self.run_openstack(restore_args)

            # Verify
            verified = self.snapshot_port(port_id)
            if set(verified.get("security_group_ids", [])) != set(original_secgroups):
                raise RuntimeError(f"Release verification mismatch: {verified['security_group_ids']}")

        return {
            "status": "released",
            "port_id": port_id,
            "restored_secgroups": original_secgroups,
            "released_at": datetime.now(timezone.utc).isoformat(),
        }


class ResponseController:
    def __init__(self, executor: OpenStackResponseExecutor, controller_id: str = "kltn-resp-ctrl-01"):
        self.executor = executor
        self.controller_id = controller_id

    def fetch_approved_responses(self) -> list[dict]:
        with db_connect() as conn:
            rows = conn.execute(
                '''SELECT r.request_id, r.alert_id, r.host_id, r.action, r.requested_by,
                          r.approved_by, r.execution, a.state AS alert_state, a.risk_score
                   FROM response_requests r
                   JOIN alerts a ON a.alert_id = r.alert_id
                   WHERE r.state = 'approved'
                   ORDER BY r.created_at ASC LIMIT 10'''
            ).fetchall()
        return [{
            'request_id': r[0], 'alert_id': r[1], 'host_id': r[2], 'action': r[3],
            'requested_by': r[4], 'approved_by': r[5], 'execution': r[6] or {},
            'alert_state': r[7], 'risk_score': r[8],
        } for r in rows]

    def claim_request(self, request_id: str) -> bool:
        with db_connect() as conn:
            row = conn.execute(
                "SELECT state FROM response_requests WHERE request_id=%s FOR UPDATE", (request_id,)
            ).fetchone()
            if not row or row[0] != 'approved':
                return False
            conn.execute(
                '''UPDATE response_requests
                   SET state='executing',
                       execution = jsonb_set(COALESCE(execution, '{}'::jsonb), '{claimed_by}', %s)
                   WHERE request_id=%s''',
                (json.dumps(self.controller_id), request_id)
            )
        return True

    def process_request(self, req: dict) -> bool:
        req_id = req['request_id']
        host_id = req['host_id']
        action = req['action']
        alert_state = req['alert_state']

        print(f"\nProcessing response request {req_id} ({action}) for host {host_id}...")

        # Strict safety precondition: reject non-confirmed alerts
        if alert_state != 'confirmed':
            err_msg = f"Safety block: alert {req['alert_id']} is '{alert_state}', response requires 'confirmed'"
            print(err_msg, file=sys.stderr)
            with db_connect() as conn:
                conn.execute(
                    "UPDATE response_requests SET state='rejected', execution=jsonb_set(COALESCE(execution, '{}'::jsonb), '{rejection_reason}', %s), updated_at=now() WHERE request_id=%s",
                    (json.dumps(err_msg), req_id)
                )
            return False

        if not self.claim_request(req_id):
            print(f"Request {req_id} already claimed or invalid state.")
            return False

        try:
            if action == 'quarantine_network':
                result = self.executor.apply_quarantine(host_id)
            elif action == 'release_network':
                initial = (req.get('execution') or {}).get('initial_state')
                result = self.executor.apply_release(host_id, initial)
            else:
                result = {'status': 'unsupported_action', 'action': action}

            with db_connect() as conn:
                conn.execute(
                    '''UPDATE response_requests
                       SET state='completed', execution=%s, updated_at=now()
                       WHERE request_id=%s''',
                    (json.dumps(result), req_id)
                )
            print(f"Response request {req_id} COMPLETED successfully: {result['status']}")
            return True
        except Exception as e:
            err_details = {'error': str(e), 'failed_at': datetime.now(timezone.utc).isoformat()}
            with db_connect() as conn:
                conn.execute(
                    '''UPDATE response_requests
                       SET state='failed', execution=jsonb_set(COALESCE(execution, '{}'::jsonb), '{error}', %s), updated_at=now()
                       WHERE request_id=%s''',
                    (json.dumps(err_details), req_id)
                )
            print(f"Response request {req_id} FAILED: {e}", file=sys.stderr)
            return False

    def run_once(self) -> int:
        requests = self.fetch_approved_responses()
        if not requests:
            print("No approved response requests pending.")
            return 0
        processed = 0
        for req in requests:
            if self.process_request(req):
                processed += 1
        return processed

    def run_daemon(self, interval: int = 15):
        print(f"Starting OpenStack Response Controller daemon (interval: {interval}s)...")
        while True:
            try:
                self.run_once()
            except Exception as e:
                print(f"Controller loop error: {e}", file=sys.stderr)
            time.sleep(interval)


def main():
    parser = argparse.ArgumentParser(description="KLTN OpenStack Response Controller")
    parser.add_argument('--daemon', action='store_true', help="Run continuously as daemon")
    parser.add_argument('--interval', type=int, default=15, help="Polling interval in seconds")
    parser.add_argument('--simulation', action='store_true', help="Run in simulation mode (no actual cloud modification)")
    parser.add_argument('--controller-id', default="kltn-resp-ctrl-01")
    args = parser.parse_args()

    executor = OpenStackResponseExecutor(simulation=args.simulation)
    ctrl = ResponseController(executor, controller_id=args.controller_id)

    if args.daemon:
        ctrl.run_daemon(interval=args.interval)
    else:
        ctrl.run_once()


if __name__ == '__main__':
    main()

