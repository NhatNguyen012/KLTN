#!/usr/bin/env python3
"""Wait for a reachable RDP TCP listener; this does not test authentication."""

import argparse
import socket
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", help="Windows fixed or floating IP reachable from this host")
    parser.add_argument("--timeout", type=float, default=900, help="Deadline in seconds (default: 900)")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    deadline = time.monotonic() + args.timeout
    consecutive = 0
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((args.host, 3389), timeout=min(5, max(0.01, deadline - time.monotonic()))):
                consecutive += 1
            # First-boot can reboot after a listener first becomes available.
            if consecutive >= 3:
                print(f"RDP TCP reachable: {args.host}:3389 (3 checks; login not tested)")
                return 0
        except OSError:
            consecutive = 0
        time.sleep(min(5, max(0, deadline - time.monotonic())))
    print(f"RDP readiness timeout: {args.host}:3389; inspect Cloudbase-Init and Windows Setup logs.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
