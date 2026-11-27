# KLTN Architecture, Log Forwarding Policy & VM Isolation

Status: Active (aligned with [General_Architecture.png](../images/General_Architecture.png)).

## 1. Model Placement: Endpoint ML vs Central DL

| Layer | Host / Service | Model | Detection Mode |
|---|---|---|---|
| **End Host (Windows VM)** | `kltn-windows-1` (`kltn-agent` `127.0.0.1:18081`) | **LightGBM OpTC Seed-02** (`optc-seed02-host-ml-v1`, 500 trees, width `10,317`, `threshold=0.87427`, `select_threshold=0.50`) | **Near real-time per-event** inside VM |
| **End Hosts (Linux VMs)** | `kltn-ubuntu-1`, `kltn-ubuntu-2` (`kltn-agent` `127.0.0.1:18081`) | **LightGBM Incremental Chain** (`host-ml-il3-20261114`, 900 trees, width `21,487`, `threshold=0.786395`, `select_threshold=0.50`) | **Near real-time per-event** inside VM |
| **Central Server (Docker)** | `openstack-aio` (`optc-dl-service:8002` + `kltn-optc-theia-scorer --dl-only`) | **ExpandableMixHeadCausalIL OpTC+THEIA** (`optc-theia-mixhead-il-v1`, thresholds `0.50` Linux / `0.55` Windows) | **Per-chunk (`<= 64` events) sequential window** at Central |
| **Central Fusion & Lifecycle** | `kltn-il3-framework-1` + `optc-soc-ui:8080` + `kltn-il-service` | Threshold-normalized noisy-OR (`host_ml` from VMs + `host_dl` from Central) | SOC alert triage, IL drift/retrain trigger |

Central does **not** run duplicate Host ML inference (`--dl-only`); every `host_ml` score originates directly from `kltn-agent` inside the monitored VMs.

---

## 2. Explicit Log Collection, Filtering & Forwarding Policy

To prevent redundant telemetry loops and Central DB bloat while keeping full attack visibility and forensics:

### Layer A — Local Raw Ring Buffer (`Storage (Raw Logs)` on End Hosts)
- Native disk logs (`/var/log/audit/audit.log` on Ubuntu, Sysmon/Security/PowerShell EVTX on Windows) remain untouched on the VM for forensic pull (`collect_evidence`).
- `kltn-agent` maintains a bounded SQLite ring buffer (`max_rows=200,000`, `max_bytes=512 MiB`, `retention_hours=6`) strictly for local crash-safe dedup and ML outbox delivery.

### Layer B — Edge Sensor & Fluent Bit Pre-Filtering (Before Network Transfer)
1. **Pipeline self-exclusion (`kltn-sensor.rules`, `sysmon.xml v3`)**:
   - Linux `auditctl`: excludes `connect()` syscalls of `/opt/fluent-bit/bin/fluent-bit`, `kltn-agent` uid, and airgapped NTP loop `/usr/lib/systemd/systemd-timesyncd`. All `execve`, file, auth, and `ptrace` syscalls remain audited.
   - Windows `sysmon.xml v3`: excludes `C:\KLTN\agent\` and `C:\KLTN\packages\fluent-bit\` from `NetworkConnect`, `RegistryEvent`, and `DnsQuery`; restricts `ProcessAccess (EID 10)` to sensitive access masks/`lsass.exe` and `FileCreate/Delete (EID 11/26)` to executable/script/document extensions.
2. **Fluent Bit `[FILTER]` / `Event_Query` Channel Reduction**:
   - Linux (`audit`): Fluent Bit `grep` excludes non-provenance audit noise (`^type=(SERVICE_START|SERVICE_STOP|BPF|AVC|CRYPTO_KEY_USER|CRED_DISP|CRED_ACQ|CRED_REFR|USER_END)`) and `systemd-timesyncd` lines; `journal` ships only `ssh.service` and `kltn-smoke`.
   - Windows (`powershell`): `Event_Query *[System[(EventID=4104)]]` collects ScriptBlock executions only, dropping engine init chatter (`40961, 40962, 53504, 4100`). `Security` collects `4624, 4634, 4672, 4688`.
3. **Scheduled / Bounded Batch Delivery**:
   - Fluent Bit uses `Flush 5`, `Retry_Limit 10`, and per-output bounded filesystem buffers (`256 MiB` Central, `128 MiB` Loopback `127.0.0.1:18081` with `net.keepalive Off`).

### Layer C — What Crosses the Network to Central
1. **From Endpoint ML (`kltn-agent` -> `POST /v1/scores`, `/v1/summaries`)**:
   - **Only `Selected logs`** (`score >= select_threshold = 0.50` or `score >= decision threshold`) with SHAP top features + event summary are sent per-event (`score.v1`), **not** every benign prediction.
   - One lightweight aggregate `summary.v1` (event counts, OOV tokens, 10-bin score histogram) is sent once every **60 seconds**.
2. **From Fluent Bit -> Central Log Receive (`POST /v1/events`, consumed by Central DL)**:
   - Sends only Edge-filtered provenance streams in 5s batches required to assemble chronological 64-event DL context chunks.
3. **On-Demand Deep Forensics (`collect_evidence`)**:
   - Full raw logs/evidence bundles are exported to `runtime/evidence/` only when SOC/framework requests `collect_evidence`.

---

## 3. Compromised VM Blocking & Network Isolation

1. **Approval Gate (`response_controller.py`)**: `quarantine_network` requires `alert_state == "confirmed"` (approved in SOC UI or `/v1/alerts/{id}/reviews` -> `POST /v1/responses`).
2. **Live OpenStack Neutron Enforcement (`kltn-quarantine`)**:
   - Snapshots original Neutron port Security Groups (`initial_state`) into Postgres before mutation (`release_network` restores exact original SGs cleanly).
   - Verifies `kltn-quarantine` contains **only** the allowlisted management/telemetry rules (`egress tcp/18443 -> 172.31.250.1/32`, `egress udp/67 -> 255.255.255.255/32`, `ingress tcp/22,5986 & icmp <- 172.31.250.1/32`) and zero `0.0.0.0/0` rules before applying.
   - Isolated VM cannot scan/attack peer VMs or `kltn-attacker`, while admin management (`22`/`5986`) and forensic telemetry (`18443`) remain reachable.
