# Installed model-free serving foundation

The preparation deployment adds endpoint runtimes and a central DL staging worker.
No model is loaded and no prediction is emitted. This is **not yet a detector**:
model-specific normalization, causal context/features and DL window construction
still require their agreed training contract and implementation before activation.
Copying a model file alone does not enable inference.

## Reproduce installation

Start with the existing Terraform VMs, central stack and private inventory from
[KLTN README](../README.md). From `/mnt/SSD_Data/optc`:

```bash
bash Openstack/KLTN/scripts/prepare_serving.sh
```

This verifies/caches official Windows installers, downloads pinned ML runtime
wheels, creates a restricted `kltn_dl` PostgreSQL role and staging tables, builds
CPU PyTorch, starts the `model-prep` Compose profile, and runs
`ansible/prepare-serving.yml`. The successful installer records
`runtime/serving-enabled` and sets `endpoint_agent_enabled` in the private
inventory so subsequent `site.yml` runs preserve the local output. Inventory
regeneration respects that marker. The marker enables runtime preparation, not
inference. Do not enable it manually before installing the endpoint role.

New/recreated endhosts use empty state; a host UUID change must not reuse another
host's SQLite inbox. No Terraform change or new floating IP/port is required.
The existing raw collector output remains active; local delivery starts only
after the agent reports runtime health.

| Component | Location / service | Installed behavior |
|---|---|---|
| Ubuntu agent | `/opt/kltn-agent`, `kltn-agent.service` | Dedicated venv, unprivileged `kltn-agent`, 512MiB/1CPU limit |
| Windows agent | `C:\KLTN\agent`, service `kltn-agent` | Dedicated Python3.12.10 + venv, WinSW2.12.0 under LocalService, rolling logs |
| Endpoint frameworks | All3 endhosts | LightGBM4.6.0, NumPy2.2.6, SciPy1.15.3, FastAPI/Uvicorn |
| Local ingestion | `127.0.0.1:18081/v1/raw/{source}` | Derived bearer token; SQLite commit before ACK, retries deduplicated |
| Linux state | `/var/lib/kltn-agent/inbox.sqlite` | WAL, FULL synchronous, service-user only |
| Windows state | `C:\KLTN\agent\state\inbox.sqlite` | LocalService Modify; code/config read-only to service |
| DL worker | Docker `kltn-central-dl-prep-1` | CPU PyTorch2.7.1, two threads, 1GiB/2CPU container cap, no listening port |
| DL staging | PostgreSQL `dl_jobs`, `serving_status` | Independent archive scan, durable unique event/pipeline references, heartbeat |
| Future bundle directories | `/opt/kltn-agent/models`, `C:\KLTN\agent\models`, controller `runtime/models/dl` | Empty; no auto-load or model execution |

The Windows native dependency is Microsoft Visual C++ x64 Redistributable.
Python and VC runtime signatures are verified before installation. Installer
SHA256 pins record the bytes retrieved from official HTTPS release URLs; they
are not claimed to be independently published publisher checksums. The Microsoft
URL is mutable: a future checksum mismatch must be investigated and the verified
pin updated, not bypassed. Windows wheel hashes are recorded in
`runtime/assets/serving-manifest.json`; endpoint dependency versions are pinned.
Future model framework versions must match or pass parity tests against this
runtime. Models trained under other versions may require a runtime rebuild.

## Health and verification

```bash
python3 Openstack/KLTN/scripts/serving_status.py
docker compose -f Openstack/KLTN/central/compose.yaml --profile model-prep ps
export ANSIBLE_CONFIG="$PWD/Openstack/KLTN/ansible/ansible.cfg"
Openstack/KLTN/runtime/venv/bin/ansible-playbook Openstack/KLTN/ansible/test-serving.yml -e smoke_marker=kltn-runtime-check-001
Openstack/KLTN/runtime/venv/bin/ansible-playbook Openstack/KLTN/ansible/smoke.yml -e smoke_marker=kltn-delivery-check-001
Openstack/KLTN/runtime/venv/bin/ansible-playbook Openstack/KLTN/ansible/verify-serving-telemetry.yml -e smoke_marker=kltn-delivery-check-001
python3 Openstack/KLTN/scripts/check_serving_telemetry.py kltn-delivery-check-001
```

Use a new marker per run. `test-serving.yml` intentionally restarts agents and
checks auth rejection, duplicate delivery, persistence and no-model readiness.
The other two checks verify actual OS events reached all7 local inbox sources
and all7 central archive sources. The central check can be retried if the raw
archive is still draining; HTTP accepted is not a DB-commit guarantee.

On an endhost, `GET http://127.0.0.1:18081/healthz` returns status, framework
versions, counts and `inference: waiting_for_model`, `score: null`.
`GET /readyz` returns HTTP503 by design: the runtime is alive but detection is
not ready. Central heartbeat age should remain below60s; a healthy Docker
container means the DB staging transaction and heartbeat succeeded, not that
model inference is available. The original raw-ingest `/healthz` still correctly
reports `disabled_schema_pending`.

## Capacity and behavior while models are absent

Each local inbox holds at most50,000 events or128MiB of raw JSON, with256MiB free
disk reserve. Whole batches roll back and return503 if they exceed capacity;
retries containing only already-stored events can still succeed. No inbox rows
are silently evicted. SQLite/index/WAL overhead is additional to the raw-byte cap.
Local HTTP outputs use one worker and disable connection keepalive so agent
restarts do not reuse stale sockets. Each new Fluent Bit local output has128MiB buffer; when this also fills, Fluent
Bit's configured buffer eviction can lose **local-branch** events. The independent
raw archive output retains its existing delivery policy. Do not describe this
preparation buffer as unlimited storage or guaranteed lossless operation.

DL staging is bounded to50,000 event references, including historical archived
events. Reaching the cap pauses staging; subsequent raw events stay in `events`.
Jobs are never marked scored/benign or consumed without a model. The full ledger
is retained, so an anti-join can resume without timestamp-watermark omissions.
At this stage the worker does not assemble sequences or tokenize data.
The role can read archive events and insert staging references/heartbeats; it
cannot delete raw events. No OpenStack admin credential is mounted into it.

No scoring outbox, score API, fusion or isolation is active: there are no scores
to send. The [serving contract](README.md) describes those later activation pieces.
The validated release must include the adapter/feature implementation and parity
fixtures alongside weights; incremental learning is not required for first use.

## Stop preparation without stopping raw collection

First render collectors without the local branch:

```bash
Openstack/KLTN/runtime/venv/bin/ansible-playbook Openstack/KLTN/ansible/prepare-serving.yml -e endpoint_agent_enabled=false
```

Then stop `kltn-agent` on the endhosts and use
`docker compose -f Openstack/KLTN/central/compose.yaml --profile model-prep stop dl-prep`.
Remove `runtime/serving-enabled` and set the private inventory's
`all.vars.endpoint_agent_enabled` to false to keep subsequent deployments disabled.
Do not remove raw collector services, PostgreSQL volumes or inbox files just to
pause preparation. Re-enable with `prepare_serving.sh`.

Measured deployment results: [VALIDATION.md](VALIDATION.md).
