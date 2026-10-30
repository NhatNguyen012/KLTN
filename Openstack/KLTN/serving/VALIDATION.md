# Model-free serving validation — 2026-10-30

Installed on the existing two Ubuntu VMs, Windows11 VM and physical Docker host.
This is a runtime/inbox/staging validation, not model accuracy or load testing.

| Check | Result |
|---|---|
| Focused unit tests | 7 passed: event identity, retry deduplication, restart/reopen persistence, batch rollback on capacity, byte cap, host identity boundary, no fake scores |
| Ansible installation | All3 hosts: failed=0, unreachable=0 |
| Idempotent deployment | Ubuntu1/Ubuntu2/Windows1: changed=0, failed=0 |
| Native libraries | LightGBM4.6.0, NumPy2.2.6, SciPy1.15.3 imported on all3 hosts |
| Runtime readiness | health200; inference readiness503; waiting_for_model and score=null |
| Authentication | Invalid loopback bearer rejected with401 on all3 hosts |
| Restart + replay | One event persisted exactly once through actual service restart on all3 hosts |
| Real OS telemetry | All7 source/host combinations reached local SQLite and central PostgreSQL |
| DL container restart | Healthy after restart; durable job ledger retained |
| DL staging uniqueness | 38,500 rows /38,500 unique(event_id,pipeline_version) at sampled check |
| DL DB permissions | SELECT events=true; DELETE events=false |
| DL memory sample | 136.4MiB with1GiB limit, CPU-only; not a capacity benchmark |

Final OS marker: `kltn-prep-delivery-v2-20261030`.

| Host | Source | Local marker rows at check | Central marker rows at check |
|---|---|---:|---:|
| ubuntu1 | audit | 3 | 4 |
| ubuntu1 | journal | 1 | 1 |
| ubuntu2 | audit | 3 | 4 |
| ubuntu2 | journal | 1 | 1 |
| windows1 | sysmon | 2 | 4 |
| windows1 | security | 1 | 3 |
| windows1 | powershell | 1 | 1 |

Counts are observations at different times, not an equality assertion: verification
commands can themselves mention the marker and create more audit/process events.
The assertion is nonzero delivery per source and host. Direct replay tests separately
assert exactly one stored row for the same canonical event.

Issues found and fixed during installation:

- Windows LightGBM needed Microsoft Visual C++ x64 runtime. Added checksum-pinned
  download, Microsoft Authenticode validation and idempotent installation.
- Windows local HTTP delivery failed following an agent restart while central
  delivery continued. Local outputs now use one worker with keepalive disabled;
  another restart followed by fresh telemetry passed on all7 sources.
- Central archive is asynchronous. The first immediate final-marker query ran
  before archive commit; the subsequent check passed for all7 sources. The helper
  now polls with a bounded timeout instead of assuming immediate persistence.

Evidence logs (private, gitignored):
`runtime/prepare-serving-final.log`, `runtime/serving-reconcile.log`,
`runtime/serving-restart-v2.log`, `runtime/serving-delivery-v2.log`,
`runtime/serving-idempotence.log`. Use the operations runbook to reproduce tests.

Remaining activation work: define/implement and validate the model-compatible
normalizers, causal feature/context logic, DL sequence construction, loaders and
score transport together with the model bundle. No models, inference scores,
fusion, response actions or incremental learning were installed in this step.
