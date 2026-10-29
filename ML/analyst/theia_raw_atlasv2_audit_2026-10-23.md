THEIA raw and ATLASv2 download audit — 2026-10-23

THEIA: correct published E3 topic names and usable raw CDM telemetry. ATLASv2: correct documentation and label repositories, but the telemetry payload has not been downloaded. Neither finding alone establishes drop-in compatibility with all three OpTC checkpoints.

**THEIA verification and scope**

The RAW directory contains JSON and binary archives for `ta1-theia-e3-official-1r`, `-3`, `-5m`, and `-6r`, the four topics listed by the [official DARPA E3 release](https://github.com/darpa-i2o/Transparent-Computing/blob/master/README-E3.md). First-member headers of all binary archives match Avro Object Container Files. JSON and binary versions must not be counted as separate examples. This audit does not prove byte-for-byte correspondence between both representations or compare against publisher checksums.

Streamed all 25 regular tar members in the four JSON archives without extracting into any input directory: **113,293,343 decoded records, zero JSON parse failures**, including 106,044,692 Events, 279,391 Subject records and 245,107 NetFlowObject records. Repeated UUIDs reduce these to 279,369 unique Subject UUIDs and 186,100 unique NetFlowObject UUIDs. Unique statistics below use the last record per UUID in archive/file order, not a time-qualified metadata join. All Subjects declare SUBJECT_PROCESS, but the count includes a sentinel zero-UUID Subject and should not be interpreted as 279,369 verified real executions.

| Required information | Raw observation | Implication |
|---|---|---|
| Subject.properties.path | 278,363 / 279,369 (99.64%) | Executable path is largely available |
| Subject.cmdLine | 271,834 / 279,369 (97.30%) | Command lines largely available; semantic quality not certified |
| Non-sentinel parentSubject | 279,211 / 279,369 (99.94%); referenced UUIDs found | Strong basis for lineage reconstruction, pending cycle/time checks |
| hostId, localPrincipal, startTimestampNanos | Fields populated on all Subject UUIDs | Presence alone does not establish valid values; sentinel start time is zero |
| Host and Principal joins | All Subject host/principal references resolve; 23 distinct principals | Recoverable identity/context omitted from processed node tables |
| NetFlowObject.ipProtocol | 0 / 186,100 unique flows; null in all 245,107 raw flow records | Raw cannot supply the current DL protocol feature from this field |
| Both endpoints parse as IP addresses | 156,944 / 186,100 (84.33%) | Filter/classify special local or incomplete endpoints before flow adaptation |
| Event.subject | Populated/nonzero on 106,044,689 / 106,044,692 events | Actual actor field is subject; Event.process is absent throughout |
| Event predicateObjectPath / predicateObject2Path | Both absent/null throughout | Use appropriately joined object metadata; those event-path fields cannot repair gaps |

There is **one observed Host UUID**, with interface IP 10.0.6.60; hostName and osDetails are empty. A stable namespaced hostId can serve as an adapter identity without inventing a hostname. The telemetry/source identifies THEIA's Linux collection. A remote address is not evidence that the peer host was instrumented. Do not manufacture a multi-host graph from IP endpoints.

All 279,369 process UUIDs in the existing processed CSV are present in raw, and raw and CSV have the same path/cmd coverage counts. Thus the previous concern about lost command/path coverage is not supported for this THEIA export. Raw does recover other metadata absent from CSV: host, principal, parent and subject start information. Equality of coverage is not a value-by-value equality test.

All 126 distinct THEIA UUIDs in the new REAPr labels match raw: 125 attack and one contaminated. Every one has path and command metadata. This is a label identity check, not a verification that every event from those processes is malicious.

**Important validity checks before building model inputs**

- The all-zero Subject UUID exists as a sentinel, points to itself and has startTimestampNanos=0. A naive dictionary lookup gives 100% parent/two-ancestor resolution by counting this sentinel. The evidence JSON explicitly separates non-sentinel parent hits. Cycle-free, strictly-past two-hop graph coverage has not been established by this inventory.
- A full follow-up scan of the small `-3` archive found 205 EVENT_SHM records with timestamps outside 2018; interpreting the declared nanoseconds as Unix time places them in 1970. Other archive event minima/maxima are within April 2018. Quarantine or investigate those timestamps before temporal splits; do not silently guess a conversion.
- Parent UUID availability does not establish when all parent attributes were first observable. Retain observation times and enforce causal cutoffs in the adapter.
- Only 84.33% of unique NetFlowObjects have two parseable IP endpoints. Examples include LOCAL/NA and zero ports. Parseability is still not proof of a valid connection or responder direction.
- The supplied THESEUS E3 CSV exporter reads Event.process, whereas these raw records use Event.subject. Do not rerun that exporter unchanged and assume it reconstructs this corpus correctly.

**Consequences for incremental learning on THEIA**

| Model | Assessment after raw audit |
|---|---|
| LightGBM | Host-event adaptation is feasible to investigate: path/cmd, principal identity, file/object metadata and event operations exist. Linux token semantics and sparse-vocabulary coverage still need an adapter audit; Windows-specific features do not have universal Linux equivalents. |
| Two-hop GraphSAGE | Process ancestry and host assignment can be reconstructed more faithfully than from processed CSV. The dataset supplies one observed host, so it cannot exercise the full observed-host communication branch. Validate parent timing/cycles; do not claim the whole original graph distribution is reproduced. |
| BiLSTM / Mixed-Type | Not feature-complete for the current notebook: proto cannot be recovered from ipProtocol. Connection/session construction and responder roles also need an explicit policy. All-missing protocol is an ablation/domain adaptation decision, not full feature compatibility. |

A missing-value encoding can make a tensor executable, but does not prove successful knowledge transfer. Do not infer TCP from port 443 or 80. Options are a documented missing-protocol experiment or a consistently redefined feature set with an OpTC reference model trained/evaluated under the same contract. Preserve old feature IDs when extending neural vocabularies; do not silently relabel existing embedding indices or change the LightGBM column schema.

**ATLASv2 download verification**

The local `DATASET/ATLASv2/atlasv2/` directory contains README.md and docs/edr_alert_labels.xlsx, plus Git metadata. It does not contain the dataset's `data/` tree or CBC/Sysmon/Windows Security telemetry. Its total directory size is roughly 412 KB. The repository is the dataset documentation/access point, not the large telemetry payload.

The README points to the separate [ATLASv2 telemetry download](https://uofi.box.com/s/feunur7280afxrfeb0af73recexa73yc), approximately 12 GB compressed / 160 GB unpacked. The paper reports 154 GB generated; these are author estimates, not a local measurement. The link was read from the supplied repository; the browser tool could not access Box, so current remote availability was not independently confirmed. No large download was started.

The expected payload layout is:

```
data/
  benign/{h1,h2}/
  attack/{h1,h2}/
    cbc-edr/
    sysmon/
    msft-security/
    dns/
    firefox/
    ... other sensor and alert streams ...
```

The paper and README describe two Windows 7 victim VMs, four benign days and an attack day. The Kali attacker does not make this a Linux endpoint-telemetry dataset. THEIA supplies the Linux side of the proposed pair.

**Why REAPr contains several dataset names**

`reapr-ground-truth/` is a multi-dataset annotation repository. These directories are expected:

| Subdirectory | What the local download supplies |
|---|---|
| atlasv2 | 16 host/scenario .labels files, .seeds, attack descriptions and visualizations |
| darpa-tc-engagement3 | TC process labels, graph visualizations and newly included edge-label archives |
| carbanakv2 | Separate CARBANAKv2 label/seed files and visualizations |
| streamspot | StreamSpot process labels and documentation |
| utilities | Labeling/graph tooling and helper resources |

They are not additional raw telemetry datasets, and their labels must not be combined with ATLASv2 records. Approximately 711 MB is Git history; the TC subdirectory contains large edge-label archives. This explains why the repository can be large without containing ATLASv2 telemetry.

ATLASv2 labels: ten h1 files (s1-s4, m1-m6) plus six h2 files (m1-m6); 191 rows and 191 distinct process_uuid values, all labeled attack in this checkout. Columns are attack, process_name, process_id, process_uuid, label. This is a malicious-process list, not a fully materialized benign/malicious event table. Successful joining to raw telemetry has not been checked because that telemetry is absent. Use host/scenario plus stable identity; do not join solely by PID, or use label-file process_name as a substitute for missing feature data.

The supplied paper additionally describes EventRecordID ground truth within the original Windows Security payload. Those files were not downloaded here. They are distinct from the REAPr process labels and require their own source-specific mapping.

The new REAPr checkout also supplies `darpa-tc-engagement3/theia_edge_labels.tar.gz`: its CSV has attack_chain, vertex_uuid, vertex_label, edge_uuid; 68,929 rows (68,925 attack, 4 contaminated), 68,924 distinct edge UUIDs and 126 distinct vertex UUIDs. This audit inventories those annotations; it has not joined every edge UUID to the raw stream. They provide a published labeling option for an event-level adapter, with the publisher's mapping/evaluation assumptions, not new independent manual event annotations.

**ATLASv2 suitability for the existing models**

The instrumentation and the supplied THESEUS CBC parser make ATLASv2 a plausible Windows candidate, but do not establish actual field coverage in an absent download:

| Model | Candidate telemetry and mapping to verify |
|---|---|
| LightGBM | CBC process_path/process_cmdline, filemod and regmod events; Sysmon/Security supplementary evidence; map action/object/principal and parent-image semantics |
| Two-hop GraphSAGE | CBC procstart process_guid -> childproc_guid, childproc_name/target_cmdline, device_name and timestamps; netconn host/endpoint linkage |
| BiLSTM / Mixed-Type | Process-associated netconn events with executable path, timestamps, local/remote ports and direction; protocol still needs direct verification; normalize connection records before windowing |

The code reference is `paper-general/code/NDSS/theseus-main/scripts/create_csv_files_atlasv2.py`. It reads CBC fields but is not a raw-field census and should not be used as proof that every downloaded event supplies them. Prefer auditing `cbc-edr` and `sysmon` before rebuilding a reduced graph export. Do not use vendor alert/watchlist verdicts as ordinary features in a telemetry-only comparison.

ATLASv2 is a controlled multi-stage attack engagement: phishing/exploitation, execution and exfiltration, with lateral movement in m1-m6. It is not ten independent named APT campaigns. Both the paper and REAPr warn that attacks share most steps and the same payload method; VM snapshots also produce recurring startup activity. Its paper is explicitly unfavorable to multiclass attack-family claims.

For supervised incremental learning, using some attacks to learn and later testing related variants can be legitimate if described as such. It does not establish unseen-campaign generalization. Keep complete host/scenario executions together; splitting events/windows randomly is not an adequate leakage control. Even scenario-disjoint evaluation retains the documented attack-template similarity. Report adaptation and retained OpTC performance separately; fit preprocessing on training data only and freeze held-out evaluation sets. If THEIA is introduced after newer OpTC/ATLAS data, describe the sequence as simulated domain increments, not natural chronological collection order.

**Decision**

THEIA and ATLASv2 remain a sensible Linux/Windows pair to investigate, but are not yet two verified, drop-in incremental-learning datasets for the three frozen checkpoints. THEIA now has directly measured raw evidence; ATLASv2 still needs its actual telemetry. Resolve each model's representation and label unit explicitly. The existing Windows vocabulary/role/path rules do not become Linux-compatible simply because raw metadata is complete. The previous audit's zero THEIA basename matches against the local OpTC DL vocabulary remains relevant.

No training, checkpoint migration, frozen vocabulary/split changes, source-data edits or archive extraction into dataset roots were performed.

References inspected locally: ATLASv2 PDF; atlasv2/README.md; REAPr root/atlasv2/TC/StreamSpot READMEs and label files; THESEUS ATLAS exporter; existing model-field audit. Repository commits: atlasv2 `2fd77199fd7225b2387cbaded2b5b5de5da0de5b`; REAPr `32babb5613f7d8c4c9f7ab0a0e602da64521f149`. Reference hashes and the per-scenario label inventory are in `atlasv2_download_audit_2026-10-23.json`.
