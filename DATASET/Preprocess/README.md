# OpTC Decoupled Sidecar Multi-Task Labeling System

This package implements the **Two-Tier Grounded Semantic Multi-Task Labeling** system for DARPA OpTC, replacing the brittle in-place dataset rewriting approach with a high-performance **Decoupled Sidecar Index**.

---

## 1. Design & Core Philosophy

1. **Dataset Immutability**:
   - The raw OpTC dataset (1+ TB compressed JSON) is strictly read-only.
   - Zero edits, zero rewrites, zero decompression in place.

2. **Sidecar Indexing (The 7.68 MB Catalog)**:
   - Only the **360,567 malicious events** are indexed into `output/optc_multitask_labels_v1.json.gz`.
   - Benign events (billions of events) require **0 bytes** of storage; any UUID not found in the catalog dynamically defaults to `(is_malicious=0, scenario=0, stage=0)`.

3. **Two-Tier Grounded Semantic Mapping**:
   - **Tier 1 (Corpus Anchor)**:
     - High-confidence scenario attribution derived from Provatek Red Team Ground Truth and Inria ground truth:
       - `SC1_EmpireStaging` (2019-09-23)
       - `SC2_CustomEmpireLateral` (2019-09-24 & overnight continuation)
       - `SC3_MaliciousUpdate` (2019-09-25 targeted update on sysclient0051 & sysclient0351)
   - **Tier 2 (Event-level Semantic Discriminator)**:
     - Dissects the actual intrinsic semantics of each eCAR event (`object`, `action`, `properties.command_line`, `properties.payload`, `parent_image_path`, destination IP):
       - `Execution` (T1059): General command executions and base PowerShell scripts.
       - `Defense_Evasion_Injection` (T1055): `THREAD:REMOTE_CREATE` and cross-process thread injection.
       - `Defense_Evasion_AMSI` (T1562): Memory patching of AMSI (`amsiInitFailed`).
       - `Discovery` (T1018, T1057): Subnet ping sweeps, `ipconfig`, `whoami`, process enumeration.
       - `Credential_Access` (T1003): Access to `lsass.exe` and Mimikatz execution (`lsadump`).
       - `Lateral_Movement` (T1021, T1047): RDP sessions (`mstsc.exe`), SSH tunnels (`plink.exe`), remote WMI.
       - `Persistence` (T1078, T1547): Backdoor user creation (`net user admin /add`), registry Run keys.
       - `Command_and_Control` (T1071): Network flows to known C2 server IPs/ports.
       - `Collection_Exfiltration` (T1560, T1048): File archiving (`export.zip`) and transfer via `nc.exe`.

---

## 2. Benchmark Performance

- **Generation Time**: 6.05 seconds for all 360,567 events.
- **Lookup Latency**: 59.2 nanoseconds per event ($O(1)$ in-memory hash map).
- **Lookup Throughput**: 16,898,616 events / second.

---

## 3. Usage

### Generate or Update Labels:
```bash
python3 DATASET/Preprocess/generate_multitask_labels.py --version v1
```

### Runtime Lookup in Python / DL DataLoader:
```python
from DATASET.Preprocess.label_catalog import MultiTaskLabelCatalog

catalog = MultiTaskLabelCatalog("DATASET/Preprocess/output/optc_multitask_labels_v1.json.gz")

# Returns (is_malicious, scenario_id, stage_id) in 59 nanoseconds
is_mal, sc_id, st_id = catalog.lookup(event_uuid)
```

### Run Tests:
```bash
python3 DATASET/Preprocess/test_multitask_labeling.py
```
