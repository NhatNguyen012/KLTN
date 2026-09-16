# EC2 Training Guide — OpTC Host ML (RF / XGBoost / LightGBM)

## Dataset facts (from `package_report.json`)

| Split | Rows | NNZ | On-disk bytes |
|-------|------|-----|---------------|
| **TRAIN** | 3,476,277,622 (~3.5 B) | 50,317,041,569 (~50 B) | 11.6 GiB |
| val   | 463,503,683 | 6,709,185,367 | 2.5 GiB |
| test  | 695,255,524 | 10,063,229,950 | 3.5 GiB |
| Total archive | — | — | **~18.2 GiB** |

Class imbalance TRAIN: **201,551 positives vs 3,476,076,071 negatives** (ratio ≈ 17,250 : 1)

---

## Memory math — what actually lands in RAM

The runtime materialises the sample as a **binary CSR matrix** (formula from [`host_training_runtime.py`](file:///mnt/SSD_Data/optc/code/kaggle/host_training_runtime.py#L287-L315)):

```
required_bytes = 8 × NNZ  +  4 × (rows + 1)  +  rows
                   ↑ float32+int32 indices     ↑ indptr   ↑ uint8 labels
```

> [!IMPORTANT]
> Random Forest additionally calls `X.tocsc()` inside `fit_sample_model`
> (line 571), so **RF needs ~2× the CSR bytes simultaneously**.

### Sample-size RAM map

| `TRAIN_TARGET_ROWS` | ~NNZ | CSR RAM | RF peak RAM | Notes |
|---|---|---|---|---|
| **100 M** (current) | 1.4 B | **~11 GiB** | ~22 GiB | Kaggle fits fine |
| 500 M | 7.2 B | **~56 GiB** | ~112 GiB | Kaggle out |
| 1 B | 14.5 B | **~112 GiB** | ~224 GiB | needs r7i.8xlarge+ |
| **FULL 3.5 B** | 50.3 B | **~391 GiB** | **~782 GiB** | only `u-` or `x2` class |

> [!CAUTION]
> The full 3.5 B row run requires **~400–800 GiB RAM** depending on model.
> XGBoost QuantileDMatrix and LightGBM Dataset compress the CSR internally,
> so they can work with 400-500 GiB. RF is the hard case at 780+ GiB.

---

## Library scalability — can they handle 3.5 B rows?

### ✅ LightGBM (`lgbm`)
- `Dataset(X, free_raw_data=True)` converts CSR → its internal compact bin format then **frees the raw matrix** — peak RAM is the CSR load + bin rebuild (~1.5× CSR), then settles to ~50–80 GiB for the binned data at 3.5 B rows.
- `num_leaves=31`, `force_col_wise=True`, `deterministic=True` — all production-safe at any scale.
- **No hard row limit.** LightGBM is designed for hundreds of millions of rows; billions are unusual but supported if RAM fits. `int32` leaf-index arrays cap at 2^31 rows but your sample planning code already guards `max(n, nz, width) >= 2**31`.
- ✅ **Works at full scale with ≥512 GiB RAM** (or ~256 GiB for ≤1 B sample).

### ✅ XGBoost (`xgb`)
- `QuantileDMatrix` (hist method) compresses to `max_bin=16` bins per feature; internal storage is `uint8` per bin, so it only needs ~**NNZ bytes** (50 GB at full scale) after construction, but building it requires the full CSR first.
- `device=cuda` enables GPU histogram acceleration — cuts tree build 10–30×.
- **No row limit** in `hist` mode. 3.5 B rows is large but XGBoost handles it (Microsoft and NVIDIA benchmarks go to billions).
- ✅ **Works at full scale with ≥512 GiB RAM for CPU, or GPU (A100/H100) with enough VRAM** (~80 GB VRAM for full NNZ at max_bin=16 is borderline; a 500 M sample is comfortable on 80 GB VRAM).

### ⚠️ Random Forest (sklearn `rf`)
- Requires **CSR + CSC simultaneously** (see `X.tocsc()` on line 571).
- Each tree bootstrap samples `rows × 32` bytes temporarily.
- `max_depth=20, min_samples_leaf=5, n_estimators=500` — each fully-grown tree on 3.5 B rows uses enormous in-memory node buffers.
- scikit-learn RF **does not stream data**; the entire dataset + CSC copy must fit in RAM.
- ⚠️ **At full 3.5 B rows, RF is impractical** — needs ~800 GiB RAM. Recommended max sample: **500 M rows (~112 GiB peak)**.

---

## EC2 Instance Recommendations

> **AMI** — there is **no stable single AMI ID**; AWS rotates them with every release.
> Use one of these two methods to get the correct ID in your region:
>
> ```bash
> # Method A: SSM parameter (always latest, simplest)
> aws ssm get-parameter \
>   --region us-east-1 \
>   --name /aws/service/deeplearning/ami/x86_64/oss-nvidia-driver-gpu-pytorch-2.5-ubuntu-22.04/latest/ami-id \
>   --query "Parameter.Value" --output text
>
> # Method B: describe-images (filter by name pattern)
> aws ec2 describe-images --region us-east-1 --owners amazon \
>   --filters 'Name=name,Values=Deep Learning OSS Nvidia Driver AMI GPU PyTorch 2.* (Ubuntu 22.04) ????????' \
>             'Name=state,Values=available' \
>   --query 'reverse(sort_by(Images, &CreationDate))[:1].ImageId' --output text
> ```
>
> For **CPU-only** r7i.8xlarge you can also use a plain Ubuntu 22.04 AMI
> (`ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*`) and install packages manually —
> cheaper and faster to boot since CUDA drivers are not needed.

> **EBS**: `gp3`, 200 GiB root + 1 TB data volume. Set **16,000 IOPS** and **500 MB/s throughput** for fast shard streaming.

---

### 🟢 Tier 1 — 500 M rows · RF + LightGBM + XGBoost CPU

**Instance**: `r7i.8xlarge`
- vCPUs: 32 | RAM: 256 GiB | Network: 12.5 Gbps | EBS: 10 Gbps
- On-demand: ~$2.02/hr | Spot: ~$0.60–0.80/hr

| Setting | Value |
|---------|-------|
| `TRAIN_TARGET_ROWS` | `500_000_000` |
| `CPU_THREADS` | `28` (leave 4 for I/O decode — or leave `None` to auto) |
| `DEVICE` | `cpu` (auto-detected) |
| `PROFILE` | `ec2-500m` |
| `MAX_MATRIX_GIB` | `90` |
| `MAX_SAMPLE_NNZ` | `7_500_000_000` |
| `BALANCE_CLASSES` | `False` (scale_pos_weight handles imbalance) |
| `SAMPLE_DIR` | shared across all 3 models: `train-500m-seed01` |

**Use for**: LightGBM ✅ · XGBoost CPU ✅ · RF ✅ (peak ~112 GiB, fits comfortably in 256 GiB)

> [!TIP]
> All 3 models share the **same sample directory** (`train-500m-seed01`). Build it once with any model
> first; the others will resume from the completed sample without re-scanning shards.

---

### 🟡 Tier 2 — Large sample (1 B rows) + XGBoost GPU

**Instance**: `g5.12xlarge`
- vCPUs: 48 | RAM: 192 GiB | GPUs: 4× A10G (24 GB each) | EBS: 8 Gbps
- On-demand: ~$5.67/hr | Spot: ~$1.70/hr

> [!NOTE]
> 192 GiB RAM fits a 1 B sample CSR (~112 GiB) plus QuantileDMatrix overhead. GPU accelerates XGBoost hist building significantly. LightGBM also fits. RF at 1 B rows needs ~224 GiB — use a smaller sample (500 M) for RF on this tier.

| Setting | Value |
|---------|-------|
| `TRAIN_TARGET_ROWS` | `1_000_000_000` (XGB/LGBM) · `500_000_000` (RF) |
| `CPU_THREADS` | `40` |
| `DEVICE` | `cuda` (XGB only) |
| `PROFILE` | `ec2-1b` |
| `MAX_MATRIX_GIB` | `120` |
| `MAX_SAMPLE_NNZ` | `15_000_000_000` |

**Use for**: XGBoost GPU ✅ · LightGBM CPU ✅ · RF at 500 M ✅

---

### 🔴 Tier 3 — Full 3.5 B rows · XGBoost + LightGBM only

**Instance**: `r7i.48xlarge` (or `r8g.48xlarge` for Graviton ARM)
- vCPUs: 192 | RAM: **1,536 GiB** | Network: 50 Gbps | EBS: 40 Gbps
- On-demand: ~$12.10/hr | Spot: ~$3.60–5.00/hr

> [!WARNING]
> At 3.5 B rows the `materialize_sample` code (line 291) checks `max(n, nz, width) >= 2**31` — your train rows (~3.5 B) **exceed int32 range**. The indptr array uses `int32`, which **overflows at 2.1 B rows**. You must either: (a) cap the sample below 2 B rows, or (b) patch the runtime to use `int64` indptr before running at full scale.

| Setting | Value |
|---------|-------|
| `TRAIN_TARGET_ROWS` | `2_000_000_000` (int32 safe max) |
| `CPU_THREADS` | `160` |
| `DEVICE` | `cpu` |
| `PROFILE` | `ec2-full` |
| `MAX_MATRIX_GIB` | `500` |
| `MAX_SAMPLE_NNZ` | `30_000_000_000` |

**Use for**: XGBoost ✅ · LightGBM ✅ · **RF NOT RECOMMENDED** at this scale

---

## Quick Launch & Run Script

```bash
#!/bin/bash
# ── 0. Resolve current AMI (run once, copy the output) ───────────────────────
AMI_ID=$(aws ssm get-parameter \
  --region us-east-1 \
  --name /aws/service/deeplearning/ami/x86_64/oss-nvidia-driver-gpu-pytorch-2.5-ubuntu-22.04/latest/ami-id \
  --query "Parameter.Value" --output text)
echo "Using AMI: $AMI_ID"

# For CPU-only r7i (RF/LGBM), a plain Ubuntu 22.04 is cheaper:
# AMI_ID=$(aws ec2 describe-images --region us-east-1 --owners 099720109477 \
#   --filters 'Name=name,Values=ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*' \
#             'Name=state,Values=available' \
#   --query 'reverse(sort_by(Images, &CreationDate))[:1].ImageId' --output text)

# ── 1. Launch EC2 Tier-1 (r7i.8xlarge, Spot) ────────────────────────────────
aws ec2 run-instances \
  --image-id "$AMI_ID" \
  --instance-type r7i.8xlarge \
  --key-name d-key-DVA-common \
  --security-group-ids sg-0ead10da8cfddfc24 \
  --subnet-id subnet-08cbcec2afa1c1b0e \
  --block-device-mappings '[
    {"DeviceName":"/dev/sda1","Ebs":{"VolumeSize":200,"VolumeType":"gp3","Iops":8000,"Throughput":250}},
    {"DeviceName":"/dev/sdb","Ebs":{"VolumeSize":1000,"VolumeType":"gp3","Iops":16000,"Throughput":500}}
  ]' \
  --instance-market-options '{"MarketType":"spot","SpotOptions":{"SpotInstanceType":"one-time"}}' \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=optc-host-ml-tier1}]'

# ── 2. SSH in ─────────────────────────────────────────────────────────────────
ssh -i ~/.ssh/d-key-DVA-common.pem ubuntu@<EC2_PUBLIC_IP>

# ── 3. Mount data EBS ─────────────────────────────────────────────────────────
sudo mkfs -t xfs /dev/nvme1n1
sudo mkdir -p /data /output
sudo mount /dev/nvme1n1 /data
echo '/dev/nvme1n1 /data xfs defaults,nofail 0 2' | sudo tee -a /etc/fstab

# ── 4. Upload your package ────────────────────────────────────────────────────
# From LOCAL machine (rsync over SSH):
rsync -avz --progress \
  /mnt/SSD_Data/optc/code/output/host_ml/kaggle_upload_ustar/host-input.tar \
  ubuntu@<EC2_PUBLIC_IP>:/data/

# Or stage via S3 first:
# aws s3 cp host-input.tar s3://your-bucket/host-input.tar
# aws s3 cp s3://your-bucket/host-input.tar /data/host-input.tar

# ── 5. Extract & install ──────────────────────────────────────────────────────
cd /data
tar -xf host-input.tar          # extracts manifest.json + volumes/
pip install lightgbm xgboost scikit-learn scipy numpy psutil threadpoolctl

# ── 6. Copy notebooks + runtime from your local machine ───────────────────────
rsync -avz /mnt/SSD_Data/optc/code/kaggle/host_{lgbm,rf,xgb}_shards.ipynb \
           /mnt/SSD_Data/optc/code/kaggle/host_training_runtime.py \
           /mnt/SSD_Data/optc/code/kaggle/host_shards.py \
           ubuntu@<EC2_PUBLIC_IP>:/data/

# ── 7. Run training (example: LightGBM 500M, nohup) ──────────────────────────
mkdir -p /output
export OPTC_MANIFEST=/data/manifest.json
export OPTC_OUTPUT=/output
export OPTC_SAMPLE_DIR=/output/train-500m-seed01
export OPTC_DEVICE=cpu

# Run as script (notebooks use the same runtime):
nohup python3 /data/host_lgbm_shards.ipynb   # wrong extension
# Correct way: extract and run the embedded code, OR use jupyter nbconvert:
pip install jupyter nbconvert
nohup jupyter nbconvert --to script --stdout /data/host_lgbm_shards.ipynb | \
  nohup python3 - > /output/lgbm_500m.log 2>&1 &
echo "Training PID: $!"
tail -f /output/lgbm_500m.log

# Alternatively, use the runtime directly:
nohup python3 - <<'PYEOF' > /output/lgbm_500m.log 2>&1 &
from pathlib import Path
import os, sys, json, subprocess

MODEL_NAME        = 'lgbm'
PROFILE           = 'ec2-500m'
MANIFEST          = Path(os.environ['OPTC_MANIFEST'])
OUTPUT_ROOT       = Path(os.environ.get('OPTC_OUTPUT', '/output'))
TRAIN_TARGET_ROWS = 500_000_000
NEG_PER_POS       = 30
SEED              = 1
CPU_THREADS       = 28
DEVICE            = 'cpu'
SAMPLE_DIR        = OUTPUT_ROOT / 'sample-500m'
MAX_MATRIX_GIB    = 90
MAX_SAMPLE_NNZ    = 7_500_000_000

sys.path.insert(0, '/data')   # adjust if host_shards.py is elsewhere
exec(open('/path/to/host_training_runtime.py').read())
PYEOF

echo "Training PID: $!"
tail -f /output/lgbm_500m.log
```

---

## Cost Estimate

| Tier | Instance | Spot $/hr | 500M LGBM | 500M XGB | 500M RF | 1B LGBM | 1B XGB GPU |
|------|----------|-----------|-----------|----------|---------|---------|------------|
| 1 | r7i.8xlarge | ~$0.70 | ~2h $1.40 | ~3h $2.10 | ~6h $4.20 | OOM | OOM |
| 2 | g5.12xlarge | ~$1.70 | ~2h $3.40 | ~1h $1.70 | ~4h $6.80 | ~4h $6.80 | ~2h $3.40 |
| 3 | r7i.48xlarge | ~$4.50 | ~1h $4.50 | ~2h $9.00 | ❌ | ~2h $9.00 | ~3h $13.50 |

> Evaluation over full val+test (1.16 B rows, streaming) adds ~1–3h more regardless of tier.

---

## XGBoost on g5.48xlarge — what changes?

**Short answer: Yes, change just the instance type to `g5.48xlarge` and set `DEVICE=cuda` (or `OPTC_DEVICE=cuda` env). Everything else can stay the same as Tier-1.**

### g5.48xlarge specs
- vCPUs: **192** | RAM: **768 GiB** | GPUs: **8× NVIDIA A10G** (24 GB VRAM each) | NVMe: 7.6 TB local SSD
- On-demand: ~$16.29/hr | Spot: ~$4.90–6.00/hr

### What to change vs Tier-1

| Setting | r7i.8xlarge (Tier-1) | g5.48xlarge XGB GPU |
|---------|---------------------|---------------------|
| Instance type | `r7i.8xlarge` | **`g5.48xlarge`** |
| `DEVICE` | `cpu` | **`cuda`** |
| `CPU_THREADS` | `28` | `160` (auto is fine too) |
| `TRAIN_TARGET_ROWS` | `500_000_000` | same — or raise to `1_000_000_000` (768 GiB fits it) |
| `MAX_MATRIX_GIB` | `90` | `120` (optional — RAM is huge) |
| Everything else | — | **unchanged** |

### Why only DEVICE matters for XGBoost
- `tree_method='hist'` with `device='cuda'` moves the histogram build to GPU.
- `QuantileDMatrix` construction is CPU-bound (reads CSR, bins features) — happens on CPU regardless.
  At 500 M rows this takes ~5–10 min. After that, all 300 rounds of tree building run on GPU (~20–40 min total vs ~3h CPU).
- **One A10G (24 GB VRAM)** is enough for 500 M rows × ~7.2 B NNZ at `max_bin=16` (uint8 = ~7.2 GB binned).
  XGBoost will use just GPU 0 unless you add `nthread` GPU-specific config; the others sit idle. That is fine.
- **RAM** is more than enough: 500 M row CSR ~56 GiB + QuantileDMatrix ~7 GiB + headroom ≪ 768 GiB.

### XGBoost GPU launch command

```bash
# Resolve AMI (same Deep Learning AMI with CUDA pre-installed)
AMI_ID=$(aws ssm get-parameter \
  --region us-east-1 \
  --name /aws/service/deeplearning/ami/x86_64/oss-nvidia-driver-gpu-pytorch-2.5-ubuntu-22.04/latest/ami-id \
  --query "Parameter.Value" --output text)
echo "Using AMI: $AMI_ID"

aws ec2 run-instances \
  --region us-east-1 \
  --image-id "$AMI_ID" \
  --instance-type g5.48xlarge \
  --key-name d-key-DVA-common \
  --security-group-ids sg-0ead10da8cfddfc24 \
  --subnet-id subnet-08cbcec2afa1c1b0e \
  --block-device-mappings '[
    {"DeviceName":"/dev/sda1","Ebs":{"VolumeSize":200,"VolumeType":"gp3","Iops":8000,"Throughput":250}},
    {"DeviceName":"/dev/sdb","Ebs":{"VolumeSize":1000,"VolumeType":"gp3","Iops":16000,"Throughput":500}}
  ]' \
  --instance-market-options '{"MarketType":"spot","SpotOptions":{"SpotInstanceType":"one-time"}}' \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=optc-xgb-gpu}]'
  
# ── 2. SSH in ─────────────────────────────────────────────────────────────────
ssh -i ~/.ssh/d-key-DVA-common.pem ubuntu@<EC2_PUBLIC_IP>

# ── 3. Mount data EBS ─────────────────────────────────────────────────────────
sudo mkfs -t xfs /dev/nvme1n1
sudo mkdir -p /data /output
sudo mount /dev/nvme1n1 /data
echo '/dev/nvme1n1 /data xfs defaults,nofail 0 2' | sudo tee -a /etc/fstab

# ── 4. Upload your package ────────────────────────────────────────────────────
# From LOCAL machine (rsync over SSH):
rsync -avz --progress \
  /mnt/SSD_Data/optc/code/output/host_ml/kaggle_upload_ustar/host-input.tar \
  ubuntu@<EC2_PUBLIC_IP>:/data/

# Or stage via S3 first:
# aws s3 cp host-input.tar s3://your-bucket/host-input.tar
# aws s3 cp s3://your-bucket/host-input.tar /data/host-input.tar

# ── 5. Extract & install ──────────────────────────────────────────────────────
cd /data
tar -xf host-input.tar          # extracts manifest.json + volumes/
pip install lightgbm xgboost scikit-learn scipy numpy psutil threadpoolctl

# ── 6. Copy notebooks + runtime from your local machine ───────────────────────
rsync -avz /mnt/SSD_Data/optc/code/kaggle/host_{lgbm,rf,xgb}_shards.ipynb \
           /mnt/SSD_Data/optc/code/kaggle/host_training_runtime.py \
           /mnt/SSD_Data/optc/code/kaggle/host_shards.py \
           ubuntu@<EC2_PUBLIC_IP>:/data/

# ── 7. Run training (example: LightGBM 500M, nohup) ──────────────────────────
mkdir -p /output
# On the instance:
export OPTC_MANIFEST=/data/manifest.json
export OPTC_OUTPUT=/output
export OPTC_SAMPLE_DIR=/output/train-500m-seed01   # share with r7i sample if using S3
export OPTC_DEVICE=cuda   # ← the only real change

nohup python3 - <<'PYEOF' > /output/xgb_gpu_500m.log 2>&1 &
from pathlib import Path
import os, sys, json, subprocess

MODEL_NAME        = 'xgb'
PROFILE           = 'ec2-500m'
MANIFEST          = Path('/data/manifest.json')
OUTPUT_ROOT       = Path('/output')
TRAIN_TARGET_ROWS = 500_000_000
NEG_PER_POS       = 30
SEED              = 1
CPU_THREADS       = 160          # ← larger machine; I/O decode uses 4
DEVICE            = 'cuda'       # ← the only meaningful change
SAMPLE_DIR        = OUTPUT_ROOT / 'train-500m-seed01'
MAX_MATRIX_GIB    = 120
MAX_SAMPLE_NNZ    = 7_500_000_000
BOOST_ROUNDS      = 300
RF_TREES          = 500
BALANCE_CLASSES   = False
DEDUPE_PREDICTION = True
DEDUPE_BUDGET_MIB = 256
RANKING_BINS      = 100_000

sys.path.insert(0, '/data')
exec(open('/data/host_training_runtime.py').read())
PYEOF
```

> [!NOTE]
> The runtime already handles `device=cuda` for XGBoost and automatically switches back to `device=cpu`
> for evaluation inference (line 593: `model.set_param({'device':'cpu', ...})`). No other code changes needed.

---

## Key Caveats & Required Patch

> [!CAUTION]
> **int32 overflow at >2.1 B rows**: [`materialize_sample`](file:///mnt/SSD_Data/optc/code/kaggle/host_training_runtime.py#L287-L315) line 291 raises `MemoryError` if `max(n, nz, width) >= 2**31`. Since `train_rows = 3,476,277,622 > 2^31`, attempting `TRAIN_TARGET_ROWS = None` (full train) will crash. Cap at `TRAIN_TARGET_ROWS ≤ 2_000_000_000` OR patch the CSR construction to use `int64` indptr.

> [!NOTE]
> **Spot interruption**: Use `checkpoint_every=25` (default) so you lose at most 25 rounds/trees. Attach an EBS root volume (not instance store) so checkpoints survive termination. Resume is fully automatic.

> [!TIP]
> **Fastest path to large-scale XGBoost**: Use `g5.48xlarge` (768 GiB RAM, 8× A10G) with `DEVICE=cuda`. The `QuantileDMatrix` at 500 M rows builds in ~5 min on CPU, then 300 rounds run in ~25 min on one A10G GPU. Total ~30 min vs ~3h on r7i.8xlarge CPU.
