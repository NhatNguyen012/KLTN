# Multi-Container ML & DL APT Detection Stack (`Docker/`)

Triển khai hệ thống phát hiện APT gồm **3 Docker containers** độc lập (`optc-ml-service` cổng `8001`, `optc-dl-service` cổng `8002`, `optc-soc-ui` cổng `8080`) giao tiếp qua REST API (`network_mode: host` tương thích cấu hình `"bridge": "none"` trên máy chủ này), kèm giao diện Web SOC cơ bản (`http://localhost:8080`):

1. **`ml-service` (port `8001`)**: Mô hình **Host ML LightGBM** (`300` cây, `10,317` đặc trưng, ngưỡng VAL `0.87427`) + bộ tiền xử lý thời gian thực `ecar_tokenizer` & `HostProcessContextTracker` (Parent + Incoming past-only).
2. **`dl-service` (port `8002`)**: Mô hình **Host DL Unified Continual Learning `ExpandableMixHeadCausalIL`** (`theia_mixhead_il_best.pt`, `20,937` tokens) chạy song song cho **cả OpTC Windows eCAR lẫn DARPA TC E3 THEIA Linux** mà **không cần Task-ID**, xuất đủ 3 heads (`Binary`, `6 Scenarios`, `14 MITRE Stages`) + `Line Attention Weights` (`E_incoming`, `E_parent`, `E_current`).
3. **`ui-service` (port `8080`)**: Gateway REST + Giao diện Web SOC (`index.html`), cho phép bấm chạy ngay các kịch bản tấn công thật hoặc tải/dán file log `.jsonl` / `.json` / `.json.gz`.

---

## Khởi chạy nhanh

```bash
# 1. (Tuỳ chọn) Tái tạo lại bộ log mẫu thật từ tập TEST không rò rỉ
python3 /mnt/SSD_Data/optc/Docker/scripts/export_demo_samples.py

# 2. Build & khởi động cả 3 containers
cd /mnt/SSD_Data/optc/Docker
docker compose up -d --build

# 3. Kiểm tra sức khoẻ & chạy bộ test đầu-cuối
python3 /mnt/SSD_Data/optc/Docker/tests/test_docker_stack.py
```

Mở trình duyệt tại **http://localhost:8080**.

---

## Nguồn log tấn công để đưa vào kiểm thử

Toàn bộ log mẫu dựng sẵn trong `sample_logs/` được trích **100% từ dữ liệu thật thuộc tập TEST (chưa từng dùng khi huấn luyện/validation)** — **tuyệt đối không rò rỉ nhãn** vì gateway gỡ bỏ toàn bộ trường `label` / `_meta_truth` trước khi gửi sang `ml-service` và `dl-service`:

- **OpTC SC1 (`optc_sc1_empire_staging_test.jsonl`)**: Trích từ `DATASET/DARPA-OPTC/host-malicious/2019-09-23` (`sysclient0201`, chiến dịch Empire Staging), kết hợp lịch sử `PROCESS CREATE / OPEN` quá khứ (`warmup`) của chính host đó để tracker dựng đúng ngữ cảnh cha + incoming.
- **OpTC SC2 (`optc_sc2_custom_empire_lateral_test.jsonl`)**: Trích từ `DATASET/DARPA-OPTC/host-malicious/2019-09-24` (`sysclient0203`, Custom Empire Lateral Movement).
- **OpTC SC3 (`optc_sc3_malicious_update_test.jsonl`)**: Trích từ `DATASET/DARPA-OPTC/host-malicious/2019-09-25` (`sysclient0051`, Malicious Update).
- **DARPA TC E3 THEIA (`theia_linux_apt_test.jsonl`)**: Trích từ các shard TEST sạch `IL/dataset_4-THEIA/output/dl_shards/test/` (`NationState_Firefox_Drakon` + `BrowserExtension_MicroAPT`, bao gồm các sự kiện `/tmp/memtrace.so`, portscan và C2 beacon).

Người dùng cũng có thể dán hoặc upload bất kỳ file log JSONL / XML Sysmon nào rút ra từ `DATASET/DARPA-OPTC/host-malicious/**/*.json.gz`, `DATASET/Kellect4APT/`, `OTRF/Security-Datasets` (`empire_apt3`, `caldera_apt3`) hoặc `splunk/attack_data` (`windows-sysmon.log`). Module `shared/schema_adapters.py` tự động ánh xạ các schema Windows ETW / Sysmon JSON & XML / PowerShell / DARPA CDM về chuẩn OpTC eCAR trước khi chạy suy luận.

---

## Kiểm chứng ngoài phân phối (Zero-Shot Benchmark trên log thật chưa từng train)

- `scripts/eval_unseen_datasets.py`: Benchmark `Kellect4APT` (Windows ETW 5 kỹ thuật ATT&CK) & `DARPA-TC-E3-FIVEDIRECTIONS` (REAPr ground truth), so sánh trực tiếp khi chưa chuyển đổi schema (`adapt_external=False`) vs đã chuyển đổi (`adapt_external=True`).
- `scripts/eval_github_repos.py`: Benchmark log thật từ GitHub `OTRF/Security-Datasets` (`empire_apt3`, `caldera_apt3`) và upload file XML `splunk/attack_data` `T1003.001`.
