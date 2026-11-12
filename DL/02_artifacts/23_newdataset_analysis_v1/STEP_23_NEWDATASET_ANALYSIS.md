# STEP 23 — Phân tích sơ lược 5 dataset mới và đề xuất bỏ field Bro để train lại DL

Ngày: 2026-10-21. Nguồn: `E:\NEWDATASET` (giải nén từ `NEWDATASET.7z`). Mã và log: `scripts/`, `tc_e3_netflow_stats.out.txt`. Chỉ đọc dữ liệu, không ghi vào `E:`. Số liệu bên dưới do mình tự đếm lại từ dữ liệu; số liệu trong `NewDataset.md` chưa kiểm chứng thì không dùng (ví dụ nhãn FIN6 thật có 2,354,056 dòng, báo cáo ghi 2,601,757).

## 1. Mô hình hiện tại cần gì (OpTC v2, `preprocess_spec.json`)
| Nhóm | Field |
|---|---|
| Category (7) | `app_family`, `proto`, `service`, `conn_state`, `resp_port_class`, `image_dir_class`, `principal_class` |
| Numeric (7) | `duration`, `orig_bytes`, `resp_bytes`, `orig_pkts`, `orig_ip_bytes`, `resp_pkts`, `resp_ip_bytes` |
| Nhị phân / thời gian | `has_missed_bytes`, `delta_t_log1p` |
Nguồn: `app_family`, `image_dir_class`, `principal_class` từ eCAR-Bro (host); còn lại là Bro conn.

## 2. Thuộc tính từng dataset (chỉ phần liên quan flow mạng + ngữ cảnh tiến trình)
| Dataset | Đơn vị flow | Có | Không có | Nhãn |
|---|---|---|---|---|
| **skrghosh** (Windows, eCAR JSON, 5 chiến dịch) | `object=FLOW`, action `START` (mở) và `MESSAGE` (mỗi gói/đoạn có `size`) | `image_path`, `src/dest ip`, `src/dest port`, `l4_protocol`, `direction`, `size`, `timestamp`, `pid/ppid/actorID` | `principal` rỗng 100% ở FLOW; không `conn_state`, `service`, `duration`, số gói; `hostname` luôn `localhost` (mỗi file = 1 máy) | `labeled/*.labels.csv` theo `id` sự kiện (lineage `splunkd.exe`) |
| **THEIA** (Linux, provenance) | cạnh tiến trình → netflow: `EVENT_SENDMSG/SENDTO/CONNECT/WRITE_SOCKET_PARAMS` | `process.path`, `cmd`, `dst_addr`, `dst_port`, `timestamp_rec` | không byte, không proto, không user; `dst_port=0`/`NA` ở phần lớn event | UUID tiến trình (126 dòng nhãn) |
| **CADETS** (FreeBSD) | cạnh tiến trình → netflow: `WRITE/CLOSE/SENDTO/CONNECT` | `dst_addr`, `dst_port`, `timestamp_rec` | `process.path` không ghép được bằng khóa dùng ở đây (cột `path` rỗng sau join; cần kiểm tra lại khóa); không byte/proto/user | UUID tiến trình (102,359 dòng nhãn) |
| **CIC-APT-IIoT-2024** | flow CICFlowMeter, 70+ cột thống kê | IP/port, proto, `flow_duration`, cờ TCP, số gói/byte tổng, `ts` | **không có ngữ cảnh tiến trình** (không `app_family`, `image_dir`, `principal`) | `label`, `subLabel` (tactic), `subLabelCat` (technique) |
| **AIT_Log_V2.1** (Linux) | không có flow mức kết nối được gán nhãn | log auditd/apache/dnsmasq/openvpn/auth có nhãn 0/1; Suricata `eve.json` nằm trong `gather/` nhưng không có nhãn | không Zeek | 945,055/1,439,105 dòng dương, 99% là dirb/wpscan trên Apache |

### Số liệu đã đếm
- **skrghosh FLOW** (hai chiến dịch đã đếm; `scripts/skrghosh_flow_stats.py`):
  - FIN6: 435,313 sự kiện FLOW, **6,000 dương**; `image_path` dương chủ yếu `C:\Users\Public\splunkd.exe` (5,062) và `powershell.exe` (937); đích dương 3 IP; cổng dương `8888` (4,908), `443` (820), `5353` (272).
  - APT29: 705,218 sự kiện FLOW, **11,565 dương**; dương gồm `powershell.exe` 6,835, `splunkd.exe` 4,730; cổng `443` 6,695, `8888` 4,870.
  - Benign áp đảo là `python3.11.exe` (192,923 ở FIN6; 552,566 ở APT29), `msedge.exe`, `chrome.exe`, `svchost.exe`.
  - `principal`: rỗng 100% (cả dương lẫn âm). `l4_protocol`: `6`, `17` và cả giá trị `4` (inbound, 332,739 benign ở FIN6) → giá trị `4` không có trong từ điển OpTC.
  - `size` có ở hầu hết sự kiện MESSAGE (423,076/429,313 âm; 5,995/6,000 dương) nhưng là kích thước từng mảnh, không phải orig/resp bytes của Bro.
- **THEIA** (`tc_e3_netflow_stats.out.txt`): 44.4M cạnh; 186,100 netflow node; **3,818,431 cạnh tiến trình→netflow**, trong đó **64,012 dương (1.7%) từ 114 tiến trình, nhưng 63,608 cạnh thuộc đúng một tiến trình `/var/log/mail`** và 3 IP đích; 2,809,658 cạnh (74%) có `dst_port=0`; dương gần như toàn `dst_port=0` (63,714). Khoảng thời gian 2018-04-03 → 04-13.
- **CADETS**: 445,689 cạnh tiến trình→netflow; 75,423 cạnh có nhãn dương (17%), 22 IP đích; cổng 53 chiếm 40,437 cạnh dương và 132,932 cạnh âm (cổng không phân biệt được). Chưa lấy được đường dẫn tiến trình.
- **CIC-APT-IIoT**: phase1 12,062,396 flow, 100% benign; phase2 9,535,819 benign + **1,004 tấn công** (2 IP nguồn, 2 IP đích, 47 cổng đích); `ts` là epoch giả lập NS-3 (Readme: phải dịch thời gian).

## 3. Tính phù hợp với mô hình Network DL hiện tại
| Dataset | Dùng được với đầu vào "flow + ngữ cảnh tiến trình"? | Nhận xét (có hạn chế) |
|---|---|---|
| skrghosh | **Có, tốt nhất** | Cùng Windows/eCAR; có `app_family`, thư mục chạy, cổng, giao thức, thời gian. Phải gộp `MESSAGE` theo `objectID` thành flow; thiếu `principal`; mỗi file 1 máy nên cửa sổ khóa theo (file/máy, 15 phút), không phải hostname. Dương chủ yếu là beacon `splunkd.exe`/`powershell.exe` (cùng kiểu bẫy beacon của OpTC) |
| THEIA | Một phần | `app_family` từ đường dẫn Linux (không có từ điển chung với Windows), `image_dir_class` hiện tại là luật Windows nên không dùng được nguyên; thiếu cổng (74% `0`); dương bị chi phối bởi 1 tiến trình |
| CADETS | Thấp lúc này | Chưa có tên tiến trình; cổng 53 không phân biệt; nhãn tiến trình dày (75k cạnh dương) |
| CIC-APT-IIoT | Chỉ phần mạng | Không có ngữ cảnh tiến trình nên không có 3 field host; chỉ 1,004 flow dương ở phase2; phù hợp làm thử nghiệm độc lập, không phải thử nghiệm "học từ OpTC" |
| AIT | Không | Không có flow mạng gán nhãn |

## 4. Field nào phải bỏ để cùng một mô hình tiền xử lý được dataset mới
Tiêu chí: field phải tính được **cùng nghĩa** từ skrghosh/THEIA/CADETS (các dataset có ngữ cảnh tiến trình).

| Field | skrghosh | THEIA/CADETS | Quyết định đề xuất |
|---|---|---|---|
| `service` | không | không | **Bỏ** (Bro-only) |
| `conn_state` | không | không | **Bỏ** (Bro-only) |
| `duration`, `orig_bytes`, `resp_bytes`, `orig_pkts`, `resp_pkts`, `orig_ip_bytes`, `resp_ip_bytes`, `has_missed_bytes` | chỉ xấp xỉ khác nghĩa (gộp `MESSAGE`) | không | **Bỏ** |
| `principal_class` | **rỗng 100%** | không | **Bỏ** (đề xuất thêm; xem mục 5) |
| `proto` | có (cần ánh xạ `6→tcp`, `17→udp`, `4→<UNK>`) | không (THEIA/CADETS) | Giữ, nhưng trong OpTC TRAIN chỉ 72 flow UDP/59.9M nên gần như không mang tín hiệu |
| `resp_port_class` | có (cần xác định hướng) | có nhưng nhiều `0` ở THEIA | Giữ |
| `app_family` | có | có (đường dẫn Linux) | Giữ |
| `image_dir_class` | có (luật Windows áp dụng được) | cần luật Linux riêng | Giữ |
| `delta_t_log1p` | có | có | Giữ |

**Phương án A (tối thiểu, đúng yêu cầu "bỏ field mạng của Bro"):** bỏ 10 field Bro-only. Còn 6 đầu vào: `app_family`, `image_dir_class`, `principal_class`, `proto`, `resp_port_class`, `delta_t_log1p`.
**Phương án B (đề xuất):** A + bỏ `principal_class` → 5 đầu vào: `app_family`, `image_dir_class`, `proto`, `resp_port_class`, `delta_t_log1p`.

## 5. Cảnh báo (cần nói rõ trước khi train)
1. Sau khi bỏ field Bro, thông tin còn lại gần như chỉ là `app_family`/`image_dir_class`/(`principal_class`) + cổng. Đây chính là các field đã cho luật "có `powershell.exe`" đạt F1 0.994 trên TEST OpTC (S7). Vì vậy F1 trên OpTC sau khi bỏ field **không** phải bằng chứng mô hình học thêm điều gì; chưa train nên chưa biết F1 sẽ là bao nhiêu.
2. `principal_class = ADMINISTRATOR` có 13,297 flow dương và 0 benign trong OpTC (đặc điểm testbed). Ở dataset mới trường này trống, nên nếu giữ, mô hình sẽ dựa vào tín hiệu không tồn tại ở dữ liệu mới.
3. Từ điển `app_family` của OpTC không chứa `splunkd.exe`, `python3.11.exe`… của skrghosh, nên chúng thành `<UNK>`. Dự đoán chưa kiểm chứng: zero-shot sang skrghosh chỉ bắt được phần `powershell.exe`; benign `python3.11.exe` (UNK) có nguy cơ báo nhầm. Cần fine-tune với từ điển mở rộng (giữ id cũ cho token chung, thêm token mới).
4. Dương của skrghosh/THEIA vẫn là beacon C2 lặp / một tiến trình chi phối, tức là cùng kiểu rủi ro shortcut như OpTC.

## 5b. Đối chiếu 9 file md của bạn (`03_datasets/others/1..9.md`, câu trả lời AI chưa kiểm chứng) với dữ liệu thật (2026-10-21)
Các ý dùng được: mở rộng từ điển bằng cách **nối thêm** token mới, giữ nguyên id cũ của OpTC (9.md); replay buffer trộn một phần mẫu OpTC khi fine-tune (5.md, 8.md); freeze rồi mở khóa với lr nhỏ (8.md); đo BWT/FWT (5.md, 9.md); source mask khi thiếu field host (5.md, 7.md).
Các ý **sai hoặc không kiểm chứng được**:
| Khẳng định trong md/ảnh | Kiểm tra trên dữ liệu |
|---|---|
| skrghosh là Sysmon (ảnh, 2.md) | Là định dạng eCAR (`object=FLOW`, `action=START/MESSAGE`, `image_path`, `l4_protocol`), không phải Sysmon |
| AIT auditd có `faddr`/`fport`, protocol "từ syscall" (ảnh) | `audit.log` của fox/harrison chỉ có 0–4 dòng `SYSCALL` và 0 dòng `SOCKADDR`/`faddr`/`syscall=42` (connect); toàn bộ là PAM/service (`USER_START`, `LOGIN`, `SERVICE_START`...) |
| AIT có Zeek log (7.md) | Không có Zeek. Mạng nằm ở Suricata `eve.json` (flow có `dest_ip/dest_port/proto`, bytes, pkts, state) nhưng **không có tên tiến trình** và file nhãn không phủ `eve.json` |
| THEIA netflow có `local_ip/remote_ip` (7.md) | Cột thật: `src_addr, src_port, dst_addr, dst_port`; 74% cạnh có `dst_port=0` |
| `principal_class`: root→ADMINISTRATOR cho THEIA (7.md) | Bảng THEIA/CADETS không có user của tiến trình |
| Bảng F1 mẫu (0.953/0.941..., 0.05→0.932...) (5.md, 9.md) | Là số minh họa do AI viết, chưa có thí nghiệm nào; không dùng |
| Hướng "đổi BiLSTM sang chuỗi hành vi tiến trình PROC_SPAWN/FILE_WRITE..." (9.md) | Là hướng thiết kế khác với quyết định đã chốt (giữ kiến trúc, train một lần); chưa đề xuất làm |

## 6. Cách thực hiện bước train lại (đã build, chờ bạn chạy Kaggle)
**Đã chọn phương án B (người dùng, 2026-10-21).** Đầu vào còn lại: `app_family`, `proto`, `resp_port_class`, `image_dir_class` (4 category) và `delta_t_log1p`. Bỏ: `service`, `conn_state`, `principal_class`, 7 numeric Bro (`duration`, `orig_bytes`, `resp_bytes`, `orig_pkts`, `orig_ip_bytes`, `resp_pkts`, `resp_ip_bytes`), `has_missed_bytes` (đặt hằng 0 vì mô hình Mixed-Type yêu cầu đúng 1 token nhị phân; token hằng không mang thông tin).
- Không build lại shards; dùng lại gói Kaggle v2 đã upload (`v2_network_dl_kaggle_upload`). Mã: `01_code/pipeline_v2/s8_notebooks_subset.py` (sinh notebook), `s8_smoke_test.py` (chạy thử CPU). Notebook: `04_notebooks/06e_BiLSTM_Kaggle_v2_subsetB.ipynb`, `07e_Mixed_Type_Kaggle_v2_subsetB.ipynb`. Tên run: `bilstm_v2_subsetB`, `mixed_v2_subsetB`.
- Cách làm: một cell sau bước resolve dataset ghi `preprocessing/feature_subset.json` và sửa `network_preprocess_spec.json` trong bản làm việc (không đụng dataset gốc); loader cắt `x_cat` theo cột giữ, `x_num` còn 0 cột. Kiến trúc và siêu tham số giữ nguyên 06d/07d; seed 42; VAL chọn checkpoint/ngưỡng, TEST chạy một lần.
- Chạy thử CPU (shards local, vài batch): cả hai mô hình dựng đúng `[CAT] app_family 61, proto 4, resp_port_class 11, image_dir_class 10`, `[NUM] []`; số tham số BiLSTM 78,698, Mixed-Type 144,065; train/validate/chọn ngưỡng chạy hết. Lỗi duy nhất là thiếu `matplotlib` trên máy local khi vẽ đường cong (giống lần chạy thử bản 06d/07d; Kaggle có sẵn). Chỉ số PR-AUC trong lần chạy thử bằng 0 vì chỉ chạy vài batch đầu không có mẫu dương, không có ý nghĩa.
- Train chạy trên Kaggle do người dùng chạy (chưa chạy).
