# STEP 32 — Đọc KLTN-main.zip (nhánh Host), khả năng ánh xạ dòng lệnh, và kiểm tra FiveDirections: bản xử lý của THESEUS hay raw

Ngày: 2026-10-23. Mình giải nén `KLTN-main.zip` vào thư mục tạm và chỉ đọc (không chạy mã). Không tải dataset nào.

## 1. KLTN-main.zip có gì và liên quan thế nào đến fine-tune
Cấu trúc: `DL/` (bản mã và tài liệu của nhánh Network DL của bạn tại một thời điểm), `ML/` (nhánh Host của Nguyễn: `ML/code`, 23 tài liệu phân tích trong `ML/analyst`, README/AGENTS), `docs/` (đề cương, kiến trúc). Zip **không có** artifact đầu ra lớn (các chỉ mục, shards, graph SQLite 1.81 GB, checkpoint) nên không dùng trực tiếp được kết quả của họ.
Nhánh Host của Nguyễn:
- **Host ML:** RF, XGBoost, LightGBM trên **từng sự kiện eCAR** (không dùng FLOW), tokenizer có cấu trúc (`ecar_tokenizer.py`, `command_syntax.py`): `PROCESS`/`CREATE` cho ra token từ `command_line`, `image_path`, `parent_image_path` (họ launcher, công tắc, toán tử, quan hệ cha → con). Vocabulary 9,048 cột fit trên TRAIN. Kết quả TEST (1,249,689 sự kiện): LightGBM F1 95.33%, XGBoost 94.92%, RF 91.09%; có LightGBM + GraphSAGE cascade F1 98.50% (recall 98.57%).
- **GraphSAGE 2 hop (`provenace_graph`)**: đồ thị Process/Host với 4 quan hệ (`creates`, `communicates`, `communicates_reverse`, `hosts`), **40 thuộc tính hữu hạn** (`graph.py`): vai trò tiến trình (shell, script, office, browser, service, ...), vị trí (system, program_files, user, temp), **đặc điểm dòng lệnh** (`encoded`, `download`, `inline`, `hidden`, `remote_admin`) rút từ `command_line`, và phạm vi/dịch vụ mạng. Chỉ mục SQLite có bảng `fact(host, proc, fact, t)`, `parent(host, child, parent)`, `binding`, `flow`.
- Tài liệu của họ cũng ghi sẵn **hợp đồng join còn là việc tương lai**: `PROCESS.objectID → FLOW.actorID` và `FLOW.properties.bro_uid → Zeek.uid`; nhánh Host **không đọc Bro/eCAR-Bro**.
Giúp gì cho fine-tune:
1. **Đặc trưng dòng lệnh dạng tổng quát (không phải chuỗi thô)**: 5 đặc điểm `launch=` và 9 vai trò tiến trình là các thuộc tính hữu hạn, dùng được xuyên bộ dữ liệu (FiveDirections `cmd`, skrghosh `command_line`, OpTC log host). Đây là ứng viên tốt cho "đầu vào mở rộng" nếu bạn quyết làm.
2. **Chỉ mục graph của họ có đúng khóa cần để nối** `(hostname, actorID)` → thuộc tính tiến trình và chuỗi cha; nếu Nguyễn xuất bảng này (khoảng 1.8 GB hoặc chỉ cột cần thiết), có thể **tránh quét lại log host 6–7 giờ**. Mình chưa thấy file nên chưa kiểm được phủ.
3. Ghi chú nhãn: họ cũng nhận xét nhãn OpTC lan theo cây tiến trình (A New Hope) và đã kiểm chứng nhãn các dataset khác (CIC-APT-IIoT, AIT, Windows-APT, SAGA).
Không giúp trực tiếp cho vòng fine-tune hiện tại: tokenizer, mô hình cây, GraphSAGE đều làm ở mức sự kiện/đồ thị host; đầu vào của mô hình mạng B không thay đổi.

## 2. Dùng dòng lệnh: có khả thi không
**Về dữ liệu:** có. Log host thô OpTC (`E:\host-malicious`, `host-begnin`) có `command_line` ở sự kiện `PROCESS`/`CREATE`; FLOW mang `actorID` là UUID của tiến trình tạo ra flow; join theo `(hostname, actorID = PROCESS.objectID)`.
**Đo thử phủ ánh xạ (chỉ một máy, hai ngày, là thử nghiệm sơ bộ):** máy `sysclient0201`:
- 23/9 (có tấn công): 28.2% số dòng flow của OpTC có `actor_id` khớp một `PROCESS/CREATE` trong cùng file ngày; **100% flow dương (1,887/1,887) khớp**; 11,848 flow `firefox.exe` benign không khớp (trình duyệt chạy từ trước, không có sự kiện tạo trong ngày đó).
- 20/9 (benign): 100% khớp (5,039 dòng, 2 actor).
- Trên log host thô, 88% số actor có FLOW khớp, nhưng theo số sự kiện FLOW chỉ 3.5% vì một tiến trình giám sát (`lwabeat.exe`) chạy từ trước chiếm gần hết.
**Hai nguy cơ cần xử lý nếu làm:**
- **Rò rỉ nhãn qua độ phủ:** tiến trình độc thường mới được tạo (có CREATE) còn tiến trình benign dài hạn thì không; "có dòng lệnh hay không" sẽ tương quan với nhãn nếu để thiếu thành `<MISSING>`. Phải kiểm tra riêng và có thể phải tra thêm các ngày trước.
- **Độ chính xác ánh xạ chưa đo toàn bộ** (bài A New Hope báo khoảng 40% tiến trình bị gán sai theo họ; cần đo trên dữ liệu thật) và chi phí quét log host ~6–7 giờ nếu tự làm; hoặc dùng bảng `fact`/`parent` từ chỉ mục graph của Nguyễn.
Kết luận: **khả thi nhưng cần quyết định riêng** (đổi đầu vào, dựng lại shards OpTC, train lại OpTC trên Kaggle).

## 3. Có phải là fusion với nhánh Host không
Chưa phải, về mặt thuật ngữ trong đề tài (đây là các mức, từ yếu đến mạnh):
1. **Làm giàu ngữ cảnh tiến trình (hiện tại):** `app_family`, `image_dir_class` (và `principal_class` ở bản đầy đủ) lấy từ eCAR-Bro làm đầu vào của mô hình mạng. Đây không phải fusion với Host ML.
2. **Thêm dòng lệnh và đặc điểm cha-con vào đầu vào mạng** (mục 2): vẫn là làm giàu bằng telemetry host, **cùng mức 1**, chỉ nhiều trường hơn; có thể gọi "đầu vào đa nguồn" (early fusion thô) nhưng **không dùng mô hình Host**.
3. **Fusion mức điểm:** kết hợp điểm của mô hình Host (LightGBM/GraphSAGE trên sự kiện của tiến trình đó) với điểm mạng (STEP 17, đã làm sơ bộ; kết quả cải thiện 2/1,103 cửa sổ).
4. **Fusion mức đặc trưng / gating với source mask** (STEP 20, mới là thiết kế nháp): trộn biểu diễn của Host và mạng.
Chỉ từ mức 3 trở đi mới là "fusion với nhánh Host".

## 4. FiveDirections: bản đang có là bản xử lý của THESEUS, không phải raw
**Bằng chứng (đã đọc mã và tài liệu):**
- Bản trong `NEWDATASET (1)` là **Zenodo DOI 10.5281/zenodo.18450779** "Processed DARPA TC E3 Provenance Data..." (Parquet 17.9 GB, CSV 30.7 GB), của bài NDSS 2027 *How Benchmarks and Evaluation Protocols Shape Conclusions in Provenance-Based Intrusion Detection* (Guerra và cộng sự). README của repo THESEUS nói rõ đây là "Parquet and CSV node and event tables derived from the raw JSON logs"; xử lý raw cần ~500 GB đĩa và nhiều ngày.
- Mã tiền xử lý `scripts/create_csv_files_e3.py` (trong `research/code_references/NDSS/theseus-main`) cho thấy các trường bị bỏ:
  - **Netflow:** chỉ giữ `localAddress`, `localPort`, `remoteAddress`, `remotePort`; **bỏ nút nào thiếu một trong bốn giá trị**; không có giao thức IP, không có file descriptor. (Theo schema CDM18 từ trí nhớ, chưa tự kiểm chứng: `NetFlowObject` còn có `ipProtocol`.)
  - **Process:** chỉ giữ `path` (từ `path` hoặc `properties.map.path`) và `cmd` (`cmdLine`); bỏ `parentSubject`, `localPrincipal`, thời điểm bắt đầu, cid/pid, v.v.
  - **Event:** chỉ giữ `type`, chủ thể, đối tượng, `timestampNanos` (và dùng `predicateObjectPath` để điền đường dẫn file); **bỏ** `size`, `threadId`, `parameters`, `properties` của sự kiện. (Theo schema CDM18 từ trí nhớ, chưa kiểm chứng: `Event.size` là số byte gửi/nhận.) Có một danh sách loại bỏ loại cạnh (`EXCLUDE_EDGE_TYPE`).
  - Còn lọc: bỏ cạnh mà hai đầu không nằm trong bảng nút.
- Hệ quả đối với mô hình mạng của mình: raw **có thể** cho thêm `ipProtocol` và số byte (nếu CDM18 đúng như trên), tức gần hơn với `proto`, `orig_bytes/resp_bytes` mà mô hình gốc dùng; chuỗi cha-con và tài khoản chủ tiến trình cũng có. Vì vậy việc bạn của bạn nói "đã drop vài field" là **đúng**, và mình đã nói quá khi gọi cột `cmd` rỗng/`path` rỗng ở STEP 29 là đặc điểm của dataset; đó là kết quả xử lý của THESEUS.
- Mình **chưa đọc bài báo PDF** (`research/papers/How benchmarks and evaluation protocols...`), chỉ mã, README, trang Zenodo và README-E3 của DARPA; chưa mở file raw nên các điều ghi "từ trí nhớ" cần kiểm khi có raw.

## 5. Link raw gốc
- **DARPA TC Engagement 3, nguồn chính thức** (CDM18, Avro nhị phân, do Five Directions lưu trên Google Drive): https://drive.google.com/open?id=1QlbUFWAGq3Hpl8wVdzOdIoZLFxkII4EK (trang hướng dẫn: https://github.com/darpa-i2o/Transparent-Computing/blob/master/README-E3.md, trong đó nêu FiveDirections E3 gồm các topic `ta1-fivedirections-e3-official`, `-official-2`, `-official-3`; cần công cụ Java `ta3-java-consumer` để chuyển Avro sang JSON; kích thước không được nêu). Repo: https://github.com/darpa-i2o/Transparent-Computing
- **Bản raw dạng JSON mà THESEUS dùng** (script `download_raw_darpa_e3.sh`, gồm TRACE, CADETS, FIVEDIRECTIONS, THEIA, dạng `*.json.tar.gz` và `*.bin.tar.gz`): https://drive.google.com/drive/folders/1fOCY3ERsEmXmvDekG-LUUSjfWs6TRdp- (mình **không mở được** trang này bằng công cụ, nên chưa xác minh nội dung/kích thước; lấy từ mã của họ).
- Bản đã xử lý (đang có): https://doi.org/10.5281/zenodo.18450779 (Parquet, CSV), kèm artifact https://doi.org/10.5281/zenodo.22343430 và nhãn REAPr (https://bitbucket.org/sts-lab/reapr-ground-truth).
Mình chưa tải gì; tải về cần bạn quyết (dung lượng không rõ cho riêng FiveDirections; THESEUS ước ~500 GB cho cả 4 dataset khi xử lý).

## 6. Đề xuất
1. Chạy fine-tune hiện tại trên Kaggle với đầu vào hiện có (đã sẵn sàng, STEP 31).
2. Nếu muốn dùng dòng lệnh/byte/giao thức: (a) tải raw FiveDirections JSON để kiểm tra trường; (b) hỏi Nguyễn xuất bảng `(hostname, proc, facts, parent)` từ chỉ mục graph để nối cho OpTC; (c) thiết kế "đầu vào mở rộng" với đặc điểm dòng lệnh dạng hữu hạn, kiểm tra rò rỉ qua độ phủ, rồi train lại OpTC trên Kaggle.
