# STEP 35 — Quét streaming raw FiveDirections E3 (CDM18 JSON): có thêm trường nào so với bản THESEUS

Ngày: 2026-10-23. Mã: `01_code/pipeline_v2/s16_fd_raw_peek.py` (xem vài dòng đầu), `s16_fd_raw_scan.py` (quét). Đọc streaming từ `.tar.gz`, **không giải nén ra đĩa**; chỉ đọc `03_datasets/ta1-fivedirections-e3-official*.json.tar.gz`. Số liệu: `scan_official.json`, `scan_official-3.json` (log kèm theo). Thời gian: `official-3` 54 giây, `official` 228 giây. Số liệu do mình tự đếm trên file thật; phần "bản THESEUS" so với schema Parquet đọc trực tiếp từ `E:\NEWDATASET (1)\DARPA-TC-E3-FIVEDIRECTIONS\Parquet`.

## 1. Hai file đã có nằm NGOÀI các ngày có nhãn tấn công
| File | Kích thước (gz → JSON) | Dòng | Khoảng thời gian (UTC) | Subject / NetFlowObject / Event |
|---|---|---:|---|---|
| `official` | 1.0 GB → 15.8 GB | 21.8 M | **2018-04-03 12:16 → 04-04 12:42** | 38,793 / 3,445 / 21.1 M |
| `official-3` | 0.22 GB → 3.8 GB | 4.75 M | **2018-04-13 13:37 → 21:08** | 10,688 / 1,818 / 4.5 M |
Khoảng thời gian lấy từ `TimeMarker` và từ các sự kiện mạng/mẫu 1/200 (đủ chính xác cỡ vài phút, không phải min/max tuyệt đối của mọi sự kiện). Bản Parquet THESEUS chạy **04-04 13:53 → 04-13 21:08** (`event_table`, 161 M cạnh). Hệ quả: `official` nằm **trước** phần Parquet (không có nhãn nào của mình rơi vào đó), `official-3` trùng ngày cuối của Parquet. Ba đợt dương của mình rơi vào **04-09, 04-11, 04-12** (xem `sample_features_fivedirections.csv`) nên cần file thứ ba `official-2` (11.5 GB, hiện còn đang tải; ~6.7 GB lúc kiểm tra) để nối trường mới với mẫu dương. Suy luận này (file `-2` phủ khoảng 04-04 → 04-13 sáng) mình **chưa kiểm** cho tới khi quét được file đó.

## 2. Trường có trong raw mà bản THESEUS đã bỏ (đã kiểm trên file thật)
Schema Parquet: `netflow_node_table` = `src_addr, src_port, dst_addr, dst_port`; `process_node_table` = `path, cmd`; `event_table` = `src_node, dst_node, operation, timestamp_rec` (không có size, thread, principal).
| Trường raw | Có trong raw? | Ghi chú đo được |
|---|---|---|
| `NetFlowObject.ipProtocol` | **Có, 100% bản ghi** (int) | `official`: UDP(17) 3,176 (92%), TCP(6) 263 (7.6%), ICMPv6(58) 4, IGMP(2) 2. `official-3`: UDP 1,769 (97%), TCP 41, ICMPv6 6, IGMP 2. Bản Parquet không có; STEP 29 phải để `proto` = thiếu |
| `Event.size` (byte) | **Có trên mọi sự kiện**, nhưng chỉ khác 0 ở `EVENT_SENDTO` và `EVENT_RECVFROM` | `official` SENDTO: 221,398 sự kiện, tổng 2.32 GB, lớn nhất 1 MiB; RECVFROM: 297,552 sự kiện, tổng 31.4 MB, lớn nhất 520 KB. `CONNECT, ACCEPT, BIND, RECVMSG, SENDMSG`: `size` luôn 0 (RECVMSG 2,721 sự kiện toàn 0, nên byte nhận qua RECVMSG không đo được). Tức byte gửi/nhận có thể cộng theo flow, với hạn chế đó |
| `Subject.cmdLine` | Có, **chỉ ở tiến trình** (`SUBJECT_PROCESS`), không ở thread | `official`: 1,340/1,412 tiến trình (95%); `official-3`: 533/582 (92%). Ví dụ: `explorer.exe`, `cmd.exe`, lệnh Windows Defender `MpCmdRun.exe -IdleTask ...`. (Bản Parquet THESEUS đã giữ `cmd` ở `process_node_table`, nên dòng lệnh **không** mới so với Parquet.) |
| `Subject.parentSubject` | **Có**, 99.8% bản ghi (`official`: 38,710/38,793) | UUID của subject cha (cha của thread là tiến trình; cha của tiến trình là tiến trình tạo ra nó). Parquet không có. Chưa kiểm cha có `cmdLine` hay đúng cây tiến trình |
| `Subject.localPrincipal` + `Principal.username` | Có (100% subject có `localPrincipal`); `Principal` có 14 (`official`), 10 (`-3`) bản ghi, `username` có ở 13/14 | Parquet không có. Đây là tương đương `principal` của eCAR-Bro |
| `Subject.properties` | **Luôn null** | không có ppid dạng map; cây tiến trình chỉ qua `parentSubject` |
| `NetFlowObject.baseObject`, `fileDescriptor` | luôn null (trừ `hostId`) | không có thêm |
| Hướng kết nối | Không có trường hướng; suy từ loại sự kiện (`CONNECT` = ra, `ACCEPT` = vào) | giống bản THESEUS |
| Thời gian | `timestampNanos` epoch UTC (ns) của từng sự kiện | Parquet có `timestamp_rec` tương tự |

## 3. Nối được flow → tiến trình → dòng lệnh → cha trong chính file raw
Sự kiện mạng (`CONNECT, ACCEPT, SENDTO, RECVFROM, SENDMSG, RECVMSG, BIND`) có `subject` (UUID subject) và `predicateObject` (UUID NetFlowObject):
| | `predicateObject` là NetFlowObject | `subject` có mặt trong file | subject có `cmdLine` | subject có `parentSubject` |
|---|---:|---:|---:|---:|
| `official` (526,541 sự kiện mạng) | 523,652 (99.5%) | 100% | 523,180 (99.4%) | 525,759 (99.9%) |
| `official-3` (155,883) | 153,703 (98.6%) | 100% | 122,286 (**78.4%**) | 155,319 (99.6%) |
Ở `official-3` tỉ lệ có `cmdLine` thấp hơn rõ (78%) — mình chưa tìm nguyên nhân (có thể subject là thread, hoặc tiến trình khởi chạy trước khi bắt đầu thu). Nghĩa là: **nối được trong cùng file mà không cần quét log 6–7 giờ như OpTC**, nhưng độ phủ `cmdLine` không đều theo ngày.

## 4. Khác biệt định dạng giữa hai file (ảnh hưởng mã đọc)
`official-3`: khóa kiểu `com.bbn.tc.schema.avro.cdm18.Event`, UUID **chữ hoa**, dòng không có dấu phẩy cuối. `official`: khóa **không** có tiền tố, UUID **chữ thường**, mỗi dòng kết thúc bằng `,`. Hai file là hai lần xuất khác nhau; khi nối giữa file phải chuẩn hóa chữ hoa/thường. Lần quét đầu trên `official` ra toàn "?" vì mình giả định khóa có tiền tố `com.bbn...cdm18.`; đã sửa mã (log lỗi giữ ở `log_official_failed_parse.txt`).

## 5. Kết luận được phép và hạn chế
- Raw **có** `ipProtocol`, `size` (chỉ SENDTO/RECVFROM), `parentSubject`, `localPrincipal`/`username`, mà bản Parquet không có. `cmdLine` đã có trong Parquet.
- Hai file đã tải **không** chứa ba đợt dương (04-09/11/12). Không thể nói trường mới có giúp tách mẫu dương hay không cho tới khi có `official-2`. Cũng chưa đo: `ipProtocol` có phân biệt dương/âm không (dự đoán yếu vì 92–97% là UDP), `size` có phân biệt không.
- Chỉ quét toàn bộ sự kiện mạng và 1/200 sự kiện khác; không dựng lại flow, không thử tái lập 87,167 flow của STEP 29, không gán nhãn. Số tiến trình/flow ở đây là số bản ghi, không phải số cửa sổ của mình.
- Việc cần người dùng quyết: có tải/đọc `official-2` để nối với nhãn, và có cho phép đầu vào mở rộng (proto/byte/cha/dòng lệnh) hay không (đổi đầu vào ⇒ dựng lại shards OpTC và train lại, đã ghi ở HANDOFF mục 5.5).
