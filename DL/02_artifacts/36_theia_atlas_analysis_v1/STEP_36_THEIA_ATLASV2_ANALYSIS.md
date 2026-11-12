# STEP 36 — Phân tích THEIA (raw) và ATLASv2, so với đầu vào mô hình OpTC, và việc ánh xạ `actorID`

Ngày: 2026-10-23. Nguồn chỉ đọc: `E:\IL_DATASET\DARPA-TC-E3-THEIA` và `E:\IL_DATASET\ATLASv2` (gửi bởi bạn của người dùng). Mã mới (`01_code/pipeline_v2/`): `s17_tar_list.py`, `s17_theia_scan.py`, `s17_theia_edges.py`, `s17_atlas_peek.py`, `s17_atlas_netconn.py`. Đọc streaming từ `.tar.gz`, **không giải nén ra đĩa**. Số liệu: các JSON cùng thư mục. Sơ đồ: `visual_overview.html` (mở bằng trình duyệt). Giả định mình đã dùng: THEIA + ATLASv2 thay cho cặp skrghosh + FiveDirections ở vòng fine-tune sau; chưa chạy train gì.

## 0. Trả lời ngắn
1. **THEIA raw là đồ thị sự kiện Linux (CDM18), không có "flow" sẵn; ATLASv2 là log Windows 7 với Carbon Black EDR trong đó hàng `netconn` đã là flow kèm tiến trình, tiến trình cha, dòng lệnh và người dùng.** ATLASv2 khớp từ điển OpTC (tên tiến trình, đường dẫn Windows) hơn hẳn; THEIA có tên tiến trình Linux (từ điển OpTC không có) và **không có `ipProtocol`**.
2. **Giữ bản B** (5 đầu vào: `app_family`, `proto`, `resp_port_class`, `image_dir_class`, `delta_t`). Bỏ `service`, `conn_state`, 7 số Bro, `has_missed_bytes`, `principal_class`. ATLASv2 dựng được đủ 5 đầu vào; THEIA thiếu `proto`, và `image_dir_class` cần lớp Linux. Mục 4.
3. **Ánh xạ `actorID` chỉ cần nếu quyết định mở rộng đầu vào** (thêm dòng lệnh/tiến trình cha). Với bản B thì không cần. Hai cách làm và phần xin Nguyễn ở mục 5.

## 1. Cấu trúc thư mục
`E:\IL_DATASET\ATLASv2\`: `atlasv2.tar.gz` (12.2 GB, dữ liệu log), `atlasv2_attack_igraphs.tar.gz` (21 MB, đồ thị dùng gán nhãn REAPr), `reapr-ground-truth/` (nhãn: `atlasv2/*.labels`, `*.seeds`, mô tả kịch bản; `darpa-tc-engagement3/` có nhãn THEIA), PDF mô tả ATLASv2, `atlasv2/docs/edr_alert_labels.xlsx`.
`E:\IL_DATASET\DARPA-TC-E3-THEIA\` (21 GB): `RAW/` (4 file `.json.tar.gz`: `1r`, `3`, `5m`, `6r`; tổng 2.8 GB nén), `CSV/` và `Parquet/` (bản THESEUS đã xử lý), `Artifact/` (checkpoint THESEUS, không dùng).

## 2. THEIA raw
### 2.1 Bốn file là bốn lát cắt thời gian của một máy (Ubuntu, `ta1-theia`, IP 10.0.6.60)
| File | Khoảng thời gian (UTC) | Sự kiện | NetFlowObject | Subject | Ghi chú |
|---|---|---:|---:|---:|---|
| `1r` | 04-03 14:02 → 04-05 15:19 | 44.0 M | 69,870 | 92,376 | không có nhãn tấn công |
| `3` | 04-05 15:42 → 16:41 | 1.47 M | 6,174 | 3,455 | một giờ, không nhãn |
| `5m` | 04-09 12:46 → 22:15 | 0.92 M | 907 | 13,916 | không nhãn |
| `6r` | **04-10 16:44 → 04-13 21:04** | 59.6 M | 168,156 | 169,644 | **chứa toàn bộ nhãn cạnh REAPr (68,924/68,924)** |
Mỗi `.tar.gz` chứa nhiều phần `.json`, `.json.1`, ... mỗi phần ~3.7 GB. THEIA E3 gốc còn nhiều lát khác (04-04, 04-06, 04-07, 04-08...) không có trong bốn file này.

### 2.2 Trường chi tiết (kiểm trên file thật; "null" = luôn rỗng)
| Bản ghi | Trường có giá trị | Trường luôn null / không có |
|---|---|---|
| `NetFlowObject` | `uuid`, `localAddress`, `localPort`, `remoteAddress`, `remotePort`, `baseObject.hostId` | **`ipProtocol` (null 100%)**, `fileDescriptor`, `baseObject.properties/permission/epoch` |
| `Subject` (đều là `SUBJECT_PROCESS`) | `uuid`, `cid` (pid), `cmdLine` (chuỗi; "N/A" với tiến trình kernel), `parentSubject` (UUID cha), `localPrincipal`, `startTimestampNanos`, `properties.map{path, ppid, tgid}` | `privilegeLevel`, `importedLibraries`... |
| `Principal` | `uuid`, `type` (LOCAL/REMOTE), `userId` (0, 1000, 116...), `groupIds`, `properties.map.cred` | **`username` null 100%** |
| `Event` chạm netflow | `uuid`, `type`, `timestampNanos` (UTC ns), `threadId`, `subject`, `predicateObject` (= NetFlowObject), `size` (byte), `properties.map.rc` | `size` trống ở `CONNECT`; không có hướng, thời lượng, trạng thái kết nối, số gói |
Các loại sự kiện chạm netflow (lát `6r`): `RECVFROM` 9.96 M, `RECVMSG` 1.22 M, `SENDMSG` 0.98 M, `CONNECT` 0.37 M, `SENDTO` 0.35 M, `READ_SOCKET_PARAMS` 0.21 M, `WRITE_SOCKET_PARAMS` 0.15 M; tổng 13.2 M sự kiện trên 168,156 netflow. **Một "flow" phải tự dựng** bằng cách gom Event theo `predicateObject` (STEP 28 đã làm theo bản Parquet).
Cái gì là "mạng thật": ở `6r`, cổng xa 80 có 110,601 netflow, 53 có 27,969, và **28,743 netflow có cổng 0** (`LOCAL`/`NETLINK`, ổ cắm cục bộ, không phải kết nối mạng); `1r`: 24,121/69,870 cổng 0. Tiến trình sinh nhiều sự kiện mạng nhất: `fluxbox` (8.2 M), `firefox` (2.8 M), `thunderbird`, `sshd`, `console-kit-daemon` (ở `1r` còn `Xvnc4` 3.5 M). Byte có thể xấp xỉ bằng tổng `size` của `SENDTO/SENDMSG` và `RECVFROM/RECVMSG`; `RECVFROM` ở `6r` cộng được 16.7 GB, `SENDTO` 0.14 GB.
Đường dẫn: `properties.path` đủ đường dẫn Linux (`/usr/bin/fluxbox`, `/home/admin/Downloads/firefox/firefox`), có ở 99.4% Subject của `6r` (168,643/169,644); `cmdLine` khác "N/A" ở 162,307/169,644; `ppid` ở 169,618/169,644. Tức **có đủ dòng lệnh và cây cha-con** (khác OpTC, nơi phải quét log host).

### 2.3 Nhãn REAPr cho THEIA (`reapr-ground-truth/darpa-tc-engagement3`)
- `theia_labels.csv`: 126 tiến trình (theo `uuid` Subject; 126 `attack`/`contaminated`), thuộc 6 chuỗi: `3.3` (ngày 04-10 14:00 EDT: một lần thất bại allstate, thất bại gatech_clean, thành công gatech_profile), `3.11` (04-12: thất bại SSHD, thành công "micro APT" ghi đĩa), `4.8` (thất bại). Chuỗi `fail` tác giả khuyên không dùng để test.
- `theia_edge_labels.tar.gz`: **nhãn mức cạnh (sự kiện)**, 68,924 `edge_uuid` (khóa là `Event.uuid`): `3.11_success` 65,516; `3.3_success_gatech_profile` 1,481; `3.3_fail_gatech_clean` 1,310; `3.11_fail` 561; `4.8_fail` 52; `3.3_fail_allstate` 9. Cả 68,924 sự kiện được tìm thấy trong `6r`. Phân bố loại sự kiện có nhãn: `CONNECT` 63,585; `RECVFROM` 1,407; `OPEN` 1,327; `READ` 1,284; `MMAP` 897; `SENDTO` 274; `CLONE` 118; còn lại ít. Đây là **nhãn mức sự kiện thật**, tốt hơn cách STEP 28 (nhãn tiến trình + giờ báo cáo) — nhưng 95% cạnh có nhãn (65,516/68,924) là `3.11_success`, một đợt.
### 2.4 Nối nhãn cạnh với sự kiện mạng trong raw (`theia_edges_6r.json`, `theia_edges_6r_rows.csv`)
Trong 68,924 cạnh có nhãn của `6r`, **65,266 chạm NetFlowObject** (`CONNECT` 63,585; `RECVFROM` 1,407; `SENDTO` 274), trên 25,302 netflow khác nhau, từ chỉ **118 tiến trình**. Phân theo chuỗi: `3.11_success` 64,093; `3.3_success_gatech_profile` 560; `3.3_fail_gatech_clean` 402; `3.11_fail` 202; `3.3_fail_allstate` 9. Thời gian: 04-10 18:25 UTC (14:25 EDT, khớp báo cáo "04-10 14:00") và 04-12 16:00–17:26 UTC.
**Phát hiện cần lưu ý:** 63,561 sự kiện (97%) là `CONNECT` tới netflow có **đầu xa `NA:0`** (không có địa chỉ xa), từ **đúng một tiến trình** (`283847BC-0200-...`) trong khoảng 04-12 17:00–18:00 UTC: một vòng thử kết nối (kiểu quét) của chuỗi `3.11_success`, 25,278 ổ cắm khác nhau. Các netflow này không có địa chỉ/cổng xa nên **bị loại khi dựng flow** (quy tắc giống STEP 29: bỏ netflow thiếu đầu xa). Phần còn lại, **flow có đầu xa thật chỉ gồm 1,701 sự kiện trên 20 netflow** (`3.11_success` 11, `3.3_success_gatech_profile` 4, `3.3_fail_gatech_clean` 3, `3.11_fail` 1, `3.3_fail_allstate` 1), đi tới máy chủ HTTP cổng 80: `141.43.176.203` (868 sự kiện), `146.153.68.151` (398), `161.116.88.72` (327), `149.52.198.23` (89), `61.130.69.232` (9), và một ít tới `128.55.12.110` (chính máy trong mạng thử nghiệm: 22, 80, 111, 5901). Tức nhãn mức sự kiện tốt hơn STEP 28, nhưng **số flow dương dùng được cho mô hình mạng rất ít (20 netflow, vài cửa sổ 15 phút), cùng hai đợt (04-10 và 04-12)** và không thể khẳng định đây là "tấn công mạng" ngoài việc tiến trình đó bị nhiễm. Chưa dựng cửa sổ nên chưa có số mẫu dương.

## 3. ATLASv2
### 3.1 Bối cảnh (PDF và README)
Hai VM Windows 7 32-bit (h1, h2) do hai người dùng thật dùng 4 ngày (benign, 2022-07-15 → 19 sáng), rồi ngày tấn công 2022-07-19/20 với **10 kịch bản** (s1–s4 chỉ h1; m1–m6 lan sang h2), mỗi kịch bản 30 phút – 2 giờ, kết hợp hoạt động benign xen kẽ. Tấn công từ Kali: email phishing → Flash/Word exploit → Meterpreter → thả `payload.exe` → thu PDF và gửi ra ngoài qua HTTPS → ghi đè trang portal rồi lan sang h2. Tác giả (và REAPr) **cảnh báo: 10 cuộc tấn công gần như trùng nhau (4/5 bước giống)**; chia ngẫu nhiên giữa các cuộc tấn công = rò rỉ, không dùng để đánh giá phát hiện tấn công mới.

### 3.2 Các nguồn log và cái gì dùng được cho "flow"
| Nguồn | Nội dung (đã kiểm trên `h1`, scenario `m1`) | Dùng được cho mô hình mạng? |
|---|---|---|
| **Carbon Black EDR** `cbc-edr/*.jsonl` | `endpoint.event.netconn`: `remote_ip`, `remote_port`, `local_ip`, `local_port`, `netconn_protocol` (PROTO_TCP/UDP), `netconn_inbound`, `netconn_domain`, `action` (CREATE/ESTABLISHED/LISTEN), `netconn_community_id`, `device_timestamp`; **cùng hàng đã kèm** `process_guid`, `process_path`, `process_cmdline`, `process_username`, `parent_guid`, `parent_path`, `parent_cmdline`, `process_hash`. Các loại khác trong cùng file: `filemod` 18,274, `moduleload`, `regmod`, `procend`, `procstart`, `crossproc`, `scriptload` | **Có, nguồn chính.** Một hàng `netconn` = một flow có tiến trình + cha + dòng lệnh + người dùng. Không có byte, số gói, thời lượng, service, conn_state |
| Windows Security (xml) | `5156` (kết nối được phép): `ProcessID`, `Application`, `Direction`, `SourceAddress/Port`, `DestAddress/Port`, `Protocol`; `4688` tạo tiến trình; mười mấy loại khác; file attack 160–560 MB mỗi scenario | Có thể (thêm), không cần: trùng với netconn, không có tên người dùng ở 5156 |
| Sysmon (xml) | trong `h1-m1`: chỉ **EventID 1** (tạo tiến trình, có `CommandLine`, `ParentImage`...) và **5** (kết thúc); **không có EventID 3 (kết nối mạng)** | Không (không có mạng) |
| DNS (Wireshark txt) | truy vấn/đáp DNS | Không (không có tiến trình) |
| Firefox (txt, 0.7–4.6 GB mỗi file) | nhật ký gỡ lỗi (`nsStreamPump`...) | Không |
| Nhãn REAPr `atlasv2/*.labels` | theo **tiến trình**: `process_uuid` = `process_guid` của CBC; 191 tiến trình `attack` cho 16 cặp (host, kịch bản) | Có, khớp thẳng với `process_guid` |

### 3.3 Số netconn và nhãn (đếm toàn bộ cbc-edr, `atlas_netconn_counts.json`)
| | netconn | từ tiến trình có nhãn `attack` | cửa sổ 15 phút (xấp xỉ) | cửa sổ có dương |
|---|---:|---:|---:|---:|
| 16 file tấn công (h1: s1–s4, m1–m6; h2: m1–m6) | 9,068 | **7,793 (86%)** | 67 | 56 |
| 2 file benign (h1, h2; 4 ngày) | 20,676 | 0 | 391 | 0 |
Tức toàn bộ dữ liệu chỉ ~29,700 flow (OpTC: 92 triệu). Nhãn theo tiến trình nên **mọi** kết nối của tiến trình bị nhiễm (ví dụ `firefox.exe` bị khai thác) đều dương, kể cả duyệt web thường; vì vậy 86% flow trong file tấn công là dương, và flow `firefox.exe` dương trông giống flow `firefox.exe` benign (4 ngày benign có 14,106 netconn `firefox.exe` trên h1). Đặc trưng mô hình thấy (tên tiến trình, cổng, thư mục) khó tách hai nhóm này; điều gì có thể tách (IP đích, thời gian trong ngày) hoặc không dùng, hoặc là rò rỉ. Đây là **hạn chế quan trọng của nhãn**, chưa đo trên mô hình.
Độ phủ từ điển: tên tiến trình ATLASv2 nằm trong từ điển `app_family` của OpTC (59 giá trị) cho ~98.7% netconn tấn công và ~97.3% benign (xấp xỉ theo 12 đường dẫn phổ biến nhất mỗi file; ngoài từ điển chủ yếu `discord.exe` 462, `mmc.exe`, `lsass.exe`, `iexplore.exe`). Giao thức: TCP 98%, UDP 2%; cổng đích chủ yếu 443/80.

## 4. Đối chiếu với đầu vào mô hình và quy tắc tiền xử lý
OpTC (`flows_joined.parquet`, 92,045,755 flow, 743 máy) → mô hình đầy đủ dùng 7 cột phân loại, 7 số, 1 cờ, `delta_t`. Bản B (đã train, OpTC TEST F1 0.988) chỉ dùng 5 đầu vào. Bảng khả năng:
| Đầu vào | THEIA raw | ATLASv2 (CBC netconn) |
|---|---|---|
| `app_family` | basename `properties.path` (tên Linux) → từ điển OpTC không có, gần như toàn `<UNK>` (STEP 28: UNK 100%) | basename `process_path` → khớp từ điển ~97–99% |
| `image_dir_class` | đường dẫn Linux; 8 lớp Windows không áp dụng → phải thêm lớp mới (mở rộng embedding) hoặc dồn `OTHER` | `process_path` đầy đủ → dùng đúng 8 lớp |
| `proto` | **thiếu** (`ipProtocol` null) → `<MISSING>` | `netconn_protocol` |
| `resp_port_class` | `remotePort`; hướng suy từ `CONNECT` (đi) / `ACCEPT` | `remote_port` + `netconn_inbound` |
| `delta_t` | `timestampNanos` sau khi dựng flow | `device_timestamp` |
**Bỏ khỏi OpTC khi fine-tune (không có hoặc không so sánh được ở dữ liệu mới):** `service`, `conn_state`, 7 cột số (`duration`, `orig_bytes`, `resp_bytes`, `orig_pkts`, `orig_ip_bytes`, `resp_pkts`, `resp_ip_bytes`), `has_missed_bytes`, và `principal_class` (ADMINISTRATOR là tài khoản Red Team, đường tắt đã biết; ATLASv2 có `process_username` nhưng THEIA không có `username`). Giữ nguyên quy tắc: cửa sổ theo máy 15 phút tối đa 512 flow, nhãn cửa sổ = có flow dương, preprocessing fit chỉ trên TRAIN, từ điển mở rộng chỉ thêm token (hàng mới = bản sao `<UNK>`), `delta_t` dùng mean/std OpTC.
Có thể thêm nếu quyết định đổi đầu vào (phải train lại OpTC): byte (THEIA xấp xỉ qua `size`, ATLASv2 **không có**), dòng lệnh và tiến trình cha (cả hai dataset có sẵn, OpTC thì không — xem mục 5).
Việc dựng flow: **ATLASv2** dùng thẳng hàng `netconn` (một dòng = một flow, khóa `process_guid`); **THEIA** gom Event theo NetFlowObject, bỏ netflow cổng 0/LOCAL/NETLINK/127.0.0.1, đầu xa theo CONNECT/ACCEPT (quy tắc giống STEP 29).

## 5. Ánh xạ `actorID` OpTC: quét ổ hay xin Nguyễn
**Mục đích:** thêm vào flow OpTC `command_line` và tiến trình cha (`parent_image_path`), thứ mà bảng ghép eCAR-Bro không có (có `actor_id`, `pid`, `ppid` nhưng không có dòng lệnh/cha). THEIA và ATLASv2 có sẵn hai thứ này nên chỉ khi OpTC cũng có thì mô hình mới dùng được.
**Chỉ cần làm nếu người dùng chốt "đầu vào mở rộng".** Với bản B không cần.
**Cách 1 — tự quét log host thô** (`E:\host-malicious` 292 GB / 1,500 file, `E:\host-begnin` 622 GB / 3,195 file): trích `PROCESS/CREATE` (`objectID`, `command_line`, `image_path`, `parent_image_path`) theo `(hostname, objectID)` rồi nối `flows_joined.actor_id`. Giống STEP 17a: **~6–7 giờ**, ghi ra bảng nhỏ (ước vài chục triệu dòng); cần ổ E gắn liên tục. Đo thử (STEP 32, một máy, hai ngày): 100% flow dương khớp, nhưng tiến trình benign chạy lâu (như `firefox.exe`) không có sự kiện tạo trong cùng ngày → chỉ khớp 28.2% flow ngày 23/9. **Rủi ro rò rỉ nhãn qua độ phủ** (tiến trình độc mới tạo nên có dòng lệnh, benign dài hạn thì thiếu); phải quét đủ các ngày trước đó và/hoặc coi "không khớp" là một giá trị công bằng cho cả hai lớp, rồi kiểm tra riêng. Độ chính xác ánh xạ (A New Hope báo ~40% tiến trình gán sai) chưa đo.
**Cách 2 — xin Nguyễn** (nhanh nhất, nên hỏi song song vì không tốn gì): chỉ mục graph SQLite của nhánh Host (~1.8 GB) có bảng `fact(host, proc, fact, t)`, `parent(host, child, parent)`, `binding`, `flow`, và 40 thuộc tính hữu hạn (`launch=encoded/download/hidden/inline/remote_admin`, vai trò tiến trình, vị trí). Cần từ Nguyễn:
1. Xuất bảng `(host, proc_id, image_path, command_line hoặc cờ `launch=`, parent_proc_id, parent_image_path, thời điểm tạo)`, hoặc cả file SQLite.
2. Xác nhận khóa `proc` là **`PROCESS.objectID` (UUID)** hay `(host, pid)`; chỉ khi là `objectID` mới nối được với `FLOW.actorID`.
3. Phạm vi chỉ mục: bao nhiêu máy/ngày (log host thô chỉ là ~4,700 file; Nguyễn có thể đã lấy mẫu), tức tỉ lệ flow OpTC nối được.
4. Hàm dựng 5 `launch=` và 9 vai trò tiến trình (`command_syntax.py`, `graph.py`) để dùng cùng bộ đặc trưng hữu hạn cho THEIA/ATLASv2 (dòng lệnh dạng chuỗi thô không dùng được xuyên bộ dữ liệu).
5. Có đo độ chính xác ánh xạ chưa.
Dù cách nào, đây vẫn là **làm giàu ngữ cảnh tiến trình, không phải fusion với Host ML** (fusion thật chỉ từ mức điểm trở đi, STEP 17/20).

## 6. Hạn chế và việc cần người dùng quyết
- Mình chưa dựng flow/shards cho THEIA hay ATLASv2, chưa chạy zero-shot hay train; mọi số ở đây là đếm bản ghi, không phải số cửa sổ.
- THEIA: chỉ 4 lát cắt trong E3; nhãn cạnh nằm trọn trong `6r`; sau khi bỏ netflow không có đầu xa chỉ còn 20 netflow dương (mục 2.4). THEIA là máy Linux, mô hình học tên tiến trình Windows: dự đoán zero-shot thấp (STEP 28: ~0). ATLASv2: ~29,700 flow, 191 tiến trình dương, nhãn theo tiến trình làm 86% flow tấn công là dương và giống benign về đặc trưng mô hình thấy; 10 cuộc tấn công gần như giống nhau (chia trộn rò rỉ mạnh).
- Số cửa sổ ATLASv2 ở mục 3.3 là xấp xỉ (nhóm theo giờ + phần tư giờ của `device_timestamp`); tỉ lệ UNK là xấp xỉ theo 12 đường dẫn phổ biến nhất mỗi file.
- Quyết định cần bạn chốt: (a) có thật sự bỏ cả skrghosh; (b) THEIA có dùng cho fine-tune không (không `proto`, từ điển lệch, nhưng nhãn mức cạnh tốt) hay chỉ làm phân tích; (c) có chốt "đầu vào mở rộng" (kéo theo quét log host hoặc xin Nguyễn) hay giữ bản B.


## ĐÍNH CHÍNH 2026-10-24
- **`app_family` của THEIA không lấy từ `Subject.properties.map.path`.** Bản ghi `Subject` giữ tên lúc fork; ví dụ tiến trình `7F1FD92F-...` (pid 8063, nhãn REAPr `/usr/bin/firefox`) có `path = /usr/bin/fluxbox` nhưng hai sự kiện `EVENT_EXECUTE` của nó (18:53:22 UTC) ghi `cmdLine` là `/bin/bash -c /usr/bin/firefox` rồi `/usr/bin/firefox`, và các tiến trình con có `path = /home/admin/Downloads/firefox/firefox`. Phải lấy tên từ `EVENT_EXECUTE` (hoặc `process_name` của REAPr). Bằng chứng: `38_slide_records_v1/_theia_exec_check.json`.
- README-E3 liệt kê đúng bốn topic THEIA tốt (`1r`, `3`, `5m`, `6r`); câu "gốc còn nhiều lát khác" ở mục 2.1 là chưa kiểm chứng.
