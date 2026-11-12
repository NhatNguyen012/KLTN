# STEP 40 — Vì sao flow được gán "độc": OpTC, ATLASv2, THEIA (số liệu đếm từ dữ liệu thật)

Ngày: 2026-10-30. Theo góp ý của thầy: phải biết mỗi dataset gán nhãn dựa vào đâu và field nào nhìn vào mới thấy độc, rồi mới chọn field cho mô hình. Chỉ đọc dữ liệu (E: và S1); không train. Mã: `01_code/pipeline_v2/s25_why_optc.py`, `s26_atlas_rows.py`, `s28_why_atlas.py`, `s29_why_atlas2.py`, `s27_theia_why.py`, `s30_why_theia.py`. Kết quả chi tiết: thư mục `optc/`, `atlas/summary.txt`, `atlas/summary2.txt`, `theia/summary.txt`.

## 0. Kết luận ngắn
1. **Cách gán nhãn khác nhau ở ba dataset**, nên "vì sao độc" cũng khác:
   - **OpTC**: nhãn theo tiến trình Red Team (powershell) + IP C2 + thời gian. Field phân biệt rõ: tên chương trình (`powershell.exe`), đích C2, và (từ context) công tắc dòng lệnh `-nop -sta -w -enc`.
   - **ATLASv2**: nhãn theo **tiến trình bị nhiễm** (REAPr); **mọi** flow của tiến trình đó là dương. 99% flow dương là của `firefox.exe` và **các trường trong một dòng netconn không phân biệt được** flow dương với benign của `firefox.exe` (cùng binary hash, cùng dòng lệnh, cùng cha, cùng người dùng).
   - **THEIA**: nhãn theo tiến trình/cạnh (REAPr). Dương gồm mã độc có tên riêng (`profile (deleted)`, `gtcache`, `clean`, `mail`, `pass_mgr`) và `firefox` bị backdoor (23 khóa dương so với 213,267 khóa benign của `firefox`).
2. **Thầy đúng ở điểm chính**: ở ATLASv2 và THEIA, `firefox` vừa dương vừa benign; nếu chỉ dùng tên chương trình thì mô hình (đã học `firefox` = benign ở OpTC: 6 dương / 91.8 triệu flow) không tách được. Cần thêm ngữ cảnh. Nhưng **ngữ cảnh cha–con cũng chưa đủ** ở ATLASv2 (mục 2).

## 1. OpTC (92,045,755 flow, 24,721 dương; 541 cửa sổ dương, 28 máy)
- **Tên chương trình**: `powershell.exe` 24,503 / 24,721 dương (99.1%) và là 100% flow của nó. Còn 218 flow dương ở 23 chương trình khác (nhiều chương trình tên lạ: `biguwcmnsucig.exe` 140, `ckfgw.exe` 10...). `firefox.exe` có 91,841,864 flow nhưng **chỉ 6 dương**.
- **Đích**: hai C2 chiếm 24,501 flow dương: `202.6.172.98:443` (13,411 flow, 100% dương) và `132.197.158.98:80` (11,090, 100% dương). Ngoại lệ: `53.192.68.50:80` có 5,581 flow nhưng chỉ 18 dương → đích đơn lẻ không đủ; có **5,563 flow benign tới cùng đích** với flow dương.
- **Ngày**: 23/9 9,030; 24/9 5,527; 25/9 10,164 flow dương (các ngày trước 0).
- **Tài khoản**: `SYSTEMIACOM\Administrator` 13,097 flow, toàn dương (đặc điểm testbed, đã biết ở audit).
- **Dòng lệnh** (từ tracker của Nguyễn, STEP 41; ví dụ trên một máy): flow dương của `powershell.exe` mang `switch=-nop -sta -w -enc`, `path_role=relative`; flow dương của `firefox.exe` tới `132.197.158.98:8000` có cha `explorer.exe`, không có dấu hiệu lạ ở actor/cha (tokens `exe=firefox.exe`, `path_role=program_files`).
- Cách gán (A New Hope): tiến trình độc + con cháu (§4.1) → mọi sự kiện/flow của chúng là dương; nhãn mạng thêm kiểm IP/domain và thời gian. Vì thế vài flow `firefox.exe` dương là do bị coi là con cháu/hoạt động tấn công, không do bản thân flow.

## 2. ATLASv2 (29,744 netconn; 29,565 sau bỏ LISTEN/đích rỗng: 7,761 dương, 21,804 benign)
Dương: toàn bộ nằm trong 16 tệp tấn công; 0 dương ở tệp benign.
- **Theo chương trình**: `firefox.exe` 7,696 / 7,761 dương; còn lại `winword.exe` 17, `payload.exe` 16, `powershell.exe` 8, `mshta.exe` 8, `regsvr32.exe` 5, `plugin-container.exe` 5...
- **Trong `firefox.exe` (27,287 flow)**, dương vs benign **giống nhau** ở mọi field của netconn:
  - cha: `explorer.exe` (dương 7,680; benign 19,345); `firefox.exe` (16 vs 246);
  - binary hash (md5): **1 giá trị duy nhất, dùng chung** cho dương và benign; dòng lệnh `"C:\Program Files\Mozilla Firefox\firefox.exe"` giống nhau; người dùng `aalsahee` giống nhau;
  - đích: private 109/7,696 (1.4%) với dương, 513/19,591 (2.6%) với benign; đích dương là IP công cộng phổ thông (Google/Cloudflare...), không phải IP kẻ tấn công.
- **Ở mức tiến trình** (process_guid): `firefox` trong tệp tấn công có 26 tiến trình dương (7,696 flow) và 60 không dương (350 flow); tệp benign 93 tiến trình (19,241 flow). Nhãn là thuộc tính của **tiến trình**, không của flow.
- **Cha–con có giúp không**: chỉ **6/26** tiến trình `firefox` dương sinh con bất thường (`payload.exe`; cmd/powershell/python/regsvr32/mshta); 20/26 chỉ sinh `firefox.exe`/`plugin-container.exe` hoặc không con. Với 6 tiến trình có con lạ, phần lớn flow nằm **trước** mốc sinh con lạ đầu tiên (ví dụ 601/927, 184/330) nên ở thời điểm flow ngữ cảnh này chưa có (nhân quả). Tức ngữ cảnh cha–con **chỉ giải thích được một phần nhỏ** nhãn `firefox` ở ATLASv2.
- **Chương trình có tính độc rõ** (dương gần như 100% và hiếm ở benign): `payload.exe` (16/16), `winword.exe` (17/17), `mshta.exe`, `regsvr32.exe`, `powershell.exe` (8/8) — nhưng năm chương trình này chỉ chiếm 54 flow dương (0.7%).
- **Cặp cha→con** (procstart): 29 cặp có tiến trình cha dương; 16 cặp cũng xuất hiện ở benign → cặp không phân biệt hoàn toàn. Ví dụ cặp dương: `plugin-container.exe → cmd.exe`, `firefox.exe → payload.exe`, `cmd.exe → payload.exe`.
- **Id cố định của ứng dụng**: `process_hash` = [md5, sha256] có trong netconn và procstart (cả `parent_hash`). Hạn chế: với `firefox` (giá trị duy nhất) không giúp phân biệt nhãn.
- Hạn chế: nhãn mức tiến trình (REAPr), 10 cuộc tấn công gần như trùng nhau; procstart gồm cả `ACTION_PROCESS_DISCOVERED` (không chứng minh thời điểm sinh).

## 3. THEIA 6r (59,634,578 sự kiện; 169,644 Subject; 139,408 NetFlowObject có đầu xa thật)
- **Khóa (subject, netflow thật)**: 226,692; dương 127 (118 subject, 20 netflow, 1,701 sự kiện có nhãn cạnh); benign 226,565 (≈10.3k subject).
- **Chương trình** (từ EXECUTE nếu có, nếu không thì `Subject.path`): dương gồm `profile (deleted)` 38 khóa, `gtcache` 35, `firefox` 23, `clean (deleted)` 16, `mail` 9, `pass_mgr` 2...; benign gồm `firefox` 213,267, `python2.7` 10,253, `thunderbird` 1,551, `wget` 419, `sshd` 371. **Chỉ `firefox` có cả dương và benign** (23 so với 213,267).
- **Hạn chế quan trọng về cách lấy tên**: chỉ 9/118 subject dương có sự kiện `EVENT_EXECUTE` mang `cmdLine` (66,953/169,644 subject nói chung có). 109 subject dương lấy tên từ `Subject.path`, tức tên có thể là tên lúc fork (đã ghi ở STEP 36–37). Vì vậy tên các tiến trình mã độc (`profile`, `gtcache`...) là tên tệp mã độc gốc/đường dẫn `(deleted)`, và **chưa chứng minh** rằng `EVENT_EXECUTE` sửa được những trường hợp này.
- **Đích**: 0/226,565 khóa benign có cùng đích với flow dương (IP nằm riêng cho tấn công) → đích tách hoàn hảo, nhưng 5–6 IP không khái quát được và mô hình bản B không dùng IP.
- **Cha**: dương có cha `u:0` (67 khóa; giá trị cha không ánh xạ được tên), `init` (34), `fluxbox` (23, cùng cha với `firefox` benign `fluxbox` 214,597) → `firefox` dương/benign cùng cha.
- **Tính lặp**: các chuỗi 3.3 và 3.11 dùng lại cùng tên (`profile`, `gtcache`, `clean`) → chia trộn theo cửa sổ có khả năng làm mô hình học thuộc tên (rò rỉ).

## 4. Hệ quả cho thiết kế (đề xuất, chưa làm)
1. **Tên chương trình** tách được mã độc có tên riêng (OpTC `powershell.exe` + tên lạ; THEIA `profile/gtcache/...`), nhưng **không tách `firefox`** ở ATLASv2/THEIA. Với `firefox`, tín hiệu nằm ngoài flow.
2. **Dòng lệnh** (công tắc `-enc`...) giải thích được OpTC; với ATLASv2/THEIA `firefox` dòng lệnh dương/benign giống nhau → không giúp riêng cho `firefox`.
3. **Cha–con**: giúp trong OpTC (có cha ổn định) và với một số tiến trình ATLASv2 (`payload.exe`, `cmd.exe`) nhưng 20/26 `firefox` dương ở ATLASv2 không có con lạ.
4. **"Tương tác với tiến trình độc thì độc" (block/graph)**: ở ATLASv2 nhãn `firefox` có lẽ đến từ quan hệ với các sự kiện khác (file, module, crossproc, tải tệp) mà ta chưa trích; cần phân tích thêm (chưa làm) trước khi hứa.
5. **Hash id** chỉ có ở ATLASv2 và không giúp riêng `firefox`.
6. Nguy cơ chia trộn: ATLASv2 (10 cuộc tấn công gần giống nhau) và THEIA (tên lặp giữa chuỗi 3.3/3.11) → điểm cao có thể là nhớ mẫu; luôn nêu.
