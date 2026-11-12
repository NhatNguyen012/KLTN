const { P, H1, H2, B, NOTE, T, SP, build } = require("./s20_docx_lib.js");

const c = [];
c.push(P("**Mục đích:** giúp hiểu rõ dataset ATLASv2 để trình bày với thầy (dùng làm dataset mới cho fine-tune nhánh Network DL). Nội dung lấy từ bài báo ATLASv2, bài báo ATLAS gốc, tài liệu của kho REAPr và README đi kèm dataset; phần nào do mình tự đếm trên file thật thì ghi rõ."));
c.push(NOTE("**Cách đọc nhãn nguồn.** [BB] = lấy từ bài báo hoặc tài liệu gốc (số trong ngoặc vuông chỉ mục Tài liệu tham khảo ở cuối). [ĐO] = mình đo trực tiếp trên file ở `E:\\IL_DATASET` (không có trong bài báo). Khi tài liệu gốc mâu thuẫn nhau, mình ghi cả hai và nói theo nguồn nào."));

// ---------------------------------------------------------------- 1
c.push(H1("1. Tóm tắt nhanh"));
c.push(T(["Mục", "Nội dung"], [
  ["Tên và tác giả", "ATLASv2: ATLAS Attack Engagements, Version 2 – Andy Riddle, Kim Westfall, Adam Bates (University of Illinois Urbana-Champaign), arXiv:2401.01341, 2023 [1]. Dựa trên dataset của ATLAS (Alsaheel và cộng sự, USENIX Security 2021) [2]."],
  ["Môi trường", "Hai máy ảo Windows 7 32-bit, gọi là host 1 (h1) và host 2 (h2); Mozilla Firefox 52.0, Microsoft Office Professional Plus 2010, Adobe Flash Player 17.0.0.188 và 18.0.0.194 (đổi theo kịch bản); cảm biến Carbon Black v3.8.0.627 gửi dữ liệu lên AWS S3. Máy tấn công là Kali Linux [1][5]."],
  ["Thời gian", "Tạo ra từ 15/7/2022 đến 19/7/2022 [5]: bốn ngày đầu hoàn toàn benign, ngày thứ năm (19/7, kéo sang 20/7 theo giờ UTC) có 10 kịch bản tấn công [1]."],
  ["Hoạt động benign", "Hai nhà nghiên cứu dùng hai máy ảo làm máy làm việc chính khoảng 8 giờ mỗi ngày: duyệt web, họp Zoom, làm việc với Office, gửi nhận email đính kèm, chat Discord, xem video. Trên h1 còn chạy một máy chủ SimpleHTTP đóng vai cổng web nội bộ để dùng cho tấn công di chuyển ngang [1]."],
  ["Số cuộc tấn công", "10 kịch bản: s1–s4 (một máy, chỉ h1) và m1–m6 (hai máy, h1 rồi h2) [1]. Tác giả nhấn mạnh các cuộc tấn công gần như trùng nhau (xem mục 7)."],
  ["Nguồn log", "Windows Security (ETW), Sysmon, Carbon Black Cloud (EDR, NGAV và cảnh báo), DNS (Wireshark), nhật ký Firefox [1][5]."],
  ["Kích thước", "12 GB nén, 160 GB giải nén theo README [5]; bài báo ghi 154 GB cho cả đợt thu [1]."],
  ["Nhãn", "Không có trường nhãn trong log. Nhãn mức sự kiện cho Windows Security (EventRecordID độc hại) đi kèm dataset [1]; nhãn mức tiến trình của REAPr (191 tiến trình) và đồ thị tấn công nằm ở kho riêng [3][4]."],
], [2000, 7638], { firstColFill: true }));

// ---------------------------------------------------------------- 2
c.push(H1("2. Nguồn gốc: ATLAS (2021) và ATLASv2"));
c.push(P("**ATLAS gốc [2].** Nhóm tác giả tự dựng bài kiểm tra: cài lại 10 chiến dịch APT thật trong môi trường thử nghiệm có kiểm soát (máy ảo Windows 7 32-bit), mỗi cuộc tấn công mất khoảng một giờ, sau đó thu log trong cửa sổ 24 giờ. Hoạt động benign do người tự thực hiện trên cùng máy, ngẫu nhiên trong cửa sổ 8 giờ ban ngày. Trung bình mỗi lần thu có 20,088 thực thể và khoảng 249 nghìn sự kiện; thực thể tấn công chỉ chiếm dưới 0.14% toàn bộ log [BB][2]."));
c.push(P("**ATLASv2 [1].** Làm lại 10 kịch bản đó nhưng cải thiện ba điểm: (1) hoạt động benign tốt hơn vì hai nhà nghiên cứu thật dùng máy như máy làm việc, thay vì kịch bản tự động; (2) có bốn ngày dữ liệu benign thuần túy để huấn luyện; (3) có hoạt động benign xen kẽ trong lúc tấn công. Ngoài ra bổ sung thêm nguồn log. Theo bài báo, dataset gốc chỉ gồm Windows Security Auditing, log Firefox và log DNS (Wireshark); ATLASv2 thêm Sysmon và sự kiện của VMware Carbon Black Cloud [BB]."));
c.push(NOTE("Lưu ý: bài báo ATLAS gốc [2] cũng nói prototype dùng Windows system log có bật Sysmon để ghi thao tác tệp và kết nối mạng. Dataset ATLASv2 hiện có thì Sysmon chỉ ghi tạo và kết thúc tiến trình (xem mục 5.3). Hai điều này không mâu thuẫn với nhau (cấu hình Sysmon có thể khác giữa hai đợt thu), nhưng mình không có tài liệu để khẳng định."));

// ---------------------------------------------------------------- 3
c.push(H1("3. Mười cuộc tấn công"));
c.push(P("Bảng dưới gộp ba nguồn: Bảng 1 và 2 của bài ATLASv2 (CVE và thời gian UTC) [1], Bảng 2 của bài ATLAS gốc (tên chiến dịch APT mà kịch bản mô phỏng) [2], và các tệp mô tả tấn công `attack_descriptions` (tên module Metasploit; sao chép từ kho của ATLAS gốc) [4]."));
c.push(T(["ID", "Máy", "CVE và phần mềm", "Module / công cụ (Metasploit)", "Chiến dịch mô phỏng [2]", "Cửa sổ chạy (UTC) / bước tấn công đầu"], [
  ["s1", "h1", "CVE-2015-5122 – Adobe Flash", "adobe_flash_opaque_background_uaf", "Strategic web compromise", "2022-07-19 13:12–13:40 / 13:26"],
  ["s2", "h1", "CVE-2015-3105 – Adobe Flash", "adobe_flash_shader_drawing_fill", "Malvertising dominate", "2022-07-19 13:45–14:20 / 14:07"],
  ["s3", "h1", "CVE-2017-11882 – Microsoft Word", "exploit CVE-2017-11882 (embedi) + multi/handler", "Spam campaign", "2022-07-19 14:20–15:05 / 15:36 (*)"],
  ["s4", "h1", "CVE-2017-0199 – Microsoft Word", "office_word_hta", "Pony campaign", "2022-07-20 00:31–01:00 / 00:52"],
  ["m1", "h1 → h2", "CVE-2015-5122 – Adobe Flash", "adobe_flash_opaque_background_uaf", "Strategic web compromise", "2022-07-19 16:00–17:50 / 17:20"],
  ["m2", "h1 → h2", "CVE-2015-5119 – Adobe Flash", "adobe_flash_hacking_team_uaf", "Targeted GOV phishing", "2022-07-19 19:32–20:02 / 19:44"],
  ["m3", "h1 → h2", "CVE-2015-3105 – Adobe Flash", "adobe_flash_shader_drawing_fill", "Malvertising dominate", "2022-07-19 20:06–20:40 / 20:28"],
  ["m4", "h1 → h2", "CVE-2018-8174 – Microsoft Word", "exploit CVE-2018-8174 (0x09AL) + multi/handler", "Monero miner by Rig", "2022-07-19 22:31–23:04 / 22:49"],
  ["m5", "h1 → h2", "CVE-2017-0199 – Microsoft Word", "office_word_hta", "Pony campaign", "2022-07-19 23:16–23:46 / 23:38"],
  ["m6", "h1 → h2", "CVE-2017-11882 – Microsoft Word", "exploit CVE-2017-11882 (embedi) + multi/handler", "Spam campaign", "2022-07-19 23:54 – 07-20 00:27 / 00:10"],
], [600, 800, 2000, 2300, 1700, 2238]));
c.push(P("(*) Đúng như in ở Bảng 2 của bài [1]: giờ bắt đầu tấn công 15:36 nằm ngoài cửa sổ chạy 14:20–15:05, nhiều khả năng là lỗi in; mình giữ nguyên số của nguồn.", { size: 19, italics: true }));
c.push(NOTE("**Hai chỗ tài liệu gốc không nhất quán (mình theo bài báo ATLASv2 và tệp mô tả tấn công):** (1) README của REAPr [3] viết s1, s2 dùng lỗ hổng Word còn s3, s4 dùng Flash, ngược với Bảng 1 của bài báo [1] và các tệp mô tả (s1, s2 là Flash; s3, s4 là Word). (2) Phần mô tả cấp cao của S-3 trong `attack_descriptions` vẫn ghi \"Flash\" (sao chép từ bản gốc), nhưng các lệnh thực hiện và CVE của S-3 là Word."));
c.push(H2("3.1 Các bước tấn công (Bảng 3 của bài ATLASv2 [1] và mô tả tấn công [4])"));
c.push(T(["Bước", "Mô tả", "Áp dụng cho"], [
  ["1", "Kẻ tấn công gửi email phishing (liên kết hoặc tệp đính kèm Word).", "s1–s4, m1–m6"],
  ["2", "Nạn nhân mở trang web độc hại (Flash) hoặc tải và mở tệp Word độc hại, tùy CVE.", "s1–s4, m1–m6"],
  ["3", "Kẻ tấn công có được shell Meterpreter (reverse_https tới máy chủ điều khiển).", "s1–s4, m1–m6"],
  ["4", "Dùng shell để thu thập thông tin (getuid, ps, ipconfig, usb_history, enum_shares...) và tải thêm payload `payload.exe` lên máy h1.", "s1–s4, m1–m6"],
  ["5", "Payload quét hệ thống lấy tệp PDF quan trọng, mở kết nối HTTPS để đưa tệp ra ngoài.", "s1–s4, m1–m6"],
  ["6", "Kẻ tấn công ghi đè trang chủ của máy chủ web trên h1 bằng trang phishing.", "m1–m6"],
  ["7", "Người dùng h2 truy cập trang web của h1, làm theo hướng dẫn tải và chạy payload.", "m1–m6"],
  ["8", "Payload trên h2 cũng thu PDF và gửi ra ngoài qua HTTPS.", "m1–m6"],
], [800, 6638, 2200]));
c.push(P("Thông tin kỹ thuật từ mô tả tấn công [4] và README REAPr [3]: máy chủ web độc hại `0xevil.com:9999`, máy chủ nhận payload Meterpreter `0xevil.com:8888`, cổng nhận dữ liệu bị đánh cắp `0xevil.com:8080`; trong log, IP kẻ tấn công xuất hiện là `10.193.66.115`, và IP của h1 trong log của h2 là `10.193.242.113`. Bài báo [1] liệt kê các thực thể tấn công đã biết: `ortrta.net`, `payload.exe`, `10.193.66.115:9999`, `10.193.66.115:8443`, `s3take2.zip`, `s4-at-night.zip`, `m4.zip`, `m5-2.zip`, `m6.zip`."));
c.push(P("Đặc điểm tấn công theo bài ATLAS gốc [2] (Bảng 2): phishing liên kết (PL) hoặc đính kèm (PA), tiêm mã (INJ), thu thập thông tin (IG), cửa hậu (BD), di chuyển ngang (LM, chỉ có ở nhóm m) và đánh cắp dữ liệu (DE)."));

// ---------------------------------------------------------------- 4
c.push(H1("4. Cấu trúc dữ liệu và các file"));
c.push(P("Cây thư mục `data/{benign,attack}/{h1,h2}/<luồng log>/` [5]. Số file lấy từ danh sách thành viên của `atlasv2.tar.gz` [ĐO]."));
c.push(T(["Luồng", "Định dạng", "Nội dung và số file", "Ví dụ kích thước [ĐO]"], [
  ["cbc-edr", "jsonl", "Telemetry Carbon Black (netconn, procstart, filemod...). Một file mỗi kịch bản: benign và m1–m6 cho cả h1, h2; s1–s4 chỉ h1.", "h1-m1: 90 MB; h1-benign: 2.4 GB"],
  ["cbc-edr-alerts", "jsonl", "Cảnh báo (watchlist hit) do Carbon Black sinh ra trong mỗi kịch bản.", "vài chục KB"],
  ["cbc-ngav, cbc-ngav-alerts", "jsonl", "Telemetry và cảnh báo của antivirus thế hệ mới (NGAV).", "vài MB / vài KB"],
  ["sysmon", "xml", "Xuất từ Event Viewer; benign mỗi máy 5 file (mỗi ngày một file); tấn công mỗi máy mỗi kịch bản một file.", "h1-m1: 1.8 MB"],
  ["msft-security", "xml", "Windows Security; benign mỗi máy 4 file (cuối ngày 2, 3, 4 và sáng ngày 5); tấn công một file mỗi kịch bản; thư mục `groundtruth/` chứa danh sách EventRecordID độc hại.", "h1-m1: 562 MB"],
  ["dns", "txt", "Log DNS do Wireshark ghi: benign 5 file mỗi máy (mỗi ngày một), tấn công một file mỗi kịch bản.", "h1-m1: 4.9 MB"],
  ["firefox", "txt", "Log gỡ lỗi do Firefox ghi; một số kịch bản có nhiều file (ví dụ h1-m5 có m5-a, m5-b).", "h1-m1: 4.6 GB"],
], [1700, 900, 4900, 2138]));
c.push(P("Ngoài ra có `atlasv2_attack_igraphs.tar.gz` (21 MB): các đồ thị tấn công dạng iGraph dùng để gán nhãn REAPr [5]."));

// ---------------------------------------------------------------- 5
c.push(H1("5. Các trường dữ liệu chi tiết"));
c.push(H2("5.1 Carbon Black EDR (cbc-edr, jsonl) – nguồn dùng làm \"flow\""));
c.push(P("Mỗi dòng là một sự kiện endpoint với **cùng một schema phẳng gồm 66 trường cho mọi loại sự kiện**. Trường của loại sự kiện khác tự động là `null`, nên dòng `netconn` có rất nhiều `null`; đây là đặc điểm của schema, không phải dữ liệu bị mất [ĐO]. Các loại sự kiện trong file `h1-m1` [ĐO]:"));
c.push(T(["type", "Số dòng (h1-m1)", "Ý nghĩa"], [
  ["endpoint.event.filemod", "18,274", "Ghi/ sửa tệp"],
  ["endpoint.event.moduleload", "8,811", "Nạp module (DLL)"],
  ["endpoint.event.regmod", "6,983", "Sửa registry"],
  ["endpoint.event.netconn", "1,519", "Kết nối mạng (dùng làm flow)"],
  ["endpoint.event.procend", "735", "Kết thúc tiến trình"],
  ["endpoint.event.procstart", "127", "Tạo tiến trình"],
  ["endpoint.event.crossproc", "126", "Tiến trình tác động sang tiến trình khác"],
  ["endpoint.event.scriptload", "113", "Nạp script"],
], [3200, 2000, 4438]));
c.push(SP());
c.push(P("Nhóm trường của một dòng `netconn` (nghĩa theo tên trường; giá trị quan sát được ghi trong ngoặc) [ĐO]:"));
c.push(T(["Nhóm", "Trường", "Ghi chú"], [
  ["Định danh sự kiện và máy", "`type`, `schema`, `org_key`, `device_id`, `device_name`, `device_external_ip`, `device_os`, `device_group`, `event_origin`, `sensor_action`, `action`", "Hằng số trong cả file (một máy, một tổ chức), trừ `action`: `ACTION_CONNECTION_CREATE`, `ACTION_CONNECTION_ESTABLISHED`, `ACTION_CONNECTION_LISTEN`. `device_group` luôn rỗng."],
  ["Thời gian", "`device_timestamp`, `backend_timestamp`", "`device_timestamp`: giờ trên máy (UTC, có phần ngàn giây); `backend_timestamp`: giờ phía cloud (làm tròn giây)."],
  ["Kết nối mạng", "`remote_ip`, `remote_port`, `local_ip`, `local_port`, `netconn_protocol`, `netconn_inbound`, `netconn_domain`, `netconn_community_id`", "`netconn_protocol`: PROTO_TCP hoặc PROTO_UDP. `netconn_inbound`: 0.0 (đi ra) hoặc 1.0 (đi vào). Dòng LISTEN có `remote_ip` rỗng, `remote_port` 0. `netconn_domain` chỉ có ở khoảng một nửa số dòng; `netconn_community_id` là mã băm của 5-tuple (khoảng 75% dòng có)."],
  ["Tiến trình tạo kết nối", "`process_guid`, `process_pid`, `process_path`, `process_cmdline`, `process_username`, `process_hash`, `process_publisher`, `process_reputation`, `process_terminated`, `process_duration`", "`process_guid` là khóa nối với nhãn REAPr. `process_path` là đường dẫn đầy đủ chữ thường (ví dụ `c:\\program files\\mozilla firefox\\firefox.exe`)."],
  ["Tiến trình cha", "`parent_guid`, `parent_pid`, `parent_path`, `parent_cmdline`, `parent_hash`, `parent_reputation`", "Cho biết ai khởi chạy tiến trình (ví dụ `explorer.exe` mở `firefox.exe`)."],
  ["Của loại sự kiện khác (luôn null ở netconn)", "`filemod_hash`, `filemod_name`, `regmod_name`, 7 trường `modload_*`, 7 trường `childproc_*`, 7 trường `crossproc_*`, 4 trường `scriptload_*`, `target_cmdline`", "29 trường. Cộng với `device_group` và `process_duration` luôn null, tổng 31 trường luôn null trong mẫu 335 hàng netconn mà mình kiểm tra."],
], [1900, 3900, 3838]));
c.push(H2("5.2 Windows Security (msft-security, xml)"));
c.push(P("Mỗi `<Event>` là một bản ghi Windows Event Log. Trong 80 MB đầu của file `h1-m1`, các EventID phổ biến là 4663 (21,267), 4656 (20,166), 4658 (19,835; thao tác đối tượng/tệp), **5156** (1,465; kết nối được Windows Filtering Platform cho phép), 5447, 5158, 4660, 4690, 4689 và **4688** (120; tạo tiến trình) [ĐO]."));
c.push(T(["EventID", "Trường chính trong EventData [ĐO]"], [
  ["5156 (kết nối mạng)", "`ProcessID`, `Application` (đường dẫn dạng \\device\\harddiskvolume1\\...), `Direction`, `SourceAddress`, `SourcePort`, `DestAddress`, `DestPort`, `Protocol` (6 = TCP, 17 = UDP), `FilterRTID`, `LayerName`, `LayerRTID`, `RemoteUserID`, `RemoteMachineID`. Không có số byte hay thời lượng."],
  ["4688 (tạo tiến trình)", "`SubjectUserSid`, `SubjectUserName`, `SubjectDomainName`, `SubjectLogonId`, `NewProcessId`, `NewProcessName`, `TokenElevationType`, `ProcessId`, `CommandLine` (thường rỗng trong mẫu)."],
], [2400, 7238]));
c.push(H2("5.3 Sysmon (xml)"));
c.push(P("Trong file `sysmon-h1-m1.xml` chỉ có hai loại: EventID 1 (tạo tiến trình, 652 sự kiện) và EventID 5 (kết thúc tiến trình, 653 sự kiện); **không có EventID 3 (kết nối mạng)** [ĐO]. Trường của EventID 1: `RuleName`, `UtcTime`, `ProcessGuid`, `ProcessId`, `Image`, `FileVersion`, `Description`, `Product`, `Company`, `OriginalFileName`, `CommandLine`, `CurrentDirectory`, `User`, `LogonGuid`, `LogonId`, `TerminalSessionId`, `IntegrityLevel`, `Hashes`, `ParentProcessGuid`, `ParentProcessId`, `ParentImage`, `ParentCommandLine`, `ParentUser`. Vì vậy Sysmon không dùng được làm nguồn flow mạng ở dataset này."));
c.push(H2("5.4 DNS, Firefox và cảnh báo"));
c.push(B("**DNS (Wireshark):** mỗi dòng dạng `số thứ tự, thời gian, IP nguồn → IP đích, giao thức, độ dài, nội dung truy vấn/đáp` (ví dụ truy vấn `detectportal.firefox.com`). Không có thông tin tiến trình [ĐO]."));
c.push(B("**Firefox:** log gỡ lỗi mỗi dòng có thời gian UTC, tên luồng và thông điệp (ví dụ `nsStreamPump ... OnStateStart`). Không phải bảng kết nối [ĐO]."));
c.push(B("**Cảnh báo (cbc-edr-alerts):** sự kiện `watchlist.hit` kèm `ioc_hit`, `report_name`, `report_tags` (gắn kỹ thuật MITRE ATT&CK), `process_*`, `parent_*`, `severity`. Kho còn có `docs/edr_alert_labels.xlsx` với hai sheet `attack_windows` và `benign`, cột `timestamp, attack_window, host, guid, path, pid, parent_guid, report, parent_pid, severity, label` – gán nhãn cho từng cảnh báo EDR [ĐO]."));

// ---------------------------------------------------------------- 6
c.push(H1("6. Nhãn"));
c.push(H2("6.1 Nhãn có trong dataset gốc"));
c.push(P("Theo bài báo ATLASv2 [1], nhãn cho Windows Security nằm ở `msft-security/groundtruth/`: mỗi file (tên dạng `h1_m1`) là danh sách `EventRecordID` của các sự kiện độc hại trong file xml tương ứng. Bài báo cũng liệt kê các thực thể tấn công đã biết (mục 3.1). Với Sysmon, Carbon Black, DNS và Firefox thì dataset gốc không có nhãn riêng; README khuyến nghị dùng nhãn REAPr vì \"đầy đủ hơn\" [5]."));
c.push(H2("6.2 Nhãn REAPr (mức tiến trình)"));
c.push(P("REAPr (Recovery Every Attack Process) là bộ nhãn chuẩn hóa của cùng nhóm tác giả [3][4]. Quy trình (tóm tắt): từ tài liệu tấn công xác định các nút gốc (root cause) và nút tác động (impact) trong đồ thị provenance; lần theo hướng xuôi từ gốc, chỉ đi qua các nút tiến trình, để lấy tập CONTAMINATED; lần theo hướng ngược từ nút tác động; phần giao của hai tập được gán nhãn MALICIOUS; còn lại BENIGN. Sau đó kiểm tra mọi thực thể tấn công đã biết đều là MALICIOUS và vẽ lại đồ thị để đối chiếu mô tả. Nhãn cuối cùng chỉ gán cho **thực thể tiến trình**, vì chỉ tiến trình mới \"tác nhân\" và gần với sản phẩm EDR thương mại [BB][4]."));
c.push(P("**Định dạng file nhãn** (`reapr-ground-truth/atlasv2/<máy>-<kịch bản>.labels`) [ĐO]: các cột `attack, process_name, process_id, process_uuid, label`. `process_uuid` trùng với `process_guid` trong cbc-edr nên nối trực tiếp được. Cột `label` trong các file đã phát hành **chỉ nhận giá trị `attack`**; mọi tiến trình không được liệt kê là benign. Kèm theo là file `.seeds` (cột `vertex_id, vertex_name, seed_label`): 60 đỉnh hạt giống, trong đó 38 `root_cause` (ví dụ `10.193.66.115:8080`, `10.193.66.115:8443`) và 22 `impact` (ví dụ `10.193.66.115:9999`, tệp `index.html`) [ĐO]."));
c.push(T(["File nhãn", "Số tiến trình attack", "File nhãn", "Số tiến trình attack"], [
  ["h1-s1", "21", "h2-m1", "5"],
  ["h1-s2", "8", "h2-m2", "5"],
  ["h1-s3", "17", "h2-m3", "5"],
  ["h1-s4", "23", "h2-m4", "5"],
  ["h1-m1", "18", "h2-m5", "5"],
  ["h1-m2", "8", "h2-m6", "5"],
  ["h1-m3", "8", "", ""],
  ["h1-m4", "9", "", ""],
  ["h1-m5", "35", "", ""],
  ["h1-m6", "14", "**Tổng**", "**191** (h1: 161, h2: 30)"],
], [2200, 2619, 2200, 2619]));
c.push(P("Số tiến trình theo máy khớp với bài THESEUS [6]: h1 có 10 kịch bản, 161 tiến trình tấn công; h2 có 6 kịch bản, 30 tiến trình tấn công; 100% dòng nhãn nối được vào nút tiến trình qua UUID của Carbon Black. Trong tập kiểm thử của họ, tỉ lệ tiến trình tấn công là 2.09% (h1, 7,712 tiến trình) và 0.40% (h2, 7,413 tiến trình) [BB][6]."));
c.push(H2("6.3 Dùng nhãn cho flow mạng: những gì mình đo được"));
c.push(P("Nối `process_guid` của các dòng `netconn` với `process_uuid` trong `.labels` của đúng kịch bản [ĐO]:"));
c.push(T(["Tập", "Số netconn", "Từ tiến trình có nhãn attack", "Ghi chú"], [
  ["16 file tấn công", "9,068", "7,793 (86%)", "h1-m1 là lớn nhất (1,519 netconn, 1,415 từ tiến trình có nhãn); h1-m5 chỉ 212"],
  ["Benign h1 + h2 (4 ngày)", "20,676", "0", "h1: 14,827; h2: 5,849"],
], [2300, 1700, 2600, 3038]));
c.push(NOTE("**Điều này có nghĩa gì:** nhãn gán theo tiến trình, nên **mọi** kết nối của một tiến trình bị nhiễm đều được coi là tấn công, kể cả duyệt web bình thường của `firefox.exe` bị khai thác. Vì vậy 86% flow trong file tấn công là dương, và flow dương của `firefox.exe` trông giống flow benign của `firefox.exe` (file benign có 14,106 netconn của `firefox.exe` trên h1). Đây là hạn chế về nhãn khi đưa vào mô hình mức flow, chưa đo ảnh hưởng lên mô hình."));

// ---------------------------------------------------------------- 7
c.push(H1("7. Hạn chế và cảnh báo của chính tác giả"));
c.push(B("**Các cuộc tấn công gần như giống nhau.** Theo README của REAPr (cùng nhóm tác giả ATLASv2), huấn luyện trên dữ liệu tấn công tương đương huấn luyện trên dữ liệu kiểm thử: với s1–s4, bốn trong năm bước giống hệt nhau (khác nhau chủ yếu ở bước 2, vector khai thác); với m1–m6, bảy trong tám bước tương tự. Dùng \"bỏ một cuộc tấn công ra làm kiểm thử\" cho mô hình phát hiện tổng quát mà không nêu bối cảnh thì gây hiểu lầm [3][5]."));
c.push(B("**Không thích hợp cho học có giám sát nhiều lớp** vì các cuộc tấn công cùng một tập bước chung (payload.exe giống nhau ở mọi cuộc) và vector chỉ có hai kiểu: trang web độc hại hoặc tệp Word độc hại [1]."));
c.push(B("**Mỗi kịch bản chạy trên một snapshot máy ảo khác nhau**, nên đầu mỗi log tấn công có một chuỗi hoạt động khởi động lặp lại; phải lưu ý khi dùng cho phát hiện bất thường [1]."));
c.push(B("**IP bị gán nhầm do hoạt động benign của người thí nghiệm thứ hai** trong lúc tấn công: các đồ thị của REAPr đánh dấu một số IP từ xa (m1: 1; m2: nhiều; m3: 2; m4: 1; m5: 1; m6: 5) là liên quan tấn công một cách sai; không ảnh hưởng đến các tiến trình trong chuỗi tấn công [3]."));
c.push(B("**Tất cả tấn công tập trung trong một ngày**, cùng cấu trúc payload, nên không có dữ liệu tấn công độc lập để làm tập validation [6]. Đồ thị provenance dựng từ telemetry EDR là xấp xỉ bảo thủ (có thể thừa phụ thuộc) [6]."));
c.push(B("**Quy mô nhỏ so với OpTC:** chỉ khoảng 29,700 netconn trong toàn bộ dataset [ĐO] (OpTC có 92 triệu flow). Chỉ có hai máy và hai người dùng."));

// ---------------------------------------------------------------- 8
c.push(H1("8. Ý nghĩa đối với đề tài (nhánh Network DL)"));
c.push(B("Dùng hàng `netconn` của `cbc-edr` làm flow: đã có sẵn tên tiến trình, đường dẫn, tiến trình cha, người dùng, giao thức, cổng, giờ; sinh được đủ 5 đầu vào của bản B (`app_family`, `proto`, `resp_port_class`, `image_dir_class`, `delta_t`)."));
c.push(B("Lọc dòng `ACTION_CONNECTION_LISTEN` hoặc `remote_ip` rỗng (đây là cổng đang lắng nghe, chưa có kết nối)."));
c.push(B("Bỏ khỏi đầu vào các trường luôn null, hằng số, hash, publisher, reputation; giữ `process_cmdline`, `parent_*`, `process_username`, IP cục bộ/từ xa làm cột audit."));
c.push(B("Khi báo cáo kết quả phải nêu: nhãn mức tiến trình, các cuộc tấn công gần như giống nhau (chia trộn theo cửa sổ rò rỉ mạnh), dataset nhỏ."));

// ---------------------------------------------------------------- refs
c.push(H1("Tài liệu tham khảo"));
c.push(P("[1] A. Riddle, K. Westfall, A. Bates. *ATLASv2: ATLAS Attack Engagements, Version 2*. arXiv:2401.01341, 2023 (bản PDF trong `E:\\IL_DATASET\\ATLASv2`).".replace(/\*/g, "")));
c.push(P("[2] A. Alsaheel, Y. Nan, S. Ma, L. Yu, G. Walkup, Z. B. Celik, X. Zhang, D. Xu. ATLAS: A Sequence-based Learning Approach for Attack Investigation. 30th USENIX Security Symposium, 2021, pp. 3005–3022."));
c.push(P("[3] Kho REAPr, bản ATLASv2: README và `attack_descriptions` (Bitbucket sts-lab/reapr-ground-truth). Phương pháp REAPr: J. Liu, M. A. Inam, A. Goyal, A. Riddle, K. Westfall, A. Bates. What We Talk About When We Talk About Logs: Understanding the Effects of Dataset Quality on Endpoint Threat Detection Research. IEEE S&P 2025, pp. 112–129, doi:10.1109/SP61157.2025.00112."));
c.push(P("[4] Mô tả các cuộc tấn công S-1…S-4, M-1…M-6 trong `reapr-ground-truth/atlasv2/attack_descriptions` (nguyên văn từ kho github.com/ausenix/USENIXSECURITY30 của ATLAS gốc), tệp `.labels`, `.seeds`."));
c.push(P("[5] README của kho ATLASv2 (`atlasv2/README.md`) và danh sách thành viên `atlasv2.tar.gz`."));
c.push(P("[6] Bài THESEUS: How benchmarks and evaluation protocols shape conclusions in provenance-based intrusion detection. NDSS Symposium 2027, arXiv:2608.01454 (bản PDF trong thư mục `research/papers`); Bảng II tóm tắt ATLASv2."));

build("ATLASv2 – Mô tả dataset", "Dataset tấn công APT trên Windows 7, phục vụ fine-tune nhánh Network DL (KLTN)", c, process.argv[2]).then(() => console.log("ok"));
