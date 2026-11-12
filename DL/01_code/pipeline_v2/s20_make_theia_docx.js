const { P, H1, H2, B, NOTE, T, SP, build } = require("./s20_docx_lib.js");

const c = [];
c.push(P("**Mục đích:** giúp hiểu rõ dataset THEIA (DARPA Transparent Computing, Engagement 3) để trình bày với thầy. Nội dung lấy từ báo cáo ground truth chính thức của đội tấn công (Kudu Dynamics), README của DARPA, bài báo về mô hình dữ liệu CDM, tài liệu REAPr và bài THESEUS; phần nào do mình tự đếm trên file raw thì ghi rõ."));
c.push(NOTE("**Cách đọc nhãn nguồn.** [BB] = lấy từ báo cáo/bài báo/tài liệu gốc (số trong ngoặc vuông chỉ mục Tài liệu tham khảo ở cuối). [ĐO] = mình đo trực tiếp trên file ở `E:\\IL_DATASET` (không có trong tài liệu gốc). Các giờ trong báo cáo của Kudu là giờ miền Đông Mỹ (EDT = UTC−4); mình đã đối chiếu với dữ liệu ở mục 6.3 và 6.4."));

// ---------------------------------------------------------------- 1
c.push(H1("1. Tóm tắt nhanh"));
c.push(T(["Mục", "Nội dung"], [
  ["Chương trình", "DARPA Transparent Computing (TC): làm cho hệ thống doanh nghiệp \"trong suốt\" để phát hiện sớm APT và truy vết nguyên nhân gốc. Engagement 3 (E3) diễn ra tháng 4/2018; trước đó sinh dữ liệu benign theo kịch bản, sau đó đội tấn công TA5.1 (Kudu Dynamics) thực hiện các hoạt động kiểu APT; hoạt động độc hại chỉ diễn ra khoảng 9 giờ sáng đến 5 giờ chiều các ngày trong tuần [2][3]."],
  ["THEIA là gì", "Tên của một nhóm TA1 (nhóm thu thập provenance) trong chương trình TC; \"máy mục tiêu THEIA\" là một máy Ubuntu 12.04 x64 chạy Firefox 54.0.1, tên máy trong log là `ta1-theia-target` [BB][1]."],
  ["Quy mô dữ liệu", "Một máy Linux. README E3 liệt kê bốn topic THEIA tốt: `ta1-theia-e3-official-1r`, `-3`, `-5m`, `-6r` [2]; bốn file này phủ 3/4 → 13/4/2018 (xem mục 4) [ĐO]."],
  ["Định dạng", "Avro nhị phân theo schema CDM18 [2]; bản người dùng có là bản chuyển sang JSON, mỗi dòng một bản ghi `{\"datum\":{...},\"CDMVersion\":\"18\",\"source\":\"SOURCE_LINUX_THEIA\"}`, nén `.json.tar.gz` [ĐO]."],
  ["Các cuộc tấn công nhằm THEIA", "Hai của nhóm \"quốc gia\" (Nation State): 10/4 14:00 (mục 3.3 của báo cáo) và 12/4 (mục 3.11); hai của nhóm \"mối đe dọa phổ thông\" (Common Threat): 10/4 13:00 (mục 4.6) và 13/4 14:00 (mục 4.8) [BB][1]."],
  ["Nhãn", "Không có trường nhãn trong log. Báo cáo Kudu cung cấp mô tả định tính (giờ, IP, tiến trình); nhãn mức tiến trình và mức cạnh (sự kiện) là của REAPr: giá trị `attack`, `contaminated`, còn lại là benign [BB][4][5]."],
], [2200, 7438], { firstColFill: true }));

// ---------------------------------------------------------------- 2
c.push(H1("2. Bối cảnh: chương trình TC, E3 và kẻ tấn công"));
c.push(P("**Mô hình dữ liệu chung CDM.** Mọi nhóm TA1 (CADETS, ClearScope, FAROS, FiveDirections, THEIA, TRACE, TA5.2) xuất dữ liệu theo một mô hình chung gọi là Common Data Model (CDM), do các nhóm trong chương trình cùng thiết kế trong khoảng bốn năm [BB][3]. CDM có sáu thực thể lõi: Host, Principal, Subject, Event, Object và ProvenanceTag. **Event là thực thể trung tâm**: một cạnh có hướng giữa chủ thể (Subject) và đối tượng (Object), mô tả một hành động như lời gọi hệ thống; các Event không liên hệ trực tiếp với nhau mà chỉ liên hệ qua Subject và Object [BB][3]."));
c.push(P("**Hai nhóm kẻ tấn công trong E3 [BB][1].**"));
c.push(B("**Nation State:** mục tiêu đánh cắp thông tin độc quyền và thông tin cá nhân. Công cụ: cửa hậu Nginx, cửa hậu Firefox, tiện ích mở rộng trình duyệt (trình tải trình quản lý mật khẩu), Drakon APT và micro APT; có khả năng giao tiếp HTTP, tạo tiến trình nâng quyền, tiêm `.dll`/`.so` vào tiến trình."));
c.push(B("**Common Threat:** mục tiêu đánh cắp thông tin cá nhân (PII) vì lợi ích tài chính, bằng email phishing giả mạo công ty Bovia, dùng thông tin đăng nhập đánh cắp rồi giả danh nạn nhân gửi tiếp cho người khác trong danh bạ; công cụ gồm email phishing, script PowerShell, macro Excel, cửa hậu Pine và một chương trình mã độc."));
c.push(B("Ngoài ra có vài cuộc tấn công lẻ dùng Metasploit nhằm vào ClearScope và TA5.2 (không nhằm vào THEIA)."));
c.push(P("Công cụ của nhóm Nation State có sẵn cho THEIA theo bảng của báo cáo [1]: cửa hậu Firefox, trình tải quản lý mật khẩu, Drakon APT, giao tiếp HTTP, quét cổng, tạo tiến trình nâng quyền, tiêm tiến trình (THEIA không có cửa hậu Nginx)."));

// ---------------------------------------------------------------- 3
c.push(H1("3. Các cuộc tấn công nhằm vào THEIA"));
c.push(T(["Mục báo cáo", "Ngày giờ (EDT)", "Nhóm", "Tên và cách thức", "Kết quả [1]"], [
  ["3.3", "2018-04-10 14:00", "Nation State", "Cửa hậu Firefox với Drakon chạy trong bộ nhớ: khai thác Firefox 54.0.1 qua máy chủ quảng cáo độc hại đặt trên trang www.allstate.com rồi www.gatech.edu", "Lần đầu (allstate) thất bại, Firefox treo; lần sau qua gatech.edu thành công, có shell, được nâng quyền root"],
  ["3.11", "2018-04-12 12:00 (log 12:44–13:26)", "Nation State", "Tiện ích mở rộng trình duyệt (trình quản lý mật khẩu) trên Firefox 54.0.1 và Drakon ghi xuống đĩa; sau đó chạy micro APT", "Tiêm vào tiến trình sshd thất bại; micro APT (`/var/log/mail`) nâng quyền, kết nối C2 và quét cổng các máy trong mạng"],
  ["4.6", "2018-04-10 13:00", "Common Threat", "Email phishing có liên kết tới www.nasa.ng (208.75.117.3); form nhập tên, email, mật khẩu gửi về www.foo1.com (208.75.117.2)", "Thành công: người dùng THEIA mở email lúc 13:42, nhập thông tin"],
  ["4.8", "2018-04-13 14:00", "Common Threat", "Email phishing đính kèm tệp thực thi `tcexec`", "Thất bại: thiếu thư viện (QT) trên máy mục tiêu, tệp không chạy"],
], [800, 1500, 1200, 3638, 2500]));
c.push(H2("3.1 Cuộc tấn công 3.3 (10/4) chi tiết"));
c.push(P("Diễn biến theo báo cáo [1] (giờ EDT): 09:58 THEIA không phản hồi, được khởi động lại (nhóm TA2 và BBN phát hiện **THEIA đã đăng dữ liệu cũ do chậm**, nên không ai nhận ra máy bị treo). 13:41 khai thác qua www.allstate.com thất bại ba trên bốn lần, Firefox treo, phải `kill -9` qua SSH. 14:31 khai thác qua www.gatech.edu, nhận shell. 14:35 `putfile clean` rồi `elevate clean` (tiến trình root mới), đóng shell không phải root. 14:51 Drakon (chạy với quyền root) ngừng phản hồi. 14:55 khai thác lại gatech.edu, `putfile profile`, để lại kết nối mở."));
c.push(P("Địa chỉ liên quan trong báo cáo [1] và vai trò của chúng (các IP này xuất hiện trong flow có nhãn của mình, xem mục 6.4):"));
c.push(T(["IP:cổng", "Vai trò theo báo cáo", "Thuộc cuộc"], [
  ["145.199.103.57:80", "Máy chủ web www.allstate.com (quảng cáo độc hại)", "3.3"],
  ["61.130.69.232:80", "Máy chủ shellcode (qua allstate.com)", "3.3"],
  ["104.228.117.212:80", "Máy chủ web www.gatech.edu", "3.3, 3.11"],
  ["141.43.176.203:80", "Máy chủ shellcode (qua gatech.edu)", "3.3, 3.11"],
  ["146.153.68.151:80", "Máy chủ chứa loaderDrakon.linux.x64", "3.3, 3.11"],
  ["161.116.88.72:80", "Máy chủ chứa drakon.linux.x64 (tệp `clean`, `profile`)", "3.3"],
  ["5.214.163.155:80", "Máy chủ chứa libdrakon.linux.x64.so", "3.3"],
  ["7.149.198.40:80", "Mô-đun netrecon (nrtcp)", "3.3"],
  ["149.52.198.23:80", "Máy chủ điều khiển của micro APT", "3.11"],
], [2200, 5638, 1800]));
c.push(H2("3.2 Cuộc tấn công 3.11 (12/4) chi tiết"));
c.push(P("Theo báo cáo [1]: kẻ tấn công định tiêm tệp đã thả trước đó vào tiến trình sshd để quét cổng các máy trong mạng, nhưng **tiêm tiến trình bị lỗi** (nhiều lần thử với `memtrace.so` đều thất bại). Thay vào đó ghi micro APT xuống đĩa (`putfile /var/log/mail`), nâng quyền (`elevate /var/log/mail 149.52.198.23`) lúc 13:17, có kết nối C2, rồi dùng micro APT quét cổng nhiều máy trong mạng (các lệnh `APT>scan 128.55.12.x <cổng đầu> <cổng cuối>`); 13:26 xóa tệp và thoát. Tại thời điểm đó hai kết nối mở tồn tại tới máy THEIA: một từ nhiều ngày trước chạy với quyền root, một mới chạy với quyền người dùng thường."));

// ---------------------------------------------------------------- 4
c.push(H1("4. Dữ liệu và các file"));
c.push(P("README E3 [2] nói dữ liệu THEIA nằm ở `data/theia/`, các topic tốt là bốn topic sau; dữ liệu gốc là Avro nhị phân, kèm công cụ `ta3-java-consumer` để chuyển sang JSON và schema `CDM18.avdl`. Mỗi file `.tar.gz` của bạn chứa nhiều phần `.json`, `.json.1`, ... mỗi phần khoảng 3.7 GB (giải nén). Phạm vi thời gian, số bản ghi [ĐO]:"));
c.push(T(["File", "Khoảng thời gian (UTC)", "Sự kiện", "NetFlowObject", "Subject (tiến trình)", "Nhãn REAPr"], [
  ["`1r`", "2018-04-03 14:02 → 04-05 15:19", "44.0 triệu", "69,870", "92,376", "không"],
  ["`3`", "2018-04-05 15:42 → 16:41", "1.47 triệu", "6,174", "3,455", "không"],
  ["`5m`", "2018-04-09 12:46 → 22:15", "0.92 triệu", "907", "13,916", "không"],
  ["`6r`", "2018-04-10 16:44 → 04-13 21:04", "59.6 triệu", "168,156", "169,644", "**có**: toàn bộ 68,924 cạnh có nhãn"],
], [800, 2700, 1200, 1300, 1500, 2138]));
c.push(P("Một cảnh báo về chất lượng dữ liệu: báo cáo ghi nhận THEIA có lúc đăng dữ liệu cũ do chậm và máy từng treo [1]; bài THESEUS còn lưu ý workload sinh dữ liệu benign đổi cấu hình giữa các lát thời gian nên họ chỉ dùng lát cuối ổn định (T3) của THEIA [BB][6]."));

// ---------------------------------------------------------------- 5 fields
c.push(H1("5. Các trường dữ liệu chi tiết (CDM18)"));
c.push(P("Định nghĩa trường theo bài mô tả CDM [3]; cột cuối là giá trị mình quan sát trên file THEIA [ĐO]."));
c.push(T(["Bản ghi", "Trường (theo CDM [3])", "Ý nghĩa", "Quan sát ở THEIA [ĐO]"], [
  ["Host", "`uuid`, `hostName`, `hostIdentifiers`, `osDetails`, `hostType`, `interfaces`", "Máy chủ nơi tiến trình và đối tượng cùng sự kiện xảy ra", "`hostName` rỗng, `hostType` = HOST_DESKTOP, giao diện `eth0`, IP 10.0.6.60"],
  ["Principal", "`uuid`, `type`, `userId`, `username`, `groupIds`, `properties`", "Người dùng cục bộ sở hữu tiến trình và đối tượng", "`type` PRINCIPAL_LOCAL/REMOTE; `userId` (0, 1000, 116...); **`username` luôn null**; `properties.map.cred`"],
  ["Subject", "`uuid`, `type`, `cid`, `parentSubject`, `hostId`, `localPrincipal`, `startTimestampNanos`, `unitId`, `iteration`, `count`, `cmdLine`, `privilegeLevel`, `importedLibraries`, `exportedLibraries`, `properties`", "Ngữ cảnh thực thi: tiến trình (hoặc luồng); `parentSubject` của tiến trình là tiến trình cha", "Mọi Subject là `SUBJECT_PROCESS`; `cid` là pid; `cmdLine` là chuỗi lệnh (\"N/A\" với tiến trình nhân); `properties.map` có `path`, `ppid`, `tgid`; các trường còn lại null. **Lưu ý:** `path` và `cmdLine` là tên **lúc fork** (tiến trình con fork từ `fluxbox` vẫn ghi `fluxbox` dù sau đó exec thành `firefox`); chương trình thật nằm ở sự kiện `EVENT_EXECUTE` (`properties.map.cmdLine`)"],
  ["Event", "`uuid`, `sequence`, `type`, `threadId`, `hostId`, `subject`, `predicateObject`, `predicateObject2`, `*Path`, `timestampNanos`, `name`, `parameters`, `location`, `size`, `programPoint`, `properties`", "Hành động (lời gọi hệ thống) do Subject thực hiện lên Object; cạnh có hướng", "`subject` trỏ Subject; `predicateObject` trỏ đối tượng; `timestampNanos` là giờ UTC theo nano giây; `name` là tên syscall (clone, open, mmap...); `size` có ở read/write/send/recv, trống ở CONNECT; `properties.map.rc` là mã trả về"],
  ["NetFlowObject", "`uuid`, `baseObject`, `localAddress`, `localPort`, `remoteAddress`, `remotePort`, `ipProtocol`, `fileDescriptor`", "Một ổ cắm mạng (socket)", "Có địa chỉ và cổng hai đầu; **`ipProtocol` luôn null**; `remoteAddress` có thể là `NA`, `LOCAL`, `NETLINK` (ổ cắm cục bộ, không phải kết nối mạng), `127.0.0.1`"],
  ["FileObject", "`uuid`, `baseObject`, `type`, `fileDescriptor`, `localPrincipal`, `size`, `peInfo`, `hashes`", "Tệp", "`baseObject.properties.map` có `filename`, `inode`, `dev`, `syscall`"],
  ["MemoryObject", "`uuid`, `baseObject`, `memoryAddress`, `pageNumber`, `pageOffset`, `size`", "Vùng nhớ", "`properties.map.prot` (PROT_READ...)"],
], [1400, 3000, 2200, 3038], { size: 17 }));
c.push(P("**Sự kiện chạm ổ cắm mạng** ở lát `6r` [ĐO]: `RECVFROM` 9.96 triệu, `RECVMSG` 1.22 triệu, `SENDMSG` 0.98 triệu, `CONNECT` 0.37 triệu, `SENDTO` 0.35 triệu, `READ_SOCKET_PARAMS` 0.21 triệu, `WRITE_SOCKET_PARAMS` 0.15 triệu, tổng 13.2 triệu sự kiện trên 168,156 ổ cắm. THEIA **không có \"flow\" dựng sẵn**: muốn có flow phải gom Event theo `predicateObject`. Không có thời lượng, trạng thái kết nối hay số gói; byte chỉ có thể xấp xỉ bằng tổng `size` của các sự kiện gửi/nhận."));
c.push(P("**Tiến trình chạm mạng nhiều nhất** ở `6r` theo `Subject.path` [ĐO]: `fluxbox` (8.2 triệu sự kiện), `firefox` (2.8 triệu), `thunderbird`, `console-kit-daemon`, `sshd`; lát `1r` còn có `Xvnc4` (3.5 triệu). Vì `Subject.path` là tên lúc fork nên mục `fluxbox` có thể gồm cả tiến trình con sau đó exec thành chương trình khác."));

// ---------------------------------------------------------------- 6 labels
c.push(H1("6. Nhãn"));
c.push(H2("6.1 Ground truth gốc của DARPA"));
c.push(P("Do nhóm tấn công Kudu Dynamics viết, là **báo cáo định tính** (file `TC_Ground_Truth_Report_E3_Update.pdf`, tháng 5/2018) [1]: từng cuộc tấn công có mô tả, nhật ký sự kiện theo giờ, danh sách địa chỉ IP vai trò gì, tệp và tiến trình đã dùng, kèm đồ thị mẫu. Không có file nhãn cho từng bản ghi. Mọi IP và tên miền trong mạng thử nghiệm là giả [2]."));
c.push(H2("6.2 Nhãn REAPr"));
c.push(P("REAPr [4] tiêu chuẩn hóa nhãn bằng một quy trình chung (phương pháp trong bài S&P 2025 [5]): xác định nút gốc và nút tác động của từng cuộc tấn công trong đồ thị provenance; lần theo hướng xuôi từ gốc chỉ qua các nút tiến trình (tập CONTAMINATED), lần theo hướng ngược từ nút tác động; phần giao hai tập là MALICIOUS; còn lại BENIGN. Kết quả ghi ở mức **tiến trình**. Trong file nhãn đã phát hành, nhãn MALICIOUS được ghi là `attack` và nhãn CONTAMINATED là `contaminated`. Ý nghĩa của `contaminated`: tiến trình chịu ảnh hưởng của kẻ tấn công (ví dụ Firefox bị khai thác rồi sinh ra các tiến trình tấn công) nhưng không nằm trên đường đi tấn công; bài THESEUS loại các tiến trình này khỏi chấm điểm vì chúng có thể bất thường do kẻ tấn công mà báo cáo của DARPA không xác nhận là tấn công [BB][6]."));
c.push(P("REAPr chỉ gán nhãn cho các cuộc tấn công của nhóm Nation State, không gán cho Common Threat vì nhiều cuộc không phân biệt được với hoạt động người dùng bình thường; mỗi lần thử được gán theo số mục trong báo cáo, và chia thành thành công (`success`) hoặc thất bại (`fail`); tác giả **không khuyến nghị** test trên các lần thất bại vì thường không để lại dấu vết đáng kể [BB][4]. (Trong file nhãn mình thấy vẫn có chuỗi `theia_4.8_fail` thuộc mục 4.8 của Common Threat; README không giải thích điều này [ĐO].)"));
c.push(H2("6.3 Hai file nhãn và số liệu"));
c.push(P("**`theia_labels.csv`** (nhãn tiến trình): cột `attack_chain, uuid, process_name, label`; khóa `uuid` trùng `Subject.uuid`. **`theia_edge_labels.tar.gz` → `edge_labels.csv`** (nhãn cạnh): cột `attack_chain, vertex_uuid, vertex_label, edge_uuid`; khóa `edge_uuid` trùng `Event.uuid`. Luật suy ra nhãn cạnh từ nhãn đỉnh [BB][4]: nếu đỉnh attack/contaminated là **nguồn** của luồng thông tin (ví dụ ghi) thì cạnh thừa hưởng nhãn; nếu là **đích** (ví dụ đọc) thì cạnh thừa hưởng nhãn chỉ khi nguồn không phải tiến trình."));
c.push(T(["Chuỗi (attack_chain)", "Tiến trình attack", "Tiến trình contaminated", "Cạnh có nhãn", "Trong đó chạm NetFlow"], [
  ["theia_3.3_fail_allstate", "1", "0", "9", "9"],
  ["theia_3.3_fail_gatech_clean", "32", "0", "1,310", "402"],
  ["theia_3.3_success_gatech_profile", "48", "0", "1,481", "560"],
  ["theia_3.11_fail", "1", "1", "561", "202"],
  ["theia_3.11_success", "41", "1", "65,516", "64,093"],
  ["theia_4.8_fail", "2", "0", "52", "0"],
  ["**Tổng**", "125 attack (126 tiến trình khác nhau kể cả contaminated)", "1 (`3A3530B4-...`, firefox)", "68,929 dòng (68,924 cạnh khác nhau; 4 dòng contaminated)", "65,266"],
], [2900, 1700, 1700, 1700, 1638], { size: 17 }));
c.push(P("[ĐO] Tất cả 68,924 cạnh có nhãn đều nằm trong lát `6r`, vào hai khoảng: 10/4 18:25–19:xx UTC (khoảng 14:25–15:xx EDT, ứng với cuộc 3.3) và 12/4 16:00–17:26 UTC (12:00–13:26 EDT, ứng với cuộc 3.11), cộng một ít cạnh của tiến trình `profile` về sau (11/4, 12/4)."));
c.push(P("Hai sự kiện contaminated (mỗi sự kiện xuất hiện ở hai chuỗi) đều là `EVENT_CLONE` của tiến trình firefox `3A3530B4-...` sinh ra hai tiến trình attack (`7235B0B4-...`, `B33501B6-...`): đúng ý nghĩa \"contaminated\" ở trên; không có sự kiện mạng nào [ĐO]."));
c.push(H2("6.4 Đối chiếu nhãn với báo cáo: các con số khớp"));
c.push(P("Nối `edge_uuid` với sự kiện raw rồi lấy ổ cắm mà sự kiện chạm tới [ĐO]:"));
c.push(T(["Đầu xa của ổ cắm", "Số sự kiện có nhãn", "Vai trò trong báo cáo [1]"], [
  ["`NA:0` (ổ cắm không có đầu xa)", "63,561 (chỉ `CONNECT`)", "Toàn bộ từ **một** tiến trình `283847BC-...` có `path` = `/var/log/mail` = micro APT đang quét cổng (mục 3.11); 25,278 ổ cắm khác nhau"],
  ["141.43.176.203:80", "868", "Máy chủ shellcode qua gatech.edu"],
  ["146.153.68.151:80", "398", "loaderDrakon"],
  ["161.116.88.72:80", "327", "drakon.linux.x64 (tệp `clean`, `profile`)"],
  ["149.52.198.23:80", "89", "C2 của micro APT (3.11)"],
  ["61.130.69.232:80", "9", "Máy chủ shellcode qua allstate.com (lần thất bại)"],
  ["7.149.198.40:80", "2", "netrecon"],
  ["128.55.12.110:22, :80, :111, :5901", "2 mỗi cổng", "Máy bị micro APT quét (báo cáo có lệnh `scan 128.55.12.110 ...`)"],
], [3300, 2300, 4038]));
c.push(NOTE("**Hệ quả cho mô hình mức flow:** 97% sự kiện mạng có nhãn là `CONNECT` của một tiến trình quét tới ổ cắm không có đầu xa; các ổ cắm này bị loại khi dựng flow (không có địa chỉ/cổng xa). Sau khi loại, flow dương có đầu xa thật chỉ gồm **1,701 sự kiện trên 20 ổ cắm** (cuộc 3.11 thành công: 11; 3.3 thành công: 4; 3.3 thất bại gatech: 3; 3.11 thất bại: 1; 3.3 thất bại allstate: 1), đều tới cổng 80. Số mẫu dương theo cửa sổ 15 phút chưa dựng."));

// ---------------------------------------------------------------- 7
c.push(H1("7. Hạn chế và cảnh báo"));
c.push(B("**Chỉ một máy Linux** (Ubuntu 12.04), chỉ hai cuộc tấn công Nation State nhắm vào máy này; một cuộc (3.11) chiếm 95% cạnh có nhãn [ĐO]."));
c.push(B("**Nhãn theo tiến trình và theo cạnh, không phải nhãn từng flow chuẩn.** Tiến trình `contaminated` bị loại khỏi chấm điểm trong THESEUS [6]; các chuỗi `fail` tác giả khuyên không dùng để test [4]."));
c.push(B("**Dữ liệu thiếu so với OpTC:** không có `ipProtocol` (không biết TCP hay UDP), không có `username`, không có thời lượng, trạng thái kết nối, số gói; flow phải tự dựng từ sự kiện [ĐO]."));
c.push(B("**Chất lượng thu thập:** THEIA từng đăng dữ liệu cũ do chậm và máy treo trong ngày tấn công; Firefox 54.0.1 treo nhiều lần trong lúc khai thác; tiêm tiến trình thất bại [1]. Workload benign đổi cấu hình giữa các lát thời gian [6]."));
c.push(B("**Từ vựng khác Windows:** tên tiến trình và đường dẫn là của Linux (`/usr/bin/fluxbox`, `/home/admin/Downloads/firefox/firefox`), từ điển OpTC không có, gần như toàn `<UNK>`."));

// ---------------------------------------------------------------- 8
c.push(H1("8. Ý nghĩa đối với đề tài (nhánh Network DL)"));
c.push(B("Dựng flow bằng cách gom Event theo NetFlowObject; bỏ ổ cắm thiếu đầu xa (`NA`), `LOCAL`, `NETLINK`, 127.0.0.1; lấy `app_family` từ `cmdLine` của sự kiện `EVENT_EXECUTE` mới nhất của tiến trình (hoặc `process_name` trong `theia_labels.csv`), không lấy từ `Subject.properties.map.path` vì đó là tên lúc fork; `resp_port_class` từ `remotePort` (hướng suy từ CONNECT), `delta_t` từ `timestampNanos`; `proto` thiếu; `image_dir_class` cần lớp thư mục Linux hoặc dồn về `OTHER`."));
c.push(B("Nhãn flow lấy bằng cách kiểm `Event.uuid` có trong `edge_labels.csv` (hoặc `Subject.uuid` có trong `theia_labels.csv`)."));
c.push(B("Khi báo cáo phải nêu: số flow dương rất ít, một máy, hai đợt tấn công; nhãn mức tiến trình/cạnh."));

// ---------------------------------------------------------------- refs
c.push(H1("Tài liệu tham khảo"));
c.push(P("[1] Kudu Dynamics. DARPA Transparent Computing, TA5.1 Ground Truth Report, Engagement 3. Tháng 5/2018 (`TC_Ground_Truth_Report_E3_Update.pdf`; bản đọc từ `research/code_references/NDSS/theseus-main/ground_truth`). Các mục 2, 3.3, 3.11, 4.6, 4.8."));
c.push(P("[2] DARPA Transparent Computing, README-E3 (github.com/darpa-i2o/Transparent-Computing): mô tả E3, cấu trúc thư mục dữ liệu, danh sách topic THEIA."));
c.push(P("[3] J. Khoury, T. Upthegrove, A. Caro, B. Benyo, D. Kong (Raytheon BBN Technologies). An Event-based Data Model for Granular Information Flow Tracking (mô hình dữ liệu CDM của chương trình TC); bản PDF trong `research/papers`."));
c.push(P("[4] Kho REAPr, phần `darpa-tc-engagement3` (README, `theia_labels.csv`, `theia_edge_labels.tar.gz`) và README tổng (Bitbucket sts-lab/reapr-ground-truth)."));
c.push(P("[5] J. Liu, M. A. Inam, A. Goyal, A. Riddle, K. Westfall, A. Bates. What We Talk About When We Talk About Logs: Understanding the Effects of Dataset Quality on Endpoint Threat Detection Research. IEEE S&P 2025, pp. 112–129, doi:10.1109/SP61157.2025.00112."));
c.push(P("[6] How benchmarks and evaluation protocols shape conclusions in provenance-based intrusion detection (bài THESEUS). NDSS Symposium 2027, arXiv:2608.01454 (bản PDF trong `research/papers`)."));

build("THEIA – Mô tả dataset", "DARPA Transparent Computing, Engagement 3: máy Linux THEIA, phục vụ fine-tune nhánh Network DL (KLTN)", c, process.argv[2]).then(() => console.log("ok"));
