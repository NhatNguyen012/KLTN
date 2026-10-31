
Để tái tạo bộ dữ liệu **ATLASv2** (*ATLAS Attack Engagements, Version 2* do nhóm nghiên cứu tại UIUC thực hiện), các tác giả đã kế thừa 10 kịch bản tấn công APT từ công trình **ATLAS gốc (Version 1)** của Đại học Purdue nhưng nâng cấp toàn diện cách thức tạo nhiễu nền (benign activity), luồng ghi nhận nhật ký (telemetry) và quy trình tích hợp tấn công vào công việc thực tế của người dùng.

---

### 1. Thiết lập môi trường Testbed và Công cụ ghi Log (Instrumentation)

Khác với Version 1 chỉ thu thập khoảng 6.7 GB log trong vòng 24 giờ cho mỗi kịch bản, **ATLASv2** xây dựng một môi trường thực nghiệm kéo dài **5 ngày** liên tục và thu thập tổng cộng **154 GB dữ liệu** trên 3 máy ảo (VM):

* **2 Máy nạn nhân (`h1` và `h2`):** Chạy hệ điều hành Windows 7 32-bit, cài đặt sẵn các phần mềm có lỗ hổng gồm Mozilla Firefox 52.0, Microsoft Office Professional Plus 2010, và Adobe Flash Player (phiên bản 17.0.0.188 và 18.0.0.194 tùy theo CVE của từng kịch bản).
* **Máy chủ nội bộ (trên `h1`):** Người dùng trên máy `h1` chạy thêm một `SimpleHTTP server` đóng vai trò làm cổng thông tin nội bộ (internal web portal - tương ứng với `portal.com` ở bản gốc). Máy chủ này chính là bàn đạp để kẻ tấn công thực hiện di chuyển ngang (lateral movement) sang máy `h2` trong các kịch bản đa máy chủ.
* **1 Máy tấn công:** Chạy hệ điều hành **Kali Linux**, đóng vai trò là máy của kẻ tấn công (sử dụng Metasploit/Meterpreter và đóng vai trò C&C server tại địa chỉ IP `10.193.66.115` với các cổng `9999` và `8443`, cùng tên miền độc hại `ortrta.net`).
* **5 Nguồn thu thập Log trên mỗi máy nạn nhân:** Nếu như bản ATLASv1 chỉ thu thập 3 nguồn (Windows Security Event/Sysmon, Firefox log, TShark DNS log), thì ATLASv2 ghi lại đồng thời 5 luồng dữ liệu:

1. **Microsoft Windows ETW Security Audit** (`msft-security`).
2. **Sysmon** (System Monitor cho Windows - `sysmon`).
3. **Wireshark** (thu thập thông tin truy vấn DNS - `dns`).
4. **Firefox Application Logs** (`firefox`).
5. **VMware Carbon Black Cloud Sensor (v3.8.0.627):** Tự động đẩy dữ liệu về AWS S3 bucket, được tách thành 4 thư mục con gồm log sự kiện và cảnh báo của EDR (`cbc-edr`, `cbc-edr-alerts`) và Next-Gen Antivirus (`cbc-ngav`, `cbc-ngav-alerts`).

---

### 2. Giai đoạn tạo hoạt động bình thường (Benign Period - 4 ngày đầu)

Một điểm yếu thường gặp ở các bộ dữ liệu trước là hành vi người dùng chỉ được tạo trong thời gian ngắn hoặc qua kịch bản mô phỏng cố định. Trong **ATLASv2**:

* Hai nhà nghiên cứu trực tiếp sử dụng hai máy ảo `h1` và `h2` làm **máy trạm làm việc chính (primary workstations)** của họ trong suốt 4 ngày đầu tiên, khoảng **8 tiếng mỗi ngày**, và để máy chạy qua đêm sau khi hết giờ làm việc.
* Toàn bộ hoạt động đều là hành vi thật 100% của con người: duyệt web, họp trực tuyến qua Zoom, soạn thảo tài liệu dự án trên bộ Microsoft Office, gửi/nhận email có tệp đính kèm, trò chuyện trên Discord, xem video...
* Cuối mỗi ngày làm việc, các bản ghi Windows Security, Sysmon, Firefox và DNS được chuyển ra ngoài qua một thư mục chia sẻ (shared folder) với máy chủ vật lý để giảm dung lượng lưu trữ trên VM, trong khi log Carbon Black được đẩy thẳng lên đám mây AWS S3.

---

### 3. Quy trình triển khai 10 kịch bản tấn công (Attack Day - Ngày thứ 5)

Sang ngày thứ 5 (19/07/2022 – 20/07/2022 theo giờ UTC), hai nhà nghiên cứu bắt đầu ngày làm việc bình thường, sau đó lần lượt kích hoạt **10 kịch bản tấn công** (4 kịch bản đơn máy `s1`–`s4` chỉ đánh vào `h1`, và 6 kịch bản đa máy `m1`–`m6` đánh từ `h1` lan sang `h2`). Mỗi kịch bản được thực thi trên một bản **snapshot** riêng của máy ảo Windows 7 trong một khung thời gian từ **30 phút đến 2 giờ**.

Trong lúc cuộc tấn công diễn ra từ máy Kali Linux, người dùng trên `h1` (và `h2` đối với kịch bản multi-host) vẫn tiếp tục làm việc bình thường để log độc hại hòa trộn tự nhiên vào luồng công việc thực tế.

#### A. Kịch bản 8 bước tấn công chuẩn hóa (Attack Chain)

Kết hợp thông tin từ báo cáo ATLASv2 và thiết kế gốc trong ATLASv1, các bước tấn công cụ thể được thực thi theo trình tự sau:

* Các kịch bản Đơn máy chủ (`s1` – `s4`) thực hiện từ Bước 1 đến Bước 5 trên `h1`:
* **Bước 1 (Phishing):** Kẻ tấn công từ máy Kali Linux gửi một email lừa đảo (phishing email) tới nạn nhân trên `h1`.
* **Bước 2 (Khai thác lỗ hổng - Exploitation):** Nạn nhân mở email trên trình duyệt Firefox. Tùy theo CVE của kịch bản, nạn nhân sẽ:
* *Nhấp vào đường link độc hại* dẫn tới trang web khai thác lỗ hổng **Adobe Flash Player** (các kịch bản `s1`, `s2`, `m1`, `m2`, `m3`).
* Hoặc *tải xuống và mở tệp đính kèm độc hại* (các file nén `.zip` chứa tài liệu Word độc hại như `s3take2.zip`, `s4-at-night.zip`, `m4.zip`, `m5-2.zip`, `m6.zip`) nhằm khai thác lỗ hổng của **Microsoft Word / Office** (`s3`, `s4`, `m4`, `m5`, `m6`).
* **Bước 3 (Chiếm quyền điều khiển - Meterpreter Shell):** Khai thác thành công giúp kẻ tấn công tiêm mã độc (injection) và mở được một phiên kết nối ngược **Meterpreter shell** về máy Kali Linux.
* **Bước 4 (Hạ cánh mã độc - Drop Payload):** Thông qua phiên Meterpreter, kẻ tấn công thu thập thông tin và thả thêm một tệp thực thi backdoor có tên `payload.exe` xuống máy `h1`.
* **Bước 5 (Đánh cắp dữ liệu trên `h1` - Exfiltration):** Mã độc `payload.exe` thực thi, quét và thu thập các tệp tài liệu nhạy cảm (`.pdf`) trên máy `h1`, sau đó mở kết nối HTTPS tới máy chủ C&C (`10.193.66.115:8443` / `10.193.66.115:9999`) để tuồn dữ liệu ra ngoài.
* Các kịch bản Đa máy chủ (`m1` – `m6`) thực hiện tiếp Bước 6 đến Bước 8 để lây nhiễm sang `h2`:
* **Bước 6 (Sabotage Web Portal nội bộ):** Từ quyền kiểm soát trên `h1`, kẻ tấn công phát hiện `h1` đang chạy `SimpleHTTP server` làm cổng web nội bộ. Kẻ tấn công tải `payload.exe` lên thư mục web và **ghi đè trang chủ `index.html**` của server này bằng một trang giả mạo (phishing page) hiển thị thông báo yêu cầu người dùng nội bộ tải bản cập nhật hệ thống.
* **Bước 7 (Di chuyển ngang - Lateral Movement sang `h2`):** Người dùng trên máy `h2` truy cập vào trang web nội bộ của `h1`, bị lừa tải xuống và chạy tệp `payload.exe`.
* **Bước 8 (Đánh cắp dữ liệu trên `h2`):** Tệp `payload.exe` trên máy `h2` tiếp tục thu thập các tệp `.pdf` nhạy cảm của `h2` và mở kết nối HTTPS gửi thẳng về máy chủ C&C của kẻ tấn công.

---

#### B. Bảng ánh xạ chi tiết 10 kịch bản giữa ATLASv1 (Purdue) và ATLASv2 (UIUC)

Khi đối chiếu tài liệu của hai phiên bản, có thể thấy cách các tác giả thiết kế từng kịch bản dựa trên các chiến dịch APT thực tế:

| Kịch bản   | Chiến dịch APT gốc (từ ATLASv1)    | Mã lỗ hổng (CVE) | Phần mềm bị khai thác & Vector xâm nhập đầu tiên | Thời gian chạy máy & Bắt đầu tấn công trong ATLASv2 (UTC) |
| ------------ | -------------------------------------- | ------------------- | --------------------------------------------------------- | ----------------------------------------------------------------- |
| **s1** | Strategic web compromise (HackingTeam) |                     |                                                           |                                                                   |

 | CVE-2015-5122

 | **Adobe Flash** (Click link độc hại qua email)

 | `2022-07-19` `13:12`–`13:40` (Attack: `13:26`)

 |
| **s2** | Malvertising dominate (Exploit Kits)

 | CVE-2015-3105

 | **Adobe Flash** (Click link độc hại qua email)

 | `2022-07-19` `13:45`–`14:20` (Attack: `14:07`)

 |
| **s3** | Spam campaign (Australia/Japan)

 | CVE-2017-11882

 | **MS Word** (Tải file đính kèm `s3take2.zip`)

 | `2022-07-19` `14:20`–`15:05` (Attack: `15:36`*)

 |
| **s4** | Pony campaign (HTA Handler)

 | CVE-2017-0199

 | **MS Word** (Tải file đính kèm `s4-at-night.zip`)

 | `2022-07-20` `00:31`–`01:00` (Attack: `00:52`)

 |
| **m1** | Strategic web compromise + Lateral Movement

 | CVE-2015-5122

 | **Adobe Flash** (Click link) $\rightarrow$ Ghi đè HTTP `h1` $\rightarrow$ `h2`

 | `2022-07-19` `16:00`–`17:50` (Attack: `17:20`)

 |
| **m2** | Targeted GOV phishing (HackingTeam)

 | CVE-2015-5119

 | **Adobe Flash** (Click link) $\rightarrow$ Ghi đè HTTP `h1` $\rightarrow$ `h2`

 | `2022-07-19` `19:32`–`20:02` (Attack: `19:44`)

 |
| **m3** | Malvertising dominate + Lateral Movement

 | CVE-2015-3105

 | **Adobe Flash** (Click link) $\rightarrow$ Ghi đè HTTP `h1` $\rightarrow$ `h2`

 | `2022-07-19` `20:06`–`20:40` (Attack: `20:28`)

 |
| **m4** | Monero miner by Rig Exploit Kit

 | CVE-2018-8174

 | **MS Word / VBScript** (Link/File `m4.zip`) $\rightarrow$ `h2`

 | `2022-07-19` `22:31`–`23:04` (Attack: `22:49`)

 |
| **m5** | Pony campaign + Lateral Movement

 | CVE-2017-0199

 | **MS Word** (File `m5-2.zip` / `msf.doc`) $\rightarrow$ `h2`

 | `2022-07-19` `23:16`–`23:46` (Attack: `23:38`)

 |
| **m6** | Spam campaign + Lateral Movement

 | CVE-2017-11882

 | **MS Word** (File đính kèm `m6.zip`) $\rightarrow$ `h2`

 | `2022-07-19` `23:54`–`00:27` (Attack: `00:10`)

 |

(Lưu ý: Ở kịch bản `s3`, bảng báo cáo của ATLASv2 ghi nhận mốc Initial Attack Step là `15:36:00` do lần chạy lại `s3take2.zip`).

---

### 4. Cách thức gán nhãn Ground Truth và Các lưu ý quan trọng từ Repo thực tế

Qua kiểm chứng cấu trúc kho lưu trữ `bitbucket.org/sts-lab/atlasv2` và bộ nhãn `bitbucket.org/sts-lab/reapr-ground-truth` (thuộc dự án chuẩn hóa nhãn REAPr và nghiên cứu đánh giá chất lượng dataset của nhóm STS-Lab tại UIUC):

1. **Cách lưu trữ Ground Truth (Nhãn thực tế):**

* **Nhãn mức sự kiện (Event-level):** Được đặt tại đường dẫn `/atlasv2/data/attack/h*/msft-security/groundtruth/`. Mỗi tệp tương ứng với một kịch bản tấn công và chứa danh sách các mã `EventRecordID` độc hại ánh xạ trực tiếp tới tệp XML nhật ký bảo mật Windows (`msft-security-*-*.xml`) của máy đó.
* **Nhãn mức thực thể (Entity-level):** Các thực thể độc hại cốt lõi (Indicators of Compromise) được xác định trước gồm tên miền `ortrta.net`, tiến trình `payload.exe`, địa chỉ C&C `10.193.66.115:9999`, `10.193.66.115:8443`, và các tệp nén chứa mẫu khai thác (`s3take2.zip`, `s4-at-night.zip`, `m4.zip`, `m5-2.zip`, `m6.zip`).
* **Nhãn mức tiến trình (Process-level - REAPr):** Do log của Carbon Black EDR và Windows có cách biểu diễn tiến trình khác nhau, nhóm tác giả cung cấp thêm bộ nhãn chuẩn hóa cho toàn bộ các tiến trình bị kiểm soát bởi kẻ tấn công (attacker-controlled processes) trong repo `reapr-ground-truth` để phục vụ các bài toán phát hiện xâm nhập dựa trên đồ thị nguồn gốc (Provenance-based IDS).

2. **Hai điểm hạn chế kỹ thuật của ATLASv2 cần lưu ý khi huấn luyện mô hình:**

* **Sự trùng lặp ở giai đoạn hậu khai thác (Post-exploitation overlap):** Mặc dù bước xâm nhập đầu tiên (Bước 2) sử dụng các CVE và phương thức khác nhau (Adobe Flash hoặc MS Word), nhưng từ Bước 3 trở đi (mở Meterpreter shell, thả và chạy cùng một tệp `payload.exe` để gom file PDF), các kịch bản đều thực hiện giống hệt nhau. Do đó, nhật ký hệ thống sinh ra ở nửa sau cuộc tấn công có độ tương đồng rất cao giữa cả 10 kịch bản (không phù hợp cho bài toán phân loại đa lớp - *multi-class supervised learning* để phân biệt các loại mã độc khác nhau).
* **Dấu vết khởi động máy ảo (VM Startup Footprint):** Vì mỗi kịch bản trong số 10 kịch bản được chạy bằng cách khôi phục lại từ một bản **snapshot** khác nhau của máy ảo Windows 7, nên ở đầu mỗi tệp log tấn công đều xuất hiện chuỗi sự kiện khởi động máy ảo (startup footprint) lặp đi lặp lại. Khi sử dụng ATLASv2 để huấn luyện hoặc đánh giá các thuật toán phát hiện bất thường (anomaly detection), cần lọc bỏ hoặc tính đến chuỗi khởi động này để tránh việc mô hình học nhầm dấu hiệu bật máy ảo thành dấu hiệu bắt đầu cuộc tấn công.
