## Các file liên kết như thế nào

`conn.log` với **29,311 Connection UIDs độc hại**.

1. **Với các file chứa trường `uid` (Application Logs)**:

   * Bao gồm: `conn.log`, `http.log`, `dns.log`, `ssl.log`, `rdp.log`, `smb_files.log`, `smb_mapping.log`, `dce_rpc.log`, `ntlm.log`, `smtp.log`, `ssh.log`, `weird.log`, `dpd.log`.
2. **Với các file chứa trường `conn_uids` (`files.log`)**:

   * Khi một tệp (mã độc, web page, script) được truyền qua mạng, Zeek lưu danh sách các UID kết nối trong cột `conn_uids` (dạng danh sách cách nhau bởi dấu phẩy).
   * **Cách xử lý:** Script tự động tách chuỗi UID và kiểm tra: nếu bất kỳ `uid` nào nằm trong tập kết nối độc hại, dòng file đó trong `files.log` sẽ được gán `label: 1`.
3. **Với các file hệ thống / không có `uid`**:

   * Bao gồm: `loaded_scripts.log`, `packet_filter.log`, `communication.log`, `reporter.log`, `nema_fileless.log`, `conn-summary.log`

   ## Phân tích chi tiết về **ý nghĩa của từng loại file** và **cách chúng bổ sung thông tin cho `conn.log.gz`**.

   `conn.log.gz` (Connection Log) là **trọng tâm và là file log nền tảng nhất** của Bro:


   * **Tầng hoạt động:** Tầng Mạng & Vận chuyển (L3 / L4 - TCP, UDP, ICMP).
   * **Nội dung:** Ghi nhận metadata tổng quát của mỗi phiên kết nối mạng, bao gồm:
     * `uid`: Mã định danh duy nhất của kết nối (Unique Connection Identifier, ví dụ: `CgoxTv4J01jh656LQ8`).
     * `id.orig_h`, `id.orig_p`: Địa chỉ IP nguồn và cổng nguồn (Source IP / Port).
     * `id.resp_h`, `id.resp_p`: Địa chỉ IP đích và cổng đích (Destination IP / Port).
     * `proto`, `service`: Giao thức (tcp, udp, icmp) và dịch vụ ứng dụng nhận diện được (http, ssl, dns, ...).
     * `duration`: Thời lượng phiên kết nối (tính bằng giây).
     * `orig_bytes`, `resp_bytes`: Số lượng byte dữ liệu gửi đi và nhận về.
     * `conn_state`: Trạng thái kết thúc của kết nối TCP (như `SF` - thành công đóng phiên bình thường, `S0` - chỉ gửi SYN không thấy trả lời, `RSTO` - bị reset từ phía gửi,...).
     * `orig_pkts`, `resp_pkts`: Số gói tin trao đổi 2 chiều.

   > **Hạn chế của `conn.log`:** `conn.log` chỉ trả lời câu hỏi: *"Ai kết nối tới ai, lúc nào, qua cổng nào, chuyển bao nhiêu byte?"*. Nó **hoàn toàn không biết nội dung ứng dụng bên trong (L7 payload)** là gì (ví dụ: truy cập trang web nào, gọi hàm RPC gì, tải file tên gì, chứng chỉ bảo mật nào,...).
   >

   ---

   ### Các loại file log khác là gì?

   Các file log khác được chia thành 4 nhóm chính:

   #### Nhóm 1: Giao thức ứng dụng tầng L7 (Application-Layer Protocol Logs)

   Tất cả các log này đều chứa trường **`uid`** trùng khớp với `uid` trong `conn.log`, giúp liên kết ngữ cảnh chi tiết:

   1. **`http.log.gz`**: Ghi lại chi tiết các giao dịch web không mã hóa (HTTP).
      * *Thông tin:* URL/URI truy cập (`/data/skins/...`), phương thức (`GET`, `POST`), `host` (`www.cnooc.com.cn`), `user_agent`, mã phản hồi `status_code` (`200`, `404`), dung lượng request/response body, danh sách mã hash file tải về (`orig_fuids`, `resp_fuids`).
   2. **`dns.log.gz`**: Ghi lại các truy vấn phân giải tên miền.
      * *Thông tin:* Tên miền được hỏi `query` (`www.centosweb04.systemia.com`), loại bản ghi `qtype_name` (`A`, `AAAA`, `PTR`), mã trả lời `rcode_name` (`NOERROR`, `NXDOMAIN`), và các địa chỉ IP được giải đáp (`answers`).
   3. **`ssl.log.gz`**: Ghi lại quá trình bắt tay bảo mật SSL/TLS (HTTPS).
      * *Thông tin:* Phiên bản TLS (`TLSv12`), bộ mã hóa (`cipher`), tên máy chủ trong SNI `server_name` (`www.sis.gov.uk`), trạng thái phiên (`established`), và danh sách ID chứng chỉ số (`cert_chain_fuids`).
   4. **`rdp.log.gz`**: Ghi lại các phiên điều khiển máy tính từ xa (Remote Desktop Protocol).
      * *Thông tin:* Phiên bản client RDP, bố cục bàn phím (`keyboard_layout`), độ phân giải màn hình (`desktop_width`, `desktop_height`), thuật toán mã hóa, giao thức bảo mật (`HYBRID`, `SSL`).
   5. **`smb_files.log.gz` & `smb_mapping.log.gz`**: Ghi lại các hoạt động chia sẻ tệp nội bộ Windows (Server Message Block / NetBIOS).
      * *Thông tin:* Đường dẫn chia sẻ mạng (`\\142.20.56.124\ADMIN$`, `\\IPC$`), tên file mở/đọc/ghi, quyền truy cập, thời gian chỉnh sửa tệp (`times.modified`).
   6. **`dce_rpc.log.gz`**: Ghi lại các lời gọi hàm từ xa (Distributed Computing Environment / Remote Procedure Call) trong môi trường Windows Domain.
      * *Thông tin:* Named pipe (`\PIPE\srvsvc`), endpoint giao tiếp, thao tác thực thi (`operation` như `NetrShareEnum`).
   7. **`ntlm.log.gz`**: Ghi lại quá trình xác thực mật khẩu NTLM qua mạng.
      * *Thông tin:* Tài khoản người dùng (`username`), tên máy khách (`hostname`), tên miền (`domainname`), kết quả xác thực.
   8. **`smtp.log.gz`**: Ghi lại các phiên gửi nhận email (Simple Mail Transfer Protocol).
      * *Thông tin:* Tên miền HELO, người gửi `mailfrom`, người nhận `rcptto`, tiêu đề thư `subject`, message ID, phản hồi của SMTP server.
   9. **`ssh.log.gz`**: Ghi lại thông số kết nối SSH (Secure Shell).
      * *Thông tin:* Phiên bản client/server banner (`PuTTY_Release_0.63`, `OpenSSH`), thuật toán mã hóa `cipher_alg`, xác thực thành công hay thất bại.

   ---

   #### Nhóm 2: Tệp tin truyền qua mạng & Chứng chỉ số (File & PKI Analysis)

   Liên kết thông qua trường **`fuid`** (File Unique Identifier) và liên kết ngược về `conn_uids`:

   10. **`files.log.gz`**: Quản lý toàn bộ tệp/dòng dữ liệu truyền tải qua các giao thức (HTTP, SMTP, SMB, v.v.).
       * *Thông tin:* Loại MIME (`text/html`, `application/x-dosexec`), kích thước file, mã băm mật mã toàn vẹn (**`md5`**, **`sha1`**, **`sha256`**), trạng thái trích xuất.
   11. **`x509.log.gz`**: Phân tích chi tiết chứng chỉ số X.509 trao đổi trong các kết nối SSL/TLS.
       * *Thông tin:* Chủ thể chứng chỉ `certificate.subject` (`CN=www.systemia.com`), đơn vị cấp phát `certificate.issuer` (`CN=rootCA`), thời hạn hiệu lực (`not_valid_before`, `not_valid_after`), danh sách tên miền phụ SAN (`san.dns`).

   ---

   #### Nhóm 3: Cảnh báo bất thường & Phân tích chuyên sâu (Detection & Anomaly)

   12. **`weird.log.gz`**: Ghi lại các hành vi bất thường, sai lệch chuẩn RFC hoặc khả nghi trong luồng mạng (ví dụ: `unknown_HTTP_method`, `dns_unmatched_msg`, gói tin TCP gửi cờ bất thường).
   13. **`dpd.log.gz`** (Dynamic Protocol Detection): Ghi nhận các lỗi khi giải mã giao thức động (ví dụ: lưu lượng chạy trên port nhưng định dạng gói tin không khớp với giao thức chuẩn).
   14. **`nema_fileless.log.gz`**: Log thống kê bộ phân tích tệp không lưu vết (fileless / NEMA analyzer) của DARPA TC, đếm số lượng mã HTML, Javascript, WebAssembly được nạp.

   ---

   #### Nhóm 4: Quản trị & Hoạt động của hệ thống Bro (System & Engine Management)

   15. **`conn-summary.log.gz`**: Bảng tổng kết thống kê định kỳ (Top ports, top Services, top IPs, phân phối băng thông).
   16. **`reporter.log.gz`**: Log ghi nhận thông báo, cảnh báo lỗi nội bộ của tiến trình Bro.
   17. **`loaded_scripts.log.gz`**: Danh sách tất cả các script chính sách (`.bro`) được Bro nạp vào bộ nhớ lúc khởi động.
   18. **`communication.log.gz`**: Log giao tiếp nội bộ giữa các nút trong cụm Bro (giữa logger, manager và worker).
   19. **`packet_filter.log.gz`**: Bộ lọc gói tin mức nhân (BPF filter) được áp dụng trên card mạng.
   20. **`stdout.log.gz` / `stderr.log.gz`**: Luồng đầu ra tiêu chuẩn và lỗi của tiến trình Bro.

   ---

   ### 4. Các file khác bổ sung thông tin gì cho `conn.log.gz`?

   ```
   [conn.log] (L4 Flow: IP, Port, Bytes, Duration, State)
        │
        │ (khóa ngoại: uid)
        ├──► [http.log]       --> URI, Method, User-Agent, Status Code
        ├──► [dns.log]        --> Domain Query (sports.com), Resolved IPs
        ├──► [ssl.log]        --> SNI Server Name, TLS Cipher
        │         │ (khóa: cert_chain_fuids)
        │         └──► [x509.log]  --> Certificate Issuer, Subject, SAN
        ├──► [smb_files.log]  --> Remote File Operations, Admin Share (ADMIN$)
        ├──► [dce_rpc.log]    --> Remote RPC Call (NetrShareEnum)
        ├──► [rdp.log]        --> RDP Session, Screen Resolution, Keyboard
        └──► [weird.log]      --> Protocol Anomalies, Evasion Techniques
        │
        │ (khóa ngoại: conn_uids / fuid)
        └──► [files.log]      --> MD5/SHA256, MIME Type, Payload Extracted
   ```

   #### Cụ thể các giá trị bổ sung then chốt:

   1. **Phân biệt lưu lượng độc hại C2 và lưu lượng thông thường (Disambiguate C&C vs Benign Traffic):**

      * *Trong bài báo "A New Hope for DARPA OpTC" (Mục 4.1):* Red Team đã sử dụng các tên miền công cộng phổ biến như `sports.com` hoặc `news.com` để làm máy chủ C&C.
      * Nếu chỉ nhìn vào `conn.log`, bạn chỉ thấy kết nối TCP Port 80/443. Nhưng khi ghép nối với `dns.log` (xem domain), `http.log` (xem URI, User-Agent) và `ssl.log` (xem SNI), các tác giả mới xác định được chính xác đâu là kết nối bình thường của người dùng và đâu là kết nối mã độc C2/Beaconing.
   2. **Truy vết tải mã độc (Malware Payload Delivery Tracking):**

      * Khi kẻ tấn công tải mã độc (ví dụ: Meterpreter DLL trong Scenario 3), `conn.log` chỉ thấy một lượng byte tải về. `files.log` (thông qua `conn_uids` và `fuid`) cung cấp mã băm **MD5, SHA256** và **MIME type** để xác minh file thực thi đã được đưa vào hệ thống.
   3. **Truy vết di chuyển ngang và leo thang đặc quyền (Lateral Movement & PrivEsc):**

      * Các cuộc tấn công APT luôn có bước do thám và di chuyển ngang giữa các máy trong mạng. Các file `smb_files.log`, `smb_mapping.log`, `dce_rpc.log`, `ntlm.log`, `rdp.log` cung cấp chính xác tài khoản nào (`username`), đã gọi lệnh RPC nào, truy cập share quản trị nào (`ADMIN$`, `IPC$`) hoặc mở phiên RDP trái phép nào.
   4. **Tương quan toàn diện giữa Host và Network (Cross-layer Provenance Graph):**

      * Theo bài báo *Analyzing the Usefulness of the DARPA OpTC Dataset...* (Mục 3.3.1) và *A New Hope...*: Trong thư mục `ecar-bro/`, các sự kiện mạng ở Host (`FLOW-START`) chứa `bro-id` liên kết trực tiếp với `uid` của Bro.
      * Nhờ các file chi tiết (`http.log`, `dns.log`, `files.log`), có thể xây dựng đồ thị quan hệ hoàn chỉnh:

        ```math
        \text{Process (Host eCAR)}
        \longrightarrow \text{FLOW-START}
        \longrightarrow \text{conn.log (Network)}
        \longrightarrow \text{http.log / dns.log / files.log}
        ```

        từ đó biết chính xác tiến trình nào (PID), người dùng nào đã sinh ra gói tin mạng đó và thực hiện hành vi gì ra Internet.

## Mức độ đầy đủ của các loại log trong các ngày

Không có ngày nào có đủ cả 23 loại.

- 05/09/2019 thiếu: `conn.log`, `conn-summary.log`, `dce_rpc.log`, `dns.log`, `dpd.log`, `files.log`, `http.log`, `nema_fileless.log`, `ntlm.log`, `rdp.log`, `smb_files.log`, `smb_mapping.log`, `smtp.log`, `ssh.log`, `ssl.log`, `weird.log`, `x509.log`.
- 12–13/09/2019 thiếu: `dce_rpc.log`, `dpd.log`, `ntlm.log`, `rdp.log`, `smb_files.log`, `smb_mapping.log`, `ssh.log`.
- 14–15/09/2019 thiếu: `dce_rpc.log`, `dpd.log`, `loaded_scripts.log`, `ntlm.log`, `packet_filter.log`, `rdp.log`, `smb_files.log`, `smb_mapping.log`, `smtp.log`, `ssh.log`, `stderr.log`, `stdout.log`.
- 16–19, 21–23/09/2019 thiếu: `dce_rpc.log`, `dpd.log`, `loaded_scripts.log`, `ntlm.log`, `packet_filter.log`, `rdp.log`, `smb_files.log`, `smb_mapping.log`, `ssh.log`, `stderr.log`, `stdout.log`.
- 20/09/2019 thiếu: `loaded_scripts.log`, `packet_filter.log`, `rdp.log`, `ssh.log`, `stderr.log`, `stdout.log`.
- 24/09/2019 thiếu: `dce_rpc.log`, `dpd.log`, `loaded_scripts.log`, `ntlm.log`, `packet_filter.log`, `rdp.log`, `smb_files.log`, `smb_mapping.log`, `stderr.log`, `stdout.log`.
- 25/09/2019 thiếu: `dce_rpc.log`, `dpd.log`, `loaded_scripts.log`, `ntlm.log`, `packet_filter.log`, `smb_files.log`, `smb_mapping.log`, `ssh.log`, `stderr.log`, `stdout.log`.
