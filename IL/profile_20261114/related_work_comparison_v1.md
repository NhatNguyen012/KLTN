# So sánh với các công trình liên quan và chi phí tính toán (14/11/2026)

Tài liệu phục vụ chương "Related work / So sánh" của luận văn. Số của các công trình khác được đọc từ chính bài báo. Ô ghi *(suy ra)* là số tôi tự tính từ số họ công bố, *(chưa kiểm)* là chưa đọc được bản gốc.
Số của mình lấy từ `IL/README.md`. Chi phí tính toán được đo lại ngày 14/11 trong `IL/profile_20261114/`, mỗi cấu hình 1 seed, chạy một mình trên máy.

## 0. Phần cứng và chi phí của mình (đo thật)

Máy: laptop RTX 3050 Laptop 4 GB, i5-11400H (12 luồng), RAM 32 GB.

| | Train | Bộ nhớ khi train | Suy luận | Kích thước model |
|---|---|---|---|---|
| DL bước 1 (BiLSTM OpTC) | 5 epoch, khoảng 18 phút trên GPU Kaggle, có AMP (lấy từ `history.csv`) | — | — | 78.698 tham số, 315 KB |
| DL bước 2 (IL ATLASv2) | **2 phút 14 giây** (20 epoch, gồm cả đánh giá OpTC) | VRAM tối đa 983 MiB (máy nghỉ đã dùng 168 MiB), RSS 2,8 GB | — | — |
| DL bước 3 (IL SL700) | **4 phút 10 giây** (20 epoch) | VRAM tối đa 1,3 GB, RSS 5,8 GB | GPU: 1,4 triệu sự kiện/s (0,26 ms/cửa sổ); CPU 6 luồng: 215 nghìn sự kiện/s (1,7 ms/cửa sổ). Trên OpTC TEST: 2,0 triệu flow/s (GPU), 295 nghìn flow/s (CPU) | 282.521 tham số, 1,1 MB |
| ML bước 1 (LightGBM OpTC) | không có log thời gian | — | — | 300 cây, 1,3 MB |
| ML bước 2 | **2,5 giây** trên CPU 12 luồng, 144.564 dòng gồm cả replay | — | — | +300 cây, 1,3 MB |
| ML bước 3 | **17 giây** cho cả lần chạy (load, train, đánh giá 3 miền), CPU, không dùng GPU | RSS 3,3 GB | 40 nghìn sự kiện/s với 1 luồng (25 µs/sự kiện); 215 nghìn sự kiện/s với 10 luồng (cả 3 booster) | tổng 3 booster ≈ 4,1 MB |

Lần chạy lại DL bước 3 với seed 42 cho SL700 F1 0,976. Bản đã công bố cùng seed là 0,973, vì GPU không tất định. ML tái hiện đúng tuyệt đối.

## 1. Bước 1: OpTC

| Công trình | Đơn vị chấm, cách chia | Kết quả | Tài nguyên |
|---|---|---|---|
| **Của mình, DL** | cửa sổ 15 phút theo host; **chia ngẫu nhiên theo cửa sổ**; có giám sát | F1 0,988 (P 1,0, R 0,976; 80/82 dương, 0 FP) | 18 phút trên GPU Kaggle, 79 nghìn tham số |
| **Của mình, ML** | sự kiện host; chia ngẫu nhiên theo sự kiện | F1 0,996 | CPU |
| Kairos (S&P'24) | cửa sổ 15 phút; train ngày benign, test 3 ngày tấn công; không giám sát | P 0,579, R 1,0, AUC 0,993 → F1 ≈ 0,73 *(suy ra)*; bản "adjusted" (FP được bỏ thủ công) P 0,842 → F1 ≈ 0,91 *(suy ra)* | Xeon 20 nhân, RAM 64 GB; mỗi cửa sổ trung vị 19,8 s; train 229 phút (MADELINE đo lại) |
| MADELINE (ACSAC'24) | cửa sổ theo host (10k sự kiện) | recall 0,996, FPR 0,011 | i7-11700K, RTX 3090; train 48 s, dự đoán 4 s |
| FLASH (S&P'24) | node (tính cả lân cận 2 bước) | F1 0,91 / 0,93 / 0,92 trên 3 ngày tấn công | RTX 2080, RAM 80 GB |
| Euler (NDSS'22) | cạnh flow giữa các host (lateral movement) | AUC 0,995, AP 0,984, FPR 0,012 % | 2 Xeon, RAM 512 GB; train 154–1.085 s |
| Argus (S&P'24) | cạnh flow | AP 0,807, AUC 0,997 | RTX 3090 24 GB, RAM 256 GB |
| Bilot et al. / Velox (USENIX Sec'25) | node, chia theo thời gian, nhãn kiểu Orthrus | ADP 0,39–0,90; precision tốt nhất của Kairos/Orthrus chỉ 0,2–1,0 | A100 80 GB, RAM 1 TB; chuẩn triển khai họ trích là ≤ 160 MB RAM |
| DeepTaskAPT (2021) | chuỗi tác vụ, LSTM 2 lớp | accuracy 0,985, FPR 0,011 | laptop i7-10750H |

**Đánh giá:** về con số, mình cao hơn hoặc ngang các công trình trên. Tuy vậy không được ghi "vượt SOTA" vì ba lẽ:
1. Mình có giám sát. Kairos, MADELINE, Velox chỉ học dữ liệu benign.
2. **Model OpTC gốc chia ngẫu nhiên theo cửa sổ hoặc sự kiện**, nên TRAIN và TEST lấy từ cùng ngày và cùng đợt tấn công. Các công trình khác chia theo thời gian. Đây là điểm yếu dễ bị hỏi nhất khi bảo vệ. Nên ghi rõ, hoặc chạy thêm một bản chia theo ngày nếu còn thời gian.
3. Đơn vị chấm khác nhau. Chỉ Kairos và MADELINE cùng mức cửa sổ theo host như DL của mình.

**Về tài nguyên**, đây là lợi thế rõ: 79 nghìn tham số, train vài phút, chạy được trên laptop 4 GB VRAM. Các GNN như Kairos, Orthrus, Argus cần GPU 24–80 GB hoặc RAM 64 GB–1 TB, và Kairos train mất 229 phút. MADELINE (48 s) là tiền lệ gần nhất về chi phí thấp, nên được trích.

## 2. Bước 2: OpTC → ATLASv2

| Công trình | Dữ liệu, đơn vị | Kết quả | Tài nguyên |
|---|---|---|---|
| **Của mình, DL IL** | ATLASv2, cửa sổ 180 s; chia theo kịch bản (test S4, M6 + ngày benign 4); nhãn v9b | F1 0,990 ± 0,014; OpTC 0,988 → 0,994 (không quên) | **2 phút 14 giây**, VRAM < 1 GB |
| **Của mình, ML IL** | ATLASv2, sự kiện | F1 0,959; OpTC 0,996 → 0,991 | **2,5 giây** trên CPU |
| Guerra et al. (arXiv 2608.01454, 2026) | **ATLASv2**, process, chia theo thời gian, nhãn REAPr | F1 tốt nhất: allowlist 0,364 / 0,462 (h1/h2); Theseus 0,17 / 0,27; Velox 0 | GPU L40S/A100, RAM 80–128 GB |
| SHIELD (arXiv 2507.10873) | **ATLASv2**, sự kiện | precision TB 0,957; AirTag chạy lại trên v2 chỉ còn precision 0,446 | A6000, RAM 768 GB + LLM 671B qua API |
| ORCHID (arXiv 2408.13347) | **ATLASv2**, process | khoảng 89 % TPR khi FPR gần 0 | GRU streaming 0,002 s/sự kiện, 2,7 GB (đo trên E3) |
| ATLAS (USENIX Sec'21) | **ATLAS v1**, entity; leave-one-attack-out; cần analyst cho điểm xuất phát | F1 entity 0,938; F1 event 0,999 | **58 phút 49 giây mỗi model**, laptop không rõ cấu hình |
| DeepDist (TrustCom'23, PDF trong `analyst/`) | **ATLAS v1**, entity | P 0,949, R 0,947, F1 0,947 | Tesla V100 32 GB, RAM 128 GB |
| APT-LMSPS (MDPI Information 2026, PDF trong `analyst/`) | ATLAS v1 + DARPA TC + StreamSpot | F1 ≥ 0,98 (số ATLAS chỉ có trong hình) | RTX 3080 16 GB, RAM 300 GB; dùng 52 GB → < 10 GB; 70.635 cạnh/s |
| AirTag (USENIX Sec'23) | ATLAS v1, dòng log | TPR 99,8 %, FPR 6,2 % | RTX 6000, RAM 376 GB |
| ATLASv2 (dataset paper) | — | **không có baseline**; cảnh báo "startup footprint" lặp lại ở mọi log tấn công | — |

**Đánh giá:**
- **Trên ATLASv2**, công trình chia theo thời gian đã công bố mới đạt F1 tối đa khoảng 0,46 (Guerra). Số của mình (0,96–0,99) cao hơn nhiều, nhưng không so trực tiếp được vì:
  - mình có giám sát;
  - mình chia theo kịch bản;
  - nhãn v9b do mình tinh chỉnh. Với nhãn gốc, BiLSTM đơn chỉ đạt 0,64.
- Nên viết rằng *phân tích nhãn* (endpoint benign như captive portal Firefox, mốc bắt đầu tấn công muộn) là một đóng góp. Nó giải thích vì sao các phương pháp trên ATLASv2 có F1 thấp.
- Các số 0,94–0,98 của ATLAS, DeepDist, APT-LMSPS là trên **ATLAS v1**, một dataset khác. Chỉ đưa vào bảng tham khảo, ghi rõ "v1".
- **Về tài nguyên:** ATLAS mất gần 1 giờ train mỗi model, DeepDist cần V100 32 GB, APT-LMSPS cần RAM 300 GB, SHIELD cần LLM 671B. Mình chỉ cần 2 phút (DL) hoặc 2,5 giây (ML) trên laptop, **và không phải train lại từ đầu**: chỉ học thêm phần mới và giữ được OpTC.

## 3. Bước 3: OpTC → ATLASv2 → AInception SL700

**Không có công trình nào công bố kết quả phát hiện trên AInception hoặc SL700.**
- Dataset chỉ có trên Zenodo (AInception Consortium, 11/2025, DOI 10.5281/zenodo.17659656), chưa có bài báo bình duyệt.
- PDF đi kèm ghi rằng nhãn từng sự kiện "không hoàn toàn tin cậy" và khuyên dùng `attackmate.json`. Mình đã dựng lại nhãn từ attack log cộng cây tiến trình (relabel_v3). Nên trích câu này để biện minh cho relabel.
- AIT-LDS v2 (TDSC 2022), dataset cùng nhóm tác giả, cũng không có kết quả phát hiện.

Vì vậy, ở bước này mình so với **baseline tự dựng**. Đây là cách làm chuẩn khi dataset mới:

| Cấu hình (TEST f_a) | DL (cửa sổ) | ML (sự kiện / cửa sổ) |
|---|---|---|
| Model cũ chạy thẳng, không học thêm | — | 0,799 / 0,540 |
| Train từ đầu, cùng kiến trúc | SL700 1,000 nhưng ATLASv2 0,03, OpTC 0,00 | 0,995, nhưng mất 2 miền cũ |
| IL không replay | ATLASv2 0,810 (quên) | ATLASv2 0,741 (quên) |
| **IL + replay (chính)** | **0,978 ± 0,004**; ATLASv2 0,970, OpTC 0,994 | **0,995 / 0,883**; ATLASv2 0,953, OpTC 0,994 |
| Thêm phạm vi địa chỉ (báo cáo riêng) | 0,999 | 0,997 / 0,966 |

Có thể bổ sung, nếu còn thời gian: chấm điểm cảnh báo của **AMiner/Telosian** (có sẵn trong dataset) bằng cùng nhãn của mình. Đó sẽ là baseline bên ngoài duy nhất có thể so cùng điều kiện.

**Tài nguyên bước 3:** DL 4 phút 10 giây trên GPU (VRAM tối đa 1,3 GB); ML 17 giây trên CPU. Suy luận DL đạt 1,4 triệu sự kiện/s trên GPU và 215 nghìn/s trên CPU; ML đạt 40 nghìn sự kiện/s với một luồng. Để đặt cạnh: Velox khoảng 2.400 cạnh/s, Kairos khoảng 11 nghìn cạnh/s, APT-LMSPS 70.635 cạnh/s trên RTX 3080. Đơn vị cạnh và sự kiện không hoàn toàn giống nhau, nên ghi là "cùng bậc độ lớn" chứ không ghi "nhanh hơn x lần".

## 4. Học tăng dần (vị trí của đóng góp IL)

| Công trình | Bối cảnh | Kết luận liên quan |
|---|---|---|
| Rahman et al. (CoLLAs'22) | malware, EMBER domain-IL 12 tháng | các phương pháp CL không replay thua; **replay 1 % dữ liệu** đạt 93,9 so với joint 95,9 → khớp với kết quả mình: replay là thứ chống quên |
| Tidal (NINeS'26) | provenance DARPA E3 → E5 | giữ E3: P 0,85, R 0,94; Kairos 0,64 / 0,85; Flash 0,57 / 0,90; A100, 2,1 s/đầu vào |
| METANOIA (arXiv 2501.00438) | IDS provenance học suốt đời, E3/E5 | P/R cửa sổ 0,43 / 0,95; 134,6 s/cửa sổ; không đo quên |
| Amalapuram et al. (NeurIPS'23), QCL-IDS | NIDS, các task **trong cùng một dataset** | forgetting 0,004–0,005 |

**Khoảng trống để nêu, ghi "theo hiểu biết của chúng tôi":** chưa thấy công trình nào học tăng dần qua **các dataset host khác hệ điều hành, khác cảm biến và khác cách gán nhãn** (eCAR Windows → Carbon Black EDR → auditd Linux) và báo cáo cả backward transfer.

Backward transfer của mình:

| | DL | ML |
|---|---|---|
| OpTC qua 2 bước | +0,006 | −0,002 |
| ATLASv2 qua bước 3 | −0,020 | −0,006 |

## 5. Chỗ mình thấp hơn hoặc yếu hơn, và cách trình bày

| Điểm yếu | Cách viết |
|---|---|
| Không có chuyển giao xuôi: train từ đầu ngang IL trên miền mới | Giá trị của IL là *một model giữ cả 3 miền* với chi phí vài phút. Train từ đầu thì mất hẳn miền cũ (ATLASv2 0,03; OpTC 0,00). |
| ML theo cửa sổ trên SL700 chỉ đạt 0,883 (DL 0,978) | ML chấm từng sự kiện; quy về cửa sổ là phép chuyển đổi để so. Bù lại, ML train 17 s, chỉ dùng CPU và tất định. |
| Biến thể chưa thấy (fold e_a, persistence bằng cron): DL 0,74–0,83 | Đây là giới hạn khái quát. LightGBM cùng token cũng chỉ đạt 0,81–0,91, nên giới hạn nằm ở dữ liệu chứ không ở model. |
| DL bước 3 làm ATLASv2 giảm 0,02 | Vẫn ≥ 0,97. Không replay thì giảm còn 0,81. |
| Bước 1 chia ngẫu nhiên | Ghi rõ ở phần threats to validity. |
| TEST SL700 chỉ có 1 run | Báo cáo thêm leave-one-run-out: LightGBM 0,945. |

## 6. Gợi ý một bảng tổng hợp cho luận văn

| | Mình (DL) | Mình (ML) | Đại diện SOTA |
|---|---|---|---|
| OpTC | F1 0,988 · 18 phút · 79 nghìn tham số | F1 0,996 · CPU | Kairos F1 ≈ 0,73 (0,91 adjusted) · 229 phút · RAM 64 GB; FLASH F1 0,91–0,93 · RTX 2080 + RAM 80 GB |
| + ATLASv2 | F1 0,990, OpTC giữ 0,994 · 2,2 phút · < 1 GB VRAM | F1 0,959 · 2,5 s CPU | trên v2: F1 ≤ 0,46 (Guerra, chia theo thời gian, không giám sát); trên v1: ATLAS F1 0,938 · 59 phút/model |
| + SL700 | F1 0,978, giữ ATLASv2 0,970, OpTC 0,994 · 4,2 phút · 1,3 GB VRAM | F1 0,995 sự kiện · 17 s CPU | chưa có công bố |

Nguồn: Kairos arXiv 2308.05034; FLASH dartlab.org/assets/pdf/flash.pdf; Euler par.nsf.gov/servlets/purl/10440905; Argus S&P'24; Bilot et al. USENIX Sec'25; MADELINE ACSAC'24; DeepTaskAPT arXiv 2108.13989; ATLASv2 arXiv 2401.01341; ATLAS USENIX Sec'21; AirTag USENIX Sec'23; Guerra et al. arXiv 2608.01454; SHIELD arXiv 2507.10873; ORCHID arXiv 2408.13347; AInception zenodo.org/records/17659656; AIT-LDS v2 arXiv 2203.08580; Rahman et al. arXiv 2208.06568; Amalapuram et al. NeurIPS'23; QCL-IDS arXiv 2601.21318; Tidal NINeS'26; METANOIA arXiv 2501.00438.
