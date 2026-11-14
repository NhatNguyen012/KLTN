# So sánh với các công trình liên quan, theo nhóm phương pháp, và chi phí tính toán (14/11/2026, bản 2)

Tài liệu phục vụ chương Related work / So sánh của luận văn. Số của các công trình khác được đọc từ bài báo, slide hoặc luận văn gốc; *(suy ra)* là số tự tính, *(chưa kiểm)* là chưa đọc được bản gốc. Số của mình lấy từ `IL/README.md`. Chi phí đo lại ngày 14/11 trong `IL/profile_20261114/`.

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

## 1. Cách phân nhóm

| Nhóm | Định nghĩa trong tài liệu này | Mình thuộc nhóm |
|---|---|---|
| R. Rule / heuristic / signature | luật viết tay, allowlist, chữ ký, tương quan IOC; không học | — (REAPr và relabel_v3 là luật, nhưng mình chỉ dùng để **gán nhãn**) |
| U. Không giám sát / bán giám sát | chỉ học dữ liệu benign hoặc học tự giám sát rồi chấm bất thường; nhiều nhất là GNN trên provenance graph | — |
| S-DL. Có giám sát, deep learning | học từ nhãn tấn công/benign; LSTM, CNN, Transformer | **DL: BiLSTM IL** |
| S-ML. Có giám sát, ML cổ điển | cây, boosting, RF, SVM trên đặc trưng rời rạc | **ML: LightGBM IL** |
| LLM | dùng LLM để phát hiện hoặc lọc cảnh báo | — |
| CL. Học tăng dần / liên tục | tiêu chí phụ, chồng lên các nhóm trên | **cả hai nhánh** |

**Chú ý khi so:**
- So nhóm S với nhóm U luôn bất lợi cho nhóm U, vì nhóm U không thấy tấn công khi train. Phải ghi rõ điều này cạnh mọi bảng.
- So cùng nhóm thì công bằng hơn, nhưng vẫn cần cùng đơn vị chấm (sự kiện, tiến trình, node, cửa sổ, host) và cùng bộ nhãn.
- Bài "A New Hope for DARPA OpTC" cho thấy **chỉ đổi bộ nhãn** đã làm F1 của cùng một IDS đổi từ 0,23 lên 0,39 (FLASH, host 051), hoặc từ 0,24 lên 0,60 (GAE, host 501).

## 2. Bước 1: OpTC

### 2.1 Bài "A New Hope for DARPA OpTC"

- Majorczyk, Pilastre, Dijoud (INRIA), *CSET 2025 – workshop của ACSAC 2025*, Honolulu, 12/2025; HAL hal-05474126v2.
- Bản PDF đầy đủ và code đã có trong `DATASET/DARPA-OPTC/a_new_hope_for_darpa_optc/`. Dữ liệu đã sửa ở correctedoptc.inria.fr.

**Mình dùng chính nhãn của bài này** (đã kiểm trong code):
- DL OpTC lấy `label` của Zeek conn, tức nhãn mạng của INRIA (`s1_join.py`: "Bro conn.label (A New Hope)"). Script `script/label_optc_network_logs.py` gán 29.311 uid độc hại → 71.726 flow tấn công.
- ML OpTC lấy nhãn host của INRIA (`ground_truth_corrected_all_evts.json.gz`, 360.567 event id). Script `script/label_optc_host_logs.py` gán nhãn cho eCAR trên HDD.
- Như vậy **cùng bộ nhãn** với cột "Ours" trong bảng dưới. Đây là điểm mạnh khi so sánh.

**Thiết lập thí nghiệm của họ** (§5):
- Kairos, FLASH và GAE đều không giám sát. Mỗi model train trên hoạt động benign của ngày 22/09, rồi chạy end-to-end, không tinh chỉnh.
- Chỉ dùng 3 host 051, 201, 501.
- Đơn vị chấm: Kairos và GAE chấm **đồ thị 15 phút**, cùng đơn vị với DL của mình. FLASH chấm **entity (node)** và cảnh báo lan sang lân cận 1 bước; gần nhất với ML (sự kiện) của mình.
- Bài không báo cáo chi phí tính toán (phần cứng, thời gian).
- **Đóng góp:**
  - sửa lỗi actorID trong eCAR: 40 % tiến trình và 4,22 % sự kiện bị lỗi, giảm còn 1,6 % sau 3 lượt sửa (mất 1 tháng tính);
  - gán nhãn lại cả host lẫn mạng (Zeek);
  - chạy lại 3 IDS không giám sát trên host 051, 201, 501 với 3 bộ nhãn.

Kết quả trên eCAR gốc, P / R / F1 (bảng 2 của bài; AUC: Kairos 0,55, GAE 0,30–0,72):

| IDS | Host | Nhãn Nikulshin & Talhi | Nhãn INRIA | Nhãn của FLASH |
|---|---|---|---|---|
| Kairos | 051 + 201 + 501 | 0,81 / 0,11 / **0,20** | 0,81 / 0,10 / **0,18** | 0,14 / 0,85 / **0,24** |
| FLASH | 051 | 0,98 / 0,23 / 0,38 | 0,99 / 0,25 / 0,39 | 0,13 / 0,95 / 0,23 |
| FLASH | 201 | 0,98 / 0,73 / 0,84 | 0,98 / 0,73 / 0,84 | 0,79 / 0,92 / 0,85 |
| FLASH | 501 | 1,00 / 0,72 / 0,83 | 1,00 / 0,72 / 0,84 | — |
| GAE | 051 | 0,07 / 1,0 / 0,14 | 0,07 / 0,88 / 0,13 | — |
| GAE | 201 | 0,46 / 0,59 / 0,52 | 0,14 / 0,67 / 0,24 | — |
| GAE | 501 | 0,23 / 1,0 / 0,38 | 0,43 / 0,99 / 0,60 | — |

- Trên eCAR đã sửa, với nhãn INRIA: Kairos F1 0,16; FLASH 0,39 / 0,84 / 0,87; GAE 0,13 / 0,19 / 0,60. Họ kết luận: sửa dữ liệu không đổi nhiều, **đổi nhãn thì đổi nhiều**.
- So sánh trực tiếp, **cùng nhãn INRIA**:
  - DL của mình (cửa sổ 15 phút) F1 0,988, so với Kairos 0,16–0,18 và GAE 0,13–0,60 (đồ thị 15 phút).
  - ML của mình (sự kiện) F1 0,996, so với FLASH 0,39 / 0,84 / 0,87 (node).
  - Ba khác biệt vẫn còn: mình có giám sát; mình chia ngẫu nhiên, họ train trên 22/09 rồi test các ngày tấn công; mình chấm trên mọi host có dữ liệu, họ chỉ chấm 3 host.
  - Ngoài ra, DL dùng nhãn mạng còn Kairos/GAE dùng nhãn host. Cả hai đều của INRIA và được đối chiếu qua eCAR-Bro.
- **Thí nghiệm nên làm:** chấm lại model của mình chỉ trên 051, 201, 501, train đến hết 22/09 rồi test các ngày tấn công. Khi đó so được cùng nhãn, cùng host, cùng cách chia.
- So với số tự công bố (Kairos P 0,579 / R 1,0; FLASH F1 0,91–0,93), các con số khi người khác chạy lại thấp hơn nhiều.

### 2.2 Bảng theo nhóm

| Nhóm | Công trình | Đơn vị, nhãn, cách chia | Kết quả | Tài nguyên |
|---|---|---|---|---|
| R | SCAHunter (Ahmed et al. 2023) | chữ ký tấn công, 1 kịch bản | không công bố metric (theo bảng 2.1 của Nikulshin) | — |
| R | — | Chưa tìm thấy baseline Sigma hoặc rule-based nào có P/R/F1 trên OpTC. Đây là khoảng trống, nên nói rõ. | | |
| U | Kairos (S&P'24), số tự công bố | cửa sổ 15 phút, 6 host, chia theo ngày | P 0,579, R 1,0 → F1 ≈ 0,73 *(suy ra)* | Xeon 20 nhân, RAM 64 GB; train 229 phút |
| U | Kairos, INRIA chạy lại | đồ thị 15 phút, 3 host, 3 bộ nhãn, train benign 22/09 | F1 **0,16–0,24** | — |
| U | FLASH (S&P'24), số tự công bố | node + lân cận 2 bước | F1 0,91–0,93 | RTX 2080, RAM 80 GB |
| U | FLASH, INRIA chạy lại | entity, theo host | F1 0,23–0,39 (051), 0,84–0,85 (201), 0,83–0,87 (501) | — |
| U | GAE (INRIA chạy) | đồ thị 15 phút, theo host | F1 0,13–0,60 | — |
| U | Velox / Orthrus / Kairos (Bilot et al., USENIX Sec'25) | node, chia theo thời gian | ADP 0,25–0,90 | A100 80 GB, RAM 1 TB |
| U | MADELINE (ACSAC'24) | cửa sổ host 10k sự kiện | recall 0,996, FPR 0,011 | RTX 3090; train 48 s |
| U | Nikulshin, **luận văn thạc sĩ** ÉTS 2025 (pha 1: phát hiện bất thường) | toàn bộ sự kiện, nhãn tự dựng (công bố ở github AT03380/optc-labels) | F1: sự kiện 0,61 · tiến trình 0,70 · lệnh 0,89 · host 1,0 (bảng 5.3) | 231,8 nghìn sự kiện/s; xử lý 10 ngày dữ liệu trong 20 giờ |
| U | Euler (NDSS'22) / Argus (S&P'24) | chỉ cạnh flow mạng | Euler AUC 0,995, AP 0,984; Argus AP 0,807 | CPU RAM 512 GB / RTX 3090 |
| U | DeepTaskAPT (2021) | chuỗi tác vụ, LSTM học benign | accuracy 0,985, FPR 0,011 | laptop i7 |
| S-DL | ANUBIS (Anjum et al. 2022) | sự kiện, mạng nơ-ron Bayes, toàn bộ dataset | có P/R/F1/FPR nhưng **chưa kiểm số** | — |
| S-DL | **Của mình** | cửa sổ 15 phút theo host (flow mạng ⨝ eCAR); **nhãn mạng INRIA**; chia **ngẫu nhiên** theo cửa sổ | F1 **0,988** (P 1,0, R 0,976) | 79 nghìn tham số; 18 phút trên GPU Kaggle |
| S-ML | **Của mình** | sự kiện host eCAR; **nhãn host INRIA**; chia ngẫu nhiên theo sự kiện | F1 **0,996** | CPU |
| S-ML | — | Chưa tìm thấy bài dùng cây hoặc boosting có giám sát trên eCAR OpTC (Velox là bản đơn giản nhưng không giám sát) | | |

**Đánh giá bước 1:**
- Trong nhóm S, gần như không có đối thủ đã công bố. Nếu so với nhóm U, số của mình cao hơn rất nhiều (0,99 so với 0,2–0,87 khi chạy lại độc lập). Tuy vậy, khoảng cách này chủ yếu đến từ việc có giám sát và **chia ngẫu nhiên**, không phải từ kiến trúc.
- Bài INRIA và luận văn Nikulshin đều nhấn mạnh rằng nhãn và đơn vị chấm làm đổi kết quả rất mạnh. Nên trích cả hai để biện minh cho việc mình ghi rõ đơn vị, nhãn và cách chia.
- **Bổ sung nên làm:** chấm lại model của mình bằng nhãn INRIA hoặc Nikulshin trên 3 host 051/201/501, chia theo ngày. Khi đó mới có một bảng so sánh "cùng nhãn, cùng host".

## 3. Bước 2: OpTC → ATLASv2

| Nhóm | Công trình | Dữ liệu, đơn vị | Kết quả | Tài nguyên |
|---|---|---|---|---|
| R | Allowlist baseline (Guerra et al., arXiv 2608.01454) | **ATLASv2**, tiến trình, chia theo thời gian, nhãn REAPr | F1 **0,364 / 0,462** (h1 / h2), tốt nhất bài | rất nhẹ |
| U | Theseus, Velox (Guerra et al.) | như trên | Theseus F1 0,17 / 0,27 (AUROC 0,91 / 0,94); Velox F1 0 | L40S/A100, RAM 80–128 GB |
| U | ORCHID (arXiv 2408.13347) | **ATLASv2**, tiến trình | khoảng 89 % TPR khi FPR gần 0 | GRU 2,7 GB |
| U | AirTag (USENIX Sec'23) | ATLAS **v1**, dòng log | TPR 99,8 %, FPR 6,2 %; chạy lại trên **v2** chỉ còn precision 0,446 (theo SHIELD) | RTX 6000, RAM 376 GB |
| U | APT-LMSPS (MDPI 2026) | ATLAS **v1**, node, khoảng cách tới tâm benign | F1 ≥ 0,98 (chỉ có trong hình) | RTX 3080 16 GB, RAM 300 GB |
| U (tự giám sát) | DeepDist (TrustCom'23) | ATLAS **v1**, entity, học tương phản + DBSCAN | P 0,949, R 0,947, F1 0,947 | V100 32 GB, RAM 128 GB |
| S-DL | ATLAS (USENIX Sec'21) | ATLAS **v1**, entity; leave-one-attack-out; cần analyst chỉ điểm xuất phát | F1 entity 0,938; F1 event 0,999 | **59 phút train mỗi model** |
| S-DL | **Của mình** | **ATLASv2**, cửa sổ 180 s, chia theo kịch bản, nhãn v9b | F1 **0,990 ± 0,014**, giữ OpTC 0,994 | **2 phút 14 giây**, < 1 GB VRAM |
| S-ML | **Của mình** | **ATLASv2**, sự kiện | F1 **0,959**, giữ OpTC 0,991 | **2,5 giây** CPU |
| LLM | SHIELD (arXiv 2507.10873) | **ATLASv2**, sự kiện | precision TB 0,957 | A6000, RAM 768 GB + LLM 671B |

**Đánh giá bước 2:**
- Trên **ATLASv2**, nhóm R (allowlist) lại thắng nhóm U trong bài của Guerra. Đây là chi tiết hay để đưa vào luận văn.
- Mình thuộc nhóm S, chưa có đối thủ S nào trên v2. ATLAS (nhóm S, trên v1) là đối thủ gần nhất về phương pháp: cùng là LSTM có giám sát chia theo tấn công. Mình nhanh hơn khoảng 26 lần (2,2 phút so với 59 phút) và không cần analyst chỉ điểm xuất phát.
- **Phải nói rõ:** với nhãn REAPr gốc, BiLSTM đơn chỉ đạt 0,64. Số 0,99 dựa trên nhãn v9b.

## 4. Bước 3: + AInception SL700

| Nhóm | Công trình | Ghi chú |
|---|---|---|
| R / U | AMiner, Telosian (cảnh báo đi kèm dataset, AIT) | AMiner là phát hiện bất thường dựa trên mô hình học từ log. Dataset có sẵn cảnh báo nhưng **không có số độ chính xác**. Chấm các cảnh báo này bằng nhãn của mình sẽ cho baseline R/U duy nhất. |
| tất cả | — | **Chưa có công bố phát hiện nào trên AInception.** Chỉ có Zenodo DOI 10.5281/zenodo.17659656; PDF đi kèm ghi nhãn từng sự kiện "không hoàn toàn tin cậy". |
| S-DL (mình) | IL + replay | F1 0,978 ± 0,004; giữ ATLASv2 0,970, OpTC 0,994; 4 phút 10 giây, 1,3 GB VRAM |
| S-ML (mình) | IL + replay | sự kiện 0,995, cửa sổ 0,883; giữ ATLASv2 0,953, OpTC 0,994; 17 giây CPU |

Baseline nội bộ (đã có trong README): model cũ chạy thẳng 0,799; train từ đầu 0,995 nhưng mất cả 2 miền cũ; không replay thì ATLASv2 tụt còn 0,74–0,81.

## 5. Nhóm CL: học tăng dần

| Công trình | Nhóm nền | Bối cảnh | Kết quả |
|---|---|---|---|
| Rahman et al. (CoLLAs'22) | S-DL (MLP) | malware EMBER, 12 tháng | CL không replay thua; replay 1 % đạt 93,9 so với joint 95,9 |
| Tidal (NINeS'26) | U (Transformer) | DARPA E3 → E5 | giữ E3: P 0,85, R 0,94 |
| METANOIA (arXiv 2501.00438) | U | E3/E5 | P/R 0,43 / 0,95; không đo quên |
| Amalapuram et al. (NeurIPS'23), QCL-IDS | S | NIDS, các task trong cùng 1 dataset | forgetting 0,004–0,005 |
| **Mình** | S-DL + S-ML | 3 dataset host khác OS và cảm biến | BWT: DL OpTC +0,006, ATLASv2 −0,020; ML OpTC −0,002, ATLASv2 −0,006 |

## 6. Trường mạng trong hai model

| Miền | DL | ML |
|---|---|---|
| OpTC | **Có, từ cảm biến mạng.** Mỗi mẫu là một flow **Zeek/Bro conn** inner-join với sự kiện eCAR FLOW. 4 trường: `proto` và `resp_port_class` lấy từ Zeek; `app_family` và `image_dir_class` lấy từ host (ảnh tiến trình). Không dùng IP, byte hay duration (phương án B bỏ các trường chỉ có ở Bro). | **Không có trường mạng.** Hàng là sự kiện host eCAR; FLOW không làm hàng. Mạng chỉ góp token `has_netconn` (tiến trình có kết nối trong 30 s / 300 s trước đó). |
| ATLASv2 | **Có, nhưng từ log host.** Sự kiện `netconn` của Carbon Black EDR cho `proto`, lớp cổng phía responder, và trường ngữ cảnh `net` = proto:lớp_cổng:có/không domain. `ip_scope` (private/public) **bị bỏ** vì là shortcut. Không có cảm biến mạng riêng. | Chỉ `has_netconn`. Netconn không làm hàng. |
| SL700 | **Có, từ log host:** `connect`/`accept` của auditd → `netconn` (proto, lớp cổng). Nhóm `g_scope` (nguồn đăng nhập/kết nối private, external hay loopback) **không dùng** trong số chính, chỉ báo cáo riêng. | Chỉ `has_netconn`. 6 cột phạm vi địa chỉ bị bỏ trong cấu hình chính. |

Tóm lại:
- **Chỉ DL ở bước OpTC** thực sự kết hợp **log mạng (Zeek)** với log host.
- Ở ATLASv2 và SL700, DL dùng **sự kiện mạng do agent host ghi** (EDR, auditd), không có log mạng riêng.
- ML chỉ dùng log host; mạng chỉ là một cờ ngữ cảnh nhân quả.
- Không model nào dùng IP cụ thể làm đặc trưng.
## 7. Chỗ mình thấp hơn hoặc yếu hơn, và cách trình bày

| Điểm yếu | Cách viết |
|---|---|
| Không có chuyển giao xuôi: train từ đầu ngang IL trên miền mới | Giá trị của IL là *một model giữ cả 3 miền* với chi phí vài phút. Train từ đầu thì mất hẳn miền cũ (ATLASv2 0,03; OpTC 0,00). |
| ML theo cửa sổ trên SL700 chỉ đạt 0,883 (DL 0,978) | ML chấm từng sự kiện; quy về cửa sổ là phép chuyển đổi để so. Bù lại, ML train 17 s, chỉ dùng CPU và tất định. |
| Biến thể chưa thấy (fold e_a, persistence bằng cron): DL 0,74–0,83 | Đây là giới hạn khái quát. LightGBM cùng token cũng chỉ đạt 0,81–0,91, nên giới hạn nằm ở dữ liệu chứ không ở model. |
| DL bước 3 làm ATLASv2 giảm 0,02 | Vẫn ≥ 0,97. Không replay thì giảm còn 0,81. |
| Bước 1 chia ngẫu nhiên | Ghi rõ ở phần threats to validity. |
| TEST SL700 chỉ có 1 run | Báo cáo thêm leave-one-run-out: LightGBM 0,945. |


Nguồn chính: Kairos arXiv 2308.05034; FLASH dartlab.org/assets/pdf/flash.pdf; A New Hope for DARPA OpTC cset25.isi.edu/slides/cset2025-slides-optc.pdf; Nikulshin, mémoire ÉTS 2025 espace.etsmtl.ca/3646; Nikulshin & Talhi CIoT 2024 doi 10.1109/CIoT63799.2024.10757066; Bilot et al. USENIX Sec'25; MADELINE ACSAC'24; Euler; Argus S&P'24; DeepTaskAPT arXiv 2108.13989; ATLASv2 arXiv 2401.01341; ATLAS USENIX Sec'21; AirTag USENIX Sec'23; Guerra et al. arXiv 2608.01454; SHIELD arXiv 2507.10873; ORCHID arXiv 2408.13347; DeepDist TrustCom'23; APT-LMSPS MDPI Information 2026; AInception zenodo 17659656; Rahman et al. arXiv 2208.06568; Tidal NINeS'26; METANOIA arXiv 2501.00438.
