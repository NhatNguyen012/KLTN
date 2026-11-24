# So sánh LightGBM và BiLSTM trước IL trên OpTC

Ngày đối chiếu: 21/11/2026. Chỉ sử dụng model OpTC trước mọi bước IL, fine-tuning trên miền mới hoặc fusion. Các số bên ngoài là kết quả tác giả công bố hoặc nghiên cứu tái đánh giá công bố; chưa chạy lại các hệ thống đó trên split của dự án.

**Kết luận:** LightGBM của dự án đạt F1 lớp tấn công 99,6325%, cùng mức số công bố 99,6% của ANUBIS và cao hơn nhiều kết quả OpTC của FLASH, TAPAS, TraceCluster. BiLSTM đạt 98,7654%, cao hơn một số kết quả đó nhưng thấp hơn số F1 công bố của ANUBIS. Đây là đối chiếu số báo cáo, chưa chứng minh ưu thế phương pháp: dữ liệu, nhãn, đơn vị dự đoán và cách chia tập khác nhau. Điểm yếu lớn nhất của LightGBM là cohort chọn theo nhãn và split ngẫu nhiên; của BiLSTM là split không tách host và luật đơn giản đã đạt bằng hoặc hơn model trên TEST.

**Trạng thái đọc:** đã kiểm kê và trích xuất văn bản từ toàn bộ 143 PDF dưới `paper-*`, nhưng **chưa hoàn tất đọc toàn văn từng tài liệu**. Kiểm kê không đồng nghĩa với đọc. Bảng dưới đây dựa trên các phần phương pháp, thực nghiệm, bảng kết quả và giới hạn đã kiểm tra; các bảng ảnh quan trọng được xem trực tiếp. Không coi tài liệu này là biên bản hoàn tất yêu cầu đọc toàn bộ kho. Chi tiết kiểm kê trong [optc_paper_inventory_20261121.tsv](optc_paper_inventory_20261121.tsv).

## Kết quả gốc của dự án

Tất cả Precision, Recall, F1, FPR, PR-AUC trong bảng này dùng đơn vị %. PR-AUC của LightGBM là xấp xỉ theo 100.000 bin; không coi nó là cùng phép tính với Average Precision của mọi paper.

| Model trước IL | Đơn vị dự đoán | Precision | Recall | F1 lớp tấn công | FPR | PR-AUC | TP / FP / FN / TN |
|---|---|---:|---:|---:|---:|---:|---|
| LightGBM + Parent & Incoming | Một sự kiện host | 99,7291 | 99,5361 | **99,6325** | **0,009013** | 99,9254, binned | 40.123 / 109 / 187 / 1.209.270 |
| BiLSTM subsetB | Một chunk tối đa 512 flow trong cửa sổ host 15 phút | 100 | 97,5610 | **98,7654** | 0 quan sát được | 98,8848 | 80 / 0 / 2 / 34.331 |

Nguồn gốc:

- [LightGBM metrics](../ML/code/output/host_ml_parent_incoming_seed02/kaggle_output/lgbm_kaggle_results/results/lgbm_metrics.json).
- [LightGBM scope](../ML/code/output/host_ml_parent_incoming_seed02/scope.json) và [split manifest](../ML/code/output/host_ml_seed02/split/manifest.json).
- [BiLSTM metrics](../DL/05_models/v2_subsetB/bilstm_v2_subsetB/metrics.json), [config](../DL/05_models/v2_subsetB/bilstm_v2_subsetB/config.json), [báo cáo subsetB](../DL/02_artifacts/24_v2_subsetB_results/STEP_24_SUBSETB_RESULTS.md).
- [DL split summary](../DL/02_artifacts/22_v2_pipeline/S2_windows_split/split_summary.json).

### Phạm vi thực sự của LightGBM

Manifest xác định `strategy=contextual_option_b`, seed split 2, tỷ lệ 75/10/15. Cohort được tạo từ 106 source file thuộc 34 file-host bị tấn công. Các sự kiện được chọn trong khoảng tấn công từng host/ngày và hai cửa sổ baseline `[10:00,10:30)` giờ ET ngày 21–22/09/2019; bốn baseline host-day bị thiếu được ghi nhận trong manifest. Cohort có 8.331.257 sự kiện đủ điều kiện, gồm TRAIN 6.248.443, VAL 833.125 và TEST 1.249.689. TRAIN sau lấy mẫu dùng 6.248.110 dòng.

Đây **không phải** phép kiểm thử trên toàn bộ hàng tỷ sự kiện hoặc toàn bộ 500 host được thu thập của OpTC. Manifest tự ghi rõ `label-informed cohort; attacked file-hosts only; no temporal/process/campaign generalization`. Việc dùng nhãn để chọn cohort là điều kiện chọn mẫu đánh giá, không đồng nghĩa nhãn đã đi vào feature; nhưng nó giới hạn mạnh khả năng suy rộng FPR ra mạng vận hành liên tục.

Đầu vào gồm 10.317 cột token nhị phân và context tiến trình cha, tương tác incoming. Bộ theo dõi dùng bằng chứng quá khứ; vocabulary fit trên TRAIN, ngưỡng 0,87427 chọn trên VAL. Điều đó bảo vệ các bước fit/calibration tương ứng nhưng không biến split ngẫu nhiên thành kiểm thử tấn công mới. Seed sampling/training 1 trong metrics khác seed split 2.

### Phạm vi thực sự của BiLSTM

Split được tạo ở cấp cửa sổ host 15 phút, tỷ lệ xấp xỉ 70/15/15, rồi chia cửa sổ dài thành chunk tối đa 512 flow. TEST có 16.560 cửa sổ gốc, 81 cửa sổ dương; sau chunking có 34.413 sample, 82 sample dương. Vì vậy confusion matrix trên là **chunk/sample**, không phải 34.413 cửa sổ 15 phút độc lập.

Đặc trưng subsetB gồm `app_family`, `proto`, `resp_port_class`, `image_dir_class` và Δt. Không dùng địa chỉ IP cụ thể, các field số L3/L4 của Bro hay `principal_class`. Dữ liệu vẫn là flow Bro/Zeek nối context eCAR; bỏ field Bro chuyên biệt không đồng nghĩa bộ dữ liệu huấn luyện không còn phụ thuộc bước nối Bro.

Checkpoint tốt nhất epoch 2, seed model 42; ngưỡng VAL 0,99560546875. Có một lần chạy chính. TEST dương phân bố SC1/SC2/SC3 = 9/72/1 sample. Không đủ bằng chứng để phát biểu chắc về SC3.

Audit split ghi 613 host xuất hiện trong cả ba split, và 80/81 cửa sổ dương TEST có host từng có cửa sổ dương TRAIN. Không có kiểm thử host mới hoặc chiến dịch mới trong phép đo chính này.

## Baseline nội bộ cùng TEST

Các model host dưới đây dùng cùng TEST; số baseline lấy từ bảng lịch sử của [ML README](../ML/code/README.md), vì các artifact RF/XGB cũ đã được dọn. Số LightGBM hiện hành được kiểm tra trực tiếp từ JSON. Đơn vị %.

| Host ML | Precision | Recall | F1 | FP | FN |
|---|---:|---:|---:|---:|---:|
| Random Forest baseline | 95,87 | 86,77 | 91,09 | 1.505 | 5.334 |
| XGBoost baseline | 97,93 | 92,09 | 94,92 | 786 | 3.189 |
| LightGBM baseline | 98,81 | 92,09 | 95,33 | 446 | 3.189 |
| LightGBM + Parent & Incoming | **99,73** | **99,54** | **99,63** | **109** | **187** |

So với LightGBM baseline, phiên bản context tăng khoảng **4,30 điểm phần trăm F1**, giảm **94,14% FN** và **75,56% FP**. Đây là bằng chứng trực tiếp mạnh nhất về cải thiện trong phạm vi thực nghiệm host hiện có. Nó chứng minh hiệu quả của cấu hình context tổng thể; chưa tách riêng đóng góp parent và incoming nếu không có ablation tương ứng.

Baseline trên cùng TEST DL theo [audit S7](../DL/02_artifacts/22_v2_pipeline/S7_results/STEP_S7_RESULTS.md) và báo cáo subsetB:

| Phương pháp | TP / FP / FN | F1 (%) |
|---|---|---:|
| BiLSTM subsetB | 80 / 0 / 2 | 98,7654 |
| Luật có `powershell.exe` | 81 / 0 / 1 | 99,3865 |
| Luật có PowerShell hoặc Temp/AppData | 82 / 0 / 0 | 100 |

Các luật này là **baseline chẩn đoán hậu kiểm**, chưa phải một đối thủ được chọn độc lập trên VAL. Chúng vẫn cho thấy TEST hiện tại không cung cấp bằng chứng rằng BiLSTM cần học quan hệ chuỗi phức tạp mới đạt điểm cao. Không nên tuyên bố BiLSTM vượt luật đơn giản.

## ML truyền thống và DL chuỗi trong các nghiên cứu OpTC

Các tỷ lệ đều là %, trừ nơi ghi khác. Dấu — nghĩa là không báo cáo hoặc chưa xác minh được ở cùng cấu hình, không phải bằng 0.

| Công trình | Nhóm và giao thức | Kết quả OpTC | So với dự án |
|---|---|---|---|
| **ANUBIS**, SAC 2022 | Hai nhánh LSTM + Bayesian NN trên trace từ provenance graph; có giám sát; split 80/20 | Table 4/7: P≈99, R≈100, **F1=99,6**, Acc=99,3 | LightGBM 99,6325 cùng mức số báo cáo; BiLSTM 98,7654 thấp hơn. Khác trace/event/chunk và cohort, chưa có thắng/thua trực tiếp. |
| **DeepTaskAPT**, 2021/2022 | LSTM trên trace/task-tree, học dự đoán hành động; Table IV, #candidate=5 | Cùng user: **Acc=98,54; FPR=1,1**. Khác user: **Acc=93,63; FPR=5,29** | Không lấy Accuracy thay F1. Paper có đánh giá khác user mà phép đo chính DL dự án chưa có. |
| **RF trong DeepTaskAPT** | Baseline trên trace, cùng thiết lập Table IV | Tree-processed: Acc=90,52/87,39; FPR=8,33/9,21 cho cùng/khác user. Raw: Acc=80,88/79,67; FPR=18,31/18,00 | Cho thấy RF là đối thủ ML thực sự có trong literature; khác biểu diễn và đơn vị nên không xếp hạng trực tiếp với host event của dự án. |
| **Nikulshin**, luận văn ÉTS 2025, Phase 1 | Random Forest dự đoán identity làm nhãn proxy; mismatch được coi là anomaly; context graph/tree, bỏ tên chương trình cụ thể | Table 5.3: cấp event **P=87, R=47, F1=61**; cấp process **P=55, R=97, F1=70**; cấp command **F1=89**; cấp host **F1=100** | Là đối thủ ML có ngữ cảnh gần về ý tưởng, nhưng khác feature, supervision và tập đánh giá. Cùng một detector cho F1=61 đến 100 chỉ do đổi đơn vị tổng hợp. |
| **Event2Vec**, IPEC 2023 | Embedding word/character + attention GRU, phát hiện lateral movement không giám sát | **Table II: F1=89; AUC=84; Acc=75** | Số F1 thấp hơn hai model dự án, nhưng bài toán và giám sát khác. Kết luận paper còn nêu P=91/R=96 không khớp F1 trong bảng; giữ nguyên số theo từng nguồn, không ghép. |
| **MADELINE**, ACSAC 2024 | LSTM autoencoder trên thống kê hành vi; học benign; cửa sổ 10.000 event | Self-reconstruction: **R=98,8; FPR=3,0**. Thêm NCM: **R=99,6; FPR=1,1** | Recall NCM xấp xỉ LightGBM và cao hơn BiLSTM; FPR báo cáo cao hơn, nhưng khác đơn vị/cỡ cửa sổ/cohort. Không đủ P để tự điền F1. |
| **MADELINE composite + NCM** | Cấu hình khác của cùng paper | **R=100; FPR=1,2** | Không được nói dự án có recall cao hơn mọi cấu hình MADELINE. |
| **Francis et al.**, IC2SPM 2024 | Stateless/Bidirectional/Stateful LSTM trên OpTC | Nguồn chính thức truy cập được chỉ xác nhận phương pháp; chưa lấy được bảng số toàn văn | Không điền F1 hoặc kết luận BiLSTM dự án thắng bài này. |

Nguồn: [ANUBIS Table 4 và 7](https://arxiv.org/html/2112.11032v1), [DeepTaskAPT Table IV–VII](https://arxiv.org/pdf/2108.13989), [Nikulshin Table 5.3 p.172](https://espace.etsmtl.ca/id/eprint/3646/1/Nikulshin_Viktor.pdf), [Event2Vec DOI](https://doi.org/10.1109/IPEC57296.2023.00074) và PDF local `paper-token/Leveraging-Token-Based-Representation-to-Detect-Lateral-Movement.pdf` p.398, [MADELINE Table 2–3](https://people.cs.vt.edu/penggao/papers/madeline-acsac24.pdf), [Francis et al.](https://doi.org/10.1109/IC2SPM62723.2024.10841340).

ANUBIS có bất nhất FPR giữa Table 4, văn bản và các trích dẫn sau này. Table 4 trung bình ghi 0,003, đoạn sau lại nêu 2,28%; BPGV trích 2,8%. Không dùng một trong các số đó để tính lợi thế FPR. Precision/recall/F1 cũng bị làm tròn không đồng nhất. Chênh lệch 99,6325−99,6=0,0325 điểm phần trăm không đủ để tuyên bố LightGBM tốt hơn ANUBIS.

## Mô hình đồ thị và provenance

P/R/F1 trong bảng là %. Đây là các kết quả theo đơn vị và giao thức riêng của từng paper.

| Công trình | Nhóm và đơn vị | P | R | F1 | Điều kiện quan trọng |
|---|---|---:|---:|---:|---|
| **FLASH**, S&P 2024, Attack 1 | GNN/Word2Vec + XGBoost; node | 90 | 92 | 91 | Học kiểu node từ benign; không phải XGB nhị phân có nhãn tấn công như host ML. |
| FLASH, Attack 2 | Như trên | 94 | 92 | 93 | Cần ghi đúng cấu hình GNN+XGB trong Table 2. |
| FLASH, Attack 3 | Như trên | 92 | 93 | 92 | Có tạo attack evolution graph. |
| **TAPAS**, USENIX Security 2025, Attack 1 | Process/task graph; representation LSTM–GRU | 97,29 | 96,82 | 97,05 | Table 3. |
| TAPAS, Attack 2 | Như trên | 97,83 | 96,24 | 96,97 | Không lấy số DARPA TC cho OpTC. |
| TAPAS, Attack 3 | Như trên | 97,91 | 96,71 | 97,29 | Khác task/node/event/chunk. |
| **TraceCluster**, TIFS 2026, Custom PowerShell | Subgraph attention, node, benign-only | 89 | 84 | 86 | Table VII; train/VAL benign 80/20, TEST chứa tấn công. |
| TraceCluster, Malicious Upgrade | Như trên | 92 | 87 | 90 | Bảng được kiểm tra trực tiếp bằng ảnh PDF p.1076. |
| **MAGAPT**, ISPEC 2025 / LNCS 2026 | MAGNN + ATT&CK + LR; có giám sát; node | 60 | 97 | 74 | Table 7; TEST 5.938 benign + 233 malicious node; train có 234 malicious node. |
| **CDTD / Along Came a Spider**, TMC 2026 | Collaborative graph learning, nhiều domain | 92 | 91 | 92 | Table II, trung bình các domain OpTC; FPR=0,06‰ = **0,006%**, không phải 0,06%. |
| **OCR-APT**, CCS 2025, H201 | GNN phát hiện subgraph; LLM diễn giải; bảng detection theo node mở rộng | 100 | 88 | 94 | Table 2; phát hiện và tạo narrative là hai khâu. |
| OCR-APT, H501 | Như trên | 100 | 100 | 100 | Một host; không phải kết quả toàn corpus. |
| OCR-APT, H051 | Như trên | 89 | 77 | 82 | Không chỉ chọn host có F1=100 để đại diện paper. |

Nguồn: FLASH Table 2 trong PDF local `paper-general/code/Flash-IDS/FLASH - A Comprehensive Approach to Intrusion Detection via Provenance Graph Representation Learning.pdf`; [TAPAS Table 3](https://www.usenix.org/system/files/usenixsecurity25-zhang-bo-tapas.pdf); [TraceCluster DOI](https://doi.org/10.1109/TIFS.2026.3653175) và PDF local; [MAGAPT DOI](https://doi.org/10.1007/978-981-95-9284-5_18) và PDF local; CDTD PDF local `paper-general/Along-Came-a-Spider-Enabling-Effective-Cross-Domain-Threat-Detection-Via-Collaborative-Graph.pdf` p.5076; [OCR-APT Table 2](https://arxiv.org/html/2510.15188v1).

TAPAS phần văn bản nêu trung bình OpTC P/R/F1 = 97,88/96,65/97,19; chúng không trùng trung bình số học ba dòng Table 3. Bảng này giữ các dòng Table 3 để không tự chọn giữa hai cách báo cáo.

MAGAPT Table 6 có một số dòng SVM/XGB mà P/R không khớp TP/FP/FN, trong khi dòng LR dùng trong Table 7 phù hợp gần đúng. Không dùng các dòng bất nhất làm baseline định lượng. Paper gọi FLASH là XGB trên feature thủ công; bài FLASH gốc thực tế còn có representation learning bằng GNN và Word2Vec, nên phân loại nó là phương pháp lai DL + ML.

Các F1 trên đều thấp hơn LightGBM và phần lớn thấp hơn BiLSTM dự án, **trừ OCR-APT trên H501**. Điều này chỉ mô tả độ lớn số công bố. Riêng FPR, FLASH gốc suy từ Table 2 khoảng 0,00109–0,00825% theo từng attack, CDTD báo 0,006%, đều có thể thấp hơn LightGBM 0,009013% trên đơn vị đánh giá riêng. Không có bằng chứng dự án thắng đồng thời mọi metric.

## Kairos và các kết quả tái đánh giá

Kairos gốc chấm cửa sổ thời gian, gần nhánh DL hơn về cách cảnh báo nhưng vẫn dùng toàn bộ host provenance và nhãn khác. Từ confusion matrix paper gốc:

| Kairos trên OpTC | TP / FP / FN / TN | P (%) | R (%) | F1 suy từ counts (%) | FPR suy từ counts (%) |
|---|---|---:|---:|---:|---:|
| Table 4, nhãn gốc | 22 / 16 / 0 / 1.210 | 57,8947 | 100 | **73,3333** | 1,3051 |
| Table 5, adjusted | 32 / 6 / 0 / 1.210 | 84,2105 | 100 | **91,4286** | 0,4934 |

Nguồn: [Kairos](https://arxiv.org/abs/2308.05034), Table 4–5 và mục 5.2 trong PDF local `paper-general/code/kairos/Kairos_Practical_Intrusion_Detection_and_Investigation_using_Whole-system_Provenance.pdf`.

Adjusted không đơn giản là bỏ 10 FP: tác giả xác định một số FP thực ra là thực thể vẫn bị ảnh hưởng bởi tấn công và chuyển cách tính sang TP. Không trộn adjusted với nhãn ban đầu của dự án để tuyên bố thắng công bằng. BiLSTM có P/F1 số học cao hơn cả hai dòng nhưng R=97,56% thấp hơn Kairos 100%.

### Cùng họ nhãn corrected OpTC

Tài liệu trình bày của **A New Hope for DARPA OpTC** đánh giá lại Kairos, FLASH và graph autoencoder trên corrected eCAR với nhãn do nhóm đó xây dựng. Đây là nguồn sát với phiên bản dữ liệu của dự án hơn các số trên OpTC gốc, nhưng vẫn khác split, cohort và đơn vị.

| Hệ thống trên corrected OpTC | Host | P (%) | R (%) | F1 (%) |
|---|---|---:|---:|---:|
| Kairos | 051, 201, 501 | 79 | 9 | 16 |
| FLASH | 051 | 100 | 25 | 39 |
| FLASH | 201 | 99 | 73 | 84 |
| FLASH | 501 | 100 | 78 | 87 |
| Graph autoencoder | 051 | 7 | 100 | 13 |
| Graph autoencoder | 201 | 12 | 58 | 19 |
| Graph autoencoder | 501 | 43 | 99 | 60 |

Nguồn: [slides chính thức, trang PDF 29](https://cset25.isi.edu/slides/cset2025-slides-optc.pdf), không gán nhầm đây là toàn văn bài báo. [Trang dự án corrected OpTC](https://correctedoptc.inria.fr/) và [bài báo xuất bản](https://doi.org/10.1109/ACSACW69556.2025.00064).

### Node attribution với giao thức thống nhất

Bilot et al., **Sometimes Simpler is Better**, USENIX Security 2025, Table 6 đánh giá lại nhiều PIDS bằng nhãn node, train theo thời gian và ngưỡng từ VAL. ADP đo khả năng tìm một dấu hiệu tấn công hữu ích, không phải F1 hay recall trên toàn node.

| Hệ thống tái đánh giá | ADP trung bình H051 / H201 / H501 | Precision trung bình H051 / H201 / H501 |
|---|---|---|
| Kairos | 0,50 / 0,75 / 0,38 | 0,14 / 0,38 / 0,12 |
| Orthrus | 0,68 / 0,48 / 0,25 | 0,08 / 0,14 / 0,11 |
| Velox | 0,57 / 0,90 / 0,39 | 0,12 / 0,18 / 0,13 |

Nguồn: [Bilot et al., Table 6](https://www.usenix.org/system/files/usenixsecurity25-bilot.pdf). Không chuyển ADP=0,90 thành F1=90%. Không so F1 sự kiện của dự án với các số này như cùng bài toán forensic attribution.

**ProvFusion**, repository tác giả gắn S&P 2026, báo TP/FP node trên refined ground truth: H201=3/5, H051=16/30, H501=2/4 ở các checkpoint công bố. Có thể suy Precision tương ứng 37,5%, 34,78%, 33,33%; chưa đủ tổng dương để suy Recall/F1 từ riêng bảng README. Kết quả regeneration H051=22/20 là một lần chạy khác, không thay vào dòng checkpoint gốc. Nguồn: [repository tác giả](https://github.com/Joney-Yf/ProvFusion#-detection-results).

## Lateral movement và mô hình foundation

Các mô hình này thường coi host là node và kết nối là edge. Không xem AP là Precision tại ngưỡng, không xem AUC/AP là F1.

| Công trình và cấu hình | AUROC (%) | AP (%) | Recall / FPR nếu có | Giao thức |
|---|---:|---:|---|---|
| **Euler-SM LSTM**, TOPS 2023, dynamic link detection | 99,5 | 98,4 | 96,7% / 0,012% | Table 9; cần ghi hậu tố SM, không gán cho mọi Euler. |
| **Argus**, S&P 2024 | 99,70 | 80,74 | — | Table 7; train năm ngày đầu, test ba ngày sau; label/network aggregation riêng. |
| **CyberGFM static**, 2026 | 97,39 | 89,81 | — | Table 5; 80/10/10 benign và anomalous đưa vào TEST; không phải temporal split như Argus. |
| CyberGFM temporal | 97,59 | 88,70 | — | Cùng paper, cùng split với các baseline họ chạy lại. |
| Euler do CyberGFM chạy lại | 98,40 | 64,23 | — | Không thay bằng AP=98,4 của Euler-SM, vì khác cấu hình/giao thức. |
| Argus do CyberGFM chạy lại | 88,85 | 78,47 | — | Không gộp với số gốc 99,70/80,74. |

Nguồn: [Euler Table 9, bản tác giả](https://isaiahjking.com/papers/EulerACM.pdf); [Argus, bản tác giả](https://c0ldstudy.github.io/commons/papers/SP2024_paper118.pdf); [CyberGFM](https://arxiv.org/abs/2601.05988) và Table 5 trong PDF local.

Larroche, **On Fair and Realistic Performance Evaluations for Graph-Based Lateral Movement Detectors**, ESORICS 2026, đưa preprocessing và nhãn LM nghiêm ngặt hơn. Table 6 báo AUROC/AP cho LM-only của Pikachu, Euler, Argus lần lượt 50,74/0,01; 52,90/0,00; 43,23/0,01 (%). Kết quả này minh họa độ nhạy với nhãn và giao thức, không phải bằng chứng LightGBM dự án phát hiện LM tốt hơn: dự án chưa đo cùng tập LM-only. Nguồn: [paper tác giả](https://superviz.inria.fr/assets/pdf/anubis26/ESORICS_2026_paper_1002.pdf).

## Threat hunting, luật, pattern mining, LLM và RL

| Công trình | Loại nghiên cứu | Kết quả OpTC | Điều không nên suy diễn |
|---|---|---|---|
| **TapTree**, 2022/2023 | Process-tree pattern queries, sequential pattern mining | Tree queries: R=100%, FPR=2,9%. Sequential: R≈86%, FPR<1%; cấu hình R≈67%, FPR<0,1% | Không ghép recall tốt nhất với FPR thấp nhất từ cấu hình khác. |
| **BPGVAD**, 2026 | Behavioral graph views, normal-pattern rule matching | User-process case: Acc=99,332%, R=100%, FPR=0,669% | Đây là accuracy, không phải F1; không tự suy F1 từ R/FPR thiếu prevalence. |
| **APT-CGLP**, KDD 2026 | Graph–text contrastive learning, LLM, CTI retrieval | Table 3/4, k=10: P=83,3%, R=95,2%, F1=88,9%, FPR=3,8% | Đánh giá matching subgraph–CTI; cần CTI, khác detector nhị phân độc lập. |
| **MEGR-APT**, tái đánh giá trong APT-CGLP | GNN graph matching + human-involvement query | P=77,8%, R=100%, F1=87,5% | Nêu rõ nguồn là paper chạy lại, không tự coi là toàn bộ kết quả bài gốc. |
| **ProvG-Searcher**, cùng giao thức APT-CGLP | Learned subgraph search + query được sửa thủ công | P=70%, R=100%, F1=82,4% | Cùng lưu ý về nguồn tái đánh giá. |
| **TREC**, cùng giao thức APT-CGLP | Few-shot graph matching + query được sửa thủ công | P=72,4%, R=100%, F1=84,0% | Recognition/hunting khác binary event classification. |
| **ProHunter**, 2026 | Whole-system graph compaction, sampling và learned CTI matching | Table 13: R=100%, FPR=7%, Acc=93%, AUC=99% | Explicit-IoC case 13/13 và 0/35 là một phép đo khác; không dùng nó thay số semantic matching. |
| **APT-CGSV**, luận văn Shoukat Ali 2026 | CTI graph retrieval + GNN + LLM validation | Table 3.4: P=96,67%, R=80%, F1=86,36% | Chỉ vài malicious subgraph; các số trung bình theo lần chạy không cần thỏa harmonic mean của P/R trung bình. |
| **CPD**, trong luận án KIT local | Quy tắc chuyên biệt persistence + provenance | Host0501: phát hiện cả setup và execution; Kairos/FLASH chỉ setup. Run time gồm xử lý/training: 2/630/312 phút; RAM 2,6/10,2/9,1 GB | Đây là phát hiện một kỹ thuật cụ thể; không phải F1 tổng thể OpTC. |
| **GADRL**, Technologies 2026 | GNN + Double DQN + PER | TEST tương lai: TP=5, FP=91, FN=0; R=100%, **F1=9,90%**, AP=4,9% | Recall=100% và accuracy=99,90% không đồng nghĩa detector tốt hơn. Không dùng phần incremental/adaptive training của bài để so cơ chế IL của dự án. |
| **SEDetector**, Computer Networks 2026 | Semantic Evidence Units + hypergraph | Abstract nhà xuất bản: **Macro-F1=99,52±0,07%**, 5 seed | Mới xác minh được thông tin công khai, chưa toàn văn. Macro-F1 khác F1 lớp tấn công của dự án; chưa đủ điều kiện xếp hạng. |

Nguồn: [TapTree](https://arxiv.org/html/2312.07575v1); [BPGV Table 2–3](https://doi.org/10.1016/j.jjimei.2026.100397); [APT-CGLP](https://arxiv.org/abs/2511.20290), Table 3–4 PDF local; [ProHunter Table 13](https://arxiv.org/html/2603.19658v1); APT-CGSV trong `paper-general/ucalgary_2026_shoukat_ali.pdf`, Table 3.4 p.60; CPD trong `paper-general/10.5445IR1000179480.pdf`, Table 7.5 p.111; [GADRL Table 9–10](https://www.mdpi.com/2227-7080/14/10/624); [SEDetector, abstract nhà xuất bản](https://www.sciencedirect.com/science/article/pii/S1389128626007486).

## Dự án hơn và thua ở đâu

| Khía cạnh | LightGBM trước IL | BiLSTM trước IL | Đối chiếu với literature |
|---|---|---|---|
| Chất lượng trên split hiện tại | F1=99,6325%, 109 FP/1,21 triệu benign event | F1=98,7654%, 0 FP/34.331 benign sample | Điểm cao; LightGBM cùng mức ANUBIS công bố, chưa chứng minh vượt SOTA. |
| Bằng chứng giá trị kiến trúc | Context cải thiện rõ so với baseline cùng TEST | Luật PowerShell/Temp đã bằng hoặc hơn | Bằng chứng hiện có thuyết phục hơn cho biểu diễn/context host so với sự cần thiết của BiLSTM. |
| Nhãn tấn công khi học | Có | Có | Nhiều đối thủ anomaly-based chỉ học benign; dự án giải bài toán thuận lợi hơn ở khía cạnh này. ANUBIS/MAGAPT là đối thủ có giám sát gần hơn. |
| Kiểm thử tấn công/host mới | Chưa có trong kết quả chính | Chưa có trong kết quả chính | Thua về độ mạnh bằng chứng generalization so với giao thức temporal/held-out có kiểm soát. Không khẳng định mọi paper đều làm tốt hơn về split. |
| Tính đại diện | Cohort 34 attacked file-host, khoảng thời gian chọn theo nhãn | TEST 82 sample dương, chỉ 1 SC3 | Chưa chứng minh chất lượng vận hành trên toàn mạng hoặc mọi loại APT. |
| Điều tra attack chain | Feature context có thể diễn giải; chưa có chỉ số reconstruction | Binary chunk score; trước IL chưa có stage head được đánh giá | Kairos/FLASH/OCR-APT/CPD/APT-CGLP có đầu ra graph/narrative/hunting chuyên biệt mà F1 dự án chưa đo. |
| Kích thước | 300 cây, file weights 1.305.231 byte | 78.698 tham số | Đều nhỏ gọn. MADELINE/Velox/CPD cũng là các tiền lệ nhẹ; không nên nói mọi hệ khác cần GPU lớn. |
| Chi phí train gốc | Artifact hiện tại không có thời gian train đủ tin cậy | Tổng elapsed history ≈1.081,47 s, khoảng 18 phút trên Kaggle | Không dùng số train/inference sau IL để chứng minh tốc độ trước IL. Không tính speedup xuyên paper khi thiếu cùng phần cứng và pipeline. |

Về FPR DL=0, chỉ có thể nói không quan sát FP trong TEST này. Nếu giả định các benign sample độc lập, giới hạn trên một phía 95% từ 0/34.331 khoảng 0,00873%; do tương quan chunk/host, giả định đó còn lạc quan. Không được diễn giải zero FP quan sát thành tỷ lệ FP ngoài thực tế bằng 0.

## Các phép so sánh cần loại khỏi bảng OpTC

- MAGIC gốc: đánh giá DARPA TC E3, StreamSpot, Unicorn Wget; không lấy F1 TC E3 để điền OpTC. Số MAGIC trên OpTC nếu dùng phải ghi nguồn tái đánh giá như Bilot et al.
- ORTHRUS gốc: E3/E5; tương tự chỉ dùng số OpTC từ các nghiên cứu chạy lại phù hợp.
- ThreaTrace gốc không có benchmark OpTC; các số OpTC thường là FLASH/TAPAS tái chạy.
- SLOT, SHAPE, Dinspector, EagleEye, TFLAG và các phương pháp dùng DARPA TC/CICAPT-IIoT/dataset riêng: chỉ thêm khi xác minh được một kết quả OpTC cụ thể; tên DARPA không đủ để coi cùng dataset.
- StageFinder có pretraining OpTC nhưng F1≈96% là stage classification trên DARPA TC E5; không điền vào bảng binary detection OpTC. [Nguồn](https://arxiv.org/abs/2603.07560).
- SAGA và Unraveled là nghiên cứu sinh dữ liệu/benchmark, không tự động có F1 detector trên OpTC chỉ vì nhắc OpTC.
- Các survey và paper IL, iCaRL, DER, episodic memory, Toolscaler, StructCoder, LOL/PowerShell/log parsing không cung cấp đối thủ OpTC trước IL nếu không có thực nghiệm OpTC tương ứng.
- Guerra et al. v4 **How Benchmarks and Evaluation Protocols Shape Conclusions** loại OpTC khỏi benchmark chính vì điều kiện nhãn/audit; không lấy các số ATLASv2 hoặc E3 của bài để điền OpTC. [Nguồn](https://arxiv.org/abs/2608.01454).

## Cách phát biểu phù hợp trong luận văn

“Trên các phân vùng OpTC của nghiên cứu này, LightGBM kết hợp ngữ cảnh tiến trình cha và tương tác incoming đạt F1 lớp tấn công 99,63%, còn BiLSTM đạt 98,77%. Kết quả có cùng mức hoặc cao hơn nhiều số OpTC đã công bố; tuy nhiên, khác biệt về cohort, nhãn, đơn vị đánh giá và mức độ giám sát ngăn cản kết luận vượt trội trực tiếp. Cải thiện được kiểm chứng rõ nhất là LightGBM có context so với baseline cùng TEST. Đối với BiLSTM, các baseline luật đơn giản và sự giao nhau giữa host ở TRAIN/TEST cho thấy cần thêm đánh giá độc lập để xác lập giá trị của mô hình chuỗi.”

Để kiểm tra thứ hạng phương pháp, cần một benchmark bổ sung riêng: cùng corrected OpTC, cùng nhãn và cohort, split theo thời gian hoặc host/campaign, calibration trên VAL, baseline lexical/allowlist/MLP/histogram/LightGBM và một vài PIDS được chọn. Phải báo attack F1, AP, recall tại các mức FPR, false alerts/host/day, theo từng scenario và nhiều seed. Đây là thiết kế đề xuất; chưa thực hiện và không thay đổi split/model đang đóng băng.
