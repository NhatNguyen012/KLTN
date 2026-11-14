# Threat hunting và soạn kịch bản APT cho lab KLTN — tài liệu tham khảo và ràng buộc của hạ tầng

Cập nhật 14/11/2026.
- Mọi nguồn dưới đây đã được kiểm tra là có thật (tên, tác giả, nơi công bố) bằng tìm kiếm web ngày 14/11/2026.
- Với các luận văn, thông tin chỉ lấy từ trang thư viện và abstract; toàn văn chưa được đọc.
- Repo chỉ chứa phương pháp và ràng buộc của hạ tầng. **Không có kịch bản hay code tấn công** (`red-team/` để trống); kịch bản do người làm đề tài tự soạn.

## 1. Phương pháp hunting (nên đọc theo thứ tự)

- **MITRE — [TTP-Based Hunting](https://www.mitre.org/sites/default/files/2021-11/prs-19-3892-ttp-based-hunting.pdf)** (R. Daszczyszak, D. Ellis, S. Luke, S. Whitley; MTR180158, 3/2019).
  - Hunt theo hành vi (TTP) thay vì IOC: mô hình hoá hành vi → xác định dữ liệu cần có → viết analytic → kiểm bằng emulation.
  - Áp dụng thẳng cho lab: bộ rule auditd SL700 (`kltn.rules`) vốn đã gắn key theo technique ATT&CK.
- **[MITRE Active Defense Capability Set — Technical Manual](https://info.mitre-engenuity.org/hubfs/ATTACK%20Evals/MITRE_ActiveDefenseCapabilitySet_TechnicalManual.pdf)** (MITRE Engenuity, 4/2022): quy trình hunting 7 bước dựa trên báo cáo trên, có yêu cầu dữ liệu Sysmon cho từng technique.
- **[PEAK](https://www.splunk.com/en_us/blog/security/peak-threat-hunting-framework)** (Splunk SURGe; D. Bianco, R. Fetterman).
  - Prepare → Execute → Act with Knowledge.
  - Ba kiểu hunt: theo giả thuyết, theo baseline, và có model hỗ trợ. Kiểu thứ ba đúng là cách lab này dùng hai model.
- **[TaHiTI](https://www.nvb.nl/media/rygbrwew/def-tahiti-threat-hunting-methodology.pdf)** (FI-ISAC NL, v1.0, 12/2018): hunting dẫn dắt bởi threat intel, có quy trình và cách ghi chép từng lần hunt.
- **R. M. Lee, D. Bianco — [Generating Hypotheses for Successful Threat Hunting](https://www.sans.org/white-papers/37172)** (SANS, 8/2016): ba loại giả thuyết và khi nào dùng loại nào; giả thuyết phải kiểm chứng được bằng dữ liệu đang có.
- **B. Nour, M. Pourzandi, M. Debbabi — [A Survey on Threat Hunting in Enterprise Networks](https://www.ericsson.com/en/reports-and-papers/research-papers/threat-hunting-enterprise-networks)** (IEEE Communications Surveys & Tutorials 25(4), 2023, doi:10.1109/COMST.2023.3299519): tổng quan học thuật, dùng cho phần related work.
- **W. P. Maxam III, J. C. Davis — [An Interview Study on Third-Party Cyber Threat Hunting Processes in the U.S. DHS](https://arxiv.org/abs/2402.12252)** (USENIX Security 2024): phỏng vấn 11 threat hunter; quy trình thực tế khác lý thuyết ra sao.

## 2. Soạn kịch bản (adversary emulation)

- **[CTID Adversary Emulation Library](https://github.com/center-for-threat-informed-defense/adversary_emulation_library)** (MITRE Engenuity Center for Threat-Informed Defense, Apache 2.0).
  - Kế hoạch emulation đầy đủ theo từng nhóm APT (ví dụ FIN6, menuPass, APT29), mỗi bước gắn technique ATT&CK.
  - Có thêm các "micro emulation plan" cho từng hành vi riêng lẻ.
  - Đây là mẫu tốt nhất để học cách viết kịch bản từ threat intel.
- **[SCYTHE Purple Team Exercise Framework (PTEF)](https://github.com/scythe-io/purple-team-exercise-framework)**: cách tổ chức một buổi purple team (lập kế hoạch, CTI, thực thi, rút kinh nghiệm).
- **M. Landauer, W. Hotwagner, T. Boenke, F. Skopik, M. Wurzenberger — [AttackMate: Realistic Emulation and Automation of Cyber Attack Scenarios Across the Kill Chain](https://arxiv.org/abs/2601.14108)** (arXiv, 1/2026).
  - Đây là công cụ đã sinh dữ liệu AInception SL700, tức domain Linux mà hai model được train.
  - Bài lập luận rằng log của công cụ dùng agent (Caldera, Atomic Red Team) khác log của attacker thật. Nên đọc trước khi chọn cách thực thi kịch bản (mục 7, điểm 5).

## 3. Dataset làm mẫu thiết kế kịch bản và ground truth

Ba dataset đầu là nguồn train của hai model, nên kịch bản lab càng gần cách chúng được tạo thì kết quả càng dễ so sánh.

- **[The AInception Dataset](https://zenodo.org/records/17659656)** (SL100/SL300/SL700): mỗi run có timeline AttackMate, là mẫu tốt cho nhật ký red team (mục 8).
- **A. Riddle, K. Westfall, A. Bates — [ATLASv2: ATLAS Attack Engagements, Version 2](https://arxiv.org/abs/2401.01341)**: 4 ngày benign do hai nhà nghiên cứu dùng máy như máy làm việc thật, sau đó 1 ngày chạy 10 kịch bản tấn công.
- **[DARPA OpTC](https://github.com/FiveDirections/OpTC-data)**: benign trước, red team sau; có PDF ground truth của red team.
- **M. Landauer và cộng sự — [Maintainable Log Datasets for Evaluation of Intrusion Detection Systems](https://arxiv.org/abs/2203.08580)** (AIT-LDS v2).
  - Testbed doanh nghiệp nhỏ, người dùng mô phỏng bằng state machine, tấn công nhiều bước.
  - Chạy lặp với tham số khác nhau và gán nhãn tự động; đúng thứ cần để có nhiều incident.

## 4. Luận văn tham khảo (cấu trúc thí nghiệm gần đề tài)

- **Zargham Ahmad — [Emulation and Detection of Cyber Threat Scenarios](https://theses.cz/id/begzs4?lang=en)** (Masaryk University, Faculty of Informatics, 2024): kịch bản Caldera tổ chức theo kill chain/ATT&CK, phát hiện bằng Wazuh SIEM. Gần setup của lab nhất.
- **T. Mokoena — [A methodological approach to investigating lateral movement attacks using a threat hunting architecture](https://repository.nwu.ac.za/bitstreams/0897121c-17b9-48a5-869e-2ffbdf4a9c40/download)** (North-West University): TaHiTI + ATT&CK, thực nghiệm mô phỏng lateral movement.
- **Fulvio Colombrino — [Threat Hunting: detection of LoLbin attacks in a large distributed enterprise infrastructure](https://www.politesi.polimi.it/handle/10589/204806)** (Politecnico di Milano, 2022/23, hướng dẫn: S. Zanero): luật phát hiện theo TTP cho LOLBins ở nhiều pha kill chain, kiểm trong môi trường thử.
- **Roman Chrenšť — [Detection of Malicious Behavior in Sysmon Audit Events](https://theses.cz/id/z2egbw?lang=en)** (Masaryk University, thạc sĩ): Sysmon trên Windows và Linux, ánh xạ hành vi phát hiện được sang ATT&CK.

## 5. Hunting trên audit log / provenance (related work)

- **S. M. Milajerdi và cộng sự — [HOLMES: Real-time APT Detection through Correlation of Suspicious Information Flows](https://arxiv.org/abs/1810.01594)** (IEEE S&P 2019): ánh xạ event audit lên các stage APT (initial compromise, establish foothold, …). Cùng ý tưởng với stage head của model DL.
- **S. M. Milajerdi, B. Eshete, R. Gjomemo, V. N. Venkatakrishnan — [POIROT: Aligning Attack Behavior with Kernel Audit Records for Cyber Threat Hunting](https://arxiv.org/abs/1910.00056)** (ACM CCS 2019): hunting là bài toán so khớp gần đúng giữa đồ thị hành vi lấy từ threat intel và đồ thị provenance dựng từ kernel audit.
- **P. Gao và cộng sự — [Enabling Efficient Cyber Threat Hunting With Cyber Threat Intelligence (ThreatRaptor)](https://github.com/peng-gao-lab/threatraptor)** (IEEE ICDE 2021): từ báo cáo CTI tự sinh truy vấn TBQL trên audit log; có mã nguồn.

## 6. Không nên trích

- **S-DAPT-2026** ([arXiv 2601.06690](https://arxiv.org/abs/2601.06690)): tác giả đã rút bài ngày 1/4/2026 vì lỗi phân tích ảnh hưởng đến kết luận chính.

## 7. Ràng buộc từ hạ tầng KLTN khi soạn kịch bản

1. **Chuỗi stage.**
   - Mỗi đợt nên đi qua các stage mà head của model DL dự đoán: `initial_compromise` → `execution_discovery` → `lateral_movement` → `exfiltration` / `impact`. Ô chọn stage khi review trên SOC dùng đúng các giá trị này.
   - Mỗi bước ghi kèm technique/tactic ATT&CK và telemetry kỳ vọng: key rule auditd (`kltn.rules`) hoặc EID Sysmon (`sysmon.xml` v3). Cách ánh xạ stage ↔ tactic do người làm đề tài tự chọn và ghi rõ trong luận văn.
   - Bước nào sensor không ghi lại thì model không thể thấy. Đây chính là "yêu cầu dữ liệu" trong TTP-Based Hunting, nên kiểm tra trước khi chạy.
2. **Số đợt.**
   - Gate IL (`scripts/il/dataset.py`) cần, cho mỗi domain: ≥ 3 incident được xác nhận có nhãn event tấn công, ≥ 20 event tấn công, ≥ 2000 event benign, và có tấn công ở cả VAL lẫn TEST.
   - Split theo thời gian incident 60/20/20, nên 3 incident chỉ cho 1 train / 1 val / 1 test. Nên chạy ≥ 5 đợt mỗi OS.
   - Đợt cuối nên dùng biến thể kỹ thuật khác (ví dụ cơ chế persistence hay lateral movement khác) để đo khả năng tổng quát một cách trung thực, như fold e_a của SL700.
3. **Mỗi đợt phải thành một incident riêng.**
   - Bucket dương cách nhau ≤ 15 phút được gộp vào alert `needs_review` đang mở. Workload benign trên Ubuntu sinh FP liên tục.
   - Vì vậy cần review alert đang mở **ngay trước và ngay sau** mỗi đợt; nếu không, nhiều đợt sẽ bị gộp thành một incident.
4. **Nhãn trên SOC.**
   - Alert **Confirmed**: event được tick là tấn công; event không tick là `unknown`, không dùng để train và cũng không bị coi là benign.
   - Alert **False positive**: mọi event trong cửa sổ alert ±30 phút là benign.
   - Quarantine/release chỉ request được trên alert đã Confirmed. Lab dùng chính sách duyệt `single_operator`: người yêu cầu tự duyệt được, và lần duyệt được ghi vào `execution.approval`.
5. **Cách thực thi là một quyết định thiết kế thí nghiệm.**
   - SL700 được sinh bằng AttackMate (không agent); ATLASv2 do người làm tay; OpTC do red team.
   - Nếu dùng công cụ có agent (Caldera, Atomic Red Team), model có thể học dấu vết của agent thay vì kỹ thuật tấn công. Nên ghi rõ lựa chọn này trong luận văn.
6. **Vùng sensor bỏ qua.**
   - Sensor không ghi `connect()` của Fluent Bit và uid `kltn-agent` trên Ubuntu, cũng như event mạng/DNS/registry của `C:\KLTN\agent\` và `C:\KLTN\packages\fluent-bit\` trên Windows.
   - Hoạt động tấn công đặt ở các vùng đó sẽ không được ghi, làm kết quả sai lệch.
7. **Chuẩn bị và an toàn.**
   - Chụp snapshot VM trước mỗi đợt để reset.
   - Mọi hạ tầng tấn công nằm trong mạng lab, chỉ nhắm các VM của lab.
   - Ghi lại trạng thái workload benign (chạy hay tạm dừng) cho từng đợt.
8. **Sau mỗi đợt.**
   - Hunt trên `/soc` theo giả thuyết của từng stage, tick event tấn công rồi bấm Confirmed.
   - Dùng `collect_evidence` để lưu bằng chứng (raw + host events ±30 phút, có sha256).
   - Khi đủ incident thì chạy IL từ nút **Model lifecycle**.

## 8. Mẫu nhật ký red team (ground truth)

Mỗi bước một dòng, giờ UTC. Lưu cùng dữ liệu thí nghiệm, không cần đưa vào repo. Nhật ký này dùng để tick event trên SOC và để tính metric.

| run | bước | UTC bắt đầu | UTC kết thúc | host | user | stage (model) | ATT&CK tactic / technique | hành động (tóm tắt) | telemetry kỳ vọng (key auditd / EID Sysmon) | ghi chú |
|---|---|---|---|---|---|---|---|---|---|---|
| | | | | | | | | | | |

## 9. Metric gợi ý cho luận văn

- **Theo event và theo cửa sổ, cho từng stage**: precision, recall, F1 (từ nhãn SOC và nhật ký red team).
- **Độ trễ phát hiện**: thời gian từ khi bắt đầu một bước đến alert/score đầu tiên vượt ngưỡng.
- **FP mỗi host-giờ** trong giai đoạn chỉ có workload benign.
- **Sau IL**: các metric trên trước và sau, cộng mức quên trên domain cũ (gate: F1 VAL của mỗi domain cũ giảm ≤ 0,02).
- **Windows/Sysmon**: đây sẽ là số đo độ chính xác đầu tiên trên Sysmon; hiện domain này vẫn ở trạng thái `shadow_unvalidated`.
