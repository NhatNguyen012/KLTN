**Tư vấn dataset, phạm vi nghiên cứu và ontology — 14/10/2026**

**Cập nhật sau khi người dùng làm rõ:** Nhánh BiLSTM/Mixed-type Self-Attention của cộng sự được giữ và dùng cửa sổ 15 phút với host activity/communication context. Xem [bản tư vấn và hình ontology chính mới](image/host_multisource_ontology_v2/README.md); bản đó thay thế lựa chọn dataset ưu tiên và sơ đồ triển khai trong tài liệu này. Nguồn gốc Zeek của trường lấy từ `bro` vẫn phải được ghi đúng, dù được ghép với host logs.

Tài liệu này đối chiếu lời góp ý của giảng viên, hai đề cương, `apt.png`, kết quả cascade mà người dùng chỉ định, mã MORPH-IDS cục bộ và các nguồn dataset chính thức. Đây là đề xuất nghiên cứu, không phải báo cáo đã tải dữ liệu mới hoặc đã thực hiện thí nghiệm mới. Không thay đổi pipeline, frozen seed02, checkpoint, dataset gốc hay hình `apt.png`.

**Cách hiểu yêu cầu của thầy.** Theo ảnh trao đổi, thầy cho phép dùng nguồn khác ngoài Enterprise Windows/OpTC, và cho phép mở rộng số dataset nếu chưa tìm được nhãn multi-label phù hợp. Cách hiểu hợp lý là mở rộng độ đa dạng và sức thuyết phục của thực nghiệm. Tin nhắn không quy định phải gộp toàn bộ dữ liệu, không bắt buộc fine-tuning và không nói rằng nhiều dataset tương đương multi-label. Việc thầy muốn chứng minh điều gì — portability, transfer, một model chung hay incremental adaptation — cần được diễn đạt thành câu hỏi nghiên cứu rõ ràng trong đề cương.

**1. Ba dataset đề xuất**

| Dataset | Hệ điều hành và nguồn | Vai trò đề xuất | Điều phải kiểm tra trước khi dùng |
|---|---|---|---|
| CITAR / `skrghosh/apt-dataset`: FIN6, APT29, menuPass, OilRig, Wizard Spider | Windows 10; audit JSON theo CAR/eCAR; có benign background và ground truth riêng | Ưu tiên đầu tiên vì gần schema OpTC; kiểm tra transfer và khả năng tái huấn luyện trên chiến dịch khác | Tái dựng nhãn có chứng cứ từ ground truth; không mặc định đã có multi-label từng event. Không lấy các liên kết **OpTC Day-1/Day-2** trong README làm dataset mới. |
| Windows-APT 2025 | Windows 10; Wazuh/Sysmon; 36 kịch bản, khoảng 102 nghìn records theo trang tác giả | Kiểm tra sensor/domain shift và mở rộng kịch bản Windows | Kiểm tra raw fields, benign coverage, nhãn và parent/process IDs; ATT&CK mapping chưa chứng minh multi-label từng record. |
| DARPA Transparent Computing E3, chọn THEIA | Ubuntu Linux; host provenance CDM18/Avro; có công cụ chuyển JSON và báo cáo ground truth | Kiểm tra nhánh learned provenance graph trên Linux | Cần adapter CDM→schema chung và chính sách nhãn. Báo cáo/IoC không phải ma trận nhãn từng event có sẵn. Chỉ dùng topic mà release xác định dữ liệu hợp lệ. |

Nguồn: [CITAR và giấy phép CC BY 4.0](https://github.com/skrghosh/apt-dataset), [ground truths CITAR](https://github.com/skrghosh/apt-dataset/tree/main/Ground_Truths); [Windows-APT: mô tả tác giả](https://cybersciencelab.com/datasets/windows-apt-2025/), [release V4 ngày 03/07/2026, CC BY 4.0](https://data.mendeley.com/datasets/b8fmtzvpy8/4); [DARPA TC E3: dữ liệu public domain, schema, ground truth, topic hợp lệ](https://github.com/darpa-i2o/Transparent-Computing/blob/master/README-E3.md), [UNICORN, trang 8: THEIA trên Ubuntu Linux](https://www.ndss-symposium.org/wp-content/uploads/2020/02/24046-paper.pdf).

THEIA được chọn vì phù hợp với provenance, không phải vì là dataset mới nhất. Nó là một subset của **DARPA TC**, khác OpTC; không tính các file/topic trong THEIA là nhiều dataset độc lập. Các trang công bố/download đã được kiểm tra; chưa tải archive để xác nhận schema và độ đầy đủ thực tế.

Các nguồn thầy gửi còn lại:

- [SAGA — trang dataset hiện tại](https://www.saga-cyber.net/dataset) có audit logs tổng hợp và nhãn sự kiện; [paper](https://arxiv.org/html/2411.13138v2) dùng Windows/Procmon. Đây là ứng viên tốt cho thí nghiệm bổ sung dữ liệu tổng hợp/technique detection, nhưng không thay thế phần Linux. Nên bắt đầu bằng tập nhỏ, không lấy toàn bộ training corpus 5,1 TB ngay. Chia theo template/campaign để tránh biến thể cùng mẫu lọt sang TEST. URL GitHub Pages cũ không mở được qua công cụ tra cứu; không khẳng định đó là một redirect đã xác minh.
- [Multi-Source Cybersecurity Logs, arXiv:2606.18190](https://arxiv.org/html/2606.18190v1) mô tả Windows 10/11, 870 phiên, khoảng 2,3 triệu events từ system/network/browser. Paper có nhãn ATT&CK và gom bảy sự kiện thành chunk. Chunk có nhiều techniques không đồng nghĩa mọi event có nhiều nhãn. Trong bản đã kiểm tra chưa xác định được repository tải dataset và giấy phép dữ liệu công khai; vì vậy chưa chọn làm một trong ba nguồn sẵn sàng tích hợp. Có thể chỉ dùng system/browser theo phạm vi host mới.
- [Linux-APT 2024 V2](https://data.mendeley.com/datasets/5x68fv63sh/2) là phương án Linux nhỏ để pilot tabular. Release mô tả Wazuh CSV/XLSX và cách đặt nhãn 0/1 theo TTP. Phải loại trường TTP/rule tạo nhãn khỏi feature; chưa có bằng chứng đủ lineage để thay THEIA trong thí nghiệm graph.

Không dataset nào ở trên tự chứng minh có đầy đủ **orchestration/Kubernetes audit logs**. Đa hệ điều hành, đa dataset và đa loại nguồn log là ba chiều khác nhau.

**2. Model hiện tại đã làm được gì?**

[Kết quả TEST được người dùng chỉ định](../code/output/provenace_graph/kaggle_output/lgbm-two-stage-cascade-results/two_stage_cascade_metrics.json) đo trên 1.249.689 events:

| Chỉ số | LightGBM | LightGBM + GraphSAGE |
|---|---:|---:|
| Precision | 98,813% | 98,439% |
| Recall | 92,089% | 98,566% |
| F1 | 95,332% | 98,503% |
| False positives | 446 | 630 |
| False negatives | 3.189 | 578 |
| False-positive rate | 0,03688% | 0,05209% |

F1/recall tăng, FP cũng tăng. Đây là kết quả có giá trị của cascade trên frozen seed02. Metadata ghi rõ phạm vi **random event generalization only**. [README chính](../code/README.md) và [graph design](../code/provenace_graph/docs/DESIGN.md) giải thích giới hạn: host/process có thể xuất hiện ở nhiều partition; ngữ cảnh quá khứ không nhãn được dùng theo cách transductive; cohort được xác định từ cửa sổ tấn công. Chưa thể suy rộng các con số thành kết quả trên Linux, host mới, chiến dịch chưa biết hay distribution vận hành tự nhiên.

[GraphSAGE loss](../code/provenace_graph/model/relational_sage.py) dùng nhãn 0/1. Ba dải score để routing không phải ba lớp benign/known malicious/unknown malicious. Một binary model có thể phát hiện được một số tấn công chưa thấy, nhưng phải có thí nghiệm giữ lại chiến dịch/technique để chứng minh; bản thân score không cho biết tấn công là known hay unknown.

| Thuật ngữ | Ý nghĩa | Ví dụ |
|---|---|---|
| Binary | Một trong hai lớp | benign hoặc malicious |
| Multi-class | Một lớp trong nhiều lớp | benign hoặc một loại tấn công trong danh mục loại trừ nhau |
| Multi-label | Một mẫu có thể mang đồng thời nhiều nhãn | một cửa sổ log có tập techniques `{T1, T2, T3}` |
| Multi-source | Nhiều loại nguồn quan sát | OS/security, application, orchestration |
| Multi-dataset | Nhiều bộ dữ liệu | OpTC, CITAR, Windows-APT, THEIA |
| Open-set/unknown | Đánh giá với lớp/kiểu tấn công giữ lại khỏi TRAIN | giữ riêng một campaign và đồng thời kiểm tra benign domain shift |

Benign/known-malicious/unknown-malicious, nếu dùng như ba lựa chọn loại trừ nhau, vẫn không phải multi-label. Chỉ có nhãn binary thì không được tự suy ra nhãn ATT&CK từ dự đoán rồi coi đó là ground truth. Nhãn technique bị thiếu phải được biểu diễn là **unknown/unannotated**, không mặc định negative.

**3. Vai trò và thứ tự thí nghiệm cho dataset mới**

| Thí nghiệm | Train | Test | Câu hỏi được trả lời |
|---|---|---|---|
| Baseline đã có | OpTC TRAIN seed02 | OpTC TEST seed02 | Chất lượng trong setting hiện tại |
| Tái lập phương pháp | TRAIN riêng của mỗi dataset, khởi tạo model riêng | TEST riêng của dataset đó | Phương pháp có áp dụng được cho nguồn khác? |
| Transfer không cập nhật | Chỉ OpTC TRAIN; giữ nguyên model/schema/threshold | Dataset đích chưa dùng để fit/tune | Checkpoint hiện tại tổng quát hóa được đến đâu? |
| Huấn luyện chung | Hợp các TRAIN partitions sau chuẩn hóa | TEST riêng của từng nguồn, không đưa vào fit | Thêm dữ liệu có cải thiện và có gây negative transfer? |
| Adaptation | Model OpTC → target TRAIN, có replay phù hợp | Target TEST và old-domain TEST | Cập nhật có cải thiện domain mới và gây quên domain cũ? |

Ưu tiên khả thi: giữ baseline; làm CITAR adapter/label audit; chạy tái lập và transfer; mở rộng Windows-APT/THEIA; sau đó mới thí nghiệm huấn luyện chung hoặc adaptation. Đánh giá external chỉ trả lời generalization, chưa làm model học thêm. Muốn chứng minh lợi ích học thêm phải có đối chứng OpTC-only so với training thêm nguồn, với cùng held-out target TEST và chế độ feature/compute được mô tả.

LightGBM hiện tại nên có đối chứng **retrain model mới** từ TRAIN đã chuẩn hóa. Không dùng từ fine-tuning theo nghĩa cập nhật trọng số neural một cách chung cho cả cascade. GraphSAGE có thể khởi tạo từ checkpoint cũ và fine-tune nếu feature dimensions, quan hệ, preprocessing và ý nghĩa nhãn tương thích. Đổi schema/vocabulary thì phải xử lý compatibility hoặc train mới. Cả hai stage thay đổi thì chọn lại routing/threshold bằng validation.

Adapter chung có thể xuất các trường: `event_time`, `observed_time`, `host_key`, `os_family`, `source_type`, `actor_key`, `action`, `object_type`, `object_key`, `parent_key`, `attributes`, `availability_mask`. Đây là thiết kế đề xuất. Giữ process/host IDs có namespace `(dataset, host, boot/session, process_identity)` để join, không dùng UUID/PID/tên campaign làm feature. Không tạo ancestry giả khi nguồn thiếu parent ID. Linux cần mapping action/path/command khác Windows, không chỉ đổi tên cột.

Trước khi nhận một dataset vào thí nghiệm:

1. Xác định unit dự đoán và nhãn: event, process, window hay campaign. Nếu không đủ nhãn từng event, đánh giá ở unit có ground truth tin cậy hoặc công bố đây là weak-label protocol; không ép nhãn.
2. Tách annotation/rule/ATT&CK/campaign columns khỏi telemetry feature. Nếu Wazuh rule quyết định nhãn, không đưa chính rule đó vào input và gọi đây là phát hiện độc lập.
3. Kiểm tra file trùng, nguồn chia sẻ và train/test contamination. Cẩn thận consolidated CSV so với các CSV thành phần.
4. Tách theo host/session/campaign/time khi phù hợp; nhóm các biến thể từ cùng template. Giữ nguyên baseline seed02, tạo experiment mới với split mới riêng.
5. Fit vocabulary/transforms chỉ trên TRAIN được phép. Transfer frozen phải báo unknown-token rate và thiếu graph context; không âm thầm refit bằng target TEST.
6. Graph tại thời điểm t chỉ dùng bằng chứng quan sát được đến t, tuyệt đối không dùng nhãn thật của ancestor hay tương lai. Tránh gán toàn bộ hàng xóm/descendants là malicious chỉ vì liên quan một process tấn công.
7. Báo riêng từng dataset: precision, recall, PR-AUC, FPR, FP/host/time khi có exposure, latency và chi phí graph. Giữ prevalence thực khi đánh giá. Multi-label bổ sung micro/macro-F1 và per-technique precision/recall; không coi missing label là negative.

Không chạy huấn luyện hay tải toàn bộ dataset trong lần tư vấn này.

**4. Vẽ lại architecture theo ý thầy**

Hai tài liệu gốc vẫn mô tả phạm vi cũ:

- [NCKH PDF](<image/NCKH - Võ Ngọc Hoàng Lâm - Nguyễn Nhật Nguyễn.pdf>), trang 4–7: host provenance + network telemetry, nhãn 0/1, Bro/Zeek/eCAR-Bro, host-only/network-only/fusion và thử nghiệm mất nguồn.
- [Đề cương KLTN](image/DeCuongKLTN_23521047_NguyenNhatNguyen_23520839_VoNgocHoangLam.pdf), trang 2–5: Host ML + Network DL, Central VM, packet tap và continual learning. Trang 4 còn giới hạn hai nguồn host/network, chưa mở rộng application/cloud.

Theo góp ý mới, cần sửa mục tiêu/input/ablations/demo cùng hình: **OS/security + application + orchestration logs**. Có thể giữ đóng góp đo được dưới tên **Lightweight Host ML + learned provenance context cascade**. Không bắt buộc giữ nguyên danh sách GraphSAGE/GAT/BiLSTM/cross-attention nếu chúng không còn phục vụ câu hỏi nghiên cứu mới.

`apt.png` hiện trộn ba khía cạnh trong một hình: đối tượng miền bài toán, module xử lý, và máy triển khai. Cách trình bày rõ là ba view, trong đó ontology là hình chính; deployment và lifecycle giải thích chỗ đặt module và trigger. Từ lời thầy có thể suy ra thầy cần rõ thực thể/quan hệ và module placement; chưa có căn cứ rằng thầy bắt buộc một OWL reasoning engine.

[Bản draw.io chỉnh sửa được, ba trang](image/host_ontology_2026-10-14/host_ontology_architecture.drawio). Các ảnh cùng thư mục minh họa ontology, deployment và learning lifecycle. Các hình là đề xuất, không chứng nhận hệ thống đã được triển khai.

**Ontology mô tả những gì tồn tại và chúng quan hệ thế nào.** Ví dụ:

```text
Process --runsOn--> Host
HostEvent --performedBy--> Process
HostEvent --targets--> Resource
LogSource --records--> HostEvent
EndpointAgent --monitors--> Host
EndpointAgent --uses--> ModelVersion
Detection --supportedBy--> HostEvent
Detection --producedBy--> ModelVersion
TechniqueAnnotation --annotates--> HostEvent/window
VM --hosts--> Container --runs--> SoftwareService
TrainingJob --uses--> DatasetSnapshot
TrainingJob --produces--> ModelVersion
```

Phân biệt class/instance: `Host` là class; `host-001` là instance. `VM`, `Container`, `Service`, `ModelVersion` không phải cùng một loại đối tượng. Một VM có thể host nhiều containers; một service có thể được triển khai thành nhiều replicas. LogSource có các loại OS/security/application/orchestration; orchestration audit có thể phát sinh ở control plane, không phải lúc nào cũng ở endpoint.

Các quan hệ cần định nghĩa domain/range và multiplicity hợp lý. Ví dụ một process instance thuộc một host đã namespace; một Detection có một hoặc nhiều events làm bằng chứng và ghi rõ model/policy version. Field thiếu phải cho phép unknown. TechniqueAnnotation cần ghi nguồn annotation, mức tin cậy và unit được annotate, tách khỏi feature inference. Các source logs phải có timestamp và provenance; source masks biểu diễn nguồn vắng mặt, không tạo log giả để lấp chỗ trống.

[W3C PROV-O](https://www.w3.org/TR/prov-o/) là nguồn tham khảo cho class/property và provenance. Nếu cần formal hóa tiếp, có thể dùng RDF/OWL và constraint validation; ba sơ đồ hiện tại là **conceptual ontology + deployment/lifecycle views**, chưa phải ontology OWL đã kiểm chứng. Một GNN provenance graph không tự đồng nghĩa với ontology đầy đủ.

[Graph README hiện tại](../code/provenace_graph/README.md) đã có Host/Process, CREATE lineage và eCAR FLOW communication. Host-observed connection là bằng chứng endpoint, khác sensor Zeek/packet capture độc lập. Nếu thầy muốn loại cả loại bằng chứng này, cần một ablation riêng; không âm thầm coi kết quả cũ là kết quả của mô hình đã bỏ FLOW.

**Triển khai đề xuất.** End host chạy native collector/normalizer, lightweight ML và local buffer. Có thể thêm coordinator agentic để gọi công cụ truy vấn bằng chứng và gửi alert theo policy, nhưng đây là thành phần mới cần đánh giá. Gọi một daemon là agent không chứng minh nó có agentic reasoning; MARL agent cũng không đồng nghĩa LLM agent.

Một Central VM có thể chứa các container/service: ingestion + normalization; causal context + GraphSAGE; decision/correlation; monitoring/review; training worker; model registry. Training worker có thể tách sang worker khác khi thiếu tài nguyên. VM là deployment boundary, không phải bản thân một module DL. Việc truyền log qua mạng không có nghĩa mạng L3/L4 là nguồn feature.

Nên gửi evidence/context cần thiết và mẫu benign phục vụ monitoring, không chỉ các event ML đã đánh malicious, nếu không có thể mất antecedent và không đo được drift/false-positive distribution. Thiết kế sampling/retention phải mô tả cụ thể khi triển khai.

**Known/unknown cần được định nghĩa.** Bản thiết kế có thể dùng ba trạng thái vận hành: benign, detected malicious, suspicious/unknown. Muốn tách malicious-known và malicious-unknown cần định nghĩa tập attack đã biết, cơ chế novelty/open-set, cùng bằng chứng xác nhận. Low confidence có thể do benign mới, thiếu log hoặc sensor shift; nó không chứng minh maliciousness. Có thể dùng hai trục `risk` và `novelty` rồi map sang quyết định vận hành; hai score đó vẫn không phải bằng chứng đã có multi-label technique prediction.

**5. Trigger incremental learning phải cụ thể**

Đề xuất một policy, chưa phải threshold đã đo:

```text
Sustained drift OR reviewed performance degradation OR enough confirmed new examples
    → UpdateRequest (monitor chỉ yêu cầu, không tự sửa model)
    → eligibility: label quality + sample minimum + schedule/cooldown + resource budget
    → DatasetSnapshot: new reviewed data + replay from allowed historical TRAIN
    → TrainingJob: retrain ML / fine-tune compatible GraphSAGE
    → Candidate evaluation: recent validation + old-domain validation + FPR/cost limits
    → pass: registry version + staged deployment; fail: keep current version
```

Unknown alert tạo yêu cầu điều tra/thu thập bằng chứng. Nhãn được xác nhận tạo dữ liệu học; không tự dùng prediction làm nhãn thật. Drift cần được xác nhận và phân biệt thay đổi benign workload/schema với attack drift. Model candidate phải giữ được performance trên miền cũ; rollback dùng version trước. TEST cố định dùng để báo cáo sau khi policy được freeze, không lặp lại dùng TEST để quyết định promote.

Trong báo cáo, **continual learning** là mục tiêu quản lý học qua thời gian; có thể thực hiện bằng batch retraining. **Incremental update** là tiếp tục cập nhật model; **fine-tuning** là một dạng adaptation đối với model tương thích. Không phải mọi classifier đều hỗ trợ cùng một thao tác online.

**6. MORPH-IDS thực sự dùng nhiều dataset thế nào?**

[README của bản mã cục bộ](../paper-general/code/MORPH-IDS/README.md) và notebooks thể hiện:

| Dataset | Các thí nghiệm |
|---|---|
| CIC-IDS2017 | Scenario 1: detection; Scenario 2: adversarial robustness; Scenario 3: temporal/synthetic drift |
| CIC-DDoS2019 | Scenario 1; folder gọi CIC-IDS2019 nhưng README trỏ tới CIC-DDoS2019 |
| CIC-APT-IIoT-2024 | Scenario 1: detection; Scenario 4: streaming APT/adaptation |

Notebook riêng tạo preprocessing/model riêng cho từng dataset. Có concat các CSV/ngày/phase **trong một dataset**; không tìm thấy quy trình gộp cả ba dataset thành một training set chung hay fine-tune lần lượt qua ba domain. Vì vậy, ở đây nhiều dataset chủ yếu làm bằng chứng phương pháp hoạt động trên nhiều benchmark. Đừng diễn đạt việc train/test riêng trên A và riêng trên B là chứng minh checkpoint train-A→test-B.

Cụ thể:

- [CIC-IDS2017 notebook](../paper-general/code/MORPH-IDS/Scenario1/CIC-IDS2017/morphids-cicids2017.ipynb), raw JSON lines 1119 và 1157–1159: ghép daily CSV, map Benign→0 và attack→1.
- [CICAPT notebook](../paper-general/code/MORPH-IDS/Scenario1/CIC-APT-IIOT-2024/morphids-cicapt.ipynb), raw JSON lines 691–700, 1691–1699: dùng `phase1_NetworkData.csv` và `phase2_NetworkData.csv`, bỏ `subLabel`/`subLabelCat`, output hai lớp, tạo MLP mới. Đây không phải model host provenance hoặc multi-label technique.
- [DDoS2019 notebook](../paper-general/code/MORPH-IDS/Scenario1/CIC-IDS2019/morphids-cicids2019.ipynb), raw JSON line 13963: khởi tạo MLP mới.
- [Scenario 3](../paper-general/code/MORPH-IDS/Scenario3/Scenario3-Drift-Adaption.ipynb), raw JSON lines 2831, 3036, 3517 trở đi: drift threshold, buffer/cooldown và cập nhật gradient model pool; predict rồi nhận true labels để cập nhật. Đây là supervised feedback trong stream, không phải tự nhiên có nhãn khi gặp unknown.

[Hình của họ](../paper-general/code/MORPH-IDS/High-level-design.png) mô tả network traffic, Defender/Attacker, model pool, drift embedding, ADI và continual learning. Đó là kiến trúc module/tương tác huấn luyện. Không phải ontology entity–relation–constraint của Host/Service/Event/Model, cũng không phải deployment VM/container. Có thể học cách làm rõ module và trigger, không cần sao chép nhánh network hoặc MARL. [Paper xuất bản](https://doi.org/10.1016/j.comnet.2026.112541) mô tả framework NIDS; không kiểm chứng riêng thứ hạng Q1 trong lần này.

Một lưu ý tái lập có chứng cứ từ **notebook cục bộ Scenario 4**, không suy rộng thành kết luận về toàn bộ paper: lines 5682–5696 lấy TRAIN/VAL từ `X_eval`; line 5750 gán `X = X_eval`; lines 5827–5831 đánh giá full stream `X`. Protocol này có record đã dùng cho train/validation trong stream cuối. Ngoài ra lines 3549–3567 dùng pseudo-label cho một monitor nhưng true labels cho incremental buffer. Không sao chép thiết kế đó như một held-out TEST sạch hoặc một hệ thống không cần feedback. [Notebook cần xem](../paper-general/code/MORPH-IDS/Scenario4/Scenario4-APT-Campaigns.ipynb).

**Cách trình bày ngắn với giảng viên**

“Em giữ kết quả OpTC làm baseline và bổ sung CITAR, Windows-APT 2025, THEIA/Linux để kiểm tra tính tổng quát. Em tách rõ thí nghiệm huấn luyện riêng, transfer và huấn luyện chung; không xem nhiều dataset là multi-label. Em đổi architecture sang ontology của Host–Process–LogSource–Event–Detection–Model và một deployment view trong đó Central VM chạy nhiều service/container. Luồng cập nhật được kích hoạt bởi drift/feedback đã kiểm tra và dữ liệu được xác nhận; model mới phải qua validation trước khi đưa vào sử dụng. Multi-label ATT&CK là một nhánh mở rộng riêng khi ground truth đủ tin cậy.”
