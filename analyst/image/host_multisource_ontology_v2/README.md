# Ontology architecture — kiến trúc mục tiêu, 14/10/2026

Bản này cập nhật theo yêu cầu của thầy và góp ý trong `Temp/1.md`: mô tả **ontology khái niệm cho multi-source host logs**, ánh xạ xuống end host, Central VM và persistent storage. Đây là thiết kế mục tiêu; chưa phải ontology OWL/reasoner hoặc hệ thống tích hợp đã triển khai. Các model riêng có mã/thí nghiệm không có nghĩa toàn bộ deployment đã hoạt động.

- [Hình chính PNG](main_architecture.png)
- [Vector SVG](main_architecture.svg)
- [Bản draw.io chỉnh sửa được](main_architecture.drawio)
- [Generator](render.py)
- [High-level diagram của implementation Lam đã kiểm tra](../host_apt_high_level_lam_verified/high_level_design.png)
- [Audit Lam và bằng chứng mã](../../lam_dl_review_2026-10-14/README.md)

## Bốn tầng

| Tầng | Vai trò |
|---|---|
| Meta-model | Định nghĩa các loại thực thể, quan hệ, provenance, prediction target và chính sách vòng đời model. |
| Shared ontology | Các khái niệm và quan hệ dùng chung giữa nguồn log, mô hình và dịch vụ. |
| Domain ontologies | Host activity; multi-source log; temporal/prediction/learning. Các module ontology imports/extends ontology chung; đây không phải quan hệ subclass giữa module. |
| Executable mapping & deployment | Các module triển khai hiện thực hóa hoặc sử dụng khái niệm ontology. Luồng vận hành chỉ xuất hiện trong tầng này. |

Mũi tên xám: ánh xạ ngữ nghĩa. Vàng nét đứt: trao đổi dữ liệu đề xuất. Đỏ: điều khiển học và triển khai. Hình là sơ đồ phân lớp ontology kèm deployment mapping, không phải sơ đồ class OWL đầy đủ.

## Multi-source và quan hệ ontology

Nguồn mục tiêu gồm **OS/Security, Application/Service, Orchestration/Audit logs**. CommunicationEvent là sự kiện quan sát từ endpoint, gắn host/process khi nguồn cung cấp được quan hệ đó. Không có Network Sensor riêng; không đổi tên trường Zeek thành trường OS chỉ vì đã join với host context.

| Quan hệ | Ý nghĩa |
|---|---|
| `Process runsOn Host / spawns Process` | Scope host và quan hệ lineage; PID thô không phải định danh toàn cục. |
| `Event performedBy Process / Principal; targets Resource` | Ngữ nghĩa hoạt động trên host. |
| `LogRecord observedBy LogSource / associatedWithHost` | Giữ nguồn và liên kết host; các loại nguồn OS, application, orchestration là subclass của LogSource. |
| `LogRecord hasEventTime / availableAt / sourceProvenance` | Tách thời gian xảy ra và thời điểm đủ bằng chứng để suy luận. |
| `EventSequence containsEvent; belongsTo TemporalWindow` | Nhóm thời gian tổng quát; kích thước window và sequence là cấu hình benchmark. |
| `Prediction aboutTarget / usesModel / supportedBy Evidence` | Target event/sequence/window phải được thống nhất trước fusion. |
| `GroundTruth hasLabelSet / labelUnit / verifiedBy` | Nhãn thật tách prediction; thiếu nhãn không đồng nghĩa benign. |
| `TrainingJob usesDataset / producesCandidateModel` | Dataset đã xác minh và replay được chọn cho lần học mới. |
| `CandidateModel evaluatedBy ValidationReport` | Báo cáo kiểm định là bằng chứng cho quyết định promotion. |

## End host, Central VM và storage

End host có Collector, Lightweight ML, Novelty/OOD Detector và Agent Coordinator. Ba trạng thái là benign, known malicious và unknown/suspicious. **Unknown chưa phải malicious đã xác nhận**. Novelty detector cần xây dựng/calibrate/đánh giá riêng; binary classifier hiện có không tự cung cấp khả năng này. Agentic investigation là mở rộng tùy chọn.

Một Central VM có thể chạy nhiều service/container: ingestion/correlation, graph/temporal analysis, fusion, SOC review, drift monitoring, learning controller, trainer, validator, registry và deployment. Các trách nhiệm được nhóm trong hình cho dễ đọc; không bắt buộc mỗi trách nhiệm là một container. GraphSAGE, BiLSTM và Mixed-Type là lựa chọn model; BiLSTM và Mixed-Type được huấn luyện độc lập.

Persistent Storage/Mounted Volume chứa các logical store: raw logs, processed observations, evidence/label provenance, verified datasets, replay buffer, model artifacts và metadata. VM được gắn storage; service tương ứng đọc/ghi các store theo trách nhiệm ghi trong hình. Chưa chọn công nghệ volume hoặc OpenStack Cinder. Dataset nghiên cứu offline đi qua adapter, ánh xạ nhãn và kiểm tra chất lượng trước khi sử dụng; không đồng nhất với live telemetry.

## Trigger và vòng đời học

1. Sustained drift **hoặc** suy giảm đã được review **hoặc** đủ mẫu mới có nhãn xác nhận tạo điều kiện xem xét update.
2. Learning Controller kiểm tra chất lượng dữ liệu, nhãn và chính sách; drift không tự tạo ground truth.
3. Trainer dùng phần TRAIN của dữ liệu mới + replay; retrain ML hoặc fine-tune DL khi phù hợp.
4. CandidateModel được kiểm định trên dữ liệu giữ lại ở miền cũ và mới; chọn threshold/policy bằng validation. TEST dành cho đánh giá độc lập.
5. ValidationReport hỗ trợ quyết định phê duyệt ModelVersion, sau đó rollout tới endpoint/central services phù hợp; giám sát và rollback khi cần.

Registry lưu weights, schema/vocabulary/normalization, label policy, threshold, dataset lineage và trạng thái triển khai. Việc thêm dataset chỉ giúp model học thêm khi có bước training/update; chạy evaluation với checkpoint cũ không thay đổi trọng số.

## Ranh giới giữa thiết kế và benchmark

Chi tiết Zeek, cửa sổ 15 phút và chunk 512 flow thuộc implementation Lam, được giữ trong phần dưới và hình high-level riêng. Không đưa chúng thành ràng buộc bắt buộc của ontology mục tiêu. Chuyển sang endpoint-only inputs cần adapter, kiểm tra feature semantics, huấn luyện và đánh giá lại; không thể mặc định checkpoint Lam tương thích.

## Phần DL đã xác minh

Pipeline v2 đọc **Bro conn + eCAR-Bro**, không trực tiếp đưa toàn bộ `host-begnin/host-malicious` vào DL. Active input gồm 7 categorical (3 host-derived), 7 numeric, 7 numeric missing masks, `has_missed_bytes` và `delta_t_log1p`. `history`, PID/PPID/actorID không phải input trực tiếp; principal và image_path chỉ đi vào qua các field dẫn xuất.

BiLSTM và Mixed-Type Self-Attention là **hai model huấn luyện riêng**, chưa có ensemble hoặc chuỗi BiLSTM → Attention. Mixed-Type có 16 feature tokens cho mỗi flow rồi temporal self-attention; self-attention này không phải cross-attention giữa Host ML và DL. Cả hai chỉ có binary output ở cấp chunk. Nhãn chunk = có ít nhất một malicious flow trong chunk, không phải nhãn của cả window được sao chép cho mọi chunk.

DNS query log, application log và orchestration audit riêng chưa được xác nhận trong pipeline Lam; trong hình mới, chúng là nguồn mục tiêu, không phải đầu vào đã triển khai. Chúng có thể được thêm qua các adapter mới khi có dữ liệu thật. OS-only collection theo hướng của thầy cần feature mapping và đánh giá lại vì model hiện phụ thuộc Zeek connection statistics.

## Dataset và nhãn

Danh sách ưu tiên có bằng chứng nhãn công bố: **SAGA v2.0 (Windows, synthetic audit), CICAPT-IIoT2024 provenance (Linux, node labels), AIT V2.1 (Linux, line annotations)**. Windows-APT V4 giữ ở mức ứng viên vì binary ground truth từng record chưa được xác minh; không đồng nhất MITRE/Wazuh tag với malicious label. Chi tiết paper/release và giới hạn kiểm tra ở [label audit](../../dataset_label_verification_2026-10-14.md).

Ba corpus không tự tương thích checkpoint DL hiện tại. Adapter phải giữ đúng semantics của feature/label, tách supervision khỏi input, và ghi missingness rõ ràng. Nhiều dataset không tự tạo bài toán multi-label. Các nhãn AIT có thể mang hierarchy; nhãn node CICAPT cần quy tắc riêng khi chuyển sang event/window.

## Hợp đồng tích hợp cần thực hiện

Frozen Host seed02 dùng event split 75/10/15; Lam dùng window split 70/15/15, split seed 1 và train seed 42. Hai TEST không tự tạo thành một joint TEST sạch. Cần kiểm tra overlap theo host/time/source, thống nhất target, chọn aggregation trên validation và tạo protocol riêng để model/fusion không thấy nhãn TEST khi fit. Không đổi approved baseline để làm việc này.

Hình chỉ là logical deployment; chưa đo resource budget, độ trễ end-to-end hoặc khả năng triển khai trên một VM. Không dùng true ancestor labels/future evidence làm feature. Việc dữ liệu node có nhãn không cho phép dùng nhãn đó trong message passing ở inference.

## Dựng lại và xác minh

Chạy `python3 analyst/image/host_multisource_ontology_v2/render.py` từ workspace để xuất PNG/SVG/draw.io tại chính thư mục này. Generator không đọc telemetry hoặc thay đổi model. Đã kiểm tra giới hạn text, XML/SVG, ID/tham chiếu draw.io, local links và xem trước PNG.
