# Khả thi của incremental learning từ checkpoint OpTC

Ngày kiểm tra: 2026-10-22. Phạm vi: LightGBM, GraphSAGE hai hop Process/Host,
và BiLSTM mới theo thông tin người dùng: bỏ đặc trưng mạng Layer 3/4, chưa có code mới.

## Kết luận

- `skrghosh`: ưu tiên pilot thích ứng Windows, có điều kiện về nhãn, biểu diễn và
  đơn vị chia tập. Chưa đủ cơ sở gọi là benchmark sẵn sàng cho cả ba checkpoint.
- `THEIA`: ứng viên thứ hai cho nghiên cứu chuyển miền Linux; metadata tiến trình
  trong bản CSV hiện có phong phú hơn FIVEDIRECTIONS/CADETS. Cần adapter, xác minh
  quan hệ nhân quả và định nghĩa nhãn, không đưa thẳng vào checkpoint.
- `FIVEDIRECTIONS`: có provenance và nhãn UUID nhưng bản xuất hiện có thiếu metadata
  nghiêm trọng; không ưu tiên chỉ vì cùng Windows.
- `CADETS`: ứng viên provenance bổ sung, cần adapter FreeBSD và phục hồi/kiểm tra
  ý nghĩa metadata trước khi dùng lại checkpoint OpTC.
- `AIT` fox/harrison hiện có: không chọn làm dataset học tiếp chung cho cả ba
  mô hình. Có giá trị cho log ứng dụng/xác thực, nhưng audit hiện có không cung cấp
  đủ dấu vết thực thi/cha–con cho backbone GraphSAGE đang dùng.
- `CIC-APT-IIoT-2024` hiện có: CSV mạng không cung cấp đầu vào host/provenance cho
  cả ba mô hình. Không phù hợp với thí nghiệm chung này.

Không huấn luyện, thay checkpoint, sửa dataset hay thay split/vocabulary trong lần
kiểm tra này. Báo cáo này là đánh giá tính khả thi, không phải kết quả chuyển giao.

## Nguồn đã đọc và cách kiểm tra

Đọc đủ `Temp/1.md` đến `Temp/11.md` trong `/mnt/SSD_Data/optc/Temp`.
Đường dẫn `/mnt/SS_Data/optc/Temp` trong yêu cầu không tồn tại; dùng thư mục thực tế.
Các trao đổi cũ được xem là giả thuyết cần đối chiếu, không phải ground truth.

Đã đọc quy tắc dự án, `ML/MENU.md`, README DL/GraphSAGE, mã tokenizer,
`ego.py`, `graph.py`, `relational_sage.py`, script gán nhãn skrghosh,
tài liệu/summary nhãn AIT, header CSV TC và nhãn REAPr đi kèm THESEUS.

Đã stream toàn bộ năm JSON gốc skrghosh bằng `orjson`, đếm object, hostname,
CREATE/PROCESS và lỗi parse. Đã đọc toàn bộ 14 file theo glob
`DATASET/AIT_Log_V2.1/*_dataset/gather/*/logs/audit/audit.log*`, đếm loại record
và kiểm tra file labels tương ứng. Đã quét toàn bộ ba bảng process CSV TC,
kiểm tra metadata và đối chiếu UUID với các file nhãn; chưa quét toàn bộ edge
tables để chứng minh chất lượng dựng graph.

Các số 46.646 flow, 196 sample, 8 sample dương, 74,5% UNK và các số Suricata trong
ảnh là kết quả người dùng cung cấp. Chưa tái lập adapter/windowing sinh ra chúng.

## Đo trực tiếp trên skrghosh

| File | JSON hợp lệ | FLOW records thô | CREATE/PROCESS |
|---|---:|---:|---:|
| apt29.json | 3.742.216 | 705.218 | 16.589 |
| output_fin6.json | 2.354.056 | 435.313 | 9.501 |
| output_menuPass.json | 6.346.261 | 1.429.132 | 15.998 |
| oilrig.json | 6.190.695 | 0 | 13.236 |
| wizard_spider.json | 3.694.371 | 0 | 19.626 |

OilRig có thêm một dòng không parse được. Tổng hợp lệ: 22.327.599 records.
Đây là số record thô, không phải số kết nối đã gộp hay số mẫu độc lập.
Trong CREATE/PROCESS, actorID/objectID/timestamp đều có và ID khác UUID toàn zero;
điều này chưa chứng minh mọi cạnh đều đúng, liên thông hay có đủ lịch sử hai hop.

Toàn bộ records hợp lệ ở cả năm file có `hostname=localhost`. Phải namespace
theo lần thu thập/scenario để tránh nối nhầm graph giữa các file. Không thể dùng
host-disjoint 70/30 trong một file với khóa hostname này. Đồ thị host giao tiếp
cũng bị giới hạn do thiếu telemetry của các peer; không tự tạo host đã quan sát
chỉ từ IP đích.

Nhãn trong `labeled/` do script KLTN tạo, không phải annotation event độc lập của
tác giả. `label_skrghosh_dataset.py` dùng actor/object thuộc tập tiến trình bị đánh
dấu, artifact path và C2 IP. Script cũng dùng PID/PPID trong bước dựng context;
README khẳng định loại bỏ hoàn toàn lỗi PID recycling là quá mạnh.

`labeled/summary_report.json` báo 7.509 / 18.240 / 6.444 / 1.754 / 13.824 event
dương tương ứng FIN6 / APT29 / menuPass / OilRig / Wizard Spider. Đây là số nhãn
do quy tắc sinh ra, không phải độ chính xác annotation đã được kiểm định độc lập.
Tỷ lệ benign gần bảng tác giả không chứng minh precision/recall của nhãn.

Nếu nhãn suy ra từ lineage của agent Caldera, GraphSAGE học lineage có nguy cơ
chỉ tái hiện quy tắc tạo nhãn. Cần kiểm chứng theo attack manifest/UUID/thời gian,
audit mẫu âm và dương, và đánh giá khi che dấu tên agent, marker/câu lệnh đặc thù.
Không dùng membership nhãn/ancestor labels làm feature.

## Đo trực tiếp trên AIT fox/harrison

- 14 file audit, tổng 49.440 dòng (toàn file, gồm cả khả năng log ngoài thời gian
  mô phỏng; đây là kiểm kê nguồn, chưa phải cohort dùng để học).
- `EXECVE`: 0; `SOCKADDR`: 0; `SYSCALL`: 28.
- Cả 28 SYSCALL có `syscall=1`, `comm=apparmor_parser`, `exe=/sbin/apparmor_parser`
  trong các record đã kiểm kê về loại syscall; ví dụ trực tiếp cho thấy arch x86-64.
  Không có cơ sở suy ra nguồn connect/exec/fork đầy đủ từ các file này.
- File labels gốc cho audit: fox internal_share 2, fox intranet_server 19,
  harrison internal_share 2, harrison intranet_server 24: tổng 47 dòng được đánh dấu.
  Nhiều dòng có thể thuộc cùng một audit event; không coi là 47 phiên độc lập.

Suricata thiếu process metadata không đồng nghĩa tất cả AIT đều thiếu `exe`/PID:
audit có chúng, chủ yếu ở sự kiện xác thực/dịch vụ. Tuy nhiên, có PID và exe không
đồng nghĩa có lifecycle và quan hệ cha–con để dựng đúng graph OpTC.

AIT có nhãn theo số dòng cho một số log, gồm DNSteal; vì thế nhãn flow suy diễn
qua IP NAT + khoảng VPN trong ảnh không đại diện chất lượng mọi nhãn của AIT.
Ưu tiên nhãn đúng nguồn và dòng, giữ vùng không xác định khi chưa có quy tắc hợp lệ.
Không mặc định mọi dòng trong một file không được annotation là benign đã xác minh.

## Đo trực tiếp trên bảng process của TC

`present` nghĩa là giá trị sau strip/lower không thuộc rỗng, n/a, na, none, null.

| Bản CSV | Process rows | path có giá trị | cmd có giá trị | UUID nhãn duy nhất khớp process |
|---|---:|---:|---:|---:|
| FIVEDIRECTIONS | 519.493 | 0 | 15.912 | 32/32 |
| THEIA | 279.369 | 278.363 | 271.834 | 126/126 |
| CADETS | 224.629 | 0 | 224.146 | 102.359/102.359 |

`cmd` có giá trị không bảo đảm đó là command line đầy đủ. Nhãn có UUID khớp
không chứng minh mọi event của UUID đó là hành động tấn công. Phải phân biệt
nhãn compromised process, attack-related event và cửa sổ có tấn công.

CSV event có `src_node`, `src_index_id`, `operation`, `dst_node`,
`dst_index_id`, `event_uuid`, `timestamp_rec`; node table có cả `hash_id` và
`node_uuid`. Ví dụ đã đọc cho thấy src/dst là hash, nên không join thẳng
`src_node` với UUID nhãn như tài liệu cũ đề xuất. Không giả định mọi src là process:
ví dụ FIVEDIRECTIONS EVENT_READ có src thuộc file table.

Bốn bảng CSV không có cột host riêng. Cần xác minh phạm vi host/nguồn thu thập,
hướng cạnh, timestamp và thời điểm thuộc tính được quan sát trước khi tạo adapter.
Không dùng metadata toàn vòng đời làm bằng chứng quá khứ nếu chưa có kiểm chứng.
`EXEC` không đồng nghĩa `FORK`/`CREATE`: thay executable có thể giữ cùng process.

## Tương thích với checkpoint

LightGBM đang dùng binary sparse semantic tokens và bỏ FLOW. Giữ số cột, thứ tự,
ngữ nghĩa token/giá trị và preprocessing khi dùng `init_model`; train thêm cây
với dữ liệu mới và replay TRAIN cũ là một baseline cập nhật hợp lệ. Không có bảo
đảm chống quên. Không tự thay các bit 0 bằng NaN, tự thêm cột hay dùng một bộ 20
token mới và gọi đó là input tương thích checkpoint cũ. Mở rộng schema cần thí
nghiệm migration riêng; giữ index cũ chỉ là một điều kiện cần.

GraphSAGE hiện tại: Process/Host, 40 attributes, bốn relations `creates`,
`communicates`, `communicates_reverse`, `hosts`; hai lớp, embedding 16 chiều.
Không phải backbone Process/File/Socket 128 chiều. Evidence phải có thời gian
nhỏ hơn cutoff. Thiếu FLOW không loại bỏ nhánh ancestry, nhưng giảm thông tin
network và có thể tạo graph lệch phân phối. Adapter tuyến tính không khôi phục
cạnh hay evidence không tồn tại.

BiLSTM: bỏ L3/4 features chưa cho biết đơn vị chuỗi. Nếu vẫn lọc FLOW trước khi
dựng chuỗi thì OilRig/Wizard Spider vẫn không đóng góp mẫu, dù đã bỏ proto/port.
Nếu chuyển sang event host, phải đếm lại chuỗi/dương/coverage và dùng checkpoint
OpTC được học với chính biểu diễn mới. Nếu chỉ đổi tensor đầu vào của notebook
cũ thì không tự động có checkpoint tương thích. Cần code/spec mới để kết luận.

## Thiết kế thực nghiệm đề xuất

1. Giữ nguyên baseline/split/vocabulary OpTC đã phê duyệt. Dùng bản BiLSTM OpTC
   tương ứng schema mới; không gắn điểm của notebook mạng cũ cho nó.
2. Audit representation coverage trên từng nhánh: OOV/empty/collisions của
   LightGBM; ancestry/metadata/peer resolution của graph; nhóm chuỗi, cửa sổ và
   số dương độc lập của BiLSTM. Không giảm độ dài cửa sổ chỉ để tăng sample count.
3. Audit nhãn skrghosh trước khi cam kết benchmark. Thiết kế split theo run,
   nhóm lineage hoặc khối thời gian tùy dữ liệu thật; bảo đảm không chồng cửa sổ,
   không rò nhãn hoặc tương lai. Không có cách chia nào đảm bảo đủ positives nếu
   chỉ có một chuỗi tấn công độc lập. Khi đó chỉ báo cáo pilot hoặc bổ sung runs.
4. So sánh model đóng băng, cập nhật chỉ dữ liệu mới, cập nhật có replay, và khi
   đủ tài nguyên baseline train-from-scratch với ngân sách tương ứng. Không mặc
   định freeze head/backbone hoặc tỷ lệ replay nào là tối ưu.
5. Đánh giá trên held-out mới và OpTC cũ; chọn ngưỡng/early stopping trên validation,
   replay chỉ từ TRAIN. Báo PR-AUC, precision/recall/FPR, số TP/FP/FN, mức thay đổi
   trên tác vụ cũ, bộ nhớ/thời gian cập nhật và số run/campaign độc lập.
6. Nếu replay stream: dự đoán trước, cập nhật sau khi nhãn đến; không đánh giá
   hiệu quả học mới trên chính batch vừa dùng cập nhật. Đổi dataset là chuỗi task
   mô phỏng, không tự chứng minh drift thời gian thật trong cùng hệ thống.

Không diễn giải F1 sau adaptation là FWT chuẩn; không dự đoán trước F1 zero-shot
bằng 0 hoặc F1 sau update bằng 0,95. Replay và learning rate nhỏ không bảo đảm
không quên. F1 giảm cũng không tự chứng minh mô hình khái quát tốt hơn.

## Nguồn công khai đối chiếu

- Dataset skrghosh: https://github.com/skrghosh/apt-dataset/blob/main/README.md
- AIT V2.1, cấu trúc log và nhãn dòng: https://zenodo.org/records/19483937
- LightGBM continue training: https://lightgbm.readthedocs.io/en/stable/pythonapi/lightgbm.train.html

Các số đo kiểm kê ở trên đến từ file local trong phiên kiểm tra, không lấy từ
bảng quảng bá dataset hoặc nội dung trò chuyện cũ.
