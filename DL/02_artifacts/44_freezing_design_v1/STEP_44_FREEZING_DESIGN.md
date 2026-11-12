# STEP 44 — Thiết kế freezing (đóng băng) và mở dần (gradual unfreezing) cho fine-tune sang THEIA + ATLASv2

Ngày: 2026-11-04. Chỉ là tài liệu thiết kế; chưa viết mã, chưa chạy job, chưa đổi kiến trúc. Dựa trên cấu trúc mô hình thật (`05_models/v2_subsetB/*/config.json`, notebook `06e`, `07d`) và bằng chứng STEP 40–42.

## 0. Tóm tắt
- Freezing giải quyết **quên và nhiễu khi thêm token mới**; nó **không** giải quyết xung đột nhãn (firefox lành ở OpTC, độc ở ATLASv2), vì xung đột nằm ở nhãn và ở thông tin có trong đầu vào, không ở trọng số.
- Đề xuất 3 giai đoạn: (A) chỉ học phần mới, (B) mở dần theo tầng với learning rate phân biệt (discriminative lr), (C) tinh chỉnh toàn bộ với replay OpTC. Mỗi giai đoạn chọn checkpoint trên VAL; TEST chạy một lần.
- Điều kiện để có ý nghĩa: đầu vào phải có thêm thông tin tách được firefox độc/lành (ngữ cảnh tiến trình: cha, dòng lệnh, kết nối tới nút gốc). Nếu không, freezing chỉ làm mô hình quên chậm hơn, không học được gì thêm.

## 1. Mô hình hiện tại (cần đóng băng cái gì)
Bản B: 4 trường category `app_family(61), proto(4), resp_port_class(11), image_dir_class(10)` + `delta_t_log1p`, `has_missed_bytes`.

| Mô hình | Thành phần có tham số | Ghi chú |
|---|---|---|
| BiLSTM (78,698 tham số) | `embeddings` (ModuleList, mỗi trường một `nn.Embedding`, chiều `min(16,max(4,round(2·√card)))`) → `event_encoder` (Linear → LayerNorm → GELU) → `lstm` (hai chiều, hidden 64) → `classifier` | Embedding và `event_encoder` là nơi token mới đi vào. |
| Mixed-Type | `cat_embeddings`, `num_weight/bias/missing_vector`, `binary_embedding`, `delta_weight/bias`, `field_embedding`, `type_embedding`, `blocks` (attention giữa các trường), `position_embedding`, `temporal_blocks`, `output_norm`, `classifier` | Mỗi trường một token d_model; attention theo trường rồi theo thời gian. |

## 2. Nguyên tắc
1. **Từ điển mở rộng từ đầu, mỗi trường một từ điển riêng**: `app_family` id mới nối từ 61, `image_dir_class` từ 10 (đã chốt 2026-10-23/24). Id cũ giữ nguyên nghĩa; mọi từ điển fit trên TRAIN của đúng split.
2. **Hàng embedding cũ đóng băng, hàng mới học**: `nn.Embedding` không đóng băng theo hàng được nên có hai cách; chọn (a):
   - (a) Hai bảng: `emb_old` (kích thước cũ, `requires_grad=False`) và `emb_new` (chỉ các id mới); tra bằng `where(id < n_old, emb_old[id], emb_new[id - n_old])`. Rõ ràng, không rò gradient.
   - (b) Một bảng mở rộng + mặt nạ gradient (hook xóa gradient hàng cũ) và `weight_decay = 0` cho hàng cũ (decay vẫn làm trôi trọng số đã "đóng băng" nếu không tắt).
3. **Cột đầu vào mới (cmdline, cha, nút gốc) khởi tạo bằng 0** trong `event_encoder` (hoặc `field_embedding` mới trong Mixed-Type) để mô hình mới ở bước 0 hành xử đúng như mô hình cũ trên OpTC. Cần kiểm tra bằng đẳng thức đầu ra (logit trùng đến sai số số học) trước khi huấn luyện.
4. **LayerNorm/BatchNorm**: LayerNorm có tham số học nên coi là phần của tầng; không dùng BatchNorm (mô hình không có). Khi đóng băng, đặt `eval()` cho Dropout để tránh nhiễu không cần thiết ở phần đóng băng.
5. **Cùng chuẩn đánh giá**: checkpoint và ngưỡng chọn trên VAL; TEST một lần; chỉ báo ma trận nhầm lẫn (TRAIN, TEST mới và TEST OpTC), không so "trước/sau" (đã chốt).

## 3. Lịch huấn luyện đề xuất (1 seed 42, Kaggle)
| Giai đoạn | Mở | Đóng | lr | Dừng | Mục đích |
|---|---|---|---|---|---|
| A. Chỉ phần mới | `emb_new`, cột đầu vào mới, `classifier` | embedding cũ, `event_encoder` (BiLSTM) hoặc `blocks`/`temporal_blocks` (Mixed-Type), `lstm` | 1e-3 | VAL PR-AUC (patience 3) | Gắn nghĩa cho token mới mà không làm hỏng biểu diễn cũ |
| B1. Mở tầng mã hóa sự kiện | + `event_encoder` (hoặc `blocks`) | embedding cũ, `lstm`/`temporal_blocks` | 1e-4 | như trên | Cho biểu diễn từng sự kiện điều chỉnh |
| B2. Mở tầng thời gian | + `lstm` (hoặc `temporal_blocks`) | embedding cũ | 5e-5 | như trên | Cho mô hình chuỗi điều chỉnh |
| C. Mở hết | + embedding cũ | không | 1e-5 | như trên | Tinh chỉnh toàn bộ |

- Discriminative lr: tầng càng gần đầu vào lr càng nhỏ (hệ số 1 / 0.1 / 0.01 so với đầu ra); các giá trị trên là **điểm xuất phát chưa kiểm chứng**, không phải kết quả.
- Mở dần theo **epoch cố định** (ví dụ 3 epoch/giai đoạn) hoặc theo VAL; chọn một cách và ghi rõ, không tinh chỉnh bằng TEST.
- **Replay OpTC**: mỗi batch trộn một phần cố định mẫu OpTC TRAIN (đề xuất 25–50%, cần chọn trên VAL của cả hai miền) để không quên; thêm trọng số lớp (pos_weight) tính **riêng từng miền** vì tỉ lệ dương rất khác (OpTC ~0.03%, ATLASv2 ~26%, THEIA ~0.06% theo khóa).
- Số lượng: chạy 3 fold × seed 42 như đã chốt, cùng lịch cho cả 3 fold.

## 4. Giới hạn và rủi ro (phải nêu khi báo cáo)
1. **Xung đột nhãn firefox không giải được bằng freezing.** ATLASv2: 7,696 flow dương của firefox, chỉ 56 (0.7%) tới nút `root_cause`; THEIA 23 dương vs 213,267 lành; OpTC 6 dương. Nếu đầu vào chỉ có `app_family`, cùng một token cho nhãn ngược nhau ở hai miền → cần trường ngữ cảnh mới hoặc chấp nhận mô hình học theo miền. Đây là lý do thầy đề xuất cmdline/cha–con.
2. **Phần lớn nhãn dương ATLASv2 là nhiễu/kế thừa** (8/26 tiến trình dương là con của tiến trình có nhãn; 7/26 chạm IP công cộng bị gán `root_cause`). Điểm cao trên ATLASv2 không chứng minh phát hiện hành vi.
3. **Ít mẫu dương** ở THEIA (127 khóa dương) và OpTC; ma trận nhầm lẫn có thể dao động mạnh giữa fold; một seed không cho độ lệch chuẩn.
4. **Rò rỉ do chia trộn theo cửa sổ** (đã chấp nhận): cửa sổ kề và 10 cuộc tấn công ATLASv2 gần giống nhau → TEST đo nhận ra mẫu đã thấy.
5. **Freezing có thể làm hại khi miền khác mạnh**: nếu giai đoạn A/B1 không đủ, VAL dương sẽ không cải thiện; không kết luận "freezing tốt/xấu" từ một lần chạy.
6. Ngữ cảnh cha/cmdline **OpTC eCAR-Bro hiện không có** → phải huấn luyện lại mô hình gốc với trường mới trước (trường mới = 0 cho mẫu không có ngữ cảnh), nếu không replay OpTC không đồng nhất với miền mới.

## 5. Kiểm tra bắt buộc trước khi chạy
- Đẳng thức khởi tạo (mục 2.3): logit mô hình mở rộng = logit mô hình gốc trên 1,000 mẫu OpTC VAL.
- Đóng băng thật: sau giai đoạn A, băm trọng số tầng đóng băng không đổi; sau mở, kiểm tra từng nhóm tham số có `requires_grad` đúng.
- Số tham số có thể học mỗi giai đoạn được in ra và ghi vào `config.json`.
- Từ điển: id cũ không đổi so với `preprocess_spec.json` của v2; id mới chỉ từ TRAIN.

## 6. Liên hệ với gói Nguyễn (đã nhận và kiểm ở STEP 46; cập nhật 2026-11-05)
- **Mask split của Nguyễn (seed 02):** mã là **1 = TRAIN, 2 = VAL, 3 = TEST, 0 = không dùng** (README của gói ghi sai 0/1/2). Đếm khớp: TRAIN 6,248,443 / VAL 833,125 / TEST 1,249,689. Chỉ số dòng bắt đầu từ 1 (`source_line`), đã kiểm trên file nhỏ nhất và đang chạy toàn bộ (STEP 47).
- **Hợp đồng DL của Nguyễn** (cửa sổ 15 phút theo host, tối đa 512 sự kiện, 4 cột `[app_family, proto, resp_port_class, image_dir_class]` + `delta_t_log1p`, nhãn cửa sổ OR) trùng bản B của ta nên thiết kế trên áp dụng nguyên vẹn. Nhưng danh sách giá trị trong hợp đồng (7 họ `app_family`, `proto` có `file/ipc/reg`, `LOCAL_IPC`...) **không khớp từ điển thật 61/4/11/10** và fixture đi kèm dùng cardinality 141/4/11/10: coi hợp đồng là bản thiết kế, chưa phải bản cài đặt.
- **Ngưỡng 0.245** là của Run 12 IL ATLASv2 do Nguyễn tự chạy (STEP 45); mô hình bản B của ta có ngưỡng 0.9956 (BiLSTM) và 1.0 (Mixed-Type).
- **Chưa có** dữ liệu DL chuỗi sự kiện host (FILE/REGISTRY/MODULE → 4 trường): phải tự thiết kế ánh xạ trước khi chuyển DL sang chuỗi sự kiện host.
- **Nhãn của Nguyễn khác nhãn REAPr của ta**: adapter THEIA của Nguyễn gán nhãn bằng danh sách IOC cố định (IP, tên tệp, trong đó `firefox` nằm trong `malicious_binaries`) và `LabelRefiner` của ATLASv2 dùng IP/cổng C2 + mốc thời gian (73 sự kiện dương). Không ghép số của hai bên khi chưa thống nhất nhãn.
