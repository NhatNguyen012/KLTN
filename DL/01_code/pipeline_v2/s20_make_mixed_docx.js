const { P, H1, H2, B, NOTE, T, SP, CODE, IMG, build } = require("./s20_docx_lib.js");
const IMGDIR = "D:/UIT/KLTNv2/02_artifacts/39_dataset_word_v1/img/";

const c = [];
c.push(P("**Mục đích:** mô tả để hiểu và hình dung mô hình Mixed-Type Self-Attention của nhánh Network DL: nhận đầu vào thế nào, xử lý ra sao, dựa vào đâu để quyết định \"cửa sổ này có tấn công hay không\". Không đi sâu vào toán. Số liệu lấy từ mã `mixed_type_attention_model.py`, cấu hình và kết quả đã train (`05_models/v2_subsetB`, `22_v2_pipeline`)."));
c.push(NOTE("**Phiên bản dùng cho fine-tune là \"bản B\"**: mỗi flow có 4 trường phân loại (`app_family`, `proto`, `resp_port_class`, `image_dir_class`), `delta_t` và một cờ nhị phân luôn bằng 0 (giữ để cùng định dạng). Bản đầy đủ có thêm 3 trường phân loại và 7 số của Bro, nhắc ở mục 9. Mọi số trong tài liệu là của bản B nếu không ghi khác."));

// ------------------------------------------------------------ 1
c.push(H1("1. Mô hình làm gì, trong một đoạn"));
c.push(P("Giống BiLSTM, mô hình đọc **một cửa sổ** tối đa 512 flow của một máy trong 15 phút và trả ra **một xác suất** cửa sổ có tấn công. Khác ở cách đọc: thay vì đọc lần lượt từng flow bằng một \"bộ nhớ\", Mixed-Type dùng **self-attention** (cơ chế tự chú ý): mỗi phần tử nhìn tất cả phần tử khác cùng lúc và tự quyết định phần tử nào đáng chú ý. Việc này diễn ra ở **hai tầng**: giữa các trường của một flow, rồi giữa các flow của một cửa sổ."));
c.push(IMG(IMGDIR + "mixed_flow.png", 640, 168));
c.push(P("Tên \"Mixed-Type\" (nhiều kiểu dữ liệu) vì các trường có kiểu khác nhau (loại, số, nhị phân, thời gian) đều được biến thành cùng một dạng \"token\" để đưa vào attention."));

// ------------------------------------------------------------ 2
c.push(H1("2. Hai ví dụ thật xuyên suốt tài liệu"));
c.push(P("Hai cửa sổ lấy từ tập TEST của OpTC (mô hình chưa từng học trên chúng):"));
c.push(T(["", "Cửa sổ tấn công", "Cửa sổ benign"], [
  ["Máy, giờ", "`sysclient0010`, 25/9/2019 01:15 UTC", "`sysclient0616`, 21/9/2019 17:30 UTC"],
  ["Số flow", "30 flow, cả 30 đều dương", "10 flow, không flow nào dương"],
  ["Mỗi flow", "`powershell.exe`, tên trần (không thư mục), tcp, cổng 443, tới `202.6.172.98`", "`firefox.exe`, thư mục Program Files, tcp, cổng 443"],
  ["Nhịp thời gian", "đều tăm tắp, mỗi flow cách trước khoảng 30 giây (`delta_t` = 3.438)", "ngắn và không đều (0.002, 0.014, 0.424, ...)"],
  ["Xác suất của Mixed-Type", "**1.0**", "**0.00005**"],
  ["Xác suất của BiLSTM (để so)", "1.0", "0.0005"],
], [2300, 3769, 3569], { firstColFill: true }));
c.push(P("Đây là beacon (liên lạc định kỳ tới máy chủ điều khiển) của kịch bản SC2 trong OpTC."));

// ------------------------------------------------------------ 3
c.push(H1("3. Đầu vào: mỗi flow thành 6 \"token\""));
c.push(P("Mỗi flow gồm 4 id (số thứ tự trong từ điển) và 1 số thực `delta_t`, thêm một cờ nhị phân. Mô hình biến mỗi trường thành một **token**, tức một vector 64 số:"));
c.push(T(["Token", "Biến thành vector bằng cách nào", "Ví dụ ở cửa sổ tấn công"], [
  ["`app_family`", "tra bảng embedding riêng (61 hàng × 64 số)", "id 5 (`powershell.exe`)"],
  ["`proto`", "tra bảng riêng (4 hàng)", "id 2 (`tcp`)"],
  ["`resp_port_class`", "tra bảng riêng (11 hàng)", "id 2 (`PORT_443_HTTPS`)"],
  ["`image_dir_class`", "tra bảng riêng (10 hàng)", "id 3 (`BARE_NAME`)"],
  ["cờ nhị phân", "tra bảng 2 hàng (0 hoặc 1)", "0 (luôn 0 ở bản B)"],
  ["`delta_t_log1p`", "nhân con số với một vector học được rồi cộng độ lệch", "3.438 (≈ 30 giây)"],
], [2300, 4200, 3138]));
c.push(P("Mỗi token được cộng thêm hai \"nhãn dán\" học được: **nhãn trường** (đây là trường nào trong 6 trường) và **nhãn kiểu** (loại, số, nhị phân hay thời gian). Nhờ vậy mô hình biết một vector thuộc trường nào, dù cùng kích thước. Cửa sổ ngắn hơn 512 flow được đệm; phần đệm bị che (mask) và không ảnh hưởng kết quả."));

// ------------------------------------------------------------ 4
c.push(H1("4. Xử lý bên trong, từng bước"));
c.push(H2("Bước 1 – Attention trong một flow (tầng 1)"));
c.push(P("6 token của một flow đưa vào một lớp self-attention (4 \"đầu\", mỗi đầu chú ý một kiểu quan hệ). Mỗi token nhìn 5 token còn lại và quyết định chú ý bao nhiêu vào từng token. Ví dụ: token `powershell.exe` có thể chú ý mạnh vào token \"tên trần\" và token cổng 443, vì tổ hợp này khác với `firefox.exe` từ Program Files. Kết quả là 6 token đã \"trao đổi thông tin\" với nhau."));
c.push(H2("Bước 2 – Vector flow"));
c.push(P("Lấy trung bình 6 token thành **một vector 64 số cho mỗi flow**, tức một bản tóm tắt flow có xét tổ hợp các trường."));
c.push(H2("Bước 3 – Cộng vị trí"));
c.push(P("Attention tự nó không biết thứ tự, nên mỗi flow được cộng thêm một vector vị trí học được (flow thứ 1, 2, ..., tối đa 512). Như vậy mô hình biết flow nào đứng trước, đứng sau."));
c.push(H2("Bước 4 – Attention giữa các flow (tầng 2)"));
c.push(P("Chuỗi vector flow đi qua 2 lớp self-attention (4 đầu, lớp nở ra 128 số rồi thu lại). Mỗi flow nhìn mọi flow khác trong cửa sổ cùng lúc và chọn flow nào đáng chú ý. Với cửa sổ beacon, 30 flow giống hệt nhau và cách đều nhau nhìn nhau, mô hình có thể \"thấy\" rằng cùng một thứ đang lặp lại. Khác với BiLSTM đọc tuần tự và phải \"nhớ\", attention so sánh trực tiếp mọi cặp flow."));
c.push(H2("Bước 5 – Phân loại"));
c.push(P("Lấy trung bình các flow thật (bỏ phần đệm) thành một vector 64 số cho cả cửa sổ, đưa qua mạng nhỏ 64 → 64 → 1 và sigmoid thành **xác suất tấn công**. Tổng cộng khoảng **144,000 tham số**."));

// ------------------------------------------------------------ 5
c.push(H1("5. Mô hình biết nhãn bằng cách nào"));
c.push(P("**Nhãn không phải là đầu vào**; nhãn chỉ dùng khi huấn luyện và chấm điểm. Nhãn từng flow lấy từ bước làm dữ liệu; nhãn cửa sổ = có ít nhất một flow dương."));
c.push(B("Mô hình đoán xác suất cho cửa sổ TRAIN, so với nhãn thật để ra độ sai (loss), rồi chỉnh các con số bên trong theo hướng giảm sai. Lặp lại nhiều vòng (epoch)."));
c.push(B("**Dữ liệu mất cân bằng:** TRAIN có 160,210 cửa sổ, chỉ 401 dương (khoảng 1/400). Loss tính mẫu dương nặng gấp khoảng 398.5 lần."));
c.push(B("Tốc độ học 0.0003 (nhỏ hơn BiLSTM vì attention nhạy hơn), mỗi lần học 16 cửa sổ và dồn gradient hai lần nên hiệu quả như 32 cửa sổ; tối đa 8 epoch, dừng sớm sau 3 epoch không cải thiện (PR-AUC trên VAL). Bản này tốt nhất ngay epoch 1 và dừng ở epoch 4."));
c.push(B("Ngưỡng chọn trên VAL cho F1 lớn nhất: **1.0**. Đây là ngưỡng \"bão hòa\": xác suất của hầu hết cửa sổ dương bằng đúng 1.0 trong số thực, nên ngưỡng không phân biệt thêm."));
c.push(H2("Mô hình chú ý vào đâu (kiểm tra attention)"));
c.push(P("Mình đo mức chú ý trung bình mà mỗi token nhận được ở tầng 1 trên tập VAL (bản B). Đây là chỉ báo bên trong mô hình, **không phải độ quan trọng nhân quả** (chính file kiểm tra cũng ghi cảnh báo này):"));
c.push(T(["Token", "Cửa sổ dương", "Cửa sổ âm"], [
  ["`app_family`", "0.33", "0.74"],
  ["`image_dir_class`", "0.30", "0.18"],
  ["`delta_t`", "0.14", "0.04"],
  ["`proto`", "0.14", "0.01"],
  ["`resp_port_class`", "0.06", "0.01"],
  ["cờ nhị phân", "0.03", "0.01"],
], [3200, 3219, 3219]));
c.push(P("Ở cửa sổ dương, mô hình chú ý nhiều vào tên chương trình và nơi chạy, cộng với nhịp thời gian và giao thức; ở cửa sổ âm gần như chỉ nhìn tên chương trình. Phù hợp với việc ở OpTC tên chương trình và nơi chạy là dấu hiệu chính."));
c.push(NOTE("**Điều cần nói thẳng khi trình bày.** Luật một dòng \"cửa sổ có `powershell.exe`\" đạt F1 0.994 trên TEST OpTC, ngang mô hình. Vì vậy điểm cao không chứng minh mô hình học được hành vi tấn công tổng quát; phần lớn tín hiệu là tên chương trình và nơi chạy. Mô hình cũng trả lời theo cả cửa sổ nên flow độc lẫn trong rất nhiều flow benign dễ bị chìm."));

// ------------------------------------------------------------ 6
c.push(H1("6. Kết quả: ma trận nhầm lẫn"));
c.push(P("Bản B, ngưỡng chọn trên VAL (1.0). Một mẫu là một cửa sổ hoặc một khúc 512 flow của cửa sổ dài:"));
c.push(T(["Tập", "TP (bắt đúng)", "FP (báo nhầm)", "FN (bỏ sót)", "TN (benign đúng)", "Precision / Recall / F1"], [
  ["VAL", "82", "0", "1", "34,278", "1.000 / 0.988 / 0.994"],
  ["TEST", "80", "0", "2", "34,331", "1.000 / 0.976 / **0.988**"],
  ["TRAIN", "chưa xuất ma trận", "", "", "", "loss huấn luyện giảm 0.57 → 0.08 (4 epoch)"],
], [900, 2100, 1500, 1500, 1700, 1938]));
c.push(P("Ma trận trên TRAIN chưa được xuất khi chạy Kaggle. TEST chỉ có 82 cửa sổ dương, nên một cửa sổ = 1.2 điểm recall. BiLSTM bản B cho đúng cùng ma trận TEST (80/0/2): chênh lệch giữa hai mô hình không có ý nghĩa. Bản đầy đủ của Mixed-Type đạt F1 0.994 (81/0/1)."));

// ------------------------------------------------------------ 7
c.push(H1("7. So sánh nhanh với BiLSTM"));
c.push(T(["", "BiLSTM", "Mixed-Type Self-Attention"], [
  ["Cách đọc dãy flow", "đọc lần lượt, hai chiều, có \"bộ nhớ\"", "mỗi flow nhìn mọi flow khác cùng lúc (attention)"],
  ["Cách xử lý các trường của một flow", "ghép các vector trường rồi trộn một lần", "attention giữa 6 token trong flow (tầng 1)"],
  ["Biết thứ tự flow nhờ", "thứ tự đọc", "vector vị trí học được"],
  ["Số tham số", "78,698", "144,065"],
  ["Tốc độ học, batch", "0.001, 64", "0.0003, 32 (16 × 2)"],
  ["TEST bản B (TP/FP/FN/TN)", "80 / 0 / 2 / 34,331", "80 / 0 / 2 / 34,331"],
], [2900, 3369, 3369], { firstColFill: true }));

// ------------------------------------------------------------ 8
c.push(H1("8. Khi fine-tune trên THEIA và ATLASv2"));
c.push(B("Giữ kiến trúc; **mở rộng các bảng embedding** của `app_family` và `image_dir_class` (thêm hàng cho tên chương trình và lớp thư mục mới, khởi tạo bằng bản sao hàng `<UNK>`)."));
c.push(B("Dữ liệu mới đưa về đúng 5 trường và định dạng shard; trộn thêm một phần OpTC lúc học để không quên."));
c.push(B("Đánh giá bằng ma trận nhầm lẫn trên TRAIN và TEST của dữ liệu mới, và trên TEST OpTC để biết có quên không."));
c.push(B("Lưu ý với Mixed-Type: tốc độ học khi tinh chỉnh dùng 3×10⁻⁵ (nhỏ hơn BiLSTM) vì attention dễ lệch."));

// ------------------------------------------------------------ 9
c.push(H1("9. Bản đầy đủ khác bản B ở đâu"));
c.push(P("Bản đầy đủ thêm `service`, `conn_state`, `principal_class` (3 token phân loại nữa), 7 số của Bro (thời lượng, số byte, số gói, ...), mỗi số một token, và cờ `has_missed_bytes`: tổng 16 token mỗi flow (7 loại + 7 số + 1 nhị phân + `delta_t`). Các trường này không có ở THEIA/ATLASv2 nên bản B chỉ giữ 6 token. Kiểm tra attention ở bản đầy đủ cho thấy mô hình chú ý nhiều nhất vào `principal_class` (0.32), `app_family` (0.25), `image_dir_class` (0.16) ở cửa sổ dương; trong đó `principal_class = ADMINISTRATOR` là tài khoản của đội Red Team (đặc điểm của testbed, không tổng quát), một lý do bản B bỏ trường này."));

build("Mixed-Type – Mô tả mô hình", "Mô hình Mixed-Type Self-Attention của nhánh Network DL: đầu vào, xử lý và cách nhận biết nhãn", c, process.argv[2]).then(() => console.log("ok"));
