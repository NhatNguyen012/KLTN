const { P, H1, H2, B, NOTE, T, SP, CODE, IMG, build } = require("./s20_docx_lib.js");
const IMGDIR = "D:/UIT/KLTNv2/02_artifacts/39_dataset_word_v1/img/";

const c = [];
c.push(P("**Mục đích:** mô tả để hiểu và hình dung mô hình BiLSTM của nhánh Network DL: nó nhận đầu vào thế nào, xử lý ra sao và dựa vào đâu để cho ra \"cửa sổ này có tấn công hay không\". Không đi sâu vào toán. Số liệu lấy từ mã mô hình `05b_train_bilstm.py`, cấu hình và kết quả đã train (`05_models/v2_subsetB`, `22_v2_pipeline`)."));
c.push(NOTE("**Phiên bản đang dùng cho fine-tune là \"bản B\"**: mỗi flow chỉ có 4 trường phân loại (`app_family`, `proto`, `resp_port_class`, `image_dir_class`) và `delta_t`. Bản đầy đủ (7 trường phân loại, 7 số, 1 cờ) chỉ nhắc ở mục 9. Mọi số trong tài liệu này, nếu không ghi khác, là của bản B."));

// ------------------------------------------------------------ 1
c.push(H1("1. Mô hình làm gì, trong một đoạn"));
c.push(P("BiLSTM đọc **một cửa sổ** gồm tối đa 512 flow mạng của **một máy** trong **15 phút**, theo thứ tự thời gian, rồi trả ra **một xác suất duy nhất** (từ 0 đến 1) rằng cửa sổ đó chứa hoạt động tấn công. Nếu xác suất lớn hơn hoặc bằng một ngưỡng cố định thì kết luận \"cửa sổ tấn công\"; ngược lại là benign. Mô hình **không chỉ ra flow nào độc**, chỉ trả lời cho cả cửa sổ. Nhãn của cửa sổ lúc huấn luyện là: có ít nhất một flow dương thì cửa sổ là dương."));
c.push(IMG(IMGDIR + "bilstm_flow.png", 640, 168));

// ------------------------------------------------------------ 2
c.push(H1("2. Hai ví dụ thật xuyên suốt tài liệu"));
c.push(P("Hai cửa sổ lấy từ tập TEST của OpTC (mô hình chưa từng được học trên chúng), cùng xác suất mà mô hình thật trả ra:"));
c.push(T(["", "Cửa sổ tấn công", "Cửa sổ benign"], [
  ["Máy, giờ", "`sysclient0010`, 25/9/2019 01:15 UTC", "`sysclient0616`, 21/9/2019 17:30 UTC"],
  ["Số flow", "30 flow, cả 30 đều là flow dương", "10 flow, không flow nào dương"],
  ["Mỗi flow là gì", "`powershell.exe` chạy từ \"tên trần\" (không có thư mục), tcp, cổng đích 443, tới `202.6.172.98`", "`firefox.exe` chạy từ Program Files, tcp, cổng đích 443"],
  ["Nhịp thời gian giữa các flow", "đều tăm tắp: mỗi flow cách flow trước khoảng 30 giây", "lộn xộn: 0.002 s, 0.014 s, 0.4 s, ..."],
  ["Xác suất của BiLSTM", "**1.0**", "**0.0005**"],
  ["Xác suất của Mixed-Type", "**1.0**", "**0.00005**"],
], [2000, 3919, 3719], { firstColFill: true }));
c.push(P("Đây là một beacon (kết nối liên lạc định kỳ tới máy chủ điều khiển, C2) của kịch bản SC2 trong OpTC. Các mục dưới đây dùng đúng hai cửa sổ này để minh họa từng bước."));

// ------------------------------------------------------------ 3
c.push(H1("3. Đầu vào: mỗi flow là mấy con số"));
c.push(P("Mỗi flow đã được tiền xử lý thành **4 con số nguyên (id) và 1 số thực**. Id là số thứ tự của giá trị trong từ điển (`0` = chưa biết, `<UNK>`; `1` = thiếu, `<MISSING>`; từ `2` trở đi là các giá trị đã biết xếp theo độ phổ biến trong TRAIN)."));
c.push(T(["Trường", "Ý nghĩa", "Ví dụ giá trị → id"], [
  ["`app_family`", "Tên chương trình tạo ra kết nối", "`firefox.exe` → 2; `cmd.exe` → 3; `powershell.exe` → 5"],
  ["`proto`", "Giao thức tầng giao vận", "`tcp` → 2; `udp` → 3"],
  ["`resp_port_class`", "Cổng đích, gom thành lớp", "`PORT_443_HTTPS` → 2; `PORT_80_HTTP` → 3"],
  ["`image_dir_class`", "Chương trình chạy từ loại thư mục nào", "`PROGRAM_FILES` → 2; `BARE_NAME` (chỉ có tên, không có thư mục) → 3; `SYSTEM32` → 4"],
  ["`delta_t_log1p`", "ln(1 + số giây kể từ flow trước trong cửa sổ); flow đầu = 0", "30.1 giây → 3.438; 5 giây → 1.79; 0 giây → 0"],
], [2300, 3600, 3738]));
c.push(P("Hai cửa sổ ví dụ trông như sau khi đã thành số (đây là dữ liệu thật trong file shard `test_0001.npz`):"));
c.push(T(["Flow", "Cửa sổ tấn công: [app, proto, cổng, thư mục] và delta_t", "Cửa sổ benign: [app, proto, cổng, thư mục] và delta_t"], [
  ["1", "[5, 2, 2, 3]   delta_t = 0.000", "[2, 2, 2, 2]   delta_t = 0.000"],
  ["2", "[5, 2, 2, 3]   delta_t = 3.438", "[2, 2, 2, 2]   delta_t = 0.002"],
  ["3", "[5, 2, 2, 3]   delta_t = 3.438", "[2, 2, 2, 2]   delta_t = 0.014"],
  ["4", "[5, 2, 2, 3]   delta_t = 3.438", "[2, 2, 2, 2]   delta_t = 0.000"],
  ["5", "[5, 2, 2, 3]   delta_t = 3.438", "[2, 2, 2, 2]   delta_t = 0.424"],
  ["...", "(30 flow giống hệt nhau, cách đều)", "(10 flow, nhịp ngắn và không đều)"],
], [900, 4369, 4369]));
c.push(P("Cửa sổ ngắn hơn 512 flow được **đệm** (thêm flow rỗng cho đủ bó dữ liệu) và mô hình biết độ dài thật để không đọc phần đệm."));

// ------------------------------------------------------------ 4
c.push(H1("4. Xử lý bên trong, từng bước"));
c.push(H2("Bước 1 – Tra bảng embedding: id → vector"));
c.push(P("Mô hình không hiểu \"5\" nghĩa là `powershell.exe`. Với mỗi trường có một **bảng tra**: id nào ứng với một vector (một dãy số) do mô hình tự học. Flow có cùng id thì dùng chung một vector, nên các flow giống nhau trông giống nhau với mô hình. Kích thước vector: `app_family` 16 số, `proto` 4, `resp_port_class` 7, `image_dir_class` 6, tổng 33 số. Cộng một cờ nhị phân (luôn 0 trong bản B, giữ để tương thích) và `delta_t`, mỗi flow là **35 số**."));
c.push(P("Đây cũng là chỗ \"mở rộng từ điển\" xảy ra: thêm token mới (ví dụ `firefox` của Linux) nghĩa là thêm một hàng mới vào bảng tra; hàng mới khởi tạo bằng bản sao của hàng `<UNK>` để lúc đầu mô hình xử lý đúng như trước, rồi mới học dần."));
c.push(H2("Bước 2 – Gộp thành vector flow"));
c.push(P("35 số được trộn qua một lớp tuyến tính, chuẩn hóa và hàm kích hoạt để thành một vector **64 số** \"mô tả một flow\". Vector này hòa lẫn thông tin: chương trình nào, giao thức nào, cổng nào, thư mục nào, và cách flow trước bao lâu."));
c.push(H2("Bước 3 – BiLSTM đọc cả dãy flow"));
c.push(P("**LSTM** là một mạng đọc dãy theo thứ tự và có \"bộ nhớ\": mỗi lần đọc một flow, nó cập nhật trí nhớ về những gì đã thấy (ví dụ \"đã thấy 20 flow `powershell.exe` đều đặn\"). **Bi** nghĩa là hai chiều: một lượt đọc từ flow đầu đến flow cuối, một lượt đọc ngược lại, nên mỗi vị trí được hiểu trong bối cảnh cả trước lẫn sau. Mô hình dùng 1 lớp, mỗi chiều có 64 đơn vị nhớ."));
c.push(H2("Bước 4 – Tóm tắt cửa sổ"));
c.push(P("Sau khi đọc xong, lấy trạng thái nhớ cuối cùng của mỗi chiều (64 số mỗi chiều), ghép lại thành **vector 128 số tóm tắt cả cửa sổ**. Đây là \"bản nhớ\" của mô hình về toàn bộ cửa sổ."));
c.push(H2("Bước 5 – Phân loại"));
c.push(P("Vector 128 số đi qua một mạng nhỏ (128 → 64 → 1) cho ra một số thực, rồi hàm sigmoid ép về khoảng 0–1 thành **xác suất tấn công**. Với hai ví dụ: cửa sổ beacon 30 flow cho 1.0; cửa sổ duyệt web 10 flow cho 0.0005."));
c.push(P("Tổng cộng mô hình có khoảng **78,700 tham số** (nhỏ), phần lớn nằm ở LSTM."));

// ------------------------------------------------------------ 5
c.push(H1("5. Mô hình biết nhãn bằng cách nào"));
c.push(P("**Nhãn không phải là đầu vào.** Nhãn chỉ dùng khi huấn luyện và khi chấm điểm. Nhãn của từng flow đến từ bước làm dữ liệu (ở OpTC: nhãn trong log mạng theo IP máy chủ điều khiển và giờ); nhãn cửa sổ = có ít nhất một flow dương."));
c.push(P("**Quá trình học** (lặp qua nhiều vòng, mỗi vòng là một epoch):"));
c.push(B("Mô hình đoán xác suất cho từng cửa sổ TRAIN, rồi so với nhãn thật. Độ sai gọi là loss."));
c.push(B("Dựa vào độ sai, các con số bên trong (bảng embedding, trọng số LSTM, mạng phân loại) được chỉnh một chút theo hướng giảm sai."));
c.push(B("**Dữ liệu cực mất cân bằng:** TRAIN có 160,210 cửa sổ nhưng chỉ 401 cửa sổ dương (khoảng 1 trên 400). Để mô hình không lờ cửa sổ dương, loss tính **mẫu dương nặng gấp khoảng 398.5 lần** (đúng bằng tỉ lệ âm trên dương)."));
c.push(B("Sau mỗi epoch đo trên tập VAL; dừng sớm nếu 3 epoch liền không cải thiện (PR-AUC trên VAL). Bản BiLSTM tốt nhất ở epoch 2 và dừng ở epoch 5. Tốc độ học 0.001, tối đa 8 epoch, mỗi lần 64 cửa sổ."));
c.push(B("**Ngưỡng** (xác suất bao nhiêu thì coi là tấn công) chọn trên VAL sao cho F1 cao nhất: 0.9956. TEST chỉ được chấm một lần ở ngưỡng đã chốt."));
c.push(H2("Vậy nó \"nhận ra\" tấn công dựa vào cái gì"));
c.push(P("Mô hình không hiểu thế nào là độc hại. Nó học các **dấu hiệu thống kê** xuất hiện nhiều ở cửa sổ dương trong TRAIN. Với 5 trường đầu vào, các dấu hiệu có thể dùng là:"));
c.push(B("**Tên chương trình và nơi chạy:** `powershell.exe`, chương trình chạy từ thư mục Temp/AppData hoặc từ \"tên trần\" xuất hiện nhiều ở cửa sổ dương."));
c.push(B("**Nhịp lặp:** cùng một chương trình, cùng một cổng, lặp lại với khoảng cách đều (beacon). `delta_t` giống nhau nhiều lần như 3.438 ở ví dụ."));
c.push(B("**Cổng hiếm hoặc giao thức hiếm.**"));
c.push(NOTE("**Điều cần nói thẳng khi trình bày.** Ở OpTC, luật một dòng \"cửa sổ có `powershell.exe`\" đã cho F1 0.994 trên TEST, ngang mô hình (0.988). Tức phần lớn điểm của mô hình đến từ tên chương trình và nơi chạy; nhịp và cổng đóng góp ít. Điểm cao ở OpTC vì vậy không chứng minh mô hình học được hành vi tấn công tổng quát. Và vì mô hình trả lời theo cả cửa sổ, một vài flow độc lẫn trong hàng nghìn flow benign (ví dụ 8 flow beacon giữa 1,800 flow `firefox.exe`) rất dễ bị chìm."));

// ------------------------------------------------------------ 6
c.push(H1("6. Kết quả: ma trận nhầm lẫn"));
c.push(P("Bản B, ngưỡng chọn trên VAL (0.9956). Một \"mẫu\" là một cửa sổ (hoặc một khúc 512 flow của cửa sổ dài):"));
c.push(T(["Tập", "TP (bắt đúng tấn công)", "FP (báo nhầm)", "FN (bỏ sót)", "TN (benign đúng)", "Precision / Recall / F1"], [
  ["VAL", "83", "0", "0", "34,278", "1.000 / 1.000 / 1.000"],
  ["TEST", "80", "0", "2", "34,331", "1.000 / 0.976 / **0.988**"],
  ["TRAIN", "chưa xuất ma trận", "", "", "", "loss huấn luyện giảm 0.49 → 0.03 (5 epoch)"],
], [900, 2100, 1500, 1500, 1700, 1938]));
c.push(P("Ma trận nhầm lẫn trên TRAIN chưa được xuất ở lần chạy Kaggle; muốn có phải chạy lại suy luận trên TRAIN (160,210 mẫu). Chỉ có 82 cửa sổ dương ở TEST nên một cửa sổ bằng 1.2 điểm recall."));

// ------------------------------------------------------------ 7
c.push(H1("7. Bảng tham số tóm tắt"));
c.push(T(["Mục", "Giá trị"], [
  ["Đầu vào mỗi flow", "4 id (app_family, proto, resp_port_class, image_dir_class) + delta_t (+ 1 cờ luôn 0)"],
  ["Embedding", "61, 4, 11, 10 hàng; chiều 16, 4, 7, 6"],
  ["Vector flow / bộ nhớ LSTM", "64 / 64 mỗi chiều, 1 lớp, hai chiều"],
  ["Tóm tắt cửa sổ", "128 số; phân loại 128 → 64 → 1"],
  ["Số tham số", "78,698"],
  ["Loss", "BCE có trọng số dương 398.5 (tỉ lệ âm/dương của TRAIN)"],
  ["Huấn luyện", "AdamW, lr 0.001, weight decay 0.0001, batch 64, dropout 0.2, cắt gradient 1.0, tối đa 8 epoch, dừng sớm 3 epoch theo PR-AUC của VAL, seed 42"],
  ["Ngưỡng", "0.9956 (chọn trên VAL, F1 lớn nhất)"],
], [2800, 6838], { firstColFill: true }));

// ------------------------------------------------------------ 8
c.push(H1("8. Khi fine-tune trên THEIA và ATLASv2"));
c.push(B("Mô hình gốc giữ nguyên kiến trúc; chỉ **mở rộng bảng embedding** (thêm hàng cho tên chương trình và lớp thư mục mới, khởi tạo bằng bản sao `<UNK>`)."));
c.push(B("Dữ liệu mới được đưa về đúng 5 trường này và cùng định dạng shard; thêm một phần dữ liệu OpTC cũ trộn vào lúc học để mô hình không quên."));
c.push(B("Đánh giá bằng ma trận nhầm lẫn trên TRAIN và TEST của dữ liệu mới; thêm ma trận trên TEST OpTC để biết mô hình có bị quên không."));
c.push(B("Hạn chế: nhãn THEIA/ATLASv2 mức tiến trình hoặc cạnh; số cửa sổ dương rất ít; từ vựng Linux khác Windows."));

// ------------------------------------------------------------ 9
c.push(H1("9. Bản đầy đủ khác bản B ở đâu"));
c.push(P("Bản đầy đủ (kết quả TEST: F1 0.988) có thêm `service`, `conn_state`, `principal_class`, 7 số của Bro (thời lượng, số byte, số gói, ...) và cờ `has_missed_bytes`. Các trường này không có ở THEIA/ATLASv2 nên bản B bỏ chúng; kết quả TEST của bản B vẫn F1 0.988 vì tên chương trình và nơi chạy đã đủ tách ở OpTC."));

build("BiLSTM – Mô tả mô hình", "Mô hình BiLSTM của nhánh Network DL: đầu vào, xử lý và cách nhận biết nhãn", c, process.argv[2]).then(() => console.log("ok"));
