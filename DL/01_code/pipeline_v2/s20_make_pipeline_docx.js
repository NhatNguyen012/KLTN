const { P, H1, H2, B, NOTE, T, SP, CODE, IMG, build } = require("./s20_docx_lib.js");
const IMGDIR = "D:/UIT/KLTNv2/02_artifacts/39_dataset_word_v1/img/";

const c = [];
c.push(P("**Mục đích:** mô tả toàn bộ đường đi của dữ liệu từ log thô (raw) đến các shard đưa vào mô hình: từng bước nhận gì, làm gì, ra gì, kèm **ví dụ thật** ở đầu vào và đầu ra mỗi bước. Phần chính là OpTC (dữ liệu đã dùng để train, pipeline v2, ngày chạy 13/10/2026). Mục 8 nói cách áp dụng cho THEIA và ATLASv2."));
c.push(NOTE("**Ví dụ xuyên suốt:** một flow tấn công của máy `sysclient0255` lúc 23/9/2019 19:15:53 UTC (`powershell.exe` kết nối tới `132.197.158.98:80`, uid `CaYeyw4Odk0qg3aek6`). Hai dòng raw của flow này mình lấy thẳng từ `E:\\bro` và `E:\\ecar-bro`; các đầu ra là file thật của pipeline v2. Với bước 4 dùng thêm hai cửa sổ ví dụ (tấn công 30 flow, benign 10 flow) lấy từ shard TEST."));
c.push(IMG(IMGDIR + "pipeline_flow.png", 640, 168));

// ------------------------------------------------------------ 1
c.push(H1("1. Tổng quan các bước"));
c.push(T(["Bước", "Đầu vào", "Làm gì", "Đầu ra", "Mã"], [
  ["0. Raw", "log mạng Bro/Zeek và log host eCAR-Bro (9 ngày, 17–25/9/2019)", "(không xử lý, chỉ đọc)", "—", "—"],
  ["S1. Join", "Bro `conn.*.log.gz` + eCAR-Bro `ecarbro.json.gz`", "ghép mỗi kết nối mạng với tiến trình tạo ra nó (INNER JOIN theo uid)", "`flows_joined.parquet` (92,045,755 flow)", "`s1_join.py`"],
  ["S2. Cửa sổ và split", "`flows_joined.parquet`", "gom flow thành cửa sổ (máy × 15 phút), chia TRAIN/VAL/TEST 70/15/15", "`windows.csv` (110,402 cửa sổ)", "`s2_windows_split.py`"],
  ["S3. Preprocess", "flow thuộc cửa sổ TRAIN", "xây từ điển, thống kê chuẩn hóa; **không dùng nhãn, VAL, TEST**", "`preprocess_spec.json`", "`s3_preprocess.py`"],
  ["S4. Shards", "flows_joined + windows + spec", "mã hóa từng flow thành số; đóng gói thành sample (khúc ≤ 512 flow)", "86 file `.npz` (4.6 GB) + `samples.csv`", "`s4_shards.py`"],
  ["S5. Kiểm tra", "tất cả các đầu ra trên", "giải mã ngược 400 sample so với raw; kiểm tra số đếm", "`PASS`", "`s5_validate.py`"],
], [1400, 2300, 2700, 2000, 1238], { size: 17 }));

// ------------------------------------------------------------ 2
c.push(H1("2. Bước 0 – Dữ liệu raw"));
c.push(H2("2.1 Log mạng Bro/Zeek: `E:\\bro\\<ngày>\\conn.*.log.gz`"));
c.push(P("Định dạng: văn bản TSV (cách nhau bằng tab), một dòng một kết nối, nén gzip, mỗi giờ một file (210 file, 10.4 GB nén). Dòng `#fields` cho biết 22 cột:"));
c.push(...CODE(["ts  uid  id.orig_h  id.orig_p  id.resp_h  id.resp_p  proto  service  duration  orig_bytes  resp_bytes  conn_state", "local_orig  local_resp  missed_bytes  history  orig_pkts  orig_ip_bytes  resp_pkts  resp_ip_bytes  tunnel_parents  label"]));
c.push(P("**Ví dụ thật** (file `conn.19_00_00-20_00_00.log.gz` ngày 2019-09-23), dòng của flow ví dụ:"));
c.push(T(["Cột", "Giá trị", "Ý nghĩa"], [
  ["ts", "1569266153.143904", "giờ (epoch UTC, giây)"],
  ["uid", "CaYeyw4Odk0qg3aek6", "mã định danh kết nối, dùng để ghép với log host"],
  ["id.orig_h : id.orig_p", "142.20.57.0 : 61867", "IP và cổng nguồn"],
  ["id.resp_h : id.resp_p", "132.197.158.98 : 80", "IP và cổng đích"],
  ["proto / service", "tcp / http", "giao thức và dịch vụ Bro nhận diện"],
  ["duration", "0.052996", "thời lượng (giây)"],
  ["orig_bytes / resp_bytes", "199 / 1443", "số byte gửi / nhận"],
  ["conn_state", "SF", "trạng thái kết nối (SF = bình thường, đóng đúng)"],
  ["history", "ShADadfF", "chuỗi cờ TCP"],
  ["orig_pkts / orig_ip_bytes", "5 / 411", "số gói và byte IP gửi"],
  ["resp_pkts / resp_ip_bytes", "6 / 1695", "số gói và byte IP nhận"],
  ["**label**", "**1**", "**nhãn tấn công theo IP máy chủ điều khiển và giờ (bài A New Hope)**"],
], [2600, 2900, 4138], { size: 17 }));
c.push(H2("2.2 Log host eCAR-Bro: `E:\\ecar-bro\\...\\ecarbro.json.gz`"));
c.push(P("Định dạng: mỗi dòng một JSON, nén gzip (156 file, 6.5 GB nén). Mỗi dòng là một sự kiện của agent trên máy; ở đây dùng sự kiện `object = FLOW`, cho biết **tiến trình nào** đã tạo kết nối. Dòng **thật** ứng với flow ví dụ (file `evaluation/23Sep19-red/AIA-251-275/ecarbro.json.gz`):"));
c.push(...CODE(String.raw`{"timestamp":"2019-09-23T15:15:11.746-04:00","id":"fc18a673-d2a0-4c32-838f-c54379c23b55","hostname":"SysClient0255.systemia.com","objectID":"5eb03d04-7dd7-44bb-b58b-f78d31d4bbbd","object":"FLOW","action":"INFO","actorID":"b5a0a459-229f-4e49-9783-e39a150804e6","pid":3472,"ppid":2684,"tid":-1,"principal":"SYSTEMIACOM\\zleazer","properties":{"acuity_level":"1","bro_uid":"CaYeyw4Odk0qg3aek6","dest_ip":"132.197.158.98","dest_port":"80","direction":"outbound","image_path":"powershell.exe","l4protocol":"6","src_ip":"142.20.57.0","src_port":"61867"}}`.match(/.{1,150}/g), { size: 14 }));
c.push(P("Các trường quan trọng: `properties.bro_uid` (khóa ghép với Bro `uid`), `properties.image_path` (chương trình tạo kết nối: `powershell.exe`), `hostname`, `actorID`, `pid`, `ppid` (tiến trình và tiến trình cha), `principal` (tài khoản chạy), `direction`. Lưu ý giờ ở đây là EDT (UTC−4): 15:15:11 EDT = 19:15:11 UTC, khớp với `ts` bên Bro."));

// ------------------------------------------------------------ 3
c.push(H1("3. Bước S1 – Join: mỗi flow mạng kèm tiến trình"));
c.push(P("**Đầu vào:** hai nguồn ở mục 2. **Làm gì:** (1) đọc 92,097,521 bản ghi eCAR-Bro có `bro_uid`, loại các `uid` trùng (26,347 uid xuất hiện nhiều lần, giữ bản sớm nhất); (2) chuẩn hóa tên máy (chữ thường, bỏ phần miền: `SysClient0255.systemia.com` thành `sysclient0255`); `app_family` = tên file của `image_path`; (3) với mỗi ngày Bro, **INNER JOIN** theo `uid = bro_uid` (flow nào không có bản ghi eCAR-Bro thì bị loại); (4) gộp 9 ngày, sắp theo (máy, giờ), ghi một file parquet; (5) thêm cột `ts_utc`, `date_utc`, `window_start_epoch = floor(ts/900)×900`."));
c.push(P("**Đầu ra:** `S1_join/data/flows_joined.parquet` (2.6 GB). 92,045,755 flow, 743 máy, trong đó 24,721 flow dương. Có 4,509 flow độc hại của Bro không có bản ghi eCAR-Bro nên không vào bảng (hệ quả của inner join). **Ví dụ thật** – dòng đầu ra cho flow ví dụ (34 cột; các cột hiển thị nhóm theo nguồn):"));
c.push(T(["Nhóm", "Cột và giá trị"], [
  ["Định danh, giờ", "uid = `CaYeyw4Odk0qg3aek6`; ts_utc = `2019-09-23 19:15:53.143904`; hostname = `sysclient0255`; window_start_epoch = 1569266100; **label = 1**"],
  ["Từ eCAR-Bro (host)", "app_family = `powershell.exe`; image_path = `powershell.exe`; direction = `outbound`; actor_id = `b5a0a459-...`; pid = 3472; ppid = 2684; principal = `SYSTEMIACOM\\zleazer`"],
  ["Từ Bro (mạng)", "orig_h:orig_p = `142.20.57.0:61867`; resp_h:resp_p = `132.197.158.98:80`; proto = `tcp`; service = `http`; duration = 0.052996; orig_bytes = 199; resp_bytes = 1443; conn_state = `SF`; history = `ShADadfF`; orig_pkts = 5; orig_ip_bytes = 411; resp_pkts = 6; resp_ip_bytes = 1695"],
], [2000, 7638], { firstColFill: true, size: 17 }));

// ------------------------------------------------------------ 4
c.push(H1("4. Bước S2 – Cửa sổ và chia tập"));
c.push(P("**Đầu vào:** `flows_joined.parquet` và danh sách 620 máy có cả log host lẫn log mạng. **Làm gì:**"));
c.push(B("**Cửa sổ** = (máy, khoảng 15 phút) theo `window_start_epoch`. Cửa sổ có thể rất nhiều flow nên được cắt thành các **chunk tối đa 512 flow**. **Nhãn cửa sổ = có ít nhất một flow dương.**"));
c.push(B("**Chia 70/15/15** cho TRAIN/VAL/TEST, **phân tầng**: cửa sổ dương theo kịch bản tấn công (SC1, SC2, SC3), cửa sổ benign theo ngày; trong mỗi tầng chia theo thứ tự băm sha256 nên tái lập được. Mọi chunk của một cửa sổ luôn nằm cùng một tập."));
c.push(B("**Không chia theo máy** (yêu cầu có chủ ý): 613/620 máy có cửa sổ ở cả ba tập, nên điểm đo khả năng nhận ra mẫu và máy đã thấy, không đo phát hiện trên máy mới."));
c.push(P("**Đầu ra:** `S2_windows_split/data/windows.csv`, 110,402 dòng. **Ví dụ thật:**"));
c.push(T(["", "Cửa sổ dương", "Cửa sổ benign"], [
  ["hostname", "sysclient0005", "sysclient0001"],
  ["window_start_utc", "2019-09-24 18:30:00", "2019-09-23 13:15:00"],
  ["scenario", "scenario_2", "(trống)"],
  ["n_flows / n_positive_flows", "7 / 7", "307 / 0"],
  ["label / stratum / split", "1 / scenario_2 / train", "0 / benign_2019-09-23 / train"],
], [2800, 3419, 3419], { firstColFill: true }));
c.push(T(["Tập", "Cửa sổ", "Cửa sổ dương", "Flow", "Flow dương"], [
  ["TRAIN", "77,281", "379", "59,902,514", "17,682"],
  ["VAL", "16,561", "81", "12,836,373", "3,495"],
  ["TEST", "16,560", "81", "12,887,298", "3,544"],
], [1300, 1800, 1900, 2338, 2300]));

// ------------------------------------------------------------ 5
c.push(H1("5. Bước S3 – Preprocess: từ điển và chuẩn hóa"));
c.push(P("**Đầu vào:** chỉ các flow thuộc cửa sổ **TRAIN** (77,281 cửa sổ, 59.9 triệu flow); không dùng nhãn, VAL hay TEST, để tránh rò rỉ thông tin. **Làm gì:**"));
c.push(B("**Trường phân loại → id.** Giá trị đưa về chữ thường; thiếu hoặc `-` thành `<MISSING>` (id 1); giá trị chưa có trong từ điển là `<UNK>` (id 0). Từ điển xếp theo số lần xuất hiện trong TRAIN giảm dần, id bắt đầu từ 2; giá trị quá hiếm (dưới 5 flow ở `app_family`, `service`) bị đưa về `<UNK>`."));
c.push(B("**Trường dẫn xuất:** `resp_port_class` từ cổng đích (cổng thông dụng thành tên như `PORT_443_HTTPS`; còn lại theo dải); `image_dir_class` từ thư mục của `image_path` (8 lớp)."));
c.push(B("**Trường số** (bản đầy đủ): lấy `log1p`, rồi chuẩn hóa z-score theo trung bình và độ lệch chuẩn của TRAIN, cắt ở ±10. Thiếu thì để 0 kèm một cờ \"thiếu\"."));
c.push(B("**`delta_t_log1p`:** ln(1 + số giây kể từ flow trước trong cùng chunk); flow đầu của chunk bằng 0. Ví dụ: 0 giây → 0; 5 giây → 1.79; 30 giây → 3.43; 300 giây → 5.71."));
c.push(B("**Quy tắc \"active\":** trường chỉ được dùng nếu có ít nhất 2 giá trị đủ phổ biến trong TRAIN; trường gần như hằng số bị tắt."));
c.push(P("**Đầu ra:** một file duy nhất `S3_preprocess/data/preprocess_spec.json` (từ điển, thống kê, thứ tự cột vào mô hình, dấu vân tay sha256), cộng `vocab.csv`. **Ví dụ thật – các từ điển (trích):**"));
c.push(T(["Trường", "Các id đầu", "Số giá trị"], [
  ["`app_family`", "2 `firefox.exe` (59.8 triệu flow); 3 `cmd.exe`; 4 `conhost.exe`; 5 `powershell.exe`; ...", "59 (68 giá trị gốc, 9 hiếm bị đưa về `<UNK>`)"],
  ["`proto`", "2 `tcp`; 3 `udp`", "2"],
  ["`resp_port_class`", "2 `PORT_443_HTTPS`; 3 `PORT_80_HTTP`; 4 `PORT_8080_HTTP_ALT`; 5 `PORT_53_DNS`; ...", "9"],
  ["`image_dir_class`", "2 `PROGRAM_FILES`; 3 `BARE_NAME`; 4 `SYSTEM32`; 5 `MISSING`; ...", "8"],
], [2300, 5100, 2238]));
c.push(P("**Ví dụ thật – mã hóa flow ví dụ** (kết quả bước này áp lên dòng ở mục 3):"));
c.push(T(["Trường", "Giá trị raw", "Kết quả"], [
  ["app_family", "`powershell.exe`", "id **5**"],
  ["proto", "`tcp`", "id **2**"],
  ["resp_port_class", "cổng 80 → `PORT_80_HTTP`", "id **3**"],
  ["image_dir_class", "`powershell.exe` (không có thư mục) → `BARE_NAME`", "id **3**"],
  ["service, conn_state", "`http`, `SF`", "id 3, id 2 (chỉ bản đầy đủ)"],
  ["orig_bytes (bản đầy đủ)", "199", "log1p = 5.298; z = (5.298 − 6.826) / 0.552 = **−2.768**"],
  ["duration (bản đầy đủ)", "0.052996 giây", "log1p = 0.0516; z = −0.079"],
], [2600, 3900, 3138]));
c.push(NOTE("Bản B (dùng để fine-tune) chỉ lấy 4 trường phân loại `app_family`, `proto`, `resp_port_class`, `image_dir_class` và `delta_t`; các trường số, `service`, `conn_state`, `principal_class` không dùng."));

// ------------------------------------------------------------ 6
c.push(H1("6. Bước S4 – Shards: đóng gói sample"));
c.push(P("**Đầu vào:** `flows_joined.parquet`, `windows.csv` (để biết cửa sổ nào thuộc tập nào), `preprocess_spec.json`. **Làm gì:**"));
c.push(B("**Sample** = các flow của một (máy, cửa sổ) sắp theo (`ts`, `uid`), cắt chunk mỗi 512 flow; nhãn sample = có ít nhất 1 flow dương."));
c.push(B("Mỗi flow mã hóa thành: 7 id phân loại, 7 z-score (+7 cờ thiếu), 1 cờ `has_missed_bytes`, `delta_t_log1p`, và hai chỉ số phụ."));
c.push(B("Sample của mỗi tập được xáo trộn có seed (20261013) rồi chia vào các file khoảng 1 triệu flow, nên mỗi file trộn nhiều máy và nhiều ngày."));
c.push(P("**Đầu ra:** 86 file `shards/{train,val,test}/*.npz` (4.6 GB) và `samples.csv` (một dòng một sample). Mỗi file `.npz` có các mảng nối tiếp mọi flow của file (T flow) cùng mảng `sample_offsets` cho biết sample nào chiếm đoạn nào:"));
c.push(T(["Khóa trong .npz", "Kiểu và kích thước", "Ý nghĩa"], [
  ["`x_cat`", "uint16 [T, 7]", "id của 7 trường phân loại (thứ tự: app_family, proto, service, conn_state, resp_port_class, image_dir_class, principal_class)"],
  ["`x_num`, `x_num_missing`", "float32/uint8 [T, 7]", "7 z-score và cờ thiếu"],
  ["`x_bin`", "uint8 [T, 1]", "`has_missed_bytes`"],
  ["`delta_t_log1p`", "float32 [T]", "ln(1 + giây từ flow trước)"],
  ["`sample_offsets`", "int64 [S+1]", "điểm đầu/cuối của từng sample trong mảng T"],
  ["`sample_labels` (và các mảng `sample_*`)", "uint8 [S]", "nhãn sample, số flow, số flow dương, cửa sổ, chỉ số chunk"],
], [2800, 2200, 4638], { size: 17 }));
c.push(P("**Ví dụ thật 1 – sample tấn công** (`sample_id` = `d54eb97632b0af70c3b89bad`, nằm ở `shards/test/test_0001.npz`, vị trí 43). Dòng của nó trong `samples.csv`:"));
c.push(T(["Cột", "Giá trị"], [
  ["split / date / hostname", "test / 2019-09-25 / sysclient0010"],
  ["window_start_utc / chunk_index", "2019-09-25 01:15:00 / 0"],
  ["label / event_count / positive_event_count", "1 / 30 / 30"],
  ["app_node_count / remote_node_count", "1 / 1 (một chương trình, một đích)"],
  ["shard_file / shard_sample_index", "shards/test/test_0001.npz / 43"],
], [4000, 5638], { firstColFill: true }));
c.push(P("Sáu flow đầu của sample này, như được lưu trong shard (7 cột phân loại theo thứ tự trên; bản B đọc cột 1, 2, 5, 6 cộng `delta_t`):"));
c.push(T(["Flow", "x_cat (7 id)", "delta_t_log1p", "Ý nghĩa"], [
  ["1", "[5, 2, 2, 2, 2, 3, 5]", "0.000", "powershell.exe, tcp, ssl, SF, 443, BARE_NAME, ADMINISTRATOR; flow đầu = 0"],
  ["2", "[5, 2, 2, 2, 2, 3, 5]", "3.438", "giống hệt, cách flow 1 khoảng 30.1 giây"],
  ["3", "[5, 2, 2, 2, 2, 3, 5]", "3.438", "giống hệt, lại cách 30 giây"],
  ["4–6", "[5, 2, 2, 2, 2, 3, 5]", "3.438", "..."],
], [800, 2900, 1700, 4238]));
c.push(P("**Ví dụ thật 2 – sample benign** (`48752b0307dd8e5dcc95739d`, `test_0001.npz`, vị trí 53; `sysclient0616`, 21/9/2019 17:30 UTC; 10 flow): các flow đều `[2, 2, 2, 2, 2, 2, 2]` (`firefox.exe`, tcp, ssl, SF, 443, PROGRAM_FILES, DOMAIN_USER), riêng flow thứ 7 có `conn_state` id 3; `delta_t` = 0.000, 0.002, 0.014, 0.000, 0.424, 0.003, 0.013, 0.005, 0.006, 0.003."));
c.push(P("**Số liệu đầu ra:**"));
c.push(T(["Tập", "Sample", "Sample dương", "Flow", "Flow dương", "Số file"], [
  ["TRAIN", "160,210", "401", "59,902,514", "17,682", "60"],
  ["VAL", "34,361", "83", "12,836,373", "3,495", "13"],
  ["TEST", "34,413", "82", "12,887,298", "3,544", "13"],
], [1200, 1600, 1800, 2000, 1700, 1338]));

// ------------------------------------------------------------ 7
c.push(H1("7. Bước S5 – Kiểm tra"));
c.push(P("Kiểm tra chéo và **giải mã ngược**: lấy 400 sample (150 dương, 250 benign), mã hóa lại bằng Python từ raw theo đúng spec, rồi so với những gì lưu trong shard. Kết quả **PASS**:"));
c.push(B("Cùng số flow; 0 flow sai id phân loại; sai số z-score lớn nhất 4.7×10⁻⁷; 0 sai cờ thiếu, `has_missed_bytes`, nhãn; sai số `delta_t` lớn nhất 2.4×10⁻⁷."));
c.push(B("Phạm vi fit của S3 đúng bằng các cửa sổ TRAIN của S2; mỗi cửa sổ chỉ ở một tập; số flow, flow dương, sample của mỗi tập khớp `windows.csv`."));
c.push(P("Ý nghĩa: đường đi raw → shard không làm mất hay đổi flow. Sau bước này shard được đóng gói và train trên Kaggle (BiLSTM, Mixed-Type)."));

// ------------------------------------------------------------ 8
c.push(H1("8. Áp dụng cho THEIA và ATLASv2 (fine-tune)"));
c.push(P("Cùng khung S1–S5 nhưng bước S1 khác (không có Bro/eCAR-Bro) và S3 chỉ **mở rộng** từ điển OpTC thay vì xây mới. Đây là thiết kế; mình chưa chạy đủ pipeline trên toàn bộ hai dataset, các ví dụ là một dòng minh họa lấy từ raw thật."));
c.push(T(["Bước", "OpTC (đã chạy)", "THEIA (Linux)", "ATLASv2 (Windows 7)"], [
  ["Raw", "Bro conn + eCAR-Bro FLOW", "JSON CDM18: `Event` (CONNECT...), `NetFlowObject`, `Subject`", "Carbon Black `cbc-edr` jsonl, hàng `endpoint.event.netconn`"],
  ["S1 – ra một bảng flow", "INNER JOIN `uid = bro_uid`", "gom `Event` theo `NetFlowObject` (`predicateObject`); bỏ ổ cắm thiếu đầu xa, LOCAL, NETLINK, 127.0.0.1; tên chương trình lấy từ sự kiện `EXECUTE` (không lấy từ `Subject`, vì đó là tên lúc fork)", "mỗi hàng netconn đã là một flow; bỏ dòng `ACTION_CONNECTION_LISTEN` hoặc `remote_ip` rỗng"],
  ["Nhãn", "cột `label` của conn.log", "`Event.uuid` có trong `edge_labels.csv` (hoặc `Subject.uuid` có trong `theia_labels.csv`)", "`process_guid` có trong `.labels`"],
  ["S2 – cửa sổ", "máy × 15 phút, chunk 512", "như OpTC, một máy", "như OpTC, hai máy"],
  ["S3 – từ điển", "xây mới từ TRAIN OpTC", "**mở rộng**: nối token mới (`firefox`, lớp thư mục Linux), hàng embedding mới khởi tạo bằng bản sao `<UNK>`, id OpTC cũ giữ nguyên", "mở rộng ít hơn (tên .exe phần lớn đã có trong từ điển)"],
  ["S4 – shards", "`.npz` 7 cột phân loại", "cùng định dạng, mã hóa bằng spec mở rộng, đọc 4 trường bản B + `delta_t`", "như THEIA"],
], [1500, 2000, 3500, 2638], { size: 17 }));
c.push(P("**Ví dụ thật – từ raw đến dòng sau tiền xử lý** (đã chụp cho slide):"));
c.push(T(["", "THEIA", "ATLASv2"], [
  ["Raw (một dòng chính)", "`Event` `EVENT_CONNECT` lúc 2018-04-10 18:54:16.612 UTC; `predicateObject` trỏ tới `NetFlowObject` `128.55.12.110:33157` → `141.43.176.203:80`; `subject` là tiến trình `7F1FD92F-...`", "hàng `netconn`: `firefox.exe` (`c:\\program files\\mozilla firefox\\firefox.exe`), `PROTO_TCP`, `185.199.108.153:443`, 2022-07-19 16:18:11"],
  ["Tên chương trình", "`EVENT_EXECUTE` của tiến trình: `cmdLine` = `/usr/bin/firefox` (bản ghi `Subject` còn ghi `fluxbox` vì đó là tên lúc fork)", "`process_path`"],
  ["Sau tiền xử lý", "app_family `firefox` (id mới 61), proto thiếu (id 1), resp_port_class `PORT_80_HTTP` (id 3), image_dir_class `SYSTEM_BIN` (id mới 10), delta_t 0.0, label 1", "app_family `firefox.exe` (id 2), proto `tcp` (id 2), `PORT_443_HTTPS` (id 2), `PROGRAM_FILES` (id 2), delta_t 0.0, label 1"],
], [2200, 3900, 3538], { firstColFill: true, size: 17 }));
c.push(P("Ghi chú: các id mới (61 cho tên chương trình, 10 cho lớp thư mục) là minh họa, id thật gán theo thứ tự tần suất trên TRAIN của dữ liệu mới. `delta_t` = 0.0 ở hai dòng này vì mỗi dòng được lấy riêng lẻ và coi là flow đầu cửa sổ (theo quy tắc bước S3); trong pipeline thật nó được tính từ flow đứng trước trong cửa sổ."));
c.push(H2("Các lớp thư mục Linux mới (image_dir_class)"));
c.push(P("Luật Windows của OpTC không có lớp cho đường dẫn Linux nên cần thêm lớp và nối vào từ điển (đề xuất của mình, chưa kiểm độ nhạy):"));
c.push(T(["Đường dẫn bắt đầu bằng", "Lớp mới"], [
  ["`/usr/bin/`, `/bin/`, `/sbin/`, `/usr/sbin/`", "`SYSTEM_BIN`"],
  ["`/usr/lib/`, `/lib/`", "`SYSTEM_LIB`"],
  ["`/tmp/`, `/var/tmp/`", "`TEMP_LINUX`"],
  ["`/var/log/` (nơi chương trình micro APT của THEIA chạy)", "`VAR_LOG`"],
  ["`/home/`", "`HOME_USER`"],
  ["`/etc/`, `/opt/`", "`ETC_OPT`"],
  ["còn lại", "`OTHER`"],
], [6400, 3238]));
c.push(H2("Hạn chế"));
c.push(B("THEIA không có `ipProtocol` nên `proto` thiếu; ATLASv2 không có byte, số gói, thời lượng (đã bỏ khỏi bản B)."));
c.push(B("Nhãn THEIA/ATLASv2 mức tiến trình hoặc cạnh (xem hai file mô tả dataset); số cửa sổ dương ít và chưa được đếm; chia trộn theo cửa sổ gây rò rỉ giữa các cửa sổ kề."));

build("Xử lý dataset từ raw đến shards", "Pipeline v2 của nhánh Network DL: đầu vào, đầu ra và ví dụ thật từng bước", c, process.argv[2]).then(() => console.log("ok"));
