# LightGBM + GraphSAGE v4: truy vết lỗi theo sự kiện và kịch bản

**Phạm vi.** Chỉ xét `code/kaggle/notebooks/lgbm_two_stage_cascade.ipynb` với `code/output/provenace_graph/kaggle_output/lgbm-two-stage-cascade-results/`. Nguồn đo chính là `two_stage_cascade_metrics.json`, toàn bộ 1.208 dòng `test_errors_full_scores.jsonl`, `source_index.json`, các shard Host seed02, vector census và raw eCAR. Script đối soát `code/output/provenace_graph/audit_v4_root_causes/census.py` tạo `census.json` và `errors_with_controls.jsonl`. Tất cả nguồn thô được đọc, không sửa. Từ “nguyên nhân” dưới đây chỉ cơ chế quan sát được trong quyết định mô hình; chứng minh một thay đổi sẽ sửa lỗi cần ablation trên validation.

## Mô hình thực sự quyết định như thế nào

LightGBM và GraphSAGE **không tìm một sự kiện mẫu rồi so sánh với nó lúc inference**. LightGBM dùng các nhánh cây học từ TRAIN để biến vector nhị phân thành score; GraphSAGE tổng hợp đặc trưng nút/cạnh đã học rồi cho score. Một sự kiện TRAIN nhãn ngược với vector giống hệt là *đối chứng chẩn đoán*: nó chứng minh hai sự kiện không thể được LightGBM phân biệt từ đầu vào hiện tại, chứ không chứng minh LightGBM đã “nhớ” đúng sự kiện đó. “Trọng số” của LightGBM không phải một trọng số cho từng sự kiện. Các mức đóng góp theo đường đi cây trong `code/output/host_ml_seed02/fp_fn_casebook/explanations.json` là phép phân rã log-odds, **không phải SHAP hay quan hệ nhân quả**.

Policy v4 chọn trên validation: ML <0.30 → benign; 0.30≤ML<0.96 → GraphSAGE với ngưỡng 0.95; ML≥0.96 → malicious. Full TEST 1.249.689 dòng: TP 39.732, FP 630, FN 578, TN 1.208.749; precision 0,984391, recall 0,985661, F1 0,985026. Đường đi thẳng tạo **379 FP, 269 FN**; đường GraphSAGE tạo **251 FP, 309 FN**. `graph_score` của nhánh đi thẳng trong file full-scores là chẩn đoán tính *sau quyết định*, không tham gia dự đoán v4.

| Lỗi/route | Số lỗi | Có vector giống hệt TRAIN nhãn ngược | Cả hai nhãn tồn tại trong TRAIN cho vector ấy | Vector duy nhất |
| --- | ---: | ---: | ---: | ---: |
| FP, ML đi thẳng | 379 | 305 | 255 | 175 |
| FN, ML đi thẳng | 269 | 238 | 155 | 203 |
| FP, qua GraphSAGE | 251 | 158 | 155 | 116 |
| FN, qua GraphSAGE | 309 | 237 | 205 | 166 |

Tổng cộng **938/1.208 lỗi (77,6%)** có đối chứng nhãn ngược, vector Host giống hệt trong TRAIN partition. Census TRAIN này có 333 dòng benign bị bỏ trước khi fit LightGBM, nên “có trong TRAIN partition” không luôn đồng nghĩa “được fit”. Nhiều lỗi lặp trong cùng tiến trình/vector; các con số là **event**, không phải 938 nguyên nhân độc lập. Exact-vector collision là chứng cứ mạnh về thiếu khả năng phân biệt bằng *Host vector*, nhưng không đủ để kết luận nhãn sai hoặc GraphSAGE cũng không thể phân biệt.

## Vì sao các sự kiện ML đi thẳng sai

**FP, Chrome đọc font, SC2.** TEST `source_id=1b70bf046dfc4b986018604e0cfb71164280863a53edfbb18ae8446f05e76882`, dòng giải nén **2.380.855**, benign, Chrome `READ FILE WINDOWS\FONTS\COMICBD.TTF`. Đối chứng TRAIN label 1 ở sysclient0501 dòng **2.335.212** đọc `Windows\fonts\sylfaen.ttf`. Hai vector 10 cột giống hệt; cả hai nhận ML **0,971660**, nên policy đi thẳng dương và TEST thành FP. Tên font cụ thể và `size` khác nhau trong raw log nhưng không phân biệt được qua vector. Graph chẩn đoán của TEST cũng **0,997730**; đây không phải trường hợp chỉ cần route thêm là chắc chắn hết FP. Đóng góp đường cây nổi bật gồm `principal::admin_account` **+0,995** và `image_path::basename=chrome.exe` **+0,849** log-odds, bên cạnh các đóng góp âm lớn; không quy lỗi cho riêng một token.

**FP, PowerShell Start-Sleep, SC2.** TEST cùng source dòng **2.813.533** có `context_info` cho thấy updater chạy `powershell.exe -File c:\autoupdate\updater.ps1`; TRAIN nhãn 1 sysclient0501 dòng **1.687.226** có cùng cmdlet trong PowerShell hidden/encoded. Vector giống hệt; ML **0,989433** cho cả hai. `action::command` **+4,651**, `image_path::basename=powershell.exe` **+3,435**, `shell::invocation=start-sleep` **+1,103** log-odds trong phép phân rã cây, dù cũng có tín hiệu âm. Sự khác nhau trong `context_info` không thành Host feature. Graph chẩn đoán TEST **0,086251**, tức có tín hiệu veto, nhưng gate ≥0,96 không dùng GraphSAGE. Đây là lỗi **biểu diễn Host kết hợp routing**, không phải lỗi không dựng được graph.

**FN, PING loopback, SC1.** TEST sysclient0402 dòng **2.977.354** label 1 là `TERMINATE PROCESS`, lệnh `ping -w 2000 -n 2 127.0.0.1`. TRAIN benign sysclient0051 dòng **1.915.449** có cùng vector/hành vi. ML cùng **0,142003** dưới ngưỡng 0,30, nên TEST bị loại trước graph. Graph chẩn đoán TEST cũng chỉ **0,003315**; việc chỉ route thêm trường hợp này cũng không cứu được ở ngưỡng 0,95. `image_path::basename=ping.exe` đóng góp **+2,149** nhưng các nhánh khác, đặc biệt thiếu `image_path::subcategory=system32` **−4,786**, kéo tổng score xuống. Đây là phân rã *đường cây*, không chứng minh lỗi do một cột. TEST sysclient0005 dòng **2.408.546** (`sppsvc.exe`, `THREAD TERMINATE`) tương tự: ML **0,235908**, graph chẩn đoán **0,001555**, dù có hai cạnh CREATE.

Trong toàn bộ lỗi đi thẳng, **105/379 FP** có graph chẩn đoán <0,95 (ứng viên veto) và **53/269 FN** có graph chẩn đoán ≥0,95 (ứng viên rescue). Đây là đếm trên TEST để giải thích quyết định, **không phải** rule được phép chọn bằng TEST. Phần còn lại không được sửa chỉ bằng cách hỏi GraphSAGE ở cùng ngưỡng.

## Vì sao đã qua GraphSAGE vẫn sai

Graph input v4 lấy bằng chứng **trước timestamp sự kiện** từ SQLite thô, độc lập với mask TRAIN/VAL/TEST. Nó có nút `Process`/`Host`, cạnh `creates`, `hosts`, `communicates` và các fact coarse như launch/location/network. Nó **không có nút FILE hay MODULE**, không đưa hành động/đối tượng của chính sự kiện đích vào graph. Đây là giới hạn biểu diễn có chủ đích; không thể khẳng định thêm FILE/MODULE sẽ cải thiện nếu chưa thử validation. Vì index raw label-blind được tạo trước split, split seed02 **không cắt cha/ông** khỏi graph. Điều kiện strict-past có thể loại sự kiện cùng timestamp hoặc metadata thiếu thật; đó là cơ chế khác với “cắt bởi split”.

Đối soát graph v4 cho thấy **301/309 FN qua graph có ít nhất một cạnh CREATE; chỉ 8 thiếu cạnh**, và **251/251 FP qua graph có CREATE**. Không có missing target lookup/identity. Vậy mất quan hệ cha–con không phải nguyên nhân chính của 560 lỗi graph còn lại. Exact microsecond cutoff đã phục hồi một số cạnh cùng giây; checkpoint GraphSAGE vẫn được huấn luyện với snapshot làm tròn giây, nên ảnh hưởng của phân phối graph mới lên score chưa được kiểm tra bằng retraining.

Năm cặp đối chứng bên dưới khi dựng lại bằng SQLite v4 đều có hai cạnh CREATE ở cả TEST và TRAIN. Chúng cũng đều mang flag `truncated` và `unresolved_relation`, nghĩa là graph *có* ancestry nhưng không nhất thiết chứa mọi nhánh/hàng xóm. Vì các flag xuất hiện ở cả đối chứng đúng và sự kiện sai, không thể quy riêng lỗi cho chúng nếu thiếu ablation.

**FN, Edge partial download, SC2.** TEST sysclient0005 dòng **2.653.068** label 1: `MicrosoftEdgeCP.exe` tạo `Downloads\movingonup.exe...partial`; đối chứng TRAIN benign sysclient0351 dòng **2.221.325** tạo `Downloads\update.exe...partial`. Host vector giống 90% theo Jaccard, ML lần lượt **0,932255/0,093840**; TEST được route nhưng graph **0,853858 <0,95** nên FN (đối chứng benign graph **0,893848** trong audit cùng checkpoint). Graph nhìn thấy bối cảnh tiến trình/host trước đó, nhưng không thấy nút file đích hay tên file tại quyết định này. Nó xếp cả hai dưới ngưỡng; không thể kết luận chỉ thiếu FILE node là nguyên nhân duy nhất.

**FP, Chrome renderer, SC2.** TEST sysclient0005 dòng **2.394.489** benign `OPEN PROCESS`; đối chứng TRAIN label 1 sysclient0501 dòng **2.386.419** có cùng Host vector, ML **0,912526**. Graph của TEST **0,997730**, đối chứng **0,994231** trong audit checkpoint; cả hai được dự đoán dương. Cả hai có browser actor và hai CREATE edges. Đây là lỗi khi graph *đã dựng* nhưng ngữ cảnh coarse vẫn tương tự cho hai nhãn.

**FP do bối cảnh rủi ro phủ lên event benign, SC1.** TEST sysclient0402 dòng **2.982.008** là `PING.EXE MODULE LOAD msvcrt.dll`, label 0, ML **0,896068**. CREATE trước đó 6 ms nối PING với PowerShell và đích mạng `142.20.57.226`; graph v4 có hai CREATE edges và cho **0,998326**, gây FP. Raw event được gắn nhãn benign dù bối cảnh tiến trình đáng ngờ. Đây là bằng chứng cụ thể rằng *có thêm cạnh* cũng có thể tăng FP khi nhãn là cấp sự kiện.

Một đối chứng tích cực: TEST malicious `lwabeat.exe OPEN PROCESS` sysclient0351 dòng **1.816.073** và TRAIN benign sysclient0051 dòng **1.915.101** cùng Host vector/ML **0,339562**, nhưng graph **0,968561** so với **0,041357**; graph tách được khi bối cảnh CREATE/launch khác rõ. Không nên gộp tất cả 560 lỗi graph vào “GraphSAGE vô dụng”.

Nguồn nhãn giải thích phần khó: [bài nghiên cứu địa phương](../a_new_hope_for_darpa_optc/A%20New%20Hope%20for%20DARPA%20OpTC.pdf) mục 4.1/4.3 nói nhãn host theo tiến trình, con của tiến trình và các event của chúng; chính tác giả nêu các tiến trình bình thường trong RDP session độc hại có thể bị gắn nhãn malicious. Vì thế `ping`, `conhost`, đọc font/DLL riêng lẻ không nhất thiết chứa đủ bằng chứng để suy ra nhãn kế thừa. Không có căn cứ coi các nhãn ví dụ trên là sai.

## Lỗi tập trung ở SC nào?

SC dưới đây được xác định bằng danh sách host **không giao nhau** của các file `ground_truth_corrected_sc?_evts_sysclient*.json.gz` trong bộ nghiên cứu. Đó là **cohort host của SC**, không phải xác nhận từng FP label-0 là event tấn công SC; một số FP còn nằm trong file ngày benign. FN label-1 thuộc host SC tương ứng theo split, nhưng bảng này chưa kiểm tra từng `id` với danh sách event corrected SC. Mẫu số lấy từ **toàn bộ TEST shard trên cùng host**, không lấy số sự kiện trong Table 4 của bài báo.

| Cohort | TEST malicious | TEST benign | FN (direct/graph) | FP (direct/graph) | Recall | FPR | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| SC1, 17 host | 14.569 | 215.748 | **286** (146/140) | 133 (113/20) | 98,04% | 0,0616% | 98,55% |
| SC2, 10 host | 21.659 | 898.608 | 233 (68/165) | **370** (249/121) | 98,92% | 0,0412% | 98,61% |
| SC3, 2 host | 4.077 | 64.918 | 59 (55/4) | 127 (17/110) | 98,55% | **0,1956%** | **97,74%** |
| Host ngoài ba danh sách | 5 | 30.105 | 0 | 0 | 100% | 0% | 100% |

SC1 có **nhiều FN tuyệt đối nhất** (286/578); SC2 có **nhiều FP tuyệt đối nhất** (370/630) vì cũng có nhiều benign event nhất. SC3 có **tỷ lệ FP trên benign cao nhất**, và 102/110 FP qua graph ở SC3 tập trung ở `sysclient0351`. Các cụm host lớn khác: sysclient0501 228 lỗi, sysclient0201 197, sysclient0974 156, sysclient0005 149. Đây là event counts, không phải số chiến dịch hay số tiến trình độc lập.

**Kết luận có mức chứng cứ rõ:** nguyên nhân trực tiếp của nhánh ML là gate cùng các vector Host không tách được event nhãn ngược; ở nhánh GraphSAGE, phần lớn graph có ancestry nhưng biểu diễn prior Process/Host coarse và ngưỡng 0,95 vẫn xếp sai các subevent gần nhau về hành vi. Cơ chế nhãn kế thừa theo tiến trình làm một số sự kiện rất khó suy ra chỉ từ event. Tài liệu hiện tại không chứng minh FILE/MODULE nodes hoặc retraining sẽ sửa được bao nhiêu lỗi; muốn định lượng phải thiết kế ablation và chọn policy chỉ trên validation.
