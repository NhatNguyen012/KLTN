# STEP 09B — Phân tích cách gán nhãn (bài báo "A New Hope for DARPA OpTC") và kế hoạch retrain

**Trạng thái:** ANALYSIS COMPLETE — chưa retrain. Tiếp nối `STEP_09_LEAKAGE_AUDIT.md`.

Nguồn: Majorczyk, Pilastre, Dijoud, *A New Hope for DARPA OpTC*, CSET @ ACSAC 2025 (hal-05474126v2). Trong tài liệu này gọi tắt là "bài báo".

---

## 0. Kết luận ngắn

Metric ≈ 1.0 **không phải bằng chứng model học được APT behavior**. Nó là hệ quả gần như tất yếu của ba điều ghép lại: cách nhãn được tạo, loại traffic mà Bro nhìn thấy, và cách train/test được chia.

1. **Nhãn network = liên lạc C2 của cây process độc hại.** Bài báo gán nhãn network bằng IP của máy bị chiếm và IP của C2 server, lọc theo thời gian, rồi kiểm tra tay. Sau đó họ đồng bộ hai chiều qua eCAR-Bro: flow của process độc hại là malicious, và process tạo flow malicious cũng là malicious.
2. **Bro chỉ thấy traffic giữa hệ thống và Internet**, không thấy lateral movement. Vì vậy lớp positive trong nhánh Network gần như chỉ gồm *beacon của agent tới C2*.
3. **Input của model chứa đúng "chữ ký" của luật gán nhãn.** `app_family` chính là image của process agent (`powershell.exe`, cũng là process mà nhãn host bám theo). Timing/bytes lại là chữ ký của beacon. Trong khi đó benign traffic ra ngoài là firefox được script hóa. Kết quả là bài toán **tách được theo cấu trúc (separable by construction)**. Đây là **label-construction leakage (rò rỉ qua cách xây dựng nhãn)**: feature lặp lại tiêu chí dùng để gán nhãn.
4. **Host split đặt cùng một beacon template vào cả train và test.** Scenario 2 beacon suốt đêm 24→25/9. Bài báo cũng ghi nhận điều này ở host 501 (Appendix C): 72/83 positive test window là bản sao của train.

Với cùng bộ nhãn, các IDS provenance *unsupervised* trong bài báo (Kairos, Flash, GAE) ở mức graph 15 phút chỉ đạt F1 **0.13–0.87** (Table 2–3). Mô hình supervised của mình đạt 0.99 vì đã *thấy* chính chiến dịch đó trong train.

---

## 1. Những gì bài báo nói, liên quan trực tiếp tới pipeline

| Điểm trong bài báo | Mục | Hệ quả cho pipeline Network DL |
|---|---|---|
| OpTC 16–25/9/2019: 6 ngày benign, 3 ngày cuối mỗi ngày một APT scenario | §2.1 | scenario ≈ ngày; LOSO thực chất là leave-one-day-out |
| Bro NIDS có vẻ chỉ bắt traffic hệ thống ↔ Internet, **không có** traffic nội bộ | §2.1, §4.1 | nhánh Network không thấy lateral movement; positive = C2/exfil |
| Không có ground truth chính thức; chỉ có PDF mô tả Red Team (máy bị chiếm, pid agent, C2) | §1 | nhãn là do nhóm tác giả suy ra |
| **Nhãn network:** lọc Bro theo IP client bị chiếm + IP/hostname C2; lọc theo thời gian mỗi ngày (**trừ Scenario 2**, vì agent liên lạc C2 suốt đêm); kiểm tra tay từng bro uid | §4.1 | nhãn gắn với **đích C2 + khung thời gian**; SC2 có beacon qua đêm |
| Có 4 máy (SC1) và 1 máy mỗi SC2/SC3 liên lạc C2 nhưng không có trong PDF, **không có eCAR log**, vẫn gán malicious | §4.1 | các flow này bị loại ở inner join eCAR↔Bro (xem §2) |
| **Nhãn host:** mọi event có `actorID` là agent độc hại, cộng mọi process con; RDP session SC2/SC3 | §4.1 | nhãn bám theo **process tree**, không phải theo hành vi từng event |
| **Bước đồng bộ:** dùng eCAR-Bro để flow của process malicious là malicious, và process có flow malicious là malicious | §4.1 | nhãn network và process của flow bị ràng buộc; `app_family` của positive = image của process độc hại |
| "Vùng xám": notepad++, RDP, winlogon và con của nó… | §4.3 | nhãn SC3 nhiễu; process hệ thống trên host bị chiếm cũng có thể thành positive |
| eCAR có lỗi: ~40% process / 4.22% event gán sai `actorID`, `image_path`, `pid`… do ghi "giá trị cuối cùng gắn với pid" | §2.2, Table 1 | `app_family` trích từ eCAR-Bro có thể sai với một phần event |
| IDS unsupervised trên graph 15 phút: F1 0.13–0.87 | §5, Table 2–3 | mốc so sánh thực tế cho độ khó của bài toán |
| Benign activity thiếu đa dạng; việc sinh traffic benign để lại artifact | §6 | benign ≈ firefox script, là nguồn gốc của shortcut |

---

## 2. Đối chiếu bài báo với dữ liệu thực tế của pipeline

| Kiểm tra | Dữ liệu của mình | Khớp bài báo? |
|---|---|---|
| Số host positive theo scenario | ground truth split: 20 + 5 + 4 = 29 host, gồm SC1 17, SC2 10, SC3 2 | ✅ trùng Table 4 (17/10/2), nên GT của split lấy từ bộ nhãn này |
| Positive network event đi đâu | chỉ 3 IP C2 (`202.6.172.98:443`, `132.197.158.98:80`, `53.192.68.50:80/8080`) + 1 RDP nội bộ | ✅ nhãn network theo IP C2 |
| Process của positive flow | `powershell.exe` = 16,422/16,422 (100% malicious), chiếm 98.7% positive; toàn dataset có 24,503 event PowerShell, tất cả nằm trong positive window | ✅ agent PowerShell Empire; bước đồng bộ process↔flow |
| SC2 beacon qua đêm | 431/566 positive window chung một template: ~30 kết nối / 15 phút tới `202.6.172.98:443`, qua đêm 24→25/9 trên 6 host | ✅ Appendix C: "the agent was running the whole night of the 24th" |
| Phủ nhãn sau join | Bro có 71,726 event `label=1`, joined chỉ còn 24,721 (≈34%) | ⚠️ khớp với việc một số máy liên lạc C2 không có eCAR (§4.1); phần còn lại cần kiểm tra thêm |
| **SC3 và vùng xám** | `53.192.68.50:80` ngày 25/9: **5,563 benign event trên 498 host** (chủ yếu `appidcertstorecheck.exe`) và 188 malicious trên 2 host. Trên `sysclient0351`, cùng `appidcertstorecheck.exe` → cùng IP lại được gán malicious (8 event). Trên `sysclient0051`, cả `adobearm.exe`, `googleupdate.exe`, `gpupdate.exe`, `ngen.exe`… đều malicious | ✅ §4.3: nhãn phụ thuộc **ngữ cảnh host bị chiếm**, không phụ thuộc bản thân flow |

**Hệ quả quan trọng:** SC3 là trường hợp duy nhất mà luật một dòng thất bại (4 window của `sysclient0051`). Đó cũng là trường hợp mà **một flow sequence thuần network không thể tự phân biệt**, vì flow y hệt là benign trên 498 host khác. Đây là lập luận tốt cho đề tài đa nguồn: cần ngữ cảnh host (process tree, command line) để quyết định.

---

## 3. Chuỗi nhân quả dẫn tới 1.0

```text
PDF Red Team (IP C2, pid agent, ngày)
        │  gán nhãn network theo IP C2 + thời gian
        │  gán nhãn host theo process tree agent
        │  đồng bộ flow ↔ process qua eCAR-Bro
        ▼
positive network event  =  beacon/lệnh của agent (powershell.exe) tới 3 C2 server
        │
        │  Bro chỉ thấy traffic ra Internet; benign ra Internet ≈ 99.8% firefox script
        ▼
feature app_family = image của agent   ──►  luật "có powershell.exe" : F1 test 0.975
timing/bytes của beacon lặp đều        ──►  metadata-only (4 số)   : ROC-AUC 0.9994
        │
        │  host split stratify theo scenario ⇒ cùng template beacon có ở train/val/test
        ▼
BiLSTM F1 0.976, Mixed-Type F1 0.994  (≈ luật một dòng; khác biệt = 2–3 window)
```

Phân loại lỗi, dùng để viết trong luận văn:

| Loại | Có không? | Ghi chú |
|---|---|---|
| Leakage kỹ thuật (preprocessing / split / threshold) | Không | đã kiểm chứng ở STEP 09 |
| **Label-construction leakage** (feature lặp tiêu chí gán nhãn) | **Có** | `app_family`; nhãn bám process tree agent, benign không có PowerShell ra mạng |
| **Near-duplicate / campaign contamination** | **Có** | cùng beacon template trên nhiều host |
| Dataset artifact (benign thiếu đa dạng) | **Có** | bài báo §6 thừa nhận |
| Label noise | Có ở SC3 | vùng xám + lỗi `actorID`/`image_path` của eCAR |
| Overfit | Không kết luận | không có train–test gap để nói overfit |

---

## 4. Hướng xử lý và kế hoạch retrain

Mục tiêu của retrain **không phải** tìm split cho ra số đẹp. Mục tiêu là trả lời được: *"Bỏ phần đi tắt đi thì model còn học được gì từ hành vi mạng?"*

### 4.1 Giao thức đánh giá (chốt trước khi train)

1. **Baseline bắt buộc**, báo cáo cùng bảng với DL:
   - B1: rule "window có `powershell.exe`";
   - B2: metadata-only HGB (4 số);
   - B3: **oracle C2-IP** "window có flow tới 3 IP C2". Không phải model hợp lệ; dùng để minh họa nhãn ≈ IP.
2. **Nhiều mức metric:** window-level (P, R, F1, PR-AUC, ROC-AUC, CM); **host-level** (host bị chiếm có ≥1 window bị bắt, FP host); **per-scenario**; **dedup** (mỗi positive host có trọng số bằng nhau).
3. **Hard-negative set:**
   - 5,563 flow benign tới `53.192.68.50` (cùng IP với C2 SC3);
   - benign window có app ≠ firefox (`cmd.exe`, `conhost.exe`, `appidcertstorecheck.exe`…).

   Báo cáo FPR riêng trên tập này.
4. **Độ tin cậy:** ≥5 seed / split, báo cáo mean ± std, bootstrap CI theo host. Chỉ nói "Mixed-Type tốt hơn BiLSTM" khi chênh lệch vượt độ dao động giữa các seed.

### 4.2 Ma trận thí nghiệm

| ID | Feature | Split | Câu hỏi trả lời |
|---|---|---|---|
| E1 | full (A0) | host split hiện tại | tái lập số cũ (sanity) |
| **E2** | **A1: bỏ `app_family`** (network-only: proto, service, conn_state, port class, numeric, Δt) | host split hiện tại | model có nhận ra beacon chỉ từ hành vi mạng không? |
| E3 | A2: chỉ `app_family` (bag-of-apps, không sequence) | host split hiện tại | riêng process name giải thích được bao nhiêu? |
| **E4** | A0 và A1 | **random host split theo scenario, 5 seed** (feedback giảng viên) | kết quả ổn định không; độ dao động do chọn host |
| E5 | A0 và A1 | LOSO (phụ lục, stress test) | tổng quát hóa sang chiến dịch chưa thấy |
| E6 | A0 và A1 | hard-negative set (§4.1.3) | FPR ở vùng dễ nhầm |

Dự đoán cần kiểm chứng:
- E1/E4-A0 ≈ 1.0, xác nhận shortcut.
- E2/E4-A1 vẫn cao với SC1/SC2, vì beacon đều và rất đặc trưng. Nếu vậy, cần nói rõ đây là *phát hiện beaconing của chiến dịch đã biết*.
- SC3 và E5 sẽ thấp. Đây là chỗ để lập luận cho **fusion với host context**, đúng trọng tâm đề tài.

### 4.3 Thay đổi code tối thiểu (không cần build lại shards)

| Việc | Ở đâu | Ghi chú |
|---|---|---|
| Thêm `--drop-cat app_family` | notebook 06/07 (dataset/collate) | gán cột `x_cat[:, :, 0]` về một hằng số, hoặc bỏ embedding đó; **không cần build lại shards** |
| Sinh 5 random host split theo scenario | script mới `10a_random_scenario_split.py` | tái dùng logic stratify của `00_ground_truth_and_split.py`, output dạng `host_split_frozen.csv` như LOSO |
| Refit preprocessing + build shards theo từng split | `08b_loso_preprocess.py`, `08c_loso_dl_shards.py`, `08d_loso_validate.py` | các script này nhận mapping host→split đông cứng, nên dùng lại được cho split ngẫu nhiên |
| Báo cáo đánh giá mở rộng | mở rộng `09_leakage_audit.py` thành `10b_eval_report.py` | baseline B1–B3, per-host, host-level, dedup, hard-negative, CI |

### 4.4 Về dữ liệu (làm sau E2/E4, không đổi dataset ngay)

- Kiểm tra lại **47k positive Bro event bị rơi ở inner join**. Nếu thuộc các máy không có eCAR, có thể tạo biến thể *network-only* giữ chúng (không có `app_family`) để tăng số host positive.
- Cân nhắc dùng **bản eCAR đã sửa** của bài báo (GitLab `fmajorcz/a_new_hope_for_darpa_optc`) để trích `app_family` chính xác hơn.
- Bỏ bản ingest trùng `23Sep-Night`/`23Sep-night` khi build lại.
- Nhãn multilabel (scenario/tactic) để sau, đúng thứ tự giảng viên nêu: fix leakage → retrain → evaluate → dataset mới.

---

## 5. Câu hỏi cần thống nhất với giảng viên

1. Kết quả chính của nhánh Network nên là **E4-A1** (network-only, random scenario split, 5 seed) còn A0 để làm phân tích shortcut, hay ngược lại?
2. Chấp nhận framing: *"Network-only phát hiện tốt beaconing của chiến dịch đã biết, nhưng không phân biệt được SC3 nếu thiếu ngữ cảnh host"*, và dùng nó làm động lực cho fusion?
3. Có dùng bản eCAR đã sửa và nhãn của bài báo làm ground truth chính thức, trích dẫn nguồn?
