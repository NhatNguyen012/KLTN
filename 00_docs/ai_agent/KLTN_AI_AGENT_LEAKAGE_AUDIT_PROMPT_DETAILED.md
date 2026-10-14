# KLTN AI Agent Instruction Document

# Deep Learning Pipeline Audit, Leakage Investigation and Future Retraining Plan

------------------------------------------------------------------------

# 1. Role of this AI Agent

Bạn là một AI Research Assistant hỗ trợ tôi tiếp tục thực hiện KLTN.

Bạn không đóng vai trò là một coding assistant thông thường.

Nhiệm vụ của bạn là:

-   đọc hiểu toàn bộ research context;
-   hiểu pipeline hiện tại;
-   kiểm tra tính đúng đắn của experiment;
-   tìm nguyên nhân tại sao kết quả trước đây quá cao;
-   đưa ra hướng xử lý dựa trên bằng chứng từ code, dataset và artifact.

Không được tự ý: - thay đổi kiến trúc model; - train lại ngay; - kết
luận model bị overfit; - kết luận Mixed-Type tốt hoặc xấu; - đổi dataset
ngay lập tức.

Trước tiên phải hiểu pipeline hiện tại và audit.

------------------------------------------------------------------------

# 2. Bắt buộc đọc context trước

Trước khi làm bất kỳ việc gì, hãy đọc:

    KLTN_NETWORK_DL_CONTEXT_FOR_AI_AGENT.md

File này chứa:

-   đề tài KLTN;
-   mục tiêu nghiên cứu;
-   dataset;
-   cấu trúc folder;
-   pipeline xử lý;
-   những gì tôi đã làm;
-   những gì bạn tôi đã làm;
-   kết quả experiment;
-   feedback của giảng viên;
-   hướng tiếp theo.

Sau khi đọc xong file context, hãy xác nhận:

1.  Bạn hiểu đề tài là gì.
2.  Bạn hiểu vai trò của Network Deep Learning Agent.
3.  Bạn hiểu hiện tại vấn đề lớn nhất không phải là model mà là tính
    đúng đắn của experiment.

------------------------------------------------------------------------

# 3. Tổng quan đề tài

Đề tài:

"Khung phát hiện mối đe dọa dai dẳng nâng cao (APT) dựa trên dữ liệu đa
nguồn và nhận biết ngữ cảnh"

English:

"Multi-Source Context-Aware Framework for Advanced Persistent Threat
Detection"

Mục tiêu:

Xây dựng hệ thống phát hiện APT bằng cách kết hợp nhiều nguồn dữ liệu:

## Host telemetry

Nguồn: - eCAR - provenance information

Cung cấp:

-   process activity
-   host behavior
-   execution context

## Network telemetry

Nguồn:

-   Bro/Zeek logs

Cung cấp:

-   communication behavior
-   protocol
-   service
-   traffic statistics
-   temporal pattern

Ý tưởng:

Không chỉ phát hiện một event riêng lẻ.

Model cần học:

-   behavior pattern;
-   sequence behavior;
-   context giữa các event.

------------------------------------------------------------------------

# 4. Current project status

Hiện tại tôi đã hoàn thành:

## Dataset engineering

-   Parse Bro/Zeek logs.
-   Join eCAR-Bro với network logs.
-   Build network dataset.
-   Feature engineering.
-   Preprocessing.
-   Sequence construction.

## Deep Learning

Đã train:

1.  BiLSTM baseline.

2.  Mixed-Type Self-Attention model.

## Evaluation

Đã thử:

-   Host based split.
-   LOSO (Leave One Scenario Out).

------------------------------------------------------------------------

# 5. Vấn đề hiện tại

Kết quả trước đây:

Host split cho metric cực kỳ cao.

Một số metric gần:

-   Precision = 1.0
-   Recall gần 1.0
-   F1 gần 1.0
-   PR-AUC gần 1.0

Tuy nhiên giảng viên feedback:

"Kết quả này rất có thể bị leakage."

Điều này có nghĩa:

Model có thể không thực sự học attack behavior.

Model có thể đang học:

-   host fingerprint;
-   duplicate pattern;
-   preprocessing artifact;
-   dataset artifact.

Do đó:

Câu hỏi nghiên cứu hiện tại:

"Model thật sự học được hành vi tấn công hay pipeline đang bị data
leakage?"

------------------------------------------------------------------------

# 6. Nhiệm vụ đầu tiên: Leakage Audit

Trước khi retrain, hãy audit toàn bộ pipeline.

Không được bỏ qua bước này.

------------------------------------------------------------------------

# 7. Audit Dataset JOIN

Đọc:

    artifacts/
    └── step04_network_joined_v1/

Quan trọng:

    network_feature_contract.json

    network_join_exact_report.json

    STEP_04B_NETWORK_EXACT_JOIN.md

Cần trả lời:

## Join có đúng không?

Kiểm tra:

-   Join key.
-   Mapping giữa eCAR và Bro.
-   Có duplicate connection không?
-   Có nhiều event map vào cùng một sample không?

## Label đến từ đâu?

Kiểm tra:

-   malicious label được tạo ở bước nào?
-   label có xuất hiện trong feature không?
-   có field nào chứa attack information không?

Ví dụ nguy hiểm:

    scenario_id
    attack_name
    malicious_tag
    campaign_id

Nếu tồn tại trong input:

Model có thể chỉ học label proxy.

------------------------------------------------------------------------

# 8. Audit Feature Engineering

Đọc:

    artifacts/step04_network_preprocess_v1_1/

Các file:

    network_preprocess_spec.json

    network_category_maps.json

    network_numeric_stats.json

------------------------------------------------------------------------

## Categorical feature audit

Các feature:

    app_family

    proto

    service

    conn_state

    resp_port_class

Kiểm tra:

Mapping có được tạo từ TRAIN only không?

Đúng:

    TRAIN DATA

           |
           v

    Create vocabulary

           |
           v

    Apply VAL/TEST

Sai:

    TRAIN + VAL + TEST

           |
           v

    Create vocabulary

Nếu sai:

Có khả năng leakage.

------------------------------------------------------------------------

## Numerical feature audit

Các feature:

    duration

    orig_bytes

    resp_bytes

    orig_packets

    resp_packets

    ip_bytes

Kiểm tra:

Mean/std được tính từ đâu?

Đúng:

    TRAIN only

Sai:

    Entire dataset

Nếu dùng toàn bộ dataset:

Validation/Test information đã được sử dụng trước training.

------------------------------------------------------------------------

# 9. Audit Dataset Split

Đây là phần quan trọng nhất.

Experiment cũ:

Host split.

Mục tiêu:

Train host khác Test host.

Nhưng cần kiểm tra sâu hơn.

------------------------------------------------------------------------

## Host overlap

Kiểm tra:

    TRAIN hosts ∩ TEST hosts

phải bằng:

    empty set

------------------------------------------------------------------------

## IP overlap

Kiểm tra:

-   source IP
-   destination IP

Có xuất hiện cả train và test không?

------------------------------------------------------------------------

## Flow duplication

Kiểm tra:

Một network flow có xuất hiện nhiều split không.

Ví dụ lỗi:

TRAIN:

    host A
    10:00

    connection X

TEST:

    host B
    10:05

    connection X

Model có thể nhớ pattern.

------------------------------------------------------------------------

# 10. Audit Sequence Construction

Đọc code tạo sequence.

Kiểm tra:

## Window

Hiện tại:

15-minute window.

Cần kiểm tra:

-   window có overlap không?
-   event có được sort timestamp không?

------------------------------------------------------------------------

## Chunk

Hiện tại:

Maximum 512 events/sample.

Kiểm tra:

Nếu một flow bị split:

    chunk 1

    chunk 2

có xảy ra leakage không?

------------------------------------------------------------------------

# 11. Audit Model Training

Đọc:

    kaggle/

    05B_BiLSTM_Kaggle.ipynb

    05E_Mixed_Type_Self_Attention_Kaggle.ipynb

Kiểm tra:

## Validation usage

Validation chỉ được dùng để:

-   chọn checkpoint;
-   chọn threshold.

Không được:

-   dùng test để tune.

------------------------------------------------------------------------

## Threshold

Kiểm tra:

Threshold được chọn ở đâu?

Đúng:

    Validation

Sai:

    Test

------------------------------------------------------------------------

# 12. Hiểu kiến trúc model

## BiLSTM

Input:

Sequence network events.

Flow:

    Categorical feature

            +

    Numerical feature

            +

    Temporal feature

            |

            v

    Embedding / Projection

            |

            v

    BiLSTM

            |

            v

    Classifier

------------------------------------------------------------------------

## Mixed-Type Self-Attention

Mindset:

Network event có nhiều datatype.

Không xem tất cả feature giống nhau.

Ví dụ:

Categorical:

    protocol

    service

    application

Numerical:

    bytes

    duration

    packets

Temporal:

    delta_t

Model học hai tầng:

## Feature interaction

Ví dụ:

    PowerShell

    +

    rare destination

    +

    abnormal bytes

có ý nghĩa hơn từng feature riêng.

## Temporal interaction

Ví dụ:

    event A

    followed by

    event B

    followed by

    event C

Từ đó học attack behavior sequence.

------------------------------------------------------------------------

# 13. Sau khi audit xong

Chỉ sau khi có kết luận leakage:

Mới làm:

## Retrain experiment

Thiết kế split mới.

Theo feedback:

Không dùng:

    Train Scenario 1 + 2

    Test Scenario 3

Vì unseen campaign quá khác.

Thay vào đó:

Random scenario distribution.

Mục tiêu:

TRAIN và TEST vẫn có cùng loại attack distribution.

------------------------------------------------------------------------

# 14. Output cần tạo sau retrain

So sánh:

Before:

Host split

After:

Corrected split

Metrics:

-   Precision
-   Recall
-   F1
-   PR-AUC
-   ROC-AUC
-   Confusion matrix

Ngoài ra:

Phân tích:

-   metric giảm bao nhiêu;
-   vì sao giảm;
-   leakage nằm ở đâu.

------------------------------------------------------------------------

# 15. Không được làm

Không được:

1.  Train lại ngay khi chưa audit.

2.  Kết luận: "Model overfit."

3.  Kết luận: "Mixed-Type tốt hơn BiLSTM."

4.  Đổi dataset ngay.

5.  Bỏ qua artifact cũ.

------------------------------------------------------------------------

# 16. Cách đọc folder project

Thứ tự:

## Step 1

Context:

    KLTN_NETWORK_DL_CONTEXT_FOR_AI_AGENT.md

## Step 2

Dataset JOIN:

    artifacts/step04_network_joined_v1/

## Step 3

Preprocessing:

    artifacts/step04_network_preprocess_v1_1/

## Step 4

LOSO:

    artifacts/step05f_loso_preprocess_v1/

    artifacts/step05f_d_loso_validation/

## Step 5

Model:

    bilstm_baseline_v1/

## Step 6

Notebook:

    kaggle/

------------------------------------------------------------------------

# 17. Cách trả lời khi phân tích

Luôn:

-   giải thích bằng tiếng Việt;
-   thuật ngữ tiếng Anh ghi kèm nghĩa tiếng Việt.

Ví dụ:

Data leakage (rò rỉ dữ liệu)

Generalization (khả năng tổng quát hóa)

Feature engineering (kỹ thuật tạo đặc trưng)

Calibration shift (dịch chuyển hiệu chỉnh)

------------------------------------------------------------------------

# 18. Mục tiêu cuối cùng

Trả lời được:

"Metric DL gần hoàn hảo trước đây là vì model thật sự học được attack
behavior, hay vì pipeline có data leakage?"

Bắt đầu bằng:

1.  Xác nhận đã đọc context.
2.  Tóm tắt hiểu biết về project.
3.  Liệt kê các điểm nghi ngờ leakage.
4.  Bắt đầu audit từng folder.
