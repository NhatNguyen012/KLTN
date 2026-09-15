# Chạy Host ML trên EC2 và Kaggle

Cập nhật 2026-09-16. Đây là cấu hình đề xuất từ kích thước sparse và giới hạn
backend, chưa phải benchmark 100 triệu dòng trên EC2.

## Hai profile

| Nhánh/profile | TRAIN | Validation/test |
| --- | --- | --- |
| main / `ec2-100m` | Chính xác **100.000.000** dòng: 201.551 positive + 99.798.449 negative; seed 01 | Toàn bộ split gốc |
| Nguyen / `kaggle` | Giữ toàn bộ positive, Bernoulli negative sampling 30:1 theo kỳ vọng, cùng membership RNG cũ | Toàn bộ split gốc |

Corpus gốc có 3.476.277.622 dòng TRAIN, 463.503.683 validation, 695.255.524 test,
204.969 cột. Vì vậy profile 100 triệu là một mẫu TRAIN của corpus, không phải
train toàn bộ 3,48 tỷ dòng. Không đổi index, split 75/10/15, vocabulary hoặc
matrix gốc. Ba supervised model dùng chung mẫu. Seed 01 không đảm bảo F1 tăng.

Nguồn số liệu: `code/output/host_ml/kaggle_upload_ustar/package_report.json`.
100 triệu dòng ước tính khoảng 1,45 tỷ nnz và 11,25 GiB cho CSR float32/int32
cộng nhãn; đây chỉ là ma trận, chưa gồm mô hình và bộ nhớ tạm.
Runtime kiểm tra nnz thực tế, chặn ở 1,8 tỷ và kiểm tra ngân sách RAM trước khi
nạp. Nếu vượt, chương trình báo lỗi; không tự cắt mẫu cho riêng một model.

## Cấu hình nên thuê

### Main: mỗi model một instance

| Model | Instance đề xuất | vCPU | RAM GiB | GPU | EBS dữ liệu/checkpoint đề xuất |
| --- | --- | ---: | ---: | --- | ---: |
| XGBoost 100M | `g6e.8xlarge` | 32 | 256 | 1 × L40S, 48 GB VRAM | 200 GiB gp3 |
| Random Forest 100M | `r7i.8xlarge` | 32 | 256 | Không | 300 GiB gp3 |
| LightGBM 100M | `r7i.4xlarge` | 16 | 128 | Không | 200 GiB gp3 |

Nếu ưu tiên thêm CPU/RAM cho LightGBM, chọn `r7i.8xlarge`; tăng CPU không đảm
bảo tốc độ tăng tuyến tính. Nếu chỉ thuê **2 instance**, dùng `g6e.8xlarge` cho
XGB và `r7i.8xlarge` chạy RF rồi LGBM tuần tự. Không cần GPU cho RF sklearn hay
LightGBM CPU trong bản này. Không cần nhiều GPU cho XGB: notebook dùng một GPU.

Thông số máy đối chiếu [AWS G6e](https://aws.amazon.com/ec2/instance-types/g6e/)
và [AWS R7i](https://aws.amazon.com/ec2/instance-types/r7i/).
G6e.8xlarge còn có tổng 900 GB NVMe instance store, phù hợp scratch. Checkpoint
cần nằm trên EBS được giữ lại hoặc được sao lưu; không chỉ nằm trên NVMe.

RAM XGB gồm cả CSR/quantization bên CPU. VRAM phụ thuộc chiều dài hàng sparse
lớn nhất và histogram, không chỉ số nnz trung bình. 48 GB là điểm khởi đầu có
dư địa, **chưa được kiểm chứng đủ cho corpus này**. Đo một pilot có output riêng
trước khi chạy dài; nếu CUDA OOM, dùng instance VRAM lớn hơn hoặc chạy CPU với
output model mới. Không chuyển ma trận 204.969 cột sang dense. Notebook hiện
dùng `QuantileDMatrix` trong RAM; không triển khai external-memory GPU hoặc
multi-GPU. Xem [XGBoost GPU memory](https://xgboost.readthedocs.io/en/stable/gpu/).

RF có giới hạn sparse int32 ở backend và nhiều buffer theo số dòng trên mỗi
tree worker. Mẫu 100M + guard nnz tránh vượt giới hạn này; worker được giới hạn
theo RAM khả dụng. LightGBM 100M nằm dưới giới hạn row int32 của backend; tăng
RAM không biến bản này thành giải pháp cho toàn bộ 3,48 tỷ dòng.

### Nguyen: mẫu khoảng 6,24 triệu dòng

| Model | Instance khởi đầu | vCPU / RAM | GPU |
| --- | --- | --- | --- |
| XGBoost | `g5.2xlarge` | 8 / 32 GiB | 1 × A10G 24 GB |
| LightGBM | `c7i.4xlarge` | 16 / 32 GiB | Không |
| Random Forest | `r7i.2xlarge` | 8 / 64 GiB | Không |
| Isolation Forest | `c7i.4xlarge` | 16 / 32 GiB | Không |

Chọn 100–150 GiB EBS dữ liệu cho các mẫu nhỏ, ngoài root disk. Nguồn thông số:
[AWS G5](https://aws.amazon.com/ec2/instance-types/g5/),
[AWS C7i](https://aws.amazon.com/ec2/instance-types/c7i/),
[AWS R7i](https://aws.amazon.com/ec2/instance-types/r7i/).
Máy local 32 GiB có thể chạy thử LGBM/XGB CPU mẫu nhỏ; 64 GiB phù hợp RF hơn.
Full validation/test vẫn hơn 1,15 tỷ dòng, nên local có thể mất nhiều thời gian.
Không chạy full training local trong đợt hiệu chỉnh này.

Chưa chọn region/AZ nên chưa báo giá Spot; các cấu hình trên không phải khẳng
định rẻ nhất ở mọi region. Kiểm tra capacity, quota và giá của cùng cấu hình
khi thuê. Root disk gợi ý 60 GiB hoặc tối thiểu AMI yêu cầu nếu lớn hơn.

## AMI và môi trường

**AMI = Amazon Machine Image**, ảnh hệ điều hành và phần mềm để khởi tạo EC2.
CPU: Ubuntu 24.04 LTS x86_64. GPU: chọn AMI AWS có NVIDIA driver, ví dụ
[Deep Learning Base GPU AMI Ubuntu 24.04](https://docs.aws.amazon.com/dlami/latest/devguide/aws-deep-learning-x86-base-gpu-ami-ubuntu-24-04.html).
AMI ID khác nhau theo region; lấy ID theo hướng dẫn chính thức, không sao chép
một ID cố định từ region khác. Kiểm tra `nvidia-smi` trên GPU instance.

Từ root của checkout tương ứng, tạo Python 3.12 venv trên EC2:

```bash
python3 -m venv .venv-host
source .venv-host/bin/activate
python -m pip install -r code/kaggle/requirements-cpu.txt
python -m pip install ipykernel jupyterlab nbconvert
python -m ipykernel install --user --name optc-host --display-name 'OpTC Host ML'
```

Trên GPU instance, thay dòng requirements bằng `requirements-gpu.txt`.
Chọn đúng một file requirements trong venv mới; không cài chồng hai bản XGBoost.
Đã kiểm thử CPU với numpy 2.2.6, scipy 1.15.3, sklearn 1.6.1,
LightGBM 4.6.0, xgboost-cpu 3.0.5. GPU chưa được kiểm thử trên phần cứng CUDA.

## Input, mẫu dùng chung và thực thi

1. Giải nén gói input đã có vào thư mục riêng trên EC2, ví dụ `/mnt/optc/input`.
   Dùng manifest của gói, giữ nguyên `volumes/`, assets và reader đi kèm.
   Notebook chứa runtime mới ngay trong setup cell nên không phải rebuild gói
   19,05 GB hoặc upload thêm helper lên Kaggle. Cần chọn kernel đã cài thư viện.
2. Chỉnh `MANIFEST`, `OUTPUT_ROOT`, `SAMPLE_DIR` ở đầu notebook hoặc đặt env như
   bên dưới. Input và output phải tách thư mục. Không ghi output vào raw roots.
3. Với main, tạo mẫu một lần bằng CLI (không training):

```bash
export OPTC_MANIFEST=/mnt/optc/input/manifest.json
export OPTC_OUTPUT=/mnt/optc/results
export OPTC_SAMPLE_DIR=/mnt/optc/samples/train-100m-seed01
python code/kaggle/prepare_train_sample.py \
  --manifest "$OPTC_MANIFEST" \
  --output-dir "$OPTC_SAMPLE_DIR" --rows 100000000 --workers 4
```

4. Khi `manifest.json` của mẫu có `complete: true`, sao chép **toàn bộ thư mục
   mẫu** và cùng gói input sang máy model khác. Giữ mtime input khi sao chép
   (ví dụ `rsync -a`); checkpoint kiểm tra cả size/mtime của shard. Dùng cùng
   runtime/reader/NumPy/SciPy trên ba máy. Không chia sẻ thư mục đang ghi qua
   cơ chế đồng bộ file. Có thể để mỗi notebook tự dựng mẫu, nhưng sẽ quét TRAIN
   lại trên mỗi máy. Sample ID phải trùng nhau trong ba báo cáo.
5. Mở notebook model tương ứng, chọn kernel `OpTC Host ML`, Run All. Nếu chạy
   headless, ví dụ LightGBM, tạo thư mục result ngoài input rồi chạy:

```bash
mkdir -p "$OPTC_OUTPUT"
jupyter nbconvert --to notebook --execute code/kaggle/host_lgbm_shards.ipynb \
  --ExecutePreprocessor.kernel_name=optc-host \
  --ExecutePreprocessor.timeout=-1 \
  --output lgbm-executed.ipynb --output-dir "$OPTC_OUTPUT"
```

Trên Kaggle, dùng notebook profile Nguyen trong `code/kaggle/`, input cũ vẫn
được nhận diện tự động. `CPU_THREADS=None` dùng số CPU được cgroup/affinity cấp,
không mặc định lấy toàn bộ CPU vật lý của host. Cần đúng các thư viện đã nêu;
runtime ghi version vào checkpoint và từ chối resume không tương thích.

## Tối ưu và ý nghĩa log timeout

Log cuối được cung cấp:

```text
2483.2s kept 201551 positives, 6042814/3476076071 negatives -> X_train (6244365, 204969)
```

Sampling kết thúc ở 41,4 phút; lần chạy bị hủy ở 12 giờ. Notebook cũ không có
log đủ chi tiết để phân biệt training với full evaluation trong khoảng còn lại.
Không có bằng chứng đủ để quy toàn bộ thời gian đó cho LightGBM fit.

Thay đổi RF/XGB/LGBM:

- Loader prefetch có giới hạn; cache đường dẫn parent; không gom tất cả shard
  rồi `vstack` một bản CSR thứ hai. Mẫu được lưu thành các part có checksum.
- Dùng số CPU thực tế, BLAS một thread để tránh nhiều lớp thread tranh CPU;
  LightGBM dùng `force_col_wise=True` cho ma trận rất nhiều cột. XGB train hist
  trên GPU nếu chọn CUDA, inference sparse trên CPU rõ ràng.
- RF fit dùng worker phù hợp bộ nhớ; cả ba inference dùng thread budget riêng.
- Ghi `BEGIN`/`END`, tiến độ sample/evaluation và checkpoint mỗi 25 round/tree.
  Vòng đầu tiên hoặc dựng Dataset vẫn có thể lâu trước checkpoint đầu tiên.
- Dự đoán một lần cho mỗi hàng binary giống hệt nhau **trong một batch** rồi
  trả score về tất cả hàng gốc. So sánh chính xác cột, không dùng hash gần đúng;
  giới hạn RAM và bỏ dedupe nếu batch quá lớn. Lợi ích phụ thuộc tỷ lệ lặp thực
  tế, chưa có số đo tốc độ corpus. Không thay nhãn, trọng số hoặc độ phủ test.
- Giữ membership mẫu Nguyen, nhưng thứ tự hàng trong shard chuyển về thứ tự
  nguồn; kết quả fit có thể khác do row order/thư viện. Giữ chính sách class
  weight của nhánh: RF balanced, boosting main unweighted, Nguyen balanced.
- Chọn threshold trên validation bằng histogram 100.000 bins (cũ 10.000).
  Confusion test đếm trực tiếp trên score với threshold đã khóa; PR/ROC AUC là
  xấp xỉ histogram và được ghi rõ. Không dùng test để chọn threshold.

Isolation Forest Nguyen được chỉnh CPU fit/scoring, prefetch và full evaluation
checkpoint; giữ uniform sample 4M và phép biến đổi percentile cũ. Notebook này
vẫn dựng mẫu/fit lại khi Run All; cơ chế resume training áp dụng cho ba model
supervised. River online còn xử lý cập nhật tuần tự, không sửa thuật toán để ép
song song; notebook River không thuộc bản chỉnh này.

Tham khảo lựa chọn CPU:
[LightGBM parameters](https://lightgbm.readthedocs.io/en/latest/Parameters.html),
[joblib CPU quota](https://joblib.readthedocs.io/en/latest/generated/joblib.cpu_count.html),
[IsolationForest scoring threads](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html).
Chưa thể cam kết hoàn thành full evaluation trong 12 giờ Kaggle.

## Checkpoint và Spot

Trong `OUTPUT_ROOT/<model>-<profile>/`:

- `model/latest.json` trỏ tới một trong hai model slot đã ghi atomically.
- `validation-state.npz`, `test-state.npz`: resume theo shard, mỗi 32 shard.
- `validation_metrics.json`: xuất ngay khi validation xong.
- `<model>_metrics.json`: báo cáo cuối, sample/split/vocab identity, version,
  threshold, precision/recall/F1/FPR, confusion, binned AUC.

Chạy lại notebook với cùng input, sample, settings và thư viện sẽ tiếp tục từ
checkpoint. Model hoàn tất thì bỏ qua nạp CSR và training. Đổi cấu hình cần output
mới; không xóa checkpoint cũ để lẫn hai thí nghiệm. Mẫu ghi checkpoint mỗi 64
part; phần chưa được publish có thể phải làm lại.

Với Spot, đặt sample/checkpoint trên EBS data volume và cấu hình giữ volume khi
instance terminate (`DeleteOnTermination=false`); sao lưu định kỳ sang S3 nếu
cần chuyển AZ. Không có uploader S3 hoặc interruption handler tự động trong
notebook này. Sao lưu model slot cùng `latest.json` ở ranh giới checkpoint ổn
định, không chỉ sao chép riêng con trỏ. AWS gửi interruption notice theo cơ chế
best effort, thường trước hai phút; không chờ notice mới bắt đầu lưu một model
lớn. Xem [AWS Spot interruption](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/spot-instance-termination-notices.html).

File trong `/kaggle/working` không được coi là đã sao lưu khi phiên bị hủy;
cần lưu/download output để đưa vào lần chạy tiếp. Không có cơ chế vượt timeout
Kaggle trong bản chỉnh này.

## Kiểm thử và cập nhật code

Chỉ chạy synthetic fixtures và regression reader/packager tại local, không
train corpus thật. Bộ runtime kiểm thử exact sampling, giữ positive/membership,
path guards, checksum, sparse dedupe, đủ val/test, timeout/resume cho cả ba
estimator, standalone notebooks và Isolation Forest Nguyen. Main bỏ qua test
Isolation Forest vì notebook đó không đổi.

Runtime nguồn là `host_training_runtime.py`. Sau khi sửa runtime, regenerate
notebook **đúng nhánh**:

```bash
python code/kaggle/refresh_host_notebooks.py --profile ec2-100m
# Hoặc ở Nguyen:
python code/kaggle/refresh_host_notebooks.py --profile kaggle
python code/test_host_training_runtime.py
python code/test_host_shards.py
python code/test_package_host_shards.py
```

Generator xóa output đã chạy của ba notebook supervised. Bản Kaggle XGB cũ có
log/F1 đã được giữ riêng tại
`code/output/reviews/original_runs/host_xgb_shards_kaggle_5715s.ipynb`.
