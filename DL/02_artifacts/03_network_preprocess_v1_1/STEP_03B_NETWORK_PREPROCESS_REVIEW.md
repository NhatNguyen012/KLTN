# STEP 04C v1.1 — Review và freeze Network preprocessing

## Trạng thái

**FROZEN — READY FOR STEP 04D**

## Vì sao không freeze thẳng candidate v1.0?

Candidate v1.0 đã PASS leakage/OOV/missing checks, nhưng có nhiều categorical field không thay đổi trên TRAIN và `missed_bytes` có variance gần 0.

Nếu giữ các field constant trong Mixed-Type Self-Attention, chúng không giúp phân biệt sample nhưng vẫn tạo feature token/embedding không cần thiết.

Nếu z-score trực tiếp `missed_bytes`, các giá trị hiếm khác 0 có thể trở thành outlier rất lớn vì TRAIN std quá nhỏ.

## Active categorical features

- `app_family`
- `proto`
- `service`
- `conn_state`
- `resp_port_class`

## Inactive categorical features

- `direction` — constant_on_train; kept only for audit/reproducibility
- `local_orig` — constant_on_train; kept only for audit/reproducibility
- `local_resp` — constant_on_train; kept only for audit/reproducibility
- `orig_ip_scope` — constant_on_train; kept only for audit/reproducibility
- `resp_ip_scope` — constant_on_train; kept only for audit/reproducibility
- `orig_port_class` — constant_on_train; kept only for audit/reproducibility

## Active numerical features

- `duration`
- `orig_bytes`
- `resp_bytes`
- `orig_pkts`
- `orig_ip_bytes`
- `resp_pkts`
- `resp_ip_bytes`

## Inactive/raw numerical features

- `missed_bytes` — TRAIN log1p std=0.002403829 < 0.01; raw z-score would be unstable for rare non-zero values

## Derived binary feature

```text
has_missed_bytes = 1.0 if missed_bytes > 0 else 0.0
```

Feature này giữ lại thông tin `missed_bytes` hiếm nhưng tránh unstable z-score.

## Numerical safety

- Active numerical: `log1p -> TRAIN z-score -> clip ±10.0`.
- Missing numerical vẫn dùng normalized value `0.0` + parallel missing mask.

## Leakage

- Active/inactive decision chỉ dùng TRAIN cardinality/std.
- Không dùng VAL/TEST để chọn feature.
- Không dùng label để chọn feature.
- VAL/TEST OOV chỉ dùng audit.

## Frozen fingerprint

`a24ef2cc96b8db8e80875971a1b2c348650bbfde103143811c33af3711ae0839`

## Next step

STEP 04D — build shared `(hostname, 15-minute-window, chunk)` graph/sequence samples.
