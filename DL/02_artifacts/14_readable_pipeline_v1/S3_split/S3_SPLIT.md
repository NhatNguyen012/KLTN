# S3 — Chia host thành train / val / test

## Mục đích
Quyết định host nào dùng để học (TRAIN), chọn ngưỡng và checkpoint (VAL), và chấm cuối cùng (TEST). **Chia theo hostname** (host-disjoint): một host chỉ nằm ở một tập, để không có dữ liệu của cùng một máy ở cả train và test.

## Đầu vào
- Bảng 625 host có log host (`02_artifacts/11_dataset_overview_v1/hosts_625.csv`): nhóm host, scenario, số flow, số flow tấn công, số event host độc hại.
- Ba file chia ngẫu nhiên theo scenario (`02_artifacts/10a_random_split_v1/seed_{1,2,3}/host_split_frozen.csv`).

## Cách chia (STEP 10A)
- Chia ngẫu nhiên (seed 1, 2, 3) nhưng **stratify theo scenario** của host bị tấn công, để mỗi tập đều có host của các scenario.
- Hai tập phụ: 123 host chỉ có log mạng (`unmatched_split`) và 5 host chỉ có log host không tham gia.

## Đầu ra
| File | Nội dung |
|---|---|
| `host_split_all.csv` | 625 dòng: `hostname, host_group, scenario, split_original (STEP 02), n_flows, n_attack_flows, n_host_malicious_events, split_random_seed1/2/3, has_host_log` |
| `split_summary.csv` | Với mỗi seed và mỗi tập: số host, số host có flow tấn công, số host mỗi scenario |

## Số liệu (split_summary)
| Seed | Tập | Số host | Host có flow tấn công | SC1 / SC2 / SC3 |
|---|---|---:|---:|---|
| 1 | train / val / test | 434 / 93 / 93 | 20 / 4 / 4 | 12,7,1 / 3,2,0 / 2,1,1 |
| 2 | train / val / test | 434 / 93 / 93 | 19 / 5 / 4 | 12,7,1 / 3,2,0 / 2,1,1 |
| 3 | train / val / test | 434 / 93 / 93 | 19 / 5 / 4 | 12,7,1 / 3,2,0 / 2,1,1 |

Ghi chú: số host mỗi scenario cộng lại là 29 (SC1 17, SC2 10, SC3 2). Cột "host có flow tấn công" thấp hơn 29 vì một số host bị tấn công không có flow dương trong bảng đã ghép (xem S1).

## Điểm cần nhớ
- **SC3 chỉ có 2 host.** Ở cả ba seed, `sysclient0051` rơi vào TEST (seed_1, 2, 3 đều có 1 host SC3 trong TEST), nên mọi kết luận về SC3 chỉ dựa trên một host.
- TEST của mỗi seed bị chi phối bởi một host SC2 (khoảng 88% số cửa sổ dương), nên điểm TEST phụ thuộc nhiều vào host đó.
- Nhánh Host của Nguyễn dùng split gốc STEP 02 (437/94/94 host), **khác** split này; muốn fusion phải thống nhất một file split chung.

## Đầu ra này đi đâu tiếp
`split_random_seedK` quyết định S4 (mã hóa chỉ học từ TRAIN của seed K) và S5 (shard theo tập).
