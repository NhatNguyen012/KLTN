# red-team/campaign — scheduler cho chiến dịch dài (24–48h), giống APT dwell

Chạy các kịch bản (L1–L5 Linux; W-series Windows tách riêng) rải trên 24–48h với dwell giữa các giai đoạn,
có resume qua reboot và auto-stop theo ROE. **Chưa bật** — chủ lab chọn thời điểm.

## Thành phần
- `lib_actions.sh` — thư viện action (một primitive ATT&CK mỗi hàm), ghi ground-truth JSONL khi bước thành công.
- `scenarios.conf` — scenario → chuỗi action.
- `run_campaign.sh <L1..L5>` — chạy trọn một kịch bản liền tay (dùng cho dry run, không dwell).
- `gen_timeline.py <tổng_giây> [seed]` — sinh timeline rải + jitter (campaign chồng lấn nhau).
- `scheduler.sh <timeline>` — thực thi timeline theo mốc thời gian; **resume** (state ở `~/campaign/state`),
  **pause** khi guard tạo `/tmp/campaign/PAUSE`.
- `campaign_guard.sh` — chạy trên host; raise/clear PAUSE theo RAM/swap/health container (ROE §6).
- `pssh.py` — password-SSH qua pty (reuse-credential foothold).
- `campaign.service` / `campaign-guard.service` — unit systemd.

## Bật campaign 48h (khi chủ lab quyết định)
```bash
# 1) trên attacker: sinh timeline + cài scheduler
python3 ~/campaign/gen_timeline.py 172800 7 > ~/campaign/campaign.tl   # 48h; 86400 = 24h
sudo cp ~/campaign/campaign.service /etc/systemd/system/kltn-campaign.service
# 2) trên host: cài guard TRƯỚC
sudo cp .../campaign/campaign-guard.service /etc/systemd/system/kltn-campaign-guard.service
sudo systemctl enable --now kltn-campaign-guard
# 3) snapshot 2 Ubuntu, rồi bật scheduler
sudo systemctl enable --now kltn-campaign        # trên attacker
```
Dừng: `systemctl stop kltn-campaign`. Resume tự động khi start lại (state giữ nguyên offset tuyệt đối).

## Trước khi bật (checklist ROE §8 + điều chỉnh từ dry run)
- Thu hồi swap host hoặc giữ `MAX_SWAP_MB` nới (host hiện ~7.2GB swap tồn).
- Re-assert prereq (`prep_lab2.sh`) ngay trước khi bật: config lab bị trôi trong ~40 phút (xem HANDOFF).
- Windows: plan W phải **ghim test number** + input args (technique trần = chạy mọi atomic).
