#!/usr/bin/env bash
# Tải từng phần (HTTP Range) log host của AInception vào DATASET/AInception/extracted/<tên ngắn>/.
# Bỏ Suricata, mail Exchange, bản labelled của ngày benign (trùng logs/benign_days). Chạy lại được (--skip-existing).
# Chạy tuần tự: Zenodo giới hạn 133 request/phút mỗi IP (remote_zip.py tự chờ theo x-ratelimit-*).
#   bash fetch_host_logs.sh [zip ...]     # mặc định: SL300 v2,v4,v5 + SL700 a_a,a_b,a_c,b_a,e_a
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/selection.sh"
DST=/mnt/SSD_Data/optc/DATASET/AInception/extracted
LOG=/mnt/SSD_Data/optc/IL/dataset_2-AInception/output/fetch_logs
mkdir -p "$LOG"
ZIPS=("$@")
[ ${#ZIPS[@]} -eq 0 ] && ZIPS=(SL300_variant_2 SL300_variant_4 SL300_variant_5 SL700_variant_a_a SL700_variant_a_b SL700_variant_a_c SL700_variant_b_a SL700_variant_e_a)
rm -f "$LOG/DONE"
for z in "${ZIPS[@]}"; do
  case "$z" in
    SL300_variant_*) short="SL300_v${z#SL300_variant_}"; rx="$SL300_RX" ;;
    SL700_variant_*) short="SL700_${z#SL700_variant_}"; rx="$SL700_RX" ;;
  esac
  (
    mkdir -p "$DST/$short"
    python3 "$HERE/remote_zip.py" get "$z.zip" --grep "$rx" --out "$DST/$short" --skip-existing > "$LOG/$z.log" 2>&1
    echo "exit=$? $(date -Is)" >> "$LOG/$z.log"
    printf 'Giải nén từng phần từ %s.zip (Zenodo 17659656) bằng code/remote_zip.py, %s.\nRegex: %s\n' "$z" "$(date -I)" "$rx" > "$DST/$short/PARTIAL_EXTRACT.txt"
  )
done
grep -H "^exit=" "$LOG"/*.log > "$LOG/DONE"
