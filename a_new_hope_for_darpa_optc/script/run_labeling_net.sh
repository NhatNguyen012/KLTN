#!/bin/bash
# ==============================================================================
# Helper Script to Run OpTC Parallel Zeek / Bro Network Log Labeling Pipeline
# ==============================================================================
# Usage:
#   ./script/run_labeling_net.sh                      # Run end-to-end on all dates
#   ./script/run_labeling_net.sh --dates 2019-09-25   # Run only for 2019-09-25
#   ./script/run_labeling_net.sh --log-types conn     # Run only for conn.log.gz files
#   ./script/run_labeling_net.sh --dry-run            # Dry run (scan and preview)
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PYTHON_EXEC="${PYTHON_EXEC:-python3}"
BRO_ROOT="${BRO_ROOT:-/mnt/SSD_Data/bro}"
OUT_ROOT="${OUT_ROOT:-/mnt/SSD_Data/temp_label_staging_net}"
GT_DIR="${GT_DIR:-${WORKSPACE_ROOT}/labelling/network}"
WORKERS="${WORKERS:-$(nproc)}"
COMPRESS_LEVEL="${COMPRESS_LEVEL:-6}"
LOG_FILE="${LOG_FILE:-${SCRIPT_DIR}/labeling_net.log}"

echo "=================================================================="
echo "Starting OpTC Zeek/Bro Network Log Labeling Pipeline"
echo "=================================================================="
echo "Workspace:     ${WORKSPACE_ROOT}"
echo "Bro Root:      ${BRO_ROOT}"
echo "Out Staging:   ${OUT_ROOT}"
echo "Ground Truth:  ${GT_DIR}"
echo "Workers:       ${WORKERS}"
echo "Log File:      ${LOG_FILE}"
echo "=================================================================="

"${PYTHON_EXEC}" "${SCRIPT_DIR}/label_optc_network_logs.py" \
    --bro-root "${BRO_ROOT}" \
    --out-root "${OUT_ROOT}" \
    --gt-dir "${GT_DIR}" \
    --workers "${WORKERS}" \
    --compress-level "${COMPRESS_LEVEL}" \
    --log-file "${LOG_FILE}" \
    "$@"
