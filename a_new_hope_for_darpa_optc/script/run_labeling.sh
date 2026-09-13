#!/bin/bash
# ==============================================================================
# Helper Script to Run OpTC Parallel Host Log Labeling Pipeline
# ==============================================================================
# Usage:
#   ./script/run_labeling.sh                  # Run end-to-end on all dates
#   ./script/run_labeling.sh --dates 2019-09-17  # Run only for 2019-09-17
#   ./script/run_labeling.sh --dry-run        # Dry run (no files written/moved)
#   ./script/run_labeling.sh --skip-swap      # Process to SSD without modifying HDD
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PYTHON_EXEC="${PYTHON_EXEC:-python3}"
HDD_ROOT="${HDD_ROOT:-/mnt/HDD_Data}"
SSD_STAGING="${SSD_STAGING:-/mnt/SSD_Data/temp_label_staging}"
GT_PATH="${GT_PATH:-${WORKSPACE_ROOT}/labelling/host/ground_truths/ground_truth_corrected_all_evts.json.gz}"
WORKERS="${WORKERS:-$(nproc)}"
COMPRESS_LEVEL="${COMPRESS_LEVEL:-6}"
LOG_FILE="${LOG_FILE:-${SCRIPT_DIR}/labeling.log}"

echo "=================================================================="
echo "Starting OpTC Host Log Labeling Pipeline"
echo "=================================================================="
echo "Workspace:     ${WORKSPACE_ROOT}"
echo "HDD Root:      ${HDD_ROOT}"
echo "SSD Staging:   ${SSD_STAGING}"
echo "Ground Truth:  ${GT_PATH}"
echo "Workers:       ${WORKERS}"
echo "Log File:      ${LOG_FILE}"
echo "=================================================================="

"${PYTHON_EXEC}" "${SCRIPT_DIR}/label_optc_host_logs.py" \
    --hdd-root "${HDD_ROOT}" \
    --ssd-staging "${SSD_STAGING}" \
    --gt-path "${GT_PATH}" \
    --workers "${WORKERS}" \
    --compress-level "${COMPRESS_LEVEL}" \
    --log-file "${LOG_FILE}" \
    "$@"
