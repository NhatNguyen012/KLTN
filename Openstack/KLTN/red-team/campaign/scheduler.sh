#!/bin/bash
# KLTN campaign scheduler (authorized lab). Executes a dwell timeline of (offset,scenario,action),
# resumable across restarts/reboots, and pauses when the host-side guard raises /tmp/campaign/PAUSE.
# Usage: scheduler.sh <timeline_file>
set +u
DIR="$(cd "$(dirname "$0")"&&pwd)"; source "$DIR/lib_actions.sh"
TL="${1:?timeline}"; ST="$HOME/campaign/state"; mkdir -p "$ST"
STARTF="$ST/started_at"; DONEF="$ST/done"; LOG="$ST/scheduler.log"; PAUSE="/tmp/campaign/PAUSE"
touch "$DONEF"; [ -s "$STARTF" ] || date -u +%s > "$STARTF"; START=$(cat "$STARTF")
log(){ echo "$(date -u +%FT%TZ) $*" >> "$LOG"; echo "$(date -u +%FT%TZ) $*"; }
log "scheduler up; campaign_start=$(date -u -d @$START +%FT%TZ); timeline=$TL"
sort -n "$TL" | while read -r off scn act rest; do
  [ -z "$off" ] && continue; case "$off" in \#*) continue;; esac
  key="${off}:${scn}:${act}"; grep -qxF "$key" "$DONEF" && continue
  tgt=$((START+off))
  while [ "$(date -u +%s)" -lt "$tgt" ]; do sleep 15; done
  while [ -f "$PAUSE" ]; do log "PAUSED by guard ($(cat $PAUSE 2>/dev/null)); holding"; sleep 30; done
  export RUNID="$scn"; export GT="$HOME/campaign/gt_${scn}.jsonl"
  log "exec $scn/$act (t+${off}s)"; do_action "$act" >/dev/null 2>>"$LOG"
  echo "$key" >> "$DONEF"
done
log "scheduler finished timeline"
