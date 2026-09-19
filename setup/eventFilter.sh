#!/usr/bin/env bash
# https://github.com/drduh/mess/blob/main/setup/eventFilter.sh
# Read eslogger events from fifo channel, filter with jq and write to log file.

set -euo pipefail
umask 027

APPID="mess"
VERS="v1"

JQ_FILTER="/usr/local/etc/${APPID}/exec.jq"
[[ -f "$JQ_FILTER" ]] || { echo "filter not found: $JQ_FILTER" >&2; exit 1; }

DIR_LOG="/var/log/${APPID}"
DIR_VAR="/usr/local/var/${APPID}"
/bin/mkdir -p "${DIR_LOG}" "${DIR_VAR}"

FIFO="${DIR_VAR}/events.fifo"
LOG_NAME="${APPID}-${VERS}-${HOSTNAME}-$(date '+%Y%m%d%H%M%S').log"
LOG_FILE="${DIR_LOG}/${LOG_NAME}"

[[ -p "$FIFO" ]] || /usr/bin/mkfifo "$FIFO"

/bin/launchctl kickstart system/local.mess.eslogger && \
  exec /usr/bin/jq --compact-output --unbuffered \
    --from-file "$JQ_FILTER" < "$FIFO" >> "$LOG_FILE"
