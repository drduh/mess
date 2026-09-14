#!/usr/bin/env bash
# https://github.com/drduh/mess/blob/main/setup/eventFilter.sh
# Read eslogger events from fifo channel, filter with jq and write to log file.

set -euo pipefail
umask 027

APPID="mess"
VERS="v1"

VAR_DIR="/usr/local/var/${APPID}"
FIFO="${VAR_DIR}/events.fifo"
JQ_FILTER="/usr/local/etc/mess/exec.jq"

LOGS_DIR="/var/log/mess"
LOG_FILE="${LOGS_DIR}/${APPID}-${VERS}-$(hostname)-$(date +%Y%m%d%H%M%S).log"

mkdir -p "$LOGS_DIR"
mkdir -p "$VAR_DIR"

[[ ! -p "$FIFO" ]] && mkfifo "$FIFO"
[[ -p "$FIFO" ]] || { echo "fifo not found: $FIFO" >&2; exit 1; }
[[ -f "$JQ_FILTER" ]] || { echo "jq not found: $JQ_FILTER" >&2; exit 1; }

exec /usr/bin/jq -c --unbuffered -f "$JQ_FILTER" < "$FIFO" >> "$LOG_FILE"
