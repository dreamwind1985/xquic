#!/bin/bash
# RSS Memory Leak Test for xquic server
# 
# This script tests whether the server's RSS returns to baseline
# after creating and closing many connections.
#
# Usage: cd build && bash ../scripts/test_rss_leak.sh [num_connections] [wait_seconds]
#   num_connections: number of connections to create (default: 200)
#   wait_seconds:    seconds to wait for RSS to settle after connections close (default: 120)

set -e

NUM_CONNS=${1:-200}
WAIT_SECS=${2:-120}
SERVER_BIN="tests/test_server"
CLIENT_BIN="tests/test_client"
SERVER_PORT=8443
RSS_LOG="rss_leak_test.log"

# ============================================================
# Helper functions
# ============================================================

get_rss_kb() {
    local pid=$1
    if [ -f "/proc/${pid}/status" ]; then
        grep VmRSS "/proc/${pid}/status" | awk '{print $2}'
    else
        echo "0"
    fi
}

timestamp() {
    date '+%Y-%m-%d %H:%M:%S'
}

log_msg() {
    local msg="[$(timestamp)] $1"
    echo "$msg"
    echo "$msg" >> "$RSS_LOG"
}

cleanup() {
    log_msg "Cleaning up..."
    killall test_server 2>/dev/null || true
    killall test_client 2>/dev/null || true
}

trap cleanup EXIT

# ============================================================
# Preparation
# ============================================================

echo "" > "$RSS_LOG"
log_msg "=========================================="
log_msg "  RSS Memory Leak Test"
log_msg "  Connections: ${NUM_CONNS}"
log_msg "  Wait time:   ${WAIT_SECS}s"
log_msg "=========================================="

# Generate certs if needed
if [[ ! -f "server.key" || ! -f "server.crt" ]]; then
    log_msg "Generating TLS certificates..."
    openssl req -newkey rsa:2048 -x509 -nodes \
        -keyout server.key -new -out server.crt \
        -subj /CN=test.xquic.com 2>/dev/null
fi

# Kill any existing server
killall test_server 2>/dev/null || true
sleep 1

# Clean up old state
rm -rf tp_localhost test_session xqc_token

# ============================================================
# Phase 1: Start server and record baseline RSS
# ============================================================

log_msg "Phase 1: Starting server..."
${SERVER_BIN} -l e -e > /dev/null 2>&1 &
SERVER_PID=$!
sleep 2

if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    log_msg "ERROR: Server failed to start"
    exit 1
fi

BASELINE_RSS=$(get_rss_kb "$SERVER_PID")
log_msg "Server PID: ${SERVER_PID}"
log_msg "Baseline RSS: ${BASELINE_RSS} kB"

# ============================================================
# Phase 2: Create connections and monitor RSS growth
# ============================================================

log_msg ""
log_msg "Phase 2: Creating ${NUM_CONNS} connections..."

for i in $(seq 1 "$NUM_CONNS"); do
    # Each client creates 1 connection, sends a small request, then exits
    ${CLIENT_BIN} -a 127.0.0.1 -p ${SERVER_PORT} -s 1024 -l e -n 1 -t 1 > /dev/null 2>&1

    # Log RSS every 20 connections
    if [ $((i % 20)) -eq 0 ]; then
        current_rss=$(get_rss_kb "$SERVER_PID")
        log_msg "  After ${i} connections: RSS = ${current_rss} kB"
    fi
done

# Wait a moment for last connections to finish
sleep 3

PEAK_RSS=$(get_rss_kb "$SERVER_PID")
log_msg ""
log_msg "All ${NUM_CONNS} connections completed."
log_msg "Peak RSS: ${PEAK_RSS} kB (growth: +$((PEAK_RSS - BASELINE_RSS)) kB)"

# ============================================================
# Phase 3: Wait for idle timeout and monitor RSS decline
# ============================================================

log_msg ""
log_msg "Phase 3: Waiting ${WAIT_SECS}s for connections to idle-timeout and RSS to settle..."
log_msg "  (Server idle timeout is typically 60s)"

SAMPLE_INTERVAL=10
ELAPSED=0

while [ "$ELAPSED" -lt "$WAIT_SECS" ]; do
    sleep "$SAMPLE_INTERVAL"
    ELAPSED=$((ELAPSED + SAMPLE_INTERVAL))
    current_rss=$(get_rss_kb "$SERVER_PID")
    log_msg "  t+${ELAPSED}s: RSS = ${current_rss} kB"
done

FINAL_RSS=$(get_rss_kb "$SERVER_PID")

# ============================================================
# Phase 4: Analysis
# ============================================================

log_msg ""
log_msg "=========================================="
log_msg "  Results"
log_msg "=========================================="
log_msg "  Baseline RSS:  ${BASELINE_RSS} kB"
log_msg "  Peak RSS:      ${PEAK_RSS} kB  (+$((PEAK_RSS - BASELINE_RSS)) kB)"
log_msg "  Final RSS:     ${FINAL_RSS} kB  (+$((FINAL_RSS - BASELINE_RSS)) kB from baseline)"
log_msg ""

GROWTH=$((PEAK_RSS - BASELINE_RSS))
RETAINED=$((FINAL_RSS - BASELINE_RSS))

if [ "$GROWTH" -eq 0 ]; then
    log_msg "  WARNING: No RSS growth detected. Test may not be working correctly."
    RESULT="INCONCLUSIVE"
elif [ "$RETAINED" -le 0 ]; then
    log_msg "  PASS: RSS returned to baseline. No memory leak detected."
    RESULT="PASS"
else
    # Calculate what percentage of the growth was retained
    RETAINED_PCT=$((RETAINED * 100 / GROWTH))
    log_msg "  Retained: ${RETAINED} kB (${RETAINED_PCT}% of peak growth)"

    if [ "$RETAINED_PCT" -le 10 ]; then
        log_msg "  PASS: RSS mostly returned to baseline (<=10% retained, likely allocator fragmentation)."
        RESULT="PASS"
    elif [ "$RETAINED_PCT" -le 30 ]; then
        log_msg "  WARNING: RSS partially returned (${RETAINED_PCT}% retained). Possible allocator fragmentation or minor leak."
        RESULT="WARNING"
    else
        log_msg "  FAIL: RSS did NOT return to baseline (${RETAINED_PCT}% retained). Likely memory leak!"
        RESULT="FAIL"
    fi
fi

log_msg ""
log_msg "Test result: ${RESULT}"
log_msg "Full log saved to: ${RSS_LOG}"

# Kill server
kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true

echo ""
echo "=========================================="
echo "  Test Result: ${RESULT}"
echo "  See ${RSS_LOG} for details"
echo "=========================================="

if [ "$RESULT" = "FAIL" ]; then
    exit 1
fi
exit 0
