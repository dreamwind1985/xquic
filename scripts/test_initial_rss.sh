#!/bin/bash
# RSS Memory Test for Initial Packet Attack
# 
# This script tests the server's RSS memory behavior when receiving:
# 1. Normal initial packets
# 2. Malformed initial packets (header parseable, payload decrypt fails)
#
# Usage: cd build && bash ../scripts/test_initial_rss.sh [num_packets] [mode] [wait_seconds]
#   num_packets:  number of initial packets to send (default: 100)
#   mode:         0=normal, 1=malformed (default: both modes)
#   wait_seconds: seconds to wait for RSS to settle (default: 60)

set -e

NUM_PACKETS=${1:-100}
TEST_MODE=${2:-"both"}  # "0", "1", or "both"
WAIT_SECS=${3:-60}
SERVER_BIN="tests/test_server"
CLIENT_BIN="tests/test_initial_packet"
SERVER_PORT=8443
RSS_LOG="initial_rss_test.log"

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
    killall test_initial_packet 2>/dev/null || true
}

trap cleanup EXIT

# ============================================================
# Test function for a specific mode
# ============================================================

test_mode() {
    local mode=$1
    local mode_name=$2
    
    log_msg ""
    log_msg "=========================================="
    log_msg "  Testing: ${mode_name}"
    log_msg "  Packets: ${NUM_PACKETS}"
    log_msg "  Mode:    ${mode}"
    log_msg "=========================================="
    
    # Kill any existing server
    killall test_server 2>/dev/null || true
    sleep 1
    
    # Clean up old state
    rm -rf tp_localhost test_session xqc_token
    
    # ============================================================
    # Phase 1: Start server and record baseline RSS
    # ============================================================
    
    log_msg ""
    log_msg "Phase 1: Starting server..."
    ${SERVER_BIN} -l e -e > /dev/null 2>&1 &
    SERVER_PID=$!
    sleep 2
    
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        log_msg "ERROR: Server failed to start"
        return 1
    fi
    
    BASELINE_RSS=$(get_rss_kb "$SERVER_PID")
    log_msg "Server PID: ${SERVER_PID}"
    log_msg "Baseline RSS: ${BASELINE_RSS} kB"
    
    # ============================================================
    # Phase 2: Send initial packets and monitor RSS growth
    # ============================================================
    
    log_msg ""
    log_msg "Phase 2: Sending ${NUM_PACKETS} initial packets (mode=${mode})..."
    
    # Record RSS before sending
    RSS_BEFORE=$(get_rss_kb "$SERVER_PID")
    
    # Send initial packets
    ${CLIENT_BIN} -c ${NUM_PACKETS} -m ${mode} -t 1 -s 127.0.0.1 -p ${SERVER_PORT} -l e > /dev/null 2>&1 &
    CLIENT_PID=$!
    
    # Monitor RSS during packet sending
    SAMPLE_COUNT=0
    MAX_SAMPLES=30  # Monitor for up to 30 seconds
    
    while kill -0 "$CLIENT_PID" 2>/dev/null && [ "$SAMPLE_COUNT" -lt "$MAX_SAMPLES" ]; do
        sleep 1
        SAMPLE_COUNT=$((SAMPLE_COUNT + 1))
        
        if [ $((SAMPLE_COUNT % 5)) -eq 0 ]; then
            current_rss=$(get_rss_kb "$SERVER_PID")
            log_msg "  t+${SAMPLE_COUNT}s: RSS = ${current_rss} kB"
        fi
    done
    
    # Wait for client to finish
    wait "$CLIENT_PID" 2>/dev/null || true
    sleep 2
    
    PEAK_RSS=$(get_rss_kb "$SERVER_PID")
    log_msg ""
    log_msg "All ${NUM_PACKETS} initial packets sent."
    log_msg "RSS before: ${RSS_BEFORE} kB"
    log_msg "Peak RSS:   ${PEAK_RSS} kB (growth: +$((PEAK_RSS - RSS_BEFORE)) kB)"
    
    # ============================================================
    # Phase 3: Wait and monitor RSS decline
    # ============================================================
    
    log_msg ""
    log_msg "Phase 3: Waiting ${WAIT_SECS}s for RSS to settle..."
    
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
    log_msg "  Results for ${mode_name}"
    log_msg "=========================================="
    log_msg "  Baseline RSS:  ${BASELINE_RSS} kB"
    log_msg "  Peak RSS:      ${PEAK_RSS} kB  (+$((PEAK_RSS - BASELINE_RSS)) kB)"
    log_msg "  Final RSS:     ${FINAL_RSS} kB  (+$((FINAL_RSS - BASELINE_RSS)) kB from baseline)"
    log_msg ""
    
    GROWTH=$((PEAK_RSS - BASELINE_RSS))
    RETAINED=$((FINAL_RSS - BASELINE_RSS))
    
    if [ "$GROWTH" -le 0 ]; then
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
            log_msg "  PASS: RSS mostly returned to baseline (<=10% retained)."
            RESULT="PASS"
        elif [ "$RETAINED_PCT" -le 30 ]; then
            log_msg "  WARNING: RSS partially returned (${RETAINED_PCT}% retained)."
            RESULT="WARNING"
        else
            log_msg "  FAIL: RSS did NOT return to baseline (${RETAINED_PCT}% retained). Likely memory leak!"
            RESULT="FAIL"
        fi
    fi
    
    log_msg ""
    log_msg "Test result for ${mode_name}: ${RESULT}"
    
    # Kill server
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    
    # Store results for summary
    eval "RESULT_${mode}=\"${RESULT}\""
    eval "BASELINE_${mode}=${BASELINE_RSS}"
    eval "PEAK_${mode}=${PEAK_RSS}"
    eval "FINAL_${mode}=${FINAL_RSS}"
    eval "GROWTH_${mode}=${GROWTH}"
    eval "RETAINED_${mode}=${RETAINED}"
    
    return 0
}

# ============================================================
# Main execution
# ============================================================

echo "" > "$RSS_LOG"
log_msg "=========================================="
log_msg "  Initial Packet RSS Memory Test"
log_msg "  Packets per test: ${NUM_PACKETS}"
log_msg "  Test mode:        ${TEST_MODE}"
log_msg "  Wait time:        ${WAIT_SECS}s"
log_msg "=========================================="

# Check if test binaries exist
if [ ! -f "$SERVER_BIN" ]; then
    log_msg "ERROR: Server binary not found: $SERVER_BIN"
    log_msg "Please build the project first: cmake .. && make"
    exit 1
fi

if [ ! -f "$CLIENT_BIN" ]; then
    log_msg "ERROR: Client binary not found: $CLIENT_BIN"
    log_msg "Please build test_initial_packet first"
    exit 1
fi

# Generate certs if needed
if [[ ! -f "server.key" || ! -f "server.crt" ]]; then
    log_msg "Generating TLS certificates..."
    openssl req -newkey rsa:2048 -x509 -nodes \
        -keyout server.key -new -out server.crt \
        -subj /CN=test.xquic.com 2>/dev/null
fi

# Run tests based on mode
OVERALL_RESULT="PASS"

if [ "$TEST_MODE" = "both" ] || [ "$TEST_MODE" = "0" ]; then
    test_mode 0 "Normal Initial Packets"
    if [ "$RESULT_0" = "FAIL" ]; then
        OVERALL_RESULT="FAIL"
    elif [ "$RESULT_0" = "WARNING" ] && [ "$OVERALL_RESULT" != "FAIL" ]; then
        OVERALL_RESULT="WARNING"
    fi
fi

if [ "$TEST_MODE" = "both" ] || [ "$TEST_MODE" = "1" ]; then
    test_mode 1 "Malformed Initial Packets"
    if [ "$RESULT_1" = "FAIL" ]; then
        OVERALL_RESULT="FAIL"
    elif [ "$RESULT_1" = "WARNING" ] && [ "$OVERALL_RESULT" != "FAIL" ]; then
        OVERALL_RESULT="WARNING"
    fi
fi

# ============================================================
# Final Summary
# ============================================================

log_msg ""
log_msg "=========================================="
log_msg "  FINAL SUMMARY"
log_msg "=========================================="

if [ "$TEST_MODE" = "both" ] || [ "$TEST_MODE" = "0" ]; then
    log_msg ""
    log_msg "Normal Initial Packets (mode=0):"
    log_msg "  Result:   ${RESULT_0}"
    log_msg "  Baseline: ${BASELINE_0} kB"
    log_msg "  Peak:     ${PEAK_0} kB (+${GROWTH_0} kB)"
    log_msg "  Final:    ${FINAL_0} kB (+${RETAINED_0} kB retained)"
fi

if [ "$TEST_MODE" = "both" ] || [ "$TEST_MODE" = "1" ]; then
    log_msg ""
    log_msg "Malformed Initial Packets (mode=1):"
    log_msg "  Result:   ${RESULT_1}"
    log_msg "  Baseline: ${BASELINE_1} kB"
    log_msg "  Peak:     ${PEAK_1} kB (+${GROWTH_1} kB)"
    log_msg "  Final:    ${FINAL_1} kB (+${RETAINED_1} kB retained)"
fi

# Compare modes if both were tested
if [ "$TEST_MODE" = "both" ]; then
    log_msg ""
    log_msg "Comparison:"
    DIFF_GROWTH=$((GROWTH_1 - GROWTH_0))
    DIFF_RETAINED=$((RETAINED_1 - RETAINED_0))
    
    log_msg "  Peak growth difference:    ${DIFF_GROWTH} kB (malformed - normal)"
    log_msg "  Retained memory difference: ${DIFF_RETAINED} kB (malformed - normal)"
    
    if [ "$DIFF_RETAINED" -gt 1000 ]; then
        log_msg "  WARNING: Malformed packets retain significantly more memory!"
        if [ "$OVERALL_RESULT" = "PASS" ]; then
            OVERALL_RESULT="WARNING"
        fi
    fi
fi

log_msg ""
log_msg "=========================================="
log_msg "  Overall Result: ${OVERALL_RESULT}"
log_msg "=========================================="
log_msg "Full log saved to: ${RSS_LOG}"

echo ""
echo "=========================================="
echo "  Overall Test Result: ${OVERALL_RESULT}"
echo "  See ${RSS_LOG} for details"
echo "=========================================="

if [ "$OVERALL_RESULT" = "FAIL" ]; then
    exit 1
fi
exit 0
