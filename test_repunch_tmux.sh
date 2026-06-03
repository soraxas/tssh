#!/usr/bin/env bash
# Repunch live test using tmux for reliable PTY interaction.
# Usage: ./test_repunch_tmux.sh

set -uo pipefail

REMOTE="main.claude.tinlai.coder"
TSSHD_PATH="/home/coder/tsshd/bin/tsshd"
TSSH_BIN="./bin/tssh"
SESSION="repunch_test"
DEBUG_DIR="/tmp/claude-501"
LOG="/tmp/repunch_tmux.log"

GREEN='\033[0;32m'; RED='\033[0;31m'; CYAN='\033[0;36m'; YELLOW='\033[0;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[$(date +%H:%M:%S)] ✓ $*${NC}"; }
fail() { echo -e "${RED}[$(date +%H:%M:%S)] ✗ $*${NC}"; exit 1; }
info() { echo -e "${YELLOW}[$(date +%H:%M:%S)]   $*${NC}"; }
log()  { echo -e "${CYAN}[$(date +%H:%M:%S)] $*${NC}"; }

# Clean up any previous session and processes
tmux kill-session -t "$SESSION" 2>/dev/null || true
pkill -f "tssh.*main.claude.tinlai.coder" 2>/dev/null || true
ssh "$REMOTE" 'sudo iptables -F INPUT; sudo iptables -F OUTPUT 2>/dev/null' 2>/dev/null || true
sleep 0.5

log "=== Repunch Live Test (tmux) ==="

# Step 1: Start tssh in tmux
TSSH_CMD="$TSSH_BIN --udp $REMOTE --punch --tsshd-path $TSSHD_PATH --debug -o UdpAliveTimeout=120s -o StrictHostKeyChecking=no -o ConnectTimeout=30"
log "Starting tssh in tmux: $TSSH_CMD"
tmux new-session -d -s "$SESSION" -x 220 -y 50
tmux send-keys -t "$SESSION" "$TSSH_CMD" Enter

# Step 2: Wait for connection - wait for a NEW debug log
log "Waiting for connection to establish..."
# Record existing logs BEFORE starting so we can identify new ones
EXISTING_LOGS=$(ls "$DEBUG_DIR"/tssh_debug_*.log 2>/dev/null | tr '\n' ':' || echo "")
DEBUG_LOG=""
for i in $(seq 1 30); do
    sleep 1
    # Find debug logs that didn't exist before we started
    for f in $(ls -t "$DEBUG_DIR"/tssh_debug_*.log 2>/dev/null); do
        # Skip if this file existed before we started
        if echo "$EXISTING_LOGS" | tr ':' '\n' | grep -qF "$f"; then
            continue
        fi
        if grep -q "tsshd listening: pid=" "$f" 2>/dev/null; then
            DEBUG_LOG="$f"
            ok "Debug log found: $DEBUG_LOG"
            break 2
        fi
    done
    info "Waiting... ${i}s"
done

[[ -z "${DEBUG_LOG:-}" ]] && fail "Could not find debug log (timed out)"

# Parse port and PID
TSSHD_PID=$(grep "tsshd listening: pid=" "$DEBUG_LOG" | sed 's/.*pid=\([0-9]*\).*/\1/' | head -1)
TSSHD_PORT=$(grep "tsshd listening: pid=" "$DEBUG_LOG" | sed 's/.*port=\([0-9]*\).*/\1/' | head -1)
[[ -z "$TSSHD_PID" || -z "$TSSHD_PORT" ]] && fail "Could not parse PID/port from debug log"
ok "tsshd pid=$TSSHD_PID port=$TSSHD_PORT"

# Verify socket exists
ssh "$REMOTE" "ls /run/user/1001/tsshd/socket-$TSSHD_PID" >/dev/null 2>&1 && \
    ok "tsshd socket exists: socket-$TSSHD_PID" || fail "tsshd socket not found"

# Step 3: Wait for shell prompt
sleep 3
log "Verifying session is alive..."
tmux send-keys -t "$SESSION" "echo TSSH_ALIVE" Enter
sleep 1
TMUX_OUT=$(tmux capture-pane -t "$SESSION" -p 2>/dev/null)
if echo "$TMUX_OUT" | grep -q "TSSH_ALIVE"; then
    ok "Session alive and responsive"
else
    fail "Session not responsive. Output: $TMUX_OUT"
fi

# Step 4: Block UDP to simulate disconnect
info "Blocking UDP port $TSSHD_PORT on remote..."
ssh "$REMOTE" "sudo iptables -A INPUT -p udp --dport $TSSHD_PORT -j DROP; sudo iptables -A OUTPUT -p udp --sport $TSSHD_PORT -j DROP"
DISCONNECT_TIME=$(date +%s)
ok "UDP port $TSSHD_PORT blocked at $(date +%H:%M:%S)"

# Step 5: Wait for transport offline
log "Waiting for client to detect disconnect (~3s heartbeat timeout)..."
for i in $(seq 1 15); do
    sleep 1
    if grep -q "transport offline\|attempting new transport path" "$DEBUG_LOG" 2>/dev/null; then
        ELAPSED=$(( $(date +%s) - DISCONNECT_TIME ))
        ok "Disconnect detected after ~${ELAPSED}s"
        break
    fi
    info "Waiting... ${i}s"
done

# Wait just a bit for the reconnect loop to start
sleep 1

# Step 6: Send repunch escape sequence via tmux
# The escape sequence requires: Enter (to set enterPressedFlag), then ~ within 1s.
# tmux send-keys "Enter" sends \r which forwardInput checks for.
log "Sending repunch escape sequence via tmux..."
tmux send-keys -t "$SESSION" "" Enter    # Send Enter (sets enterPressedFlag in forwardInput)
sleep 0.5
tmux send-keys -t "$SESSION" "~"         # Send ~ (triggers runConsole if enterPressedFlag && within 1s)
sleep 0.8                                # Wait for console menu to appear
tmux send-keys -t "$SESSION" "r"         # Press 'r' in the console to select repunch
sleep 1.0
ok "Escape sequence sent"

# Check if console appeared in tmux
TMUX_OUT=$(tmux capture-pane -t "$SESSION" -p -l 100 2>/dev/null)
log "Tmux pane output (last 10 lines):"
echo "$TMUX_OUT" | tail -10 | sed 's/^/  /'

# Wait for repunch goroutine to start and complete its work
# (re-STUN ~1s + SSH ~2s + tsshd --repunch ~1s + inject ~0s = ~5-10s total)
log "Waiting for repunch goroutine to run (~10s)..."
sleep 10

# Step 8: Unblock UDP BEFORE monitoring - repunch needs it to reconnect
# (The real scenario: NAT mapping expired → repunch creates new mapping → unblocked)
info "Unblocking UDP port $TSSHD_PORT..."
ssh "$REMOTE" "sudo iptables -D INPUT -p udp --dport $TSSHD_PORT -j DROP; sudo iptables -D OUTPUT -p udp --sport $TSSHD_PORT -j DROP" 2>/dev/null || true
ok "UDP unblocked at $(date +%H:%M:%S)"

# Step 7: Monitor repunch progress
log "Monitoring repunch progress..."
REPUNCH_DONE=false
REPUNCH_STARTED=false
for i in $(seq 1 40); do
    sleep 1
    ELAPSED=$(( $(date +%s) - DISCONNECT_TIME ))

    # Check tmux pane for repunch messages (repunch writes to stderr → terminal)
    TMUX_OUT=$(tmux capture-pane -t "$SESSION" -p -l 500 2>/dev/null) || TMUX_OUT=""
    if echo "$TMUX_OUT" | grep -q "\[repunch\]" && ! $REPUNCH_STARTED; then
        ok "Repunch messages visible in terminal!"
        echo "$TMUX_OUT" | grep "\[repunch\]" | head -10 | sed 's/^/  /'
        REPUNCH_STARTED=true
    fi

    # Check for successful reconnect in tmux pane
    if echo "$TMUX_OUT" | grep -q "transport reconnected"; then
        ok "TRANSPORT RECONNECTED! (elapsed: ${ELAPSED}s)"
        REPUNCH_DONE=true
        break
    fi

    # Also check debug log for transport reconnect
    if grep -q "transport resumed\|new transport path established" "$DEBUG_LOG" 2>/dev/null; then
        ok "TRANSPORT RECONNECTED (from debug log)! (elapsed: ${ELAPSED}s)"
        REPUNCH_DONE=true
        break
    fi

    info "Waiting... ${ELAPSED}s"
done

# Step 9: Show relevant debug log sections
log "=== RELEVANT DEBUG LOG ENTRIES ==="
grep -E "transport offline|attempting|reconnect|repunch|transport resumed|discard input|intercepting" "$DEBUG_LOG" 2>/dev/null | head -30 || true

# Step 10: Show final tmux pane content
log "=== FINAL TMUX PANE OUTPUT ==="
tmux capture-pane -t "$SESSION" -p -l 50 2>/dev/null | tail -20 || echo "(session ended)"

# Cleanup
tmux kill-session -t "$SESSION" 2>/dev/null || true

if $REPUNCH_DONE; then
    ok "TEST PASSED: repunch reconnected transport!"
    exit 0
else
    fail "TEST FAILED: transport did not reconnect"
fi
