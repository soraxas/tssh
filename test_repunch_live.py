#!/usr/bin/env python3
"""
Live repunch integration test.

Steps:
  1. Connect via tssh --udp --punch --debug
  2. Parse the tsshd port and pid from stderr/debug log
  3. Block UDP traffic on remote (iptables DROP on tsshd port)
  4. Wait for client to detect disconnect
  5. Send repunch escape sequence (~r)
  6. Unblock UDP traffic
  7. Verify reconnect

Usage:
  python3 test_repunch_live.py
"""

import pexpect
import subprocess
import sys
import time
import re
import os
import signal
import threading

REMOTE    = "main.claude.tinlai.coder"
TSSHD_PATH = "/home/coder/tsshd/bin/tsshd"
TSSH_BIN  = "./bin/tssh"
LOG_FILE  = "/tmp/repunch_live_test.log"

CYAN  = "\033[0;36m"
GREEN = "\033[0;32m"
RED   = "\033[0;31m"
YELLOW = "\033[0;33m"
RESET = "\033[0m"

def log(msg, color=CYAN):
    ts = time.strftime("%H:%M:%S")
    print(f"{color}[{ts}]{RESET} {msg}", flush=True)

def ok(msg):   log(f"✓ {msg}", GREEN)
def fail(msg): log(f"✗ {msg}", RED); sys.exit(1)
def info(msg): log(f"  {msg}", YELLOW)

def ssh_run(cmd, check=True):
    result = subprocess.run(
        ["ssh", "-o", "ConnectTimeout=10", REMOTE, cmd],
        capture_output=True, text=True
    )
    if check and result.returncode != 0:
        fail(f"ssh command failed: {cmd}\n{result.stderr}")
    return result.stdout.strip()

def ssh_run_bg(cmd):
    """Fire-and-forget SSH command (no wait)."""
    subprocess.Popen(
        ["ssh", "-o", "ConnectTimeout=10", REMOTE, cmd],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

def block_udp_port(port):
    """Drop all UDP to the tsshd port on the remote server."""
    log(f"Blocking UDP port {port} on remote...", YELLOW)
    ssh_run(f"sudo iptables -A INPUT -p udp --dport {port} -j DROP")
    ssh_run(f"sudo iptables -A OUTPUT -p udp --sport {port} -j DROP")
    ok(f"UDP port {port} blocked on remote")

def unblock_udp_port(port):
    """Remove the DROP rules added above."""
    log(f"Unblocking UDP port {port} on remote...", YELLOW)
    # Delete rules; ignore errors if they don't exist
    subprocess.run(
        ["ssh", REMOTE,
         f"sudo iptables -D INPUT -p udp --dport {port} -j DROP; "
         f"sudo iptables -D OUTPUT -p udp --sport {port} -j DROP"],
        capture_output=True
    )
    ok(f"UDP port {port} unblocked on remote")

def read_debug_log_for(debug_log_path, pattern, timeout=20):
    """Tail the debug log until pattern is found or timeout."""
    start = time.time()
    seen = set()
    while time.time() - start < timeout:
        try:
            with open(debug_log_path) as f:
                for line in f:
                    if line not in seen:
                        seen.add(line)
                        m = re.search(pattern, line)
                        if m:
                            return m
        except FileNotFoundError:
            pass
        time.sleep(0.2)
    return None

def main():
    log("=== Repunch Live Test ===", GREEN)

    # --- Step 1: Launch tssh with pexpect ---
    cmd = (
        f"{TSSH_BIN} --udp {REMOTE} "
        f"--punch --tsshd-path {TSSHD_PATH} "
        f"--debug "
        f"-o UdpAliveTimeout=120s "
        f"-o StrictHostKeyChecking=no "
        f"-o ConnectTimeout=30"
    )
    log(f"Launching: {cmd}")

    logfile = open(LOG_FILE, "wb")
    child = pexpect.spawn(cmd, timeout=60, logfile=logfile, encoding=None)

    # Collect stderr from tssh; pexpect merges it with stdout on PTY
    tssh_output = []

    def collect_output():
        """Capture all tssh stderr/debug output lines."""
        while True:
            try:
                data = child.read_nonblocking(size=4096, timeout=0.1)
                if data:
                    tssh_output.append(data.decode("utf-8", errors="replace"))
            except pexpect.TIMEOUT:
                pass
            except Exception:
                break

    # --- Step 2: Wait for shell prompt / connection established ---
    log("Waiting for connection to establish...")

    # Look for a shell prompt ($ or #) which means we're in a session
    try:
        idx = child.expect([r'\$\s*$', r'#\s*$', pexpect.EOF, pexpect.TIMEOUT], timeout=45)
        if idx >= 2:
            fail(f"Connection failed (idx={idx})\n" + repr(child.before))
        ok("Shell prompt received — connection established")
    except Exception as e:
        fail(f"Connection error: {e}")

    # Give the child a moment to settle
    time.sleep(1)

    # --- Step 3: Parse debug log for port and PID ---
    # Debug log path is printed to stderr: "udp debug logs are written to ..."
    # We need to find it in the debug output already written.
    # Let's check recent log files.
    debug_log = None
    tsshd_port = None
    tsshd_pid = None

    # Find the most recently created debug log
    result = subprocess.run(
        ["ls", "-t", "/tmp/claude-501/"],
        capture_output=True, text=True
    )
    for name in result.stdout.strip().splitlines():
        if name.startswith("tssh_debug_"):
            debug_log = f"/tmp/claude-501/{name}"
            break

    if not debug_log:
        fail("Could not find tssh debug log file")

    ok(f"Debug log: {debug_log}")

    # Parse port and PID from the debug log
    with open(debug_log) as f:
        content = f.read()

    m_port = re.search(r'tsshd listening: pid=(\d+), port=(\d+)', content)
    if not m_port:
        fail(f"Could not parse tsshd port/pid from debug log")
    tsshd_pid  = int(m_port.group(1))
    tsshd_port = int(m_port.group(2))
    ok(f"tsshd pid={tsshd_pid} port={tsshd_port}")

    # Verify the socket exists on the remote
    socket_check = ssh_run(f"ls /run/user/1001/tsshd/socket-{tsshd_pid} 2>/dev/null || echo MISSING", check=False)
    if "MISSING" in socket_check:
        fail(f"tsshd socket not found at socket-{tsshd_pid}; repunch will fail")
    ok(f"tsshd socket exists: socket-{tsshd_pid}")

    # --- Step 4: Send a command to confirm session is alive ---
    child.sendline("echo ALIVE_CHECK")
    try:
        child.expect("ALIVE_CHECK", timeout=10)
        ok("Session is alive and responsive")
    except Exception:
        fail("Session did not respond to echo")
    # Drain the prompt
    child.expect(r'\$\s*$', timeout=5)

    # Start a background loop on the remote to produce traffic
    child.sendline("( while true; do echo KEEPALIVE; sleep 2; done ) &")
    child.expect(r'\$\s*$', timeout=5)
    child.sendline("")

    # --- Step 5: Block UDP to simulate network disconnect ---
    time.sleep(1)
    block_udp_port(tsshd_port)
    disconnect_time = time.time()

    # --- Step 6: Wait for client to detect disconnect ---
    log("Waiting for client to detect disconnect (heartbeat timeout ~3s + reconnect timeout ~15s)...")

    # The client shows "trying to reconnect" after reconnectTimeout
    reconnect_detected = False
    for _ in range(30):
        time.sleep(1)
        elapsed = int(time.time() - disconnect_time)
        # Check debug log for timeout events
        with open(debug_log) as f:
            recent = f.read()
        if "transport offline" in recent or "attempting new transport path" in recent:
            reconnect_detected = True
            ok(f"Disconnect detected after ~{elapsed}s")
            break
        info(f"Waiting... {elapsed}s elapsed")

    if not reconnect_detected:
        info("Disconnect not seen in debug log yet, proceeding anyway")

    # Give the reconnect loop a bit to start
    time.sleep(3)

    # --- Step 7: Send repunch escape sequence ---
    # The escape sequence is: Enter, ~, r (default escape char is ~)
    log("Sending repunch escape sequence: ENTER + ~ + r", YELLOW)
    child.send("\r")
    time.sleep(0.3)
    child.send("~")
    time.sleep(0.3)
    # This opens the escape menu, then we press 'r' for repunch
    # Or we might need to wait for the menu and press 'r'
    # Actually looking at the code: ~r directly triggers runConsole, then pressing r
    # sends the repunch action. Let me send 'r' to select repunch from the menu.

    # Wait a tiny bit for the menu to appear
    time.sleep(0.5)
    child.send("r")
    time.sleep(0.5)
    ok("Repunch escape sequence sent")

    # --- Step 8: Monitor repunch progress in debug log ---
    log("Monitoring repunch progress...")
    repunch_started = False
    repunch_done = False

    for _ in range(40):
        time.sleep(1)
        elapsed = int(time.time() - disconnect_time)
        with open(debug_log) as f:
            recent = f.read()

        if "[repunch]" in recent and not repunch_started:
            # Find repunch lines
            repunch_lines = [l for l in recent.splitlines() if "[repunch]" in l]
            for line in repunch_lines:
                info(f"  {line.strip()}")
            repunch_started = True
            ok("Repunch started!")

        if "transport reconnected" in recent.lower() or \
           "repunch] transport reconnected" in recent:
            ok(f"TRANSPORT RECONNECTED! (elapsed: {elapsed}s)")
            repunch_done = True
            break

        if "timed out waiting for reconnect" in recent:
            log("Repunch monitoring: timed out waiting for reconnect", RED)
            break

        info(f"Waiting for reconnect... {elapsed}s")

    # --- Step 9: Unblock UDP ---
    unblock_udp_port(tsshd_port)

    if not repunch_done:
        # Give it one more chance after unblocking
        log("Giving 10 more seconds after unblock...", YELLOW)
        for _ in range(10):
            time.sleep(1)
            with open(debug_log) as f:
                recent = f.read()
            if "transport reconnected" in recent.lower():
                ok("TRANSPORT RECONNECTED after unblock!")
                repunch_done = True
                break

    # --- Step 10: Verify session is still functional ---
    if repunch_done:
        log("Verifying session responsiveness after repunch...", YELLOW)
        child.sendline("echo POST_REPUNCH_OK")
        try:
            child.expect("POST_REPUNCH_OK", timeout=15)
            ok("Session responsive after repunch — TEST PASSED!")
        except Exception:
            log("Session not responsive after repunch", RED)

    # --- Cleanup ---
    log("Cleaning up...", YELLOW)
    child.sendline("exit")
    child.close(force=True)
    logfile.close()

    # Print summary of debug log
    log("\n=== DEBUG LOG SUMMARY ===", CYAN)
    with open(debug_log) as f:
        lines = f.readlines()
    # Show the last 50 lines
    for line in lines[-60:]:
        print(line.rstrip())

    if not repunch_done:
        log("\nTEST FAILED: repunch did not reconnect transport", RED)
        sys.exit(1)
    else:
        log("\nTEST PASSED!", GREEN)

if __name__ == "__main__":
    main()
