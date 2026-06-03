/*
MIT License

Copyright (c) 2023-2026 The Trzsz SSH Authors.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package tssh

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/x/ansi"
	"github.com/trzsz/tsshd/tsshd"
	"golang.org/x/crypto/ssh"
)

// holePunchSetup captures the result of client-side STUN before tsshd is
// launched. conn is the still-open *net.UDPConn used for STUN -- handed
// off intact to the UDP transport so the NAT mapping established for the
// STUN exchange (and advertised to tsshd as publicEndpoint) survives into
// the live connection. Closing it discards the punched mapping.
type holePunchSetup struct {
	conn           *net.UDPConn
	publicEndpoint string
}

const kDefaultUdpAliveTimeout = 24 * time.Hour

const kDefaultUdpHeartbeatTimeout = 3 * time.Second

const kDefaultUdpReconnectTimeout = 15 * time.Second

type udpModeType int

const (
	kUdpModeNo udpModeType = iota
	kUdpModeYes
	kUdpModeKcp
	kUdpModeQuic
)

func (t udpModeType) String() string {
	return [...]string{
		"No",
		"Yes",
		"KCP",
		"QUIC",
	}[t]
}

type sshUdpClient struct {
	*tsshd.SshUdpClient
	proxyClient      *sshUdpClient
	intervalTime     time.Duration
	aliveTimeout     time.Duration
	connectTimeout   time.Duration
	reconnectTimeout time.Duration
	waitCloseChan    chan struct{}
	showNotifMutex   sync.Mutex
	notifInterceptor *notifInterceptor
	notifModel       atomic.Pointer[notifModel]
	sshDestName      string
	attachMode       bool
	sshConn          atomic.Pointer[sshConnection]
	// punchUsed, serverPid, and punchParam are populated when --punch was
	// active so the user-triggered repunch can re-STUN, open a fresh SSH
	// session to run `tsshd --repunch`, and inject the new socket back
	// into the UDP transport. We do NOT retain the original TCP/SSH
	// client across suspend: that connection has almost certainly died
	// silently while the laptop was closed, so reusing it would hang or
	// error -- repunch dials a fresh one each time instead.
	punchUsed     bool
	serverPid     int
	punchParam    *sshParam
	repunchMutex  sync.Mutex
	transportMode string // "KCP" or "QUIC" from serverInfo.Mode
}

type detachableWriter struct {
	io.WriteCloser
	attachMode bool
}

func (w *detachableWriter) Close() error {
	if w.attachMode && !wantExit.Load() {
		return nil
	}
	return w.WriteCloser.Close()
}

type detachableSession struct {
	*tsshd.SshUdpSession
	attachMode bool
}

func (s *detachableSession) StdinPipe() (io.WriteCloser, error) {
	writer, err := s.SshUdpSession.StdinPipe()
	if err != nil {
		return nil, err
	}
	return &detachableWriter{writer, s.attachMode}, nil
}

func (s *detachableSession) Close() error {
	if s.attachMode && !wantExit.Load() {
		return nil
	}
	return s.SshUdpSession.Close()
}

func (c *sshUdpClient) NewSession() (SshSession, error) {
	session, err := c.SshUdpClient.NewSession()
	if err != nil {
		return nil, err
	}
	return &detachableSession{session, c.attachMode}, nil
}

func (c *sshUdpClient) DialTimeout(network, addr string, timeout time.Duration) (net.Conn, error) {
	return c.SshUdpClient.DialTimeout(network, addr, timeout)
}

func (c *sshUdpClient) Close() (err error) {
	if !c.attachMode || wantExit.Load() {
		err = c.SshUdpClient.Close()
	}
	if c.waitCloseChan != nil {
		select {
		case c.waitCloseChan <- struct{}{}:
		default:
		}
	}
	return err
}

func (c *sshUdpClient) Wait() error {
	if c.waitCloseChan != nil {
		<-c.waitCloseChan
	}
	return c.SshUdpClient.Wait()
}

func (c *sshUdpClient) exit(code int, cause string) {
	if notif := c.notifModel.Load(); notif != nil {
		notif.clientExiting.Store(true)
		notif.renderView(true, false)
	}
	c.sshConn.Load().forceExit(code, cause)
}

func (c *sshUdpClient) debug(format string, a ...any) {
	if !enableDebugLogging {
		return
	}
	msg := fmt.Sprintf(format, a...)
	writeDebugLog(time.Now().UnixMilli(), c.sshDestName, msg)
}

// triggerRepunch is invoked by the escape-console "r" key when --punch is
// active and the underlying NAT mapping likely died (typically after a
// laptop suspend/resume). It re-STUNs the client, opens a fresh SSH/TCP
// session to run `tsshd --repunch`, and hands the freshly bound socket
// back to the UDP transport so the next renew uses it.
//
// A fresh SSH dial is required (rather than reusing the original TCP
// client) because that connection has almost certainly silently died
// during suspend -- which is the exact case the user invokes repunch
// to recover from. If the user's auth method is keyboard-interactive
// they will see a password prompt; pubkey + agent auth is seamless.
func (c *sshUdpClient) triggerRepunch() error {
	if !c.punchUsed {
		return fmt.Errorf("hole punching is not active for this session")
	}
	if c.punchParam == nil {
		return fmt.Errorf("no retained SSH params for repunch")
	}
	if c.serverPid == 0 {
		return fmt.Errorf("tsshd pid unknown; repunch unsupported by this server version")
	}

	// Serialise concurrent repunch attempts -- a user mashing the key
	// should not start two STUN runs racing for the same renewMutex.
	c.repunchMutex.Lock()
	defer c.repunchMutex.Unlock()

	step := func(msg string) { fmt.Fprintf(os.Stderr, "\r\n\033[0;36m[repunch]\033[0m %s", msg) }
	fail := func(label string, err error) error {
		fmt.Fprintf(os.Stderr, "\r\n\033[0;31m[repunch] FAILED at %s: %v\033[0m\r\n", label, err)
		return err
	}

	step("STUNing to discover new client public endpoint...")
	punch, err := setupHolePunch(c.punchParam.args)
	if err != nil {
		return fail("re-STUN", fmt.Errorf("re-STUN failed: %v", err))
	}
	step(fmt.Sprintf("client public endpoint: %s", punch.publicEndpoint))

	step("dialing SSH/TCP to reach tsshd socket...")
	tcpClient, err := tcpLogin(c.punchParam, nil, kUdpModeNo)
	if err != nil {
		_ = punch.conn.Close()
		return fail("re-dial SSH", fmt.Errorf("re-dial SSH failed: %v", err))
	}
	defer func() { _ = tcpClient.Close() }()

	tsshdPath := getTsshdPath(c.punchParam.args)
	cmd := fmt.Sprintf(" --repunch %d --punch %s", c.serverPid, punch.publicEndpoint)
	step(fmt.Sprintf("running: tsshd%s", cmd))
	output, err := execTsshdCommand(tcpClient, tsshdPath, cmd)
	if err != nil {
		_ = punch.conn.Close()
		return fail("tsshd --repunch", fmt.Errorf("run tsshd --repunch failed: %v", err))
	}
	outputStr := strings.TrimSpace(string(output))
	step(fmt.Sprintf("server response: %q", outputStr))
	if !bytes.HasPrefix(bytes.TrimSpace(output), []byte("OK")) {
		_ = punch.conn.Close()
		return fail("server repunch", fmt.Errorf("tsshd repunch error: %s", outputStr))
	}

	step("injecting new socket into UDP transport and kicking reconnect...")
	if err := c.SshUdpClient.RefreshHolePunch(punch.conn); err != nil {
		_ = punch.conn.Close()
		return fail("RefreshHolePunch", fmt.Errorf("refresh local hole-punch socket failed: %v", err))
	}
	step("socket injected — monitoring reconnect...\r\n")

	go func() {
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			time.Sleep(time.Second)
			if time.Since(time.UnixMilli(c.SshUdpClient.GetLastActiveTime())) < c.reconnectTimeout {
				fmt.Fprintf(os.Stderr, "\r\n\033[0;32m[repunch] transport reconnected!\033[0m\r\n")
				return
			}
			if err := c.SshUdpClient.GetLastReconnectError(); err != nil {
				fmt.Fprintf(os.Stderr, "\r\033[0;33m[repunch] reconnect attempt failed: %v\033[0m\x1b[K", err)
			} else {
				fmt.Fprintf(os.Stderr, "\r\033[0;36m[repunch] waiting... (last active %v ago)\033[0m\x1b[K",
					time.Since(time.UnixMilli(c.SshUdpClient.GetLastActiveTime())).Round(time.Second))
			}
		}
		fmt.Fprintf(os.Stderr, "\r\n\033[0;31m[repunch] timed out waiting for reconnect after 30s\033[0m\r\n")
	}()

	return nil
}

func (c *sshUdpClient) isReconnectTimeout() bool {
	return time.Since(time.UnixMilli(c.GetLastActiveTime())) > c.reconnectTimeout
}

func (c *sshUdpClient) udpKeepAlive() {
	for !c.IsClosed() {
		if c.sshConn.Load() != nil && time.Since(time.UnixMilli(c.GetLastActiveTime())) > c.aliveTimeout {
			c.debug("alive timeout for %v", c.aliveTimeout)
			c.exit(kExitCodeUdpTimeout, fmt.Sprintf("lost connection and timeout after %v", c.aliveTimeout))
			return
		}

		if isTerminal && c.sshConn.Load() != nil && enableWarningLogging && c.isReconnectTimeout() {
			go c.notifyConnectionLost()
		}

		time.Sleep(c.intervalTime)
	}
}

func (c *sshUdpClient) getConnLostStatus() string {
	base := fmt.Sprintf("Oops, looks like the connection to the server was lost, trying to reconnect for %d/%d seconds.",
		time.Since(time.UnixMilli(c.GetLastActiveTime()))/time.Second, c.aliveTimeout/time.Second)
	if c.punchUsed {
		// Hint appears only when --punch is active. The escape char is
		// usually '~' (configurable via EscapeChar); the hint references
		// the default since chasing the live value here would require
		// threading another field down from stdio setup.
		base += " Press <ENTER>~r to re-punch."
	}
	return base
}

func (c *sshUdpClient) notifyConnectionLost() {
	if !c.showNotifMutex.TryLock() {
		return
	}
	defer c.showNotifMutex.Unlock()
	if !c.isReconnectTimeout() {
		return
	}

	if c.notifInterceptor == nil {
		_, _ = os.Stderr.WriteString(ansi.HideCursor)
		for c.isReconnectTimeout() && !c.sshConn.Load().exited.Load() {
			fmt.Fprintf(os.Stderr, "\r\033[0;33m%s\033[0m\x1b[K", c.getConnLostStatus())
			time.Sleep(time.Second)
		}
		if !c.isReconnectTimeout() && !c.sshConn.Load().exited.Load() {
			fmt.Fprintf(os.Stderr, "\r\033[0;32m%s\033[0m\x1b[K\r\n", "Congratulations, you have successfully reconnected to the server.")
		}
		_, _ = os.Stderr.WriteString(ansi.ShowCursor)
		return
	}

	showConnectionLostNotif(c)
}

var lastJumpUdpClient *sshUdpClient
var globalUdpAliveTimeout time.Duration

func quitCallback(name, reason string) {
	for lastJumpUdpClient == nil || lastJumpUdpClient.sshConn.Load() == nil {
		time.Sleep(10 * time.Millisecond) // waiting for sshConn to be initialized
	}
	lastJumpUdpClient.sshConn.Load().forceExit(kExitCodeSignalKill, fmt.Sprintf("[%s] %s", name, reason))
}

func initGlobalUdpAliveTimeout(args *sshArgs) {
	if globalUdpAliveTimeout != 0 {
		warning("global udp alive timeout [%v] has already been initialized", globalUdpAliveTimeout)
		return
	}
	globalUdpAliveTimeout = getUdpTimeoutConfig(args, "UdpAliveTimeout", kDefaultUdpAliveTimeout)
	debug("init global udp alive timeout [%v] for [%s]", globalUdpAliveTimeout, args.Destination)
}

func udpLogin(param *sshParam, tcpClient SshClient) (SshClient, error) {
	defer func() { _ = tcpClient.Close() }()

	args := param.args
	debug("udp login to [%s] using UDP mode: %s", args.Destination, param.udpMode)

	if enableDebugLogging {
		if initDebugLogFile() && maxHostNameLength == 0 {
			debug("udp debug logs are written to \x1b[0;35m%s\x1b[0m", debugLogFileName)
		}
		maxHostNameLength = max(maxHostNameLength, len(args.Destination))
	}

	mtu := uint16(0)
	if udpMTU := getExOptionConfig(args, "UdpMTU"); udpMTU != "" {
		if v, err := strconv.ParseUint(udpMTU, 10, 16); err != nil {
			warning("UdpMTU [%s] invalid: %v", udpMTU, err)
		} else {
			mtu = uint16(v)
		}
	}

	var proxyClient *sshUdpClient
	if param.proxy != nil {
		var ok bool
		proxyClient, ok = param.proxy.client.(*sshUdpClient)
		if !ok {
			return nil, fmt.Errorf("proxy client [%T] for [%s] is not a udp client", param.proxy.client, args.Destination)
		}
		if mtu == 0 {
			mtu = proxyClient.GetMaxDatagramSize()
		}
	}

	// hole punching: must run BEFORE building the tsshd command so we can
	// pass the client's public endpoint as a --punch argument. Skipped when
	// a proxy is configured (proxy hop owns leg 1's UDP transport) or when
	// UDP-over-TCP is selected (no UDP socket to STUN against).
	var punch *holePunchSetup
	if isHolePunchEnabled(args) {
		switch {
		case param.proxy != nil:
			warning("ignoring --punch: hole punching is not supported through a proxy jump")
		case strings.ToLower(getExOptionConfig(args, "UdpProxyMode")) == "tcp":
			warning("ignoring --punch: hole punching requires UDP transport (UdpProxyMode=tcp is set)")
		default:
			var err error
			punch, err = setupHolePunch(args)
			if err != nil {
				return nil, fmt.Errorf("udp login to [%s] hole punch setup failed: %v", args.Destination, err)
			}
		}
	}
	// If anything below fails before we hand the socket off to tsshd's
	// UDP client, close it so we don't leak the fd or hold the local port.
	punchHandedOff := false
	defer func() {
		if punch != nil && !punchHandedOff {
			_ = punch.conn.Close()
		}
	}()

	// start tsshd
	attachMode := false
	tsshdPath := getTsshdPath(args)
	connectTimeout := getConnectTimeout(args)
	sessionName := getExOptionConfig(args, "UdpSessionName")
	var tsshdCmdBuf *strings.Builder
	// freshSession is true when tsshdCmdBuf will launch a brand-new tsshd
	// rather than attach to one already running. Used below to force
	// --attachable --socket when --punch is set, so the unix socket exists
	// for later repunch RPCs after the SSH control channel has closed.
	freshSession := false
	if args.Attach || strings.ToLower(getExOptionConfig(args, "UdpSessionAttach")) == "yes" {
		var err error
		tsshdCmdBuf, err = attachToSession(tcpClient, tsshdPath, sessionName)
		if err != nil {
			if _, ok := err.(*attachSelectError); ok {
				return nil, fmt.Errorf("failed to select tsshd session to attach: %v", err)
			}
			warning("falling back to new session due to attach failed: %v", err)
		}
		if tsshdCmdBuf == nil {
			tsshdCmdBuf = getTsshdCommand(param, tsshdPath, mtu, connectTimeout)
			tsshdCmdBuf.WriteString(" --attachable --socket")
			freshSession = true
		}
		attachMode = true
	} else {
		tsshdCmdBuf = getTsshdCommand(param, tsshdPath, mtu, connectTimeout)
		freshSession = true
	}
	if punch != nil {
		if freshSession && !strings.Contains(tsshdCmdBuf.String(), " --attachable") {
			tsshdCmdBuf.WriteString(" --attachable --socket")
		}
		fmt.Fprintf(tsshdCmdBuf, " --punch %s", punch.publicEndpoint)
		if host := getExOptionConfig(args, "UdpStunHost"); host != "" {
			fmt.Fprintf(tsshdCmdBuf, " --stun-host %s", host)
		}
		if port := getExOptionConfig(args, "UdpStunPort"); port != "" {
			fmt.Fprintf(tsshdCmdBuf, " --stun-port %s", port)
		}
	}
	tsshdCmd := tsshdCmdBuf.String()
	debug("udp login to [%s] tsshd command: %s", args.Destination, tsshdCmd)

	debug("udp login to [%s] waiting for tsshd to start and report ServerInfo...", args.Destination)
	tsshdStart := time.Now()
	serverInfo, err := startTsshdServer(args, tcpClient, tsshdCmd)
	if err != nil {
		return nil, fmt.Errorf("udp login to [%s] start tsshd on remote failed: %v", args.Destination, err)
	}
	debug("udp login to [%s] tsshd ready after %v: port=%d publicAddr=%q mode=%s",
		args.Destination, time.Since(tsshdStart), serverInfo.Port, serverInfo.PublicAddr, serverInfo.Mode)

	// udp config
	if globalUdpAliveTimeout == 0 {
		warning("global udp alive timeout for [%s] has not been initialized yet", args.Destination)
		initGlobalUdpAliveTimeout(param.args)
	}
	heartbeatTimeout := getUdpTimeoutConfig(args, "UdpHeartbeatTimeout", kDefaultUdpHeartbeatTimeout)
	reconnectTimeout := getUdpTimeoutConfig(args, "UdpReconnectTimeout", kDefaultUdpReconnectTimeout)
	// Ensure at least 10 keep-alive attempts before exiting on timeout,
	// and at least 3 attempts before reconnect or showing a connection lost notification.
	intervalTime := min(globalUdpAliveTimeout/10, min(heartbeatTimeout, reconnectTimeout)/3)
	debug("udp keep alive interval time [%v] for [%s]", intervalTime, args.Destination)

	// new udp client
	udpClient := &sshUdpClient{
		proxyClient:      proxyClient,
		intervalTime:     intervalTime,
		aliveTimeout:     globalUdpAliveTimeout,
		connectTimeout:   connectTimeout,
		reconnectTimeout: reconnectTimeout,
		sshDestName:      args.Destination,
		attachMode:       attachMode,
		punchUsed:        punch != nil,
		serverPid:        serverInfo.Pid,
		transportMode:    serverInfo.Mode,
	}
	if punch != nil {
		udpClient.punchParam = param
	}
	tsshdAddr := joinHostPort(param.host, strconv.Itoa(serverInfo.Port))
	if punch != nil && serverInfo.PublicAddr != "" {
		debug("udp login to [%s] using punched endpoint: %s (was %s)", args.Destination, serverInfo.PublicAddr, tsshdAddr)
		tsshdAddr = serverInfo.PublicAddr
	} else if punch != nil {
		warning("hole punch requested but tsshd did not report a public endpoint; falling back to direct address")
	}
	clientOpts := &tsshd.UdpClientOptions{
		EnableDebugging:  enableDebugLogging,
		EnableWarning:    enableWarningLogging,
		IPv4:             param.ipv4,
		IPv6:             param.ipv6,
		TsshdAddr:        tsshdAddr,
		SessionName:      sessionName,
		ServerInfo:       serverInfo,
		AliveTimeout:     globalUdpAliveTimeout,
		IntervalTime:     intervalTime,
		ConnectTimeout:   connectTimeout,
		HeartbeatTimeout: heartbeatTimeout,
		DebugFunc:        func(msec int64, msg string) { writeDebugLog(msec, args.Destination, msg) },
		WarningFunc:      func(msg string) { warning("udp [%s] %s", args.Destination, msg) },
		QuitCallback:     func(reason string) { quitCallback(args.Destination, reason) },
		DiscardCallback:  handleTmuxDiscardedInput,
	}
	if punch != nil {
		clientOpts.LocalConn = punch.conn
		if la, ok := punch.conn.LocalAddr().(*net.UDPAddr); ok {
			// On a transport renew after the punched socket has been
			// closed, fall back to dialing fresh on the same local port.
			// The NAT mapping may already be gone, but reusing the port
			// is harmless and slightly better than picking a random one.
			clientOpts.LocalPort = uint16(la.Port)
		}
	}

	if param.proxy != nil {
		clientOpts.ProxyClient = proxyClient.SshUdpClient
		debug("udp login to [%s] via proxy jump [%s] addr: %s", args.Destination, param.proxy.name, tsshdAddr)
	} else {
		debug("udp login to [%s] tsshd server addr: %s", param.args.Destination, tsshdAddr)
	}

	debug("udp login to [%s] dialing tsshd at [%s] (timeout %v)", args.Destination, tsshdAddr, connectTimeout)
	dialStart := time.Now()
	udpClient.SshUdpClient, err = tsshd.NewSshUdpClient(clientOpts)
	if err != nil {
		return nil, fmt.Errorf("udp login to [%s] failed after %v: %v", args.Destination, time.Since(dialStart), err)
	}
	// Ownership of the punched socket is now inside SshUdpClient -- its
	// lifecycle (close on transport renew or shutdown) takes over.
	punchHandedOff = true
	debug("udp login to [%s] success after %v", args.Destination, time.Since(dialStart))

	lastJumpUdpClient = udpClient

	// preventing exit for just forwarding ports
	if args.NoCommand || args.Background {
		udpClient.waitCloseChan = make(chan struct{}, 1)
	}

	// udp keep alive
	go udpClient.udpKeepAlive()

	return udpClient, nil
}

func startTsshdServer(args *sshArgs, tcpClient SshClient, tsshdCmd string) (*tsshd.ServerInfo, error) {
	session, err := tcpClient.NewSession()
	if err != nil {
		return nil, fmt.Errorf("new session failed: %v", err)
	}
	defer func() { _ = session.Close() }()

	// Some Windows SSH servers treat a missing stdin as EOF, which may
	// cause the remote command to exit prematurely and prevent tsshd
	// from starting. Attach a stdin pipe to avoid this.
	serverIn, err := session.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("stdin pipe failed: %v", err)
	}
	defer func() { _ = serverIn.Close() }()

	serverOut, err := session.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe failed: %v", err)
	}
	serverErr, err := session.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("stderr pipe failed: %v", err)
	}

	term, err := sendAndSetEnv(args, session)
	if err != nil {
		return nil, err
	}

	if err := session.RequestPty(term, 200, 800, ssh.TerminalModes{}); err != nil {
		return nil, fmt.Errorf("request pty for tsshd failed: %v", err)
	}

	if err := session.Start(tsshdCmd); err != nil {
		return nil, fmt.Errorf("session start failed: %v", err)
	}

	if err := session.Wait(); err != nil {
		var builder strings.Builder
		fmt.Fprintf(&builder, "session wait failed: %v", err)
		if outMsg, _ := readConsoleOutput(serverOut); outMsg != "" {
			builder.WriteByte('\n')
			builder.WriteString(outMsg)
		}
		if errMsg, _ := readConsoleOutput(serverErr); errMsg != "" {
			builder.WriteByte('\n')
			builder.WriteString(errMsg)
		}
		return nil, fmt.Errorf("%s\r\n%s", builder.String(),
			"\033[0;36mHint:\033[0m Have you installed tsshd on your server? You may need to specify the path to tsshd.")
	}

	output, err := readConsoleOutput(serverOut)
	if output == "" {
		if errMsg, _ := readConsoleOutput(serverErr); errMsg != "" {
			return nil, fmt.Errorf("stdout is empty, stderr output: %s", errMsg)
		}
		if err != nil {
			return nil, fmt.Errorf("read stdout output failed: %v", err)
		}
		return nil, fmt.Errorf("stdout and stderr are both empty")
	}

	pos := strings.LastIndexByte(output, '\a')
	if pos >= 0 {
		output = output[pos+1:]
	}
	pos = strings.IndexByte(output, '{')
	if pos >= 0 {
		output = output[pos:]
	}
	pos = strings.LastIndexByte(output, '}')
	if pos >= 0 {
		output = output[:pos+1]
	}
	output = strings.ReplaceAll(output, "\r", "")
	output = strings.ReplaceAll(output, "\n", "")
	if !strings.HasPrefix(output, "{") || !strings.HasSuffix(output, "}") {
		return nil, fmt.Errorf("unexpected stdout output: %s", strconv.QuoteToASCII(output))
	}

	var info tsshd.ServerInfo
	if err := json.Unmarshal([]byte(output), &info); err != nil {
		return nil, fmt.Errorf("json unmarshal [%s] failed: %v", strconv.QuoteToASCII(output), err)
	}

	return &info, nil
}

func getTsshdPath(args *sshArgs) string {
	if args.TsshdPath != "" {
		return args.TsshdPath
	}
	if tsshdPath := getExOptionConfig(args, "TsshdPath"); tsshdPath != "" {
		return tsshdPath
	}
	return "tsshd"
}

func getTsshdCommand(param *sshParam, tsshdPath string, mtu uint16, connectTimeout time.Duration) *strings.Builder {
	args := param.args
	var buf strings.Builder
	buf.WriteString(tsshdPath)

	if param.udpMode == kUdpModeKcp {
		buf.WriteString(" --kcp")
	}
	if udpProxyMode := strings.ToLower(getExOptionConfig(args, "UdpProxyMode")); udpProxyMode == "tcp" {
		buf.WriteString(" --tcp")
	}
	if enableDebugLogging {
		buf.WriteString(" --debug")
	}

	network := getNetworkAddressFamily(args)
	if strings.HasSuffix(network, "4") {
		buf.WriteString(" --ipv4")
	}
	if strings.HasSuffix(network, "6") {
		buf.WriteString(" --ipv6")
	}

	if mtu > 0 {
		buf.WriteString(" --mtu ")
		fmt.Fprintf(&buf, "%d", mtu)
	}

	tsshdPort := args.TsshdPort
	if tsshdPort == "" {
		tsshdPort = getExOptionConfig(args, "TsshdPort")
	}
	if tsshdPort == "" {
		tsshdPort = getExOptionConfig(args, "UdpPort") // backward compatibility
	}
	if tsshdPort != "" {
		ranges := parseTsshdPortRanges(tsshdPort)
		if len(ranges) > 0 {
			buf.WriteString(" --port ")
			for i, r := range ranges {
				if i > 0 {
					buf.WriteByte(',')
				}
				if r[0] == r[1] {
					fmt.Fprintf(&buf, "%d", r[0])
				} else {
					fmt.Fprintf(&buf, "%d-%d", r[0], r[1])
				}
			}
		}
	}

	if connectTimeout != kDefaultConnectTimeout {
		buf.WriteString(" --connect-timeout ")
		fmt.Fprintf(&buf, "%d", connectTimeout/time.Second)
	}

	return &buf
}

func parseTsshdPortRanges(tsshdPort string) [][2]uint16 {
	var ranges [][2]uint16

	addPortRange := func(lowPort string, highPort *string) {
		low, err := strconv.ParseUint(lowPort, 10, 16)
		if err != nil || low == 0 {
			warning("tsshd port [%s] invalid: port [%s] is not a value in [1, 65535]", tsshdPort, lowPort)
			return
		}
		high := low
		if highPort != nil {
			high, err = strconv.ParseUint(*highPort, 10, 16)
			if err != nil || high == 0 {
				warning("tsshd port [%s] invalid: port [%s] is not a value in [1, 65535]", tsshdPort, *highPort)
				return
			}
		}
		if low > high {
			warning("tsshd port [%s] invalid: port range [%d-%d] is invalid (low > high)", tsshdPort, low, high)
			return
		}
		ranges = append(ranges, [2]uint16{uint16(low), uint16(high)})
	}

	for seg := range strings.SplitSeq(tsshdPort, ",") {
		tokens := strings.Fields(seg)
		k := -1
		for i := 0; i < len(tokens); i++ {
			token := tokens[i]
			// Case 1: combined form like "8000-9000"
			if strings.Contains(token, "-") && token != "-" {
				parts := strings.Split(token, "-")
				if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
					warning("tsshd port [%s] invalid: malformed port range [%s]", tsshdPort, token)
					continue
				}
				addPortRange(parts[0], &parts[1])
				continue
			}
			// Case 2: single "-"
			if token == "-" {
				if i == 0 || i+1 >= len(tokens) || i-1 <= k {
					warning("tsshd port [%s] invalid: '-' must appear between two ports", tsshdPort)
					i++
					continue
				}
				addPortRange(tokens[i-1], &tokens[i+1])
				k = i + 1
				i++ // skip high
				continue
			}
			// Case 3: part of a range: skip (handled by '-')
			if i+1 < len(tokens) && tokens[i+1] == "-" {
				continue
			}
			// Case 4: plain number
			if i > 0 && tokens[i-1] == "-" {
				warning("tsshd port [%s] invalid: malformed port range [- %s]", tsshdPort, token)
				continue
			}
			addPortRange(token, nil)
		}
	}

	return ranges
}

func readConsoleOutput(stream io.Reader) (string, error) {
	var buf bytes.Buffer
	_, err := buf.ReadFrom(stream)
	out := strings.TrimSpace(ansi.Strip(buf.String()))
	return out, err
}

func getUdpTimeoutConfig(args *sshArgs, timeoutOption string, defaultTimeout time.Duration) time.Duration {
	timeoutConfig := getExOptionConfig(args, timeoutOption)
	if timeoutConfig == "" {
		return defaultTimeout
	}
	timeoutSeconds, err := convertSshTime(timeoutConfig)
	if err != nil {
		warning("%s [%s] invalid: %v", timeoutOption, timeoutConfig, err)
		return defaultTimeout
	}
	if timeoutSeconds <= 0 {
		warning("%s [%d] must be greater than 0", timeoutOption, timeoutSeconds)
		return defaultTimeout
	}
	return time.Duration(timeoutSeconds) * time.Second
}

func getUdpMode(args *sshArgs) udpModeType {
	if udpMode := args.Option.get("UdpMode"); udpMode != "" {
		switch strings.ToLower(udpMode) {
		case "no":
			if args.UDP || args.KCP {
				warning("disable UDP mode since -oUdpMode=No")
			}
			return kUdpModeNo
		case "yes":
			return kUdpModeYes
		case "kcp":
			return kUdpModeKcp
		case "quic":
			return kUdpModeQuic
		default:
			warning("unknown UdpMode %s", udpMode)
		}
	}

	if args.KCP {
		return kUdpModeKcp
	}

	udpMode := getExConfig(args.Destination, "UdpMode")
	switch strings.ToLower(udpMode) {
	case "", "no":
		break
	case "yes":
		return kUdpModeYes
	case "kcp":
		return kUdpModeKcp
	case "quic":
		return kUdpModeQuic
	default:
		warning("unknown UdpMode %s", udpMode)
	}

	if args.UDP || args.Attach || args.Punch {
		return kUdpModeYes
	}
	return kUdpModeNo
}

func isHolePunchEnabled(args *sshArgs) bool {
	if args.Punch {
		return true
	}
	return strings.ToLower(getExOptionConfig(args, "UdpHolePunch")) == "yes"
}

// setupHolePunch binds a local UDP socket and runs STUN to learn the public
// endpoint. The socket is left OPEN -- closing it would burn the NAT mapping
// on routers that drop the mapping on socket close. The caller is responsible
// for handing the conn to the UDP transport (or closing it on failure).
func setupHolePunch(args *sshArgs) (*holePunchSetup, error) {
	stunConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("bind stun socket: %v", err)
	}

	localAddr, ok := stunConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		_ = stunConn.Close()
		return nil, fmt.Errorf("stun socket LocalAddr is %T, not *net.UDPAddr", stunConn.LocalAddr())
	}

	stunHost := getExOptionConfig(args, "UdpStunHost")
	var stunPort int
	if p := getExOptionConfig(args, "UdpStunPort"); p != "" {
		if v, err := strconv.ParseUint(p, 10, 16); err != nil {
			warning("UdpStunPort [%s] invalid: %v", p, err)
		} else {
			stunPort = int(v)
		}
	}

	publicIP, publicPort, err := tsshd.StunDiscover(stunConn, stunHost, stunPort)
	if err != nil {
		_ = stunConn.Close()
		return nil, fmt.Errorf("stun: %v", err)
	}

	endpoint := net.JoinHostPort(publicIP, strconv.Itoa(publicPort))
	debug("hole punch: client public endpoint %s (local port %d)", endpoint, localAddr.Port)
	return &holePunchSetup{
		conn:           stunConn,
		publicEndpoint: endpoint,
	}, nil
}
