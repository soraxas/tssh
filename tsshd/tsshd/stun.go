/*
MIT License

Copyright (c) 2024-2026 The Trzsz SSH Authors.

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

package tsshd

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	kStunMagicCookie     uint32 = 0x2112A442
	kStunBindingRequest  uint16 = 0x0001
	kStunBindingResponse uint16 = 0x0101
	kStunAttrMapped      uint16 = 0x0001
	kStunAttrXorMapped   uint16 = 0x0020

	kDefaultStunHost = "stun.l.google.com"
	kDefaultStunPort = 19302
)

// StunDiscover sends a STUN Binding Request on conn to (stunHost, stunPort) and
// returns the discovered public (IP, port) for conn's local mapping.
//
// conn must be an unconnected packet conn (typically a *net.UDPConn from
// net.ListenUDP). This is the same socket the caller will use afterwards
// for application traffic, so the discovered mapping matches.
func StunDiscover(conn net.PacketConn, stunHost string, stunPort int) (string, int, error) {
	if stunHost == "" {
		stunHost = kDefaultStunHost
	}
	if stunPort == 0 {
		stunPort = kDefaultStunPort
	}

	resolveCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(resolveCtx, stunHost)
	if err != nil {
		return "", 0, fmt.Errorf("resolve stun host [%s]: %w", stunHost, err)
	}
	var stunAddr *net.UDPAddr
	for _, ia := range addrs {
		if ip4 := ia.IP.To4(); ip4 != nil {
			stunAddr = &net.UDPAddr{IP: ip4, Port: stunPort}
			break
		}
	}
	if stunAddr == nil {
		return "", 0, fmt.Errorf("no IPv4 address for stun host [%s]", stunHost)
	}

	var txid [12]byte
	if _, err := rand.Read(txid[:]); err != nil {
		return "", 0, fmt.Errorf("rand txid: %w", err)
	}

	req := make([]byte, 20)
	binary.BigEndian.PutUint16(req[0:2], kStunBindingRequest)
	binary.BigEndian.PutUint16(req[2:4], 0) // length: no attributes
	binary.BigEndian.PutUint32(req[4:8], kStunMagicCookie)
	copy(req[8:20], txid[:])

	buf := make([]byte, 2048)
	deadline := time.Now().Add(6 * time.Second)

	for attempt := 0; attempt < 3 && time.Now().Before(deadline); attempt++ {
		if _, err := conn.WriteTo(req, stunAddr); err != nil {
			return "", 0, fmt.Errorf("send stun request: %w", err)
		}

		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}
		if n < 20 {
			continue
		}

		msgType := binary.BigEndian.Uint16(buf[0:2])
		msgLen := binary.BigEndian.Uint16(buf[2:4])
		cookie := binary.BigEndian.Uint32(buf[4:8])
		if msgType != kStunBindingResponse || cookie != kStunMagicCookie {
			continue
		}
		if string(buf[8:20]) != string(txid[:]) {
			continue
		}

		pos := 20
		end := 20 + int(msgLen)
		if end > n {
			end = n
		}
		for pos+4 <= end {
			attrType := binary.BigEndian.Uint16(buf[pos : pos+2])
			attrLen := int(binary.BigEndian.Uint16(buf[pos+2 : pos+4]))
			if pos+4+attrLen > end {
				break
			}
			value := buf[pos+4 : pos+4+attrLen]
			pos += 4 + ((attrLen + 3) &^ 3)

			if attrType == kStunAttrXorMapped && attrLen >= 8 {
				if value[1] != 0x01 {
					continue
				}
				xport := binary.BigEndian.Uint16(value[2:4])
				port := int(xport ^ uint16(kStunMagicCookie>>16))
				var mask [4]byte
				binary.BigEndian.PutUint32(mask[:], kStunMagicCookie)
				addr := make(net.IP, 4)
				for i := 0; i < 4; i++ {
					addr[i] = value[4+i] ^ mask[i]
				}
				_ = conn.SetReadDeadline(time.Time{})
				return addr.String(), port, nil
			}
			if attrType == kStunAttrMapped && attrLen >= 8 {
				if value[1] != 0x01 {
					continue
				}
				port := int(binary.BigEndian.Uint16(value[2:4]))
				addr := net.IP(value[4:8])
				_ = conn.SetReadDeadline(time.Time{})
				return addr.String(), port, nil
			}
		}
	}

	_ = conn.SetReadDeadline(time.Time{})
	return "", 0, fmt.Errorf("no stun response from [%s]:%d", stunHost, stunPort)
}

// punchState retains the bits of the initial hole-punch setup that a later
// repunch needs: the stun-discovered UDP socket and a cancel handle for the
// currently-running runPunchLoop. Set once by doHolePunch and re-used by
// retargetHolePunch. The mutex serialises retargets so two concurrent
// repunch RPCs don't leave dangling loops.
type punchState struct {
	mu     sync.Mutex
	conn   *net.UDPConn
	cancel chan struct{}
}

var globalPunchState punchState

// doHolePunch STUNs the server's UDP socket and starts a goroutine sending
// punch packets to the client's public endpoint to open a NAT mapping.
// Must be called before startServerProxy so the proxy doesn't race STUN reads.
// Hole punching only applies in UDP transport mode; TCP mode is rejected.
func doHolePunch(args *tsshdArgs, fconn frontendConnection, info *ServerInfo) error {
	if args.TCP {
		return fmt.Errorf("--punch is incompatible with --tcp")
	}
	udpFront, ok := fconn.(*udpFrontendConn)
	if !ok || len(udpFront.connList) == 0 {
		return fmt.Errorf("no udp socket available for stun")
	}

	// Resolve the client's punch target up-front so we fail fast on bad input.
	clientAddr, err := net.ResolveUDPAddr("udp", args.Punch)
	if err != nil {
		return fmt.Errorf("resolve punch target [%s]: %w", args.Punch, err)
	}

	// STUN on the first listening socket. In the normal SSH-launched flow,
	// getUdpAddrs uses SSH_CONNECTION and returns a single socket bound to
	// the SSH server-side IP, so connList[0] is unambiguous. On a multi-
	// interface host with no SSH_CONNECTION env, this picks whichever
	// interface enumerated first -- which may not be the default-route
	// interface to the Internet. If that becomes a problem we'd need to
	// STUN each socket and pick the one with a successful reply, or expose
	// an explicit --stun-bind-ip.
	stunConn := udpFront.connList[0]
	publicIP, publicPort, err := StunDiscover(stunConn, args.StunHost, args.StunPort)
	if err != nil {
		return fmt.Errorf("stun discover: %w", err)
	}
	info.PublicAddr = net.JoinHostPort(publicIP, fmt.Sprintf("%d", publicPort))
	debug("tsshd public udp endpoint via stun: %s", info.PublicAddr)

	// Continuous punch: keep the server-side NAT mapping for clientAddr alive
	// until the real client traffic arrives. The proxy will drop these packets
	// on the client side (they're not auth packets) -- they exist only to make
	// the NAT translate; the actual handshake races them.
	cancel := make(chan struct{})
	globalPunchState.mu.Lock()
	globalPunchState.conn = stunConn
	globalPunchState.cancel = cancel
	globalPunchState.mu.Unlock()
	go runPunchLoop(stunConn, clientAddr, cancel)
	return nil
}

// retargetHolePunch redirects the punch loop at a new client public endpoint
// after the client has re-STUNed (typically after a laptop suspend/resume
// trashed the NAT mapping). It stops any still-running loop from the prior
// target and starts a new one. The server does NOT re-STUN -- the server's
// proxy is already reading from stunConn, so a STUN reply would race those
// reads and likely be eaten. The server's PublicAddr therefore stays as it
// was, which matches what the client is already dialing.
//
// Assumption: the server's NAT is endpoint-independent (or port-preserving)
// so the external port for stunConn is stable across the suspend window.
// On symmetric NATs or NATs that have GC'd the mapping, the external port
// may have changed and the client will keep dialing a stale PublicAddr.
// If that becomes a problem, we'd need a way to safely re-STUN the running
// socket -- likely by pausing proxy reads behind a mutex during STUN.
func retargetHolePunch(newClientEndpoint string) error {
	clientAddr, err := net.ResolveUDPAddr("udp", newClientEndpoint)
	if err != nil {
		return fmt.Errorf("resolve repunch target [%s]: %w", newClientEndpoint, err)
	}

	globalPunchState.mu.Lock()
	defer globalPunchState.mu.Unlock()
	if globalPunchState.conn == nil {
		return fmt.Errorf("hole punch was not initialised; tsshd must be started with --punch")
	}

	// Stop the previous loop (a no-op if it has already self-terminated past
	// its 30s window) before starting the new one.
	if globalPunchState.cancel != nil {
		close(globalPunchState.cancel)
	}
	cancel := make(chan struct{})
	globalPunchState.cancel = cancel
	go runPunchLoop(globalPunchState.conn, clientAddr, cancel)
	debug("repunch: punch loop retargeted at %s", clientAddr.String())
	return nil
}

func runPunchLoop(conn *net.UDPConn, peer *net.UDPAddr, cancel <-chan struct{}) {
	// Short-lived: most NAT mappings establish within a few seconds. After
	// 30s the real client should be sending QUIC/KCP packets which themselves
	// refresh the mapping, so we can stop. cancel allows a repunch to
	// preempt this loop before the deadline.
	deadline := time.Now().Add(30 * time.Second)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	msg := []byte("tsshd-punch")
	for time.Now().Before(deadline) {
		if _, err := conn.WriteToUDP(msg, peer); err != nil {
			debug("hole punch write failed: %v", err)
			return
		}
		select {
		case <-ticker.C:
		case <-cancel:
			return
		}
	}
}
