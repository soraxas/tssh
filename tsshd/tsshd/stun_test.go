/*
MIT License

Copyright (c) 2024-2026 The Trzsz SSH Authors.
*/

package tsshd

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// Tiny fake STUN server that replies to any Binding Request with a
// fixed XOR-MAPPED-ADDRESS attribute pointing at 203.0.113.42:54321.
func runFakeStunServer(t *testing.T) (string, int, func()) {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen fake stun: %v", err)
	}
	addr := conn.LocalAddr().(*net.UDPAddr)

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, peer, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n < 20 {
				continue
			}
			txid := append([]byte(nil), buf[8:20]...)

			pubIP := net.IPv4(203, 0, 113, 42).To4()
			pubPort := uint16(54321)
			xport := pubPort ^ uint16(kStunMagicCookie>>16)
			var mask [4]byte
			binary.BigEndian.PutUint32(mask[:], kStunMagicCookie)
			xaddr := make([]byte, 4)
			for i := 0; i < 4; i++ {
				xaddr[i] = pubIP[i] ^ mask[i]
			}

			attr := make([]byte, 4+8)
			binary.BigEndian.PutUint16(attr[0:2], kStunAttrXorMapped)
			binary.BigEndian.PutUint16(attr[2:4], 8)
			attr[4] = 0
			attr[5] = 0x01 // IPv4 family
			binary.BigEndian.PutUint16(attr[6:8], xport)
			copy(attr[8:12], xaddr)

			resp := make([]byte, 20+len(attr))
			binary.BigEndian.PutUint16(resp[0:2], kStunBindingResponse)
			binary.BigEndian.PutUint16(resp[2:4], uint16(len(attr)))
			binary.BigEndian.PutUint32(resp[4:8], kStunMagicCookie)
			copy(resp[8:20], txid)
			copy(resp[20:], attr)

			_, _ = conn.WriteToUDP(resp, peer)
		}
	}()

	return addr.IP.String(), addr.Port, func() {
		_ = conn.Close()
		<-done
	}
}

func TestStunDiscover_XorMappedAddress(t *testing.T) {
	host, port, stop := runFakeStunServer(t)
	defer stop()

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	defer client.Close()

	ip, p, err := StunDiscover(client, host, port)
	if err != nil {
		t.Fatalf("StunDiscover: %v", err)
	}
	if ip != "203.0.113.42" {
		t.Errorf("ip = %q, want 203.0.113.42", ip)
	}
	if p != 54321 {
		t.Errorf("port = %d, want 54321", p)
	}
}
