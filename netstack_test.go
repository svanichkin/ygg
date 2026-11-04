package ygg

import (
	"context"
	"errors"
	"io"
	"net"
	"net/url"
	"testing"
	"time"

	ycfg "github.com/yggdrasil-network/yggdrasil-go/src/config"
)

// netstackPair starts two nodes peered over localhost, both with a netstack.
func netstackPair(tb testing.TB) (server, client *Node) {
	tb.Helper()
	mk := func() *Node {
		cfg := ycfg.GenerateConfig()
		core, err := startCore(cfg, quietLogger{})
		if err != nil {
			tb.Fatalf("core: %v", err)
		}
		n := &Node{Core: core, Config: cfg}
		tb.Cleanup(func() { _ = n.Close() })
		return n
	}
	server, client = mk(), mk()
	ln, err := server.Core.Listen(&url.URL{Scheme: "tcp", Host: "127.0.0.1:0"}, "")
	if err != nil {
		if isPermissionError(err) {
			tb.Skipf("sandbox does not allow TCP listeners: %v", err)
		}
		tb.Fatalf("listen: %v", err)
	}
	u, _ := url.Parse("tcp://" + ln.Addr().String())
	if err := client.Core.AddPeer(u, ""); err != nil {
		tb.Fatalf("add peer: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.WaitConnected(ctx, 20*time.Millisecond); err != nil {
		tb.Fatalf("peering: %v", err)
	}
	for _, n := range []*Node{server, client} {
		if _, err := n.StartNetstack(); err != nil {
			tb.Fatalf("netstack: %v", err)
		}
	}
	return server, client
}

// dialRetry dials until the route to the server is known (first packets may
// be dropped while the path is looked up).
func dialRetry(tb testing.TB, client, server *Node, port int) net.Conn {
	tb.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		c, err := client.Net.DialTCP(server.Core.Address().String(), port, 2*time.Second)
		if err == nil {
			return c
		}
		if time.Now().After(deadline) {
			tb.Fatalf("dial: %v", err)
		}
	}
}

func TestNetstackEcho(t *testing.T) {
	if testing.Short() {
		t.Skip("starts real Yggdrasil cores")
	}
	server, client := netstackPair(t)
	testTCPEcho(t, server, client)
	testUDPEcho(t, server, client, []int{100, 1200, 4000, 60000})
}

func testTCPEcho(t *testing.T, server, client *Node) {
	t.Helper()
	ln, err := server.ListenTCP(7000)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c)
	}()

	c := dialRetry(t, client, server, 7000)
	defer c.Close()
	msg := make([]byte, 200_000) // larger than any MTU, many segments
	for i := range msg {
		msg[i] = byte(i)
	}
	go func() { _, _ = c.Write(msg) }()
	got := make([]byte, len(msg))
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	for i := range got {
		if got[i] != msg[i] {
			t.Fatalf("echo differs at byte %d", i)
		}
	}
}

// BenchmarkNetstackTCP measures bulk TCP throughput between two nodes over
// the user-space netstack (go test -bench NetstackTCP -run x).
func BenchmarkNetstackTCP(b *testing.B) {
	server, client := netstackPair(b)
	ln, err := server.ListenTCP(7001)
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()
	done := make(chan int64, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- 0
			return
		}
		defer c.Close()
		n, _ := io.Copy(io.Discard, c)
		done <- n
	}()
	c := dialRetry(b, client, server, 7001)

	chunk := make([]byte, 64<<10)
	b.SetBytes(int64(len(chunk)))
	b.ResetTimer()
	for b.Loop() {
		if _, err := c.Write(chunk); err != nil {
			b.Fatalf("write: %v", err)
		}
	}
	_ = c.Close()
	<-done
}

// BenchmarkNetstackTCPRoundTrip measures small request/response latency.
func BenchmarkNetstackTCPRoundTrip(b *testing.B) {
	server, client := netstackPair(b)
	ln, err := server.ListenTCP(7002)
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c)
	}()
	c := dialRetry(b, client, server, 7002)
	defer c.Close()
	buf := make([]byte, 64)
	b.ResetTimer()
	for b.Loop() {
		if _, err := c.Write(buf); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(c, buf); err != nil {
			b.Fatal(err)
		}
	}
}

// testUDPEcho sends datagrams of the given sizes and expects them back.
func testUDPEcho(t *testing.T, server, client *Node, sizes []int) {
	t.Helper()
	spc, err := server.Net.ListenUDP(7003)
	if err != nil {
		t.Fatal(err)
	}
	defer spc.Close()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := spc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = spc.WriteTo(buf[:n], from)
		}
	}()
	cpc, _, err := client.Net.DialUDP(server.Core.Address().String(), 7003, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer cpc.Close()
	conn := cpc.(net.Conn)
	for _, size := range sizes {
		msg := make([]byte, size)
		for i := range msg {
			msg[i] = byte(i * 7)
		}
		got := make([]byte, 65535)
		ok := false
		for try := 0; try < 10 && !ok; try++ { // UDP: the first ones may be lost (path lookup, PMTU)
			_, _ = conn.Write(msg)
			_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, err := conn.Read(got)
			ok = err == nil && n == size && string(got[:n]) == string(msg)
		}
		if !ok {
			t.Errorf("UDP datagram of %d bytes did not come back", size)
		}
	}
}

func shortKeepalive(t *testing.T) {
	t.Helper()
	idle, interval, count := keepaliveIdle, keepaliveInterval, keepaliveCount
	keepaliveIdle, keepaliveInterval, keepaliveCount = time.Second, 500*time.Millisecond, 2
	t.Cleanup(func() { keepaliveIdle, keepaliveInterval, keepaliveCount = idle, interval, count })
}

// An idle TCP connection to a node that vanished without FIN/RST must be
// closed by keepalive on both the dialing and the accepting side.
func TestNetstackKeepaliveDetectsDeadPeer(t *testing.T) {
	if testing.Short() {
		t.Skip("starts real Yggdrasil cores")
	}
	for _, side := range []string{"dialer", "acceptor"} {
		t.Run(side, func(t *testing.T) {
			shortKeepalive(t)
			server, client := netstackPair(t)
			ln, err := server.ListenTCP(7010)
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			accepted := make(chan net.Conn, 1)
			go func() {
				if c, err := ln.Accept(); err == nil {
					accepted <- c
				}
			}()
			dialed := dialRetry(t, client, server, 7010)
			defer dialed.Close()
			var acc net.Conn
			select {
			case acc = <-accepted:
				defer acc.Close()
			case <-time.After(10 * time.Second):
				t.Fatal("accept timed out")
			}

			// The other node vanishes: its core and netstack stop, no FIN.
			survivor, gone := dialed, server
			if side == "acceptor" {
				survivor, gone = acc, client
			}
			_ = gone.Close()

			_ = survivor.SetReadDeadline(time.Now().Add(15 * time.Second))
			start := time.Now()
			_, err = survivor.Read(make([]byte, 1))
			var ne net.Error
			if err == nil || (errors.As(err, &ne) && ne.Timeout()) {
				t.Fatalf("Read = %v after %s, want a connection error from keepalive", err, time.Since(start))
			}
			t.Logf("dead peer detected in %s: %v", time.Since(start).Round(100*time.Millisecond), err)
		})
	}
}

func TestNetstackListenerCloseUnblocksAccept(t *testing.T) {
	if testing.Short() {
		t.Skip("starts real Yggdrasil cores")
	}
	server, _ := netstackPair(t)
	ln, err := server.ListenTCP(7011)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := ln.Accept()
		done <- err
	}()
	time.Sleep(100 * time.Millisecond)
	_ = ln.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Accept returned a connection after Close")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Accept still blocked after Close")
	}
}
