package ygg

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/yggdrasil-network/yggdrasil-go/src/address"
	ycfg "github.com/yggdrasil-network/yggdrasil-go/src/config"
)

// Set once for all tests, never restored: goroutines of a finished test may
// still read them. Local candidates only (no internet in tests), and a short
// handshake wait.
var liveSTUNServers = stunServers

func init() {
	stunServers = nil
	directLinkWait = time.Second
}

func TestSTUNResponseParsing(t *testing.T) {
	req, txid := stunRequest()
	if len(req) != stunHeaderLen || binary.BigEndian.Uint32(req[4:]) != stunMagic {
		t.Fatalf("bad request %x", req)
	}
	want := netip.MustParseAddrPort("203.0.113.7:40001")
	// XOR-MAPPED-ADDRESS, IPv4.
	v := []byte{0, 1, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(v[2:], want.Port()^uint16(stunMagic>>16))
	ip := want.Addr().As4()
	var cookie [4]byte
	binary.BigEndian.PutUint32(cookie[:], stunMagic)
	for i := range ip {
		v[4+i] = ip[i] ^ cookie[i]
	}
	resp := make([]byte, stunHeaderLen, 64)
	binary.BigEndian.PutUint16(resp, stunBindingSuccess)
	binary.BigEndian.PutUint32(resp[4:], stunMagic)
	copy(resp[8:], txid[:])
	// An unknown attribute with padding first, then the address.
	resp = append(resp, 0x80, 0x22, 0, 3, 'a', 'b', 'c', 0)
	resp = append(resp, 0, byte(stunXorMappedAddr), 0, byte(len(v)))
	resp = append(resp, v...)
	binary.BigEndian.PutUint16(resp[2:], uint16(len(resp)-stunHeaderLen))
	got, err := parseSTUNResponse(resp, txid)
	if err != nil || got != want {
		t.Fatalf("got %v, %v; want %v", got, err, want)
	}
	var other [12]byte
	if _, err := parseSTUNResponse(resp, other); err == nil {
		t.Fatal("a response to another transaction was accepted")
	}
	if _, err := parseSTUNResponse(resp[:30], txid); err == nil {
		t.Fatal("a truncated response was accepted")
	}
}

func TestDirectCandidates(t *testing.T) {
	public := []netip.AddrPort{netip.MustParseAddrPort("203.0.113.7:40001"), netip.MustParseAddrPort("203.0.113.7:40001")}
	local := []netip.Addr{
		netip.MustParseAddr("192.168.1.5"),
		netip.MustParseAddr("127.0.0.1"),
		netip.MustParseAddr("fe80::1"),
		netip.MustParseAddr("200:1234::1"), // Yggdrasil's own
		netip.MustParseAddr("2001:db8::5"),
	}
	got := directCandidates(public, local, 5000)
	want := []string{"203.0.113.7:40001", "192.168.1.5:5000", "[2001:db8::5]:5000"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	parsed := parseCandidates(append(got, "127.0.0.1:1", "junk", "[fe80::1]:2", "10.0.0.1:0"))
	if len(parsed) != 3 {
		t.Fatalf("parsed %v", parsed)
	}
}

func TestCheckDirectKey(t *testing.T) {
	cfg := ycfg.GenerateConfig()
	core, err := startCore(cfg, quietLogger{})
	if err != nil {
		t.Fatal(err)
	}
	defer core.Stop()
	key := core.PublicKey()
	ip := net.IP(address.AddrForKey(key)[:])
	hexKey := hex.EncodeToString(key)
	if _, err := checkDirectKey(hexKey, ip); err != nil {
		t.Fatalf("own key rejected: %v", err)
	}
	if _, err := checkDirectKey(hexKey, net.ParseIP("200::1")); err == nil {
		t.Fatal("a key for another address was accepted")
	}
	if _, err := checkDirectKey("zz", ip); err == nil {
		t.Fatal("a malformed key was accepted")
	}
}

// directChain starts a — relay — b: a and b reach each other only through
// the relay, both with a netstack and the direct service.
func directChain(t *testing.T) (a, b *Node) {
	t.Helper()
	mk := func() *Node {
		cfg := ycfg.GenerateConfig()
		core, err := startCore(cfg, quietLogger{})
		if err != nil {
			t.Fatalf("core: %v", err)
		}
		n := &Node{Core: core, Config: cfg}
		t.Cleanup(func() { _ = n.Close() })
		return n
	}
	relay := mk()
	ln, err := relay.Core.Listen(&url.URL{Scheme: "tcp", Host: "127.0.0.1:0"}, "")
	if err != nil {
		if isPermissionError(err) {
			t.Skipf("sandbox does not allow TCP listeners: %v", err)
		}
		t.Fatalf("listen: %v", err)
	}
	u, _ := url.Parse("tcp://" + ln.Addr().String())
	a, b = mk(), mk()
	for _, n := range []*Node{a, b} {
		if err := n.Core.AddPeer(u, ""); err != nil {
			t.Fatalf("add peer: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := n.WaitConnected(ctx, 20*time.Millisecond)
		cancel()
		if err != nil {
			t.Fatalf("peering: %v", err)
		}
		if _, err := n.StartNetstack(); err != nil {
			t.Fatalf("netstack: %v", err)
		}
		if err := n.startDirectService(); err != nil {
			t.Fatalf("direct service: %v", err)
		}
	}
	return a, b
}

func TestDirectLinkThroughLocalAddresses(t *testing.T) {
	if testing.Short() {
		t.Skip("starts three nodes")
	}
	hasLocal := false
	for _, a := range localAddrs() {
		if !a.IsLoopback() && !a.IsLinkLocalUnicast() && !in0200(net.IP(a.AsSlice())) {
			hasLocal = true
		}
	}
	if !hasLocal {
		t.Skip("no non-loopback address to punch through")
	}
	SetDirect(true)
	defer SetDirect(false)

	a, b := directChain(t)
	bIP := b.Core.Address()

	// A server on b, so traffic can be checked over the direct link.
	ln, err := b.ListenTCP(9000)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()

	// A session first, as in a call: the route is known.
	_ = dialRetry(t, a, b, 9000).Close()

	stop := a.StartDirect(bIP.String())
	direct := func() bool {
		for _, p := range a.Core.GetPeers() {
			if isUp(p) && isDirectLink(p.URI) && net.IP(address.AddrForKey(p.Key)[:]).Equal(bIP) {
				return true
			}
		}
		return false
	}
	if !waitFor(context.Background(), 20*time.Second, direct) {
		t.Fatalf("no direct link: peers %+v", a.Core.GetPeers())
	}
	// The link outlives the wait for its handshake: the initiator saw it up.
	time.Sleep(directLinkWait + 500*time.Millisecond)
	if !direct() {
		t.Fatal("the direct link went down after the handshake wait")
	}
	inbound := false
	for _, p := range b.Core.GetPeers() {
		if isUp(p) && p.Inbound && isDirectLink(p.URI) {
			inbound = true
		}
	}
	if !inbound {
		t.Fatal("b has no inbound direct link")
	}

	c, err := a.Net.DialTCP(bIP.String(), 9000, 5*time.Second)
	if err != nil {
		t.Fatalf("dial over the direct link: %v", err)
	}
	msg := []byte("over the direct link")
	_, _ = c.Write(msg)
	got := make([]byte, len(msg))
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil || string(got) != string(msg) {
		t.Fatalf("echo: %q, %v", got, err)
	}
	_ = c.Close()

	stop()
	gone := func() bool { return !direct() }
	if !waitFor(context.Background(), 10*time.Second, gone) {
		t.Fatal("the direct link outlived stop")
	}
}

func TestStartDirectIsNoOpWhenOff(t *testing.T) {
	SetDirect(false)
	n := &Node{}
	stop := n.StartDirect("200::1")
	stop() // must not panic or start anything
}

func TestDirectStopsWhenThePeerHasItOff(t *testing.T) {
	if testing.Short() {
		t.Skip("starts three nodes")
	}
	SetDirect(true)
	defer SetDirect(false)
	a, b := directChain(t)
	b.direct.close() // b answers with a refusal, as a node with it off
	ln, err := b.ListenTCP(9000)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	_ = dialRetry(t, a, b, 9000).Close()
	up, _, err := a.directOnce(context.Background(), b.Core.Address(), nil)
	if up || !errors.Is(err, errDirectOff) {
		t.Fatalf("directOnce = %v, %v; want errDirectOff", up, err)
	}
}

// TestSTUNLive asks the real STUN servers (YGG_LIVE=1: needs the internet).
func TestSTUNLive(t *testing.T) {
	if os.Getenv("YGG_LIVE") == "" {
		t.Skip("set YGG_LIVE=1 to ask the real STUN servers")
	}
	stunServers = liveSTUNServers
	sock, cands, err := openDirectSocket()
	if err != nil {
		t.Fatal(err)
	}
	defer sock.Close()
	t.Logf("candidates: %v", cands)
	ctx, cancel := context.WithTimeout(context.Background(), directSTUNWait)
	defer cancel()
	public := stunDiscover(ctx, sock)
	if len(public) == 0 {
		t.Fatal("no STUN server answered")
	}
	t.Logf("public: %v", public)
}

func TestDirectHealth(t *testing.T) {
	type tick struct {
		sent, lost uint64 // packets in this second
		rtt        time.Duration
	}
	run := func(route time.Duration, ticks []tick) (closedAt int, why string) {
		h := directHealth{routeRTT: route}
		var st quic.ConnectionStats
		for i, tk := range ticks {
			st.PacketsSent += tk.sent
			st.PacketsLost += tk.lost
			st.SmoothedRTT = tk.rtt
			if worse, w := h.check(st); worse {
				return i + 1, w
			}
		}
		return 0, ""
	}
	repeat := func(n int, tk tick) []tick {
		out := make([]tick, n)
		for i := range out {
			out[i] = tk
		}
		return out
	}
	good := tick{40, 0, 5 * time.Millisecond}
	if at, why := run(100*time.Millisecond, repeat(60, good)); at != 0 {
		t.Fatalf("a good link was closed at check %d: %s", at, why)
	}
	// 10% loss from the start: closed after directBadChecks bad checks, the
	// first ones once the window holds directMinPackets (the third second).
	if at, why := run(100*time.Millisecond, repeat(20, tick{40, 4, 5 * time.Millisecond})); at != directBadChecks+2 {
		t.Fatalf("lossy link closed at check %d (%s), want %d", at, why, directBadChecks+2)
	}
	// Loss among few packets (an idle link) is not judged.
	if at, _ := run(100*time.Millisecond, repeat(20, tick{5, 1, 5 * time.Millisecond})); at != 0 {
		t.Fatalf("an idle link was closed at check %d", at)
	}
	// Slower than the Yggdrasil route.
	if at, why := run(40*time.Millisecond, repeat(20, tick{40, 0, 120 * time.Millisecond})); at != directBadChecks {
		t.Fatalf("slow link closed at check %d (%s), want %d", at, why, directBadChecks)
	}
	// About as fast as the route: kept.
	if at, why := run(40*time.Millisecond, repeat(20, tick{40, 0, 55 * time.Millisecond})); at != 0 {
		t.Fatalf("a link as fast as the route was closed at check %d: %s", at, why)
	}
	// A bad spell shorter than directBadChecks does not close it.
	ticks := append(repeat(10, good), repeat(directBadChecks-1, tick{40, 0, time.Second})...)
	ticks = append(ticks, repeat(20, good)...)
	if at, why := run(40*time.Millisecond, ticks); at != 0 {
		t.Fatalf("a short bad spell closed the link at check %d: %s", at, why)
	}
}

// Of the candidates that connect, the shortest round trip wins (a VPN
// tunnel's address connects too, the long way round); a candidate that made
// a worse link is left out next time.
func TestDirectPicksTheShortestRoundTrip(t *testing.T) {
	ms := func(n int) time.Duration { return time.Duration(n) * time.Millisecond }
	if got := bestByRTT([]time.Duration{ms(376), ms(2), ms(40)}); got != 1 {
		t.Fatalf("bestByRTT = %d, want 1 (2 ms)", got)
	}
	if got := bestByRTT([]time.Duration{0, ms(50)}); got != 1 {
		t.Fatalf("bestByRTT = %d, want 1 (an unmeasured one counts as the longest)", got)
	}
	if got := bestByRTT([]time.Duration{0, 0}); got != 0 {
		t.Fatalf("bestByRTT = %d, want 0 (the first of equals)", got)
	}
	vpn := netip.MustParseAddrPort("10.230.4.27:58593")
	lan := netip.MustParseAddrPort("[fd36::1]:58593")
	left := leaveOut([]netip.AddrPort{vpn, lan}, map[netip.AddrPort]bool{vpn: true})
	if len(left) != 1 || left[0] != lan {
		t.Fatalf("leaveOut = %v, want [%v]", left, lan)
	}
}
