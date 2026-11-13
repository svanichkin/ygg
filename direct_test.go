package ygg

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"sync/atomic"
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
			if worse, w := h.check(st, 0); worse {
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
	// QUIC sees a fast, lossless link while what is sent waits seconds in
	// its send buffer (an uplink that carries less than is sent): the round
	// trip through the link closes it.
	h := directHealth{routeRTT: 230 * time.Millisecond}
	var st quic.ConnectionStats
	for i := 1; i <= 20; i++ {
		st.PacketsSent += 40
		st.SmoothedRTT = 200 * time.Millisecond
		through := 200 * time.Millisecond
		if i > 5 {
			through = time.Duration(i-5) * time.Second
		}
		if worse, why := h.check(st, through); worse {
			if i != 5+directBadChecks {
				t.Fatalf("a link queueing seconds was closed at check %d (%s), want %d", i, why, 5+directBadChecks)
			}
			break
		} else if i == 20 {
			t.Fatal("a link queueing seconds was kept")
		}
	}
}

// The probe's round trip includes the queue ahead of it: a ping out for
// longer than the last round trip counts as that long already.
func TestLinkProbeSeesTheQueue(t *testing.T) {
	ini, resp := net.Pipe()
	defer ini.Close()
	hold := make(chan struct{})
	go func() {
		defer resp.Close()
		r := bufio.NewReader(resp)
		for {
			b, err := r.ReadByte()
			if err != nil {
				return
			}
			<-hold // the answer waits until let through
			if _, err := resp.Write([]byte{b}); err != nil {
				return
			}
		}
	}()
	p := &linkProbe{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.run(ctx, ini, bufio.NewReader(ini))
	hold <- struct{}{} // the first ping answered at once
	deadline := time.Now().Add(2 * time.Second)
	for p.latency() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if p.latency() == 0 {
		t.Fatal("no round trip measured")
	}
	// The next ping goes out after directCheckEvery and is held.
	time.Sleep(directCheckEvery + 600*time.Millisecond)
	if got := p.latency(); got < 500*time.Millisecond {
		t.Fatalf("a ping held 600 ms reads as %v", got)
	}
	close(hold)
}

// A responder that stops answering (the connection closed) leaves the
// round trip unknown, not slow.
func TestLinkProbeUnknownWhenClosed(t *testing.T) {
	ini, resp := net.Pipe()
	resp.Close()
	p := &linkProbe{}
	p.run(context.Background(), ini, bufio.NewReader(ini))
	if got := p.latency(); got != 0 {
		t.Fatalf("latency after the connection closed: %v, want 0 (unknown)", got)
	}
	var nilProbe *linkProbe
	if nilProbe.latency() != 0 {
		t.Fatal("no probe (an older responder) must read as unknown")
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

// A link found worse is set aside, its traffic on the Yggdrasil route, and
// takes the traffic again when it is the faster: the QUIC connection
// carries a new Yggdrasil link.
func TestDirectLinkParksAndComesBack(t *testing.T) {
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
	var worse, faster atomic.Bool
	judge, back := directJudge, directBack
	defer func() { directJudge, directBack = judge, back }()
	directJudge = func(h *directHealth, st quic.ConnectionStats, through time.Duration) (bool, string) {
		if worse.Load() {
			return true, "made worse by the test"
		}
		return judge(h, st, through)
	}
	directBack = func(s *directSwitch, now time.Time, link, route time.Duration) bool {
		back(s, now, link, route) // it measures the route
		return faster.Load()
	}

	a, b := directChain(t)
	bIP := b.Core.Address()
	ln, err := b.ListenTCP(9001)
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
	echo := func(what string) {
		t.Helper()
		c, err := a.Net.DialTCP(bIP.String(), 9001, 5*time.Second)
		if err != nil {
			t.Fatalf("%s: dial: %v", what, err)
		}
		defer c.Close()
		msg := []byte(what)
		_, _ = c.Write(msg)
		got := make([]byte, len(msg))
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(c, got); err != nil || string(got) != what {
			t.Fatalf("%s: echo %q, %v", what, got, err)
		}
	}
	_ = dialRetry(t, a, b, 9001).Close()

	stop := a.StartDirect(bIP.String())
	defer stop()
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
	echo("over the direct link")

	worse.Store(true)
	if !waitFor(context.Background(), 10*time.Second, func() bool { return !direct() }) {
		t.Fatal("the worse link still carries the traffic")
	}
	worse.Store(false)
	echo("over the Yggdrasil route while the link is parked")

	faster.Store(true)
	if !waitFor(context.Background(), 20*time.Second, direct) {
		t.Fatal("the parked link did not take the traffic back")
	}
	echo("over the direct link again")
}

// The switch: the route is measured while parked, the link must be clearly
// faster for directBadChecks checks and the hold must have passed; a link
// parked again soon after waits twice as long, one that did well for
// directHoldReset starts afresh.
func TestDirectSwitch(t *testing.T) {
	ms := func(n int) time.Duration { return time.Duration(n) * time.Millisecond }
	t0 := time.Unix(1000, 0)
	var s directSwitch
	s.park(t0)
	if s.hold != directHoldMin {
		t.Fatalf("first hold %v, want %v", s.hold, directHoldMin)
	}
	at := func(sec int) time.Time { return t0.Add(time.Duration(sec) * time.Second) }
	// Within the hold: not back, however fast the link.
	for i := 1; i < int(directHoldMin/time.Second); i++ {
		if s.back(at(i), ms(100), ms(400)) {
			t.Fatalf("back at %d s, within the hold", i)
		}
	}
	if !s.back(at(int(directHoldMin/time.Second)), ms(100), ms(400)) {
		t.Fatal("a clearly faster link was not taken back after the hold")
	}
	// Parked again 30 s later: the hold doubles.
	s.park(at(40))
	if s.hold != 2*directHoldMin {
		t.Fatalf("hold after a quick relapse %v, want %v", s.hold, 2*directHoldMin)
	}
	// Not clearly faster (within the margin): stays parked.
	for i := 41; i < 120; i++ {
		if s.back(at(i), ms(300), ms(360)) {
			t.Fatalf("back at %d s with the link barely faster", i)
		}
	}
	// A route that does not answer (0) is no reason to come back.
	var u directSwitch
	u.park(t0)
	for i := 1; i < 60; i++ {
		if u.back(at(i), ms(50), 0) {
			t.Fatal("back with the route unknown")
		}
	}
	// Doubling stops at directHoldMax; a long good spell resets it.
	var m directSwitch
	m.park(t0)
	for i := 0; i < 10; i++ {
		m.backAt = at(i * 10)
		m.park(at(i*10 + 1))
	}
	if m.hold != directHoldMax {
		t.Fatalf("hold %v, want the cap %v", m.hold, directHoldMax)
	}
	m.backAt = at(1000)
	m.park(at(1000).Add(directHoldReset))
	if m.hold != directHoldMin {
		t.Fatalf("hold after a long good spell %v, want %v", m.hold, directHoldMin)
	}
}
