package ygg

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/yggdrasil-network/yggdrasil-go/src/address"
	ycore "github.com/yggdrasil-network/yggdrasil-go/src/core"
)

// Direct links.
//
// Two nodes in a session usually talk through public peers, often far away
// and loaded: hundreds of ms, at worst seconds, where the two could reach
// each other in tens. A direct link connects them as Yggdrasil peers over the
// internet, through their NATs (UDP hole punching); routing then prefers it
// by itself, since the destination is one hop away.
//
//  1. The initiator (StartDirect) opens a UDP socket and learns its public
//     address from STUN servers. It sends its candidates (public and local
//     addresses of that socket), its key and a random token to the peer's
//     direct service, over Yggdrasil (TCP, port directPort).
//  2. The peer does the same with a socket of its own, answers with its
//     candidates, listens for QUIC on that socket and sends small packets to
//     every initiator candidate, which opens its NAT towards them.
//  3. The initiator dials QUIC to every peer candidate. Of those that
//     connect within directPickWait of the first, the one with the shortest
//     round trip wins: a candidate can be a VPN tunnel's address, which
//     connects but goes the long way round, through the VPN.
//  4. The QUIC connection carries Yggdrasil links. The initiator adds a peer
//     at a local relay (tcp://127.0.0.1:port?key=<peer key>, so the core
//     checks it reached the right node); each connection to the relay opens a
//     QUIC stream, which starts with the token. The peer checks the token and
//     joins the stream to a local Yggdrasil listener.
//  5. The initiator keeps an eye on the link: one persistently worse than the
//     Yggdrasil route (see direct_health.go) is set aside, its traffic back
//     on the route, and takes it again once it is clearly the faster (with
//     an older peer, which cannot be measured that way, it is closed and the
//     next attempt leaves that candidate out).
//
// It is off by default (SetDirect): a direct link shows each side the other's
// public IP address, which Yggdrasil otherwise hides, and asks STUN servers
// for one's own. Both nodes must have it on. Where the NATs do not let it
// through (both map every destination to a different port, say), the
// session stays on its Yggdrasil route.

const (
	// directPort is the Yggdrasil TCP port of the direct service.
	directPort = 7701
	directALPN = "ygg-direct/1"
	// directTokenLen is the length of the token the initiator's streams
	// start with.
	directTokenLen = 32
	// directPunchEvery and directPunchFor: how often and how long the
	// responder sends packets to the initiator's candidates; the initiator
	// tries its QUIC dials for as long.
	directPunchEvery = 100 * time.Millisecond
	directPunchFor   = 10 * time.Second
	// directSTUNWait bounds the STUN query.
	directSTUNWait = 2 * time.Second
	// directControlWait bounds the exchange over Yggdrasil.
	directControlWait = 15 * time.Second
	// directRetry: an attempt that failed is repeated after this pause, at
	// most directAttempts times in all; a link that was up and broke is
	// tried again at once. A link that was worse than the route is left
	// out next time, and the next attempt comes after directDegradedRetry;
	// once every candidate was found worse, the attempts stop.
	directRetry         = 30 * time.Second
	directDegradedRetry = 10 * time.Second
	directAttempts      = 3
	// directPickWait: after the first candidate connects, how long the
	// others get to connect too, so the one with the shortest round trip
	// can be picked.
	directPickWait = 300 * time.Millisecond
	// directKeepAlive keeps the NAT mappings open; directIdle declares the
	// link dead without traffic.
	directKeepAlive = 5 * time.Second
	directIdle      = 20 * time.Second
	// directMaxCandidates bounds the candidate list taken from a peer.
	directMaxCandidates = 16
	// directVersion is the exchange's version (see directHello).
	directVersion = 2
)

// directLinkWait bounds the Yggdrasil handshake over a new QUIC link (a
// variable for tests).
var directLinkWait = 10 * time.Second

var directEnabled bool

// directLinks holds the URIs (as PeerInfo shows them) of the Yggdrasil links
// that run over direct links. The peer manager leaves them alone, as it does
// LAN links: they are never ranked, saved or removed, and do not count as
// links to the wider network.
var directLinks sync.Map

func isDirectLink(uri string) bool {
	_, ok := directLinks.Load(uri)
	return ok
}

// isUnmanaged reports whether the peer manager leaves the link alone.
func isUnmanaged(uri string) bool {
	return isLANPeer(uri) || isDirectLink(uri)
}

// SetDirect turns direct links on or off for nodes started by New after the
// call: with it on, the node answers StartDirect from other nodes, and
// StartDirect works. See the comment at the top of direct.go.
func SetDirect(enabled bool) {
	stateMu.Lock()
	directEnabled = enabled
	stateMu.Unlock()
}

func directSetting() bool {
	stateMu.RLock()
	defer stateMu.RUnlock()
	return directEnabled
}

func directLogf(format string, a ...any) {
	log.Printf("[ygg/direct] "+format, a...)
}

// directHello is what the two sides exchange over Yggdrasil, one JSON line
// each. V is the version: from 2, the responder answers pings on the
// exchange's connection for as long as the link lasts (see linkProbe).
type directHello struct {
	V     int      `json:"v"`
	Key   string   `json:"key"`             // the sender's public key, hex
	Token string   `json:"token,omitempty"` // initiator only, hex
	Cands []string `json:"cands,omitempty"` // UDP candidates, host:port
	Err   string   `json:"err,omitempty"`   // responder only: why not
}

// directService answers direct-link requests from other nodes.
type directService struct {
	node *Node
	ln   net.Listener // Yggdrasil TCP, directPort

	mu      sync.Mutex
	yggLink *ycore.Listener // local Yggdrasil listener the streams join
	closed  bool
	conns   map[*quic.Conn]struct{}
}

// startDirectService starts the service on a node whose netstack is up.
func (n *Node) startDirectService() error {
	ln, err := n.ListenTCP(directPort)
	if err != nil {
		return err
	}
	s := &directService{node: n, ln: ln, conns: map[*quic.Conn]struct{}{}}
	n.mu.Lock()
	n.direct = s
	n.mu.Unlock()
	go s.acceptLoop()
	return nil
}

func (s *directService) close() {
	s.mu.Lock()
	s.closed = true
	conns := s.conns
	s.conns = nil
	yl := s.yggLink
	s.yggLink = nil
	s.mu.Unlock()
	_ = s.ln.Close()
	for qc := range conns {
		_ = qc.CloseWithError(0, "closed")
	}
	if yl != nil {
		yl.Cancel()
	}
}

func (s *directService) acceptLoop() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.serve(c)
	}
}

// localYggAddr returns the address of the local Yggdrasil listener that the
// streams of direct links join, starting it the first time.
func (s *directService) localYggAddr() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return "", net.ErrClosed
	}
	if s.yggLink == nil {
		core := s.node.core()
		if core == nil {
			return "", net.ErrClosed
		}
		// ListenLocal: AllowedPublicKeys does not apply. Only this process
		// reaches it, with streams that carried the token.
		yl, err := core.ListenLocal(&url.URL{Scheme: "tcp", Host: "127.0.0.1:0"}, "")
		if err != nil {
			return "", err
		}
		s.yggLink = yl
	}
	return s.yggLink.Addr().String(), nil
}

// serve answers one request.
func (s *directService) serve(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(directControlWait))
	r := bufio.NewReaderSize(c, directHelloMax)
	var hello directHello
	if err := readDirectHello(r, &hello); err != nil {
		return
	}
	reply := func(h directHello) {
		h.V = directVersion
		h.Key = hex.EncodeToString(s.node.selfKey())
		_ = writeDirectHello(c, h)
	}
	key, err := checkDirectKey(hello.Key, remoteIP(c.RemoteAddr()))
	if err != nil {
		reply(directHello{Err: err.Error()})
		return
	}
	token, err := hex.DecodeString(hello.Token)
	if err != nil || len(token) != directTokenLen {
		reply(directHello{Err: "bad token"})
		return
	}
	peerCands := parseCandidates(hello.Cands)
	if len(peerCands) == 0 {
		reply(directHello{Err: "no candidates"})
		return
	}
	yggAddr, err := s.localYggAddr()
	if err != nil {
		reply(directHello{Err: "unavailable"})
		return
	}
	sock, cands, err := openDirectSocket()
	if err != nil {
		reply(directHello{Err: "no socket"})
		return
	}
	tr := &quic.Transport{Conn: sock}
	ql, err := tr.Listen(directTLS(true), directQUICConfig())
	if err != nil {
		_ = tr.Close()
		reply(directHello{Err: "no listener"})
		return
	}
	reply(directHello{Cands: cands})
	go directPinger(c, r) // the initiator measures the Yggdrasil route
	peer := net.IP(address.AddrForKey(key)[:]).String()
	directLogf("request from %s: %d candidates, ours %v", peer, len(peerCands), cands)

	// The initiator dials all our candidates at once, and several may come
	// through (all local addresses of one machine do); it keeps the first
	// that connects on its side and closes the rest, and which one that is
	// only it knows. So every connection is served while the dials last: the
	// kept one opens streams, the others are closed by the initiator.
	ctx, cancel := context.WithTimeout(context.Background(), directPunchFor+directLinkWait)
	punchCtx, stopPunch := context.WithCancel(ctx)
	go punch(punchCtx, tr, peerCands)
	var wg sync.WaitGroup
	accepted := 0
	for {
		qc, err := ql.Accept(ctx)
		if err != nil {
			break
		}
		stopPunch() // the NAT is open
		accepted++
		if !s.track(qc) {
			_ = qc.CloseWithError(0, "closed")
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer s.untrack(qc)
			s.serveConn(qc, token, yggAddr, peer)
		}()
	}
	stopPunch()
	cancel()
	_ = ql.Close() // accepted connections stay
	if accepted == 0 {
		directLogf("%s: no QUIC connection came through", peer)
	}
	wg.Wait()
	_ = tr.Close()
}

// serveConn joins the streams of one QUIC connection to the local Yggdrasil
// listener until the connection ends.
func (s *directService) serveConn(qc *quic.Conn, token []byte, yggAddr, peer string) {
	used := false
	for {
		st, err := qc.AcceptStream(qc.Context())
		if err != nil {
			if used {
				directLogf("%s: link closed: %v", peer, context.Cause(qc.Context()))
			}
			return
		}
		if !used {
			used = true
			directLogf("%s: QUIC up from %s", peer, qc.RemoteAddr())
		}
		go joinStream(st, token, yggAddr)
	}
}

func (s *directService) track(qc *quic.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.conns[qc] = struct{}{}
	return true
}

func (s *directService) untrack(qc *quic.Conn) {
	s.mu.Lock()
	delete(s.conns, qc)
	s.mu.Unlock()
}

// joinStream checks that a stream starts with the token and joins it to the
// local Yggdrasil listener.
func joinStream(st *quic.Stream, token []byte, yggAddr string) {
	_ = st.SetReadDeadline(time.Now().Add(directLinkWait))
	got := make([]byte, directTokenLen)
	if _, err := io.ReadFull(st, got); err != nil || subtle.ConstantTimeCompare(got, token) != 1 {
		st.CancelRead(0)
		st.CancelWrite(0)
		return
	}
	_ = st.SetReadDeadline(time.Time{})
	c, err := net.DialTimeout("tcp", yggAddr, directLinkWait)
	if err != nil {
		st.CancelRead(0)
		st.CancelWrite(0)
		return
	}
	// The listener names the link after its remote end: this socket.
	uri := "tcp://" + c.LocalAddr().String()
	directLinks.Store(uri, struct{}{})
	defer directLinks.Delete(uri)
	pipe(c, st)
}

// pipe copies both ways until either side ends, then closes both.
func pipe(c net.Conn, st *quic.Stream) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(c, st); done <- struct{}{} }()
	go func() { _, _ = io.Copy(st, c); done <- struct{}{} }()
	<-done
	_ = c.Close()
	st.CancelRead(0)
	_ = st.Close()
	<-done
}

// StartDirect tries to set up a direct link to the node at peerIPv6 (see
// the comment at the top of direct.go) and keeps it until stop is called.
// It returns at once; the attempt runs in the background, and its progress is
// logged. Both nodes need SetDirect(true); otherwise nothing happens.
func StartDirect(peerIPv6 string) (stop func()) {
	node := getDefaultNode()
	if node == nil {
		return func() {}
	}
	return node.StartDirect(peerIPv6)
}

// StartDirect is the package-level StartDirect for this node.
func (n *Node) StartDirect(peerIPv6 string) (stop func()) {
	ip := net.ParseIP(trimBrackets(peerIPv6))
	if ip == nil || !in0200(ip) || !directSetting() {
		return func() {}
	}
	ctx, cancel := context.WithCancel(context.Background())
	go n.keepDirect(ctx, ip)
	return cancel
}

// keepDirect makes direct links to ip until ctx ends: again after a link
// broke, after directRetry when an attempt failed and after
// directDegradedRetry when the link was worse than the Yggdrasil route (that
// candidate left out from then on), up to directAttempts failures in a row.
func (n *Node) keepDirect(ctx context.Context, ip net.IP) {
	peer := ip.String()
	wait := func(d time.Duration) bool {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(d):
			return true
		}
	}
	avoid := map[netip.AddrPort]bool{} // candidates found worse than the route
	for failures := 0; failures < directAttempts && ctx.Err() == nil; {
		up, via, err := n.directOnce(ctx, ip, avoid)
		switch {
		case ctx.Err() != nil:
			return
		case errors.Is(err, errDirectNotNeeded), errors.Is(err, errDirectOff), errors.Is(err, errDirectAllWorse):
			directLogf("%s: %v", peer, err)
			return
		case errors.Is(err, errDirectDegraded):
			failures++
			avoid[via] = true
			if failures >= directAttempts {
				directLogf("%s: %v; staying on the Yggdrasil route", peer, err)
				return
			}
			directLogf("%s: %v; back on the Yggdrasil route, trying the other candidates in %s", peer, err, directDegradedRetry)
			if !wait(directDegradedRetry) {
				return
			}
			continue
		case up:
			failures = 0
			directLogf("%s: link lost (%v), trying again", peer, err)
			continue
		}
		failures++
		directLogf("%s: attempt %d failed: %v", peer, failures, err)
		if failures < directAttempts && !wait(directRetry) {
			return
		}
	}
}

var (
	errDirectNotNeeded = errors.New("already a direct peer, nothing to do")
	errDirectOff       = errors.New("the peer has direct links off")
	errDirectDegraded  = errors.New("the direct link is worse than the Yggdrasil route")
	errDirectAllWorse  = errors.New("every candidate made a link worse than the Yggdrasil route; staying on it")
)

// directOnce makes one direct link and holds it until it breaks or ctx ends.
// up reports whether the link came up, via the candidate it went to. The
// candidates in avoid are left out.
func (n *Node) directOnce(ctx context.Context, ip net.IP, avoid map[netip.AddrPort]bool) (up bool, via netip.AddrPort, err error) {
	core := n.core()
	if core == nil {
		return false, via, net.ErrClosed
	}
	peer := ip.String()
	if hasUpPeerAt(core, ip) {
		return false, via, errDirectNotNeeded
	}
	sock, cands, err := openDirectSocket()
	if err != nil {
		return false, via, err
	}
	tr := &quic.Transport{Conn: sock}
	defer tr.Close()
	token := make([]byte, directTokenLen)
	_, _ = rand.Read(token)

	// The exchange over Yggdrasil.
	c, err := n.dialDirectService(ctx, peer)
	if err != nil {
		if !isTimeout(err) && !errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			return false, via, fmt.Errorf("%w (%v)", errDirectOff, err)
		}
		return false, via, fmt.Errorf("direct service: %w", err)
	}
	_ = c.SetDeadline(time.Now().Add(directControlWait))
	r := bufio.NewReaderSize(c, directHelloMax)
	err = writeDirectHello(c, directHello{V: directVersion, Key: hex.EncodeToString(n.selfKey()), Token: hex.EncodeToString(token), Cands: cands})
	var reply directHello
	if err == nil {
		err = readDirectHello(r, &reply)
	}
	if err != nil {
		_ = c.Close()
		return false, via, fmt.Errorf("direct service: %w", err)
	}
	// The Yggdrasil route's RTT, the yardstick for the direct link, is
	// measured while the QUIC dials run. Once the link is up, the pings on
	// the same connection take it, behind everything queued on it: they
	// measure the link as the traffic sees it (a responder from version 2
	// answers them as long as the link lasts).
	routeRTT := make(chan time.Duration, 1)
	go func() { routeRTT <- directPing(c, r) }()
	defer c.Close()
	if reply.Err != "" {
		return false, via, fmt.Errorf("refused: %s", reply.Err)
	}
	key, err := checkDirectKey(reply.Key, ip)
	if err != nil {
		return false, via, err
	}
	peerCands := parseCandidates(reply.Cands)
	if len(peerCands) == 0 {
		return false, via, fmt.Errorf("no candidates")
	}
	directLogf("%s: ours %v, theirs %v", peer, cands, reply.Cands)
	if peerCands = leaveOut(peerCands, avoid); len(peerCands) == 0 {
		return false, via, errDirectAllWorse
	}

	// QUIC to every candidate; of those through, the shortest round trip wins.
	qc, err := dialBest(ctx, tr, peerCands)
	if err != nil {
		return false, via, err
	}
	defer qc.CloseWithError(0, "done") // nolint:errcheck
	via = qc.RemoteAddr().(*net.UDPAddr).AddrPort()
	directLogf("%s: QUIC up to %s (RTT %s)", peer, via, qc.ConnectionStats().SmoothedRTT.Round(time.Millisecond))

	health := directHealth{routeRTT: <-routeRTT}
	var probe *linkProbe
	if reply.V >= directVersion {
		probe = &linkProbe{}
		probeCtx, stopProbe := context.WithCancel(ctx)
		defer stopProbe()
		go probe.run(probeCtx, c, r)
	}

	// The relay the core peers through.
	relay, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return false, via, err
	}
	defer relay.Close()
	go func() {
		for {
			lc, err := relay.Accept()
			if err != nil {
				return
			}
			go func() {
				st, err := qc.OpenStreamSync(qc.Context())
				if err == nil {
					_, err = st.Write(token)
				}
				if err != nil {
					_ = lc.Close()
					return
				}
				pipe(lc, st)
			}()
		}
	}()
	u := &url.URL{Scheme: "tcp", Host: relay.Addr().String(), RawQuery: "key=" + hex.EncodeToString(key)}
	uri := "tcp://" + u.Host // as PeerInfo shows it: without the query
	directLinks.Store(uri, struct{}{})
	defer directLinks.Delete(uri)
	// peering: the core peers over the link (it carries the traffic) or not
	// (parked, see directSwitch).
	peering := false
	setPeering := func(on bool) error {
		if on == peering {
			return nil
		}
		peering = on
		if !on {
			return core.RemovePeer(u, "")
		}
		if err := core.AddPeer(u, ""); err != nil {
			peering = false
			return err
		}
		core.RetryPeersNow()
		return nil
	}
	defer func() { _ = setPeering(false) }()
	linkUp := func() bool {
		for _, p := range core.GetPeers() {
			if p.URI == uri && isUp(p) {
				return true
			}
		}
		return false
	}
	if err := setPeering(true); err != nil {
		return false, via, err
	}
	if !waitFor(ctx, directLinkWait, linkUp) {
		return false, via, fmt.Errorf("yggdrasil handshake over the direct link timed out")
	}
	directLogf("%s: direct link up via %s (the Yggdrasil route: %s)", peer, qc.RemoteAddr(), health.routeRTT.Round(time.Millisecond))
	var sw directSwitch
	tick := time.NewTicker(directCheckEvery)
	defer tick.Stop()
	for checks := 1; ; checks++ {
		select {
		case <-ctx.Done():
			return true, via, ctx.Err()
		case <-qc.Context().Done():
			return true, via, context.Cause(qc.Context())
		case <-tick.C:
		}
		st := qc.ConnectionStats()
		now := time.Now()
		if !peering {
			// Parked: the pings take the route, QUIC measures the idle link.
			if !directBack(&sw, now, st.SmoothedRTT, probe.latency()) {
				continue
			}
			route := sw.routeRTT()
			if err := setPeering(true); err != nil {
				return true, via, err
			}
			if !waitFor(ctx, directLinkWait, linkUp) {
				return true, via, fmt.Errorf("yggdrasil handshake over the parked direct link timed out")
			}
			health = directHealth{routeRTT: route}
			directLogf("%s: traffic back on the direct link: RTT %s, the Yggdrasil route %s", peer,
				st.SmoothedRTT.Round(time.Millisecond), route.Round(time.Millisecond))
			continue
		}
		worse, why := directJudge(&health, st, probe.latency())
		if worse && probe == nil {
			// An older responder: the route cannot be measured while
			// parked (it stops answering pings), so the link is closed
			// and the next attempt leaves this candidate out.
			_ = qc.CloseWithError(0, "degraded")
			return true, via, fmt.Errorf("%w: %s", errDirectDegraded, why)
		}
		if worse {
			if err := setPeering(false); err != nil {
				return true, via, err
			}
			sw.park(now)
			directLogf("%s: the direct link is worse than the Yggdrasil route (%s): traffic back on the route, the link kept aside for at least %s",
				peer, why, sw.hold)
			continue
		}
		if checks%30 == 0 {
			directLogf("%s: link RTT %s (through its queue %s), %d of %d packets lost so far", peer,
				st.SmoothedRTT.Round(time.Millisecond), probe.latency().Round(time.Millisecond), st.PacketsLost, st.PacketsSent)
		}
	}
}

// dialDirectService dials the peer's direct service in short attempts:
// while the route is being looked up the first packets are lost, and a fresh
// SYN gets through sooner than a retransmitted one.
func (n *Node) dialDirectService(ctx context.Context, peer string) (net.Conn, error) {
	ns := n.netstack()
	if ns == nil {
		return nil, net.ErrClosed
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return ns.dialRetrying(peer, directPort, directControlWait, func() { n.RefreshRoute(peer) })
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// dialBest dials QUIC to all candidates at once. Of the connections that
// come up within directPickWait of the first, it returns the one with the
// shortest round trip (QUIC measures it in the handshake); the others are
// closed and the dials still going are cancelled. A candidate may be a VPN
// tunnel's address: it connects, but through the VPN, the long way round.
func dialBest(ctx context.Context, tr *quic.Transport, cands []netip.AddrPort) (*quic.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, directPunchFor)
	defer cancel()
	type result struct {
		qc  *quic.Conn
		err error
	}
	results := make(chan result, len(cands))
	for _, c := range cands {
		go func(addr *net.UDPAddr) {
			qc, err := tr.Dial(ctx, addr, directTLS(false), directQUICConfig())
			results <- result{qc, err}
		}(net.UDPAddrFromAddrPort(c))
	}
	var up []*quic.Conn
	var lastErr error
	var grace <-chan time.Time // runs from the first connection
	for left := len(cands); left > 0; {
		select {
		case r := <-results:
			left--
			if r.err != nil {
				lastErr = r.err
				continue
			}
			up = append(up, r.qc)
			if grace == nil {
				grace = time.After(directPickWait)
			}
		case <-grace:
			left = 0
		}
	}
	if len(up) == 0 {
		return nil, fmt.Errorf("no candidate reachable through the NATs (%v)", lastErr)
	}
	cancel() // the dials still going stop
	rtts := make([]time.Duration, len(up))
	for i, qc := range up {
		rtts[i] = qc.ConnectionStats().SmoothedRTT
	}
	best := bestByRTT(rtts)
	for i, qc := range up {
		if i != best {
			_ = qc.CloseWithError(0, "another path won")
		}
	}
	return up[best], nil
}

// bestByRTT is the index of the shortest round trip; one not measured (0)
// counts as the longest, and the first of equals wins.
func bestByRTT(rtts []time.Duration) int {
	best := 0
	for i, rtt := range rtts {
		if rtt > 0 && (rtts[best] <= 0 || rtt < rtts[best]) {
			best = i
		}
	}
	return best
}

// leaveOut returns the candidates not in avoid.
func leaveOut(cands []netip.AddrPort, avoid map[netip.AddrPort]bool) []netip.AddrPort {
	var out []netip.AddrPort
	for _, c := range cands {
		if !avoid[c] {
			out = append(out, c)
		}
	}
	return out
}

// punch sends small packets to every candidate until ctx ends: each opens
// this side's NAT for packets from that address. They start with two zero
// bits, so a QUIC stack that gets them sets them aside as not QUIC.
func punch(ctx context.Context, tr *quic.Transport, cands []netip.AddrPort) {
	msg := []byte("\x00ygg-direct")
	t := time.NewTicker(directPunchEvery)
	defer t.Stop()
	stop := time.Now().Add(directPunchFor)
	for time.Now().Before(stop) {
		for _, c := range cands {
			_, _ = tr.WriteTo(msg, net.UDPAddrFromAddrPort(c))
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// openDirectSocket opens the UDP socket of a direct link and returns it with
// its candidates: the public addresses STUN reports and the machine's own
// addresses, all with the socket's port.
func openDirectSocket() (*net.UDPConn, []string, error) {
	sock, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), directSTUNWait)
	public := stunDiscover(ctx, sock)
	cancel()
	port := uint16(sock.LocalAddr().(*net.UDPAddr).Port)
	return sock, directCandidates(public, localAddrs(), port), nil
}

// directCandidates lists the public addresses first, then the local ones
// with port; duplicates, unusable addresses and Yggdrasil's own are left out.
func directCandidates(public []netip.AddrPort, local []netip.Addr, port uint16) []string {
	var out []string
	seen := map[netip.AddrPort]bool{}
	add := func(ap netip.AddrPort) {
		a := ap.Addr()
		if seen[ap] || !a.IsValid() || a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() ||
			a.IsLinkLocalUnicast() || in0200(net.IP(a.AsSlice())) || len(out) >= directMaxCandidates {
			return
		}
		seen[ap] = true
		out = append(out, ap.String())
	}
	for _, ap := range public {
		add(ap)
	}
	for _, a := range local {
		add(netip.AddrPortFrom(a, port))
	}
	return out
}

func localAddrs() []netip.Addr {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(ipn.IP); ok {
				out = append(out, ip.Unmap())
			}
		}
	}
	return out
}

// parseCandidates parses a peer's candidates, dropping what cannot be a
// public or local address of another machine.
func parseCandidates(cands []string) []netip.AddrPort {
	var out []netip.AddrPort
	for _, s := range cands {
		if len(out) >= directMaxCandidates {
			break
		}
		ap, err := netip.ParseAddrPort(s)
		if err != nil || ap.Port() == 0 {
			continue
		}
		a := ap.Addr().Unmap()
		if a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a.IsLinkLocalUnicast() || in0200(net.IP(a.AsSlice())) {
			continue
		}
		out = append(out, netip.AddrPortFrom(a, ap.Port()))
	}
	return out
}

// checkDirectKey decodes a hex public key and checks that it is the key of
// the Yggdrasil address ip.
func checkDirectKey(s string, ip net.IP) (ed25519.PublicKey, error) {
	key, err := hex.DecodeString(s)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("bad key")
	}
	if ip == nil || !net.IP(address.AddrForKey(key)[:]).Equal(ip) {
		return nil, fmt.Errorf("key does not match the address")
	}
	return key, nil
}

// hasUpPeerAt reports whether the node at Yggdrasil address ip is already a
// peer: then it is one hop away and a direct link adds nothing.
func hasUpPeerAt(core peerCore, ip net.IP) bool {
	for _, p := range core.GetPeers() {
		if isUp(p) && net.IP(address.AddrForKey(p.Key)[:]).Equal(ip) {
			return true
		}
	}
	return false
}

func (n *Node) selfKey() ed25519.PublicKey {
	if core := n.core(); core != nil {
		return core.PublicKey()
	}
	return nil
}

func remoteIP(a net.Addr) net.IP {
	switch v := a.(type) {
	case *net.TCPAddr:
		return v.IP
	case *net.UDPAddr:
		return v.IP
	}
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return nil
	}
	return net.ParseIP(trimBrackets(host))
}

func trimBrackets(s string) string {
	if len(s) > 1 && s[0] == '[' && s[len(s)-1] == ']' {
		return s[1 : len(s)-1]
	}
	return s
}

func writeDirectHello(w io.Writer, h directHello) error {
	b, err := json.Marshal(h)
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// directHelloMax bounds a hello line.
const directHelloMax = 4096

func readDirectHello(r *bufio.Reader, h *directHello) error {
	line, err := r.ReadSlice('\n') // fails past the buffer: directHelloMax
	if err != nil {
		return err
	}
	return json.Unmarshal(line, h)
}

func directQUICConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout: directPunchFor,
		MaxIdleTimeout:       directIdle,
		KeepAlivePeriod:      directKeepAlive,
	}
}

var (
	directCertOnce sync.Once
	directCert     tls.Certificate
)

// directTLS returns the TLS configuration of the QUIC links. QUIC needs TLS,
// but nothing rests on it: the Yggdrasil links inside authenticate the nodes
// (the initiator pins the peer's key) and traffic is encrypted end to end
// anyway; the token keeps strangers from the responder's listener. So the
// certificate is a throwaway and is not checked.
func directTLS(server bool) *tls.Config {
	directCertOnce.Do(func() {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
		if err != nil {
			return
		}
		directCert = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
	})
	cfg := &tls.Config{NextProtos: []string{directALPN}, MinVersion: tls.VersionTLS13}
	if server {
		cfg.Certificates = []tls.Certificate{directCert}
	} else {
		cfg.InsecureSkipVerify = true // see above
		cfg.ServerName = "ygg-direct"
	}
	return cfg
}
