package ygg

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// Direct link health.
//
// Routing prefers a direct link whatever its quality: the destination is one
// hop away. A NAT or a provider that throttles UDP can leave the link up but
// worse than the Yggdrasil route it replaced: losses (which QUIC turns into
// delay spikes) or a longer round trip. So the initiator measures the
// Yggdrasil route before the link comes up (once it is up, everything to the
// peer takes it, pings too), watches the link's QUIC statistics, and closes
// the link when it is persistently worse: traffic goes back to the Yggdrasil
// route at once. The other candidates are tried soon after, that one left
// out (see keepDirect).
//
// QUIC's own round trip is not enough: the link is one reliable stream, and
// when the path carries less than is sent, the excess waits in the stream's
// send buffer, above QUIC. QUIC then still sees 150 ms while what is sent
// arrives seconds late (and is never lost, so nothing above notices). So
// the initiator also pings through the link (linkProbe): those pings queue
// behind the traffic as it does.

const (
	// directPings: round trips measured over Yggdrasil; the median is the
	// route's RTT. directPingWait bounds them; a route that does not answer
	// in time counts as that slow.
	directPings    = 3
	directPingWait = 3 * time.Second
	// directCheckEvery: how often the link is looked at; directCheckWindow:
	// how many checks the loss rate covers; directBadChecks: bad checks in a
	// row that close the link.
	directCheckEvery  = time.Second
	directCheckWindow = 5
	directBadChecks   = 5
	// directMaxLossPermille: more loss than this over the window is bad
	// (50: 5%), counted once at least directMinPackets were sent in it.
	directMaxLossPermille = 50
	directMinPackets      = 50
	// directProbeWait: how long the two sides of the exchange wait for a
	// ping or its answer before giving the connection up.
	directProbeWait = 30 * time.Second
	// The link's RTT is bad above the route's RTT by 25% plus
	// directRTTMargin: the two are measured differently (QUIC acks,
	// TCP over the netstack), and a tie should keep the direct link.
	directRTTMargin = 10 * time.Millisecond
)

// directPinger answers pings on the responder's side of the exchange: each
// byte read is written back, until the initiator closes the connection or
// sends nothing for directProbeWait.
func directPinger(c net.Conn, r *bufio.Reader) {
	defer c.Close()
	for {
		_ = c.SetDeadline(time.Now().Add(directProbeWait))
		b, err := r.ReadByte()
		if err != nil {
			return
		}
		if _, err := c.Write([]byte{b}); err != nil {
			return
		}
	}
}

// linkProbe pings the responder once a directCheckEvery over the exchange's
// connection, which runs over the direct link once it is up.
type linkProbe struct {
	mu   sync.Mutex
	last time.Duration // the last round trip
	out  time.Time     // when the ping now out was sent (zero: none)
}

func (p *linkProbe) run(ctx context.Context, c net.Conn, r *bufio.Reader) {
	buf := []byte{'p'}
	for {
		t0 := time.Now()
		p.mu.Lock()
		p.out = t0
		p.mu.Unlock()
		_ = c.SetDeadline(t0.Add(directProbeWait))
		_, err := c.Write(buf)
		if err == nil {
			_, err = io.ReadFull(r, buf)
		}
		p.mu.Lock()
		p.out = time.Time{}
		if err == nil {
			p.last = time.Since(t0)
		} else {
			p.last = 0 // unknown from now on
		}
		p.mu.Unlock()
		if err != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Until(t0.Add(directCheckEvery))):
		}
	}
}

// latency is the round trip through the link: the last one, or for how long
// the ping now out has gone unanswered if that is longer. 0: unknown.
func (p *linkProbe) latency() time.Duration {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	d := p.last
	if !p.out.IsZero() && p.last > 0 {
		d = max(d, time.Since(p.out))
	}
	return d
}

// directPing measures the round trip to the responder over the exchange's
// connection: the median of directPings pings, or directPingWait if they do
// not all come back within it.
func directPing(c net.Conn, r *bufio.Reader) time.Duration {
	deadline := time.Now().Add(directPingWait)
	_ = c.SetDeadline(deadline)
	var rtts []time.Duration
	buf := []byte{'p'}
	for range directPings {
		t0 := time.Now()
		if _, err := c.Write(buf); err != nil {
			break
		}
		if _, err := io.ReadFull(r, buf); err != nil {
			break
		}
		rtts = append(rtts, time.Since(t0))
	}
	if len(rtts) < directPings {
		return directPingWait
	}
	slices.Sort(rtts)
	return rtts[len(rtts)/2]
}

// directHealth decides from periodic QUIC statistics whether a direct link is
// worse than the Yggdrasil route.
type directHealth struct {
	routeRTT time.Duration
	sent     []uint64 // cumulative packets sent, one entry per check
	lost     []uint64
	bad      int // bad checks in a row
}

// check takes the link's statistics and the round trip through it (0:
// unknown) and reports whether the link should be closed, and why.
func (h *directHealth) check(st quic.ConnectionStats, through time.Duration) (worse bool, why string) {
	h.sent = append(h.sent, st.PacketsSent)
	h.lost = append(h.lost, st.PacketsLost)
	if len(h.sent) > directCheckWindow+1 {
		h.sent, h.lost = h.sent[1:], h.lost[1:]
	}
	sent := h.sent[len(h.sent)-1] - h.sent[0]
	lost := h.lost[len(h.lost)-1] - h.lost[0]
	limit := h.routeRTT + h.routeRTT/4 + directRTTMargin
	switch {
	case sent >= directMinPackets && lost*1000 > sent*directMaxLossPermille:
		why = fmt.Sprintf("%.1f%% loss", float64(lost)*100/float64(sent))
	case st.SmoothedRTT > limit:
		why = fmt.Sprintf("RTT %s, the Yggdrasil route had %s", st.SmoothedRTT.Round(time.Millisecond), h.routeRTT.Round(time.Millisecond))
	case through > limit:
		why = fmt.Sprintf("RTT %s through its queue (QUIC sees %s), the Yggdrasil route had %s", through.Round(time.Millisecond),
			st.SmoothedRTT.Round(time.Millisecond), h.routeRTT.Round(time.Millisecond))
	default:
		h.bad = 0
		return false, ""
	}
	h.bad++
	return h.bad >= directBadChecks, why
}
