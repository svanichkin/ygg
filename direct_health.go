package ygg

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"slices"
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
	// The link's RTT is bad above the route's RTT by 25% plus
	// directRTTMargin: the two are measured differently (QUIC acks,
	// TCP over the netstack), and a tie should keep the direct link.
	directRTTMargin = 10 * time.Millisecond
)

// directPinger answers pings on the responder's side of the exchange: each
// byte read is written back, until the initiator closes the connection or the
// deadline set on it passes.
func directPinger(c net.Conn, r *bufio.Reader) {
	defer c.Close()
	for {
		b, err := r.ReadByte()
		if err != nil {
			return
		}
		if _, err := c.Write([]byte{b}); err != nil {
			return
		}
	}
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

// check takes the link's statistics and reports whether the link should be
// closed, and why.
func (h *directHealth) check(st quic.ConnectionStats) (worse bool, why string) {
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
	default:
		h.bad = 0
		return false, ""
	}
	h.bad++
	return h.bad >= directBadChecks, why
}
