package ygg

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	ycore "github.com/yggdrasil-network/yggdrasil-go/src/core"
)

// Peer selection.
//
// A peer counts as alive only when the Yggdrasil handshake with it has
// completed and the router has measured its RTT (a signed request/response
// over the established link). A plain TCP connect is not enough: DPI boxes
// can answer SYN with a forged SYN-ACK, so dead ports look open, and the
// forged answer comes from nearby, so these fake peers look the fastest.
//
// Candidates are checked in batches on a separate, short-lived probe core,
// so the live node is not disturbed. The best ones by RTT (at most
// maxPeersPerHost per host) are applied to the live core and saved to the
// config; everything else is removed.

// Tunables. Variables rather than constants so tests can shorten them.
var (
	defaultMaxPeers = 8                      // how many best peers to keep
	maxPeersPerHost = 1                      // links to one host (tcp/tls/quic of one machine)
	minKeepPeers    = 3                      // kept even if slower than the cut-off
	slowPeerFactor  = 4                      // drop peers slower than best*factor...
	slowPeerFloor   = 100 * time.Millisecond // ...but never cut below this RTT

	probeBatchSize = 60               // candidates checked at once
	probeSettle    = 20 * time.Second // max wait per batch
	pollInterval   = 500 * time.Millisecond

	startBatchWait = 10 * time.Second // per batch while waiting for the first peer
	savedPeersWait = 15 * time.Second // saved peers at start, before the public list
	startTimeout   = 60 * time.Second // public list at start (and StartAndConnect)

	pruneDelay       = 20 * time.Second // after start: drop start-up links that lost
	reselectInterval = 6 * time.Hour    // full re-check of all candidates
	reselectMinGap   = 5 * time.Minute  // never re-check more often than this
	healthInterval   = time.Minute
	applyWait        = 30 * time.Second // wait for a selected peer before removing others
)

// peerCore is the part of *ycore.Core used for peer management.
type peerCore interface {
	AddPeer(u *url.URL, sintf string) error
	RemovePeer(u *url.URL, sintf string) error
	GetPeers() []ycore.PeerInfo
	RetryPeersNow()
}

// peerSet remembers the full URIs (with ?key=...) of peers added to a core.
// The core reports peers without the query part.
type peerSet struct {
	mu   sync.Mutex
	full map[string]string // linkKey -> full URI
}

func (s *peerSet) remember(raw string) {
	s.mu.Lock()
	if s.full == nil {
		s.full = map[string]string{}
	}
	s.full[linkKey(raw)] = raw
	s.mu.Unlock()
}

func (s *peerSet) lookup(key string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if full, ok := s.full[key]; ok {
		return full
	}
	return key
}

func (s *peerSet) forget(key string) {
	s.mu.Lock()
	delete(s.full, key)
	s.mu.Unlock()
}

// linkKey normalises a peer URI the same way the core keys its links: the
// query (key=, priority=, ...) is dropped.
func linkKey(raw string) string {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.RawQuery = ""
	return u.String()
}

func peerHost(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" {
		return linkKey(raw)
	}
	return strings.ToLower(u.Hostname())
}

// isUp reports whether the link has completed the Yggdrasil handshake.
// PeerInfo.Up alone is set as soon as the socket is open, before the
// handshake, so a forged SYN-ACK would already count as "up".
func isUp(p ycore.PeerInfo) bool {
	return p.Up && len(p.Key) > 0
}

// measured returns outbound peers that are up and have a measured RTT.
// LAN links are left out: they are not managed by the peer manager.
func measured(core peerCore) map[string]time.Duration {
	out := map[string]time.Duration{}
	for _, p := range core.GetPeers() {
		if isUp(p) && !p.Inbound && !isLANPeer(p.URI) && p.Latency > 0 {
			out[p.URI] = p.Latency
		}
	}
	return out
}

func countUp(core peerCore) int {
	n := 0
	for _, p := range core.GetPeers() {
		if isUp(p) {
			n++
		}
	}
	return n
}

// countUpRemote counts up peers except LAN links: the health of the
// connection to the wider network.
func countUpRemote(core peerCore) int {
	n := 0
	for _, p := range core.GetPeers() {
		if isUp(p) && !isLANPeer(p.URI) {
			n++
		}
	}
	return n
}

func countOutbound(core peerCore) int {
	n := 0
	for _, p := range core.GetPeers() {
		if !p.Inbound && !isLANPeer(p.URI) {
			n++
		}
	}
	return n
}

// uniqPeers drops blanks and duplicates (by link key), keeping the first.
func uniqPeers(lists ...[]string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, list := range lists {
		for _, p := range list {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			k := linkKey(p)
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, p)
		}
	}
	return out
}

// addPeers adds peers to the core, remembering their full URIs. Peers the core
// rejects (bad URI, unknown scheme) are skipped. Returns the link keys of the
// peers that are now configured.
func addPeers(core peerCore, set *peerSet, peers []string) []string {
	var keys []string
	for _, p := range peers {
		u, err := url.Parse(strings.TrimSpace(p))
		if err != nil {
			continue
		}
		if err := core.AddPeer(u, ""); err != nil && !errors.Is(err, ycore.ErrLinkAlreadyConfigured) {
			logV("peers: skip %s: %v", p, err)
			continue
		}
		set.remember(p)
		keys = append(keys, linkKey(p))
	}
	return keys
}

func removePeer(core peerCore, set *peerSet, key string) {
	if u, err := url.Parse(key); err == nil {
		_ = core.RemovePeer(u, "")
	}
	set.forget(key)
}

// connectFirst adds peers batch by batch until at least one completes the
// handshake. Peers of earlier batches stay configured and keep trying.
func connectFirst(ctx context.Context, core peerCore, set *peerSet, peers []string) error {
	peers = uniqPeers(peers)
	if len(peers) == 0 {
		return fmt.Errorf("no peers to connect to")
	}
	for start := 0; start < len(peers); start += probeBatchSize {
		end := min(start+probeBatchSize, len(peers))
		added := addPeers(core, set, peers[start:end])
		logV("connect: batch %d-%d of %d, added %d", start+1, end, len(peers), len(added))
		core.RetryPeersNow()
		if waitFor(ctx, startBatchWait, func() bool { return countUp(core) > 0 }) {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	// Everything is configured now; give slow peers the rest of the time.
	if waitFor(ctx, startTimeout, func() bool { return countUp(core) > 0 }) {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return fmt.Errorf("no peer completed the handshake")
}

// connectStart connects a starting node: saved peers first (after the first
// run these are the best verified ones), then, if none is up within
// savedPeersWait, the public list from fetch. Each phase has its own time
// budget, so slow saved peers cannot use up the public list's time. The saved
// peers stay configured and keep trying during the second phase.
func connectStart(core peerCore, set *peerSet, saved []string, fetch func() []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), savedPeersWait)
	err := connectFirst(ctx, core, set, saved)
	cancel()
	if err == nil {
		return nil
	}
	logV("peers: saved peers failed (%v), fetching %s", err, publicPeersURL)
	fresh := fetch()
	if len(fresh) == 0 {
		return fmt.Errorf("saved peers: %w (public peer list unavailable)", err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), startTimeout)
	defer cancel()
	if err := connectFirst(ctx, core, set, fresh); err != nil {
		return fmt.Errorf("public peers: %w", err)
	}
	return nil
}

// waitFor polls cond until it is true, d elapses or ctx is done.
func waitFor(ctx context.Context, d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for {
		if cond() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		if sleepContext(ctx, pollInterval) != nil {
			return false
		}
	}
}

// newProbeCore starts a throw-away core with a fresh key and no listeners.
func newProbeCore() (*ycore.Core, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	cert, err := certFromPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return ycore.New(cert, quietLogger{})
}

// probePeers checks candidates on a separate core and returns the measured RTT
// of every peer that completed the handshake, keyed by full URI.
func probePeers(ctx context.Context, candidates []string) (map[string]time.Duration, error) {
	core, err := newProbeCore()
	if err != nil {
		return nil, fmt.Errorf("probe core: %w", err)
	}
	defer core.Stop()
	return probeOn(ctx, core, candidates), ctx.Err()
}

func probeOn(ctx context.Context, core peerCore, candidates []string) map[string]time.Duration {
	candidates = uniqPeers(candidates)
	results := map[string]time.Duration{}
	set := &peerSet{}
	for start := 0; start < len(candidates) && ctx.Err() == nil; start += probeBatchSize {
		end := min(start+probeBatchSize, len(candidates))
		keys := addPeers(core, set, candidates[start:end])
		core.RetryPeersNow()

		// A batch is done early when every peer is either measured or failed.
		waitFor(ctx, probeSettle, func() bool { return batchSettled(core, keys) })

		for key, rtt := range measured(core) {
			results[set.lookup(key)] = rtt
		}
		for _, key := range keys {
			removePeer(core, set, key)
		}
		logV("probe: batch %d-%d of %d, alive so far %d", start+1, end, len(candidates), len(results))
	}
	return results
}

func batchSettled(core peerCore, keys []string) bool {
	state := map[string]ycore.PeerInfo{}
	for _, p := range core.GetPeers() {
		state[p.URI] = p
	}
	for _, k := range keys {
		p, ok := state[k]
		if !ok {
			continue
		}
		ready := isUp(p) && p.Latency > 0
		failed := !p.Up && p.LastError != nil
		if !ready && !failed {
			return false
		}
	}
	return true
}

// rankPeers orders measured peers by RTT, keeps at most maxPeersPerHost per
// host, drops peers far slower than the best (keeping at least minKeepPeers)
// and returns at most limit peers (limit <= 0: no limit).
func rankPeers(results map[string]time.Duration, limit int) []string {
	type entry struct {
		uri string
		rtt time.Duration
	}
	list := make([]entry, 0, len(results))
	for uri, rtt := range results {
		list = append(list, entry{uri, rtt})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].rtt != list[j].rtt {
			return list[i].rtt < list[j].rtt
		}
		return list[i].uri < list[j].uri
	})

	var out []string
	perHost := map[string]int{}
	var cutoff time.Duration
	for _, e := range list {
		if limit > 0 && len(out) >= limit {
			break
		}
		h := peerHost(e.uri)
		if perHost[h] >= maxPeersPerHost {
			continue
		}
		if len(out) == 0 {
			cutoff = max(e.rtt*time.Duration(slowPeerFactor), slowPeerFloor)
		} else if len(out) >= minKeepPeers && e.rtt > cutoff {
			break // sorted, so everything after is slower too
		}
		perHost[h]++
		out = append(out, e.uri)
	}
	return out
}

// applySelection makes the core peer with exactly the selected peers. Others
// are removed only after at least one selected peer is up, so a bad selection
// never leaves the node disconnected.
func applySelection(ctx context.Context, core peerCore, set *peerSet, selected []string) error {
	keys := addPeers(core, set, selected)
	if len(keys) == 0 {
		return fmt.Errorf("no selected peer could be added")
	}
	want := map[string]struct{}{}
	for _, k := range keys {
		want[k] = struct{}{}
	}
	core.RetryPeersNow()
	ok := waitFor(ctx, applyWait, func() bool {
		for _, p := range core.GetPeers() {
			if _, sel := want[p.URI]; sel && isUp(p) {
				return true
			}
		}
		return false
	})
	if !ok {
		return fmt.Errorf("none of the selected peers came up")
	}
	removed := 0
	for _, p := range core.GetPeers() {
		if p.Inbound || isLANPeer(p.URI) {
			continue
		}
		if _, sel := want[p.URI]; !sel {
			removePeer(core, set, p.URI)
			removed++
		}
	}
	logV("peers: applied %d, removed %d", len(keys), removed)
	return nil
}

// fetchCandidates returns the public peer list, or nil if it cannot be fetched.
func fetchCandidates(timeout time.Duration) []string {
	peers, err := fetchPeersFromURL(timeout)
	if err != nil {
		logV("peers: fetch %s failed: %v", publicPeersURL, err)
		return nil
	}
	return peers
}

// cfgMu serialises config rewrites from the peer manager.
var cfgMu sync.Mutex

// savePeers replaces the peer list in the config on disk, keeping every other
// field as it is on disk now. full marks a complete re-check.
func savePeers(path string, peers []string, full bool) error {
	cfgMu.Lock()
	defer cfgMu.Unlock()
	c, err := LoadOrInitAppConfig(path)
	if err != nil {
		return err
	}
	c.Peers = append([]string(nil), peers...)
	if full {
		c.PeersCheckedAt = time.Now().UTC().Truncate(time.Second)
	}
	return SaveJSON(path, c)
}

// runPeerManager keeps the live core on the best peers: right after start it
// drops start-up links that lost, then periodically (and when the node loses
// its peers) re-checks all candidates on a probe core.
func (n *Node) runPeerManager(ctx context.Context, cfgPath string, lastFull time.Time) {
	core := n.core()
	if core == nil {
		return
	}

	// 1. Cheap pass after a cold start (or with an old, oversized config):
	// keep the best of what the live core has already measured. A normal
	// start with the saved peers is left alone, so a short outage at start
	// cannot shrink the saved list.
	if sleepContext(ctx, pruneDelay) != nil {
		return
	}
	if limit := configuredMaxPeers(); limit > 0 && countOutbound(core) > limit {
		if sel := n.rankLive(core); len(sel) > 0 {
			if err := applySelection(ctx, core, &n.peers, sel); err != nil {
				logV("peers: prune: %v", err)
			} else if err := savePeers(cfgPath, sel, false); err != nil {
				logV("peers: save: %v", err)
			}
		}
	}

	// 2. Full re-check now if the last one is old, then on schedule/health.
	var lastTry time.Time
	weak := 0
	tick := time.NewTicker(healthInterval)
	defer tick.Stop()
	for {
		due := time.Since(lastFull) >= reselectInterval || weak >= 2
		if due && time.Since(lastTry) >= reselectMinGap {
			lastTry = time.Now()
			weak = 0
			if err := n.reselect(ctx, core, cfgPath); err != nil {
				logV("peers: re-check: %v", err)
			} else {
				lastFull = time.Now()
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		if countUpRemote(core) < healthyPeers() {
			weak++
		} else {
			weak = 0
		}
	}
}

func healthyPeers() int {
	if limit := configuredMaxPeers(); limit > 0 && limit < 2 {
		return limit
	}
	return 2
}

func (n *Node) rankLive(core peerCore) []string {
	live := map[string]time.Duration{}
	for key, rtt := range measured(core) {
		live[n.peers.lookup(key)] = rtt
	}
	return rankPeers(live, configuredMaxPeers())
}

func (n *Node) reselect(ctx context.Context, core peerCore, cfgPath string) error {
	saved, err := LoadOrInitAppConfig(cfgPath)
	if err != nil {
		return err
	}
	candidates := uniqPeers(saved.Peers, fetchCandidates(10*time.Second))
	if len(candidates) == 0 {
		return fmt.Errorf("no candidates")
	}
	logV("peers: re-check of %d candidates", len(candidates))
	results, err := probePeers(ctx, candidates)
	if err != nil {
		return err
	}
	sel := rankPeers(results, configuredMaxPeers())
	if len(sel) == 0 {
		return fmt.Errorf("no candidate completed the handshake")
	}
	for _, p := range sel {
		logV("peers: selected %8s %s", results[p].Round(time.Millisecond/10), p)
	}
	if err := applySelection(ctx, core, &n.peers, sel); err != nil {
		return err
	}
	return savePeers(cfgPath, sel, true)
}
