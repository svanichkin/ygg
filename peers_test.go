package ygg

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/url"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	ycore "github.com/yggdrasil-network/yggdrasil-go/src/core"
)

// fakeCore simulates link states. Peers listed in rtt complete the handshake
// as soon as they are added; peers in fail get a connection error; anything
// else hangs (like a forged SYN-ACK: socket open, no handshake).
type fakeCore struct {
	mu    sync.Mutex
	rtt   map[string]time.Duration // link key -> RTT
	fail  map[string]bool
	links map[string]bool // configured link keys
}

func newFakeCore(rtt map[string]time.Duration, fail ...string) *fakeCore {
	f := &fakeCore{rtt: rtt, fail: map[string]bool{}, links: map[string]bool{}}
	for _, k := range fail {
		f.fail[k] = true
	}
	return f
}

func (f *fakeCore) AddPeer(u *url.URL, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := linkKey(u.String())
	if f.links[k] {
		return ycore.ErrLinkAlreadyConfigured
	}
	f.links[k] = true
	return nil
}

func (f *fakeCore) RemovePeer(u *url.URL, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.links, linkKey(u.String()))
	return nil
}

func (f *fakeCore) GetPeers() []ycore.PeerInfo {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []ycore.PeerInfo
	for k := range f.links {
		p := ycore.PeerInfo{URI: k}
		switch {
		case f.rtt[k] > 0:
			p.Up, p.Key, p.Latency = true, ed25519.PublicKey(make([]byte, 32)), f.rtt[k]
		case f.fail[k]:
			p.LastError = errors.New("connection refused")
		default:
			p.Up = true // socket open, handshake never completes
		}
		out = append(out, p)
	}
	return out
}

func (f *fakeCore) RetryPeersNow() {}

func (f *fakeCore) configured() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for k := range f.links {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func shortTimings(t *testing.T) {
	t.Helper()
	old := []time.Duration{probeSettle, pollInterval, startBatchWait, startTimeout, applyWait}
	oldBatch := probeBatchSize
	probeSettle, pollInterval, startBatchWait, startTimeout, applyWait = 300*time.Millisecond, 10*time.Millisecond, 200*time.Millisecond, 300*time.Millisecond, 200*time.Millisecond
	probeBatchSize = 2
	t.Cleanup(func() {
		probeSettle, pollInterval, startBatchWait, startTimeout, applyWait = old[0], old[1], old[2], old[3], old[4]
		probeBatchSize = oldBatch
	})
}

func TestLinkKeyDropsQuery(t *testing.T) {
	got := linkKey(" tls://h.example:443?key=abc&priority=1 ")
	if got != "tls://h.example:443" {
		t.Fatalf("linkKey = %q", got)
	}
}

func TestRankPeersSortsAndLimitsPerHost(t *testing.T) {
	got := rankPeers(map[string]time.Duration{
		"tls://a.example:1":         30 * time.Millisecond,
		"tcp://a.example:2":         10 * time.Millisecond, // same host, faster
		"quic://b.example:3?key=00": 20 * time.Millisecond,
		"tcp://c.example:4":         40 * time.Millisecond,
	}, 2)
	want := []string{"tcp://a.example:2", "quic://b.example:3?key=00"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rankPeers = %v, want %v", got, want)
	}
}

func TestRankPeersDropsSlowButKeepsMinimum(t *testing.T) {
	got := rankPeers(map[string]time.Duration{
		"tcp://a:1": 10 * time.Millisecond,
		"tcp://b:1": 300 * time.Millisecond,
		"tcp://c:1": 400 * time.Millisecond, // kept: still within minKeepPeers
		"tcp://d:1": 500 * time.Millisecond, // dropped: > max(4*10ms, 100ms)
		"tcp://e:1": 600 * time.Millisecond,
	}, 8)
	want := []string{"tcp://a:1", "tcp://b:1", "tcp://c:1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rankPeers = %v, want %v", got, want)
	}

	if got := rankPeers(nil, 8); len(got) != 0 {
		t.Fatalf("rankPeers(nil) = %v", got)
	}
}

func TestProbeOnKeepsOnlyHandshakedPeers(t *testing.T) {
	shortTimings(t)
	core := newFakeCore(map[string]time.Duration{
		"tls://good.example:1": 15 * time.Millisecond,
		"tcp://fast.example:2": 5 * time.Millisecond,
	}, "tcp://dead.example:3")

	got := probeOn(context.Background(), core, []string{
		"tls://good.example:1?key=aa",
		"tcp://dead.example:3",
		"tcp://fake.example:4", // forged SYN-ACK: open socket, no handshake
		"tcp://fast.example:2",
		"tls://good.example:1?key=bb", // duplicate link
	})
	want := map[string]time.Duration{
		"tls://good.example:1?key=aa": 15 * time.Millisecond,
		"tcp://fast.example:2":        5 * time.Millisecond,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("probeOn = %v, want %v", got, want)
	}
	if left := core.configured(); len(left) != 0 {
		t.Fatalf("probe left peers configured: %v", left)
	}
}

func TestConnectFirstStopsAtFirstWorkingBatch(t *testing.T) {
	shortTimings(t)
	core := newFakeCore(map[string]time.Duration{"tcp://c:1": time.Millisecond})
	set := &peerSet{}
	peers := []string{"tcp://a:1", "tcp://b:1", "tcp://c:1", "tcp://d:1", "tcp://e:1", "tcp://f:1"}

	if err := connectFirst(context.Background(), core, set, peers); err != nil {
		t.Fatalf("connectFirst: %v", err)
	}
	want := []string{"tcp://a:1", "tcp://b:1", "tcp://c:1", "tcp://d:1"}
	if got := core.configured(); !reflect.DeepEqual(got, want) {
		t.Fatalf("configured = %v, want %v (third batch must not be added)", got, want)
	}
}

func TestConnectFirstFailsWithoutHandshake(t *testing.T) {
	shortTimings(t)
	core := newFakeCore(nil, "tcp://a:1")
	err := connectFirst(context.Background(), core, &peerSet{}, []string{"tcp://a:1", "tcp://fake:1"})
	if err == nil {
		t.Fatal("connectFirst should fail when no peer completes the handshake")
	}
}

func TestApplySelectionReplacesPeers(t *testing.T) {
	shortTimings(t)
	core := newFakeCore(map[string]time.Duration{
		"tcp://old:1": time.Millisecond,
		"tcp://new:1": time.Millisecond,
	})
	set := &peerSet{}
	addPeers(core, set, []string{"tcp://old:1", "tcp://other:1"})

	if err := applySelection(context.Background(), core, set, []string{"tcp://new:1?key=00"}); err != nil {
		t.Fatalf("applySelection: %v", err)
	}
	if got := core.configured(); !reflect.DeepEqual(got, []string{"tcp://new:1"}) {
		t.Fatalf("configured = %v", got)
	}
	if got := set.lookup("tcp://new:1"); got != "tcp://new:1?key=00" {
		t.Fatalf("full URI = %q", got)
	}
}

func TestApplySelectionKeepsPeersWhenSelectionIsDown(t *testing.T) {
	shortTimings(t)
	core := newFakeCore(map[string]time.Duration{"tcp://old:1": time.Millisecond})
	set := &peerSet{}
	addPeers(core, set, []string{"tcp://old:1"})

	if err := applySelection(context.Background(), core, set, []string{"tcp://broken:1"}); err == nil {
		t.Fatal("applySelection should fail when no selected peer comes up")
	}
	if got := core.configured(); !reflect.DeepEqual(got, []string{"tcp://broken:1", "tcp://old:1"}) {
		t.Fatalf("working peer was removed: %v", got)
	}
}

func TestSavePeersReplacesListAndKeepsOtherFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := SaveJSON(path, &AppConfig{
		Seed:           "seed",
		Peers:          []string{"tcp://a:1", "tcp://b:1", "tcp://c:1"},
		DialTimeoutSec: 3,
	}); err != nil {
		t.Fatalf("SaveJSON: %v", err)
	}
	if err := savePeers(path, []string{"tls://best:1?key=00"}, true); err != nil {
		t.Fatalf("savePeers: %v", err)
	}
	c, err := LoadOrInitAppConfig(path)
	if err != nil {
		t.Fatalf("LoadOrInitAppConfig: %v", err)
	}
	if !reflect.DeepEqual(c.Peers, []string{"tls://best:1?key=00"}) || c.Seed != "seed" {
		t.Fatalf("config = %+v", c)
	}
	if c.PeersCheckedAt.IsZero() {
		t.Fatal("PeersCheckedAt not set")
	}
}

// TestProbePeersRealHandshake runs two real cores over localhost: a listening
// one and the probe core. Only the listening one must be reported alive.
func TestProbePeersRealHandshake(t *testing.T) {
	if testing.Short() {
		t.Skip("starts real Yggdrasil cores")
	}
	old := probeSettle
	probeSettle = 10 * time.Second
	t.Cleanup(func() { probeSettle = old })

	server, err := newProbeCore()
	if err != nil {
		t.Fatalf("server core: %v", err)
	}
	defer server.Stop()
	ln, err := server.Listen(&url.URL{Scheme: "tcp", Host: "127.0.0.1:0"}, "")
	if err != nil {
		if isPermissionError(err) {
			t.Skipf("sandbox does not allow TCP listeners: %v", err)
		}
		t.Fatalf("Listen: %v", err)
	}
	alive := "tcp://" + ln.Addr().String()
	dead := "tcp://127.0.0.1:1"

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	got, err := probePeers(ctx, []string{dead, alive})
	if err != nil {
		t.Fatalf("probePeers: %v", err)
	}
	if len(got) != 1 || got[alive] <= 0 {
		t.Fatalf("probePeers = %v, want only %s with RTT", got, alive)
	}
}
