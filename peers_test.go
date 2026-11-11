package ygg

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/url"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
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
	old := []time.Duration{probeSettle, pollInterval, startBatchWait, startTimeout, applyWait, savedPeersWait}
	oldBatch := probeBatchSize
	probeSettle, pollInterval, startBatchWait, startTimeout, applyWait = 300*time.Millisecond, 10*time.Millisecond, 200*time.Millisecond, 300*time.Millisecond, 200*time.Millisecond
	savedPeersWait = 300 * time.Millisecond
	probeBatchSize = 2
	t.Cleanup(func() {
		probeSettle, pollInterval, startBatchWait, startTimeout, applyWait = old[0], old[1], old[2], old[3], old[4]
		savedPeersWait = old[5]
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

// Saved peers that hang (forged SYN-ACK) must not use up the time of the
// public list: the public phase has its own budget.
func TestConnectStartFallsBackToPublicList(t *testing.T) {
	shortTimings(t)
	f := newFakeCore(map[string]time.Duration{"tcp://public:1": 10 * time.Millisecond})
	fetched := false
	err := connectStart(f, &peerSet{}, []string{"tcp://saved-hangs:1"}, func() []string {
		fetched = true
		return []string{"tcp://public:1"}
	})
	if err != nil {
		t.Fatalf("connectStart: %v", err)
	}
	if !fetched {
		t.Fatal("public list was not fetched")
	}
	// The saved peer stays configured and keeps trying.
	if got, want := f.configured(), []string{"tcp://public:1", "tcp://saved-hangs:1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("configured = %v, want %v", got, want)
	}
}

func TestConnectStartSavedPeerSkipsPublicList(t *testing.T) {
	shortTimings(t)
	f := newFakeCore(map[string]time.Duration{"tcp://saved:1": 10 * time.Millisecond})
	err := connectStart(f, &peerSet{}, []string{"tcp://saved:1"}, func() []string {
		t.Fatal("public list fetched although a saved peer is up")
		return nil
	})
	if err != nil {
		t.Fatalf("connectStart: %v", err)
	}
}

func TestConnectStartNoPublicList(t *testing.T) {
	shortTimings(t)
	f := newFakeCore(nil)
	err := connectStart(f, &peerSet{}, []string{"tcp://saved-hangs:1"}, func() []string { return nil })
	if err == nil || !strings.Contains(err.Error(), "public peer list unavailable") {
		t.Fatalf("connectStart = %v, want public list error", err)
	}
}

func withMaxPeers(t *testing.T, n int) {
	t.Helper()
	stateMu.Lock()
	old, oldSet := maxPeers, maxPeersSet
	maxPeers, maxPeersSet = n, true
	stateMu.Unlock()
	t.Cleanup(func() {
		stateMu.Lock()
		maxPeers, maxPeersSet = old, oldSet
		stateMu.Unlock()
	})
}

// With one peer, losing it switches to the fastest backup that answers;
// dead, hanging and slower backups and the lost peer are removed.
func TestFailoverSwitchesToTheBestBackup(t *testing.T) {
	shortTimings(t)
	withMaxPeers(t, 1)
	oldWait := failoverWait
	failoverWait = 300 * time.Millisecond
	t.Cleanup(func() { failoverWait = oldWait })

	core := newFakeCore(map[string]time.Duration{
		"tls://a:1": 20 * time.Millisecond,
		"tls://b:1": 80 * time.Millisecond,
		"tls://c:1": 30 * time.Millisecond,
	}, "tls://d:1")
	n := &Node{}
	addPeers(core, &n.peers, []string{"tls://a:1"})
	// The peer dies.
	core.mu.Lock()
	delete(core.rtt, "tls://a:1")
	core.fail["tls://a:1"] = true
	core.mu.Unlock()

	cfg := filepath.Join(t.TempDir(), "ygg.json")
	backups := []string{"tls://a:1", "tls://d:1", "tls://e:1", "tls://b:1", "tls://c:1"}
	ranked, ok := n.failover(context.Background(), core, cfg, backups)
	if !ok {
		t.Fatal("no backup taken")
	}
	if got := core.configured(); !reflect.DeepEqual(got, []string{"tls://c:1"}) {
		t.Fatalf("peers after failover %v, want the fastest backup only", got)
	}
	if len(ranked) == 0 || ranked[0] != "tls://c:1" {
		t.Fatalf("ranking after failover %v, want c first", ranked)
	}
	saved, err := LoadOrInitAppConfig(cfg)
	if err != nil || len(saved.Peers) == 0 || saved.Peers[0] != "tls://c:1" {
		t.Fatalf("saved peers %v (%v), want c first", saved.Peers, err)
	}
}

func TestFailoverWithoutLiveBackups(t *testing.T) {
	shortTimings(t)
	withMaxPeers(t, 1)
	oldWait := failoverWait
	failoverWait = 100 * time.Millisecond
	t.Cleanup(func() { failoverWait = oldWait })

	core := newFakeCore(map[string]time.Duration{}, "tls://a:1", "tls://d:1")
	n := &Node{}
	addPeers(core, &n.peers, []string{"tls://a:1"})
	_, ok := n.failover(context.Background(), core, filepath.Join(t.TempDir(), "ygg.json"), []string{"tls://d:1", "tls://e:1"})
	if ok {
		t.Fatal("failover reported success without a live backup")
	}
}

func TestRankAllKeepsSlowPeersAsBackups(t *testing.T) {
	got := rankAll(map[string]time.Duration{
		"tls://a:1":  10 * time.Millisecond,
		"tls://a:2":  12 * time.Millisecond, // same host
		"tls://b:1":  900 * time.Millisecond,
		"quic://c:1": 40 * time.Millisecond,
	}, 0)
	want := []string{"tls://a:1", "quic://c:1", "tls://b:1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rankAll %v, want %v", got, want)
	}
}

// While the node carries its own traffic, changes to the peers wait: they
// would move the node in the tree and break the routes in use.
func TestWaitQuietHoldsWhileTraffic(t *testing.T) {
	oldQuiet, oldPoll := quietFor, quietPoll
	quietFor, quietPoll = 150*time.Millisecond, 10*time.Millisecond
	defer func() { quietFor, quietPoll = oldQuiet, oldPoll; lastTraffic.Store(0) }()

	lastTraffic.Store(0)
	if busy() {
		t.Fatal("busy without any traffic")
	}
	start := time.Now()
	stop := time.After(300 * time.Millisecond)
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				noteTraffic()
				time.Sleep(20 * time.Millisecond)
			}
		}
	}()
	time.Sleep(30 * time.Millisecond)
	if err := waitQuiet(context.Background(), "test"); err != nil {
		t.Fatal(err)
	}
	if waited := time.Since(start); waited < 300*time.Millisecond+quietFor-50*time.Millisecond {
		t.Fatalf("went ahead after %v, while the traffic lasted 300ms (+%v quiet)", waited, quietFor)
	}
}
