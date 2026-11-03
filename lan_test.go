package ygg

import (
	"context"
	"net"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	ycfg "github.com/yggdrasil-network/yggdrasil-go/src/config"
	ycore "github.com/yggdrasil-network/yggdrasil-go/src/core"
)

const lanURI = "tls://[fe80::1%25en0]:40001"

func TestIsLANPeer(t *testing.T) {
	cases := map[string]bool{
		lanURI:                         true,
		"tls://[fe80::abcd]:1":         true,
		"tcp://[200:1::1]:1":           false,
		"tls://[2001:db8::1]:443":      false,
		"tcp://192.168.1.10:1234":      false,
		"tls://yggdrasil.example:1234": false,
		"::bad uri":                    false,
	}
	for uri, want := range cases {
		if got := isLANPeer(uri); got != want {
			t.Errorf("isLANPeer(%q) = %v, want %v", uri, got, want)
		}
	}
}

// LAN links are made by multicast, not by the peer manager: it must not rank,
// save or remove them, and they must not hide a weak internet connection.
func TestPeerManagerLeavesLANLinksAlone(t *testing.T) {
	shortTimings(t)
	f := newFakeCore(map[string]time.Duration{
		lanURI:      time.Millisecond, // fastest, but local
		"tcp://a:1": 20 * time.Millisecond,
	})
	f.links[lanURI] = true // multicast made this link

	n := &Node{}
	if got := n.rankLive(f); len(got) != 0 {
		t.Fatalf("rankLive before internet peers = %v, want none", got)
	}
	if got := countUpRemote(f); got != 0 {
		t.Fatalf("countUpRemote = %d, want 0", got)
	}
	if got := countOutbound(f); got != 0 {
		t.Fatalf("countOutbound = %d, want 0", got)
	}

	if err := applySelection(context.Background(), f, &n.peers, []string{"tcp://a:1"}); err != nil {
		t.Fatalf("applySelection: %v", err)
	}
	want := []string{"tcp://a:1", lanURI}
	if got := f.configured(); !reflect.DeepEqual(got, want) {
		t.Fatalf("configured = %v, want %v", got, want)
	}
	if got := n.rankLive(f); !reflect.DeepEqual(got, []string{"tcp://a:1"}) {
		t.Fatalf("rankLive = %v, want only the internet peer", got)
	}
}

func TestLANConfigRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := SaveJSON(path, &AppConfig{Peers: []string{}, LAN: true, LANPassword: "secret"}); err != nil {
		t.Fatalf("SaveJSON: %v", err)
	}
	c, err := LoadOrInitAppConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !c.LAN || c.LANPassword != "secret" {
		t.Fatalf("loaded lan=%v password=%q", c.LAN, c.LANPassword)
	}
}

func TestSetLANOverridesConfig(t *testing.T) {
	stateMu.Lock()
	old := []any{lanEnabled, lanPassword, lanSet}
	lanSet = false
	stateMu.Unlock()
	t.Cleanup(func() {
		stateMu.Lock()
		lanEnabled, lanPassword, lanSet = old[0].(bool), old[1].(string), old[2].(bool)
		stateMu.Unlock()
	})

	ac := &AppConfig{LAN: true, LANPassword: "from-config"}
	if on, pw := lanSettings(ac); !on || pw != "from-config" {
		t.Fatalf("without SetLAN: %v %q", on, pw)
	}
	SetLAN(false, "")
	if on, _ := lanSettings(ac); on {
		t.Fatal("SetLAN(false) did not override config")
	}
}

func TestStartLANRejectsLongPassword(t *testing.T) {
	core, err := newProbeCore()
	if err != nil {
		t.Fatal(err)
	}
	defer core.Stop()
	long := string(make([]byte, maxLANPassword+1))
	if _, err := startLAN(core, ycfg.GenerateConfig(), long, quietLogger{}); err == nil {
		t.Fatal("startLAN accepted a too long password")
	}
}

// TestLANDiscoveryLoopback runs two real cores with multicast on the loopback
// interface: with the same password they must peer, with different ones not.
func TestLANDiscoveryLoopback(t *testing.T) {
	if testing.Short() {
		t.Skip("starts real Yggdrasil cores")
	}
	lo := loopbackMulticast(t)
	cfg := &ycfg.NodeConfig{MulticastInterfaces: []ycfg.MulticastInterfaceConfig{
		{Regex: "^" + lo + "$", Beacon: true, Listen: true},
	}}

	start := func(password string) *ycore.Core {
		c, err := newProbeCore()
		if err != nil {
			t.Fatal(err)
		}
		mc, err := startLAN(c, cfg, password, quietLogger{})
		if err != nil {
			c.Stop()
			if isPermissionError(err) {
				t.Skipf("sandbox does not allow multicast: %v", err)
			}
			t.Fatalf("startLAN: %v", err)
		}
		t.Cleanup(func() { _ = mc.Stop(); c.Stop() })
		return c
	}
	peered := func(a, b *ycore.Core, d time.Duration) bool {
		return waitFor(context.Background(), d, func() bool {
			for _, p := range a.GetPeers() {
				if isUp(p) && isLANPeer(p.URI) && p.Key.Equal(b.PublicKey()) {
					return true
				}
			}
			return false
		})
	}

	a, b := start("same"), start("same")
	if !peered(a, b, 20*time.Second) {
		t.Fatal("nodes with the same password did not peer over LAN")
	}

	c := start("other")
	if peered(c, a, 5*time.Second) || peered(a, c, 0) {
		t.Fatal("node with a different password peered over LAN")
	}
}

// loopbackMulticast returns the loopback interface name if it supports
// multicast, or skips the test.
func loopbackMulticast(t *testing.T) string {
	t.Helper()
	ifs, err := net.Interfaces()
	if err != nil {
		t.Skipf("interfaces: %v", err)
	}
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 && i.Flags&net.FlagMulticast != 0 && i.Flags&net.FlagUp != 0 {
			return i.Name
		}
	}
	t.Skip("no multicast-capable loopback interface")
	return ""
}
