package ygg

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestSaveJSONRejectsBadInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := SaveJSON(path, make(chan int)); err == nil {
		t.Fatal("SaveJSON should fail for unsupported JSON values")
	}
}

func TestLoadOrInitAppConfigReturnsReadErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadOrInitAppConfig(dir); err == nil {
		t.Fatal("LoadOrInitAppConfig should fail when the path is not a file")
	}
}

func TestConfiguredMaxPeersHonorsExplicitZero(t *testing.T) {
	stateMu.Lock()
	oldMaxPeers := maxPeers
	oldMaxPeersSet := maxPeersSet
	maxPeers = 0
	maxPeersSet = false
	stateMu.Unlock()
	t.Cleanup(func() {
		stateMu.Lock()
		maxPeers = oldMaxPeers
		maxPeersSet = oldMaxPeersSet
		stateMu.Unlock()
	})

	if got := configuredMaxPeers(); got != 100 {
		t.Fatalf("configuredMaxPeers() default = %d, want 100", got)
	}

	SetMaxPeers(0)
	if got := configuredMaxPeers(); got != 0 {
		t.Fatalf("configuredMaxPeers() after SetMaxPeers(0) = %d, want 0", got)
	}
}

func TestProbePeerQUIC(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	cert, err := certFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("certFromPrivateKey: %v", err)
	}

	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS13,
	}, &quic.Config{})
	if err != nil {
		if isPermissionError(err) {
			t.Skipf("sandbox does not allow UDP listeners: %v", err)
		}
		t.Fatalf("ListenAddr: %v", err)
	}
	defer listener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept(ctx)
		if err != nil {
			return
		}
		_ = conn.CloseWithError(0, "test done")
	}()

	ok, latency := probePeer("quic://"+listener.Addr().String(), 2*time.Second)
	if !ok {
		t.Fatalf("probePeer(quic) = false, latency=%s", latency)
	}

	cancel()
	<-done
}

func TestSaveJSONWritesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	cfg := &AppConfig{Peers: []string{"tcp://127.0.0.1:1234"}}
	if err := SaveJSON(path, cfg); err != nil {
		t.Fatalf("SaveJSON: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("saved file missing: %v", err)
	}
}

func TestProbePeerTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if isPermissionError(err) {
			t.Skipf("sandbox does not allow TCP listeners: %v", err)
		}
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	ok, latency := probePeer("tcp://"+ln.Addr().String(), time.Second)
	if !ok {
		t.Fatalf("probePeer(tcp) = false, latency=%s", latency)
	}

	<-done
}

type fakePeerAdder struct {
	failFor map[string]error
	added   []string
}

func (f *fakePeerAdder) AddPeer(u *url.URL, _ string) error {
	peer := u.String()
	if err, ok := f.failFor[peer]; ok {
		return err
	}
	f.added = append(f.added, peer)
	return nil
}

func TestAddPersistentPeersCountsOnlySuccessfulAdds(t *testing.T) {
	adder := &fakePeerAdder{
		failFor: map[string]error{
			"tcp://127.0.0.1:1": errors.New("boom"),
		},
	}

	added, err := addPersistentPeers(adder, []string{
		"tcp://127.0.0.1:1",
		"tcp://127.0.0.1:2",
		"tcp://127.0.0.1:3",
	}, 1)
	if err != nil {
		t.Fatalf("addPersistentPeers: %v", err)
	}
	if added != 1 {
		t.Fatalf("added = %d, want 1", added)
	}
	if want := []string{"tcp://127.0.0.1:2"}; !reflect.DeepEqual(adder.added, want) {
		t.Fatalf("added peers = %v, want %v", adder.added, want)
	}
}

func TestAddPersistentPeersFailsWhenNothingWasAdded(t *testing.T) {
	adder := &fakePeerAdder{
		failFor: map[string]error{
			"tcp://127.0.0.1:1": errors.New("boom"),
		},
	}

	added, err := addPersistentPeers(adder, []string{"tcp://127.0.0.1:1"}, 0)
	if err == nil {
		t.Fatal("addPersistentPeers should fail when all peers are rejected")
	}
	if added != 0 {
		t.Fatalf("added = %d, want 0", added)
	}
}

func TestMergePeersIntoConfigPreservesDiskChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := SaveJSON(path, &AppConfig{
		Peers:          []string{"tcp://127.0.0.1:1"},
		DialTimeoutSec: 3,
	}); err != nil {
		t.Fatalf("SaveJSON initial: %v", err)
	}

	stale := &AppConfig{
		Peers:          []string{"tcp://127.0.0.1:1"},
		DialTimeoutSec: 3,
	}
	if err := SaveJSON(path, &AppConfig{
		Peers:          []string{"tcp://127.0.0.1:1", "tcp://127.0.0.1:2"},
		DialTimeoutSec: 3,
	}); err != nil {
		t.Fatalf("SaveJSON external update: %v", err)
	}

	merged, added, err := mergePeersIntoConfig(path, stale, []string{"tcp://127.0.0.1:3"})
	if err != nil {
		t.Fatalf("mergePeersIntoConfig: %v", err)
	}

	want := []string{"tcp://127.0.0.1:1", "tcp://127.0.0.1:2", "tcp://127.0.0.1:3"}
	if added != 1 {
		t.Fatalf("added = %d, want 1", added)
	}
	if !reflect.DeepEqual(merged, want) {
		t.Fatalf("merged peers = %v, want %v", merged, want)
	}

	cfg, err := LoadOrInitAppConfig(path)
	if err != nil {
		t.Fatalf("LoadOrInitAppConfig: %v", err)
	}
	if !reflect.DeepEqual(cfg.Peers, want) {
		t.Fatalf("saved peers = %v, want %v", cfg.Peers, want)
	}
}

func isPermissionError(err error) bool {
	return errors.Is(err, os.ErrPermission) || strings.Contains(err.Error(), "operation not permitted")
}
