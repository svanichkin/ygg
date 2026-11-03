package ygg

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

	if got := configuredMaxPeers(); got != defaultMaxPeers {
		t.Fatalf("configuredMaxPeers() default = %d, want %d", got, defaultMaxPeers)
	}

	SetMaxPeers(0)
	if got := configuredMaxPeers(); got != 0 {
		t.Fatalf("configuredMaxPeers() after SetMaxPeers(0) = %d, want 0", got)
	}
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

func isPermissionError(err error) bool {
	return errors.Is(err, os.ErrPermission) || strings.Contains(err.Error(), "operation not permitted")
}
