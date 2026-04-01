package ygg

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	ycore "github.com/yggdrasil-network/yggdrasil-go/src/core"
)

func SaveJSON(path string, v any) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("empty path")
	}
	tmp := path + ".tmp"
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// uniqUnion returns a union of a and b preserving the order of a, then appending unseen items from b.
func uniqUnion(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, s := range a {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, s := range b {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

type publicPeerEntry struct {
	Up *bool `json:"up"`
}

var supportedPeerSchemes = map[string]struct{}{
	"tcp":      {},
	"tls":      {},
	"socks":    {},
	"sockstls": {},
	"unix":     {},
	"quic":     {},
	"ws":       {},
	"wss":      {},
}

// fetchPeersFromURL downloads the JSON peer list and returns usable endpoints.
func fetchPeersFromURL(timeout time.Duration) ([]string, error) {
	ctx := context.Background()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	cl := &http.Client{Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, publicPeersURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "say/0.1")
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s", resp.Status)
	}

	var raw map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode peers: %w", err)
	}

	seen := map[string]struct{}{}
	out := make([]string, 0, len(raw))

	for _, blob := range raw {
		var nodes map[string]publicPeerEntry
		if err := json.Unmarshal(blob, &nodes); err != nil {
			continue // skip metadata blocks
		}
		for endpoint, meta := range nodes {
			endpoint = strings.TrimSpace(endpoint)
			if endpoint == "" {
				continue
			}
			if meta.Up != nil && !*meta.Up {
				continue
			}
			if _, ok := seen[endpoint]; ok {
				continue
			}
			if !isSupportedPeerScheme(endpoint) {
				continue
			}
			seen[endpoint] = struct{}{}
			out = append(out, endpoint)
		}
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("no peers found in %s", publicPeersURL)
	}
	return out, nil
}

func isSupportedPeerScheme(raw string) bool {
	if raw == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if _, ok := supportedPeerSchemes[strings.ToLower(u.Scheme)]; !ok {
		return false
	}
	return true
}

// FilterAlivePeers checks peer availability and returns only those considered "alive".
func FilterAlivePeers(peers []string, timeout time.Duration, maxParallel int) []string {
	if maxParallel <= 0 {
		maxParallel = 16
	}
	type result struct {
		idx     int
		ok      bool
		latency time.Duration
		peer    string
	}

	alive := make([]result, 0, len(peers))
	ch := make(chan result, len(peers))
	sem := make(chan struct{}, maxParallel)
	var wg sync.WaitGroup

	for i, raw := range peers {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, p string) {
			defer wg.Done()
			defer func() { <-sem }()
			ok, latency := probePeer(p, timeout)
			ch <- result{idx: idx, ok: ok, latency: latency, peer: p}
		}(i, raw)
	}

	wg.Wait()
	close(ch)

	for res := range ch {
		if res.ok {
			alive = append(alive, res)
		}
	}
	sort.SliceStable(alive, func(i, j int) bool {
		if alive[i].latency == alive[j].latency {
			return alive[i].idx < alive[j].idx
		}
		return alive[i].latency < alive[j].latency
	})

	out := make([]string, len(alive))
	for i, res := range alive {
		out[i] = res.peer
	}
	return out
}

func probePeer(raw string, timeout time.Duration) (bool, time.Duration) {
	u, err := url.Parse(raw)
	if err != nil {
		return false, 0
	}

	switch strings.ToLower(u.Scheme) {
	case "quic":
		host := u.Hostname()
		port := u.Port()
		if host == "" || port == "" {
			return false, 0
		}
		addr := net.JoinHostPort(host, port)
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
		}
		if net.ParseIP(host) == nil {
			tlsConfig.ServerName = host
		}
		ctx := context.Background()
		if timeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		}
		start := time.Now()
		conn, err := quic.DialAddr(ctx, addr, tlsConfig, &quic.Config{
			MaxIdleTimeout: timeout,
		})
		if err != nil {
			return false, time.Since(start)
		}
		_ = conn.CloseWithError(0, "probe")
		return true, time.Since(start)
	case "unix":
		path := strings.TrimSpace(u.Path)
		if path == "" {
			path = strings.TrimSpace(u.Opaque)
		}
		if path == "" {
			return false, 0
		}
		start := time.Now()
		c, err := net.DialTimeout("unix", path, timeout)
		if err != nil {
			return false, time.Since(start)
		}
		_ = c.Close()
		return true, time.Since(start)

	default:
		// For TCP-like schemes (tcp/tls/ws/wss/socks/sockstls), probe host:port.
		hostport := u.Host
		if hostport == "" && u.Opaque != "" {
			// support for forms like "scheme:host:port" without //
			hostport = u.Opaque
		}
		if hostport == "" {
			return false, 0
		}
		start := time.Now()
		d := net.Dialer{Timeout: timeout}
		c, err := d.Dial("tcp", hostport)
		if err != nil {
			return false, time.Since(start)
		}
		_ = c.Close()
		return true, time.Since(start)
	}
}

func CollectPeers(static []string, timeout time.Duration, maxParallel int) ([]string, error) {
	var all []string
	all = append(all, static...)
	fromURL, err := fetchPeersFromURL(timeout)
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return nil, err
	}
	all = append(all, fromURL...)
	// Dedupe and basic sanitize.
	seen := map[string]struct{}{}
	uniq := make([]string, 0, len(all))
	for _, p := range all {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		// Only accept schemes we know how to probe.
		if !isSupportedPeerScheme(p) {
			continue
		}
		seen[p] = struct{}{}
		uniq = append(uniq, p)
	}
	if len(uniq) == 0 {
		return nil, fmt.Errorf("no peers provided")
	}
	alive := FilterAlivePeers(uniq, timeout, maxParallel)
	if len(alive) == 0 {
		return nil, fmt.Errorf("no alive peers")
	}
	return alive, nil
}

func mergePeersIntoConfig(path string, fallback *AppConfig, peers []string) ([]string, int, error) {
	current, err := LoadOrInitAppConfig(path)
	if err != nil {
		if fallback == nil {
			return nil, 0, err
		}
		merged := uniqUnion(fallback.Peers, peers)
		return merged, len(merged) - len(fallback.Peers), err
	}

	before := len(current.Peers)
	current.Peers = uniqUnion(current.Peers, peers)
	added := len(current.Peers) - before
	if added == 0 {
		return current.Peers, 0, nil
	}
	if err := SaveJSON(path, current); err != nil {
		return current.Peers, added, err
	}
	return current.Peers, added, nil
}

func sleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// certFromPrivateKey creates a self-signed TLS cert using the provided ed25519 private key.
func certFromPrivateKey(priv ed25519.PrivateKey) (*tls.Certificate, error) {
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(3650 * 24 * time.Hour), // ~10 years
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	pub := priv.Public().(ed25519.PublicKey)
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, priv)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
	return cert, nil
}

// hasUp is an internal helper used by Connected/WaitConnected and the monitor.
// hasUp reports whether the core has at least one Up peer.
func hasUp(core *ycore.Core) bool {
	for _, p := range core.GetPeers() {
		if p.Up {
			return true
		}
	}
	return false
}

// notifyConnectivity invokes the connectivity handler if set.
func notifyConnectivity(connected bool) {
	stateMu.RLock()
	h := connectivityHandler
	stateMu.RUnlock()
	if h != nil {
		h(connected)
	}
}
