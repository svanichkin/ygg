package ygg

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

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
	req.Header.Set("User-Agent", "ygg")
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

// hasUp reports whether the core has at least one peer that completed the
// Yggdrasil handshake. Used by Connected/WaitConnected and the monitor.
func hasUp(core *ycore.Core) bool {
	return countUp(core) > 0
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
