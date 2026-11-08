package ygg

import (
	"fmt"
	"net/netip"
	"net/url"
	"regexp"

	ycfg "github.com/yggdrasil-network/yggdrasil-go/src/config"
	ycore "github.com/yggdrasil-network/yggdrasil-go/src/core"
	ymc "github.com/yggdrasil-network/yggdrasil-go/src/multicast"
)

// LAN discovery.
//
// Nodes in one local network (one Wi-Fi or Ethernet segment) find each other
// by link-local IPv6 multicast beacons and peer directly, without the
// internet. This is the standard Yggdrasil multicast module.
//
// With a password only nodes with the same password peer with each other;
// without it the node peers with any Yggdrasil node in the network. The
// password protects only these local links; it does not hide the node from
// the rest of the Yggdrasil network.

// maxLANPassword is the longest link password the core accepts (blake2b key).
const maxLANPassword = 64

var (
	lanEnabled  bool
	lanPassword string
	lanSet      bool
)

// SetLAN turns peer discovery in the local network on or off and sets its
// password (empty: peer with any Yggdrasil node in the network). It overrides
// the "lan" and "lan_password" config fields and applies to nodes started by
// New after the call.
func SetLAN(enabled bool, password string) {
	stateMu.Lock()
	lanEnabled = enabled
	lanPassword = password
	lanSet = true
	stateMu.Unlock()
}

// lanSettings returns the LAN settings: from SetLAN if it was called,
// otherwise from the config.
func lanSettings(ac *AppConfig) (bool, string) {
	stateMu.RLock()
	defer stateMu.RUnlock()
	if lanSet {
		return lanEnabled, lanPassword
	}
	return ac.LAN, ac.LANPassword
}

// startLAN starts multicast discovery on the interfaces listed in
// cfg.MulticastInterfaces (platform defaults from ycfg.GenerateConfig), all
// with the given password.
func startLAN(core *ycore.Core, cfg *ycfg.NodeConfig, password string, logger ycore.Logger) (*ymc.Multicast, error) {
	if len(password) > maxLANPassword {
		return nil, fmt.Errorf("lan password is %d bytes, at most %d allowed", len(password), maxLANPassword)
	}
	var opts []ymc.SetupOption
	for _, mi := range cfg.MulticastInterfaces {
		re, err := regexp.Compile(mi.Regex)
		if err != nil {
			return nil, fmt.Errorf("multicast interface regex %q: %w", mi.Regex, err)
		}
		opts = append(opts, ymc.MulticastInterface{
			Regex:    re,
			Beacon:   mi.Beacon,
			Listen:   mi.Listen,
			Port:     mi.Port,
			Priority: uint8(mi.Priority),
			Password: password,
		})
	}
	mc, err := ymc.New(core, logger, opts...)
	if err != nil {
		return nil, &lanUnavailableError{err}
	}
	return mc, nil
}

// lanUnavailableError: discovery could not open its socket, typically
// because another program on this machine holds the port (Plan 9 cannot
// share it). The node works without LAN discovery; a configuration error,
// by contrast, is returned as is.
type lanUnavailableError struct{ err error }

func (e *lanUnavailableError) Error() string { return e.err.Error() }
func (e *lanUnavailableError) Unwrap() error { return e.err }

// isLANPeer reports whether the peer URI points at a link-local address,
// i.e. the link was made by LAN discovery. Such links are not managed by the
// peer manager: they are never ranked, saved or removed.
func isLANPeer(uri string) bool {
	u, err := url.Parse(uri)
	if err != nil {
		return false
	}
	a, err := netip.ParseAddr(u.Hostname())
	return err == nil && a.IsLinkLocalUnicast()
}
