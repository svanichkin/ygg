package ygg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"

	ycfg "github.com/yggdrasil-network/yggdrasil-go/src/config"
	ycore "github.com/yggdrasil-network/yggdrasil-go/src/core"
	ipv6rwc "github.com/yggdrasil-network/yggdrasil-go/src/ipv6rwc"
	ymc "github.com/yggdrasil-network/yggdrasil-go/src/multicast"

	// gVisor netstack dependencies
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const (
	publicPeersURL = "https://publicpeers.neilalexander.dev/publicnodes.json"
)

type quietLogger struct{}

func (l quietLogger) Printf(string, ...interface{})     {}
func (l quietLogger) Println(...interface{})            {}
func (l quietLogger) Infof(string, ...interface{})      {}
func (l quietLogger) Infoln(...interface{})             {}
func (l quietLogger) Warnf(string, ...interface{})      {}
func (l quietLogger) Warnln(...interface{})             {}
func (l quietLogger) Errorf(f string, a ...interface{}) { log.Printf(f, a...) }
func (l quietLogger) Errorln(a ...interface{})          { log.Println(a...) }
func (l quietLogger) Debugf(string, ...interface{})     {}
func (l quietLogger) Debugln(...interface{})            {}
func (l quietLogger) Traceln(...interface{})            {}

var (
	stateMu     sync.RWMutex
	verbose     bool
	maxPeers    int
	maxPeersSet bool
	defaultNode *Node
)

// ConnectivityHandler is called whenever the node transitions between
// connected and disconnected states.
type ConnectivityHandler func(connected bool)

var connectivityHandler ConnectivityHandler

// SetConnectivityHandler installs a callback for connectivity state changes.
// The callback is invoked on a background goroutine.
func SetConnectivityHandler(h ConnectivityHandler) {
	stateMu.Lock()
	connectivityHandler = h
	node := defaultNode
	stateMu.Unlock()

	if node == nil {
		return
	}
	if h == nil {
		node.stopConnectivityMonitor()
		return
	}
	if !node.startConnectivityMonitor(3 * time.Second) {
		go notifyConnectivity(node.Connected())
	}
}

// SetVerbose enables or disables verbose logging from this package.
func SetVerbose(v bool) {
	stateMu.Lock()
	verbose = v
	stateMu.Unlock()
}

// SetMaxPeers sets how many best peers (by measured RTT) the node keeps.
// The default is 8. If n <= 0, every reachable peer is kept.
func SetMaxPeers(n int) {
	stateMu.Lock()
	maxPeers = n
	maxPeersSet = true
	stateMu.Unlock()
}

func logV(format string, a ...interface{}) {
	stateMu.RLock()
	v := verbose
	stateMu.RUnlock()
	if v {
		log.Printf(format, a...)
	}
}

func configuredMaxPeers() int {
	stateMu.RLock()
	n := maxPeers
	set := maxPeersSet
	stateMu.RUnlock()
	if !set {
		return defaultMaxPeers
	}
	return n
}

func setDefaultNode(node *Node) {
	stateMu.Lock()
	defaultNode = node
	stateMu.Unlock()
}

func getDefaultNode() *Node {
	stateMu.RLock()
	node := defaultNode
	stateMu.RUnlock()
	return node
}

func hasConnectivityHandler() bool {
	stateMu.RLock()
	h := connectivityHandler != nil
	stateMu.RUnlock()
	return h
}

// New initializes (or loads) configuration from cfgPath, discovers peers, starts
// an embedded Yggdrasil core, connects to alive peers, and returns the Node.
// If cfgPath is empty, a default location is chosen (next to the binary or
// ~/.config/say/config.json). The caller owns the returned Node and may stop it
// by calling Close().
func New(cfgPath string) (*Node, error) {
	// Resolve config path if caller left it empty.
	if strings.TrimSpace(cfgPath) == "" {
		if exe, err := os.Executable(); err == nil {
			exeDir := filepath.Dir(exe)
			cand := filepath.Join(exeDir, "config.json")
			if _, err := os.Stat(cand); err == nil {
				cfgPath = cand
			}
		}
		if cfgPath == "" {
			if home, err := os.UserHomeDir(); err == nil {
				cand := filepath.Join(home, ".config", "say", "config.json")
				if _, err := os.Stat(cand); err == nil {
					cfgPath = cand
				} else {
					_ = os.MkdirAll(filepath.Dir(cand), 0o755)
					cfgPath = cand
				}
			}
		}
	}
	if strings.TrimSpace(cfgPath) == "" {
		return nil, fmt.Errorf("config path could not be resolved")
	}

	logV("config path: %s", cfgPath)

	ac, err := LoadOrInitAppConfig(cfgPath)
	if err != nil {
		return nil, err
	}
	yc, err := PrepareYggConfig(ac)
	if err != nil {
		return nil, err
	}
	if err := SaveJSON(cfgPath, ac); err != nil {
		return nil, fmt.Errorf("write config: %w", err)
	}
	logV("config saved (keys inline)")

	t0 := time.Now()
	core, err := startCore(yc, quietLogger{})
	if err != nil {
		return nil, err
	}
	node := &Node{Core: core, Config: yc}

	// LAN discovery starts before the internet peers, so a node in the
	// same network can be the first peer.
	if on, password := lanSettings(ac); on {
		mc, err := startLAN(core, yc, password, quietLogger{})
		var unavailable *lanUnavailableError
		switch {
		case errors.As(err, &unavailable):
			logV("lan: discovery off: %v", err)
		case err != nil:
			_ = node.Close()
			return nil, fmt.Errorf("start lan discovery: %w", err)
		default:
			node.lan = mc
			logV("lan: discovery on (password set: %t)", password != "")
		}
	}

	logV("peers: saved=%d", len(ac.Peers))
	err = connectStart(core, &node.peers, ac.Peers, func() []string {
		return fetchCandidates(5 * time.Second)
	})
	switch {
	case err == nil:
		logV("connect: first peer up in %s", time.Since(t0).Truncate(time.Millisecond))
	case node.lan != nil:
		// No internet peers, but nodes in the local network may still come:
		// start anyway, peers keep being retried in the background.
		logV("connect: %v; starting anyway, LAN discovery is on", err)
	default:
		_ = node.Close()
		return nil, fmt.Errorf("connect: %w", err)
	}

	// Start in-process netstack immediately (single-mode runtime, no OS utun).
	if _, err := node.StartNetstack(); err != nil {
		_ = node.Close()
		return nil, fmt.Errorf("start netstack: %w", err)
	}

	if directSetting() {
		if err := node.startDirectService(); err != nil {
			logV("direct: service off: %v", err)
		} else {
			logV("direct: on")
		}
	}

	addr := node.Core.Address()
	keyHex := strings.TrimSpace(ac.Seed)
	if len(keyHex) >= 8 {
		logV("connected: %s (key fp=%s...)", addr.String(), keyHex[:8])
	} else {
		logV("connected: %s", addr.String())
	}

	// Keep the node on the best peers in the background.
	node.startPeerManager(cfgPath, ac.PeersCheckedAt)

	// Start connectivity monitor if user installed a handler.
	if hasConnectivityHandler() {
		node.startConnectivityMonitor(3 * time.Second)
	}
	// Expose as default for package-level helpers.
	setDefaultNode(node)

	return node, nil
}

type AppConfig struct {
	// Seed is the inline private key seed (empty => generate).
	Seed string `json:"seed,omitempty"`
	// Peers is the peer list (tcp://host:port, tls://..., quic://...). After
	// the first check it holds only the best peers that completed a real
	// Yggdrasil handshake, ordered by RTT.
	Peers []string `json:"peers"`
	// PeersCheckedAt is when all candidates were last re-checked.
	PeersCheckedAt time.Time `json:"peers_checked_at,omitzero"`
	// DialTimeoutSec controls connect timeouts.
	DialTimeoutSec int `json:"dial_timeout_sec,omitempty"`
	// LAN turns on peer discovery in the local network (see SetLAN).
	LAN bool `json:"lan,omitempty"`
	// LANPassword: only nodes with the same password peer in the local
	// network. Empty: any Yggdrasil node.
	LANPassword string `json:"lan_password,omitempty"`
	raw         map[string]json.RawMessage
}

func (c *AppConfig) UnmarshalJSON(data []byte) error {
	type alias struct {
		Seed           string    `json:"seed,omitempty"`
		Peers          []string  `json:"peers"`
		PeersCheckedAt time.Time `json:"peers_checked_at,omitzero"`
		DialTimeoutSec int       `json:"dial_timeout_sec,omitempty"`
		LAN            bool      `json:"lan,omitempty"`
		LANPassword    string    `json:"lan_password,omitempty"`
	}
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	c.Seed = a.Seed
	c.Peers = a.Peers
	c.PeersCheckedAt = a.PeersCheckedAt
	c.DialTimeoutSec = a.DialTimeoutSec
	c.LAN = a.LAN
	c.LANPassword = a.LANPassword
	if c.Peers == nil {
		c.Peers = []string{}
	}
	raw := make(map[string]json.RawMessage)
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	c.raw = raw
	return nil
}

func (c *AppConfig) MarshalJSON() ([]byte, error) {
	raw := make(map[string]json.RawMessage, len(c.raw)+3)
	for k, v := range c.raw {
		raw[k] = v
	}
	if c.Seed != "" {
		b, err := json.Marshal(c.Seed)
		if err != nil {
			return nil, err
		}
		raw["seed"] = b
	} else {
		delete(raw, "seed")
	}
	peers := c.Peers
	if peers == nil {
		peers = []string{}
	}
	b, err := json.Marshal(peers)
	if err != nil {
		return nil, err
	}
	raw["peers"] = b
	if !c.PeersCheckedAt.IsZero() {
		b, err = json.Marshal(c.PeersCheckedAt)
		if err != nil {
			return nil, err
		}
		raw["peers_checked_at"] = b
	} else {
		delete(raw, "peers_checked_at")
	}
	if c.DialTimeoutSec != 0 {
		b, err = json.Marshal(c.DialTimeoutSec)
		if err != nil {
			return nil, err
		}
		raw["dial_timeout_sec"] = b
	} else {
		delete(raw, "dial_timeout_sec")
	}
	if c.LAN {
		raw["lan"] = json.RawMessage("true")
	} else {
		delete(raw, "lan")
	}
	if c.LANPassword != "" {
		b, err = json.Marshal(c.LANPassword)
		if err != nil {
			return nil, err
		}
		raw["lan_password"] = b
	} else {
		delete(raw, "lan_password")
	}
	return json.Marshal(raw)
}

func LoadOrInitAppConfig(path string) (*AppConfig, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("empty config path")
	}
	b, err := os.ReadFile(path)
	if err == nil {
		var c AppConfig
		if e := json.Unmarshal(b, &c); e != nil {
			return nil, e
		}
		changed := false
		if c.Peers == nil {
			c.Peers = []string{}
			changed = true
		}
		if c.DialTimeoutSec == 0 {
			c.DialTimeoutSec = 3
			changed = true
		}
		// If we had to add defaults, persist them back to the existing config file.
		if changed {
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return nil, err
			}
			if err := SaveJSON(path, &c); err != nil {
				return nil, err
			}
		}
		return &c, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	// Create a new config with sane defaults if the file does not exist yet.
	c := &AppConfig{
		Peers:          []string{},
		DialTimeoutSec: 3,
		raw:            map[string]json.RawMessage{},
	}
	c.Peers = append(c.Peers, "tcp://109.107.177.127:65535",
		"quic://109.107.177.127:65535",
		"tls://109.176.250.101:65534",
		"quic://129.80.167.244:23165",
		"tls://133.18.201.69:54232",
		"tcp://146.103.107.222:65535",
		"quic://146.103.107.222:65535",
		"tcp://146.103.111.53:65535",
		"quic://146.103.111.53:65535",
		"tls://153.120.42.137:54232",
		"tls://192.3.13.16:8118",
		"tls://194.55.165.115:443?key=84a4e510bd5528d25cf17ac44d47168c4600110f32e8e8ca10d3c103f4e73aa4",
		"tcp://194.55.165.115:80?key=84a4e510bd5528d25cf17ac44d47168c4600110f32e8e8ca10d3c103f4e73aa4",
		"tls://[2001:470:1f13:e56::64]:39575",
		"tcp://[2001:470:1f13:e56::64]:39565",
		"tcp://212.34.131.160:65535",
		"quic://212.34.131.160:65535",
		"tls://23.184.48.86:1443",
		"quic://23.184.48.86:1443",
		"quic://[2603:c020:4015:b937:a1c7:aff8:b558:d1fe]:23165",
		"tls://[2a02:1b8:10:147::1:1ea]:65534",
		"tls://[2a03:3b40:fe:ab::1]:993?key=0009e16b9e3afe7b13c3612560410434d3dfc70c8a8a0a63e51e0470cb8124f6",
		"tls://[2a0c:5cc0:1:1::83f4:cbd8]:443?key=84a4e510bd5528d25cf17ac44d47168c4600110f32e8e8ca10d3c103f4e73aa4",
		"tcp://[2a0c:5cc0:1:1::83f4:cbd8]:80?key=84a4e510bd5528d25cf17ac44d47168c4600110f32e8e8ca10d3c103f4e73aa4",
		"tcp://[2a0d:8480:1:209e::]:65535",
		"quic://[2a0d:8480:1:209e::]:65535",
		"tcp://[2a0d:8480:3:234c::]:65535",
		"quic://[2a0d:8480:3:234c::]:65535",
		"tcp://[2a14:1e00:1:bae::]:65535",
		"quic://[2a14:1e00:1:bae::]:65535",
		"tcp://[2a14:1e00:1:ecd::]:65535",
		"quic://[2a14:1e00:1:ecd::]:65535",
		"tcp://[2a14:1e00:1:f3c::]:65535",
		"quic://[2a14:1e00:1:f3c::]:65535",
		"tcp://[2a14:1e00:3:15c::]:65535",
		"quic://[2a14:1e00:3:15c::]:65535",
		"tcp://[2a14:1e00:3:2b2::]:65535",
		"quic://[2a14:1e00:3:2b2::]:65535",
		"tls://31.22.111.195:32000",
		"tls://37.186.113.100:1515",
		"tcp://37.186.113.100:1514",
		"quic://37.186.113.100:1515",
		"ws://37.186.113.100:1516",
		"tls://37.192.232.33:442",
		"tcp://37.192.232.33:8080",
		"tls://37.205.14.171:993?key=0009e16b9e3afe7b13c3612560410434d3dfc70c8a8a0a63e51e0470cb8124f6",
		"tls://5.252.118.13:443",
		"tcp://5.252.118.13:65535",
		"quic://5.252.118.13:65535",
		"tcp://5.35.70.181:65535",
		"quic://5.35.70.181:65535",
		"tls://51.15.204.214:54321",
		"tcp://51.15.204.214:12345",
		"tls://62.210.85.80:39575",
		"tcp://62.210.85.80:39565",
		"tcp://87.251.77.39:65535",
		"quic://87.251.77.39:65535",
		"tcp://88.210.10.78:65535",
		"quic://88.210.10.78:65535",
		"tcp://89.110.116.167:65535",
		"quic://89.110.116.167:65535",
		"tls://91.98.161.68:9001?key=0e638944bfd6b277fa5e0dddbeb4444778eea8bece63a9862c661797022a8f05",
		"tls://asia.deinfra.org:15015",
		"quic://asia.deinfra.org:15015",
		"tls://bode.theender.net:42169?key=f91b909f43829f8b20732b3bcf80cbc4bb078dd47b41638379a078e35984c9a4",
		"tcp://bode.theender.net:42069",
		"tls://box.paulll.cc:13338",
		"tcp://box.paulll.cc:13337",
		"tls://ca.us.ygg.informatics.coop:443?key=0000000023fc6ffb62afb79448aefb0943df2e4472cf08bd489f5407378300a2",
		"tls://cirno.nadeko.net:44442",
		"tcp://cirno.nadeko.net:44441",
		"tls://cowgl.tech:1337",
		"tls://dc.txlyre.website:1337",
		"tcp://dc.txlyre.website:13372",
		"quic://dc.txlyre.website:13371",
		"ws://dc.txlyre.website:13370",
		"tls://des.8px.sk:4321",
		"quic://des.8px.sk:4321",
		"wss://donotclickthis.link:443/api/v2/socket",
		"quic://ekb.itrus.su:7993",
		"quic://ip4.fvm.mywire.org:443?key=000000000143db657d1d6f80b5066dd109a4cb31f7dc6cb5d56050fffb014217",
		"tcp://ip4.nerdvm.mywire.org:8080?key=00000000c61d731961a290d127cd3fc03a4c5f3f35b9083559d4c81d48d65854",
		"quic://ip4.nerdvm.mywire.org:443?key=00000000c61d731961a290d127cd3fc03a4c5f3f35b9083559d4c81d48d65854",
		"quic://ip6.casa2.mywire.org:44443?key=000000003cb1cc50e05147fc548f6d1f78e7ffcdc67b456f9bb0db6f0a5e4723",
		"tcp://ip6.fvm.mywire.org:8080?key=000000000143db657d1d6f80b5066dd109a4cb31f7dc6cb5d56050fffb014217",
		"quic://ip6.fvm.mywire.org:443?key=000000000143db657d1d6f80b5066dd109a4cb31f7dc6cb5d56050fffb014217",
		"tcp://ip6.nerdvm.mywire.org:8080?key=00000000c61d731961a290d127cd3fc03a4c5f3f35b9083559d4c81d48d65854",
		"quic://ip6.nerdvm.mywire.org:443?key=00000000c61d731961a290d127cd3fc03a4c5f3f35b9083559d4c81d48d65854",
		"tcp://itcom.multed.com:7991",
		"tls://ke46138.ddns.net:12345",
		"quic://ke46138.ddns.net:12345",
		"tls://kem.txlyre.website:14437",
		"tcp://kem.txlyre.website:1337",
		"quic://kem.txlyre.website:13337",
		"tls://kursk.cleverfox.org:15015",
		"quic://kursk.cleverfox.org:15015",
		"ws://kursk.cleverfox.org:15016",
		"tls://leo.node.3dt.net:9003",
		"tcp://leo.node.3dt.net:9002",
		"quic://leo.node.3dt.net:9004",
		"tls://longseason.1200bps.xyz:13122",
		"tcp://longseason.1200bps.xyz:13121",
		"tls://marisa.nadeko.net:44442",
		"tcp://marisa.nadeko.net:44441",
		"tcp://mn.us.ygg.triplebit.org:9000",
		"quic://mn.us.ygg.triplebit.org:443",
		"tls://mo.us.ygg.triplebit.org:993",
		"tcp://mo.us.ygg.triplebit.org:9000",
		"quic://mo.us.ygg.triplebit.org:443",
		"ws://mo.us.ygg.triplebit.org:9010",
		"tls://mskaeza.i113d.ru:12632",
		"tcp://mskaeza.i113d.ru:12631",
		"ws://mskaeza.i113d.ru:12634",
		"tls://nl1.route172.de:443?key=000000002643ae27bad63e2a81f1d30554ce9ea634f5990062a9e079e23593cd",
		"tls://no0.yggdrasil.netralex.com:65534?key=f4b9fe4f9923834b1c20f84e13b14d90ecde443f78613ec54cf484eea6880fea",
		"tcp://no0.yggdrasil.netralex.com:65533?key=f4b9fe4f9923834b1c20f84e13b14d90ecde443f78613ec54cf484eea6880fea",
		"quic://no0.yggdrasil.netralex.com:65535?key=f4b9fe4f9923834b1c20f84e13b14d90ecde443f78613ec54cf484eea6880fea",
		"quic://peer.ryebreads.xyz:12345",
		"tls://r1.worcester.yggdrasil.novasredes.network:2001",
		"tcp://r1.worcester.yggdrasil.novasredes.network:2000",
		"tls://r2.worcester.yggdrasil.novasredes.network:2001",
		"tcp://r2.worcester.yggdrasil.novasredes.network:2000",
		"tls://ralsei.ru:12345",
		"quic://ralsei.ru:12345",
		"tcp://rendezvous.anton.molyboha.me:50421",
		"tls://reticulum.me:12393?key=a3d411280dfc350a4484aa3da5feb0407518c5820cbb011d5620347769b26665",
		"tls://s2.i2pd.xyz:39575",
		"tcp://s2.i2pd.xyz:39565",
		"tls://satori.nadeko.net:44442",
		"tcp://satori.nadeko.net:44441",
		"tls://scandic.us:2012",
		"tcp://scandic.us:2011",
		"ws://scandic.us:2014",
		"quic://scarlet.mboa.dev:3443",
		"tls://se.laerad.top:54001?key=29512833cbca43f1f0bb1833d0edcb45791e66f7955c577b57fd0fc78892e2f8",
		"quic://se.laerad.top:54001?key=29512833cbca43f1f0bb1833d0edcb45791e66f7955c577b57fd0fc78892e2f8",
		"tls://server.i113d.ru:12632",
		"tcp://server.i113d.ru:12631",
		"ws://server.i113d.ru:12634",
		"tls://sirsegv.moe:7676",
		"tls://sto01.yggdrasil.hosted-by.skhron.eu:8884?key=ce8cfa43b8c9e71c1fe31832b39403f23166f2bac12d52c755d9ac68f55da81c",
		"tcp://sto01.yggdrasil.hosted-by.skhron.eu:8883?key=ce8cfa43b8c9e71c1fe31832b39403f23166f2bac12d52c755d9ac68f55da81c",
		"quic://sto01.yggdrasil.hosted-by.skhron.eu:8885?key=ce8cfa43b8c9e71c1fe31832b39403f23166f2bac12d52c755d9ac68f55da81c",
		"ws://sto01.yggdrasil.hosted-by.skhron.eu:8886?key=ce8cfa43b8c9e71c1fe31832b39403f23166f2bac12d52c755d9ac68f55da81c",
		"tls://supanadit.com:15021",
		"quic://supanadit.com:15022",
		"tls://syd.joel.net.au:8443",
		"tcp://u-neroit.ru:7000",
		"tls://uk-lon1.ygg-public-peers.h.wer.ee:17161",
		"tcp://uk-lon1.ygg-public-peers.h.wer.ee:17160",
		"tls://us.laerad.top:54001?key=c81bc11f522837d2def65768a2593e30cdfa65de856fa129f1aa18e55ba3a484",
		"quic://us.laerad.top:54001?key=c81bc11f522837d2def65768a2593e30cdfa65de856fa129f1aa18e55ba3a484",
		"tls://vix.duckdns.org:36014",
		"quic://vix.duckdns.org:36014",
		"tls://vpn.itrus.su:7992",
		"tcp://vpn.itrus.su:7991",
		"quic://vpn.itrus.su:7993",
		"ws://vpn.itrus.su:7994",
		"tls://waw01.yggdrasil.hosted-by.skhron.eu:8884?key=030602cee88a761c68f5f14e1dad430f25238a703b69dc382321a38f833035b0",
		"tcp://waw01.yggdrasil.hosted-by.skhron.eu:8883?key=030602cee88a761c68f5f14e1dad430f25238a703b69dc382321a38f833035b0",
		"quic://waw01.yggdrasil.hosted-by.skhron.eu:8885?key=030602cee88a761c68f5f14e1dad430f25238a703b69dc382321a38f833035b0",
		"ws://waw01.yggdrasil.hosted-by.skhron.eu:8886?key=030602cee88a761c68f5f14e1dad430f25238a703b69dc382321a38f833035b0",
		"tcp://y.zbin.eu:7743",
		"tcp://yg-mel.magicum.net:23801",
		"tls://yg-ovb.magicum.net:32333",
		"tcp://yg-ovb.magicum.net:32332",
		"tls://yg-sin.magicum.net:23900",
		"tcp://yg-sin.magicum.net:23901",
		"tls://yg-syd.magicum.net:23700",
		"tcp://yg-syd.magicum.net:23701",
		"tls://yg-tyo.magicum.net:32333",
		"tcp://yg-tyo.magicum.net:32334",
		"tls://yg-vvo.magicum.net:29331",
		"tcp://yg-vvo.magicum.net:29330",
		"tcp://ygg-1.okade.pro:20000",
		"wss://ygg-evn-1.wgos.org:443",
		"tls://ygg-kcmo.incognet.io:8884",
		"tcp://ygg-kcmo.incognet.io:8883",
		"quic://ygg-kcmo.incognet.io:8885",
		"ws://ygg-kcmo.incognet.io:8886",
		"tls://ygg-ke.8px.sk:4321",
		"quic://ygg-ke.8px.sk:4321",
		"tls://ygg-pa.incognet.io:8884",
		"tcp://ygg-pa.incognet.io:8883",
		"quic://ygg-pa.incognet.io:8885",
		"ws://ygg-pa.incognet.io:8886",
		"tls://ygg-ro.axxa.dev:18080",
		"tls://ygg-wa.incognet.io:8884",
		"tcp://ygg-wa.incognet.io:8883",
		"quic://ygg-wa.incognet.io:8885",
		"ws://ygg-wa.incognet.io:8886",
		"tcp://ygg.bruijn.nu:65535",
		"quic://ygg.bruijn.nu:65535",
		"tls://ygg.jholden.org:1555",
		"tls://ygg.med-dev-systems.ru:6221",
		"tls://ygg.mkg20001.io:443",
		"tcp://ygg.mkg20001.io:80",
		"tls://ygg.mnpnk.com:443",
		"tls://ygg.nadeko.net:44442",
		"tcp://ygg.nadeko.net:44441",
		"tcp://ygg1.asriyan.me:23672",
		"tls://ygg1.grin.hu:42444",
		"ws://ygg1.grin.hu:42443",
		"tls://ygg1.mk16.de:1338?key=0000000087ee9949eeab56bd430ee8f324cad55abf3993ed9b9be63ce693e18a",
		"tcp://ygg1.mk16.de:1337?key=0000000087ee9949eeab56bd430ee8f324cad55abf3993ed9b9be63ce693e18a",
		"quic://ygg1.mk16.de:1339?key=0000000087ee9949eeab56bd430ee8f324cad55abf3993ed9b9be63ce693e18a",
		"ws://ygg1.mk16.de:1340?key=0000000087ee9949eeab56bd430ee8f324cad55abf3993ed9b9be63ce693e18a",
		"tls://ygg2.mk16.de:1338?key=000000d80a2d7b3126ea65c8c08fc751088c491a5cdd47eff11c86fa1e4644ae",
		"tcp://ygg2.mk16.de:1337?key=000000d80a2d7b3126ea65c8c08fc751088c491a5cdd47eff11c86fa1e4644ae",
		"quic://ygg2.mk16.de:1339?key=000000d80a2d7b3126ea65c8c08fc751088c491a5cdd47eff11c86fa1e4644ae",
		"ws://ygg2.mk16.de:1340?key=000000d80a2d7b3126ea65c8c08fc751088c491a5cdd47eff11c86fa1e4644ae",
		"tls://ygg3.mk16.de:1338?key=000003acdaf2a60e8de2f63c3e63b7e911d02380934f09ee5c83acb758f470c1",
		"tcp://ygg3.mk16.de:1337?key=000003acdaf2a60e8de2f63c3e63b7e911d02380934f09ee5c83acb758f470c1",
		"quic://ygg3.mk16.de:1339?key=000003acdaf2a60e8de2f63c3e63b7e911d02380934f09ee5c83acb758f470c1",
		"ws://ygg3.mk16.de:1340?key=000003acdaf2a60e8de2f63c3e63b7e911d02380934f09ee5c83acb758f470c1",
		"tls://ygg4.mk16.de:1338?key=000000573433e11f23768b078bcdc10b42712a7b131d6d04b82042ffc0c97df0",
		"tcp://ygg4.mk16.de:1337?key=000000573433e11f23768b078bcdc10b42712a7b131d6d04b82042ffc0c97df0",
		"quic://ygg4.mk16.de:1339?key=000000573433e11f23768b078bcdc10b42712a7b131d6d04b82042ffc0c97df0",
		"ws://ygg4.mk16.de:1340?key=000000573433e11f23768b078bcdc10b42712a7b131d6d04b82042ffc0c97df0",
		"tls://ygg5.mk16.de:1338?key=0000009611ae5391dc0aceea9f3fa6a0dc1279f4306059339e84bfb8b74d2f9b",
		"tcp://ygg5.mk16.de:1337?key=0000009611ae5391dc0aceea9f3fa6a0dc1279f4306059339e84bfb8b74d2f9b",
		"quic://ygg5.mk16.de:1339?key=0000009611ae5391dc0aceea9f3fa6a0dc1279f4306059339e84bfb8b74d2f9b",
		"ws://ygg5.mk16.de:1340?key=0000009611ae5391dc0aceea9f3fa6a0dc1279f4306059339e84bfb8b74d2f9b",
		"tls://ygg7.mk16.de:1338?key=000000086278b5f3ba1eb63acb5b7f6e406f04ce83990dee9c07f49011e375ae",
		"tcp://ygg7.mk16.de:1337?key=000000086278b5f3ba1eb63acb5b7f6e406f04ce83990dee9c07f49011e375ae",
		"quic://ygg7.mk16.de:1339?key=000000086278b5f3ba1eb63acb5b7f6e406f04ce83990dee9c07f49011e375ae",
		"ws://ygg7.mk16.de:1340?key=000000086278b5f3ba1eb63acb5b7f6e406f04ce83990dee9c07f49011e375ae",
		"tls://ygg8.mk16.de:1338?key=0000000b0683e38d8cb3085cfbf217edf0f0b2de76bb5ac7f02a94cd42a3fed9",
		"tcp://ygg8.mk16.de:1337?key=0000000b0683e38d8cb3085cfbf217edf0f0b2de76bb5ac7f02a94cd42a3fed9",
		"quic://ygg8.mk16.de:1339?key=0000000b0683e38d8cb3085cfbf217edf0f0b2de76bb5ac7f02a94cd42a3fed9",
		"ws://ygg8.mk16.de:1340?key=0000000b0683e38d8cb3085cfbf217edf0f0b2de76bb5ac7f02a94cd42a3fed9",
		"tls://yggdrasil.neilalexander.dev:64648?key=ecbbcb3298e7d3b4196103333c3e839cfe47a6ca47602b94a6d596683f6bb358",
		"tls://yggdrasil.su:62586",
		"tcp://yggdrasil.su:62486",
		"tls://yggdrasil.sunsung.fun:4443",
		"tcp://yggdrasil.sunsung.fun:4442",
		"quic://yggdrasil.sunsung.fun:4441",
		"tcp://Yggdrasil.UnderEu.Net:37001",
		"quic://Yggdrasil.UnderEu.Net:37003",
		"tls://yggno.de:18227",
		"tcp://yggno.de:18226",
		"tls://yggpeer.tilde.green:59454",
		"tcp://yggpeer.tilde.green:53299",
		"quic://yggpeer.tilde.green:62265")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if err := SaveJSON(path, c); err != nil {
		return nil, err
	}
	return c, nil
}

// -------- Ygg cfg/keys --------

type Node struct {
	mu        sync.RWMutex
	closed    bool
	Core      *ycore.Core
	Config    *ycfg.NodeConfig
	monCancel context.CancelFunc
	Net       *Netstack

	peerCancel context.CancelFunc // stops the background peer manager
	peers      peerSet            // full URIs of peers added to Core
	lan        *ymc.Multicast     // LAN discovery, nil when off
	direct     *directService     // answers direct-link requests, nil when off
}

// Netstack wraps an in-process gVisor TCP/IP stack bridged to the Yggdrasil core via ipv6rwc.
type Netstack struct {
	mu        sync.RWMutex
	closeOnce sync.Once
	Stack     *stack.Stack
	NICID     tcpip.NICID
	addr      tcpip.Address
	mtu       uint32
	rwc       io.ReadWriteCloser
	chEP      *channel.Endpoint
	stopCh    chan struct{}
	stopped   bool
}

func (n *Node) core() *ycore.Core {
	if n == nil {
		return nil
	}
	n.mu.RLock()
	defer n.mu.RUnlock()
	if n.closed {
		return nil
	}
	return n.Core
}

func (n *Node) netstack() *Netstack {
	if n == nil {
		return nil
	}
	n.mu.RLock()
	defer n.mu.RUnlock()
	if n.closed {
		return nil
	}
	if n.Net == nil || n.Net.isClosed() {
		return nil
	}
	return n.Net
}

func (ns *Netstack) isClosed() bool {
	if ns == nil {
		return true
	}
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	return ns.stopped
}

func (ns *Netstack) snapshot() (*stack.Stack, tcpip.NICID, tcpip.Address, error) {
	var zero tcpip.Address
	if ns == nil {
		return nil, 0, zero, fmt.Errorf("netstack not started")
	}
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	if ns.stopped || ns.Stack == nil {
		return nil, 0, zero, fmt.Errorf("netstack not started")
	}
	return ns.Stack, ns.NICID, ns.addr, nil
}

// AddrString returns our Ygg IPv6 as string.
func (ns *Netstack) AddrString() string {
	if ns == nil {
		return ""
	}
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	return ns.addr.String()
}

// Addr returns our Ygg IPv6 as net.IP.
func (ns *Netstack) Addr() net.IP {
	if ns == nil {
		return nil
	}
	ns.mu.RLock()
	addr := ns.addr.String()
	ns.mu.RUnlock()
	ip := net.ParseIP(addr)
	return ip
}

// Close stops pumps and releases resources.
func (ns *Netstack) Close() error {
	if ns == nil {
		return nil
	}
	ns.closeOnce.Do(func() {
		ns.mu.Lock()
		ns.stopped = true
		close(ns.stopCh)
		chEP := ns.chEP
		rwc := ns.rwc
		ns.chEP = nil
		ns.rwc = nil
		ns.Stack = nil
		ns.NICID = 0
		ns.mu.Unlock()

		if chEP != nil {
			chEP.Close()
		}
		if rwc != nil {
			_ = rwc.Close()
		}
		logV("[netstack] closed")
	})
	return nil
}

// ListenTCP exposes a net.Listener-like API backed by netstack.
func (ns *Netstack) ListenTCP(port int) (net.Listener, error) {
	st, nicID, addr, err := ns.snapshot()
	if err != nil {
		return nil, err
	}
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port %d", port)
	}
	logV("[p2p] [ns] listen tcp [%s]:%d", addr.String(), port)
	fa := tcpip.FullAddress{NIC: nicID, Addr: addr, Port: uint16(port)}
	ln, err := listenTCP(st, fa)
	if err != nil {
		return nil, err
	}
	return ln, nil
}

// DialTCP dials a remote Ygg IPv6 + port through the in-process stack.
func (ns *Netstack) DialTCP(peerIPv6 string, port int, timeout time.Duration) (net.Conn, error) {
	st, nicID, _, err := ns.snapshot()
	if err != nil {
		return nil, err
	}
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port %d", port)
	}
	s := strings.TrimSpace(peerIPv6)
	if len(s) > 0 && s[0] == '[' && s[len(s)-1] == ']' {
		s = s[1 : len(s)-1]
	}
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() != nil {
		return nil, fmt.Errorf("invalid IPv6 address: %q", peerIPv6)
	}
	ip = ip.To16()
	if ip == nil {
		return nil, fmt.Errorf("invalid IPv6 address: %q", peerIPv6)
	}
	// Check 0200::/7 (first 7 bits are 0b0010 000)
	if !in0200(ip) {
		return nil, fmt.Errorf("address %q not in 0200::/7", peerIPv6)
	}
	logV("[p2p] [ns] dial tcp [%s]:%d", ip.String(), port)
	var p16 [16]byte
	copy(p16[:], ip)
	rfa := tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFrom16(p16), Port: uint16(port)}

	// Apply optional timeout via context.
	ctx := context.Background()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	// gVisor TCP has Nagle off by default, so no TCP_NODELAY is needed.
	c, err := dialTCP(ctx, st, rfa)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// ListenUDP returns an unconnected UDP PacketConn bound to our Ygg IPv6. In gonet, DialUDP with raddr=nil yields an unconnected socket that supports ReadFrom/WriteTo.
func (ns *Netstack) ListenUDP(port int) (net.PacketConn, error) {
	st, nicID, addr, err := ns.snapshot()
	if err != nil {
		return nil, err
	}
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port %d", port)
	}
	// Bind a UDP endpoint without a remote; gonet.DialUDP(lfa, nil) returns an
	// unconnected PacketConn that supports ReadFrom/WriteTo.
	lfa := tcpip.FullAddress{NIC: nicID, Addr: addr, Port: uint16(port)}
	pc, err := gonet.DialUDP(st, &lfa, nil, ipv6.ProtocolNumber)
	if err != nil {
		return nil, err
	}
	logV("[p2p] [ns] listen udp [%s]:%d", addr.String(), port)
	return pc, nil
}

// DialUDP dials a remote Ygg IPv6 + port using UDP.
func (ns *Netstack) DialUDP(peerIPv6 string, port int, timeout time.Duration) (net.PacketConn, tcpip.FullAddress, error) {
	st, nicID, addr, err := ns.snapshot()
	if err != nil {
		return nil, tcpip.FullAddress{}, err
	}
	if port <= 0 || port > 65535 {
		return nil, tcpip.FullAddress{}, fmt.Errorf("invalid port %d", port)
	}
	s := strings.TrimSpace(peerIPv6)
	if len(s) > 0 && s[0] == '[' && s[len(s)-1] == ']' {
		s = s[1 : len(s)-1]
	}
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() != nil {
		return nil, tcpip.FullAddress{}, fmt.Errorf("invalid IPv6 address: %q", peerIPv6)
	}
	ip = ip.To16()
	if ip == nil {
		return nil, tcpip.FullAddress{}, fmt.Errorf("invalid IPv6 address: %q", peerIPv6)
	}
	if !in0200(ip) {
		return nil, tcpip.FullAddress{}, fmt.Errorf("address %q not in 0200::/7", peerIPv6)
	}
	var p16 [16]byte
	copy(p16[:], ip)
	rfa := tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFrom16(p16), Port: uint16(port)}

	// Bind ephemeral local UDP on our NIC/address.
	lfa := tcpip.FullAddress{NIC: nicID, Addr: addr}
	pc, err := gonet.DialUDP(st, &lfa, &rfa, ipv6.ProtocolNumber)
	if err != nil {
		return nil, tcpip.FullAddress{}, err
	}
	logV("[p2p] [ns] dial udp [%s]:%d", ip.String(), port)
	return pc, rfa, nil
}

// ListenTCP exposes a netstack-backed listener from the node.
func (n *Node) ListenTCP(port int) (net.Listener, error) {
	ns := n.netstack()
	if ns == nil {
		return nil, fmt.Errorf("netstack not started")
	}
	return ns.ListenTCP(port)
}

// DialTCP dials a peer via this node's netstack with a default timeout.
func (n *Node) DialTCP(peerIPv6 string, port int) (net.Conn, error) {
	ns := n.netstack()
	if ns == nil {
		return nil, fmt.Errorf("netstack not started")
	}
	return ns.DialTCP(peerIPv6, port, 10*time.Second)
}

// StartNetstack wires the Yggdrasil core to the gVisor netstack via an ipv6rwc/channel endpoint.
func (n *Node) StartNetstack() (*Netstack, error) {
	if n == nil {
		return nil, fmt.Errorf("ygg core not initialized")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed || n.Core == nil {
		return nil, fmt.Errorf("ygg core not initialized")
	}
	if n.Net != nil && !n.Net.isClosed() {
		return n.Net, nil
	}
	n.Net = nil

	core := n.Core
	// L3 R/W link to Ygg core.
	rwc := ipv6rwc.NewReadWriteCloser(core)
	// Use the largest MTU the core supports (like the Yggdrasil TUN default):
	// far fewer packets for bulk data.
	rwc.SetMTU(rwc.MaxMTU())
	mtu := uint32(rwc.MTU())
	ep := channel.New(4096, mtu, "ygg-chan")
	st := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocolCUBIC, udp.NewProtocol},
	})
	cleanup := true
	defer func() {
		if cleanup {
			ep.Close()
			_ = rwc.Close()
		}
	}()
	// Enlarge transport buffers to better absorb bursts.
	_ = st.SetOption(tcpip.ReceiveBufferSizeOption{Min: 4 << 10, Default: 512 << 10, Max: 4 << 20})
	_ = st.SetOption(tcpip.SendBufferSizeOption{Min: 4 << 10, Default: 512 << 10, Max: 4 << 20})
	_ = st.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpip.TCPReceiveBufferSizeRangeOption{Min: 4 << 10, Default: 256 << 10, Max: 4 << 20})
	_ = st.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpip.TCPSendBufferSizeRangeOption{Min: 4 << 10, Default: 256 << 10, Max: 4 << 20})
	nicID := tcpip.NICID(1)
	if err := st.CreateNIC(nicID, ep); err != nil {
		return nil, fmt.Errorf("create NIC: %v", err)
	}
	// Note: in this gVisor version, NIC is usable right after CreateNIC; no explicit SetNICUp.
	// Our Ygg /128 address.
	ya := core.Address() // net.IP
	if ya == nil || ya.To16() == nil || ya.To4() != nil {
		return nil, fmt.Errorf("bad ygg address")
	}
	y16 := ya.To16()
	if y16 == nil {
		return nil, fmt.Errorf("bad ygg v6 address")
	}
	var a16 [16]byte
	copy(a16[:], y16)
	yaddr := tcpip.AddrFrom16(a16)
	if err := st.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol: ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   yaddr,
			PrefixLen: 128,
		},
	}, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("add addr: %v", err)
	}
	logV("[netstack] nic=%d ready, route 200::/7 via nic", nicID)
	logV("[netstack] addr bound /128: %s", ya.String())
	// Default ::/0 via this NIC so all IPv6 traffic (including Ygg) has a path.
	st.AddRoute(tcpip.Route{Destination: header.IPv6Any.WithPrefix().Subnet(), NIC: nicID})

	// Our /64 on-link to prefer local-prefix peers.
	ap := tcpip.AddressWithPrefix{Address: yaddr, PrefixLen: 64}
	st.AddRoute(tcpip.Route{Destination: ap.Subnet(), NIC: nicID})

	// Explicit Ygg 200::/7 (optional but documents intent).
	var pfx200 [16]byte
	pfx200[0] = 0x02
	addr200 := tcpip.AddrFrom16(pfx200)
	sub200 := (tcpip.AddressWithPrefix{Address: addr200, PrefixLen: 7}).Subnet()
	st.AddRoute(tcpip.Route{Destination: sub200, NIC: nicID})
	ns := &Netstack{Stack: st, NICID: nicID, addr: yaddr, mtu: mtu, rwc: rwc, chEP: ep, stopCh: make(chan struct{})}
	n.Net = ns
	cleanup = false
	// TX pump: packets from netstack -> ygg core. Blocks until a packet is
	// queued or the netstack is closed.
	txCtx, txCancel := context.WithCancel(context.Background())
	go func() {
		<-ns.stopCh
		txCancel()
	}()
	go func() {
		var txBytes uint64
		defer func() { logV("[netstack] tx stopped, bytes=%d", txBytes) }()
		// One reused buffer: the core copies the packet (ipv6rwc and
		// Core.WriteTo both copy), so nothing is allocated per packet.
		buf := make([]byte, 0, mtu)
		for {
			pkt := ep.ReadContext(txCtx)
			if pkt == nil {
				return
			}
			buf = buf[:0]
			for _, s := range pkt.AsSlices() {
				buf = append(buf, s...)
			}
			pkt.DecRef()
			if len(buf) == 0 {
				continue
			}
			// A packet is written whole or not at all. On error drop it, as
			// any IP hop would: retrying would stall all traffic behind it.
			if _, err := rwc.Write(buf); err != nil {
				logV("[netstack] tx: drop packet: %v", err)
				continue
			}
			txBytes += uint64(len(buf))
		}
	}()
	// RX pump: frames from ygg core -> netstack.
	go func() {
		var rxBytes uint64
		defer func() { logV("[netstack] rx stopped, bytes=%d", rxBytes) }()
		buf := make([]byte, mtu)
		for {
			select {
			case <-ns.stopCh:
				return
			default:
			}
			nread, err := rwc.Read(buf)
			if err != nil {
				if err == io.EOF || err == io.ErrClosedPipe || strings.Contains(err.Error(), "closed") {
					return
				}
				logV("[netstack] rx read error: %v", err)
				time.Sleep(10 * time.Millisecond)
				continue
			}
			if nread <= 0 {
				continue
			}
			rxBytes += uint64(nread)
			// MakeWithData copies, so buf can be reused.
			pb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(buf[:nread])})
			ep.InjectInbound(header.IPv6ProtocolNumber, pb)
			pb.DecRef()
		}
	}()
	logV("[netstack] up: addr=%s mtu=%d", ya.String(), mtu)
	return ns, nil
}

// ErrNotConnected is returned when an operation requires an active Ygg link
// (at least one Up peer), but the node currently has none.
var ErrNotConnected = errors.New("ygg: not connected")

// Connected reports whether the node currently has at least one Up peer.
func (n *Node) Connected() bool {
	core := n.core()
	if core == nil {
		return false
	}
	return hasUp(core)
}

// WaitConnected blocks until the node has at least one Up peer or the context
// is cancelled. The check runs at the given interval; if interval <= 0, 500ms
// is used. Returns nil when connected, ctx.Err() on cancellation/timeout.
func (n *Node) WaitConnected(ctx context.Context, interval time.Duration) error {
	if n == nil {
		return ErrNotConnected
	}
	core := n.core()
	if core == nil {
		return ErrNotConnected
	}
	if interval <= 0 {
		interval = 500 * time.Millisecond
	}
	// Fast path: already connected
	if hasUp(core) {
		return nil
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			core = n.core()
			if core == nil {
				return ErrNotConnected
			}
			if hasUp(core) {
				return nil
			}
			// Nudge the core to retry peers faster while we wait
			core.RetryPeersNow()
		}
	}
}

// Close attempts to gracefully stop the underlying core, if supported.
func (n *Node) Close() error {
	if n == nil {
		return nil
	}

	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return nil
	}
	n.closed = true
	cancel := n.monCancel
	n.monCancel = nil
	peerCancel := n.peerCancel
	n.peerCancel = nil
	netstack := n.Net
	n.Net = nil
	core := n.Core
	n.Core = nil
	lan := n.lan
	n.lan = nil
	direct := n.direct
	n.direct = nil
	n.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if peerCancel != nil {
		peerCancel()
	}

	if direct != nil {
		direct.close()
	}
	if netstack != nil {
		_ = netstack.Close()
	}
	if lan != nil {
		_ = lan.Stop()
	}
	if core != nil {
		core.Stop()
	}

	stateMu.Lock()
	if defaultNode == n {
		defaultNode = nil
	}
	stateMu.Unlock()

	return nil
}

// startConnectivityMonitor launches a lightweight connectivity watcher.
// It sends an initial state and then only on changes. Callers stop it via Close().
func (n *Node) startConnectivityMonitor(interval time.Duration) bool {
	if n == nil {
		return false
	}
	if interval <= 0 {
		interval = 3 * time.Second
	}

	n.mu.Lock()
	if n.closed || n.Core == nil || n.monCancel != nil {
		n.mu.Unlock()
		return false
	}
	core := n.Core
	ctx, cancel := context.WithCancel(context.Background())
	n.monCancel = cancel
	n.mu.Unlock()

	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()

		prev := hasUp(core)
		notifyConnectivity(prev)

		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				cur := hasUp(core)
				if cur != prev {
					prev = cur
					notifyConnectivity(cur)
				}
			}
		}
	}()
	return true
}

func (n *Node) stopConnectivityMonitor() {
	if n == nil {
		return
	}
	n.mu.Lock()
	cancel := n.monCancel
	n.monCancel = nil
	n.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// PrepareYggConfig generates or loads keys into ycfg.NodeConfig.
func PrepareYggConfig(app *AppConfig) (*ycfg.NodeConfig, error) {
	cfg := ycfg.GenerateConfig() // sane defaults; will be overridden below.

	loadedExisting := false

	// Step 1: read key in multiple formats (hex or base64/base64url, 32/64 bytes).
	if s := strings.TrimSpace(app.Seed); s != "" {
		var raw []byte
		if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
			raw = b
		} else if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
			raw = b
		} else if b, err := hex.DecodeString(s); err == nil {
			raw = b
		} else {
			return nil, fmt.Errorf("bad inline_key value: not base64/base64url or hex: %w", err)
		}
		switch len(raw) {
		case 32: // seed -> derive full key
			k := ed25519.NewKeyFromSeed(raw)
			cfg.PrivateKey = ycfg.KeyBytes(k)
		case ed25519.PrivateKeySize: // 64 bytes full key -> treat as seed+pub, rebuild from seed
			k := ed25519.NewKeyFromSeed(raw[:32])
			cfg.PrivateKey = ycfg.KeyBytes(k)
		default:
			return nil, fmt.Errorf("inline_key_hex has unexpected length %d (want 32 or 64 bytes)", len(raw))
		}
		// Step 2: standardize config to a 32-byte base64url seed.
		seed := []byte(cfg.PrivateKey)[:32]
		app.Seed = base64.RawURLEncoding.EncodeToString(seed)
		loadedExisting = true
	}

	// Step 3: if no key was loaded, generate a new one.
	if !loadedExisting {
		_, genPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate ed25519 key: %w", err)
		}
		cfg.PrivateKey = ycfg.KeyBytes(genPriv)
		// Store only the 32-byte seed to keep config compact.
		app.Seed = base64.RawURLEncoding.EncodeToString([]byte(cfg.PrivateKey)[:32])
		logV("generated new private key (saved to config.json)")
	} else {
		logV("using private key from config.json")
	}

	// Step 4: ensure the core has a TLS certificate.
	if cfg.Certificate == nil {
		if err := cfg.GenerateSelfSignedCertificate(); err != nil {
			return nil, err
		}
	}

	return cfg, nil
}

// startCore creates a core with the key from cfg and no peers.
func startCore(cfg *ycfg.NodeConfig, logger ycore.Logger) (*ycore.Core, error) {
	// Force core to use the same ed25519 key as in cfg.PrivateKey (ignore cfg.Certificate).
	if len(cfg.PrivateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("cfg.PrivateKey length=%d, want %d", len(cfg.PrivateKey), ed25519.PrivateKeySize)
	}
	cert, err := certFromPrivateKey(ed25519.PrivateKey(cfg.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("make cert: %w", err)
	}

	// Build setup options from cfg.
	var opts []ycore.SetupOption
	if cfg.NodeInfo != nil {
		opts = append(opts, ycore.NodeInfo(cfg.NodeInfo))
	}
	if cfg.NodeInfoPrivacy {
		opts = append(opts, ycore.NodeInfoPrivacy(true))
	}
	for _, la := range cfg.Listen {
		la = strings.TrimSpace(la)
		if la != "" {
			opts = append(opts, ycore.ListenAddress(la))
		}
	}
	for _, hexKey := range cfg.AllowedPublicKeys {
		hexKey = strings.TrimSpace(hexKey)
		if hexKey == "" {
			continue
		}
		b, err := hex.DecodeString(hexKey)
		if err == nil && len(b) == ed25519.PublicKeySize {
			opts = append(opts, ycore.AllowedPublicKey(ed25519.PublicKey(b)))
		}
	}

	// Note: we do not request OS TUN here. The process runs in user-space mode
	// and exposes L3 via ipv6rwc to an in-process netstack (configured elsewhere).
	return ycore.New(cert, logger, opts...)
}

// StartAndConnect starts the core and adds peers batch by batch until the
// first one completes the Yggdrasil handshake. It does not run the background
// peer manager; New does.
func StartAndConnect(cfg *ycfg.NodeConfig, peers []string, logger ycore.Logger) (*Node, error) {
	core, err := startCore(cfg, logger)
	if err != nil {
		return nil, err
	}
	node := &Node{Core: core, Config: cfg}
	ctx, cancel := context.WithTimeout(context.Background(), startTimeout)
	defer cancel()
	if err := connectFirst(ctx, core, &node.peers, peers); err != nil {
		core.Stop()
		return nil, fmt.Errorf("connect: %w", err)
	}
	return node, nil
}

// startPeerManager runs runPeerManager until Close.
func (n *Node) startPeerManager(cfgPath string, lastFull time.Time) {
	ctx, cancel := context.WithCancel(context.Background())
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		cancel()
		return
	}
	n.peerCancel = cancel
	n.mu.Unlock()
	go n.runPeerManager(ctx, cfgPath, lastFull)
}

// ListenTCP listens on the current default node's user-space netstack.
func ListenTCP(port int) (net.Listener, error) {
	node := getDefaultNode()
	if node == nil || node.netstack() == nil {
		return nil, fmt.Errorf("ygg: default node not initialized")
	}
	return node.ListenTCP(port)
}

// DialTCP dials a peer over the current default node's user-space netstack.
func DialTCP(peerIPv6 string, port int) (net.Conn, error) {
	node := getDefaultNode()
	if node == nil || node.netstack() == nil {
		return nil, fmt.Errorf("ygg: default node not initialized")
	}
	return node.DialTCP(peerIPv6, port)
}

// ListenUDP listens on the current default node's user-space netstack and returns
// a PacketConn bound to our Ygg IPv6 on the given port. Packets can be ReadFrom/WriteTo.
func ListenUDP(port int) (net.PacketConn, error) {
	node := getDefaultNode()
	if node == nil {
		return nil, fmt.Errorf("ygg: default node not initialized")
	}
	ns := node.netstack()
	if ns == nil {
		return nil, fmt.Errorf("ygg: default node not initialized")
	}
	return ns.ListenUDP(port)
}

// DialUDP dials a peer over the current default node's user-space netstack and returns
// a connected PacketConn (Write/Read without specifying addr each time).
func DialUDP(peerIPv6 string, port int) (net.PacketConn, error) {
	node := getDefaultNode()
	if node == nil {
		return nil, fmt.Errorf("ygg: default node not initialized")
	}
	ns := node.netstack()
	if ns == nil {
		return nil, fmt.Errorf("ygg: default node not initialized")
	}
	pc, _, err := ns.DialUDP(peerIPv6, port, 10*time.Second)
	return pc, err
}

// in0200 reports whether ip is in 0200::/7 (Yggdrasil space).
func in0200(ip net.IP) bool {
	b := ip.To16()
	if b == nil {
		return false
	}
	// 0200::/7 means the top 7 bits equal 0b0010 000.
	// Accept 0x20xx (0010 0000) and 0x30xx (0011 0000) as commonly used by Yggdrasil.
	return b[0]&0xFE == 0x02
}
