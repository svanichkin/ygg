package ygg

import (
	"crypto/ed25519"
	"net"

	"github.com/yggdrasil-network/yggdrasil-go/src/address"
)

// Fresh routes.
//
// A node keeps the path it found to another node for up to a minute while
// packets go along it (ironwood's pathTimeout). When the other node moves in
// the tree (its links dropped and came back, through other peers or another
// network), the old path can lead nowhere without anyone telling the
// sender: packets are lost until the minute is up. Calls went unanswered for
// 45 s after the far end's network came back. So a node asks for a fresh
// path (a lookup; at most one a second per destination) when a dial to a
// node goes unanswered, and to every node it has a path to when its own
// links come back.

// RefreshRoute asks the network for a fresh path to the node at peerIPv6
// (the default node). It reports whether a path to it was known.
func RefreshRoute(peerIPv6 string) bool {
	return getDefaultNode().RefreshRoute(peerIPv6)
}

// RefreshRoute asks the network for a fresh path to the node at peerIPv6.
func (n *Node) RefreshRoute(peerIPv6 string) bool {
	ip := net.ParseIP(trimBrackets(peerIPv6))
	core := n.core()
	if ip == nil || core == nil {
		return false
	}
	for _, key := range n.routedKeys() {
		if net.IP(address.AddrForKey(key)[:]).Equal(ip) {
			core.PacketConn.PacketConn.SendLookup(key)
			return true
		}
	}
	return false
}

// refreshAllRoutes asks for fresh paths to every node a path is known to.
func (n *Node) refreshAllRoutes() int {
	core := n.core()
	if core == nil {
		return 0
	}
	keys := n.routedKeys()
	for _, key := range keys {
		core.PacketConn.PacketConn.SendLookup(key)
	}
	return len(keys)
}

// routedKeys are the keys of the nodes this node has paths or sessions to.
func (n *Node) routedKeys() []ed25519.PublicKey {
	core := n.core()
	if core == nil {
		return nil
	}
	seen := map[string]bool{}
	var keys []ed25519.PublicKey
	add := func(k ed25519.PublicKey) {
		if len(k) == ed25519.PublicKeySize && !seen[string(k)] {
			seen[string(k)] = true
			keys = append(keys, k)
		}
	}
	for _, p := range core.GetPaths() {
		add(p.Key)
	}
	for _, s := range core.GetSessions() {
		add(s.Key)
	}
	return keys
}
