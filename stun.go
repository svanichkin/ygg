package ygg

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"time"
)

// A minimal STUN client (RFC 5389): a Binding request tells a node behind a
// NAT the public address and port its UDP socket is seen from. That address is
// one of the candidates direct links punch through (see direct.go).

// stunServers are public STUN servers on UDP; any one answering is enough.
var stunServers = []string{
	"stun.l.google.com:19302",
	"stun1.l.google.com:19302",
	"stun.cloudflare.com:3478",
	"stun.sipnet.ru:3478",
}

const (
	stunMagic          = 0x2112A442
	stunBindingRequest = 0x0001
	stunBindingSuccess = 0x0101
	stunMappedAddr     = 0x0001
	stunXorMappedAddr  = 0x0020
	stunHeaderLen      = 20

	stunResend = 500 * time.Millisecond // requests are resent this often
	stunSettle = 300 * time.Millisecond // wait for more answers after the first
)

// stunRequest returns a Binding request with a random transaction ID.
func stunRequest() (req []byte, txid [12]byte) {
	_, _ = rand.Read(txid[:])
	req = make([]byte, stunHeaderLen)
	binary.BigEndian.PutUint16(req[0:], stunBindingRequest)
	binary.BigEndian.PutUint32(req[4:], stunMagic)
	copy(req[8:], txid[:])
	return req, txid
}

var errSTUN = errors.New("not a STUN binding response")

// parseSTUNResponse returns the mapped address of a Binding success response
// to the request with transaction ID txid.
func parseSTUNResponse(p []byte, txid [12]byte) (netip.AddrPort, error) {
	if len(p) < stunHeaderLen || binary.BigEndian.Uint16(p) != stunBindingSuccess ||
		binary.BigEndian.Uint32(p[4:]) != stunMagic || !bytes.Equal(p[8:20], txid[:]) {
		return netip.AddrPort{}, errSTUN
	}
	n := int(binary.BigEndian.Uint16(p[2:]))
	if stunHeaderLen+n > len(p) {
		return netip.AddrPort{}, errSTUN
	}
	attrs := p[stunHeaderLen : stunHeaderLen+n]
	var mapped netip.AddrPort
	for len(attrs) >= 4 {
		typ := binary.BigEndian.Uint16(attrs)
		l := int(binary.BigEndian.Uint16(attrs[2:]))
		if 4+l > len(attrs) {
			break
		}
		v := attrs[4 : 4+l]
		switch typ {
		case stunXorMappedAddr:
			if ap, ok := stunAddr(v, true, p[4:20]); ok {
				return ap, nil
			}
		case stunMappedAddr:
			if ap, ok := stunAddr(v, false, nil); ok {
				mapped = ap
			}
		}
		attrs = attrs[4+(l+3)&^3:] // attributes are padded to 4 bytes
	}
	if mapped.IsValid() {
		return mapped, nil
	}
	return netip.AddrPort{}, errSTUN
}

// stunAddr decodes a (XOR-)MAPPED-ADDRESS value; key is the magic cookie and
// transaction ID the XOR variant is masked with.
func stunAddr(v []byte, xor bool, key []byte) (netip.AddrPort, bool) {
	if len(v) < 4 {
		return netip.AddrPort{}, false
	}
	port := binary.BigEndian.Uint16(v[2:])
	var ip []byte
	switch v[1] {
	case 1:
		ip = append([]byte(nil), v[4:min(8, len(v))]...)
		if len(ip) != 4 {
			return netip.AddrPort{}, false
		}
	case 2:
		ip = append([]byte(nil), v[4:min(20, len(v))]...)
		if len(ip) != 16 {
			return netip.AddrPort{}, false
		}
	default:
		return netip.AddrPort{}, false
	}
	if xor {
		port ^= uint16(stunMagic >> 16)
		for i := range ip {
			ip[i] ^= key[i]
		}
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(addr.Unmap(), port), true
}

// stunDiscover asks the STUN servers which public addresses conn is seen
// from. It sends to all of them at once (resent every stunResend) and
// returns what came back up to stunSettle after the first answer: usually one
// IPv4 address, plus an IPv6 one where the network has it. Several different
// IPv4 addresses or ports mean a NAT that maps every destination apart, which
// hole punching rarely gets through. It reads conn, so it must run before
// anything else does.
func stunDiscover(ctx context.Context, conn *net.UDPConn) []netip.AddrPort {
	type query struct {
		addr *net.UDPAddr
		req  []byte
		txid [12]byte
	}
	var queries []query
	for _, s := range stunServers {
		host, port, err := net.SplitHostPort(s)
		if err != nil {
			continue
		}
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			continue
		}
		seen := map[bool]bool{} // one query per family per server
		for _, ip := range ips {
			v4 := ip.IP.To4() != nil
			if seen[v4] {
				continue
			}
			seen[v4] = true
			ua, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ip.IP.String(), port))
			if err != nil {
				continue
			}
			req, txid := stunRequest()
			queries = append(queries, query{ua, req, txid})
		}
	}
	if len(queries) == 0 {
		return nil
	}
	send := func() {
		for _, q := range queries {
			_, _ = conn.WriteToUDP(q.req, q.addr)
		}
	}
	send()
	var found []netip.AddrPort
	have := map[netip.AddrPort]bool{}
	answered := 0
	buf := make([]byte, 1500)
	resend := time.Now().Add(stunResend)
	var settle time.Time // the first answer came: the rest get stunSettle more
	deadline, _ := ctx.Deadline()
	for answered < len(queries) && ctx.Err() == nil {
		wake := resend
		if !settle.IsZero() && settle.Before(wake) {
			wake = settle
		}
		if !deadline.IsZero() && deadline.Before(wake) {
			wake = deadline
		}
		_ = conn.SetReadDeadline(wake)
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
				break
			}
			now := time.Now()
			if !settle.IsZero() && !now.Before(settle) {
				break
			}
			if !now.Before(resend) {
				send()
				resend = now.Add(stunResend)
			}
			continue
		}
		for _, q := range queries {
			ap, err := parseSTUNResponse(buf[:n], q.txid)
			if err != nil {
				continue
			}
			answered++
			if settle.IsZero() {
				settle = time.Now().Add(stunSettle)
			}
			if !have[ap] {
				have[ap] = true
				found = append(found, ap)
			}
			break
		}
	}
	_ = conn.SetReadDeadline(time.Time{})
	return found
}
