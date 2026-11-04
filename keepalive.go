package ygg

import (
	"context"
	"errors"
	"net"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// TCP keepalive: an idle connection to a node that vanished (no FIN or RST,
// e.g. the phone lost the network) is closed after about
// keepaliveIdle + keepaliveInterval*keepaliveCount instead of hanging forever.
// Variables so tests can shorten them.
var (
	keepaliveIdle     = 30 * time.Second
	keepaliveInterval = 10 * time.Second
	keepaliveCount    = 3
)

func setKeepalive(ep tcpip.Endpoint) {
	idle := tcpip.KeepaliveIdleOption(keepaliveIdle)
	interval := tcpip.KeepaliveIntervalOption(keepaliveInterval)
	_ = ep.SetSockOpt(&idle)
	_ = ep.SetSockOpt(&interval)
	_ = ep.SetSockOptInt(tcpip.KeepaliveCountOption, keepaliveCount)
	ep.SocketOptions().SetKeepAlive(true)
}

// dialTCP is gonet.DialContextTCP with keepalive on. It is turned on after
// the handshake: gVisor starts the keepalive timer only when the option is
// set on an established connection.
func dialTCP(ctx context.Context, s *stack.Stack, addr tcpip.FullAddress) (net.Conn, error) {
	var wq waiter.Queue
	ep, terr := s.NewEndpoint(tcp.ProtocolNumber, ipv6.ProtocolNumber, &wq)
	if terr != nil {
		return nil, errors.New(terr.String())
	}

	entry, notify := waiter.NewChannelEntry(waiter.WritableEvents)
	wq.EventRegister(&entry)
	defer wq.EventUnregister(&entry)

	terr = ep.Connect(addr)
	if _, ok := terr.(*tcpip.ErrConnectStarted); ok {
		select {
		case <-ctx.Done():
			ep.Close()
			return nil, ctx.Err()
		case <-notify:
		}
		terr = ep.LastError()
	}
	if terr != nil {
		ep.Close()
		return nil, &net.OpError{Op: "connect", Net: "tcp", Addr: tcpAddr(addr), Err: errors.New(terr.String())}
	}
	setKeepalive(ep)
	return gonet.NewTCPConn(&wq, ep), nil
}

// listenTCP is gonet.ListenTCP whose accepted connections have keepalive on
// (gVisor does not copy it from the listening endpoint).
func listenTCP(s *stack.Stack, addr tcpip.FullAddress) (net.Listener, error) {
	var wq waiter.Queue
	ep, terr := s.NewEndpoint(tcp.ProtocolNumber, ipv6.ProtocolNumber, &wq)
	if terr != nil {
		return nil, errors.New(terr.String())
	}
	if terr := ep.Bind(addr); terr != nil {
		ep.Close()
		return nil, &net.OpError{Op: "bind", Net: "tcp", Addr: tcpAddr(addr), Err: errors.New(terr.String())}
	}
	if terr := ep.Listen(4096); terr != nil {
		ep.Close()
		return nil, &net.OpError{Op: "listen", Net: "tcp", Addr: tcpAddr(addr), Err: errors.New(terr.String())}
	}
	return &tcpListener{TCPListener: gonet.NewTCPListener(s, &wq, ep), ep: ep, wq: &wq}, nil
}

// tcpListener reuses gonet's Close and Addr and replaces Accept.
type tcpListener struct {
	*gonet.TCPListener
	ep tcpip.Endpoint
	wq *waiter.Queue
}

func (l *tcpListener) Accept() (net.Conn, error) {
	entry, notify := waiter.NewChannelEntry(waiter.ReadableEvents)
	l.wq.EventRegister(&entry)
	defer l.wq.EventUnregister(&entry)
	for {
		n, wq, terr := l.ep.Accept(nil)
		if _, ok := terr.(*tcpip.ErrWouldBlock); ok {
			<-notify // also fires when the listener is closed
			continue
		}
		if terr != nil {
			return nil, &net.OpError{Op: "accept", Net: "tcp", Addr: l.Addr(), Err: errors.New(terr.String())}
		}
		setKeepalive(n)
		return gonet.NewTCPConn(wq, n), nil
	}
}

func tcpAddr(a tcpip.FullAddress) *net.TCPAddr {
	return &net.TCPAddr{IP: net.IP(a.Addr.AsSlice()), Port: int(a.Port)}
}
