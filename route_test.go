package ygg

import "testing"

// A node that talked to another can ask for a fresh path to it; one it
// never talked to is unknown.
func TestRefreshRoute(t *testing.T) {
	if testing.Short() {
		t.Skip("starts real Yggdrasil cores")
	}
	server, client := netstackPair(t)
	ln, err := server.ListenTCP(7010)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			c.Close()
		}
	}()
	c := dialRetry(t, client, server, 7010)
	c.Close()
	if !client.RefreshRoute(server.Core.Address().String()) {
		t.Fatal("no path known to a node just dialled")
	}
	if client.RefreshRoute("200:1234::1") {
		t.Fatal("a path to a node never reached")
	}
	if client.refreshAllRoutes() == 0 {
		t.Fatal("refreshAllRoutes found no paths")
	}
	// Dials go on working after the lookups.
	c = dialRetry(t, client, server, 7010)
	c.Close()
}
