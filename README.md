# Ygg

Ygg is a lightweight Go library that embeds a self-contained Yggdrasil node — allowing your Go application to automatically connect to the Yggdrasil network without running an external daemon.

## Features

- 🧩 **Embedded Yggdrasil core** — starts and manages an in-process Yggdrasil node.
- ⚙️ **Automatic configuration** — generates or loads `config.json` automatically.
- 🌐 **Peer selection** — keeps only the fastest peers that complete a real Yggdrasil handshake (see below).
- 📡 **Graceful shutdown** — stop the node cleanly with `node.Close()`.
- 🪶 **Library-friendly API** — import and start with a single call.
- 🔔 **Connectivity events** — receive callbacks when the node connects or disconnects.
- 🏠 **LAN discovery** — nodes in one local network find each other and peer directly, optionally only with a shared password.

## Installation

```bash
go get github.com/svanichkin/ygg
```

## Usage

```go
package main

import (
    "log"
    ygg "github.com/svanichkin/ygg"
)

func main() {
    ygg.SetVerbose(true)

    ygg.SetConnectivityHandler(func(connected bool) {
        if connected {
            log.Println("[ygg] Connected to the network")
        } else {
            log.Println("[ygg] Disconnected from the network")
        }
    })

    // Pass a custom path or leave empty to auto-locate config.json
    node, err := ygg.New("")
    if err != nil {
        log.Fatal(err)
    }
    defer node.Close()

    log.Println("Connected to Yggdrasil!", node.Core.Address())
}
```

## Configuration

When `New()` is called, the library automatically searches for `config.json` in:

1. The same directory as the binary
2. `$HOME/.config/say/config.json`

If none is found, a new configuration is generated.

| Field | Meaning |
|-------|---------|
| `seed` | Private key seed (base64url). Generated on first run. |
| `peers` | Peer list. A new config starts with a built-in list; after the first check it holds only the best verified peers, ordered by RTT. |
| `peers_checked_at` | When all candidates were last re-checked. |
| `lan` | `true` turns on peer discovery in the local network (off by default). |
| `lan_password` | Only nodes with the same password peer in the local network. Empty: any Yggdrasil node. At most 64 bytes. |

## Peer Selection

A peer counts as alive only when the Yggdrasil handshake with it has completed
and the router has measured its RTT. A plain TCP connect is not used: DPI boxes
can answer with a forged SYN-ACK, so dead ports look open — and, since the
forged answer comes from nearby, such fake peers would look the fastest.

1. **Start.** Saved peers are added to the core; `New()` returns as soon as one
   completes the handshake (typically ~2 RTT, under 0.2 s). If none does within
   5 s, the public list (`publicpeers.neilalexander.dev`) is tried in batches
   of 60, with its own 60 s budget; the saved peers keep trying meanwhile.
2. **Prune.** After a cold start, 20 s later the node keeps the best of the
   peers it has measured and drops the rest.
3. **Re-check.** In the background, all candidates (saved + public list) are
   checked in batches on a separate short-lived core, so the live node is not
   disturbed. The best ones are applied to the node and saved to the config:
   - sorted by measured RTT, at most `SetMaxPeers` (default 8);
   - one link per host (tcp/tls/quic of one machine count as one);
   - peers slower than 4× the best (but not below 100 ms) are dropped,
     while at least 3 peers are kept.

   Old peers are removed only after a selected one is up. The re-check runs
   every 6 hours, and earlier if fewer than 2 peers stay up.

## LAN Discovery

Nodes in one local network (one Wi-Fi or Ethernet segment) can find each other
by link-local IPv6 multicast beacons and peer directly — no internet and no
public peers needed. This is the standard Yggdrasil multicast discovery.

```go
ygg.SetLAN(true, "my-secret") // before New(); overrides lan / lan_password in config.json
node, err := ygg.New("")
```

- **Password.** With a password, only nodes with the same password peer with
  each other; without one, the node peers with any Yggdrasil node in the
  network. The password protects only these local links: the node is still
  part of the whole Yggdrasil network through its internet peers.
- **Offline start.** With LAN discovery on, `New()` returns even when no
  internet peer comes up (offline: after ~5–10 s of trying), so nodes in a
  network without internet still find each other.
- **Peer selection** does not touch LAN links: they are never ranked, saved to
  the config or removed, and do not count towards the health of the internet
  connection. `Connected()` does count them.
- **Interfaces** are the Yggdrasil platform defaults (macOS: `en*`, `bridge*`;
  Linux: all).
- **Mobile.** iOS needs the `com.apple.developer.networking.multicast`
  entitlement; Android needs a `WifiManager.MulticastLock` held while the node
  runs.

## Netstack

Traffic to other Yggdrasil nodes goes through an in-process gVisor TCP/IP
stack (`ListenTCP`, `DialTCP`, `ListenUDP`, `DialUDP`), no OS TUN device.

- **MTU** is the largest the core supports (65535, like the Yggdrasil TUN
  default), and TCP uses CUBIC. Bulk TCP between two nodes on localhost:
  ~25 MB/s with the old 1280 MTU, 200+ MB/s now; a small request/response
  round trip: ~0.15 ms. Nodes before v0.5.6 used MTU 1280 and are not
  compatible for UDP datagrams over ~1230 bytes.
- **TCP keepalive** is on for dialed and accepted connections: an idle
  connection to a node that vanished (no FIN/RST, e.g. a phone that lost the
  network) is closed after ~60 s (30 s idle + 3 probes 10 s apart) instead of
  hanging forever.

Benchmarks: `go test -run x -bench Netstack`.

## Environment and Dependencies

- **Language:** Go 1.27.3+
- **Dependencies:**
  - `github.com/yggdrasil-network/yggdrasil-go` v0.5.15
  - `gvisor.dev/gvisor` (in-process TCP/IP netstack, `go` branch)

> **Note on gVisor:** always update it with `go get gvisor.dev/gvisor@go`.
> A plain `go get -u ./...` pulls the `master` branch, which does not build
> with the Go toolchain (it requires Bazel-generated files).

## API Overview

| Function | Description |
|-----------|-------------|
| `New(cfgPath string)` | Initializes and starts a Yggdrasil node, returning `*Node`. |
| `(*Node).Close()` | Gracefully stops the running node. |
| `SetVerbose(v bool)` | Enables verbose logging. |
| `SetLAN(enabled bool, password string)` | Turns LAN discovery on/off and sets its password (overrides the config). |
| `SetMaxPeers(n int)` | How many best peers to keep (default 8, `n <= 0` keeps every reachable one). |
| `StartAndConnect(cfg, peers, logger)` | Low-level: starts a core and returns once the first peer is up (no background selection). |
| `(*Node).Connected()` | Reports whether at least one peer has completed the handshake. |
| `SetConnectivityHandler(func(connected bool))` | Registers a callback for connection state changes. |

## Connectivity Events

The library can notify your application whenever the embedded node changes its connection status.

```go
ygg.SetConnectivityHandler(func(connected bool) {
    if connected {
        log.Println("Yggdrasil network is up")
    } else {
        log.Println("Yggdrasil network is down")
    }
})
```

The callback runs in a background goroutine. The first notification reflects the current state at startup, and further calls are made only when the state changes.
