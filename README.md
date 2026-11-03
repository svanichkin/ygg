# Ygg

Ygg is a lightweight Go library that embeds a self-contained Yggdrasil node — allowing your Go application to automatically connect to the Yggdrasil network without running an external daemon.

## Features

- 🧩 **Embedded Yggdrasil core** — starts and manages an in-process Yggdrasil node.
- ⚙️ **Automatic configuration** — generates or loads `config.json` automatically.
- 🌐 **Peer selection** — keeps only the fastest peers that complete a real Yggdrasil handshake (see below).
- 📡 **Graceful shutdown** — stop the node cleanly with `node.Close()`.
- 🪶 **Library-friendly API** — import and start with a single call.
- 🔔 **Connectivity events** — receive callbacks when the node connects or disconnects.

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

## Peer Selection

A peer counts as alive only when the Yggdrasil handshake with it has completed
and the router has measured its RTT. A plain TCP connect is not used: DPI boxes
can answer with a forged SYN-ACK, so dead ports look open — and, since the
forged answer comes from nearby, such fake peers would look the fastest.

1. **Start.** Saved peers are added to the core; `New()` returns as soon as one
   completes the handshake (usually well under a second). If none does, the
   public list (`publicpeers.neilalexander.dev`) is tried in batches of 60.
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
