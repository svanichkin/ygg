# Ygg

Ygg is a lightweight Go library that embeds a self-contained Yggdrasil node — allowing your Go application to automatically connect to the Yggdrasil network without running an external daemon.

## Features

- 🧩 **Embedded Yggdrasil core** — starts and manages an in-process Yggdrasil node.
- ⚙️ **Automatic configuration** — generates or loads `config.json` automatically.
- 🌐 **Peer discovery** — fetches peers from a public list and filters alive nodes.
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

## Environment and Dependencies

- **Language:** Go 1.25.5+
- **Dependencies:**
  - `github.com/yggdrasil-network/yggdrasil-go`

## API Overview

| Function | Description |
|-----------|-------------|
| `New(cfgPath string)` | Initializes and starts a Yggdrasil node, returning `*Node`. |
| `(*Node).Close()` | Gracefully stops the running node. |
| `SetVerbose(v bool)` | Enables verbose logging. |
| `SetMaxPeers(n int)` | Sets the maximum number of peers added at startup. |
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
