// main.go — minimal libp2p relay (uses built-in go-libp2p transports)
package main

import (
    "context"
    "fmt"
    "log"
    "os"
    "os/signal"
    "syscall"
    "time"

    libp2p "github.com/libp2p/go-libp2p"
    "github.com/libp2p/go-libp2p/core/crypto"
    "github.com/libp2p/go-libp2p/core/peer"
    "github.com/libp2p/go-libp2p/p2p/discovery/routing"
    kaddht "github.com/libp2p/go-libp2p/p2p/discovery/routing/kad"
    "github.com/libp2p/go-libp2p/p2p/muxer/yamux"
    "github.com/libp2p/go-libp2p/p2p/security/noise"
    "github.com/libp2p/go-libp2p/p2p/transport/quic"
    ma "github.com/multiformats/go-multiaddr"
)

func main() {
    ctx := context.Background()

    // Load or generate identity (for production replace with persistent key load)
    priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
    if err != nil {
        log.Fatalf("failed to generate key: %v", err)
    }

    // Listening addresses (0.0.0.0 binds all interfaces). Use VM public IP when advertising to browsers.
    listenAddrs := []ma.Multiaddr{}
    if a, err := ma.NewMultiaddr("/ip4/0.0.0.0/udp/4002/quic-v1"); err == nil {
        listenAddrs = append(listenAddrs, a)
    }
    // Also include a UDP port for WebTransport / WebRTC UDPMux if available from go-libp2p defaults:
    if a, err := ma.NewMultiaddr("/ip4/0.0.0.0/udp/4002"); err == nil {
        listenAddrs = append(listenAddrs, a)
    }

    // Build host with minimal options. We rely on go-libp2p's default transports which
    // (in recent versions) include the built-in WebRTC implementation.
    h, err := libp2p.New(
        ctx,
        libp2p.Identity(priv),
        libp2p.ListenAddrs(listenAddrs...),
        // Explicitly include QUIC transport for native peers
        libp2p.Transport(quic.NewTransport),
        // Security + muxer
        libp2p.Security(noise.ID, noise.New),
        libp2p.Muxer("/yamux/1.0.0", yamux.DefaultTransport),
        // Make this host act as a v2 relay server if reachable
        libp2p.EnableRelayService(),
        // Force public reachability so it advertises itself as a relay (useful on a public VM)
        libp2p.ForceReachabilityPublic(),
    )
    if err != nil {
        log.Fatalf("failed to create host: %v", err)
    }

    // Print addresses (append /p2p/<PeerID> so clients can hardcode it).
    fmt.Println("Relay peer ID:", h.ID().String())
    fmt.Println("Listening addrs (replace 0.0.0.0 with your VM public IP for browser dialers):")
    for _, a := range h.Addrs() {
        fmt.Printf("  %s/p2p/%s\n", a, h.ID().String())
    }

    // Start a Kademlia DHT for peer routing/discovery
    dht, err := kaddht.New(ctx, h)
    if err != nil {
        log.Printf("warning: failed to create DHT: %v", err)
    } else {
        // Bootstrap (best-effort)
        go func() {
            if err := dht.Bootstrap(ctx); err != nil {
                log.Printf("DHT bootstrap warning: %v", err)
            }
        }()
    }

    // Wait for interrupt and shutdown cleanly
    log.Println("Relay running — press Ctrl+C to stop")
    stop := make(chan os.Signal, 1)
    signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
    <-stop

    log.Println("Shutting down...")
    shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    if err := h.Close(); err != nil {
        log.Printf("error closing host: %v", err)
    }
    _ = shutdownCtx
    log.Println("Stopped")
}