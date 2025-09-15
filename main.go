package main

import (
    "context"
    "fmt"
    "log"
    "os"
    "time"

    libp2p "github.com/libp2p/go-libp2p"
    noise "github.com/libp2p/go-libp2p-noise"
    peerstore "github.com/libp2p/go-libp2p-core/peerstore"
    crypto "github.com/libp2p/go-libp2p-core/crypto"
    dht "github.com/libp2p/go-libp2p-kad-dht"
    webrtc "github.com/libp2p/go-libp2p-webrtc-direct"
    quic "github.com/libp2p/go-libp2p-quic-transport"
    yamux "github.com/libp2p/go-libp2p/p2p/muxer/yamux"
    ipnet "github.com/libp2p/go-libp2p-core/network"
    ma "github.com/multiformats/go-multiaddr"
)

func main() {
    ctx := context.Background()

    // Generate a new peer identity (or load from file for a static ID)
    priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
    if err != nil {
        log.Fatalf("Failed to generate key pair: %s", err)
    }

    // Configure listening addresses (0.0.0.0 means all interfaces; replace <VM_IP> below as needed)
    listenAddrs := []ma.Multiaddr{}
    // Listen for QUIC on port 4002 (IPv4 and IPv6)
    addr4, _ := ma.NewMultiaddr("/ip4/0.0.0.0/udp/4002/quic-v1")
    addr6, _ := ma.NewMultiaddr("/ip6/::/udp/4002/quic-v1")
    listenAddrs = append(listenAddrs, addr4, addr6)
    // Listen for WebRTC-direct on port 4002 (IPv4 and IPv6)
    addr4w, _ := ma.NewMultiaddr("/ip4/0.0.0.0/udp/4002/webrtc-direct")
    addr6w, _ := ma.NewMultiaddr("/ip6/::/udp/4002/webrtc-direct")
    listenAddrs = append(listenAddrs, addr4w, addr6w)

    // WebRTC transport requires a multiplexer (we use Yamux) and optional STUN servers
    // Here we include a public STUN server to aid NAT traversal (optional if node is on a public IP).
    // The webrtc.Configuration uses pion/webrtc types.
    iceServers := webrtc.ICEServer{URLs: []string{"stun:stun.l.google.com:19302"}}
    rtcConfig := webrtc.Configuration{ICEServers: []webrtc.ICEServer{iceServers}}
    rtcTransport, err := webrtc.NewTransport(rtcConfig, yamux.DefaultTransport)
    if err != nil {
        log.Fatalf("Failed to create WebRTC transport: %s", err)
    }

    // QUIC transport (v1)
    quicTransport := quic.NewTransport

    // Construct the libp2p host with required options
    host, err := libp2p.New(
        ctx,
        libp2p.Identity(priv),
        // Listen on specified multiaddrs
        libp2p.ListenAddrs(listenAddrs...),
        // Use the chosen transports
        libp2p.Transport(quicTransport),
        libp2p.Transport(rtcTransport),
        // Use Noise for encryption (default) and Yamux as muxer
        libp2p.Security(noise.ID, noise.New),
        libp2p.Muxer("/yamux/1.0.0", yamux.DefaultTransport),
        // Enable circuit Relay V2 service
        libp2p.EnableRelayService(),
        // Force this node to assume it is publicly reachable
        libp2p.ForceReachabilityPublic(),
    )
    if err != nil {
        log.Fatalf("Failed to create libp2p host: %s", err)
    }

    // Print the relay's listen addresses (including its peer ID) for bootstrapping
    fmt.Println("Relay is listening on:")
    for _, addr := range host.Addrs() {
        // Append /p2p/<PeerID> so others know this relay's ID
        fullAddr := addr.Encapsulate(ma.StringCast("/p2p/" + host.ID().Pretty()))
        fmt.Printf("  %s\n", fullAddr)
    }

    // Initialize a Kademlia DHT for peer discovery
    kademliaDHT, err := dht.New(ctx, host)
    if err != nil {
        log.Fatalf("Failed to create DHT: %s", err)
    }
    // Bootstrap the DHT so the node starts finding peers (empty seed list if first node)
    if err := kademliaDHT.Bootstrap(ctx); err != nil {
        log.Printf("Warning: DHT bootstrap error: %s", err)
    }

    // Keep the process running indefinitely
    log.Println("Relay node is up. Waiting for connections...")
    select {}
}
