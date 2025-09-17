// main.go — Minimal libp2p relay + HTTP rendezvous with topic filter.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	libp2p "github.com/libp2p/go-libp2p"
	crypto "github.com/libp2p/go-libp2p/core/crypto"
	network "github.com/libp2p/go-libp2p/core/network"
	yamux "github.com/libp2p/go-libp2p/p2p/muxer/yamux"
	noise "github.com/libp2p/go-libp2p/p2p/security/noise"
	ma "github.com/multiformats/go-multiaddr"
)

// PeerEntry is what we store/return via HTTP.
type PeerEntry struct {
	ID       string   `json:"id"`
	Addrs    []string `json:"addrs"`
	Topics   []string `json:"topics"`
	LastSeen int64    `json:"lastSeen"`
}

type registry struct {
	mu    sync.RWMutex
	peers map[string]*PeerEntry
}

func newRegistry() *registry { return &registry{peers: make(map[string]*PeerEntry)} }

// merge addresses + topics and update timestamp
func (r *registry) upsert(id string, addrs, topics []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().Unix()
	if e, ok := r.peers[id]; ok {
		addrSet := map[string]struct{}{}
		for _, a := range e.Addrs {
			addrSet[a] = struct{}{}
		}
		for _, a := range addrs {
			addrSet[a] = struct{}{}
		}
		addrsMerged := make([]string, 0, len(addrSet))
		for a := range addrSet {
			addrsMerged = append(addrsMerged, a)
		}

		topSet := map[string]struct{}{}
		for _, t := range e.Topics {
			topSet[t] = struct{}{}
		}
		for _, t := range topics {
			topSet[t] = struct{}{}
		}
		topicsMerged := make([]string, 0, len(topSet))
		for t := range topSet {
			topicsMerged = append(topicsMerged, t)
		}

		e.Addrs = addrsMerged
		e.Topics = topicsMerged
		e.LastSeen = now
	} else {
		r.peers[id] = &PeerEntry{ID: id, Addrs: addrs, Topics: topics, LastSeen: now}
	}
}

func (r *registry) list(topic string) []*PeerEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*PeerEntry
	for _, e := range r.peers {
		if topic == "" || contains(e.Topics, topic) {
			cp := *e
			out = append(out, &cp)
		}
	}
	return out
}

func (r *registry) pruneOlderThan(sec int64) {
	cut := time.Now().Unix() - sec
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, e := range r.peers {
		if e.LastSeen < cut {
			delete(r.peers, id)
		}
	}
}

func contains(ss []string, x string) bool {
	for _, s := range ss {
		if s == x {
			return true
		}
	}
	return false
}

// netNotifee registers peers automatically when they connect.
type netNotifee struct{ reg *registry }

func (n *netNotifee) Listen(network.Network, ma.Multiaddr)         {}
func (n *netNotifee) ListenClose(network.Network, ma.Multiaddr)    {}
func (n *netNotifee) Disconnected(network.Network, network.Conn)   {}
func (n *netNotifee) OpenedStream(network.Network, network.Stream) {}
func (n *netNotifee) ClosedStream(network.Network, network.Stream) {}
func (n *netNotifee) Connected(net network.Network, c network.Conn) {
	id := c.RemotePeer().String()
	addr := c.RemoteMultiaddr().String()
	n.reg.upsert(id, []string{addr}, nil)
	log.Printf("peer connected: %s via %s", id, addr)
}

func main() {
	ctx := context.Background()
	reg := newRegistry()

	// Load or generate persistent identity
	keyFile := "peer.key"
	var priv crypto.PrivKey
	if b, err := os.ReadFile(keyFile); err == nil {
		k, err := crypto.UnmarshalPrivateKey(b)
		if err != nil {
			log.Fatalf("unmarshal key: %v", err)
		}
		priv = k
		log.Println("loaded identity key from", keyFile)
	} else {
		k, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
		if err != nil {
			log.Fatalf("generate key: %v", err)
		}
		b, _ := crypto.MarshalPrivateKey(k)
		if err := os.WriteFile(keyFile, b, 0600); err != nil {
			log.Fatalf("save key: %v", err)
		}
		priv = k
		log.Println("generated new identity key")
	}

	// Listen on QUIC + WebSockets
	var listen []ma.Multiaddr
	if a, err := ma.NewMultiaddr("/ip4/0.0.0.0/udp/4002/quic-v1"); err == nil {
		listen = append(listen, a)
	}
	if a, err := ma.NewMultiaddr("/ip4/0.0.0.0/tcp/4003/ws"); err == nil {
		listen = append(listen, a)
	}

	// Create libp2p host
	host, err := libp2p.New(
		libp2p.Identity(priv),
		libp2p.ListenAddrs(listen...),
		libp2p.Security(noise.ID, noise.New),
		libp2p.Muxer("/yamux/1.0.0", yamux.DefaultTransport),
		libp2p.EnableRelayService(),
		libp2p.ForceReachabilityPublic(),
	)
	if err != nil {
		log.Fatalf("create host: %v", err)
	}

	fmt.Println("Relay peer ID:", host.ID().String())
	fmt.Println("Listening addresses (replace 0.0.0.0 with your VM IP for browsers):")
	for _, a := range host.Addrs() {
		fmt.Printf("  %s/p2p/%s\n", a, host.ID().String())
	}

	// Auto-register new connections
	host.Network().Notify(&netNotifee{reg: reg})

	// --- HTTP discovery endpoints ---
	http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var p PeerEntry
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
			return
		}
		if p.ID == "" {
			http.Error(w, "missing id", http.StatusBadRequest)
			return
		}
		reg.upsert(p.ID, p.Addrs, p.Topics)
		w.WriteHeader(http.StatusNoContent)
	})

	http.HandleFunc("/peers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		topic := r.URL.Query().Get("topic")
		_ = json.NewEncoder(w).Encode(reg.list(topic))
	})

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		w.Write([]byte("ok"))
	})

	srv := &http.Server{Addr: ":8080"}
	go func() {
		log.Println("HTTP rendezvous listening on", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server: %v", err)
		}
	}()

	// Periodically prune stale entries (>5 min)
	go func() {
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for range t.C {
			reg.pruneOlderThan(300)
		}
	}()

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Println("shutting down...")
	_ = srv.Close()
	_ = host.Close()
	_ = ctx
}
