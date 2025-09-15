// main.go — minimal relayed host + HTTP discovery (no DHT)
// Uses modern libp2p import paths (core/* and p2p/security/noise)
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
	noise "github.com/libp2p/go-libp2p/p2p/security/noise"
	yamux "github.com/libp2p/go-libp2p/p2p/muxer/yamux"
	crypto "github.com/libp2p/go-libp2p/core/crypto"
	network "github.com/libp2p/go-libp2p/core/network"
	ma "github.com/multiformats/go-multiaddr"
)

// PeerEntry is returned by /peers
type PeerEntry struct {
	ID       string   `json:"id"`
	Addrs    []string `json:"addrs"`
	LastSeen int64    `json:"lastSeen"`
}

type registry struct {
	mu    sync.RWMutex
	peers map[string]*PeerEntry
}

func newRegistry() *registry {
	return &registry{peers: make(map[string]*PeerEntry)}
}

func (r *registry) upsert(id string, addrs []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().Unix()
	if e, ok := r.peers[id]; ok {
		// merge addresses
		m := make(map[string]struct{}, len(e.Addrs)+len(addrs))
		for _, a := range e.Addrs {
			m[a] = struct{}{}
		}
		for _, a := range addrs {
			m[a] = struct{}{}
		}
		merged := make([]string, 0, len(m))
		for a := range m {
			merged = append(merged, a)
		}
		e.Addrs = merged
		e.LastSeen = now
	} else {
		r.peers[id] = &PeerEntry{ID: id, Addrs: addrs, LastSeen: now}
	}
}

func (r *registry) list() []*PeerEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*PeerEntry, 0, len(r.peers))
	for _, e := range r.peers {
		out = append(out, &PeerEntry{ID: e.ID, Addrs: append([]string(nil), e.Addrs...), LastSeen: e.LastSeen})
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

// netNotifee auto-registers peers when they connect
type netNotifee struct{ reg *registry }

func (n *netNotifee) Listen(network.Network, ma.Multiaddr)      {}
func (n *netNotifee) ListenClose(network.Network, ma.Multiaddr) {}
func (n *netNotifee) Connected(net network.Network, c network.Conn) {
	peerID := c.RemotePeer().String()          // <-- use String()
	addr := c.RemoteMultiaddr().String()
	n.reg.upsert(peerID, []string{addr})
	log.Printf("auto-registered peer %s via %s", peerID, addr)
}
func (n *netNotifee) Disconnected(network.Network, network.Conn) {}
func (n *netNotifee) OpenedStream(network.Network, network.Stream) {}
func (n *netNotifee) ClosedStream(network.Network, network.Stream)  {}

func main() {
	ctx := context.Background()
	reg := newRegistry()

	// persistent identity (store locally so peer ID stays constant)
	keyFile := "peer.key"
	var priv crypto.PrivKey
	if _, err := os.Stat(keyFile); err == nil {
		b, err := os.ReadFile(keyFile)
		if err != nil {
			log.Fatalf("read key: %v", err)
		}
		priv, err = crypto.UnmarshalPrivateKey(b)
		if err != nil {
			log.Fatalf("unmarshal key: %v", err)
		}
		log.Println("loaded identity key from", keyFile)
	} else {
		k, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
		if err != nil {
			log.Fatalf("generate key: %v", err)
		}
		b, err := crypto.MarshalPrivateKey(k)
		if err != nil {
			log.Fatalf("marshal key: %v", err)
		}
		if err := os.WriteFile(keyFile, b, 0600); err != nil {
			log.Fatalf("save key: %v", err)
		}
		priv = k
		log.Println("generated identity key and saved to", keyFile)
	}

	// Listen addresses:
	listen := []ma.Multiaddr{}
	if a, err := ma.NewMultiaddr("/ip4/0.0.0.0/udp/4002/quic-v1"); err == nil {
		listen = append(listen, a)
	}
	if a, err := ma.NewMultiaddr("/ip4/0.0.0.0/tcp/4003/ws"); err == nil {
		listen = append(listen, a)
	}

	// Build host — modern libp2p.New takes only options (no ctx arg)
	host, err := libp2p.New(
		libp2p.Identity(priv),
		libp2p.ListenAddrs(listen...),
		libp2p.Security(noise.ID, noise.New),
		libp2p.Muxer("/yamux/1.0.0", yamux.DefaultTransport),
		libp2p.EnableRelayService(),
		libp2p.ForceReachabilityPublic(),
	)
	if err != nil {
		log.Fatalf("failed to create libp2p host: %v", err)
	}

	fmt.Println("Relay peer ID:", host.ID().String()) // <-- use String()
	fmt.Println("Listening addresses (replace 0.0.0.0 with your VM public IP for browsers):")
	for _, a := range host.Addrs() {
		fmt.Printf("  %s/p2p/%s\n", a, host.ID().String()) // <-- use String()
	}

	// Auto-register incoming peers
	host.Network().Notify(&netNotifee{reg: reg})

	// HTTP discovery server
	http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "use POST", http.StatusMethodNotAllowed)
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
		reg.upsert(p.ID, p.Addrs)
		w.WriteHeader(http.StatusNoContent)
	})
	http.HandleFunc("/peers", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(reg.list())
	})
	http.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })

	srv := &http.Server{Addr: ":8080"}
	go func() {
		log.Printf("HTTP discovery listening on %s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server error: %v", err)
		}
	}()

	// prune stale entries
	go func() {
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for range t.C {
			reg.pruneOlderThan(300)
		}
	}()

	// wait for ctrl-c
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Println("shutting down")
	_ = srv.Close()
	_ = host.Close()
	_ = ctx
}
