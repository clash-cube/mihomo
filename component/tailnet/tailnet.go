// Package tailnet exposes the small management surface of embedded Tailscale
// outbounds without coupling rule matching or controllers to the tsnet SDK.
package tailnet

import (
	"context"
	"net/netip"
	"sort"
	"strings"
	"sync"
)

type Peer struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	DNSName string   `json:"dnsName"`
	IPs     []string `json:"ips"`
	Routes  []string `json:"routes"`
	Online  bool     `json:"online"`
	Path    string   `json:"path"` // direct, relay, or unknown
}

type Status struct {
	Name      string   `json:"name"`
	State     string   `json:"state"`
	AuthURL   string   `json:"authURL,omitempty"`
	Hostname  string   `json:"hostname"`
	IPs       []string `json:"ips"`
	DNSSuffix string   `json:"dnsSuffix"`
	Peers     []Peer   `json:"peers"`
	Health    []string `json:"health"`
	Error     string   `json:"error,omitempty"`
}

type Ping struct {
	Milliseconds float64 `json:"milliseconds"`
	Path         string  `json:"path"`
}

type Controller interface {
	Snapshot() Status
	Connect(context.Context) error
	Login(context.Context) error
	Logout(context.Context) error
	Ping(context.Context, netip.Addr) (Ping, error)
	MatchDomain(string) bool
	MatchIP(netip.Addr) bool
	QueryDNS(context.Context, string, string) ([]byte, error)
}

// Provider is optional. Adapter wrappers must forward it without starting a node.
type Provider interface{ Tailnet() Controller }

var registry = struct {
	sync.RWMutex
	nodes   map[string]Controller
	changed chan struct{}
}{nodes: map[string]Controller{}, changed: make(chan struct{})}

// Replace activates only the accepted configuration. Parsing a proposed or
// rejected configuration must not replace the live management/routing state.
func Replace(nodes map[string]Controller) {
	registry.Lock()
	defer registry.Unlock()
	registry.nodes = nodes
	close(registry.changed)
	registry.changed = make(chan struct{})
}

func Changed() <-chan struct{} {
	registry.RLock()
	defer registry.RUnlock()
	return registry.changed
}

func Notify() {
	registry.Lock()
	defer registry.Unlock()
	close(registry.changed)
	registry.changed = make(chan struct{})
}

func Get(name string) Controller {
	registry.RLock()
	defer registry.RUnlock()
	return registry.nodes[name]
}

func Statuses() []Status {
	registry.RLock()
	nodes := make(map[string]Controller, len(registry.nodes))
	for name, node := range registry.nodes {
		nodes[name] = node
	}
	registry.RUnlock()
	out := make([]Status, 0, len(nodes))
	for name, node := range nodes {
		st := node.Snapshot()
		st.Name = name
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// DNSProxy chooses only an active node's own MagicDNS suffix, never all ts.net.
func DNSProxy(domain string) string {
	registry.RLock()
	nodes := make(map[string]Controller, len(registry.nodes))
	for name, node := range registry.nodes {
		nodes[name] = node
	}
	registry.RUnlock()
	for name, node := range nodes {
		if node.MatchDomain(domain) {
			return name
		}
	}
	return ""
}

func InDomain(domain, suffix string) bool {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	suffix = strings.ToLower(strings.TrimSuffix(suffix, "."))
	return suffix != "" && (domain == suffix || strings.HasSuffix(domain, "."+suffix))
}
