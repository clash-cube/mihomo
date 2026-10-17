//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/tailnet"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/dns"
	"github.com/metacubex/tailscale/ipn"
	"github.com/metacubex/tailscale/ipn/ipnstate"
	"github.com/metacubex/tailscale/tailcfg"
	D "github.com/miekg/dns"
)

// Each config generation owns an adapter reference, while generations with the
// same identity share one tsnet session. Existing connections may retain the old
// adapter after a reload; GC must never decide when a second identity writer starts.
type Tailscale struct {
	*Base
	mu            sync.Mutex
	option        TailscaleOption
	candidate     *tailscaleSession
	session       *tailscaleSession
	closed        bool
	lastErr       error
	unregisterDNS func()
	routes        []netip.Prefix
}

var tailscaleSessions = struct {
	sync.Mutex
	entries map[string]*tailscaleSessionRef
}{entries: make(map[string]*tailscaleSessionRef)}

type tailscaleSessionRef struct {
	session *tailscaleSession
	refs    int
}

func NewTailscale(option TailscaleOption) (*Tailscale, error) {
	var routes []netip.Prefix
	for _, value := range option.RoutePrefixes {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix != prefix.Masked() || prefix.Bits() == 0 || prefix.Addr().Is4In6() || !prefix.Addr().IsGlobalUnicast() || prefix.Addr().IsLoopback() {
			return nil, fmt.Errorf("invalid Tailscale subnet %q", value)
		}
		routes = append(routes, prefix)
	}
	s, err := newTailscaleSession(option)
	if err != nil {
		return nil, err
	}
	tailscaleSessions.Lock()
	ref := tailscaleSessions.entries[s.option.StateDir]
	conflict := ref != nil && !sameTailscaleSession(ref.session.option, s.option)
	tailscaleSessions.Unlock()
	if conflict {
		_ = s.Close()
		return nil, errors.New("Tailscale identity is already running with different settings; restart the core to apply the change")
	}
	t := &Tailscale{Base: s.Base, option: s.option, candidate: s, routes: routes}
	t.unregisterDNS = dns.RegisterTailscaleDnsClient(option.Name, tailscaleAdapterDNS{t})
	return t, nil
}

func (t *Tailscale) getSession() (*tailscaleSession, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil, errors.New("Tailscale outbound is closed")
	}
	if t.session != nil {
		return t.session, nil
	}
	tailscaleSessions.Lock()
	defer tailscaleSessions.Unlock()
	if ref := tailscaleSessions.entries[t.option.StateDir]; ref != nil {
		if !sameTailscaleSession(ref.session.option, t.option) {
			t.lastErr = errors.New("Tailscale identity is already running with different settings; restart the core to apply the change")
			tailnet.Notify()
			return nil, t.lastErr
		}
		ref.refs++
		t.session = ref.session
		if t.candidate != nil {
			_ = t.candidate.Close()
			t.candidate = nil
		}
		return t.session, nil
	}
	s := t.candidate
	t.candidate = nil
	if s == nil {
		var err error
		s, err = newTailscaleSession(t.option)
		if err != nil {
			return nil, err
		}
	}
	if err := s.start(); err != nil {
		_ = s.Close()
		t.lastErr = err
		tailnet.Notify()
		return nil, err
	}
	t.session = s
	t.lastErr = nil
	tailscaleSessions.entries[t.option.StateDir] = &tailscaleSessionRef{session: s, refs: 1}
	return s, nil
}

func sameTailscaleSession(a, b TailscaleOption) bool {
	// Route selection belongs to each accepted config, not the tsnet identity.
	a.RoutePrefixes, b.RoutePrefixes = nil, nil
	return reflect.DeepEqual(a, b)
}

func (t *Tailscale) Tailnet() tailnet.Controller {
	if t.option.AutoRoute {
		return t
	}
	return nil
}

func (t *Tailscale) Connect(context.Context) error { _, err := t.getSession(); return err }

func (t *Tailscale) Snapshot() tailnet.Status {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.session == nil {
		st := tailnet.Status{State: "Starting", Hostname: t.option.Hostname, Peers: []tailnet.Peer{}, IPs: []string{}, Health: []string{}}
		if t.closed {
			st.State = "Stopped"
		}
		if t.lastErr != nil {
			st.State, st.Error = "Failed", t.lastErr.Error()
		}
		return st
	}
	t.session.statusMu.RLock()
	defer t.session.statusMu.RUnlock()
	return t.session.status
}

func (t *Tailscale) Login(ctx context.Context) error {
	s, err := t.getSession()
	if err != nil {
		return err
	}
	lc, err := s.server.LocalClient()
	if err != nil {
		return err
	}
	_, err = lc.EditPrefs(ctx, &ipn.MaskedPrefs{Prefs: ipn.Prefs{WantRunning: true}, WantRunningSet: true})
	if err != nil {
		return err
	}
	err = lc.StartLoginInteractive(ctx)
	s.refreshStatus()
	return err
}

func (t *Tailscale) Logout(ctx context.Context) error {
	s, err := t.getSession()
	if err != nil {
		return err
	}
	lc, err := s.server.LocalClient()
	if err != nil {
		return err
	}
	err = lc.Logout(ctx)
	s.refreshStatus()
	return err
}

func (t *Tailscale) QueryDNS(ctx context.Context, name, qtype string) ([]byte, error) {
	s, err := t.getSession()
	if err != nil {
		return nil, err
	}
	lc, err := s.server.LocalClient()
	if err != nil {
		return nil, err
	}
	data, _, err := lc.QueryDNS(ctx, name, qtype)
	return data, err
}

func (t *Tailscale) Ping(ctx context.Context, ip netip.Addr) (tailnet.Ping, error) {
	known := false
	for _, peer := range t.Snapshot().Peers {
		for _, addr := range peer.IPs {
			known = known || addr == ip.String()
		}
	}
	if !known {
		return tailnet.Ping{}, errors.New("choose an address of a visible Tailscale peer")
	}
	s, err := t.getSession()
	if err != nil {
		return tailnet.Ping{}, err
	}
	lc, err := s.server.LocalClient()
	if err != nil {
		return tailnet.Ping{}, err
	}
	result, err := lc.Ping(ctx, ip, tailcfg.PingDisco)
	if err != nil {
		return tailnet.Ping{}, err
	}
	if result.Err != "" {
		return tailnet.Ping{}, errors.New(result.Err)
	}
	path := "relay"
	if result.Endpoint != "" {
		path = "direct"
	}
	s.refreshStatus()
	return tailnet.Ping{Milliseconds: result.LatencySeconds * 1000, Path: path}, nil
}

func (t *Tailscale) MatchDomain(domain string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.session == nil {
		return false
	}
	t.session.statusMu.RLock()
	defer t.session.statusMu.RUnlock()
	return tailnet.InDomain(domain, t.session.dnsSuffix)
}

func (t *Tailscale) MatchIP(ip netip.Addr) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, prefix := range t.routes {
		if prefix.Contains(ip.Unmap()) {
			return true
		}
	}
	if t.session == nil {
		return false
	}
	t.session.statusMu.RLock()
	defer t.session.statusMu.RUnlock()
	return t.session.peerIPs[ip.Unmap()]
}

func (s *tailscaleSession) refreshStatus() {
	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
	defer cancel()
	lc, err := s.server.LocalClient()
	if err != nil {
		return
	}
	raw, err := lc.Status(ctx)
	if err != nil {
		return
	}
	st := tailscaleStatus(raw)
	s.statusMu.Lock()
	changed := !reflect.DeepEqual(s.status, st)
	s.status = st
	if st.DNSSuffix != "" {
		s.dnsSuffix = st.DNSSuffix
	}
	// Retain known peer destinations through logout/offline transitions so an
	// already discovered private destination cannot silently become DIRECT.
	for _, peer := range st.Peers {
		for _, addr := range peer.IPs {
			if ip, err := netip.ParseAddr(addr); err == nil {
				s.peerIPs[ip.Unmap()] = true
			}
		}
	}
	s.statusMu.Unlock()
	if changed {
		tailnet.Notify()
	}
}

func tailscaleStatus(raw *ipnstate.Status) tailnet.Status {
	st := tailnet.Status{State: raw.BackendState, AuthURL: raw.AuthURL, IPs: []string{}, Peers: []tailnet.Peer{}, Health: append([]string{}, raw.Health...)}
	for _, ip := range raw.TailscaleIPs {
		st.IPs = append(st.IPs, ip.String())
	}
	if raw.Self != nil {
		st.Hostname = raw.Self.HostName
	}
	if raw.CurrentTailnet != nil {
		st.DNSSuffix = strings.TrimSuffix(raw.CurrentTailnet.MagicDNSSuffix, ".")
	}
	for _, p := range raw.Peer {
		peer := tailnet.Peer{ID: string(p.ID), Name: p.HostName, DNSName: strings.TrimSuffix(p.DNSName, "."), IPs: []string{}, Routes: []string{}, Online: p.Online, Path: "unknown"}
		if p.Active && p.CurAddr != "" {
			peer.Path = "direct"
		} else if p.Active && (p.Relay != "" || p.PeerRelay != "") {
			peer.Path = "relay"
		}
		for _, ip := range p.TailscaleIPs {
			peer.IPs = append(peer.IPs, ip.String())
		}
		if p.PrimaryRoutes != nil {
			for _, prefix := range p.PrimaryRoutes.AsSlice() {
				if prefix.Bits() > 0 {
					peer.Routes = append(peer.Routes, prefix.String())
				}
			}
		}
		st.Peers = append(st.Peers, peer)
	}
	sort.Slice(st.Peers, func(i, j int) bool { return st.Peers[i].ID < st.Peers[j].ID })
	return st
}

func (t *Tailscale) DialContext(ctx context.Context, md *C.Metadata) (C.Conn, error) {
	s, err := t.getSession()
	if err != nil {
		return nil, err
	}
	return s.DialContext(ctx, md)
}

func (t *Tailscale) ListenPacketContext(ctx context.Context, md *C.Metadata) (C.PacketConn, error) {
	s, err := t.getSession()
	if err != nil {
		return nil, err
	}
	return s.ListenPacketContext(ctx, md)
}

func (t *Tailscale) ResolveUDP(ctx context.Context, md *C.Metadata) error {
	s, err := t.getSession()
	if err != nil {
		return err
	}
	return s.ResolveUDP(ctx, md)
}

func (t *Tailscale) ProxyInfo() C.ProxyInfo {
	info := t.Base.ProxyInfo()
	info.DialerProxy = t.option.DialerProxy
	return info
}
func (t *Tailscale) IsL3Protocol(*C.Metadata) bool { return true }

func (t *Tailscale) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	if t.unregisterDNS != nil {
		t.unregisterDNS()
	}
	if t.candidate != nil {
		_ = t.candidate.Close()
		t.candidate = nil
	}
	if t.session == nil {
		return nil
	}
	tailscaleSessions.Lock()
	defer tailscaleSessions.Unlock()
	ref := tailscaleSessions.entries[t.option.StateDir]
	ref.refs--
	if ref.refs == 0 {
		delete(tailscaleSessions.entries, t.option.StateDir)
		return ref.session.Close()
	}
	return nil
}

type tailscaleAdapterDNS struct{ t *Tailscale }

func (d tailscaleAdapterDNS) Address() string  { return "tailscale://" + d.t.Name() }
func (d tailscaleAdapterDNS) ResetConnection() {}
func (d tailscaleAdapterDNS) ExchangeContext(ctx context.Context, msg *D.Msg) (*D.Msg, error) {
	s, err := d.t.getSession()
	if err != nil {
		return nil, fmt.Errorf("Tailscale DNS: %w", err)
	}
	return (tailscaleDNSTransport{s}).ExchangeContext(ctx, msg)
}
