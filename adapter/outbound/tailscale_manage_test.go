//go:build with_gvisor && !no_tailscale

package outbound

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/tailscale/ipn"
	"github.com/metacubex/tailscale/ipn/ipnstate"
	"github.com/metacubex/tailscale/types/key"
)

func tailscaleTestHome(t *testing.T) string {
	t.Helper()
	old := C.Path.HomeDir()
	home := t.TempDir()
	C.SetHomeDir(home)
	t.Cleanup(func() { C.SetHomeDir(old) })
	return filepath.Join(home, "tailscale", "test-node")
}

func TestTailscaleStateOwnershipAndPersistence(t *testing.T) {
	dir := tailscaleTestHome(t)
	s, err := newTailscaleStateStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if _, err := newTailscaleStateStore(dir); err == nil {
		t.Fatal("two core processes can own the same identity")
	}
	value := []byte("private node state")
	if err := s.WriteState("node", value); err != nil {
		t.Fatal(err)
	}
	value[0] = 'X'
	got, err := s.ReadState("node")
	if err != nil || string(got) != "private node state" {
		t.Fatalf("%q, %v", got, err)
	}
	got[0] = 'Y'
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = newTailscaleStateStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err = s.ReadState("node")
	if err != nil || string(got) != "private node state" {
		t.Fatalf("reopen: %q, %v", got, err)
	}
	info, err := os.Stat(filepath.Join(dir, "tailscaled.state"))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("identity mode: %v", info.Mode())
	}
	if err := s.WriteState("node", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadState("node"); !errors.Is(err, ipn.ErrStateNotExist) {
		t.Fatalf("deleted key: %v", err)
	}
	if _, err := s.runtimeDir(); err != nil {
		t.Fatal(err)
	}
}

func TestTailscaleStatusRequiresTrafficBeforeReportingRelay(t *testing.T) {
	peer := &ipnstate.PeerStatus{Relay: "derp-home", Online: true}
	status := &ipnstate.Status{Peer: map[key.NodePublic]*ipnstate.PeerStatus{{}: peer}}
	if got := tailscaleStatus(status).Peers[0].Path; got != "unknown" {
		t.Fatalf("home DERP was mistaken for an active connection: %s", got)
	}
	peer.Active = true
	if got := tailscaleStatus(status).Peers[0].Path; got != "relay" {
		t.Fatalf("active relay: %s", got)
	}
	peer.CurAddr = "192.0.2.1:41641"
	if got := tailscaleStatus(status).Peers[0].Path; got != "direct" {
		t.Fatalf("active direct path: %s", got)
	}
}

func TestTailscaleStateRejectsEscapesAndSymlinks(t *testing.T) {
	dir := tailscaleTestHome(t)
	if _, err := newTailscaleStateStore(t.TempDir()); err == nil {
		t.Fatal("accepted identity outside core home")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "identity")
	if err := os.WriteFile(target, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "tailscaled.state")); err != nil {
		t.Skip(err)
	}
	if _, err := newTailscaleStateStore(dir); err == nil {
		t.Fatal("accepted a state symlink")
	}
	got, _ := os.ReadFile(target)
	if string(got) != "unchanged" {
		t.Fatal("wrote outside state home")
	}
}

func TestTailscaleReloadSharesIdentityButKeepsRouteSelection(t *testing.T) {
	dir := tailscaleTestHome(t)
	option := TailscaleOption{Name: "tailnet", Hostname: "clashcube", StateDir: dir, AutoRoute: true, UDP: true}
	first, err := NewTailscale(option)
	if err != nil {
		t.Fatal(err)
	}
	// Install a dormant session: ownership and generation handover must not
	// require contacting a real control server or logging into a user's tailnet.
	s := first.candidate
	first.candidate = nil
	first.session = s
	tailscaleSessions.Lock()
	tailscaleSessions.entries[dir] = &tailscaleSessionRef{session: s, refs: 1}
	tailscaleSessions.Unlock()
	t.Cleanup(func() { _ = first.Close() })
	option.RoutePrefixes = []string{"192.168.50.0/24"}
	second, err := NewTailscale(option)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })
	shared, err := second.getSession()
	if err != nil || shared != s {
		t.Fatalf("reload created another session: %v", err)
	}
	ip := netip.MustParseAddr("192.168.50.10")
	if first.MatchIP(ip) || !second.MatchIP(ip) {
		t.Fatal("route selection leaked between config generations")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if s.ctx.Err() != nil {
		t.Fatal("old generation closed the active identity")
	}
	option.Hostname = "changed"
	if _, err := NewTailscale(option); err == nil {
		t.Fatal("accepted concurrent identity settings change")
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if s.ctx.Err() == nil {
		t.Fatal("last generation did not release its identity")
	}
	if !second.MatchIP(ip) {
		t.Fatal("offline subnet fell through to DIRECT")
	}
}
