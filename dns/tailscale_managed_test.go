package dns

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/component/tailnet"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/rules/common"
	D "github.com/miekg/dns"
)

type managedTailnet struct {
	suffix  string
	ip      netip.Addr
	offline bool
}

func (*managedTailnet) Snapshot() tailnet.Status      { return tailnet.Status{} }
func (*managedTailnet) Connect(context.Context) error { return nil }
func (*managedTailnet) Login(context.Context) error   { return nil }
func (*managedTailnet) Logout(context.Context) error  { return nil }
func (*managedTailnet) Ping(context.Context, netip.Addr) (tailnet.Ping, error) {
	return tailnet.Ping{}, nil
}
func (n *managedTailnet) MatchDomain(domain string) bool { return tailnet.InDomain(domain, n.suffix) }
func (n *managedTailnet) MatchIP(ip netip.Addr) bool     { return ip == n.ip }
func (n *managedTailnet) QueryDNS(_ context.Context, name, qtype string) ([]byte, error) {
	if n.offline {
		return nil, errors.New("tailnet offline")
	}
	q := new(D.Msg)
	q.SetQuestion(name, D.StringToType[qtype])
	response := new(D.Msg)
	response.SetReply(q)
	rr, err := D.NewRR(name + " 60 IN A " + n.ip.String())
	if err != nil {
		return nil, err
	}
	response.Answer = []D.RR{rr}
	return response.Pack()
}

func TestManagedTailscaleDNSAndRulesFollowLiveState(t *testing.T) {
	node := &managedTailnet{suffix: "test-tail.ts.net", ip: netip.MustParseAddr("100.64.0.2")}
	tailnet.Replace(map[string]tailnet.Controller{"tailnet": node})
	defer tailnet.Replace(nil)
	rule := common.NewTailscale("tailnet", "tailnet")
	resolver := &Resolver{} // no configured nameserver-policy is required
	question := new(D.Msg)
	question.SetQuestion("device.test-tail.ts.net.", D.TypeA)
	clients := resolver.matchPolicy(question)
	if len(clients) != 1 {
		t.Fatal("own MagicDNS suffix did not select embedded DNS")
	}
	reply, err := clients[0].ExchangeContext(context.Background(), question)
	if err != nil || reply.Id != question.Id || reply.Answer[0].(*D.A).A.String() != "100.64.0.2" {
		t.Fatalf("MagicDNS answer: %v %v", reply, err)
	}
	for host, want := range map[string]bool{"device.test-tail.ts.net": true, "DEVICE.TEST-TAIL.TS.NET.": true, "other.ts.net": false, "eviltest-tail.ts.net": false} {
		if got, _ := rule.Match(&C.Metadata{Host: host}, C.RuleMatchHelper{}); got != want {
			t.Errorf("%s matched %v", host, got)
		}
	}
	oldIP := node.ip
	node.ip = netip.MustParseAddr("100.64.0.3")
	if match, _ := rule.Match(&C.Metadata{DstIP: node.ip}, C.RuleMatchHelper{}); !match {
		t.Fatal("new peer needs a config reload")
	}
	if match, _ := rule.Match(&C.Metadata{DstIP: oldIP}, C.RuleMatchHelper{}); match {
		t.Fatal("rule captured a stale peer list")
	}
	question.SetQuestion("unrelated.ts.net.", D.TypeA)
	if got := resolver.matchPolicy(question); len(got) != 0 {
		t.Fatal("hijacked another tailnet's MagicDNS")
	}
	node.offline = true
	question.SetQuestion("device.test-tail.ts.net.", D.TypeA)
	if _, err := resolver.matchPolicy(question)[0].ExchangeContext(context.Background(), question); err == nil {
		t.Fatal("offline private DNS silently fell through")
	}
	tailnet.Replace(nil)
	if got := resolver.matchPolicy(question); len(got) != 0 {
		t.Fatal("disabled module still owns DNS")
	}
}
