package common

import (
	"github.com/metacubex/mihomo/component/tailnet"
	C "github.com/metacubex/mihomo/constant"
)

// Tailscale matches the live peer addresses and MagicDNS suffix of one node.
// Subnet destinations are explicitly selected on the managed adapter.
type Tailscale struct {
	Base
	name, adapter string
}

func NewTailscale(name, adapter string) *Tailscale { return &Tailscale{name: name, adapter: adapter} }
func (r *Tailscale) RuleType() C.RuleType          { return C.TailscaleRule }
func (r *Tailscale) Payload() string               { return r.name }
func (r *Tailscale) Adapter() string               { return r.adapter }
func (r *Tailscale) Match(md *C.Metadata, _ C.RuleMatchHelper) (bool, string) {
	node := tailnet.Get(r.name)
	return node != nil && (node.MatchDomain(md.RuleHost()) || node.MatchIP(md.DstIP)), r.adapter
}
