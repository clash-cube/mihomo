//go:build android && cmfa

package dns

import (
	"github.com/metacubex/mihomo/component/resolver"
	"sync"
)

var systemResolver []dnsClient
var systemResolverMu sync.RWMutex

func FlushCacheWithDefaultResolver() {
	resolver.ClearCache()
	resolver.ResetConnection()
}

func UpdateSystemDNS(addr []string) {

	ns := make([]NameServer, 0, len(addr))
	for _, d := range addr {
		ns = append(ns, NameServer{Addr: d})
	}

	clients := transform(ns, nil)
	systemResolverMu.Lock()
	systemResolver = clients
	systemResolverMu.Unlock()
}

func (c *systemClient) getDnsClients() ([]dnsClient, error) {
	systemResolverMu.RLock()
	defer systemResolverMu.RUnlock()
	return systemResolver, nil
}

func (c *systemClient) ResetConnection() {
	clients, _ := c.getDnsClients()
	for _, r := range clients {
		r.ResetConnection()
	}
}
