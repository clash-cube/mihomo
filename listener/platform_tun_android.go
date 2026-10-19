//go:build android && clashcube

package listener

import LC "github.com/metacubex/mihomo/listener/config"

// AndroidTunConfig is installed once, before startup. The VPN service owns
// the descriptor and interface policy, including across REST config reloads.
var AndroidTunConfig func(*LC.Tun)

func platformTunConfig(c *LC.Tun) {
	if AndroidTunConfig != nil {
		AndroidTunConfig(c)
	}
}
