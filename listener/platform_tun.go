//go:build !android || !clashcube

package listener

import LC "github.com/metacubex/mihomo/listener/config"

func platformTunConfig(*LC.Tun) {}
