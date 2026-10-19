//go:build android && clashcube

package config

func platformRawConfig(c *RawConfig) {
	// Android's VPN permission never grants permission to change system time.
	c.NTP.WriteToSystem = false
}
