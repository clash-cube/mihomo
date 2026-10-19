//go:build android && cmfa && !clashcube

package route

func init() {
	SetEmbedMode(true) // set embed mode default
}
