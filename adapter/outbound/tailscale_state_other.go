//go:build !unix && !windows && with_gvisor && !no_tailscale

package outbound

import (
	"errors"
	"os"
)

func tailscaleStateOwner(os.FileInfo) (int, int) { return -1, -1 }
func lockTailscaleState(*os.File) error {
	return errors.New("managed Tailscale state locking is unsupported on this platform")
}
