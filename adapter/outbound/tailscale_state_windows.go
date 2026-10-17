//go:build windows && with_gvisor && !no_tailscale

package outbound

import (
	"os"

	"golang.org/x/sys/windows"
)

func tailscaleStateOwner(os.FileInfo) (int, int) { return -1, -1 }
func lockTailscaleState(f *os.File) error {
	return windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{})
}
