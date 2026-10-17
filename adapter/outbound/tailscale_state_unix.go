//go:build unix && with_gvisor && !no_tailscale

package outbound

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func tailscaleStateOwner(info os.FileInfo) (int, int) {
	stat := info.Sys().(*syscall.Stat_t)
	return int(stat.Uid), int(stat.Gid)
}

func lockTailscaleState(f *os.File) error { return unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) }
