//go:build with_gvisor && !no_tailscale

package outbound

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/tailscale/ipn"
)

// The managed node's state stays owned by the core home's user even when the
// core is elevated. Descriptor-relative access confines all writes, including
// symlink traversal, and an OS lock excludes another core using the same node.
type tailscaleStateStore struct {
	mu       sync.Mutex
	root     *os.Root
	lock     *os.File
	uid, gid int
	cache    map[ipn.StateKey][]byte
	closed   bool
}

func newTailscaleStateStore(dir string) (_ *tailscaleStateStore, err error) {
	home, err := os.OpenRoot(C.Path.HomeDir())
	if err != nil {
		return nil, err
	}
	defer home.Close()
	info, err := home.Stat(".")
	if err != nil {
		return nil, err
	}
	uid, gid := tailscaleStateOwner(info)
	rel, err := filepath.Rel(C.Path.HomeDir(), dir)
	if err != nil || !filepath.IsLocal(rel) || rel == "." {
		return nil, errors.New("managed Tailscale state must be inside the core home")
	}
	path := ""
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		path = filepath.Join(path, part)
		if err = home.Mkdir(path, 0700); errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		f, err := home.Open(path)
		if err != nil {
			return nil, err
		}
		if uid >= 0 {
			err = f.Chown(uid, gid)
		}
		_ = f.Close()
		if err != nil {
			return nil, err
		}
	}
	r, err := home.OpenRoot(rel)
	if err != nil {
		return nil, err
	}
	s := &tailscaleStateStore{root: r, uid: uid, gid: gid, cache: map[ipn.StateKey][]byte{}}
	defer func() {
		if err != nil {
			_ = s.Close()
		}
	}()
	s.lock, err = r.OpenFile("node.lock", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		if err = regularStateFile(r, "node.lock"); err != nil {
			return nil, err
		}
		s.lock, err = r.OpenFile("node.lock", os.O_RDWR, 0)
	} else if err == nil && uid >= 0 {
		err = s.lock.Chown(uid, gid)
	}
	if err != nil {
		return nil, err
	}
	if err = lockTailscaleState(s.lock); err != nil {
		return nil, fmt.Errorf("Tailscale identity is in use by another core: %w", err)
	}
	if err = regularStateFile(r, "tailscaled.state"); errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	data, err := r.ReadFile("tailscaled.state")
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(data, &s.cache); err != nil {
		return nil, errors.New("Tailscale identity state is damaged")
	}
	if s.cache == nil {
		s.cache = map[ipn.StateKey][]byte{}
	}
	return s, nil
}

func regularStateFile(root *os.Root, name string) error {
	info, err := root.Lstat(name)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("Tailscale %s must be a regular file", name)
	}
	return nil
}

// tsnet also writes log buffers and reconstructible tailnet-lock caches outside
// StateStore. Keep these per effective uid; switching out of a root core must not
// require opening root's log/cache files. Machine and node keys remain shared.
func (s *tailscaleStateStore) runtimeDir() (string, error) {
	name := fmt.Sprintf("runtime-%d", os.Geteuid())
	if err := s.root.Mkdir(name, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	info, err := s.root.Lstat(name)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("Tailscale runtime cache must be a directory")
	}
	return filepath.Join(s.root.Name(), name), nil
}

func (s *tailscaleStateStore) ReadState(key ipn.StateKey) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, os.ErrClosed
	}
	data, ok := s.cache[key]
	if !ok {
		return nil, ipn.ErrStateNotExist
	}
	return bytes.Clone(data), nil
}

func (s *tailscaleStateStore) WriteState(key ipn.StateKey, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return os.ErrClosed
	}
	if bytes.Equal(s.cache[key], value) {
		return nil
	}
	next := make(map[ipn.StateKey][]byte, len(s.cache)+1)
	for k, v := range s.cache {
		next[k] = v
	}
	if value == nil {
		delete(next, key)
	} else {
		next[key] = bytes.Clone(value)
	}
	data, err := json.Marshal(next)
	if err != nil {
		return err
	}
	var id [12]byte
	if _, err := rand.Read(id[:]); err != nil {
		return err
	}
	name := "state-" + hex.EncodeToString(id[:]) + ".tmp"
	f, err := s.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer s.root.Remove(name)
	if s.uid >= 0 {
		err = f.Chown(s.uid, s.gid)
	}
	if err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = s.root.Rename(name, "tailscaled.state"); err != nil {
		return err
	}
	s.cache = next
	return nil
}

func (s *tailscaleStateStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.lock != nil {
		_ = s.lock.Close()
	}
	return s.root.Close()
}
