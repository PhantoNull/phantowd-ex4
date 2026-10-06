// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package identityrpc

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"golang.org/x/sys/unix"
)

const socketName = "channel"
const maxConnections = 4

// Listener owns one protected pathname and bounded connection workers. Never
// copy it. The caller retains the Server and its operation until Close returns.
type Listener struct {
	mu       sync.Mutex
	once     sync.Once
	server   *Server
	socket   *net.UnixListener
	dir      int
	gid      uint32
	identity unix.Stat_t
	started  bool
	closed   bool
	cancel   context.CancelFunc
	done     chan struct{}
	closeErr error
}

// Listen requires an existing root:apiGID 0710 directory, trusted parents and
// a dedicated non-root API group. It neither creates nor repairs directories.
// Parents and directory must not be moved/replaced by other root tools while
// in use. A directory flock excludes cooperating owners of this exact inode,
// not privileged writers or a second authority configured at another path.
func Listen(directory string, apiGID uint32, server *Server) (*Listener, error) {
	if os.Getuid() != 0 || os.Geteuid() != 0 || apiGID == 0 || apiGID > 65534 || !server.available() ||
		!filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, ErrInvalid
	}
	dir, err := unix.Openat2(unix.AT_FDCWD, directory, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, ErrChannel
	}
	l := &Listener{server: server, dir: dir, gid: apiGID, done: make(chan struct{})}
	good := false
	defer func() {
		if !good {
			l.finish()
		}
	}()
	if !l.directorySafe() {
		return nil, ErrChannel
	}
	if err := unix.Flock(dir, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrBusy
		}
		return nil, ErrChannel
	}
	// Bind relative to a retained descriptor, without changing cwd or umask.
	// This also keeps sockaddr_un short even for a long configured directory.
	path := "/proc/self/fd/" + strconv.Itoa(dir) + "/" + socketName
	if err := l.removeStale(path); err != nil {
		return nil, err
	}
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return nil, ErrChannel
	}
	f := os.NewFile(uintptr(fd), "identity-listener")
	defer f.Close()
	if unix.Bind(fd, &unix.SockaddrUnix{Name: path}) != nil {
		return nil, ErrChannel
	}
	if unix.Fstatat(dir, socketName, &l.identity, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return nil, ErrChannel
	}
	if unix.Fchownat(dir, socketName, 0, int(apiGID), unix.AT_SYMLINK_NOFOLLOW) != nil ||
		unix.Fchmodat(dir, socketName, 0620, 0) != nil || !l.socketSafe(l.identity) ||
		unix.Listen(fd, 8) != nil {
		return nil, ErrChannel
	}
	listener, err := net.FileListener(f)
	if err != nil {
		return nil, ErrChannel
	}
	l.socket = listener.(*net.UnixListener)
	l.socket.SetUnlinkOnClose(false) // cleanup checks the bound inode, not just a name
	good = true
	return l, nil
}

func (l *Listener) directorySafe() bool {
	var st unix.Stat_t
	return unix.Fstat(l.dir, &st) == nil && st.Mode == unix.S_IFDIR|0710 && st.Uid == 0 && st.Gid == l.gid
}

func (l *Listener) socketSafe(identity unix.Stat_t) bool {
	var st, parent unix.Stat_t
	return unix.Fstatat(l.dir, socketName, &st, unix.AT_SYMLINK_NOFOLLOW) == nil &&
		unix.Fstat(l.dir, &parent) == nil && st.Dev == parent.Dev &&
		st.Dev == identity.Dev && st.Ino == identity.Ino && st.Mode == unix.S_IFSOCK|0620 &&
		st.Uid == 0 && st.Gid == l.gid && st.Nlink == 1
}

// A crash may leave a pathname. Only an exact protected socket with no listener
// is recoverable. A live listener, other type/owner/mode, or ambiguous connect
// error is preserved. The probe is nonblocking and sends no request bytes.
func (l *Listener) removeStale(path string) error {
	var st unix.Stat_t
	err := unix.Fstatat(l.dir, socketName, &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil || !l.socketSafe(st) {
		return ErrChannel
	}
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return ErrChannel
	}
	defer unix.Close(fd)
	err = unix.Connect(fd, &unix.SockaddrUnix{Name: path})
	if !errors.Is(err, unix.ECONNREFUSED) || !l.socketSafe(st) || unix.Unlinkat(l.dir, socketName, 0) != nil {
		return ErrChannel
	}
	return nil
}

// Run may be called once. Cancellation closes admission and active connections,
// then drains all workers before releasing the pathname/lease. Backend or kernel
// stalls can delay draining: this is not a hard shutdown deadline. Connection
// failures are isolated; no failed request is retried or queued in userspace.
func (l *Listener) Run(ctx context.Context) (result error) {
	if l == nil || ctx == nil {
		return ErrInvalid
	}
	l.mu.Lock()
	if l.socket == nil || l.started || l.closed {
		l.mu.Unlock()
		return ErrChannel
	}
	l.started = true
	ctx, l.cancel = context.WithCancel(ctx)
	cancel := l.cancel
	l.mu.Unlock()
	var workers sync.WaitGroup
	slots := make(chan struct{}, maxConnections)
	stop := context.AfterFunc(ctx, func() { l.socket.Close() })
	defer func() {
		cancel()
		l.socket.Close()
		stop()
		workers.Wait()
		l.finish()
		if l.closeErr != nil {
			result = l.closeErr
		}
	}()
	for {
		conn, err := l.socket.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return ErrChannel
		}
		if ctx.Err() != nil || !l.directorySafe() || !l.socketSafe(l.identity) {
			conn.Close()
			if ctx.Err() != nil {
				return nil
			}
			return ErrChannel
		}
		select {
		case slots <- struct{}{}:
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer func() { <-slots }()
				_ = l.server.Serve(ctx, conn)
			}()
		default:
			conn.Close()
		}
	}
}

// Close is idempotent, including before Run, and waits for active operations.
// Only after it returns may the caller close the authority or its stores.
func (l *Listener) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	if l.socket == nil { // zero value, not an initialized listener
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	if l.cancel != nil {
		l.cancel()
	}
	l.socket.Close()
	started := l.started
	l.mu.Unlock()
	if !started {
		l.finish()
	}
	<-l.done
	return l.closeErr
}

func (l *Listener) finish() {
	l.once.Do(func() {
		if l.socket != nil {
			l.socket.Close()
		}
		// For setup failures the captured inode can have pre-final permissions.
		// Still never unlink a replacement, symlink, hardlink or foreign owner.
		if l.identity.Ino != 0 {
			var st unix.Stat_t
			if !l.directorySafe() || (l.socket != nil && !l.socketSafe(l.identity)) || unix.Fstatat(l.dir, socketName, &st, unix.AT_SYMLINK_NOFOLLOW) != nil ||
				st.Dev != l.identity.Dev || st.Ino != l.identity.Ino || st.Mode&unix.S_IFMT != unix.S_IFSOCK ||
				st.Uid != 0 || st.Nlink != 1 || unix.Unlinkat(l.dir, socketName, 0) != nil {
				l.closeErr = ErrChannel
			}
		}
		if unix.Close(l.dir) != nil {
			l.closeErr = ErrChannel
		}
		close(l.done)
	})
}
