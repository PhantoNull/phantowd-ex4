//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicyrpc"
	"golang.org/x/sys/unix"
)

// Trusted startup configuration only. Parents must be root-managed. The held
// stream, not a later pathname lookup, is the authority: no reconnect/fallback.
// This never creates a socket, opens state or admits an Owner at product boot.
func openNASPolicyHTTP(auth *authController, path string, legacy, tls bool) (http.Handler, func() error, error) {
	if path == "" {
		return nil, func() error { return nil }, nil
	}
	refused := errors.New("NAS policy channel unavailable")
	if auth == nil || legacy || !tls || os.Getuid() == 0 || os.Geteuid() == 0 || os.Getgid() == 0 || os.Getgid() > 65534 || !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != "channel" {
		return nil, nil, refused
	}
	dir, err := unix.Openat2(unix.AT_FDCWD, filepath.Dir(path), &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, nil, refused
	}
	keep := false
	var conn *net.UnixConn
	var client *naspolicyrpc.Client
	defer func() {
		if !keep {
			if client != nil {
				client.Close()
			} else if conn != nil {
				conn.Close()
			}
			unix.Close(dir)
		}
	}()
	var parent, before, after, finalParent unix.Stat_t
	gid := uint32(os.Getgid())
	socketSafe := func(st unix.Stat_t) bool {
		return st.Mode == unix.S_IFSOCK|0660 && st.Uid == 0 && st.Gid == gid && st.Nlink == 1 && st.Dev == parent.Dev
	}
	if unix.Fstat(dir, &parent) != nil || parent.Mode != unix.S_IFDIR|0710 || parent.Uid != 0 || parent.Gid != gid || unix.Fstatat(dir, "channel", &before, unix.AT_SYMLINK_NOFOLLOW) != nil || !socketSafe(before) {
		return nil, nil, refused
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(ctx, "unix", "/proc/self/fd/"+strconv.Itoa(dir)+"/channel")
	if err != nil {
		return nil, nil, refused
	}
	conn = raw.(*net.UnixConn)
	client, err = naspolicyrpc.NewClient(conn)
	if err != nil {
		return nil, nil, refused
	}
	if unix.Fstat(dir, &finalParent) != nil || finalParent.Mode != parent.Mode || finalParent.Uid != 0 || finalParent.Gid != gid || unix.Fstatat(dir, "channel", &after, unix.AT_SYMLINK_NOFOLLOW) != nil || !socketSafe(after) || after.Ino != before.Ino || after.Ctim != before.Ctim {
		return nil, nil, refused
	}
	var once sync.Once
	var closeErr error
	close := func() error {
		once.Do(func() {
			if errors.Join(client.Close(), unix.Close(dir)) != nil {
				closeErr = refused
			}
		})
		return closeErr
	}
	keep = true
	return newNASStateHandler(auth, client), close, nil
}
