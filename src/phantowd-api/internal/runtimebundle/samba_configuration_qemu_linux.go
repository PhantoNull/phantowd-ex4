//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
)

// Fixed independent fixture expectations, never hashes measured from /etc.
// These test identities/configuration are not the product identity authority.
func sambaFixtureConfiguration() (*configurationPlan, error) {
	contents := map[string]string{
		"passwd":        "root:x:0:0:root:/:/sbin/nologin\nnobody:x:65534:65534:nobody:/:/sbin/nologin\nqpwriter:x:1801:1800:writer:/:/sbin/nologin\nqpreader:x:1802:1800:reader:/:/sbin/nologin\nqpoutsider:x:1803:1800:outsider:/:/sbin/nologin\n",
		"group":         "root:x:0:\nnogroup:x:65534:\nqpgroup:x:1800:qpwriter,qpreader,qpoutsider\n",
		"nsswitch.conf": "passwd: files\ngroup: files\nshadow: files\nhosts: files\nnetworks: files\nprotocols: files\nservices: files\n",
		"hosts":         "127.0.0.1 localhost\n",
		"protocols":     "tcp 6 TCP\nudp 17 UDP\n",
		"services":      "microsoft-ds 445/tcp\n",
		"samba/smb.conf": strings.Join([]string{
			"[global]", "server role = standalone server", "security = user", "map to guest = Never",
			"interfaces = 127.0.0.1", "bind interfaces only = yes", "smb ports = 1445",
			"server min protocol = SMB3_00", "server max protocol = SMB3_11", "server signing = mandatory",
			"load printers = no", "printing = bsd", "dos charset = CP850", "unix charset = UTF-8",
			"map archive = no", "map system = no", "map hidden = no", "store dos attributes = yes",
			"printcap name = /dev/null", "disable spoolss = yes", "dns proxy = no", "name resolve order = host",
			"vfs objects = streams_xattr", "streams_xattr:prefix = user.DosStream.",
			"streams_xattr:store_stream_type = yes", "log file = /state/log.smbd",
			"private dir = /state/private", "lock directory = /state/lock", "state directory = /state/state",
			"cache directory = /state/cache", "pid directory = /state/pid", "ncalrpc dir = /state/rpc",
			"passdb backend = tdbsam:/state/private/passdb.tdb",
			"[ReadWrite]", "path = /shares/rw", "guest ok = no", "read only = yes",
			"valid users = qpwriter qpreader", "read list = qpreader", "write list = qpwriter",
			"follow symlinks = no", "wide links = no", "create mask = 0660", "directory mask = 0770",
			"[KernelReadOnly]", "path = /shares/ro", "guest ok = no", "read only = no",
			"valid users = qpwriter", "follow symlinks = no",
			"[UnixDenied]", "path = /shares/denied", "guest ok = no", "read only = no", "valid users = qpwriter",
			"[PosixACL]", "path = /shares/rw", "guest ok = no", "read only = no",
			"valid users = qpwriter qpreader qpoutsider",
			"[OriginalAnchor]", "path = /run/phantowd-samba-source/approved", "guest ok = no",
			"read only = no", "valid users = qpwriter", "",
		}, "\n"),
	}
	files := make([]File, 0, len(contents))
	for name, data := range contents {
		mode := uint32(0644)
		if name == "samba/smb.conf" {
			mode = 0600
		}
		files = append(files, File{Path: name, SHA256: sha256.Sum256([]byte(data)), Size: int64(len(data)), Mode: mode})
	}
	return newConfigurationPlan(files)
}

func (p *Plan) newSambaConfigurationQEMU(ctx context.Context, code, configuration *os.File) (*Owner, error) {
	if ctx == nil || configuration == nil {
		return nil, ErrInvalid
	}
	owner, err := p.newSambaCodeLifetimeQEMU(ctx, code)
	if err != nil {
		return nil, err
	}
	expected, err := sambaFixtureConfiguration()
	if err == nil {
		owner.configuration, err = expected.retain(ctx, configuration)
	}
	if err == nil {
		fd, openErr := unix.Open("/run/phantowd-samba-state", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		err = openErr
		if err == nil {
			caller := os.NewFile(uintptr(fd), "fixed-disposable-samba-state")
			owner.sambaState, err = retainSambaState(ctx, caller)
			err = errors.Join(err, caller.Close())
		}
	}
	if err == nil {
		err = owner.revalidate(ctx) // Late combined fence after all fixed inputs.
	}
	if err != nil {
		return nil, errors.Join(err, owner.release())
	}
	return owner, nil
}

// No Owner or descriptors escape. Fixed root-only disposable QEMU controller
// exercises real Samba with original config/state objects and metadata faults.
func (p *Plan) ProbeSambaConfigurationLifetimeQEMU(ctx context.Context, code, configuration, writer *os.File) error {
	if p == nil || ctx == nil || code == nil || configuration == nil || writer == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := sambaCodeFixtureGuard(); err != nil {
		return err
	}
	readerInfo, err := configuration.Stat()
	writerInfo, writerErr := writer.Stat()
	var fs unix.Statfs_t
	if err != nil || writerErr != nil || !os.SameFile(readerInfo, writerInfo) ||
		unix.Fstatfs(int(writer.Fd()), &fs) != nil || fs.Type != unix.TMPFS_MAGIC || fs.Flags&unix.ST_RDONLY != 0 {
		return ErrInvalid
	}
	for _, fault := range []string{"none", "configuration", "state"} {
		if err := p.sambaConfigurationCase(ctx, code, configuration, writer, fault); err != nil {
			return err
		}
	}
	fmt.Println("PHANTOWD_SAMBA_OWNER_CONFIG_LIFETIME_READY exact_contents=true caller_close=true live_pins=true same_child_objects=true readonly_noexec=true normal_stop=true drift_stopped=true review_retained=true restoration_refused=true released=true scope=qemu-only")
	fmt.Println("PHANTOWD_SAMBA_OWNER_STATE_LIFETIME_READY caller_close=true live_directory_pins=true same_child_objects=true writable_noexec=true mutable_passdb=true normal_stop=true drift_stopped=true review_retained=true restoration_refused=true released=true scope=qemu-only")
	return nil
}

func (p *Plan) sambaConfigurationCase(ctx context.Context, code, configuration, writer *os.File, fault string) (result error) {
	caller, err := duplicateRoot(configuration)
	if err != nil {
		return err
	}
	o, err := p.newSambaConfigurationQEMU(ctx, code, caller)
	callerErr := caller.Close()
	if err != nil || callerErr != nil {
		if o != nil {
			return errors.Join(err, callerErr, o.Close(context.Background()))
		}
		return errors.Join(err, callerErr)
	}
	defer func() { result = errors.Join(result, o.Close(context.Background())) }()
	started, err := o.Start(ctx)
	if err != nil || started.State != processowner.StateReady {
		return errors.Join(errors.New("protected config readiness"), err)
	}
	pid := started.Processes.Members[0].Process.PID
	for name, pin := range o.configuration.contents.files {
		original, err := pin.Stat()
		actualPath := "/proc/" + strconv.Itoa(pid) + "/root/etc/" + name
		actual, actualErr := os.Stat(actualPath)
		if err != nil || actualErr != nil || !os.SameFile(original, actual) {
			return errors.New("child configuration is not retained object")
		}
		fd, err := unix.Open(actualPath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		view := os.NewFile(uintptr(fd), "fixed-child-config-view")
		if err := errors.Join(configurationMount(view), view.Close()); err != nil {
			return errors.Join(errors.New("child configuration mount flags"), err)
		}
	}
	if err := o.verifyLiveSambaCodeQEMU(pid); err != nil {
		return err
	}
	if err := o.verifyLiveSambaStateQEMU(pid); err != nil {
		return err
	}
	if fault != "none" {
		root, name, originalMode, changedMode := writer, "samba/smb.conf", uint32(0600), uint32(0644)
		if fault == "state" {
			root, name, originalMode, changedMode = o.sambaState.root, "private", 0700, 0755
		}
		fd, err := openBeneath(int(root.Fd()), name, unix.O_RDONLY)
		if err != nil {
			return err
		}
		control := os.NewFile(uintptr(fd), "fixed-samba-input-fault")
		defer control.Close()
		if unix.Fchmod(fd, changedMode) != nil {
			return errors.New("input fault failed")
		}
		defer unix.Fchmod(fd, originalMode)
		observed, err := o.Observe(ctx)
		if !errors.Is(err, ErrReviewRequired) || observed.State != processowner.StateReviewRequired ||
			!errors.Is(unix.Kill(-pid, 0), unix.ESRCH) || len(o.configuration.contents.files) != 7 || len(o.sambaState.files) != 7 {
			return errors.Join(errors.New("input drift did not stop and retain"), err)
		}
		for _, pin := range o.configuration.contents.files {
			if _, err := pin.Stat(); err != nil {
				return err
			}
		}
		for _, pin := range o.sambaState.files {
			if _, err := pin.Stat(); err != nil {
				return err
			}
		}
		if unix.Fchmod(fd, originalMode) != nil {
			return errors.New("input restoration failed")
		}
		if observed, err := o.Start(ctx); !errors.Is(err, ErrReviewRequired) || observed.State != processowner.StateReviewRequired {
			return errors.New("restored input restarted reviewed service")
		}
	}
	closeErr := o.Close(context.Background())
	if (fault == "none" && closeErr != nil) || (fault != "none" && !errors.Is(closeErr, ErrReviewRequired)) ||
		!errors.Is(unix.Kill(-pid, 0), unix.ESRCH) || o.configuration != nil || o.sambaState != nil || o.root != nil || len(o.files) != 0 {
		return errors.Join(errors.New("input release not verified"), closeErr)
	}
	return nil
}

func (o *Owner) verifyLiveSambaStateQEMU(pid int) error {
	for name, pin := range o.sambaState.files {
		original, err := pin.Stat()
		actualPath := "/proc/" + strconv.Itoa(pid) + "/root/state/" + name
		actual, actualErr := os.Stat(actualPath)
		if err != nil || actualErr != nil || !os.SameFile(original, actual) {
			return errors.New("child state is not retained object")
		}
		fd, err := unix.Open(actualPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		_, inspectErr := inspectSambaState(fd)
		var fs unix.Statfs_t
		fsErr := unix.Fstatfs(fd, &fs)
		closeErr := unix.Close(fd)
		const protected = unix.ST_NOSUID | unix.ST_NODEV | unix.ST_NOEXEC
		if inspectErr != nil || fsErr != nil || closeErr != nil || fs.Flags&protected != protected {
			return errors.New("child state mount flags or permissions")
		}
	}
	// Samba's existing synthetic enrollment created this mutable database; do
	// not read/hash its credential bytes or call that database identity-owned.
	info, err := os.Stat("/proc/" + strconv.Itoa(pid) + "/root/state/private/passdb.tdb")
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		return errors.New("mutable fixture passdb missing")
	}
	return o.sambaState.revalidate(context.Background())
}
