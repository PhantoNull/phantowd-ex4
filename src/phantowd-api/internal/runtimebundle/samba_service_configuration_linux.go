//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sync"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"golang.org/x/sys/unix"
)

const sambaServiceSettings = `bind interfaces only = yes
smb ports = 445
server role = standalone server
security = user
map to guest = Never
restrict anonymous = 2
disable netbios = yes
server min protocol = SMB3_00
server signing = mandatory
load printers = no
printing = bsd
printcap name = /dev/null
disable spoolss = yes
dns proxy = no
name resolve order = host
dos charset = CP850
unix charset = UTF-8
private dir = /state/private
lock directory = /state/lock
state directory = /state/state
cache directory = /state/cache
pid directory = /state/pid
ncalrpc dir = /state/rpc
passdb backend = tdbsam:/state/private/passdb.tdb
`

func sambaServiceDocuments(candidate fileserviceplan.SambaIsolatedCandidate, address netip.Addr) (map[string]string, error) {
	if !address.Is4() || !address.IsGlobalUnicast() {
		return nil, ErrInvalid
	}
	passwd, group, nss, sections, roots, err := candidate.Documents()
	if err != nil || len(roots) == 0 || sections == "" {
		return nil, ErrInvalid
	}
	globals := "[global]\ninterfaces = " + address.String() + "\n" + sambaServiceSettings
	return boundedSambaDocuments(globals, passwd, group, nss, sections)
}

// SambaConfiguration owns the exact read-only configuration of one role.
// The caller holds the corresponding evidence through each worker or daemon
// lifetime. Close follows process-group settlement and descriptor release.
type SambaConfiguration struct {
	mu         sync.Mutex
	original   *SambaConfiguration
	enrollment bool
	workspace  string
	path       string
	mounted    bool
	mount      unix.Statx_t
	root       *os.File
	retained   *retainedConfiguration
	closeErr   error
}

const sambaConfigurationMountFlags = unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC

// StageSambaServiceConfiguration derives the bytes from one opaque candidate.
// It never takes a raw configuration document from the caller. On uncertain
// cleanup both the remaining owner and the error are returned for review.
func StageSambaServiceConfiguration(ctx context.Context, candidate fileserviceplan.SambaIsolatedCandidate,
	address netip.Addr) (*SambaConfiguration, error) {
	documents, err := sambaServiceDocuments(candidate, address)
	if err != nil {
		return nil, err
	}
	return stageSambaConfiguration(ctx, documents, false)
}

// StageSambaEnrollmentConfiguration derives a shareless credential profile
// from confirmed native accounts, including disabled accounts before creation.
// The credential worker separately enters its own inactive network namespace.
func StageSambaEnrollmentConfiguration(ctx context.Context, lookup fileserviceplan.SambaEnrollmentLookup) (*SambaConfiguration, error) {
	passwd, group, nss, err := lookup.LookupDocuments()
	if err != nil {
		return nil, ErrInvalid
	}
	documents, err := boundedSambaDocuments("[global]\ninterfaces = 127.0.0.1\n"+sambaServiceSettings, passwd, group, nss, "")
	if err != nil {
		return nil, err
	}
	return stageSambaConfiguration(ctx, documents, true)
}

func stageSambaConfiguration(ctx context.Context, documents map[string]string, enrollment bool) (output *SambaConfiguration, result error) {
	if ctx == nil || os.Getuid() != 0 || os.Geteuid() != 0 || !safeSambaConfigRun() {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	files := make([]File, 0, len(documents))
	for name, contents := range documents {
		mode := uint32(0644)
		if name == sambaSettingsPath {
			mode = 0600
		}
		files = append(files, File{Path: name, Mode: mode, Size: int64(len(contents)), SHA256: sha256.Sum256([]byte(contents))})
	}
	expected, err := newConfigurationPlan(files)
	if err != nil {
		return nil, err
	}
	workspace, err := os.MkdirTemp("/run", "phantowd-samba-config-")
	if err != nil {
		return nil, err
	}
	owner := &SambaConfiguration{workspace: workspace, enrollment: enrollment}
	owner.original = owner
	defer func() {
		if result != nil {
			if err := owner.Close(); err != nil {
				output, result = owner, errors.Join(result, err)
			}
		}
	}()
	if err := os.Chmod(workspace, 0700); err != nil {
		return nil, err
	}
	target := filepath.Join(workspace, "etc")
	if err := os.Mkdir(target, 0700); err != nil {
		return nil, err
	}
	owner.path = target
	if err := unix.Mount("tmpfs", target, "tmpfs", sambaConfigurationMountFlags, "mode=0755,uid=0,gid=0,size=128k,nr_inodes=32"); err != nil {
		return nil, err
	}
	owner.mounted = true
	fd, err := unix.Open(target, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	owner.root = os.NewFile(uintptr(fd), "samba-configuration")
	owner.mount, err = sambaConfigurationIdentity(fd, "", unix.AT_EMPTY_PATH)
	if err != nil {
		return nil, err
	}
	samba := filepath.Join(target, "samba")
	if err := os.Mkdir(samba, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(samba, 0755); err != nil {
		return nil, err
	}
	for _, file := range expected.plan.files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := writeSambaConfigurationFile(filepath.Join(target, file.Path), documents[file.Path], os.FileMode(file.Mode)); err != nil {
			return nil, err
		}
	}
	if err := unix.Mount("", target, "", unix.MS_REMOUNT|unix.MS_RDONLY|sambaConfigurationMountFlags, ""); err != nil {
		return nil, err
	}
	owner.retained, err = expected.retain(ctx, owner.root)
	if err != nil {
		return nil, err
	}
	return owner, nil
}

func safeSambaConfigRun() bool {
	var st unix.Stat_t
	var fs unix.Statfs_t
	return unix.Lstat("/run", &st) == nil && st.Mode == unix.S_IFDIR|0755 && st.Uid == 0 && st.Gid == 0 &&
		unix.Statfs("/run", &fs) == nil && fs.Type == unix.TMPFS_MAGIC
}

func writeSambaConfigurationFile(path, contents string, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	_, writeErr := file.WriteString(contents)
	return errors.Join(writeErr, file.Chmod(mode), file.Close())
}

// DuplicateRoot rechecks the complete expected tree before providing an
// independent O_PATH descriptor for the same original mount.
func (c *SambaConfiguration) DuplicateRoot(ctx context.Context) (*os.File, error) {
	if c == nil || c.original != c {
		return nil, ErrInvalid
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.retained == nil || !c.originalMountPresent() {
		return nil, ErrReviewRequired
	}
	if err := c.retained.revalidate(ctx); err != nil {
		return nil, err
	}
	return duplicateRoot(c.root)
}

// DuplicateEnrollmentRoot accepts only the confirmed native-lookup profile.
func (c *SambaConfiguration) DuplicateEnrollmentRoot(ctx context.Context) (*os.File, error) {
	if c == nil || !c.enrollment {
		return nil, ErrInvalid
	}
	return c.DuplicateRoot(ctx)
}

func sambaConfigurationIdentity(fd int, path string, flags int) (unix.Statx_t, error) {
	const mask = unix.STATX_MNT_ID_UNIQUE | unix.STATX_INO | unix.STATX_TYPE
	var observed unix.Statx_t
	if err := unix.Statx(fd, path, flags|unix.AT_NO_AUTOMOUNT, mask, &observed); err != nil {
		return unix.Statx_t{}, err
	}
	if observed.Mask&mask != mask || observed.Mnt_id == 0 || observed.Mode&unix.S_IFMT != unix.S_IFDIR ||
		observed.Attributes_mask&unix.STATX_ATTR_MOUNT_ROOT == 0 || observed.Attributes&unix.STATX_ATTR_MOUNT_ROOT == 0 {
		return unix.Statx_t{}, ErrMismatch
	}
	return observed, nil
}

func (c *SambaConfiguration) originalMountPresent() bool {
	if !c.mounted || c.mount.Mnt_id == 0 {
		return false
	}
	visible, err := sambaConfigurationIdentity(unix.AT_FDCWD, c.path, unix.AT_SYMLINK_NOFOLLOW)
	return err == nil && visible.Mnt_id == c.mount.Mnt_id && visible.Ino == c.mount.Ino
}

func (c *SambaConfiguration) Close() error {
	if c == nil || c.original != c {
		return ErrInvalid
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closeErr != nil {
		return c.closeErr
	}
	if c.mounted {
		if !c.originalMountPresent() {
			return ErrReviewRequired
		}
		if c.retained != nil {
			if err := c.retained.release(); err != nil {
				return errors.Join(ErrReviewRequired, err)
			}
			c.retained = nil
		}
		// Linux requires closing the pinned root before a non-lazy unmount.
		// Retain the mount identity so a busy unmount can safely be retried.
		if c.root != nil {
			if err := c.root.Close(); err != nil {
				c.closeErr = errors.Join(ErrReviewRequired, err)
				return c.closeErr
			}
			c.root = nil
		}
		if err := unix.Unmount(c.path, unix.UMOUNT_NOFOLLOW); err != nil {
			return errors.Join(ErrReviewRequired, err)
		}
		c.mounted = false
	}
	if c.path != "" {
		if err := os.Remove(c.path); err != nil {
			return err
		}
		c.path = ""
	}
	if c.workspace != "" {
		if err := os.Remove(c.workspace); err != nil {
			return err
		}
		c.workspace = ""
	}
	return nil
}
