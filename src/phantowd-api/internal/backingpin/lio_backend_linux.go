//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package backingpin

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsicredentials"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"golang.org/x/sys/unix"
)

// Private prerequisite only. Caller must independently qualify code, storage,
// allocation/access/global-use/network and exclusive configfs mutation authority.
// This prototype accepts CHAP only; mutual-only enforcement is NOT inferred
// from configured outbound credentials. No product constructor/HTTP/startup.
type lioBackend struct {
	nonSerializable
	target                                           iscsipolicy.Target
	definitions                                      map[iscsipolicy.BackingID]iscsipolicy.Backing
	fabric, core                                     *os.File // independently owned duplicates, not caller-closeable
	fabricID, coreID                                 lioAuthIdentity
	entries                                          []*lioOwnedEntry
	tpg                                              *os.File
	auth                                             []*os.File
	sink                                             *lioCredentialSink
	members                                          []targetBacking // borrowed from containing complete-target owner
	storages, luns                                   []*os.File
	attributes                                       []lioExpectedAttribute
	topology                                         []lioDirectoryRoster
	prepared, started, ready, stopAttempted, stopped bool
	prepareAttempted                                 bool
}

type lioExpectedAttribute struct {
	directory   *os.File
	name, value string
}

// Only non-secret, fixed attributes enter this retained observation roster.
func (b *lioBackend) setExpected(directory *os.File, name, value string) error {
	if err := lioBackendSet(directory, name, value, true); err != nil {
		return err
	}
	b.attributes = append(b.attributes, lioExpectedAttribute{directory, name, value})
	return nil
}

func (b *lioBackend) checkExpected(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrReview
	}
	for _, attr := range b.attributes {
		if ctx.Err() != nil || lioBackendCheck(attr.directory, attr.name, attr.value) != nil {
			return ErrReview
		}
	}
	return nil
}

type lioOwnedEntry struct {
	parent    *os.File
	name      string
	file      *os.File
	id        lioAuthIdentity
	link      bool
	linkInode uint64
	removed   bool
}

func lioTargetDefinition(document naspolicy.Config, id iscsipolicy.TargetID) (iscsipolicy.Target, map[iscsipolicy.BackingID]iscsipolicy.Backing, error) {
	if !knownTargetUseAllowed(document, id) {
		return iscsipolicy.Target{}, nil, ErrInvalid
	}
	for _, target := range document.ISCSI.Targets {
		if target.ID != id {
			continue
		}
		target.LUNs = append([]iscsipolicy.LUN(nil), target.LUNs...)
		sort.Slice(target.LUNs, func(i, j int) bool { return target.LUNs[i].Number < target.LUNs[j].Number })
		target.Initiators = append([]iscsipolicy.Initiator(nil), target.Initiators...)
		for i := range target.Initiators {
			if target.Initiators[i].Authentication.Mode != "chap" {
				return iscsipolicy.Target{}, nil, ErrUnavailable
			}
			target.Initiators[i].Grants = append([]iscsipolicy.Grant(nil), target.Initiators[i].Grants...)
		}
		definitions := map[iscsipolicy.BackingID]iscsipolicy.Backing{}
		for _, backing := range document.ISCSI.Backings {
			definitions[backing.ID] = backing
		}
		return target, definitions, nil
	}
	return iscsipolicy.Target{}, nil, ErrInvalid
}

func newLIOBackend(document naspolicy.Config, id iscsipolicy.TargetID, fabric, core *os.File) (*lioBackend, error) {
	target, definitions, err := lioTargetDefinition(document, id)
	if err != nil {
		return nil, err
	}
	fid, err := lioConfigIdentity(fabric, true)
	if err != nil {
		return nil, err
	}
	cid, err := lioConfigIdentity(core, true)
	if err != nil || fid.mount != cid.mount || fid == cid {
		return nil, ErrUnavailable
	}
	dup := func(input *os.File) (*os.File, error) {
		fd, err := unix.FcntlInt(input.Fd(), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			return nil, ErrUnavailable
		}
		return os.NewFile(uintptr(fd), "owned-lio-config-root"), nil
	}
	f, err := dup(fabric)
	if err != nil {
		return nil, err
	}
	c, err := dup(core)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	b := &lioBackend{target: target, definitions: definitions, fabric: f, core: c, fabricID: fid, coreID: cid}
	if b.checkRoots() != nil {
		_ = f.Close()
		_ = c.Close()
		return nil, ErrUnavailable
	}
	return b, nil
}

func (b *lioBackend) checkRoots() error {
	f, err := lioConfigIdentity(b.fabric, true)
	if err != nil || f != b.fabricID {
		return ErrReview
	}
	c, err := lioConfigIdentity(b.core, true)
	if err != nil || c != b.coreID {
		return ErrReview
	}
	return nil
}

func lioBackendLeaf(directory *os.File, name string, flags int) (*os.File, error) {
	switch name {
	case "control", "enable", "disable_if_idle", "attrib/block_size", "attrib/emulate_fua_write", "attrib/emulate_write_cache",
		"attrib/authentication", "attrib/generate_node_acls", "attrib/prod_mode_write_protect", "param/AuthMethod", "write_protect", "info":
	default:
		return nil, ErrInvalid
	}
	id, err := lioConfigIdentity(directory, true)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Openat2(int(directory.Fd()), name, &unix.OpenHow{Flags: uint64(flags | unix.O_CLOEXEC | unix.O_NOFOLLOW),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return nil, ErrUnavailable
	}
	f := os.NewFile(uintptr(fd), "fixed-lio-state-attribute")
	leaf, err := lioConfigIdentity(f, false)
	if err != nil || leaf.mount != id.mount {
		_ = f.Close()
		return nil, ErrUnavailable
	}
	return f, nil
}

func lioBackendWriteFlags(name string, readback bool) (int, error) {
	if name == "control" || name == "disable_if_idle" {
		if readback {
			return 0, ErrInvalid
		}
		return unix.O_WRONLY, nil
	}
	if !readback {
		return 0, ErrInvalid
	}
	return unix.O_RDWR, nil
}

func lioBackendSet(directory *os.File, name, value string, readback bool) error {
	flags, err := lioBackendWriteFlags(name, readback)
	if err != nil {
		return err
	}
	f, err := lioBackendLeaf(directory, name, flags)
	if err != nil {
		return err
	}
	n, writeErr := f.Write([]byte(value))
	var compareErr error
	if writeErr == nil && n == len(value) && readback {
		compareErr = lioCompareAttribute(f, []byte(value))
	}
	closeErr := f.Close()
	if writeErr != nil || n != len(value) || compareErr != nil || closeErr != nil {
		return ErrReview
	}
	return nil
}
func lioBackendCheck(directory *os.File, name, value string) error {
	f, err := lioBackendLeaf(directory, name, unix.O_RDONLY)
	if err != nil {
		return err
	}
	compareErr := lioCompareAttribute(f, []byte(value))
	closeErr := f.Close()
	if compareErr != nil || closeErr != nil {
		return ErrReview
	}
	return nil
}

func (b *lioBackend) directory(parent *os.File, name string) (*os.File, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00\n") {
		return nil, ErrInvalid
	}
	if unix.Mkdirat(int(parent.Fd()), name, 0755) != nil {
		return nil, ErrUnavailable
	}
	entry := &lioOwnedEntry{parent: parent, name: name}
	b.entries = append(b.entries, entry) // Track even a subsequent uncertain open.
	fd, err := unix.Openat2(int(parent.Fd()), name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return nil, ErrReview
	}
	entry.file = os.NewFile(uintptr(fd), "owned-lio-object")
	entry.id, err = lioConfigIdentity(entry.file, true)
	if err != nil {
		return nil, ErrReview
	}
	return entry.file, nil
}

func (b *lioBackend) fixedGroup(parent *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat2(int(parent.Fd()), name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return nil, ErrUnavailable
	}
	f := os.NewFile(uintptr(fd), "owned-lio-default-group")
	id, err := lioConfigIdentity(f, true)
	if err != nil {
		_ = f.Close()
		return nil, ErrUnavailable
	}
	// Default groups are retained but removed by the kernel with their parent.
	b.entries = append(b.entries, &lioOwnedEntry{file: f, id: id})
	return f, nil
}

func (b *lioBackend) link(parent *os.File, name string, destination *os.File) error {
	if name != "backing" && name != "grant" {
		return ErrInvalid
	}
	if unix.Symlinkat(fmt.Sprintf("/proc/self/fd/%d", destination.Fd()), int(parent.Fd()), name) != nil {
		return ErrUnavailable
	}
	entry := &lioOwnedEntry{parent: parent, name: name, file: destination, link: true}
	b.entries = append(b.entries, entry)
	var st unix.Stat_t
	if unix.Fstatat(int(parent.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || st.Mode&unix.S_IFMT != unix.S_IFLNK || st.Uid != 0 {
		return ErrReview
	}
	entry.linkInode = st.Ino
	var err error
	entry.id, err = lioConfigIdentity(destination, true)
	return err
}

func (b *lioBackend) checkEntries() error {
	if b.checkRoots() != nil {
		return ErrReview
	}
	for _, entry := range b.entries {
		if entry.removed {
			continue
		}
		id, err := lioConfigIdentity(entry.file, true)
		if err != nil || id != entry.id {
			return ErrReview
		}
		if entry.name == "" {
			continue
		}
		flags := unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC
		if entry.link {
			var st unix.Stat_t
			if unix.Fstatat(int(entry.parent.Fd()), entry.name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || st.Mode&unix.S_IFMT != unix.S_IFLNK || st.Ino != entry.linkInode || st.Uid != 0 {
				return ErrReview
			}
		} else {
			flags |= unix.O_NOFOLLOW
		}
		// Following only an owned, witnessed configfs link is intentional here.
		fd, err := unix.Openat(int(entry.parent.Fd()), entry.name, flags, 0)
		if err != nil {
			return ErrReview
		}
		current := os.NewFile(uintptr(fd), "lio-object-recheck")
		observed, observeErr := lioConfigIdentity(current, true)
		closeErr := current.Close()
		if observeErr != nil || closeErr != nil || observed != entry.id {
			return ErrReview
		}
	}
	return nil
}

func (b *lioBackend) PrepareCredentials(ctx context.Context, peers []iscsicredentials.Credential) error {
	if b == nil || ctx == nil || ctx.Err() != nil || b.prepareAttempted || b.stopAttempted || b.checkRoots() != nil {
		return ErrUnavailable
	}
	if len(peers) != len(b.target.Initiators) {
		return ErrInvalid
	}
	for _, desired := range b.target.Initiators {
		found := 0
		for _, peer := range peers {
			if peer.InitiatorName != desired.Name {
				continue
			}
			found++
			if peer.Mode != "chap" || peer.InitiatorUser != desired.Authentication.InitiatorUser || peer.TargetUser != "" {
				return ErrInvalid
			}
			if _, err := peer.Incoming.WriteTo(io.Discard); err != nil {
				return ErrUnavailable
			}
		}
		if found != 1 {
			return ErrInvalid
		}
	}
	b.prepareAttempted = true // Never repeat after any possible configfs effect.
	target, err := b.directory(b.fabric, b.target.Name)
	if err != nil {
		return err
	}
	// target_fabric_make_wwn uses tf_tpg_cit (no attributes), not tf_wwn_cit.
	// lio_version/cpus_allowed_list belong to the fabric root, not this target.
	b.topology = append(b.topology, lioDirectoryRoster{target, []string{"fabric_statistics", "param", "tpgt_1"}})
	b.tpg, err = b.directory(target, "tpgt_1")
	if err != nil {
		return err
	}
	b.topology = append(b.topology, lioDirectoryRoster{b.tpg, []string{"lun", "np", "acls", "attrib", "auth", "param", "enable", "rtpi", "dynamic_sessions", "disable_if_idle"}})
	// Required non-forcing primitive, checked BEFORE any portal or data binding.
	guard, err := lioBackendLeaf(b.tpg, "disable_if_idle", unix.O_WRONLY)
	if err != nil {
		return ErrUnavailable
	}
	if guard.Close() != nil {
		return ErrReview
	}
	for _, attr := range [][2]string{{"attrib/authentication", "1"}, {"attrib/generate_node_acls", "0"}, {"attrib/prod_mode_write_protect", "0"}, {"param/AuthMethod", "CHAP"}} {
		if b.setExpected(b.tpg, attr[0], attr[1]) != nil {
			return ErrReview
		}
	}
	acls, err := b.fixedGroup(b.tpg, "acls")
	if err != nil {
		return err
	}
	var selected []lioAuthSelection
	peerNames := make([]string, 0, len(b.target.Initiators))
	for _, desired := range b.target.Initiators {
		acl, err := b.directory(acls, desired.Name)
		if err != nil {
			return err
		}
		b.auth = append(b.auth, acl)
		peerNames = append(peerNames, desired.Name)
		aclNames := []string{"attrib", "auth", "param", "fabric_statistics", "info", "cmdsn_depth", "tag"}
		for _, grant := range desired.Grants {
			for _, lun := range b.target.LUNs {
				if lun.ID == grant.LUNID {
					aclNames = append(aclNames, "lun_"+strconv.Itoa(int(lun.Number)))
				}
			}
		}
		b.topology = append(b.topology, lioDirectoryRoster{acl, aclNames})
		auth, err := b.fixedGroup(acl, "auth")
		if err != nil {
			return err
		}
		selected = append(selected, lioAuthSelection{name: desired.Name, auth: auth})
	}
	b.topology = append(b.topology, lioDirectoryRoster{acls, peerNames})
	b.sink, err = newLIOCredentialSink(b.tpg, selected)
	if err != nil {
		return err
	}
	if b.sink.PrepareCredentials(ctx, peers) != nil {
		return ErrReview
	}
	b.prepared = true
	return nil
}

func (b *lioBackend) matchMembers(members []targetBacking) bool {
	if len(members) != len(b.target.LUNs) {
		return false
	}
	for i, lun := range b.target.LUNs {
		member, definition := members[i], b.definitions[lun.BackingID]
		if member.lunID != lun.ID || member.number != lun.Number || member.backingID != lun.BackingID || member.access != lun.Access ||
			member.capacity != definition.CapacityBytes || member.blockSize != definition.BlockSize || member.file == nil {
			return false
		}
	}
	return true
}

func (b *lioBackend) startTarget(ctx context.Context, members []targetBacking) error {
	if b == nil || ctx == nil || ctx.Err() != nil || !b.prepared || b.started || b.stopAttempted || !b.matchMembers(members) || b.checkEntries() != nil || b.checkExpected(ctx) != nil || b.sink.verifyDisabled(ctx) != nil {
		return ErrUnavailable
	}
	b.started = true // Partial setup is retained for one verified stop attempt.
	b.members = append([]targetBacking(nil), members...)
	luns, err := b.fixedGroup(b.tpg, "lun")
	if err != nil {
		return err
	}
	lunNames := make([]string, 0, len(b.members))
	for _, member := range b.members {
		storage, err := b.directory(b.core, "phantowd-"+string(b.target.ID)+"-"+strconv.Itoa(int(member.number)))
		if err != nil {
			return err
		}
		b.storages = append(b.storages, storage)
		// Integer-only retained descriptor binding. NEVER interpolate desired paths.
		control := fmt.Sprintf("fd_dev_name=/proc/self/fd/%d,fd_dev_size=%d", member.file.Fd(), member.capacity)
		if lioBackendSet(storage, "control", control, false) != nil || b.setExpected(storage, "enable", "1") != nil ||
			b.setExpected(storage, "attrib/block_size", strconv.Itoa(int(member.blockSize))) != nil ||
			b.setExpected(storage, "attrib/emulate_fua_write", "0") != nil || lioBackendCheck(storage, "attrib/emulate_write_cache", "0") != nil {
			return ErrReview
		}
		b.attributes = append(b.attributes, lioExpectedAttribute{storage, "attrib/emulate_write_cache", "0"})
		lun, err := b.directory(luns, "lun_"+strconv.Itoa(int(member.number)))
		if err != nil {
			return err
		}
		b.luns = append(b.luns, lun)
		lunNames = append(lunNames, "lun_"+strconv.Itoa(int(member.number)))
		b.topology = append(b.topology, lioDirectoryRoster{lun, []string{"statistics", "alua_tg_pt_gp", "alua_tg_pt_offline", "alua_tg_pt_status", "alua_tg_pt_write_md", "backing"}})
		if b.link(lun, "backing", storage) != nil {
			return ErrReview
		}
	}
	b.topology = append(b.topology, lioDirectoryRoster{luns, lunNames})
	for i, peer := range b.target.Initiators {
		for _, grant := range peer.Grants {
			for j, member := range b.members {
				if member.lunID != grant.LUNID {
					continue
				}
				mapping, err := b.directory(b.auth[i], "lun_"+strconv.Itoa(int(member.number)))
				if err != nil {
					return err
				}
				if b.link(mapping, "grant", b.luns[j]) != nil {
					return ErrReview
				}
				b.topology = append(b.topology, lioDirectoryRoster{mapping, []string{"statistics", "write_protect", "grant"}})
				ro := "1"
				if grant.Access == "rw" {
					ro = "0"
				}
				if b.setExpected(mapping, "write_protect", ro) != nil {
					return ErrReview
				}
			}
		}
	}
	np, err := b.fixedGroup(b.tpg, "np")
	if err != nil {
		return err
	}
	// Fixed disposable loopback only. Product endpoint selection is NOT provided.
	portal, err := b.directory(np, "127.0.0.1:3260")
	if err != nil {
		return err
	}
	b.topology = append(b.topology, lioDirectoryRoster{np, []string{"127.0.0.1:3260"}}, lioDirectoryRoster{portal, []string{"iser", "cxgbit"}})
	if ctx.Err() != nil || b.checkTopology(ctx) != nil || b.checkExpected(ctx) != nil || b.sink.verifyDisabled(ctx) != nil || lioBackendSet(b.tpg, "enable", "1", true) != nil || b.checkTopology(ctx) != nil {
		return ErrReview
	}
	b.ready = true
	return nil
}

func (b *lioBackend) running(ctx context.Context) (bool, error) {
	if b == nil || ctx == nil || ctx.Err() != nil || !b.ready || b.stopAttempted || b.checkTopology(ctx) != nil || b.sink.verifyEnabled(ctx) != nil || b.checkExpected(ctx) != nil {
		return false, ErrReview
	}
	if b.checkTopology(ctx) != nil || ctx.Err() != nil {
		return false, ErrReview
	}
	return true, nil
}

func (b *lioBackend) stop(ctx context.Context) error {
	if b == nil || ctx == nil || ctx.Err() != nil || b.stopAttempted || b.stopped {
		return ErrReview
	}
	b.stopAttempted = true
	if b.checkEntries() != nil {
		return ErrReview
	}
	if b.tpg != nil {
		if lioBackendCheck(b.tpg, "enable", "0") != nil {
			if lioBackendCheck(b.tpg, "enable", "1") != nil || lioBackendSet(b.tpg, "disable_if_idle", "1", false) != nil || lioBackendCheck(b.tpg, "enable", "0") != nil {
				return ErrReview
			}
		}
		for _, acl := range b.auth {
			info, err := lioBackendLeaf(acl, "info", unix.O_RDONLY)
			if err != nil {
				return ErrReview
			}
			data, readErr := io.ReadAll(io.LimitReader(info, 4097))
			closeErr := info.Close()
			idle := readErr == nil && closeErr == nil && len(data) <= 4096 && strings.HasPrefix(string(data), "No active iSCSI Session")
			clear(data)
			if !idle {
				return ErrReview
			}
		}
	}
	if ctx.Err() != nil || b.checkEntries() != nil {
		return ErrReview
	}
	for i := len(b.entries) - 1; i >= 0; i-- {
		entry := b.entries[i]
		if entry.name != "" {
			flags := unix.AT_REMOVEDIR
			if entry.link {
				flags = 0
			}
			if unix.Unlinkat(int(entry.parent.Fd()), entry.name, flags) != nil {
				return ErrReview
			}
		}
		entry.removed = true
		if !entry.link && entry.file.Close() != nil {
			return ErrReview
		}
	}
	if b.fabric.Close() != nil || b.core.Close() != nil {
		return ErrReview
	}
	b.stopped = true
	return nil
}
