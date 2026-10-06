//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package backingpin

import (
	"context"
	"crypto/subtle"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsicredentials"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipolicy"
	"golang.org/x/sys/unix"
)

// include/uapi/linux/magic.h in the pinned Linux source; not supplied by the
// vendored x/sys version on all supported architectures.
const lioConfigFSMagic = 0x62656570

// Private typed prerequisite, NOT a LIO target backend. A future fixed backend
// must own these borrowed configfs references, exclusive configuration access
// and admission/teardown of ALL kernel borrowers. This sink opens fixed leaves
// only, never creates ACLs/portals/backings, enables a TPG or releases a Bundle.
type lioAuthSelection struct {
	name string
	auth *os.File
}
type lioAuthIdentity struct {
	mount, inode uint64
	major, minor uint32
}
type lioCredentialSink struct {
	nonSerializable
	mu                       sync.Mutex
	tpg                      *os.File
	tpgIdentity              lioAuthIdentity
	acls                     []lioAuthSelection
	identities               []lioAuthIdentity
	peers                    []iscsicredentials.Credential // opaque borrowed handles, not byte copies
	attempted, ready, review bool
}

func lioConfigIdentity(file *os.File, directory bool) (lioAuthIdentity, error) {
	if file == nil || os.Geteuid() != 0 {
		return lioAuthIdentity{}, ErrUnavailable
	}
	var st unix.Statx_t
	var fs unix.Statfs_t
	const mask = unix.STATX_TYPE | unix.STATX_MODE | unix.STATX_UID | unix.STATX_GID | unix.STATX_INO | unix.STATX_MNT_ID_UNIQUE
	if unix.Statx(int(file.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT, mask, &st) != nil || st.Mask&mask != mask ||
		unix.Fstatfs(int(file.Fd()), &fs) != nil || uint32(fs.Type) != lioConfigFSMagic || fs.Flags&unix.ST_RDONLY != 0 ||
		st.Uid != 0 || st.Gid != 0 || st.Mode&0022 != 0 || st.Ino == 0 || st.Mnt_id == 0 {
		return lioAuthIdentity{}, ErrUnavailable
	}
	typeBits := uint16(unix.S_IFREG)
	if directory {
		typeBits = unix.S_IFDIR
	}
	if st.Mode&unix.S_IFMT != typeBits {
		return lioAuthIdentity{}, ErrUnavailable
	}
	return lioAuthIdentity{st.Mnt_id, st.Ino, st.Dev_major, st.Dev_minor}, nil
}

func newLIOCredentialSink(tpg *os.File, acls []lioAuthSelection) (*lioCredentialSink, error) {
	if len(acls) == 0 || len(acls) > iscsipolicy.MaxInitiators {
		return nil, ErrInvalid
	}
	tid, err := lioConfigIdentity(tpg, true)
	if err != nil {
		return nil, err
	}
	sink := &lioCredentialSink{tpg: tpg, tpgIdentity: tid, acls: append([]lioAuthSelection(nil), acls...)}
	names, objects := map[string]bool{}, map[lioAuthIdentity]bool{tid: true}
	for _, acl := range sink.acls {
		if !lioPeerComponent(acl.name) || names[acl.name] {
			return nil, ErrInvalid
		}
		id, err := lioConfigIdentity(acl.auth, true)
		if err != nil || id.mount != tid.mount || objects[id] {
			return nil, ErrUnavailable
		}
		names[acl.name], objects[id] = true, true
		sink.identities = append(sink.identities, id)
	}
	if sink.checkDisabled() != nil {
		return nil, ErrUnavailable
	}
	return sink, nil
}

func lioOpenAttribute(directory *os.File, name string, flags int) (*os.File, error) {
	switch name {
	case "enable", "userid", "password", "userid_mutual", "password_mutual", "authenticate_target":
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
	file := os.NewFile(uintptr(fd), "lio-auth-attribute")
	leaf, err := lioConfigIdentity(file, false)
	if err != nil || leaf.mount != id.mount {
		_ = file.Close()
		return nil, ErrUnavailable
	}
	return file, nil
}

// Pinned LIO adds one newline in show(), but does not trim it in store().
// Bounded stack readback is wiped; no secret string, digest or log is produced.
func lioCompareAttribute(file *os.File, expected []byte) error {
	var observed [130]byte
	defer clear(observed[:])
	if file == nil || len(expected) > 128 {
		return ErrUnavailable
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return ErrUnavailable
	}
	n, err := io.ReadFull(file, observed[:len(expected)+2])
	if (err != io.EOF && err != io.ErrUnexpectedEOF) || n != len(expected)+1 || observed[n-1] != '\n' ||
		subtle.ConstantTimeCompare(observed[:n-1], expected) != 1 {
		return ErrUnavailable
	}
	return nil
}

type lioAttributeSink struct {
	file    *os.File
	install bool
}

func (s lioAttributeSink) Write(value []byte) (int, error) {
	if s.file == nil || len(value) < 16 || len(value) > 128 {
		return 0, ErrUnavailable
	}
	if s.install {
		// Exactly one store; never retry a short/uncertain write.
		n, err := s.file.Write(value)
		if err != nil || n != len(value) {
			return 0, ErrUnavailable
		}
	}
	if lioCompareAttribute(s.file, value) != nil {
		return 0, ErrUnavailable
	}
	return len(value), nil
}

func (s *lioCredentialSink) checkDisabled() error {
	return s.checkState("0")
}

func (s *lioCredentialSink) checkState(expected string) error {
	if s == nil || os.Geteuid() != 0 {
		return ErrUnavailable
	}
	id, err := lioConfigIdentity(s.tpg, true)
	if err != nil || id != s.tpgIdentity {
		return ErrUnavailable
	}
	for i, acl := range s.acls {
		id, err := lioConfigIdentity(acl.auth, true)
		if err != nil || id != s.identities[i] {
			return ErrUnavailable
		}
		// A same-filesystem descriptor is not evidence that this named ACL
		// belongs to the retained TPG. Re-open only this confined topology and
		// compare it with the independently borrowed auth directory.
		fd, err := unix.Openat2(int(s.tpg.Fd()), "acls/"+acl.name+"/auth", &unix.OpenHow{
			Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
			Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
		if err != nil {
			return ErrUnavailable
		}
		current := os.NewFile(uintptr(fd), "lio-auth-topology")
		observed, observeErr := lioConfigIdentity(current, true)
		closeErr := current.Close()
		if observeErr != nil || closeErr != nil || observed != id {
			return ErrUnavailable
		}
	}
	f, err := lioOpenAttribute(s.tpg, "enable", unix.O_RDONLY)
	if err != nil {
		return err
	}
	compareErr := lioCompareAttribute(f, []byte(expected))
	if closeErr := f.Close(); compareErr != nil || closeErr != nil {
		return ErrUnavailable
	}
	return nil
}

// Confined path component only. The coherent desired policy independently
// validates full IQN syntax; this check does not grant name/target authority.
func lioPeerComponent(name string) bool {
	if len(name) < 14 || len(name) > 223 || !strings.HasPrefix(name, "iqn.") {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune(".-:", c)) {
			return false
		}
	}
	return true
}

func lioUser(value string) bool {
	if len(value) == 0 || len(value) > 64 || strings.HasPrefix(value, "NULL") {
		return false
	}
	for _, c := range value {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}

func (s *lioCredentialSink) matchPeers(peers []iscsicredentials.Credential) ([]iscsicredentials.Credential, error) {
	if len(peers) != len(s.acls) {
		return nil, ErrInvalid
	}
	byName := map[string]iscsicredentials.Credential{}
	for _, peer := range peers {
		if _, ok := byName[peer.InitiatorName]; ok || !lioUser(peer.InitiatorUser) ||
			(peer.Mode != "chap" && peer.Mode != "mutual-chap") ||
			(peer.Mode == "mutual-chap" && (!lioUser(peer.TargetUser) || peer.TargetUser == peer.InitiatorUser)) ||
			(peer.Mode == "chap" && peer.TargetUser != "") {
			return nil, ErrInvalid
		}
		byName[peer.InitiatorName] = peer
	}
	result := make([]iscsicredentials.Credential, 0, len(peers))
	for _, acl := range s.acls {
		peer, ok := byName[acl.name]
		if !ok {
			return nil, ErrInvalid
		}
		result = append(result, peer)
	}
	return result, nil
}

func lioCredentialField(auth *os.File, name string, secret iscsicredentials.Secret, install bool) error {
	flags := unix.O_RDONLY
	if install {
		flags = unix.O_RDWR
	}
	f, err := lioOpenAttribute(auth, name, flags)
	if err != nil {
		return err
	}
	_, copyErr := secret.WriteTo(lioAttributeSink{f, install})
	if closeErr := f.Close(); copyErr != nil || closeErr != nil {
		return ErrUnavailable
	}
	return nil
}
func lioTextField(auth *os.File, name, text string, install bool) error {
	flags := unix.O_RDONLY
	if install {
		flags = unix.O_RDWR
	}
	f, err := lioOpenAttribute(auth, name, flags)
	if err != nil {
		return err
	}
	if install {
		n, writeErr := f.Write([]byte(text))
		if writeErr != nil || n != len(text) {
			_ = f.Close()
			return ErrUnavailable
		}
	}
	compareErr := lioCompareAttribute(f, []byte(text))
	if closeErr := f.Close(); compareErr != nil || closeErr != nil {
		return ErrUnavailable
	}
	return nil
}
func (s *lioCredentialSink) fields(install bool) error {
	for i, peer := range s.peers {
		auth := s.acls[i].auth
		if lioTextField(auth, "userid", peer.InitiatorUser, install) != nil ||
			lioCredentialField(auth, "password", peer.Incoming, install) != nil {
			return ErrUnavailable
		}
		mutual := "0"
		if peer.Mode == "mutual-chap" {
			mutual = "1"
			if lioTextField(auth, "userid_mutual", peer.TargetUser, install) != nil ||
				lioCredentialField(auth, "password_mutual", peer.Outgoing, install) != nil {
				return ErrUnavailable
			}
		} else {
			// Must explicitly unset stale outbound fields, not silently inherit them.
			if lioTextField(auth, "userid_mutual", "NULL", install) != nil ||
				lioTextField(auth, "password_mutual", "NULL", install) != nil {
				return ErrUnavailable
			}
		}
		if lioTextField(auth, "authenticate_target", mutual, false) != nil {
			return ErrUnavailable
		}
	}
	return nil
}

func (s *lioCredentialSink) PrepareCredentials(ctx context.Context, peers []iscsicredentials.Credential) error {
	if s == nil || ctx == nil {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.review {
		return ErrReview
	}
	if s.attempted {
		return ErrBusy
	}
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	matched, err := s.matchPeers(peers)
	if err != nil {
		return err
	} // Whole roster validates before any mutation.
	if s.checkDisabled() != nil {
		s.review = true
		return ErrReview
	}
	s.attempted = true
	s.peers = matched
	if s.fields(true) != nil || ctx.Err() != nil || s.checkDisabled() != nil {
		s.review = true
		return ErrReview // Partial installation must be torn down by fixed backend.
	}
	s.ready = true
	return nil
}

// Private disabled-state verification only. A target backend must implement its
// own active-state authority/session observations; no caller can inject peers.
func (s *lioCredentialSink) verifyDisabled(ctx context.Context) error {
	return s.verifyState(ctx, "0")
}

func (s *lioCredentialSink) verifyEnabled(ctx context.Context) error {
	return s.verifyState(ctx, "1")
}

func (s *lioCredentialSink) verifyState(ctx context.Context, expected string) error {
	if s == nil || ctx == nil {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.review {
		return ErrReview
	}
	if !s.ready || ctx.Err() != nil {
		return ErrUnavailable
	}
	if s.checkState(expected) != nil || s.fields(false) != nil || ctx.Err() != nil || s.checkState(expected) != nil {
		s.review = true
		return ErrReview
	}
	return nil
}
