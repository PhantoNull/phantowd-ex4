//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package revisionstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/configjson"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicyevidence"
	"golang.org/x/sys/unix"
)

// NASEvidenceAuthority is diagnostic only; no Store, lease or admission escapes.
// Trusted parents select the separately provisioned root and installation ID.
type NASEvidenceAuthority struct {
	self         *NASEvidenceAuthority
	root         *BootstrapAuthority[naspolicy.Config]
	installation string
}

type NASEvidenceObservation struct {
	Kind                 naspolicyevidence.Kind
	Roles                int
	BasePresent, Pending bool
}

func nasEvidenceCodec() Codec[naspolicy.Config] {
	return Codec[naspolicy.Config]{CurrentName: "nas-services.json", PendingName: ".nas-services.pending",
		MaxBytes: naspolicy.MaxInputBytes, Decode: naspolicy.Decode, Validate: naspolicy.Config.Validate,
		Revision: func(c naspolicy.Config) uint64 { return c.Revision }}
}

func OpenNASEvidenceAuthority(ctx context.Context, directory, installation string) (*NASEvidenceAuthority, error) {
	id, err := hex.DecodeString(installation)
	if err != nil || len(id) != 16 || hex.EncodeToString(id) != installation || bytes.Equal(id, make([]byte, 16)) {
		return nil, ErrInvalid
	}
	root, err := OpenBootstrapAuthorityWithCodec(ctx, directory, nasEvidenceCodec())
	if root == nil {
		return nil, err
	}
	a := &NASEvidenceAuthority{root: root, installation: installation}
	a.self = a
	return a, err // Preserve uncertain constructor cleanup's original authority.
}

func (a *NASEvidenceAuthority) valid() bool { return a != nil && a.self == a && a.root != nil }

func (a *NASEvidenceAuthority) Observe(ctx context.Context) (value NASEvidenceObservation, result error) {
	if !a.valid() || ctx == nil {
		return value, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return value, err
	}
	r := a.root
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return value, ErrClosed
	}
	if r.closeFailed || r.review {
		return value, ErrReview
	}
	if err := ctx.Err(); err != nil {
		return value, err
	}
	defer func() {
		if result != nil {
			r.review = true
			value, result = NASEvidenceObservation{}, errors.Join(ErrReview, result)
		}
	}()
	unchanged := func(fd int) bool {
		var st unix.Stat_t
		return unix.Fstat(fd, &st) == nil && policyStamp(st) == policyStamp(r.initial)
	}
	if !unchanged(int(r.root.Fd())) || !r.quietLocked() {
		return value, ErrReview
	}
	fd, err := unix.Openat2(int(r.root.Fd()), ".", &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOATIME | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_XDEV | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return value, ErrIO
	}
	cursor := os.NewFile(uintptr(fd), "nas-evidence-confined-cursor")
	if !unchanged(fd) {
		return value, fmt.Errorf("%w: cursor_close_failed=%t", ErrReview, cursor.Close() != nil)
	}
	value, err = collectNASEvidence(ctx, cursor, r.initial, a.installation)
	closeErr := cursor.Close()
	if err != nil || closeErr != nil {
		return value, errors.Join(err, ErrIO)
	}
	if !unchanged(int(r.root.Fd())) || !r.quietLocked() {
		return value, ErrReview
	}
	if err := ctx.Err(); err != nil {
		return value, err
	}
	if value.Kind != naspolicyevidence.NoRecordedOperation && value.Kind != naspolicyevidence.MatchingLocalRecords {
		r.review = true
	}
	return value, nil
}

func collectNASEvidence(ctx context.Context, cursor *os.File, root unix.Stat_t, installation string) (NASEvidenceObservation, error) {
	return collectNASEvidenceSet(ctx, cursor, root, installation, nil)
}

type nasEvidenceFile struct {
	stat unix.Stat_t
	data []byte
}

func collectNASEvidenceSet(ctx context.Context, cursor *os.File, root unix.Stat_t, installation string, capture map[string]nasEvidenceFile) (NASEvidenceObservation, error) {
	var names []string
	for {
		if err := ctx.Err(); err != nil {
			return NASEvidenceObservation{}, err
		}
		chunk, err := cursor.Readdirnames(7 - len(names))
		names = append(names, chunk...)
		if len(names) >= 7 {
			return NASEvidenceObservation{}, ErrUnsafe
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || len(chunk) == 0 {
			return NASEvidenceObservation{}, ErrIO
		}
	}
	fd := int(cursor.Fd())
	known, data := map[string]unix.Stat_t{}, map[string][]byte{}
	pending := false
	for _, name := range names {
		limit := naspolicy.MaxInputBytes
		switch name {
		case "nas-evidence.json", ".nas-services.intent", ".nas-services.receipt":
			limit = naspolicyevidence.MaxRecordBytes
		case "nas-services.json", ".nas-services.pending", ".nas-services.base":
		default:
			return NASEvidenceObservation{}, ErrUnsafe
		}
		if _, duplicate := known[name]; duplicate {
			return NASEvidenceObservation{}, ErrUnsafe
		}
		var st unix.Stat_t
		if unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW|unix.AT_NO_AUTOMOUNT) != nil ||
			st.Mode != unix.S_IFREG|0600 || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 || st.Dev != root.Dev || st.Size < 0 || st.Size > int64(limit) {
			return NASEvidenceObservation{}, ErrUnsafe
		}
		known[name] = st
		if name == ".nas-services.pending" {
			pending = true
			continue
		}
		contents, err := readNASEvidenceRole(ctx, fd, name, limit, st)
		if err != nil {
			return NASEvidenceObservation{}, err
		}
		data[name] = contents
	}
	var header struct {
		Format        string `json:"format"`
		SchemaVersion int    `json:"schema_version"`
		Installation  string `json:"installation_id"`
	}
	_, err := configjson.DecodeEnvelope(data["nas-evidence.json"], naspolicyevidence.MaxRecordBytes, 2, "format", "schema_version", "installation_id")
	if err != nil || json.Unmarshal(data["nas-evidence.json"], &header) != nil || header.Format != "phantowd-nas-evidence-container" || header.SchemaVersion != 1 || header.Installation != installation || data["nas-services.json"] == nil {
		return NASEvidenceObservation{}, ErrInvalid
	}
	for name, expected := range known {
		var after unix.Stat_t
		if unix.Fstatat(fd, name, &after, unix.AT_SYMLINK_NOFOLLOW|unix.AT_NO_AUTOMOUNT) != nil || policyStamp(expected) != policyStamp(after) {
			return NASEvidenceObservation{}, ErrReview
		}
	}
	kind := nasEvidenceKind(installation, data)
	if pending {
		kind = naspolicyevidence.Inconsistent
	}
	for name, st := range known {
		if capture != nil {
			capture[name] = nasEvidenceFile{st, data[name]}
		}
	}
	return NASEvidenceObservation{Kind: kind, Roles: len(names), BasePresent: data[".nas-services.base"] != nil, Pending: pending}, nil
}

func readNASEvidenceRole(ctx context.Context, dir int, name string, limit int, expected unix.Stat_t) ([]byte, error) {
	codec := nasEvidenceCodec()
	codec.CurrentName, codec.MaxBytes = name, limit
	s := &Store[naspolicy.Config]{dir: dir, noAtime: true, codec: codec}
	f, err := s.openCurrent()
	if err != nil {
		return nil, err
	}
	var before, after unix.Stat_t
	if unix.Fstat(int(f.Fd()), &before) != nil || policyStamp(before) != policyStamp(expected) {
		return nil, fmt.Errorf("%w: role_close_failed=%t", ErrReview, f.Close() != nil)
	}
	r := &bootstrapContextReader{ctx: ctx, reader: io.LimitReader(f, int64(limit)+1)}
	data, readErr := io.ReadAll(r)
	statErr, closeErr := unix.Fstat(int(f.Fd()), &after), f.Close()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if readErr != nil || closeErr != nil {
		return nil, ErrIO
	}
	if statErr != nil || int64(len(data)) != expected.Size || policyStamp(before) != policyStamp(after) {
		return nil, ErrReview
	}
	return data, nil
}

func nasEvidenceKind(installation string, data map[string][]byte) naspolicyevidence.Kind {
	kind := naspolicyevidence.Inspect(installation, data["nas-services.json"], data[".nas-services.intent"], data[".nas-services.receipt"], true)
	base := data[".nas-services.base"]
	if base == nil || kind == naspolicyevidence.Unavailable || kind == naspolicyevidence.InvalidPolicy || kind == naspolicyevidence.Inconsistent {
		return kind
	}
	// Inspect already strictly validated the intent for these operation kinds.
	var intent struct {
		Revision uint64 `json:"base_revision"`
		Hash     string `json:"base_sha256"`
	}
	policy, err := naspolicy.Decode(bytes.NewReader(base))
	digest := sha256.Sum256(base)
	if kind == naspolicyevidence.NoRecordedOperation || err != nil || json.Unmarshal(data[".nas-services.intent"], &intent) != nil || policy.Revision != intent.Revision || hex.EncodeToString(digest[:]) != intent.Hash {
		return naspolicyevidence.Inconsistent
	}
	return kind
}

func (a *NASEvidenceAuthority) Close() error {
	if !a.valid() {
		return ErrInvalid
	}
	return a.root.Close()
}

func (*NASEvidenceAuthority) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (*NASEvidenceAuthority) UnmarshalJSON([]byte) error   { return ErrInvalid }
