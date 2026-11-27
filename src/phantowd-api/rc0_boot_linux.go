// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strconv"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/configjson"
	"golang.org/x/sys/unix"
)

const (
	rc0BootFormat   = "phantowd-rc0-boot-v1"
	rc0BootMaxBytes = 4096
)

var rc0BootKeys = map[string]bool{
	"format": true, "installation_id": true, "listen_address": true, "origin": true,
	"state_mount_id": true, "state_root_inode": true, "policy_sha256": true, "tls_leaf_sha256": true,
}

type rc0BootPlan struct {
	Format         string `json:"format"`
	Installation   string `json:"installation_id"`
	Address        string `json:"listen_address"`
	Origin         string `json:"origin"`
	StateMountID   uint64 `json:"state_mount_id"`
	StateRootInode uint64 `json:"state_root_inode"`
	PolicySHA256   string `json:"policy_sha256"`
	TLSLeafSHA256  string `json:"tls_leaf_sha256"`
}

// The early launcher admits a local state root and independently selects its
// policy and TLS generations. Only its descriptors enter this process.
func runRC0BootManagement(ctx context.Context, started func() error) (result error) {
	if developmentBrowserEnrollment || os.Getuid() != 0 || os.Geteuid() != 0 {
		return errRC0Review
	}
	state, err := takeStartupFile(3, unix.S_IFDIR)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, state.Close()) }()
	plan, err := readRC0BootGrant(4)
	if err != nil {
		return err
	}
	known, proofInfo, err := readRC0PolicyGrant(5)
	if err != nil {
		return err
	}
	if !plan.matchesPolicy(known) {
		return errRC0Review
	}
	return superviseRC0State(ctx, plan, state, known, proofInfo, started)
}

func readRC0BootGrant(descriptor int) (rc0BootPlan, error) {
	file, err := takeStartupFile(descriptor, unix.S_IFREG)
	if err != nil {
		return rc0BootPlan{}, err
	}
	var fs unix.Statfs_t
	if unix.Fstatfs(int(file.Fd()), &fs) != nil || fs.Type != unix.TMPFS_MAGIC {
		return rc0BootPlan{}, errors.Join(errRC0Review, file.Close())
	}
	data, _, err := readPrivateStartupFile(file, 0, rc0BootMaxBytes)
	if err := errors.Join(err, file.Close()); err != nil {
		return rc0BootPlan{}, err
	}
	return decodeRC0BootPlan(data)
}

func decodeRC0BootPlan(data []byte) (rc0BootPlan, error) {
	var plan rc0BootPlan
	if configjson.Decode(bytes.NewReader(data), &plan, rc0BootMaxBytes, 1, rc0BootKeys) != nil ||
		plan.Format != rc0BootFormat || plan.Installation == "" || !plan.validTransport() ||
		plan.StateMountID == 0 || plan.StateRootInode == 0 ||
		!validRC0SHA256(plan.PolicySHA256) || !validRC0SHA256(plan.TLSLeafSHA256) {
		return rc0BootPlan{}, errRC0Review
	}
	return plan, nil
}

func (plan rc0BootPlan) validTransport() bool {
	origin, err := parseOrigin(plan.Origin)
	if err != nil || origin.Scheme != "https" {
		return false
	}
	host, port, wildcard, err := parseListenAddress(plan.Address)
	if err != nil || !wildcard && isLoopbackHost(host) && !sameHost(host, origin.Hostname()) {
		return false
	}
	return origin.Port() == strconv.Itoa(port) ||
		origin.Port() == "" && port == defaultPort(origin.Scheme)
}

func (plan rc0BootPlan) matchesState(root *os.File) bool {
	mount, inode, err := rc0StateIdentity(root)
	return err == nil && mount == plan.StateMountID && inode == plan.StateRootInode
}

func rc0StateIdentity(root *os.File) (mountID, inode uint64, err error) {
	const mask = unix.STATX_INO | unix.STATX_MNT_ID_UNIQUE
	var observed unix.Statx_t
	if unix.Statx(int(root.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT, mask, &observed) != nil ||
		observed.Mask&mask != mask || observed.Mnt_id == 0 || observed.Ino == 0 {
		return 0, 0, errRC0Review
	}
	return observed.Mnt_id, observed.Ino, nil
}

func (plan rc0BootPlan) matchesPolicy(known []byte) bool {
	digest := sha256.Sum256(known)
	return hex.EncodeToString(digest[:]) == plan.PolicySHA256
}

func (plan rc0BootPlan) matchesTLS(file *os.File) bool {
	pair, err := readTLSIdentity(file, 0)
	return err == nil && tlsLeafFingerprint(pair.Certificate[0]) == plan.TLSLeafSHA256
}
