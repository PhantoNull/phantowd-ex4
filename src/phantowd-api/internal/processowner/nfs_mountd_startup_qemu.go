//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"bytes"
	"strconv"
	"strings"
)

const nfsMountdHandoffQEMU = "PHANTOWD_NFS_MOUNTD_HANDOFF private_view=true capabilities_zero=true channels=3 active_interfaces=lo fixed_mountd=true\n"
const nfsMountdStartupQEMU = nfsMountdHandoffQEMU + "rpc.mountd: Version 2.8.6 starting\n"
const nfsSourceMountdHandoffQEMU = "PHANTOWD_NFS_SOURCE_MOUNTD_HANDOFF private_view=true caps=dac-read-search channels=3 sources=3 filehandle=true active_interfaces=lo fixed_mountd=true\n"
const nfsSourceMountdStartupQEMU = nfsSourceMountdHandoffQEMU + "rpc.mountd: Version 2.8.6 starting\n"

func NFSSourceMountdStartupReadyQEMU(data []byte) (bool, error) {
	if !bytes.HasPrefix([]byte(nfsSourceMountdStartupQEMU), data) {
		return false, ErrInvalid
	}
	return len(data) == len(nfsSourceMountdStartupQEMU), nil
}

// Exact finite source-fixture transcript, not a general daemon-log whitelist.
// Both successful secure MOUNTs have canonical reserved source ports; the only
// refusal is the deliberately excluded third export. Every other byte refuses.
func NFSSourceMountdAccessHandoffQEMU(data []byte, stopped bool) error {
	if len(data) > 2048 || !bytes.HasPrefix(data, []byte(nfsSourceMountdStartupQEMU)) {
		return ErrInvalid
	}
	rest := string(data[len(nfsSourceMountdStartupQEMU):])
	const base = "/srv/phantowd/volumes/qemu-plan/"
	for _, name := range []string{"books", "archive"} {
		line, tail, ok := strings.Cut(rest, "\n")
		if !ok {
			return ErrInvalid
		}
		port, ok := strings.CutPrefix(line, "rpc.mountd: authenticated mount request from 127.0.0.1:")
		if !ok {
			return ErrInvalid
		}
		port, ok = strings.CutSuffix(port, " for "+base+name+" ("+base+name+")")
		if !ok {
			return ErrInvalid
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n >= 1024 || strconv.Itoa(n) != port {
			return ErrInvalid
		}
		rest = tail
	}
	wanted := "rpc.mountd: refused mount request from 127.0.0.1 for " + base + "denied (/): not exported\n"
	if stopped {
		wanted += "rpc.mountd: Caught signal 15, un-registering and exiting.\n"
	}
	if rest != wanted {
		return ErrInvalid
	}
	return nil
}

// NFSMountdStartupReadyQEMU recognizes only the fixed fixture startup stream.
// A prefix is pending within the ORIGINAL readiness deadline, not a whitelist
// or success. Any unexpected/trailing byte refuses. No I/O or authority here.
func NFSMountdStartupReadyQEMU(data []byte) (bool, error) {
	if !bytes.HasPrefix([]byte(nfsMountdStartupQEMU), data) {
		return false, ErrInvalid
	}
	return len(data) == len(nfsMountdStartupQEMU), nil
}
