// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package stateunmountdiag formats bounded ownership evidence for the
// disposable two-boot QEMU state-volume fixture. It is not product logging.
package stateunmountdiag

import (
	"encoding/json"
	"errors"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"
)

const (
	MaxDiagnosticBytes  = 4096
	MaxProcesses        = 24
	MaxFDsPerProcess    = 32
	MaxScannedProcesses = 128
	MaxMountInfoLines   = 128

	maxProcDirectoryEntries = MaxScannedProcesses + 32
	maxFDReferences         = 32
	maxPathReferences       = 16
	maxMountReferences      = 16
)

var ErrNoSuchProcess = errors.New("process disappeared while collecting fixture diagnostics")

// ReadProcessIDs reads only a fixed number of /proc-style directory entries.
// Numeric entries become sorted process IDs; excess entries/IDs are reported
// as truncated rather than requiring an unbounded directory read.
func ReadProcessIDs(directory interface {
	Readdirnames(count int) ([]string, error)
}) (ids []int, truncated bool, err error) {
	if directory == nil {
		return nil, false, errors.New("nil process directory reader")
	}
	names, err := directory.Readdirnames(maxProcDirectoryEntries)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, false, err
	}
	if len(names) == maxProcDirectoryEntries {
		extra, extraErr := directory.Readdirnames(1)
		if extraErr != nil && !errors.Is(extraErr, io.EOF) {
			truncated = true
			err = extraErr
		} else if len(extra) != 0 {
			truncated = true
		}
	}
	ids = make([]int, 0, min(len(names), MaxScannedProcesses))
	for _, name := range names {
		pid, parseErr := strconv.Atoi(name)
		if parseErr == nil && pid > 0 {
			ids = append(ids, pid)
		}
	}
	sort.Ints(ids)
	if len(ids) > MaxScannedProcesses {
		ids = ids[:MaxScannedProcesses]
		truncated = true
	}
	return ids, truncated, err
}

type ProcessStatus struct {
	Name      string
	ParentPID int
}

// Reader is implemented only by the Linux QEMU fixture adapter. Names and
// link targets are transient observations; Capture emits no raw path or
// command line. Implementations must bound each collection operation.
type Reader interface {
	ProcessIDs() ([]int, bool, error)
	ProcessStatus(pid int) (name string, parentPID int, err error)
	FDNumbers(pid int) ([]int, bool, error)
	Link(pid int, object string) (string, error)
	MountInfo(pid int) ([]string, bool, error)
}

type processRecord struct {
	PID  int    `json:"pid"`
	PPID int    `json:"ppid"`
	Name string `json:"name"`
}

type fdRecord struct {
	PID  int    `json:"pid"`
	FD   int    `json:"fd"`
	Kind string `json:"kind"`
}

type pathRecord struct {
	PID  int    `json:"pid"`
	Kind string `json:"kind"`
}

type mountRecord struct {
	PID      int    `json:"pid"`
	MountID  int    `json:"mount_id"`
	ParentID int    `json:"parent_id"`
	Device   string `json:"device"`
}

type diagnostic struct {
	Errno           string          `json:"errno"`
	OwnerPID        int             `json:"owner_pid"`
	Processes       []processRecord `json:"processes"`
	FDReferences    []fdRecord      `json:"fd_references"`
	PathReferences  []pathRecord    `json:"path_references"`
	MountReferences []mountRecord   `json:"mount_references"`
	Incomplete      bool            `json:"incomplete"`
	Truncated       bool            `json:"truncated"`
}

const marker = "PHANTOWD_STATE_UNMOUNT_DIAG "

// Capture follows only the owner process tree. It records process identity,
// descriptor numbers and mount IDs only when a descriptor/path/mount matches
// the fixture anchor or its one synthetic source device. Raw targets, mount
// paths, mount sources, command lines and environments are never serialized.
func Capture(errno string, ownerPID int, anchor, sourceDevice string, reader Reader) string {
	d := diagnostic{
		Errno:           safeErrno(errno),
		OwnerPID:        ownerPID,
		Processes:       []processRecord{},
		FDReferences:    []fdRecord{},
		PathReferences:  []pathRecord{},
		MountReferences: []mountRecord{},
	}
	if reader == nil || ownerPID <= 0 || !strings.HasPrefix(anchor, "/") || !strings.HasPrefix(sourceDevice, "/") {
		d.Incomplete = true
		return render(d)
	}
	anchor = path.Clean(anchor)
	sourceDevice = path.Clean(sourceDevice)
	pids, truncated, err := reader.ProcessIDs()
	d.Truncated = truncated
	if err != nil {
		d.Incomplete = true
	}
	pids = uniquePositiveSorted(pids)
	if len(pids) > MaxScannedProcesses {
		pids = pids[:MaxScannedProcesses]
		d.Truncated = true
	}
	if !containsPID(pids, ownerPID) {
		pids = append(pids, ownerPID)
	}

	known := make(map[int]processRecord, len(pids))
	for _, pid := range pids {
		name, parentPID, err := reader.ProcessStatus(pid)
		if err != nil {
			if !processDisappeared(err) {
				d.Incomplete = true
			}
			continue
		}
		known[pid] = processRecord{PID: pid, PPID: positiveOrZero(parentPID), Name: safeName(name)}
	}
	if _, ok := known[ownerPID]; !ok {
		name, parentPID, err := reader.ProcessStatus(ownerPID)
		if err != nil {
			d.Incomplete = true
		} else {
			known[ownerPID] = processRecord{PID: ownerPID, PPID: positiveOrZero(parentPID), Name: safeName(name)}
		}
	}
	children := make(map[int][]int)
	for pid, process := range known {
		children[process.PPID] = append(children[process.PPID], pid)
	}
	for parent := range children {
		sort.Ints(children[parent])
	}

	ordered := make([]int, 0, MaxProcesses)
	seen := map[int]bool{ownerPID: true}
	queue := []int{ownerPID}
	for len(queue) != 0 {
		pid := queue[0]
		queue = queue[1:]
		if _, ok := known[pid]; ok {
			ordered = append(ordered, pid)
		}
		for _, child := range children[pid] {
			if !seen[child] {
				seen[child] = true
				queue = append(queue, child)
			}
		}
	}
	if len(ordered) > MaxProcesses {
		ordered = ordered[:MaxProcesses]
		d.Truncated = true
	}

	fdCount, mountCount, pathCount := 0, 0, 0
	for _, pid := range ordered {
		process := known[pid]
		d.Processes = append(d.Processes, process)

		for _, object := range []string{"cwd", "root"} {
			target, err := reader.Link(pid, object)
			if err != nil {
				if !processDisappeared(err) {
					d.Incomplete = true
				}
				continue
			}
			if kind := targetKind(target, anchor, sourceDevice); kind != "" && pathCount < maxPathReferences {
				d.PathReferences = append(d.PathReferences, pathRecord{PID: pid, Kind: object + "-" + kind})
				pathCount++
			} else if kind != "" {
				d.Truncated = true
			}
		}

		fds, cut, err := reader.FDNumbers(pid)
		if err != nil {
			if processDisappeared(err) {
				continue
			}
			d.Incomplete = true
		}
		d.Truncated = d.Truncated || cut
		fds = uniqueNonnegativeSorted(fds)
		if len(fds) > MaxFDsPerProcess {
			fds = fds[:MaxFDsPerProcess]
			d.Truncated = true
		}
		for _, fd := range fds {
			target, err := reader.Link(pid, "fd/"+strconv.Itoa(fd))
			if err != nil {
				if !processDisappeared(err) {
					d.Incomplete = true
				}
				continue
			}
			kind := targetKind(target, anchor, sourceDevice)
			if kind == "" {
				continue
			}
			if fdCount == maxFDReferences {
				d.Truncated = true
				break
			}
			d.FDReferences = append(d.FDReferences, fdRecord{PID: pid, FD: fd, Kind: kind})
			fdCount++
		}

		lines, cut, err := reader.MountInfo(pid)
		if err != nil {
			if !processDisappeared(err) {
				d.Incomplete = true
			}
		}
		d.Truncated = d.Truncated || cut
		if len(lines) > MaxMountInfoLines {
			lines = lines[:MaxMountInfoLines]
			d.Truncated = true
		}
		for _, line := range lines {
			mount, ok := parseMountReference(pid, line, anchor)
			if !ok {
				continue
			}
			if mountCount == maxMountReferences {
				d.Truncated = true
				break
			}
			d.MountReferences = append(d.MountReferences, mount)
			mountCount++
		}
	}
	return render(d)
}

func processDisappeared(err error) bool {
	return errors.Is(err, ErrNoSuchProcess)
}

func render(d diagnostic) string {
	for {
		data, err := json.Marshal(d)
		if err != nil {
			return marker + `{"errno":"E_OTHER","incomplete":true,"truncated":true}`
		}
		line := marker + string(data)
		if len(line) <= MaxDiagnosticBytes {
			return line
		}
		d.Truncated = true
		switch {
		case len(d.FDReferences) > 0:
			d.FDReferences = d.FDReferences[:len(d.FDReferences)-1]
		case len(d.MountReferences) > 0:
			d.MountReferences = d.MountReferences[:len(d.MountReferences)-1]
		case len(d.PathReferences) > 0:
			d.PathReferences = d.PathReferences[:len(d.PathReferences)-1]
		case len(d.Processes) > 1:
			d.Processes = d.Processes[:len(d.Processes)-1]
		default:
			return marker + `{"errno":"E_OTHER","incomplete":true,"truncated":true}`
		}
	}
}

func safeErrno(value string) string {
	switch value {
	case "EBUSY", "EIO", "EINVAL", "ENOTEMPTY":
		return value
	default:
		return "E_OTHER"
	}
}

func safeName(value string) string {
	if len(value) > 16 {
		value = value[:16]
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
			return "redacted"
		}
	}
	if value == "" {
		return "redacted"
	}
	return value
}

func targetKind(target, anchor, sourceDevice string) string {
	target = strings.TrimSuffix(target, " (deleted)")
	if !strings.HasPrefix(target, "/") {
		return ""
	}
	target = path.Clean(target)
	if target == sourceDevice {
		return "source-device"
	}
	if target == anchor || strings.HasPrefix(target, strings.TrimSuffix(anchor, "/")+"/") {
		return "anchor"
	}
	return ""
}

func parseMountReference(pid int, line, anchor string) (mountRecord, bool) {
	fields := strings.Fields(line)
	if len(fields) < 6 || !mountPathMatches(unescapeMountField(fields[4]), anchor) {
		return mountRecord{}, false
	}
	mountID, err1 := strconv.Atoi(fields[0])
	parentID, err2 := strconv.Atoi(fields[1])
	major, minor, ok := parseDeviceNumber(fields[2])
	if err1 != nil || err2 != nil || mountID <= 0 || parentID < 0 || !ok {
		return mountRecord{}, false
	}
	return mountRecord{PID: pid, MountID: mountID, ParentID: parentID, Device: strconv.Itoa(major) + ":" + strconv.Itoa(minor)}, true
}

func mountPathMatches(path, anchor string) bool {
	return path == anchor || strings.HasPrefix(path, strings.TrimSuffix(anchor, "/")+"/")
}

func unescapeMountField(value string) string {
	var b strings.Builder
	b.Grow(len(value))
	for index := 0; index < len(value); index++ {
		if value[index] == '\\' && index+3 < len(value) {
			if decoded, err := strconv.ParseUint(value[index+1:index+4], 8, 8); err == nil {
				b.WriteByte(byte(decoded))
				index += 3
				continue
			}
		}
		b.WriteByte(value[index])
	}
	return b.String()
}

func parseDeviceNumber(value string) (int, int, bool) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return 0, 0, false
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || major < 0 || minor < 0 {
		return 0, 0, false
	}
	return major, minor, true
}

func uniquePositiveSorted(values []int) []int {
	seen := make(map[int]bool, len(values))
	result := make([]int, 0, len(values))
	for _, value := range values {
		if value > 0 && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Ints(result)
	return result
}

func uniqueNonnegativeSorted(values []int) []int {
	seen := make(map[int]bool, len(values))
	result := make([]int, 0, len(values))
	for _, value := range values {
		if value >= 0 && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Ints(result)
	return result
}

func containsPID(values []int, target int) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func positiveOrZero(value int) int {
	if value < 0 {
		return 0
	}
	return value
}

func procLinkKey(pid int, object string) string {
	return strconv.Itoa(pid) + "/" + object
}
