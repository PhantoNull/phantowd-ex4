// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package stateunmountdiag

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

type syntheticProcNames struct {
	total    int
	position int
	requests []int
	maxNames int
}

func (directory *syntheticProcNames) Readdirnames(count int) ([]string, error) {
	directory.requests = append(directory.requests, count)
	if count <= 0 {
		return nil, strconv.ErrSyntax
	}
	end := directory.position + count
	if end > directory.total {
		end = directory.total
	}
	result := make([]string, 0, end-directory.position)
	for index := directory.position; index < end; index++ {
		switch index {
		case 0:
			result = append(result, "self")
		case 1:
			result = append(result, "thread-self")
		default:
			result = append(result, strconv.Itoa(index-1))
		}
	}
	directory.position = end
	if len(result) > directory.maxNames {
		directory.maxNames = len(result)
	}
	return result, nil
}

func TestReadProcessIDsCapsDirectoryEnumeration(t *testing.T) {
	directory := &syntheticProcNames{total: 1_000_000}
	ids, truncated, err := ReadProcessIDs(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(directory.requests) != 2 || directory.requests[0] != maxProcDirectoryEntries || directory.requests[1] != 1 {
		t.Fatalf("process directory enumeration exceeded or missed its bounded probe: requests=%v", directory.requests)
	}
	if directory.position > maxProcDirectoryEntries+1 || directory.maxNames > maxProcDirectoryEntries {
		t.Fatalf("process directory reader consumed too many entries: position=%d max_batch=%d", directory.position, directory.maxNames)
	}
	if len(ids) != MaxScannedProcesses || !truncated {
		t.Fatalf("expected capped, explicitly truncated process IDs; got %d IDs, truncated=%t", len(ids), truncated)
	}
	if ids[0] != 1 || ids[len(ids)-1] != MaxScannedProcesses {
		t.Fatalf("process IDs were not sorted and capped deterministically: first=%d last=%d", ids[0], ids[len(ids)-1])
	}
}

type fakeProc struct {
	pids     []int
	statuses map[int]ProcessStatus
	fds      map[int][]int
	links    map[string]string
	mounts   map[int][]string
}

func (f fakeProc) ProcessIDs() ([]int, bool, error) { return f.pids, false, nil }
func (f fakeProc) ProcessStatus(pid int) (string, int, error) {
	process, ok := f.statuses[pid]
	if !ok {
		return "", 0, ErrNoSuchProcess
	}
	return process.Name, process.ParentPID, nil
}
func (f fakeProc) FDNumbers(pid int) ([]int, bool, error) { return f.fds[pid], false, nil }
func (f fakeProc) Link(pid int, object string) (string, error) {
	target, ok := f.links[procLinkKey(pid, object)]
	if !ok {
		return "", ErrNoSuchProcess
	}
	return target, nil
}
func (f fakeProc) MountInfo(pid int) ([]string, bool, error) { return f.mounts[pid], false, nil }

func TestDiagnosticReportsOnlyBoundedRelatedDescendantOwnership(t *testing.T) {
	proc := fakeProc{
		pids: []int{1, 4, 5, 9},
		statuses: map[int]ProcessStatus{
			1: {Name: "phantowd-api", ParentPID: 0},
			4: {Name: "smbd", ParentPID: 1},
			5: {Name: "smb-worker", ParentPID: 4},
			9: {Name: "unrelated", ParentPID: 2},
		},
		fds: map[int][]int{4: {7, 8, 9}, 9: {3}},
		links: map[string]string{
			procLinkKey(1, "cwd"):  "/",
			procLinkKey(1, "root"): "/",
			procLinkKey(4, "cwd"):  "/",
			procLinkKey(4, "root"): "/",
			procLinkKey(4, "fd/7"): "/run/phantowd-state-volume/private/accounts.db",
			procLinkKey(4, "fd/8"): "/dev/sdb",
			procLinkKey(4, "fd/9"): "/etc/passwd",
			procLinkKey(5, "cwd"):  "/run/phantowd-state-volume/private",
			procLinkKey(5, "root"): "/",
			procLinkKey(9, "fd/3"): "/run/phantowd-state-volume/unrelated.db",
		},
		mounts: map[int][]string{
			1: {"31 1 8:16 / /run/phantowd-state-volume rw,nosuid - ext4 /dev/sdb rw"},
			4: {"31 1 8:16 / /run/phantowd-state-volume rw,nosuid - ext4 /dev/sdb rw"},
			9: {"44 1 8:32 / /run/phantowd-state-volume rw - ext4 /dev/sdc rw"},
		},
	}

	line := Capture("EBUSY", 1, "/run/phantowd-state-volume", "/dev/sdb", proc)
	if len(line) > MaxDiagnosticBytes {
		t.Fatalf("diagnostic exceeded its byte budget: %d", len(line))
	}
	const marker = "PHANTOWD_STATE_UNMOUNT_DIAG "
	if !strings.HasPrefix(line, marker) {
		t.Fatalf("missing bounded diagnostic marker: %q", line)
	}
	var got struct {
		Errno     string `json:"errno"`
		Processes []struct {
			PID  int    `json:"pid"`
			Name string `json:"name"`
		} `json:"processes"`
		FDReferences []struct {
			PID  int    `json:"pid"`
			FD   int    `json:"fd"`
			Kind string `json:"kind"`
		} `json:"fd_references"`
		PathReferences []struct {
			PID  int    `json:"pid"`
			Kind string `json:"kind"`
		} `json:"path_references"`
		MountReferences []struct {
			PID     int    `json:"pid"`
			MountID int    `json:"mount_id"`
			Device  string `json:"device"`
		} `json:"mount_references"`
		Incomplete bool `json:"incomplete"`
		Truncated  bool `json:"truncated"`
	}
	if err := json.Unmarshal([]byte(strings.TrimPrefix(line, marker)), &got); err != nil {
		t.Fatal("diagnostic was not JSON", err)
	}
	if got.Errno != "EBUSY" || got.Incomplete || got.Truncated {
		t.Fatalf("unexpected diagnostic status: %+v", got)
	}
	if len(got.Processes) != 3 || got.Processes[0].PID != 1 || got.Processes[1].PID != 4 || got.Processes[2].PID != 5 {
		t.Fatalf("diagnostic did not restrict processes to the owner and descendants: %+v", got.Processes)
	}
	if len(got.FDReferences) != 2 || got.FDReferences[0].PID != 4 || got.FDReferences[0].FD != 7 ||
		got.FDReferences[0].Kind != "anchor" || got.FDReferences[1].PID != 4 || got.FDReferences[1].FD != 8 ||
		got.FDReferences[1].Kind != "source-device" {
		t.Fatalf("unexpected descriptor ownership evidence: %+v", got.FDReferences)
	}
	if len(got.PathReferences) != 1 || got.PathReferences[0].PID != 5 || got.PathReferences[0].Kind != "cwd-anchor" {
		t.Fatalf("unexpected process path references: %+v", got.PathReferences)
	}
	if len(got.MountReferences) != 2 || got.MountReferences[0].PID != 1 || got.MountReferences[1].PID != 4 ||
		got.MountReferences[0].MountID != 31 || got.MountReferences[0].Device != "8:16" {
		t.Fatalf("unexpected mount ownership evidence: %+v", got.MountReferences)
	}
	for _, private := range []string{"phantowd-state-volume", "accounts.db", "/dev/sdb", "/etc/passwd", "unrelated", "44", "8:32"} {
		if strings.Contains(line, private) {
			t.Fatalf("diagnostic leaked a path, unrelated process, or unrequested mount identity %q: %s", private, line)
		}
	}
}

func TestDiagnosticMarksIncompleteAndTruncatesAtBudget(t *testing.T) {
	processes := make([]int, MaxProcesses+2)
	statuses := make(map[int]ProcessStatus, len(processes))
	fds := make(map[int][]int, len(processes))
	links := make(map[string]string, len(processes)*MaxFDsPerProcess)
	for index := range processes {
		pid := index + 1
		processes[index] = pid
		parent := 0
		if index > 0 {
			parent = pid - 1
		}
		statuses[pid] = ProcessStatus{Name: "worker", ParentPID: parent}
		for fd := range MaxFDsPerProcess {
			fds[pid] = append(fds[pid], fd)
			links[procLinkKey(pid, "fd/"+strconv.Itoa(fd))] = "/run/phantowd-state-volume/file"
		}
		links[procLinkKey(pid, "cwd")] = "/"
		links[procLinkKey(pid, "root")] = "/"
	}
	proc := fakeProc{pids: processes, statuses: statuses, fds: fds, links: links}
	line := Capture("E_OTHER", 1, "/run/phantowd-state-volume", "/dev/sdb", proc)
	if len(line) > MaxDiagnosticBytes || !strings.Contains(line, `"truncated":true`) {
		t.Fatalf("diagnostic did not respect its output bound: bytes=%d line=%s", len(line), line)
	}
}

func TestDiagnosticTreatsVanishedUnrelatedProcessAsSnapshotRace(t *testing.T) {
	proc := fakeProc{
		pids: []int{1, 2},
		statuses: map[int]ProcessStatus{
			1: {Name: "fixture-owner", ParentPID: 0},
		},
		fds: map[int][]int{1: {}},
		links: map[string]string{
			procLinkKey(1, "cwd"):  "/",
			procLinkKey(1, "root"): "/",
		},
		mounts: map[int][]string{1: {}},
	}
	line := Capture("EBUSY", 1, "/run/fixture-state", "/dev/sdb", proc)
	const marker = "PHANTOWD_STATE_UNMOUNT_DIAG "
	var result struct {
		Incomplete bool `json:"incomplete"`
		Processes  []struct {
			PID int `json:"pid"`
		} `json:"processes"`
	}
	if !strings.HasPrefix(line, marker) || json.Unmarshal([]byte(strings.TrimPrefix(line, marker)), &result) != nil {
		t.Fatalf("invalid diagnostic record: %s", line)
	}
	if result.Incomplete || len(result.Processes) != 1 || result.Processes[0].PID != 1 {
		t.Fatalf("a vanished unrelated PID made the owner snapshot incomplete: %+v", result)
	}
}
