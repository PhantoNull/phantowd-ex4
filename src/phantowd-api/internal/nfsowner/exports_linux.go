// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfsowner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfskernel"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
)

type exportEntry struct {
	path, mount, id string
	client          nfsconfig.Client
}

func (e exportEntry) argument() string {
	host := e.client.Network
	if strings.Contains(host, ":") {
		address, prefix, _ := strings.Cut(host, "/")
		host = "[" + address + "]/" + prefix
	}
	return host + ":" + e.path
}

func (e exportEntry) displayedOptions() []string {
	squash := "no_all_squash"
	if e.client.Squash == "all" {
		squash = "all_squash"
	}
	// nfs-utils 2.8.6 hides negative flags for subtree and cross-mount
	// access and omits the default anonymous IDs in exportfs -s.
	options := []string{"sync", "wdelay", "hide", "fsid=" + e.id, "mountpoint=" + e.mount,
		"sec=sys", e.client.Access, "secure", "root_squash", squash}
	if e.path == e.mount {
		options = append(options, "no_subtree_check")
	}
	if e.client.AnonymousUID != 65534 {
		options = append(options, fmt.Sprintf("anonuid=%d", e.client.AnonymousUID))
	}
	if e.client.AnonymousGID != 65534 {
		options = append(options, fmt.Sprintf("anongid=%d", e.client.AnonymousGID))
	}
	slices.Sort(options)
	return options
}

// Exports owns the exportfs executable and one original candidate's lifecycle.
// Its caller supplies an exclusive export table in the admitted kernel domain.
type Exports struct {
	original                  *Exports
	gate                      chan struct{}
	inputs                    *RetainedInputs
	kernel                    *nfskernel.Controller
	address                   netip.Addr
	code                      *os.File
	entries                   []exportEntry
	limit, attempted          int
	withdrawn, closed, review bool
}

// The caller holds the retained input gate through attachment.
func newExports(ctx context.Context, inputs *RetainedInputs, kernel *nfskernel.Controller, address netip.Addr, executable *os.File) (*Exports, error) {
	if err := kernel.CheckDomain(ctx, address); err != nil {
		return nil, err
	}
	_, _, roots, err := inputs.candidate.Documents()
	if err != nil || len(roots) == 0 {
		return nil, ErrInvalid
	}
	e := &Exports{gate: make(chan struct{}, 1), inputs: inputs, kernel: kernel, address: address, limit: 1024}
	e.original = e
	for _, root := range roots {
		name := path.Join(root.Volume.MountPath, root.RelativePath)
		for _, client := range root.Clients {
			e.entries = append(e.entries, exportEntry{path: name, mount: root.Volume.MountPath, id: root.ID, client: client})
			e.limit += 4*len(name) + len(root.Volume.MountPath) + len(client.Network) + 512
		}
	}
	e.code, err = processowner.RetainExecutable(executable)
	if err != nil {
		return nil, err
	}
	return e, nil
}

func (e *Exports) Publish(ctx context.Context) error {
	if err := e.enter(); err != nil {
		return err
	}
	defer e.leave()
	if e.attempted != 0 || e.withdrawn || e.review {
		return ErrState
	}
	if err := e.kernel.CheckRunning(ctx); err != nil {
		return err
	}
	if err := e.verifyEmpty(ctx); err != nil {
		return err
	}
	for _, entry := range e.entries {
		if err := e.inputs.check(ctx, e.inputs.candidate, true); err != nil {
			return e.requireReview(err)
		}
		e.attempted++ // Even an unsuccessful subprocess may have modified the table.
		options := nfsconfig.ExportOptions(entry.client, entry.id, entry.mount, entry.path == entry.mount)
		if _, err := e.run(ctx, "-i", "-o", options, entry.argument()); err != nil {
			return e.requireReview(err)
		}
	}
	return e.checkPublished(ctx)
}

func (e *Exports) CheckPublished(ctx context.Context) error {
	if err := e.enter(); err != nil {
		return err
	}
	defer e.leave()
	return e.checkPublished(ctx)
}

func (e *Exports) checkPublished(ctx context.Context) error {
	if e.review || e.withdrawn || e.attempted != len(e.entries) {
		return ErrState
	}
	if err := e.inputs.check(ctx, e.inputs.candidate, true); err != nil {
		return e.requireReview(err)
	}
	observed, err := e.observe(ctx)
	if err != nil || len(observed) != len(e.entries) {
		return e.requireReview(err)
	}
	return nil
}

func (e *Exports) Withdraw(ctx context.Context) error {
	if err := e.enter(); err != nil {
		return err
	}
	defer e.leave()
	if e.withdrawn {
		return ErrState
	}
	if e.attempted == 0 {
		return e.verifyEmpty(ctx)
	}
	if err := e.kernel.CheckStopped(ctx); err != nil {
		return e.requireReview(err)
	}
	e.withdrawn = true // One settlement attempt, with review retained on failure.
	observed, err := e.observe(ctx)
	if err != nil {
		return e.requireReview(err)
	}
	for _, index := range observed {
		if _, err := e.run(ctx, "-u", e.entries[index].argument()); err != nil {
			return e.requireReview(err)
		}
	}
	return e.verifyEmpty(ctx)
}

func (e *Exports) VerifyEmpty(ctx context.Context) error {
	if err := e.enter(); err != nil {
		return err
	}
	defer e.leave()
	return e.verifyEmpty(ctx)
}

func (e *Exports) verifyEmpty(ctx context.Context) error {
	data, err := e.run(ctx, "-s")
	if err != nil || len(bytes.TrimSpace(data)) != 0 || e.review {
		return e.requireReview(err)
	}
	return nil
}

func (e *Exports) Close(ctx context.Context) error {
	if err := e.enter(); err != nil {
		return err
	}
	defer e.leave()
	if e.attempted != 0 && !e.withdrawn {
		return ErrState
	}
	if err := e.verifyEmpty(ctx); err != nil {
		return err
	}
	if err := e.code.Close(); err != nil {
		return e.requireReview(err)
	}
	e.closed = true
	return nil
}

func (e *Exports) observe(ctx context.Context) ([]int, error) {
	data, err := e.run(ctx, "-s")
	if err != nil {
		return nil, err
	}
	byKey := make(map[[2]string]int, e.attempted)
	for i, entry := range e.entries[:e.attempted] {
		byKey[[2]string{entry.path, entry.client.Network}] = i
	}
	var observed []int
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, ErrReviewRequired
		}
		pathname, err := unescapeExportPath(fields[0])
		network, raw, found := strings.Cut(fields[1], "(")
		options, closed := strings.CutSuffix(raw, ")")
		key := [2]string{pathname, network}
		index, exists := byKey[key]
		if err != nil || !found || !closed || !exists {
			return nil, ErrReviewRequired
		}
		actual := strings.Split(options, ",")
		slices.Sort(actual)
		if !slices.Equal(actual, e.entries[index].displayedOptions()) {
			return nil, ErrReviewRequired
		}
		delete(byKey, key)
		observed = append(observed, index)
	}
	return observed, nil
}

func unescapeExportPath(value string) (string, error) {
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] != '\\' {
			out.WriteByte(value[i])
			continue
		}
		if i+3 >= len(value) {
			return "", ErrInvalid
		}
		decoded, err := strconv.ParseUint(value[i+1:i+4], 8, 8)
		if err != nil || decoded == 0 {
			return "", ErrInvalid
		}
		out.WriteByte(byte(decoded))
		i += 3
	}
	return out.String(), nil
}

type exportOutput struct {
	data  bytes.Buffer
	limit int
}

func (o *exportOutput) Write(data []byte) (int, error) {
	if len(data) > o.limit-o.data.Len() {
		return 0, ErrReviewRequired
	}
	return o.data.Write(data)
}

func (e *Exports) run(ctx context.Context, args ...string) ([]byte, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := e.kernel.CheckDomain(ctx, e.address); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, "/proc/self/fd/3", args...)
	cmd.Args[0], cmd.Dir = "/usr/sbin/exportfs", "/"
	cmd.Env, cmd.ExtraFiles = []string{"LC_ALL=C"}, []*os.File{e.code}
	cmd.WaitDelay = time.Second
	output := &exportOutput{limit: e.limit}
	cmd.Stdout = output
	if cmd.Run() != nil {
		return nil, errors.Join(ErrReviewRequired, ctx.Err())
	}
	return output.data.Bytes(), e.kernel.CheckDomain(ctx, e.address)
}

func (e *Exports) requireReview(cause error) error {
	e.review = true
	return errors.Join(ErrReviewRequired, cause)
}

func (e *Exports) enter() error {
	if e == nil || e.original != e {
		return ErrInvalid
	}
	select {
	case e.gate <- struct{}{}:
		if e.closed {
			e.leave()
			return ErrState
		}
		return nil
	default:
		return ErrBusy
	}
}

func (e *Exports) leave() { <-e.gate }
