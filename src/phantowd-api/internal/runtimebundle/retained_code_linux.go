//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"os"

	"golang.org/x/sys/unix"
)

// retainedCode privately owns the complete code-only tree's references and
// original identities. Its containing Owner serializes use and must verify
// whole-process cleanup before releasing it. It grants no execution authority.
type retainedCode struct {
	plan        *Plan
	root        *os.File
	files       map[string]*os.File
	metadata    map[string]unix.Statx_t
	observation Observation
	releaseErr  error
}

// prepareRetainedCode collects independent references without exposing them.
// The containing constructor must revalidate AFTER its other inputs are fixed
// and before publication/launch. Keep that late identity fence; preparation's
// point-in-time census alone is insufficient. No extra scan or weaker census.
func (p *Plan) prepareRetainedCode(ctx context.Context, root *os.File) (*retainedCode, error) {
	if p == nil || len(p.files) == 0 || ctx == nil || root == nil {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c := &retainedCode{plan: p, files: make(map[string]*os.File, len(p.files))}
	keep := false
	defer func() {
		if !keep {
			_ = c.release()
		}
	}()
	var err error
	c.root, err = duplicateRoot(root)
	if err != nil {
		return nil, err
	}
	c.observation, err = p.Inspect(ctx, c.root)
	if err != nil {
		return nil, err
	}
	c.metadata, err = c.nodeMetadata(ctx)
	if err != nil {
		return nil, err
	}
	mount := c.metadata["."].Mnt_id
	scratch := make([]byte, runtimeHashScratchSize)
	for _, expected := range p.files {
		fd, err := openBeneath(int(c.root.Fd()), expected.Path, unix.O_RDONLY)
		if err != nil {
			return nil, err
		}
		pin := os.NewFile(uintptr(fd), "retained-runtime-object")
		c.files[expected.Path] = pin
		if err := verifyOpenFile(ctx, pin, mount, expected, scratch); err != nil {
			return nil, err
		}
	}
	keep = true
	return c, nil
}

func (c *retainedCode) nodeMetadata(ctx context.Context) (map[string]unix.Statx_t, error) {
	if c == nil || c.root == nil || c.plan == nil || len(c.plan.nodes) == 0 {
		return nil, ErrUnavailable
	}
	if ctx == nil {
		return nil, ErrInvalid
	}
	result := make(map[string]unix.Statx_t, len(c.plan.nodes))
	for name := range c.plan.nodes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		stat, err := c.readNodeMetadata(name)
		if err != nil {
			return nil, err
		}
		result[name] = stat
	}
	// The last context check precedes real open/stat/close syscalls. Do not
	// publish a complete-looking table if cancellation arrived during them.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func (c *retainedCode) readNodeMetadata(name string) (unix.Statx_t, error) {
	var stat unix.Statx_t
	fd, err := openBeneath(int(c.root.Fd()), name, unix.O_PATH)
	if err != nil {
		return stat, err
	}
	const required = unix.STATX_BASIC_STATS | unix.STATX_MNT_ID_UNIQUE
	statErr := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT, required, &stat)
	closeErr := unix.Close(fd)
	if statErr != nil || closeErr != nil || stat.Mask&required != required {
		return stat, ErrUnavailable
	}
	return stat, nil
}

// Compare every fresh path observation with the original protected table.
// No new table, metadata cache, identity replacement or weaker late fence.
// The containing Owner serializes use; the original table is never changed.
func (c *retainedCode) verifyNodeMetadata(ctx context.Context) error {
	if c == nil || c.root == nil || c.plan == nil || len(c.plan.nodes) == 0 {
		return ErrUnavailable
	}
	if ctx == nil {
		return ErrInvalid
	}
	if len(c.metadata) != len(c.plan.nodes) {
		return ErrMismatch
	}
	for name := range c.plan.nodes {
		if err := ctx.Err(); err != nil {
			return err
		}
		initial, present := c.metadata[name]
		if !present {
			return ErrMismatch
		}
		current, err := c.readNodeMetadata(name)
		if err != nil {
			return err
		}
		if current != initial {
			return ErrMismatch
		}
	}
	return ctx.Err()
}

func (c *retainedCode) revalidate(ctx context.Context) error {
	if c == nil || c.root == nil || c.plan == nil || len(c.files) != len(c.plan.files) ||
		len(c.metadata) != len(c.plan.nodes) {
		return ErrUnavailable
	}
	if _, err := c.plan.Inspect(ctx, c.root); err != nil {
		return err
	}
	if err := c.verifyNodeMetadata(ctx); err != nil {
		return err
	}
	for name, pin := range c.files {
		if err := ctx.Err(); err != nil {
			return err
		}
		metadata, err := inspectMetadata(int(pin.Fd()), unix.S_IFREG, c.metadata["."].Mnt_id)
		if err != nil || metadata != c.metadata[name] {
			return ErrMismatch
		}
	}
	return ctx.Err()
}

// release owns no processes. The containing Owner must establish their absence
// first; neither a reference nor a successful observation is an execution token.
// A close error permanently blocks further releases. Preserve unattempted pins
// and the error; the descriptor that failed to close is not assumed still open.
func (c *retainedCode) release() error {
	if c == nil {
		return nil
	}
	if c.releaseErr != nil {
		return c.releaseErr
	}
	for name, pin := range c.files {
		if err := pin.Close(); err != nil {
			c.releaseErr = err
			return err
		}
		delete(c.files, name)
	}
	c.files = nil
	if c.root != nil {
		if err := c.root.Close(); err != nil {
			c.releaseErr = err
			return err
		}
		c.root = nil
	}
	return nil
}
