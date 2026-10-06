//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
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
	for _, expected := range p.files {
		fd, err := openBeneath(int(c.root.Fd()), expected.Path, unix.O_RDONLY)
		if err != nil {
			return nil, err
		}
		pin := os.NewFile(uintptr(fd), "retained-runtime-object")
		c.files[expected.Path] = pin
		if err := verifyOpenFile(ctx, pin, mount, expected); err != nil {
			return nil, err
		}
	}
	keep = true
	return c, nil
}

func (c *retainedCode) nodeMetadata(ctx context.Context) (map[string]unix.Statx_t, error) {
	result := make(map[string]unix.Statx_t, len(c.plan.nodes))
	for name := range c.plan.nodes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fd, err := openBeneath(int(c.root.Fd()), name, unix.O_PATH)
		if err != nil {
			return nil, err
		}
		var stat unix.Statx_t
		const required = unix.STATX_BASIC_STATS | unix.STATX_MNT_ID_UNIQUE
		statErr := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT, required, &stat)
		_ = unix.Close(fd)
		if statErr != nil || stat.Mask&required != required {
			return nil, ErrUnavailable
		}
		result[name] = stat
	}
	return result, nil
}

func (c *retainedCode) revalidate(ctx context.Context) error {
	if c == nil || c.root == nil || c.plan == nil || len(c.files) != len(c.plan.files) ||
		len(c.metadata) != len(c.plan.nodes) {
		return ErrUnavailable
	}
	if _, err := c.plan.Inspect(ctx, c.root); err != nil {
		return err
	}
	current, err := c.nodeMetadata(ctx)
	if err != nil {
		return err
	}
	for name, initial := range c.metadata {
		if current[name] != initial {
			return ErrMismatch
		}
	}
	for name, pin := range c.files {
		metadata, err := inspectMetadata(int(pin.Fd()), unix.S_IFREG, c.metadata["."].Mnt_id)
		if err != nil || metadata != c.metadata[name] {
			return ErrMismatch
		}
	}
	return nil
}

// release owns no processes. The containing Owner must establish their absence
// first; neither a reference nor a successful observation is an execution token.
func (c *retainedCode) release() error {
	if c == nil {
		return nil
	}
	var result error
	for _, pin := range c.files {
		result = errors.Join(result, pin.Close())
	}
	c.files = nil
	if c.root != nil {
		result = errors.Join(result, c.root.Close())
		c.root = nil
	}
	return result
}
