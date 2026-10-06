//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

const maxConfigurationBytes int64 = 64 << 10

// configurationPlan is separate from executable code admission. Expected
// contents come from a trusted renderer/identity authority, not from reading
// the tree being inspected. This private plan has no activation authority.
// Mutable passdb/state files must never be declared immutable inputs here.
type configurationPlan struct{ plan *Plan }

func newConfigurationPlan(inputs []File) (*configurationPlan, error) {
	if len(inputs) == 0 || len(inputs) > 16 {
		return nil, ErrInvalid
	}
	p := &Plan{files: slices.Clone(inputs), nodes: map[string]byte{".": 'd'}}
	for _, file := range p.files {
		if !canonical(file.Path) || file.SHA256 == ([32]byte{}) || file.Size <= 0 ||
			file.Size > maxConfigurationBytes-p.bytes ||
			(file.Mode != 0400 && file.Mode != 0444 && file.Mode != 0600 && file.Mode != 0644) ||
			p.addNode(file.Path, 'f') != nil {
			return nil, ErrInvalid
		}
		p.bytes += file.Size
	}
	slices.SortFunc(p.files, func(a, b File) int { return strings.Compare(a.Path, b.Path) })
	return &configurationPlan{plan: p}, nil
}

// No executable authority is attached to these pins. The containing service
// Owner must serialize their use, revalidate after fixing its other inputs,
// and establish complete process-group absence before release.
type retainedConfiguration struct{ contents *retainedCode }

func (p *configurationPlan) retain(ctx context.Context, root *os.File) (retained *retainedConfiguration, result error) {
	if p == nil || p.plan == nil || ctx == nil || root == nil {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := configurationMount(root); err != nil {
		return nil, err
	}
	contents, err := p.plan.prepareRetainedCode(ctx, root)
	if err != nil {
		return nil, err
	}
	c := &retainedConfiguration{contents: contents}
	if err := c.revalidate(ctx); err != nil {
		return nil, errors.Join(err, c.release())
	}
	return c, nil
}

func configurationMount(root *os.File) error {
	if root == nil {
		return ErrUnavailable
	}
	var fs unix.Statfs_t
	const required = unix.ST_RDONLY | unix.ST_NOSUID | unix.ST_NODEV | unix.ST_NOEXEC
	if unix.Fstatfs(int(root.Fd()), &fs) != nil {
		return ErrUnavailable
	}
	if !localCodeFilesystem(int64(fs.Type)) || fs.Flags&required != required {
		return ErrMismatch
	}
	return nil
}

func (c *retainedConfiguration) revalidate(ctx context.Context) error {
	if c == nil || c.contents == nil || c.contents.root == nil || ctx == nil {
		return ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := configurationMount(c.contents.root); err != nil {
		return err
	}
	return c.contents.revalidate(ctx)
}

func (c *retainedConfiguration) release() error {
	if c == nil || c.contents == nil {
		return nil
	}
	return c.contents.release()
}
