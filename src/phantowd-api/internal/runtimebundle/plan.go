// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package runtimebundle checks a fixed, code-only runtime tree. It grants no
// execution, installation, storage, mount or privilege authority.
package runtimebundle

import (
	"errors"
	"path"
	"slices"
	"strings"
)

const (
	maxFiles          = 256
	maxBindings       = 1024
	maxNodes          = 4096
	maxBytes    int64 = 64 << 20
)

var (
	ErrInvalid     = errors.New("invalid fixed runtime bundle")
	ErrMismatch    = errors.New("runtime bundle does not match fixed inputs")
	ErrUnavailable = errors.New("runtime bundle inspection unavailable")
)

// File describes a regular file whose expected bytes come from a separately
// trusted build/release boundary, never an HTTP request or self-hashed tree.
// Mode is exactly 0444 (data) or 0555 (executable/library).
type File struct {
	Path   string
	SHA256 [32]byte
	Size   int64
	Mode   uint32
}

// Alias materializes one absolute in-root symlink directly to a declared File.
// Both fields are canonical image-relative paths; chains are not supported.
type Alias struct{ Path, Target string }

// Plan privately copies all inputs. It is not an approved runtime manifest:
// signature/model/ABI/profile validation belongs to the future trusted owner.
type Plan struct {
	files   []File
	aliases []Alias
	nodes   map[string]byte
	bytes   int64
}

// Observation is point-in-time internal evidence, not a retained lease or token
// permitting execution. Inspection closes all of its independent descriptors.
type Observation struct {
	Files, Aliases int
	Bytes          int64
}

func NewPlan(files []File, aliases []Alias) (*Plan, error) {
	if len(files) == 0 || len(files) > maxFiles || len(files)+len(aliases) > maxBindings {
		return nil, ErrInvalid
	}
	p := &Plan{files: slices.Clone(files), aliases: slices.Clone(aliases), nodes: map[string]byte{".": 'd'}}
	filePaths := make(map[string]bool, len(files))
	for _, file := range p.files {
		if !canonical(file.Path) || file.Size <= 0 || file.Size > maxBytes-p.bytes ||
			file.SHA256 == ([32]byte{}) || (file.Mode != 0444 && file.Mode != 0555) ||
			p.addNode(file.Path, 'f') != nil {
			return nil, ErrInvalid
		}
		p.bytes += file.Size
		filePaths[file.Path] = true
	}
	for _, alias := range p.aliases {
		if !canonical(alias.Path) || !filePaths[alias.Target] ||
			p.addNode(alias.Path, 'l') != nil {
			return nil, ErrInvalid
		}
	}
	slices.SortFunc(p.files, func(a, b File) int { return strings.Compare(a.Path, b.Path) })
	slices.SortFunc(p.aliases, func(a, b Alias) int { return strings.Compare(a.Path, b.Path) })
	return p, nil
}

func (p *Plan) addNode(name string, kind byte) error {
	if _, exists := p.nodes[name]; exists {
		return ErrInvalid
	}
	p.nodes[name] = kind
	for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
		if existing, ok := p.nodes[parent]; ok && existing != 'd' {
			return ErrInvalid
		}
		p.nodes[parent] = 'd'
	}
	if len(p.nodes) > maxNodes {
		return ErrInvalid
	}
	return nil
}

func canonical(name string) bool {
	if len(name) == 0 || len(name) > 4096 || name == "." || path.Clean(name) != name || strings.HasPrefix(name, "/") {
		return false
	}
	parts := strings.Split(name, "/")
	if len(parts) > 16 {
		return false
	}
	for _, part := range parts {
		if part == ".." || len(part) > 255 {
			return false
		}
	}
	// Runtime paths intentionally have a small ASCII alphabet, not user names.
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("/_-.+", c)) {
			return false
		}
	}
	return true
}

func (Plan) MarshalJSON() ([]byte, error)        { return nil, ErrInvalid }
func (*Plan) UnmarshalJSON([]byte) error         { return ErrInvalid }
func (Observation) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (*Observation) UnmarshalJSON([]byte) error  { return ErrInvalid }
