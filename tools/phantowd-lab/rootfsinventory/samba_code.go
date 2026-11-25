// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package rootfsinventory

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const sambaCodeFormat = "phantowd-samba-code-v1"
const sambaCatalogPath = "usr/lib/gconv/gconv-modules"
const sambaCatalog = "alias CP850// IBM850//\nalias 850// IBM850//\n" +
	"alias CSPC850MULTILINGUAL// IBM850//\nalias OSF10020352// IBM850//\n" +
	"module IBM850// INTERNAL IBM850 1\nmodule INTERNAL IBM850// IBM850 1\n"

var sambaCodeEntries = [...]string{
	"usr/sbin/smbd", "usr/bin/smbpasswd", "usr/bin/testparm", "usr/bin/pdbedit",
	"usr/bin/smbstatus", "usr/bin/smbcontrol", "usr/lib/samba/vfs/streams_xattr.so", "usr/lib/gconv/IBM850.so",
}

type sambaCodeFile struct {
	Path   string      `json:"path"`
	SHA256 string      `json:"sha256"`
	Size   int64       `json:"size"`
	Mode   fs.FileMode `json:"mode"`
}

type sambaCodeAlias struct {
	Path   string `json:"path"`
	Target string `json:"target"`
}

type sambaCodeManifest struct {
	Format  string           `json:"format"`
	Files   []sambaCodeFile  `json:"files"`
	Aliases []sambaCodeAlias `json:"aliases"`
}

func (r Report) sambaCodeClosure() (sambaCodeManifest, error) {
	objects := map[string]sambaCodeFile{}
	bindings := map[string]string{}
	allowed := func(name string) bool {
		return runtimeRelative(name) && name != sambaCatalogPath && (slices.Contains(sambaCodeEntries[:], name) ||
			strings.HasPrefix(name, "lib/") || strings.HasPrefix(name, "usr/lib/"))
	}
	for _, entry := range sambaCodeEntries {
		closure, err := r.RuntimeClosure(entry)
		if err != nil {
			return sambaCodeManifest{}, fmt.Errorf("resolve Samba runtime entry %s: %w", entry, err)
		}
		if !closure.StaticDependenciesResolved {
			return sambaCodeManifest{}, fmt.Errorf("Samba closure for %s refused (%s)", entry, closure.Reason)
		}
		for _, object := range closure.Objects {
			f := sambaCodeFile{Path: object.Path, SHA256: object.SHA256, Size: object.Size, Mode: 0555}
			if !allowed(f.Path) || !runtimeHash(f.SHA256) || f.Size <= 0 {
				return sambaCodeManifest{}, errors.New("invalid Samba runtime object")
			}
			if prior, ok := objects[f.Path]; ok && f != prior {
				return sambaCodeManifest{}, errors.New("conflicting Samba runtime object")
			}
			objects[f.Path] = f
			for _, alias := range object.Bindings {
				if prior, ok := bindings[alias]; !allowed(alias) || ok && prior != f.Path {
					return sambaCodeManifest{}, errors.New("conflicting Samba runtime binding")
				}
				bindings[alias] = f.Path
			}
		}
	}
	if bindings["lib/ld-linux.so.3"] != "lib/ld-linux.so.3" {
		return sambaCodeManifest{}, errors.New("unexpected Samba runtime interpreter")
	}
	for _, entry := range sambaCodeEntries {
		if _, ok := objects[entry]; !ok {
			return sambaCodeManifest{}, errors.New("missing canonical Samba runtime entry")
		}
	}
	objects[sambaCatalogPath] = sambaCodeFile{Path: sambaCatalogPath, SHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(sambaCatalog))),
		Size: int64(len(sambaCatalog)), Mode: 0444}
	manifest := sambaCodeManifest{Format: sambaCodeFormat, Files: []sambaCodeFile{}, Aliases: []sambaCodeAlias{}}
	var size int64
	for _, file := range objects {
		if file.Size > maxRuntimeBytes-size {
			return sambaCodeManifest{}, errors.New("Samba runtime byte budget exceeded")
		}
		size += file.Size
		manifest.Files = append(manifest.Files, file)
	}
	for alias, canonical := range bindings {
		if alias == canonical {
			continue
		}
		if _, conflict := objects[alias]; conflict {
			return sambaCodeManifest{}, errors.New("Samba alias shadows runtime file")
		}
		manifest.Aliases = append(manifest.Aliases, sambaCodeAlias{Path: alias, Target: canonical})
	}
	if len(manifest.Files) > maxRuntimeObjects || len(manifest.Files)+len(manifest.Aliases) > maxRuntimeBindings {
		return sambaCodeManifest{}, errors.New("Samba runtime object budget exceeded")
	}
	slices.SortFunc(manifest.Files, func(a, b sambaCodeFile) int { return strings.Compare(a.Path, b.Path) })
	slices.SortFunc(manifest.Aliases, func(a, b sambaCodeAlias) int { return strings.Compare(a.Path, b.Path) })
	return manifest, nil
}

// StageSambaCode assembles the fixed isolated code tree from a trusted build
// target. The published destination is a separate new directory containing
// the code-only root and its manifest. The source remains untouched.
func StageSambaCode(target, destination string) error {
	if _, err := os.Lstat(destination); !errors.Is(err, fs.ErrNotExist) {
		return errors.New("fresh Samba code destination required")
	}
	inventory, err := Inspect(target)
	if err != nil {
		return err
	}
	manifest, err := inventory.sambaCodeClosure()
	if err != nil {
		return err
	}
	source, err := os.OpenRoot(target)
	if err != nil {
		return err
	}
	defer source.Close()
	stage, err := os.MkdirTemp(filepath.Dir(destination), ".samba-code-stage.")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	root := filepath.Join(stage, "root")
	if err := os.Mkdir(root, 0755); err != nil {
		return err
	}
	for _, file := range manifest.Files {
		path := filepath.Join(root, file.Path)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}
		if file.Path == sambaCatalogPath {
			err = os.WriteFile(path, []byte(sambaCatalog), file.Mode)
		} else {
			err = stageSambaObject(source, file, path)
		}
		if err != nil {
			return err
		}
	}
	for _, alias := range manifest.Aliases {
		path := filepath.Join(root, alias.Path)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}
		if err := os.Symlink("/"+alias.Target, path); err != nil {
			return err
		}
	}
	jsonBytes, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(stage, "manifest.json"), append(jsonBytes, '\n'), 0444); err != nil {
		return err
	}
	if err := os.Chmod(stage, 0755); err != nil {
		return err
	}
	return os.Rename(stage, destination)
}

func stageSambaObject(source *os.Root, expected sambaCodeFile, destination string) error {
	input, err := source.Open(expected.Path)
	if err != nil {
		return err
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != expected.Size {
		return errors.New("Samba source no longer matches the closure")
	}
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, expected.Mode)
	if err != nil {
		return err
	}
	hash := sha256.New()
	count, copyErr := io.Copy(io.MultiWriter(output, hash), io.LimitReader(input, expected.Size+1))
	if err := errors.Join(copyErr, output.Close()); err != nil {
		return err
	}
	if count != expected.Size || fmt.Sprintf("%x", hash.Sum(nil)) != expected.SHA256 {
		return errors.New("Samba source bytes changed during staging")
	}
	return nil
}
