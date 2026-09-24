// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package storagerefs finds literal WD-era disk and share references in an
// already extracted filesystem tree. It never executes or follows symlinks.
package storagerefs

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	maxEntries   = 250000
	maxFileBytes = 32 * 1024 * 1024
)

var (
	pathReferences = regexp.MustCompile(`/mnt/HD/HD_[a-d]2|/mnt/HD_[a-d]4|/dev/sd[a-d][0-9]*|/shares/Volume_[1-4]|/nfs/|hd_volume_info\.xml|raid_uuid`)
	volumeTokens   = regexp.MustCompile(`HD_[a-d][24]|Volume_[1-4]`)
)

// Finding contains only a known reference token, its relative path and count.
// Source lines and arbitrary matched text are never copied into the report.
type Finding struct {
	Path        string `json:"path"`
	Kind        string `json:"kind"`
	Reference   string `json:"reference"`
	Occurrences int    `json:"occurrences"`
}

// Report is a deterministic, literal-only scan of an extracted root tree.
type Report struct {
	Format              string    `json:"format"`
	SchemaVersion       int       `json:"schema_version"`
	FilesScanned        int       `json:"files_scanned"`
	BytesScanned        int64     `json:"bytes_scanned"`
	EmptyFilesScanned   int       `json:"empty_files_scanned"`
	SkippedLargeFiles   int       `json:"skipped_large_files"`
	SymlinksSkipped     int       `json:"symlinks_skipped"`
	SpecialFilesSkipped int       `json:"special_files_skipped"`
	Findings            []Finding `json:"findings"`
	Limitations         []string  `json:"limitations"`
}

// Inspect scans an already extracted directory for known WD storage-path
// literals. It does not read disk devices, parse live storage metadata, or
// infer how any matched code behaves at runtime.
func Inspect(root string) (Report, error) {
	report := Report{
		Format:        "phantowd-storage-reference-scan",
		SchemaVersion: 1,
		Findings:      []Finding{},
		Limitations: []string{
			"literal matching is not a complete code or data-flow analysis",
			"symlinks, special files and regular files larger than 32 MiB are not read",
			"findings do not prove that a path is active or that a disk layout is supported",
		},
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return report, err
	}
	rootInfo, err := os.Lstat(absoluteRoot)
	if err != nil {
		return report, err
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 {
		return report, errors.New("refusing symbolic-link root")
	}
	if !rootInfo.IsDir() {
		return report, errors.New("storage-reference input must be a directory")
	}

	entries := 0
	err = filepath.WalkDir(absoluteRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == absoluteRoot {
			return nil
		}
		entries++
		if entries > maxEntries {
			return fmt.Errorf("input contains more than %d entries", maxEntries)
		}
		relative, err := filepath.Rel(absoluteRoot, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		switch {
		case info.IsDir():
			return nil
		case info.Mode()&os.ModeSymlink != 0:
			report.SymlinksSkipped++
			return nil
		case info.Mode().IsRegular():
			if info.Size() > maxFileBytes {
				report.SkippedLargeFiles++
				return nil
			}
			findings, err := scanFile(path, relative, info)
			if err != nil {
				return err
			}
			report.FilesScanned++
			report.BytesScanned += info.Size()
			if info.Size() == 0 {
				report.EmptyFilesScanned++
			}
			report.Findings = append(report.Findings, findings...)
			return nil
		default:
			report.SpecialFilesSkipped++
			return nil
		}
	})
	if err != nil {
		return report, err
	}
	sort.Slice(report.Findings, func(i, j int) bool {
		a, b := report.Findings[i], report.Findings[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Reference < b.Reference
	})
	return report, nil
}

func scanFile(path, relative string, before fs.FileInfo) ([]Finding, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) || opened.Size() != before.Size() {
		return nil, fmt.Errorf("%s changed identity before inspection", relative)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFileBytes {
		return nil, fmt.Errorf("%s grew beyond the scan limit", relative)
	}
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return nil, fmt.Errorf("%s changed during inspection", relative)
	}

	type findingKey struct{ kind, reference string }
	counts := make(map[findingKey]int)
	for _, match := range pathReferences.FindAll(data, -1) {
		reference := string(match)
		counts[findingKey{kind: pathReferenceKind(reference), reference: reference}]++
	}
	for _, match := range volumeTokens.FindAll(data, -1) {
		reference := string(match)
		kind := "legacy-volume-name"
		if len(reference) > 2 && reference[:3] == "HD_" {
			kind = "legacy-hd-volume-token"
		}
		counts[findingKey{kind: kind, reference: reference}]++
	}
	findings := make([]Finding, 0, len(counts))
	for key, count := range counts {
		findings = append(findings, Finding{
			Path: relative, Kind: key.kind, Reference: key.reference, Occurrences: count,
		})
	}
	return findings, nil
}

func pathReferenceKind(reference string) string {
	switch {
	case strings.HasPrefix(reference, "/mnt/HD/HD_"):
		return "legacy-data-mount"
	case strings.HasPrefix(reference, "/mnt/HD_"):
		return "legacy-hidden-mount"
	case strings.HasPrefix(reference, "/dev/sd"):
		return "linux-disk-device"
	case strings.HasPrefix(reference, "/shares/Volume_"):
		return "legacy-share-alias"
	case reference == "/nfs/":
		return "legacy-NFS-path"
	case reference == "hd_volume_info.xml":
		return "volume-metadata-file"
	case reference == "raid_uuid":
		return "raid-identity-field"
	default:
		return "unclassified-storage-reference"
	}
}
