// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package diskimage

// ExtFeatureReview observes declarations, not actual file contents or feature
// support. Required=false never establishes WD compatibility or mount safety.
type ExtFeatureReview struct {
	Profile                  string   `json:"profile"`
	Required                 bool     `json:"required"`
	Declared                 []string `json:"declared"`
	Reasons                  []string `json:"reasons"`
	ExternalJournalReference bool     `json:"external_journal_reference"`
	UnclassifiedCompat       uint32   `json:"unclassified_compat_bits"`
	UnclassifiedIncompat     uint32   `json:"unclassified_incompat_bits"`
	UnclassifiedROCompat     uint32   `json:"unclassified_ro_compat_bits"`
}

// Names/bits follow Linux v6.18 fs/ext4/ext4.h. The review marker is this
// bounded observation's policy, never the kernel's feature-support mask.
var extFeatureDeclarations = [3][]struct {
	bit    uint32
	name   string
	review bool
}{
	{
		{0x1, "compat-dir-prealloc", true}, {0x2, "compat-imagic-inodes", true},
		{0x4, "compat-has-journal", false}, {0x8, "compat-ext-attr", false},
		{0x10, "compat-resize-inode", false}, {0x20, "compat-dir-index", false},
		{0x200, "compat-sparse-super2", false}, {0x400, "compat-fast-commit", true},
		{0x800, "compat-stable-inodes", true}, {0x1000, "compat-orphan-file", true},
	},
	{
		{0x1, "incompat-compression", true}, {0x2, "incompat-filetype", false},
		{0x4, "incompat-recover", true}, {0x8, "incompat-journal-dev", true},
		{0x10, "incompat-meta-bg", false}, {0x40, "incompat-extents", false},
		{0x80, "incompat-64bit", false}, {0x100, "incompat-mmp", true},
		{0x200, "incompat-flex-bg", false}, {0x400, "incompat-ea-inode", true},
		{0x1000, "incompat-dirdata", true}, {0x2000, "incompat-csum-seed", false},
		{0x4000, "incompat-largedir", true}, {0x8000, "incompat-inline-data", true},
		{0x10000, "incompat-encrypt", true}, {0x20000, "incompat-casefold", true},
	},
	{
		{0x1, "ro-compat-sparse-super", false}, {0x2, "ro-compat-large-file", false},
		{0x4, "ro-compat-btree-dir", true}, {0x8, "ro-compat-huge-file", false},
		{0x10, "ro-compat-gdt-csum", false}, {0x20, "ro-compat-dir-nlink", false},
		{0x40, "ro-compat-extra-isize", false}, {0x100, "ro-compat-quota", true},
		{0x200, "ro-compat-bigalloc", true}, {0x400, "ro-compat-metadata-csum", false},
		{0x1000, "ro-compat-readonly", true}, {0x2000, "ro-compat-project", true},
		{0x8000, "ro-compat-verity", true}, {0x10000, "ro-compat-orphan-present", true},
	},
}

func reviewExtFeatures(compat, incompat, roCompat uint32) *ExtFeatureReview {
	review := &ExtFeatureReview{Profile: "linux-v6.18-declarations", Declared: []string{}, Reasons: []string{}}
	unknown := [3]uint32{compat, incompat, roCompat}
	for family, declarations := range extFeatureDeclarations {
		for _, declaration := range declarations {
			if unknown[family]&declaration.bit == 0 {
				continue
			}
			unknown[family] &^= declaration.bit
			review.Declared = append(review.Declared, declaration.name)
			if declaration.review {
				review.Reasons = append(review.Reasons, declaration.name)
			}
		}
	}
	review.UnclassifiedCompat, review.UnclassifiedIncompat, review.UnclassifiedROCompat = unknown[0], unknown[1], unknown[2]
	review.Required = len(review.Reasons) != 0 || unknown != [3]uint32{}
	return review
}
