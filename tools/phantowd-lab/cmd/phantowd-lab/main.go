// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-lab/diskimage"
	"github.com/PhantoNull/phantowd-ex4/phantowd-lab/githubrelease"
	"github.com/PhantoNull/phantowd-ex4/phantowd-lab/mcuproto"
	"github.com/PhantoNull/phantowd-ex4/phantowd-lab/releaseverify"
	"github.com/PhantoNull/phantowd-ex4/phantowd-lab/rootfsinventory"
	"github.com/PhantoNull/phantowd-ex4/phantowd-lab/storageinventory"
	"github.com/PhantoNull/phantowd-ex4/phantowd-lab/storagerefs"
	"github.com/PhantoNull/phantowd-ex4/phantowd-lab/vendorupdate"
)

const (
	maxCaptureSize           = int64(16 * 1024 * 1024)
	maxStorageImageSetInputs = 4
)

func main() {
	code, err := run(os.Args[1:], os.Stdout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "phantowd-lab: %v\n", err)
		os.Exit(1)
	}
	os.Exit(code)
}

func run(args []string, output io.Writer) (int, error) {
	if len(args) == 0 {
		return 1, errors.New("usage: phantowd-lab COMMAND [arguments]")
	}
	switch args[0] {
	case "inspect-github-release":
		return inspectGitHubRelease(args[1:], output)

	case "inspect-release":
		return inspectRelease(args[1:], output)

	case "inspect-update":
		if len(args) != 2 {
			return 1, errors.New("usage: phantowd-lab inspect-update FILE")
		}
		file, size, err := openRegular(args[1])
		if err != nil {
			return 1, err
		}
		defer file.Close()
		report, err := vendorupdate.Inspect(file, size)
		if err != nil {
			return 1, err
		}
		if err := writeJSON(output, report); err != nil {
			return 1, err
		}
		if !report.Valid {
			return 2, nil
		}
		return 0, nil

	case "inspect-mtd3":
		if len(args) != 2 {
			return 1, errors.New("usage: phantowd-lab inspect-mtd3 FILE")
		}
		file, size, err := openRegular(args[1])
		if err != nil {
			return 1, err
		}
		defer file.Close()
		report, err := vendorupdate.InspectLogicalImage(file, size)
		if err != nil {
			return 1, err
		}
		if err := writeJSON(output, report); err != nil {
			return 1, err
		}
		if !report.Valid {
			return 2, nil
		}
		return 0, nil

	case "inspect-rescue":
		if len(args) != 2 {
			return 1, errors.New("usage: phantowd-lab inspect-rescue FILE")
		}
		file, size, err := openRegular(args[1])
		if err != nil {
			return 1, err
		}
		defer file.Close()
		report, err := vendorupdate.InspectRescueImage(file, size)
		if err != nil {
			return 1, err
		}
		if err := writeJSON(output, report); err != nil {
			return 1, err
		}
		if !report.Valid {
			return 2, nil
		}
		return 0, nil

	case "inventory-rootfs":
		return inventoryRootfs(args[1:], output)

	case "inspect-runtime-closure":
		if len(args) != 3 {
			return 1, errors.New("usage: phantowd-lab inspect-runtime-closure DIRECTORY IMAGE-RELATIVE-ELF")
		}
		inventory, err := rootfsinventory.Inspect(args[1])
		if err != nil {
			return 1, err
		}
		closure, err := inventory.RuntimeClosure(args[2])
		if err != nil {
			return 1, err
		}
		if err := writeJSON(output, closure); err != nil {
			return 1, err
		}
		if !closure.StaticDependenciesResolved {
			return 2, nil
		}
		return 0, nil

	case "scan-storage-refs":
		if len(args) != 2 {
			return 1, errors.New("usage: phantowd-lab scan-storage-refs EXTRACTED-ROOT")
		}
		report, err := storagerefs.Inspect(args[1])
		if err != nil {
			return 1, err
		}
		return 0, writeJSON(output, report)

	case "inspect-storage-inventory":
		if len(args) != 2 {
			return 1, errors.New("usage: phantowd-lab inspect-storage-inventory FILE")
		}
		file, _, err := openRegular(args[1])
		if err != nil {
			return 1, err
		}
		defer file.Close()
		report, err := storageinventory.Inspect(file)
		if err != nil {
			return 1, err
		}
		if err := writeJSON(output, report); err != nil {
			return 1, err
		}
		if !report.Valid {
			return 2, nil
		}
		return 0, nil

	case "inspect-gpt-image":
		if len(args) != 2 {
			return 1, errors.New("usage: phantowd-lab inspect-gpt-image FILE")
		}
		file, size, err := openRegular(args[1])
		if err != nil {
			return 1, err
		}
		defer file.Close()
		report, err := diskimage.Inspect(file, size)
		if err != nil {
			return 1, err
		}
		if err := writeJSON(output, report); err != nil {
			return 1, err
		}
		if report.Status != diskimage.StatusValid {
			return 2, nil
		}
		return 0, nil

	case "inspect-storage-image":
		return inspectStorageImage(args[1:], output)

	case "inspect-storage-image-set":
		return inspectStorageImageSet(args[1:], output)

	case "inspect-md-v1.2-image-set":
		return inspectMDV12ImageSet(args[1:], output)

	case "inspect-md-v0.90-image-set":
		return inspectMDV090ImageSet(args[1:], output)

	case "inspect-ext-partition":
		return inspectExtPartition(args[1:], output)

	case "inspect-md-v1.2-partition":
		return inspectMDV12Partition(args[1:], output)

	case "inspect-md-v1.0-partition":
		return inspectMDV10Partition(args[1:], output)

	case "inspect-md-v1.0-component":
		return inspectMDV10Component(args[1:], output)

	case "inspect-md-v1.0-component-set":
		return inspectMDV10ComponentSet(args[1:], output)

	case "inspect-md-v0.90-component":
		if len(args) != 2 {
			return 1, errors.New("usage: phantowd-lab inspect-md-v0.90-component COMPONENT-IMAGE-FILE")
		}
		file, size, err := openRegular(args[1])
		if err != nil {
			return 1, err
		}
		defer file.Close()
		report, err := diskimage.InspectMDV090Component(file, size)
		if err != nil {
			return 1, err
		}
		if err := writeJSON(output, report); err != nil {
			return 1, err
		}
		if report.Status != diskimage.MDV090StatusCandidate {
			return 2, nil
		}
		return 0, nil

	case "inspect-md-v0.90-partition":
		return inspectMDV090Partition(args[1:], output)

	case "plan-storage-inventory":
		if len(args) != 2 {
			return 1, errors.New("usage: phantowd-lab plan-storage-inventory FILE")
		}
		file, _, err := openRegular(args[1])
		if err != nil {
			return 1, err
		}
		defer file.Close()
		assessment, err := storageinventory.Assess(file)
		if err != nil {
			return 1, err
		}
		if err := writeJSON(output, assessment); err != nil {
			return 1, err
		}
		return assessment.ExitCode(), nil

	case "decode-mcu":
		if len(args) < 2 {
			return 1, errors.New("usage: phantowd-lab decode-mcu HEX-BYTES")
		}
		data, err := parseHex(strings.Join(args[1:], " "))
		if err != nil {
			return 1, err
		}
		frame, err := mcuproto.DecodeReceive(data)
		if err != nil {
			return 1, err
		}
		return 0, writeJSON(output, frame)

	case "catalog-mcu":
		if len(args) != 1 {
			return 1, errors.New("usage: phantowd-lab catalog-mcu")
		}
		return 0, writeJSON(output, struct {
			Transmit []mcuproto.Selector `json:"transmit"`
			Receive  []mcuproto.Selector `json:"receive"`
		}{mcuproto.TransmitSelectors, mcuproto.ReceiveSelectors})

	case "replay-mcu":
		return replayMCU(args[1:], output)

	default:
		return 1, fmt.Errorf("unknown command %q", args[0])
	}
}

func inspectGitHubRelease(args []string, output io.Writer) (int, error) {
	flags := flag.NewFlagSet("inspect-github-release", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	tag := flags.String("tag", "", "exact versioned GitHub release tag")
	publicKeyPath := flags.String("public-key", "", "trusted raw Ed25519 public key (32 bytes)")
	modelID := flags.String("model", "", "exact requested model identifier")
	revision := flags.String("revision", "", "exact requested hardware revision")
	channel := flags.String("channel", "", "expected channel: stable, beta, or nightly")
	currentVersion := flags.String("current-version", "", "installed vMAJOR.MINOR.PATCH for optional monotonic-upgrade assessment")
	installerVersion := flags.String("installer-version", "", "caller-supplied installer version for optional signed-minimum preflight")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *tag == "" || *publicKeyPath == "" || *modelID == "" || *revision == "" || *channel == "" {
		return 1, errors.New("usage: phantowd-lab inspect-github-release --tag VERSION --public-key FILE --model ID --revision ID --channel stable|beta|nightly [--current-version VERSION] [--installer-version VERSION]")
	}
	keyFile, keySize, err := openRegular(*publicKeyPath)
	if err != nil {
		return 1, err
	}
	defer keyFile.Close()
	if keySize != 32 {
		return 1, errors.New("trusted Ed25519 public key must be exactly 32 bytes")
	}
	publicKey, err := io.ReadAll(io.LimitReader(keyFile, 33))
	if err != nil || len(publicKey) != 32 {
		return 1, errors.New("cannot read trusted Ed25519 public key")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	result, err := githubrelease.Inspect(ctx, githubrelease.Options{
		APIBase: githubrelease.DefaultAPIBase, Owner: githubrelease.ProjectOwner,
		Repository: githubrelease.ProjectRepository, Tag: *tag, PublicKey: publicKey,
		ModelID: *modelID, Revision: *revision, Channel: *channel, InstallerVersion: *installerVersion,
	})
	if err != nil {
		return 1, err
	}
	if *currentVersion != "" {
		result.Verification = releaseverify.AssessUpgradeVersion(result.Verification, *currentVersion)
	}
	if err := writeJSON(output, result); err != nil {
		return 1, err
	}
	if !result.Verification.Valid {
		return 2, nil
	}
	return 0, nil
}

func inspectRelease(args []string, output io.Writer) (int, error) {
	flags := flag.NewFlagSet("inspect-release", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	manifestPath := flags.String("manifest", "", "signed manifest JSON file")
	signaturePath := flags.String("signature", "", "detached raw Ed25519 signature file")
	publicKeyPath := flags.String("public-key", "", "trusted raw Ed25519 public key (32 bytes)")
	artifactDir := flags.String("artifacts", "", "directory containing the named release payloads")
	modelID := flags.String("model", "", "exact requested model identifier")
	revision := flags.String("revision", "", "exact requested hardware revision")
	channel := flags.String("channel", "", "expected release channel: stable, beta, or nightly")
	currentVersion := flags.String("current-version", "", "installed vMAJOR.MINOR.PATCH for optional monotonic-upgrade assessment")
	installerVersion := flags.String("installer-version", "", "caller-supplied installer version for optional signed-minimum preflight")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *manifestPath == "" || *signaturePath == "" || *publicKeyPath == "" || *artifactDir == "" || *modelID == "" || *revision == "" || *channel == "" {
		return 1, errors.New("usage: phantowd-lab inspect-release --manifest FILE --signature FILE --public-key FILE --artifacts DIR --model ID --revision ID --channel stable|beta|nightly [--current-version VERSION] [--installer-version VERSION]")
	}
	manifest, _, err := openRegular(*manifestPath)
	if err != nil {
		return 1, err
	}
	defer manifest.Close()
	signature, signatureSize, err := openRegular(*signaturePath)
	if err != nil {
		return 1, err
	}
	defer signature.Close()
	if signatureSize != 64 {
		return 1, errors.New("detached Ed25519 signature must be exactly 64 bytes")
	}
	publicKeyFile, publicKeySize, err := openRegular(*publicKeyPath)
	if err != nil {
		return 1, err
	}
	defer publicKeyFile.Close()
	if publicKeySize != 32 {
		return 1, errors.New("trusted Ed25519 public key must be exactly 32 bytes")
	}
	publicKey, err := io.ReadAll(io.LimitReader(publicKeyFile, 33))
	if err != nil || len(publicKey) != 32 {
		return 1, errors.New("cannot read trusted Ed25519 public key")
	}
	report, err := releaseverify.InspectWithInstallerVersion(manifest, signature, publicKey, *artifactDir, *modelID, *revision, *channel, *installerVersion)
	if err != nil {
		return 1, err
	}
	if *currentVersion != "" {
		report = releaseverify.AssessUpgradeVersion(report, *currentVersion)
	}
	if err := writeJSON(output, report); err != nil {
		return 1, err
	}
	if !report.Valid {
		return 2, nil
	}
	return 0, nil
}

type extImageReport struct {
	Format          string               `json:"format"`
	SchemaVersion   int                  `json:"schema_version"`
	Status          diskimage.ExtStatus  `json:"status"`
	PartitionNumber int                  `json:"partition_number"`
	WDCompatibility string               `json:"wd_compatibility"`
	GPT             diskimage.Report     `json:"gpt"`
	Filesystem      *diskimage.ExtReport `json:"filesystem,omitempty"`
	Findings        []string             `json:"findings"`
	Limitations     []string             `json:"limitations"`
}

func inspectExtPartition(args []string, output io.Writer) (int, error) {
	if len(args) != 2 {
		return 1, errors.New("usage: phantowd-lab inspect-ext-partition IMAGE-FILE GPT-PARTITION-NUMBER")
	}
	partitionNumber, err := strconv.ParseUint(args[1], 10, 32)
	if err != nil || partitionNumber == 0 || partitionNumber > 128 {
		return 1, errors.New("GPT partition number must be between 1 and 128")
	}
	file, size, err := openRegular(args[0])
	if err != nil {
		return 1, err
	}
	defer file.Close()
	gpt, err := diskimage.Inspect(file, size)
	if err != nil {
		return 1, err
	}
	result := extImageReport{
		Format:          "phantowd-ext-gpt-partition-inspection",
		SchemaVersion:   1,
		Status:          diskimage.ExtStatusUnsupported,
		PartitionNumber: int(partitionNumber),
		WDCompatibility: "unqualified",
		GPT:             gpt,
		Findings:        []string{},
		Limitations: []string{
			"only a generic GPT and one ext-family superblock are inspected; no other filesystem, RAID metadata, WD XML, health, or data is read",
			"a structurally plausible superblock is not proof of filesystem integrity, WD compatibility, or safe mounting",
			"the supplied regular file is never mounted, modified, or treated as a block device",
		},
	}
	if gpt.Status != diskimage.StatusValid {
		if gpt.Status == diskimage.StatusDamaged {
			result.Status = diskimage.ExtStatusDamaged
		}
		result.Findings = []string{"GPT metadata must be valid before a partition superblock can be selected"}
		if err := writeJSON(output, result); err != nil {
			return 1, err
		}
		return 2, nil
	}
	var selected *diskimage.Partition
	for index := range gpt.Partitions {
		if gpt.Partitions[index].Number == int(partitionNumber) {
			selected = &gpt.Partitions[index]
			break
		}
	}
	if selected == nil {
		result.Findings = []string{"requested GPT partition number is not present"}
		if err := writeJSON(output, result); err != nil {
			return 1, err
		}
		return 2, nil
	}
	filesystem, err := diskimage.InspectExtSuperblock(file, size, selected.FirstLBA, selected.LastLBA)
	if err != nil {
		return 1, err
	}
	result.Filesystem = &filesystem
	result.Status = filesystem.Status
	result.Findings = filesystem.Findings
	if err := writeJSON(output, result); err != nil {
		return 1, err
	}
	if result.Status != diskimage.ExtStatusCandidate {
		return 2, nil
	}
	return 0, nil
}

type mdV12ImageReport struct {
	Format          string                 `json:"format"`
	SchemaVersion   int                    `json:"schema_version"`
	Status          diskimage.MDStatus     `json:"status"`
	PartitionNumber int                    `json:"partition_number"`
	WDCompatibility string                 `json:"wd_compatibility"`
	GPT             diskimage.Report       `json:"gpt"`
	MD              *diskimage.MDV12Report `json:"md_superblock,omitempty"`
	Findings        []string               `json:"findings"`
	Limitations     []string               `json:"limitations"`
}

func inspectMDV12Partition(args []string, output io.Writer) (int, error) {
	if len(args) != 2 {
		return 1, errors.New("usage: phantowd-lab inspect-md-v1.2-partition IMAGE-FILE GPT-PARTITION-NUMBER")
	}
	partitionNumber, err := strconv.ParseUint(args[1], 10, 32)
	if err != nil || partitionNumber == 0 || partitionNumber > 128 {
		return 1, errors.New("GPT partition number must be between 1 and 128")
	}
	file, size, err := openRegular(args[0])
	if err != nil {
		return 1, err
	}
	defer file.Close()
	gpt, err := diskimage.Inspect(file, size)
	if err != nil {
		return 1, err
	}
	result := mdV12ImageReport{
		Format:          "phantowd-md-v1.2-gpt-partition-inspection",
		SchemaVersion:   1,
		Status:          diskimage.MDStatusUnsupported,
		PartitionNumber: int(partitionNumber),
		WDCompatibility: "unqualified",
		GPT:             gpt,
		Findings:        []string{},
		Limitations: []string{
			"only one generic Linux MD v1.2 component superblock is inspected after generic GPT validation; other MD layouts, WD metadata, filesystem metadata, health and file data are not read",
			"one plausible member does not prove array-wide consistency, a supported WD layout, filesystem integrity, or safe assembly",
			"the supplied regular file is never mounted, modified, or treated as a block device",
		},
	}
	if gpt.Status != diskimage.StatusValid {
		if gpt.Status == diskimage.StatusDamaged {
			result.Status = diskimage.MDStatusDamaged
		}
		result.Findings = []string{"GPT metadata must be valid before a partition superblock can be selected"}
		if err := writeJSON(output, result); err != nil {
			return 1, err
		}
		return 2, nil
	}
	var selected *diskimage.Partition
	for index := range gpt.Partitions {
		if gpt.Partitions[index].Number == int(partitionNumber) {
			selected = &gpt.Partitions[index]
			break
		}
	}
	if selected == nil {
		result.Findings = []string{"requested GPT partition number is not present"}
		if err := writeJSON(output, result); err != nil {
			return 1, err
		}
		return 2, nil
	}
	metadata, err := diskimage.InspectMDV12Superblock(file, size, selected.FirstLBA, selected.LastLBA)
	if err != nil {
		return 1, err
	}
	result.MD = &metadata
	result.Status = metadata.Status
	result.Findings = metadata.Findings
	if err := writeJSON(output, result); err != nil {
		return 1, err
	}
	if result.Status != diskimage.MDStatusCandidate {
		return 2, nil
	}
	return 0, nil
}

type mdV10ImageReport struct {
	Format          string                 `json:"format"`
	SchemaVersion   int                    `json:"schema_version"`
	Status          diskimage.MDV10Status  `json:"status"`
	PartitionNumber int                    `json:"partition_number"`
	WDCompatibility string                 `json:"wd_compatibility"`
	GPT             diskimage.Report       `json:"gpt"`
	MD              *diskimage.MDV10Report `json:"md_superblock,omitempty"`
	Findings        []string               `json:"findings"`
	Limitations     []string               `json:"limitations"`
}

func inspectMDV10Partition(args []string, output io.Writer) (int, error) {
	if len(args) != 2 {
		return 1, errors.New("usage: phantowd-lab inspect-md-v1.0-partition IMAGE-FILE GPT-PARTITION-NUMBER")
	}
	partitionNumber, err := strconv.ParseUint(args[1], 10, 32)
	if err != nil || partitionNumber == 0 || partitionNumber > 128 {
		return 1, errors.New("GPT partition number must be between 1 and 128")
	}
	file, size, err := openRegular(args[0])
	if err != nil {
		return 1, err
	}
	defer file.Close()
	gpt, err := diskimage.Inspect(file, size)
	if err != nil {
		return 1, err
	}
	result := mdV10ImageReport{
		Format:          "phantowd-md-v1.0-gpt-partition-inspection",
		SchemaVersion:   1,
		Status:          diskimage.MDV10StatusUnsupported,
		PartitionNumber: int(partitionNumber),
		WDCompatibility: "unqualified",
		GPT:             gpt,
		Findings:        []string{},
		Limitations: []string{
			"only one generic Linux MD v1.0 component superblock at the end-of-component location is inspected after generic GPT validation; other MD layouts, WD metadata, filesystem metadata, health and file data are not read",
			"one plausible member does not prove array-wide consistency, a supported WD layout, filesystem integrity, or safe assembly",
			"the supplied regular file is never mounted, modified, or treated as a block device",
		},
	}
	if gpt.Status != diskimage.StatusValid {
		if gpt.Status == diskimage.StatusDamaged {
			result.Status = diskimage.MDV10StatusDamaged
		}
		result.Findings = []string{"GPT metadata must be valid before a partition superblock can be selected"}
		if err := writeJSON(output, result); err != nil {
			return 1, err
		}
		return 2, nil
	}
	var selected *diskimage.Partition
	for index := range gpt.Partitions {
		if gpt.Partitions[index].Number == int(partitionNumber) {
			selected = &gpt.Partitions[index]
			break
		}
	}
	if selected == nil {
		result.Findings = []string{"requested GPT partition number is not present"}
		if err := writeJSON(output, result); err != nil {
			return 1, err
		}
		return 2, nil
	}
	metadata, err := diskimage.InspectMDV10Superblock(file, size, selected.FirstLBA, selected.LastLBA)
	if err != nil {
		return 1, err
	}
	result.MD = &metadata
	result.Status = metadata.Status
	result.Findings = metadata.Findings
	if err := writeJSON(output, result); err != nil {
		return 1, err
	}
	if result.Status != diskimage.MDV10StatusCandidate {
		return 2, nil
	}
	return 0, nil
}

func inspectMDV10Component(args []string, output io.Writer) (int, error) {
	if len(args) != 1 {
		return 1, errors.New("usage: phantowd-lab inspect-md-v1.0-component COMPONENT-IMAGE-FILE")
	}
	file, size, err := openRegular(args[0])
	if err != nil {
		return 1, err
	}
	defer file.Close()
	lastLBA := uint64(0)
	if size >= 512 {
		lastLBA = uint64(size/512) - 1
	}
	report, err := diskimage.InspectMDV10Superblock(file, size, 0, lastLBA)
	if err != nil {
		return 1, err
	}
	if err := writeJSON(output, report); err != nil {
		return 1, err
	}
	if report.Status != diskimage.MDV10StatusCandidate {
		return 2, nil
	}
	return 0, nil
}

type mdV10ComponentSetInput struct {
	InputIndex int                   `json:"input_index"`
	Status     diskimage.MDV10Status `json:"status"`
	Report     diskimage.MDV10Report `json:"report"`
}

type mdV10ComponentSetInspection struct {
	Format             string                        `json:"format"`
	SchemaVersion      int                           `json:"schema_version"`
	Status             string                        `json:"status"`
	WDCompatibility    string                        `json:"wd_compatibility"`
	Components         []mdV10ComponentSetInput      `json:"components"`
	Comparison         diskimage.MDV10ImageSetReport `json:"comparison"`
	BlockDeviceOpened  bool                          `json:"block_device_opened"`
	MutationsPerformed bool                          `json:"mutations_performed"`
	AssemblyPerformed  bool                          `json:"assembly_performed"`
	MountPerformed     bool                          `json:"mount_performed"`
	Findings           []string                      `json:"findings"`
	Limitations        []string                      `json:"limitations"`
}

func inspectMDV10ComponentSet(args []string, output io.Writer) (int, error) {
	if len(args) < 2 || len(args) > maxStorageImageSetInputs {
		return 1, errors.New("usage: phantowd-lab inspect-md-v1.0-component-set COMPONENT-IMAGE-1 COMPONENT-IMAGE-2 [COMPONENT-IMAGE-3 [COMPONENT-IMAGE-4]]")
	}
	result := mdV10ComponentSetInspection{
		Format: "phantowd-md-v1.0-component-set-inspection", SchemaVersion: 1,
		Status: "review-required", WDCompatibility: "unqualified",
		Components: []mdV10ComponentSetInput{}, Findings: []string{},
		Limitations: []string{
			"each input is a caller-selected regular file containing one generic MD v1.0 component; GPT, WD XML, other metadata versions, filesystems, disk health, and user data are not inspected",
			"metadata-consistent means only that checksummed components agree on selected fields and cover active RAID roles; it does not establish synchronization, health, WD compatibility, import safety, or recovery",
			"no block device is opened, no array is assembled, no filesystem is mounted, and no input image is modified",
		},
	}
	components := make([]diskimage.MDV10ImageComponent, 0, len(args))
	for index, path := range args {
		file, size, err := openRegular(path)
		if err != nil {
			return 1, err
		}
		lastLBA := uint64(0)
		if size >= 512 {
			lastLBA = uint64(size/512) - 1
		}
		component, inspectErr := diskimage.InspectMDV10Superblock(file, size, 0, lastLBA)
		closeErr := file.Close()
		if inspectErr != nil {
			return 1, inspectErr
		}
		if closeErr != nil {
			return 1, errors.New("could not close component image")
		}
		inputIndex := index + 1
		result.Components = append(result.Components, mdV10ComponentSetInput{
			InputIndex: inputIndex, Status: component.Status, Report: component,
		})
		components = append(components, diskimage.MDV10ImageComponent{
			InputIndex: inputIndex, PartitionNumber: 0, Report: component,
		})
	}
	comparison, err := diskimage.CompareMDV10ImageSet(components)
	if err != nil {
		return 1, err
	}
	result.Comparison = comparison
	switch {
	case comparison.UnqualifiedComponents != 0:
		result.Findings = append(result.Findings, "one or more supplied component images are damaged, unsupported, or not a valid MD v1.0 candidate")
	case comparison.UnidentifiedCandidateComponents != 0:
		result.Findings = append(result.Findings, "one or more component candidates lack a usable array identity")
	case len(comparison.Arrays) != 1:
		result.Findings = append(result.Findings, "the supplied components do not identify exactly one MD array")
	case comparison.Arrays[0].Status != diskimage.MDV10ArrayMetadataConsistent:
		result.Findings = append(result.Findings, "the supplied components are incomplete, conflicting, divergent, ambiguous, or require feature review")
	default:
		result.Status = string(diskimage.MDV10ArrayMetadataConsistent)
		result.Findings = append(result.Findings, "the supplied generic MD v1.0 components agree on selected metadata and cover active roles; WD compatibility and data synchronization remain unqualified")
	}
	if err := writeJSON(output, result); err != nil {
		return 1, err
	}
	if result.Status != string(diskimage.MDV10ArrayMetadataConsistent) {
		return 2, nil
	}
	return 0, nil
}

type mdV090ImageReport struct {
	Format          string                  `json:"format"`
	SchemaVersion   int                     `json:"schema_version"`
	Status          diskimage.MDV090Status  `json:"status"`
	PartitionNumber int                     `json:"partition_number"`
	WDCompatibility string                  `json:"wd_compatibility"`
	GPT             diskimage.Report        `json:"gpt"`
	MD              *diskimage.MDV090Report `json:"md_superblock,omitempty"`
	Findings        []string                `json:"findings"`
	Limitations     []string                `json:"limitations"`
}

func inspectMDV090Partition(args []string, output io.Writer) (int, error) {
	if len(args) != 2 {
		return 1, errors.New("usage: phantowd-lab inspect-md-v0.90-partition DISK-IMAGE-FILE GPT-PARTITION-NUMBER")
	}
	partitionNumber, err := strconv.ParseUint(args[1], 10, 32)
	if err != nil || partitionNumber == 0 || partitionNumber > 128 {
		return 1, errors.New("GPT partition number must be between 1 and 128")
	}
	file, size, err := openRegular(args[0])
	if err != nil {
		return 1, err
	}
	defer file.Close()
	gpt, err := diskimage.Inspect(file, size)
	if err != nil {
		return 1, err
	}
	result := mdV090ImageReport{
		Format:          "phantowd-md-v0.90-gpt-partition-inspection",
		SchemaVersion:   1,
		Status:          diskimage.MDV090StatusUnsupported,
		PartitionNumber: int(partitionNumber),
		WDCompatibility: "unqualified",
		GPT:             gpt,
		Findings:        []string{},
		Limitations: []string{
			"only one generic GPT partition and one little-endian MD 0.90 component superblock are inspected; GPT type, ext/filesystem metadata, WD XML, all other partitions and other members are not combined or reconciled",
			"one plausible component does not establish array-wide consistency, filesystem integrity, WD compatibility, or safe assembly",
			"the supplied regular file is never mounted, modified, or treated as a block device",
		},
	}
	if gpt.Status != diskimage.StatusValid {
		if gpt.Status == diskimage.StatusDamaged {
			result.Status = diskimage.MDV090StatusDamaged
		}
		result.Findings = []string{"GPT metadata must be valid before an MD 0.90 component partition can be selected"}
		if err := writeJSON(output, result); err != nil {
			return 1, err
		}
		return 2, nil
	}
	var selected *diskimage.Partition
	for index := range gpt.Partitions {
		if gpt.Partitions[index].Number == int(partitionNumber) {
			selected = &gpt.Partitions[index]
			break
		}
	}
	if selected == nil {
		result.Findings = []string{"requested GPT partition number is not present"}
		if err := writeJSON(output, result); err != nil {
			return 1, err
		}
		return 2, nil
	}
	partitionSectors := selected.LastLBA - selected.FirstLBA + 1
	partitionBytes := partitionSectors * 512
	component := io.NewSectionReader(file, int64(selected.FirstLBA*512), int64(partitionBytes))
	metadata, err := diskimage.InspectMDV090Component(component, int64(partitionBytes))
	if err != nil {
		return 1, err
	}
	result.MD = &metadata
	result.Status = metadata.Status
	result.Findings = metadata.Findings
	if err := writeJSON(output, result); err != nil {
		return 1, err
	}
	if result.Status != diskimage.MDV090StatusCandidate {
		return 2, nil
	}
	return 0, nil
}

type storagePartitionObservation struct {
	Number   int                    `json:"partition_number"`
	FirstLBA uint64                 `json:"first_lba"`
	LastLBA  uint64                 `json:"last_lba"`
	Ext      diskimage.ExtReport    `json:"ext_superblock"`
	MDV12    diskimage.MDV12Report  `json:"md_v1_2_superblock"`
	MDV10    diskimage.MDV10Report  `json:"md_v1_0_superblock"`
	MDV090   diskimage.MDV090Report `json:"md_v0_90_superblock"`
}

type storageImageReport struct {
	Format             string                        `json:"format"`
	SchemaVersion      int                           `json:"schema_version"`
	WDCompatibility    string                        `json:"wd_compatibility"`
	GPTStatus          diskimage.Status              `json:"gpt_status"`
	GPT                diskimage.Report              `json:"gpt"`
	Partitions         []storagePartitionObservation `json:"partition_observations"`
	BlockDeviceOpened  bool                          `json:"block_device_opened"`
	MutationsPerformed bool                          `json:"mutations_performed"`
	AssemblyPerformed  bool                          `json:"assembly_performed"`
	MountPerformed     bool                          `json:"mount_performed"`
	Limitations        []string                      `json:"limitations"`
}

func inspectStorageImage(args []string, output io.Writer) (int, error) {
	if len(args) != 1 {
		return 1, errors.New("usage: phantowd-lab inspect-storage-image DISK-IMAGE-FILE")
	}
	file, size, err := openRegular(args[0])
	if err != nil {
		return 1, err
	}
	defer file.Close()
	result, err := observeStorageImage(file, size)
	if err != nil {
		return 1, err
	}
	if err := writeJSON(output, result); err != nil {
		return 1, err
	}
	if result.GPTStatus != diskimage.StatusValid {
		return 2, nil
	}
	return 0, nil
}

func observeStorageImage(file *os.File, size int64) (storageImageReport, error) {
	gpt, err := diskimage.Inspect(file, size)
	if err != nil {
		return storageImageReport{}, err
	}
	result := storageImageReport{
		Format:          "phantowd-read-only-storage-image-observation",
		SchemaVersion:   2,
		WDCompatibility: "unqualified",
		GPTStatus:       gpt.Status,
		GPT:             gpt,
		Partitions:      []storagePartitionObservation{},
		Limitations: []string{
			"reports only generic GPT plus bounded ext and Linux MD v1.2, v1.0, and little-endian v0.90 superblock observations for each partition; it does not detect other filesystems, MD versions, WD XML, health, or file data",
			"observations are independent and are not reconciled into an array or volume; a plausible superblock does not establish WD compatibility, filesystem integrity, or safe assembly/mounting",
			"the supplied regular file is never mounted, modified, or treated as a block device",
		},
	}
	if gpt.Status != diskimage.StatusValid {
		return result, nil
	}
	for _, partition := range gpt.Partitions {
		extReport, err := diskimage.InspectExtSuperblock(file, size, partition.FirstLBA, partition.LastLBA)
		if err != nil {
			return storageImageReport{}, err
		}
		mdV12Report, err := diskimage.InspectMDV12Superblock(file, size, partition.FirstLBA, partition.LastLBA)
		if err != nil {
			return storageImageReport{}, err
		}
		mdV10Report, err := diskimage.InspectMDV10Superblock(file, size, partition.FirstLBA, partition.LastLBA)
		if err != nil {
			return storageImageReport{}, err
		}
		partitionSectors := partition.LastLBA - partition.FirstLBA + 1
		partitionBytes := partitionSectors * 512
		component := io.NewSectionReader(file, int64(partition.FirstLBA*512), int64(partitionBytes))
		mdV090Report, err := diskimage.InspectMDV090Component(component, int64(partitionBytes))
		if err != nil {
			return storageImageReport{}, err
		}
		result.Partitions = append(result.Partitions, storagePartitionObservation{
			Number: partition.Number, FirstLBA: partition.FirstLBA, LastLBA: partition.LastLBA,
			Ext: extReport, MDV12: mdV12Report, MDV10: mdV10Report, MDV090: mdV090Report,
		})
	}
	return result, nil
}

type storageImageSetPartitionSummary struct {
	Number                int                    `json:"partition_number"`
	DeclaredTypeGUID      string                 `json:"declared_type_guid"`
	ExtStatus             diskimage.ExtStatus    `json:"ext_status"`
	ExtCleanUnmount       bool                   `json:"ext_clean_unmount_flag"`
	ExtNeedsJournalRepair bool                   `json:"ext_needs_journal_recovery"`
	MDV12Status           diskimage.MDStatus     `json:"md_v1_2_status"`
	MDV10Status           diskimage.MDV10Status  `json:"md_v1_0_status"`
	MDV090Status          diskimage.MDV090Status `json:"md_v0_90_status"`
}

type storageImageSetInputSummary struct {
	InputIndex            int                               `json:"input_index"`
	GPTStatus             diskimage.Status                  `json:"gpt_status"`
	PartitionCount        int                               `json:"partition_count"`
	MDV12CandidateCount   int                               `json:"md_v1_2_candidate_count"`
	MDV10CandidateCount   int                               `json:"md_v1_0_candidate_count"`
	MDV090CandidateCount  int                               `json:"md_v0_90_candidate_count"`
	PartitionObservations []storageImageSetPartitionSummary `json:"partition_observations"`
}

type storageImageSetIdentityScan struct {
	Complete                      bool `json:"complete"`
	DuplicateDiskGUIDGroups       int  `json:"duplicate_disk_guid_groups"`
	DuplicatePARTUUIDGroups       int  `json:"duplicate_partuuid_groups"`
	DuplicateFilesystemUUIDGroups int  `json:"duplicate_filesystem_uuid_groups"`
}

type storageImageSetAssessment struct {
	Format              string                          `json:"format"`
	SchemaVersion       int                             `json:"schema_version"`
	Status              string                          `json:"status"`
	WDCompatibility     string                          `json:"wd_compatibility"`
	MigrationAuthorized bool                            `json:"migration_authorized"`
	Inputs              []storageImageSetInputSummary   `json:"inputs"`
	IdentityScan        *storageImageSetIdentityScan    `json:"identity_scan,omitempty"`
	MDV12Comparison     *diskimage.MDV12ImageSetReport  `json:"md_v1_2_comparison,omitempty"`
	MDV10Comparison     *diskimage.MDV10ImageSetReport  `json:"md_v1_0_comparison,omitempty"`
	MDV090Comparison    *diskimage.MDV090ImageSetReport `json:"md_v0_90_comparison,omitempty"`
	BlockDeviceOpened   bool                            `json:"block_device_opened"`
	MutationsPerformed  bool                            `json:"mutations_performed"`
	AssemblyPerformed   bool                            `json:"assembly_performed"`
	MountPerformed      bool                            `json:"mount_performed"`
	Findings            []string                        `json:"findings"`
	Limitations         []string                        `json:"limitations"`
}

func inspectStorageImageSet(args []string, output io.Writer) (int, error) {
	if len(args) < 1 || len(args) > maxStorageImageSetInputs {
		return 1, errors.New("usage: phantowd-lab inspect-storage-image-set DISK-IMAGE-1 [DISK-IMAGE-2 [DISK-IMAGE-3 [DISK-IMAGE-4]]]")
	}
	result := storageImageSetAssessment{
		Format:          "phantowd-read-only-storage-image-set-observation",
		SchemaVersion:   2,
		Status:          "incomplete",
		WDCompatibility: "unqualified",
		Inputs:          []storageImageSetInputSummary{},
		Findings:        []string{},
		Limitations: []string{
			"only caller-supplied regular whole-disk images with generic GPT, ext-family, MD v1.2, MD v1.0, and little-endian MD 0.90 metadata are inspected; other formats and WD XML are not interpreted",
			"the supplied image set is not proof of the complete four-bay inventory; missing or unprovided devices cannot be inferred absent",
			"duplicate identity counts apply only to the supplied GPT-valid images; generic metadata agreement is not a WD layout, health, synchronization, filesystem-integrity or migration qualification",
			"partition type GUIDs are on-disk declarations, not proof of contents, role or compatibility; ext results inspect only one bounded superblock, not file data or full filesystem integrity",
			"the tool does not lock or snapshot source files; callers must supply stable offline copies and avoid concurrent modification during inspection",
			"all inputs are regular files; no block device is opened, no array is assembled, no filesystem is mounted, and no input is modified",
		},
	}
	result.Findings = append(result.Findings, "WD compatibility and migration remain unqualified; this report is metadata evidence only")

	diskFingerprints := make([]string, 0, len(args))
	partitionFingerprints := make([]string, 0)
	extFingerprints := make([]string, 0)
	mdV12Components := make([]diskimage.MDV12ImageComponent, 0)
	mdV10Components := make([]diskimage.MDV10ImageComponent, 0)
	mdV090Components := make([]diskimage.MDV090ImageComponent, 0)
	allGPTValid := true
	gptDamaged := false
	gptUnsupported := false
	needsReview := false
	extFilesystemNeedsReview := false
	layerConflict := false

	for inputIndex, path := range args {
		file, size, err := openRegular(path)
		if err != nil {
			return 1, err
		}
		observed, observeErr := observeStorageImage(file, size)
		closeErr := file.Close()
		if observeErr != nil {
			return 1, observeErr
		}
		if closeErr != nil {
			return 1, closeErr
		}
		input := storageImageSetInputSummary{
			InputIndex: inputIndex + 1, GPTStatus: observed.GPTStatus,
			PartitionObservations: []storageImageSetPartitionSummary{},
		}
		if observed.GPTStatus != diskimage.StatusValid {
			allGPTValid = false
			gptDamaged = gptDamaged || observed.GPTStatus == diskimage.StatusDamaged
			gptUnsupported = gptUnsupported || observed.GPTStatus == diskimage.StatusUnsupported
			result.Inputs = append(result.Inputs, input)
			continue
		}
		diskFingerprints = append(diskFingerprints, observed.GPT.DiskIdentityFingerprint)
		input.PartitionCount = len(observed.Partitions)
		for _, partition := range observed.Partitions {
			candidateStorageLayers := 0
			partitionSummary := storageImageSetPartitionSummary{
				Number: partition.Number, ExtStatus: partition.Ext.Status,
				ExtCleanUnmount:       partition.Ext.CleanUnmount,
				ExtNeedsJournalRepair: partition.Ext.NeedsJournalRecovery,
				MDV12Status:           partition.MDV12.Status, MDV10Status: partition.MDV10.Status,
				MDV090Status: partition.MDV090.Status,
			}
			for _, gptPartition := range observed.GPT.Partitions {
				if gptPartition.Number == partition.Number {
					partitionSummary.DeclaredTypeGUID = gptPartition.TypeGUID
					partitionFingerprints = append(partitionFingerprints, gptPartition.IdentityFingerprint)
					break
				}
			}
			input.PartitionObservations = append(input.PartitionObservations, partitionSummary)

			if partition.Ext.Status == diskimage.ExtStatusCandidate {
				candidateStorageLayers++
				if partition.Ext.FilesystemIdentityFingerprint == "" {
					needsReview = true
				} else {
					extFingerprints = append(extFingerprints, partition.Ext.FilesystemIdentityFingerprint)
				}
				if !partition.Ext.CleanUnmount || partition.Ext.NeedsJournalRecovery || partition.Ext.FilesystemState == "errors-recorded" {
					needsReview = true
					extFilesystemNeedsReview = true
				}
			} else if partition.Ext.Status == diskimage.ExtStatusDamaged || partition.Ext.Status == diskimage.ExtStatusUnsupported {
				needsReview = true
			}
			if partition.MDV12.Status == diskimage.MDStatusCandidate {
				candidateStorageLayers++
				input.MDV12CandidateCount++
				mdV12Components = append(mdV12Components, diskimage.MDV12ImageComponent{
					InputIndex: inputIndex + 1, PartitionNumber: partition.Number, Report: partition.MDV12,
				})
			} else if partition.MDV12.Status == diskimage.MDStatusDamaged || partition.MDV12.Status == diskimage.MDStatusUnsupported {
				needsReview = true
			}
			if partition.MDV10.Status == diskimage.MDV10StatusCandidate {
				candidateStorageLayers++
				input.MDV10CandidateCount++
				mdV10Components = append(mdV10Components, diskimage.MDV10ImageComponent{
					InputIndex: inputIndex + 1, PartitionNumber: partition.Number, Report: partition.MDV10,
				})
			} else if partition.MDV10.Status == diskimage.MDV10StatusDamaged || partition.MDV10.Status == diskimage.MDV10StatusUnsupported {
				needsReview = true
			}
			if partition.MDV090.Status == diskimage.MDV090StatusCandidate {
				candidateStorageLayers++
				input.MDV090CandidateCount++
				mdV090Components = append(mdV090Components, diskimage.MDV090ImageComponent{
					InputIndex: inputIndex + 1, PartitionNumber: partition.Number, Report: partition.MDV090,
				})
			} else if partition.MDV090.Status == diskimage.MDV090StatusDamaged || partition.MDV090.Status == diskimage.MDV090StatusUnsupported {
				needsReview = true
			}
			if candidateStorageLayers > 1 {
				layerConflict = true
			}
		}
		result.Inputs = append(result.Inputs, input)
	}

	if !allGPTValid {
		switch {
		case gptDamaged:
			result.Status = "damaged"
			result.Findings = append(result.Findings, "at least one supplied image has damaged or inconsistent GPT metadata; cross-image identity and array comparisons were withheld")
		case gptUnsupported:
			result.Status = "unsupported"
			result.Findings = append(result.Findings, "at least one supplied image is not a supported GPT image; cross-image identity and array comparisons were withheld")
		default:
			result.Status = "incomplete"
		}
		if err := writeJSON(output, result); err != nil {
			return 1, err
		}
		return 2, nil
	}

	identity := &storageImageSetIdentityScan{
		Complete:                      true,
		DuplicateDiskGUIDGroups:       duplicateFingerprintGroupCount(diskFingerprints),
		DuplicatePARTUUIDGroups:       duplicateFingerprintGroupCount(partitionFingerprints),
		DuplicateFilesystemUUIDGroups: duplicateFingerprintGroupCount(extFingerprints),
	}
	result.IdentityScan = identity
	mdV12Comparison, err := diskimage.CompareMDV12ImageSet(mdV12Components)
	if err != nil {
		return 1, err
	}
	result.MDV12Comparison = &mdV12Comparison
	mdV10Comparison, err := diskimage.CompareMDV10ImageSet(mdV10Components)
	if err != nil {
		return 1, err
	}
	result.MDV10Comparison = &mdV10Comparison
	mdV090Comparison, err := diskimage.CompareMDV090ImageSet(mdV090Components)
	if err != nil {
		return 1, err
	}
	result.MDV090Comparison = &mdV090Comparison

	ambiguous := identity.DuplicateDiskGUIDGroups != 0 || identity.DuplicatePARTUUIDGroups != 0 ||
		identity.DuplicateFilesystemUUIDGroups != 0 || layerConflict
	incomplete := needsReview || mdV12Comparison.UnqualifiedComponents != 0 || mdV12Comparison.UnidentifiedCandidateComponents != 0 ||
		mdV10Comparison.UnqualifiedComponents != 0 || mdV10Comparison.UnidentifiedCandidateComponents != 0 ||
		mdV090Comparison.UnqualifiedComponents != 0 || mdV090Comparison.UnidentifiedCandidateComponents != 0
	for _, array := range mdV12Comparison.Arrays {
		switch array.Status {
		case diskimage.MDV12ArrayAmbiguous, diskimage.MDV12ArrayConflicting, diskimage.MDV12ArrayDivergent:
			ambiguous = true
		case diskimage.MDV12ArrayIncomplete:
			incomplete = true
		}
	}
	for _, array := range mdV090Comparison.Arrays {
		switch array.Status {
		case diskimage.MDV090ArrayAmbiguous, diskimage.MDV090ArrayConflicting, diskimage.MDV090ArrayDivergent:
			ambiguous = true
		case diskimage.MDV090ArrayIncomplete:
			incomplete = true
		}
	}
	for _, array := range mdV10Comparison.Arrays {
		switch array.Status {
		case diskimage.MDV10ArrayAmbiguous, diskimage.MDV10ArrayConflicting, diskimage.MDV10ArrayDivergent:
			ambiguous = true
		case diskimage.MDV10ArrayIncomplete:
			incomplete = true
		}
	}
	switch {
	case ambiguous:
		result.Status = "ambiguous"
		result.Findings = append(result.Findings, "duplicate identities, conflicting storage-layer signatures, or divergent array metadata require operator review")
	case incomplete:
		result.Status = "incomplete"
		result.Findings = append(result.Findings, "one or more bounded filesystem or array observations are incomplete, damaged, unsupported, or unidentified")
	default:
		result.Status = "metadata-observed"
		result.Findings = append(result.Findings, "no duplicate observed identifiers or inconsistent supported array metadata were found within the supplied images; this does not imply global uniqueness")
	}
	if layerConflict {
		result.Findings = append(result.Findings, "one or more partitions contain both an ext-family filesystem candidate and an MD component candidate")
	}
	if extFilesystemNeedsReview {
		result.Findings = append(result.Findings, "an ext-family superblock is not marked clean, records filesystem errors, or advertises journal recovery; no repair or recovery was attempted")
	}
	if err := writeJSON(output, result); err != nil {
		return 1, err
	}
	if result.Status != "metadata-observed" {
		return 2, nil
	}
	return 0, nil
}

func duplicateFingerprintGroupCount(fingerprints []string) int {
	counts := make(map[string]int, len(fingerprints))
	for _, fingerprint := range fingerprints {
		if fingerprint != "" {
			counts[fingerprint]++
		}
	}
	duplicates := 0
	for _, count := range counts {
		if count > 1 {
			duplicates++
		}
	}
	return duplicates
}

type storageImageSetInput struct {
	InputIndex              int              `json:"input_index"`
	GPTStatus               diskimage.Status `json:"gpt_status"`
	MDV12Candidates         int              `json:"md_v1_2_candidates"`
	MDV12Unqualified        int              `json:"md_v1_2_unqualified_partitions"`
	MDV090CandidatesIgnored int              `json:"md_v0_90_candidates_not_compared"`
}

type storageImageSetReport struct {
	Format             string                        `json:"format"`
	SchemaVersion      int                           `json:"schema_version"`
	WDCompatibility    string                        `json:"wd_compatibility"`
	Inputs             []storageImageSetInput        `json:"inputs"`
	Comparison         diskimage.MDV12ImageSetReport `json:"md_v1_2_comparison"`
	BlockDeviceOpened  bool                          `json:"block_device_opened"`
	MutationsPerformed bool                          `json:"mutations_performed"`
	AssemblyPerformed  bool                          `json:"assembly_performed"`
	MountPerformed     bool                          `json:"mount_performed"`
	Limitations        []string                      `json:"limitations"`
}

func inspectMDV12ImageSet(args []string, output io.Writer) (int, error) {
	if len(args) < 2 || len(args) > maxStorageImageSetInputs {
		return 1, errors.New("usage: phantowd-lab inspect-md-v1.2-image-set DISK-IMAGE-1 DISK-IMAGE-2 [DISK-IMAGE-3 [DISK-IMAGE-4]]")
	}
	result := storageImageSetReport{
		Format:          "phantowd-md-v1.2-image-set-inspection",
		SchemaVersion:   1,
		WDCompatibility: "unqualified",
		Inputs:          []storageImageSetInput{},
		Limitations: []string{
			"all inputs must be regular whole-disk image files with valid generic GPT; input order is represented only by an ordinal, and no host paths are returned",
			"only MD v1.2 components are grouped; MD 0.90 candidates are counted but not compared, and other metadata versions are not detected",
			"metadata consistency does not establish array synchronization, disk health, filesystem integrity, WD layout compatibility, migration safety, or suitability for assembly",
			"the comparator does not interpret per-device recovery/replacement state, reshape, bitmap, bad-block, journal, or other feature-map semantics",
			"no block device is opened, no array is assembled, no filesystem is mounted, and no image is modified",
		},
	}
	components := make([]diskimage.MDV12ImageComponent, 0)
	allGPTValid := true
	for inputIndex, path := range args {
		file, size, err := openRegular(path)
		if err != nil {
			return 1, err
		}
		observed, observeErr := observeStorageImage(file, size)
		closeErr := file.Close()
		if observeErr != nil {
			return 1, observeErr
		}
		if closeErr != nil {
			return 1, closeErr
		}
		input := storageImageSetInput{InputIndex: inputIndex + 1, GPTStatus: observed.GPTStatus}
		if observed.GPTStatus != diskimage.StatusValid {
			allGPTValid = false
			result.Inputs = append(result.Inputs, input)
			continue
		}
		for _, partition := range observed.Partitions {
			switch partition.MDV12.Status {
			case diskimage.MDStatusCandidate:
				input.MDV12Candidates++
				components = append(components, diskimage.MDV12ImageComponent{
					InputIndex: inputIndex + 1, PartitionNumber: partition.Number, Report: partition.MDV12,
				})
			default:
				input.MDV12Unqualified++
			}
			if partition.MDV090.Status == diskimage.MDV090StatusCandidate {
				input.MDV090CandidatesIgnored++
			}
		}
		result.Inputs = append(result.Inputs, input)
	}
	comparison, err := diskimage.CompareMDV12ImageSet(components)
	if err != nil {
		return 1, err
	}
	result.Comparison = comparison
	if err := writeJSON(output, result); err != nil {
		return 1, err
	}
	if !allGPTValid || len(comparison.Arrays) == 0 || comparison.UnidentifiedCandidateComponents != 0 {
		return 2, nil
	}
	for _, array := range comparison.Arrays {
		if array.Status != diskimage.MDV12ArrayMetadataConsistent {
			return 2, nil
		}
	}
	return 0, nil
}

type mdV090ImageSetInput struct {
	InputIndex        int              `json:"input_index"`
	GPTStatus         diskimage.Status `json:"gpt_status"`
	MDV090Candidates  int              `json:"md_v0_90_candidates"`
	MDV090Unqualified int              `json:"md_v0_90_unqualified_partitions"`
}

type mdV090ImageSetReport struct {
	Format             string                         `json:"format"`
	SchemaVersion      int                            `json:"schema_version"`
	WDCompatibility    string                         `json:"wd_compatibility"`
	Inputs             []mdV090ImageSetInput          `json:"inputs"`
	Comparison         diskimage.MDV090ImageSetReport `json:"md_v0_90_comparison"`
	BlockDeviceOpened  bool                           `json:"block_device_opened"`
	MutationsPerformed bool                           `json:"mutations_performed"`
	AssemblyPerformed  bool                           `json:"assembly_performed"`
	MountPerformed     bool                           `json:"mount_performed"`
	Limitations        []string                       `json:"limitations"`
}

func inspectMDV090ImageSet(args []string, output io.Writer) (int, error) {
	if len(args) < 2 || len(args) > maxStorageImageSetInputs {
		return 1, errors.New("usage: phantowd-lab inspect-md-v0.90-image-set DISK-IMAGE-1 DISK-IMAGE-2 [DISK-IMAGE-3 [DISK-IMAGE-4]]")
	}
	result := mdV090ImageSetReport{
		Format:          "phantowd-md-v0.90-image-set-inspection",
		SchemaVersion:   1,
		WDCompatibility: "unqualified",
		Inputs:          []mdV090ImageSetInput{},
		Limitations: []string{
			"all inputs must be regular whole-disk image files with valid generic GPT; input order is represented only by an ordinal, and no host paths are returned",
			"only generic little-endian MD 0.90 components are grouped; MD v1.2 and other metadata versions are not compared by this command",
			"metadata agreement does not establish array synchronization, disk health, filesystem integrity, WD layout compatibility, migration safety, or suitability for assembly",
			"the comparator does not interpret recovery, replacement, reshape, bitmap, bad-block, journal, or other feature semantics",
			"no block device is opened, no array is assembled, no filesystem is mounted, and no image is modified",
		},
	}
	components := make([]diskimage.MDV090ImageComponent, 0)
	allGPTValid := true
	for inputIndex, path := range args {
		file, size, err := openRegular(path)
		if err != nil {
			return 1, err
		}
		observed, observeErr := observeStorageImage(file, size)
		closeErr := file.Close()
		if observeErr != nil {
			return 1, observeErr
		}
		if closeErr != nil {
			return 1, closeErr
		}
		input := mdV090ImageSetInput{InputIndex: inputIndex + 1, GPTStatus: observed.GPTStatus}
		if observed.GPTStatus != diskimage.StatusValid {
			allGPTValid = false
			result.Inputs = append(result.Inputs, input)
			continue
		}
		for _, partition := range observed.Partitions {
			if partition.MDV090.Status == diskimage.MDV090StatusCandidate {
				input.MDV090Candidates++
				components = append(components, diskimage.MDV090ImageComponent{
					InputIndex: inputIndex + 1, PartitionNumber: partition.Number, Report: partition.MDV090,
				})
			} else {
				input.MDV090Unqualified++
			}
		}
		result.Inputs = append(result.Inputs, input)
	}
	comparison, err := diskimage.CompareMDV090ImageSet(components)
	if err != nil {
		return 1, err
	}
	result.Comparison = comparison
	if err := writeJSON(output, result); err != nil {
		return 1, err
	}
	if !allGPTValid || comparison.CandidateComponents == 0 || comparison.UnidentifiedCandidateComponents != 0 || len(comparison.Arrays) == 0 {
		return 2, nil
	}
	for _, array := range comparison.Arrays {
		if array.Status != diskimage.MDV090ArrayMetadataConsistent {
			return 2, nil
		}
	}
	return 0, nil
}

func inventoryRootfs(args []string, output io.Writer) (int, error) {
	flags := flag.NewFlagSet("inventory-rootfs", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	compact := flags.Bool("summary", false, "emit a path-free compact overview")
	if err := flags.Parse(args); err != nil || flags.NArg() != 1 {
		return 1, errors.New("usage: phantowd-lab inventory-rootfs [--summary] DIRECTORY")
	}
	report, err := rootfsinventory.Inspect(flags.Arg(0))
	if err != nil {
		return 1, err
	}
	if *compact {
		return 0, writeJSON(output, report.Compact())
	}
	return 0, writeJSON(output, report)
}

func replayMCU(args []string, output io.Writer) (int, error) {
	flags := flag.NewFlagSet("replay-mcu", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	format := flags.String("format", "raw", "capture format: raw or hex")
	if err := flags.Parse(args); err != nil {
		return 1, errors.New("usage: phantowd-lab replay-mcu [--format raw|hex] FILE")
	}
	if flags.NArg() != 1 || (*format != "raw" && *format != "hex") {
		return 1, errors.New("usage: phantowd-lab replay-mcu [--format raw|hex] FILE")
	}
	file, size, err := openRegular(flags.Arg(0))
	if err != nil {
		return 1, err
	}
	defer file.Close()
	if size > maxCaptureSize {
		return 1, fmt.Errorf("capture is %d bytes; maximum is %d", size, maxCaptureSize)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxCaptureSize+1))
	if err != nil {
		return 1, err
	}
	if int64(len(data)) > maxCaptureSize {
		return 1, errors.New("capture exceeds size limit")
	}
	if *format == "hex" {
		data, err = parseHexText(data)
		if err != nil {
			return 1, err
		}
	}
	decoder := &mcuproto.StreamDecoder{}
	frames := decoder.Push(data)
	decoder.Finalize()
	state := mcuproto.NewState()
	for _, frame := range frames {
		state.Apply(frame)
	}
	report := struct {
		Format      string                  `json:"format"`
		Frames      []mcuproto.DecodedFrame `json:"frames"`
		Stats       mcuproto.StreamStats    `json:"stats"`
		State       *mcuproto.State         `json:"state"`
		Limitations []string                `json:"limitations"`
	}{
		Format: *format,
		Frames: frames,
		Stats:  decoder.Stats(),
		State:  state,
		Limitations: []string{
			"checksum and variable payload semantics are not yet assigned",
			"this is a passive software model, not evidence of safe hardware control",
		},
	}
	return 0, writeJSON(output, report)
}

func openRegular(path string) (*os.File, int64, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, 0, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, 0, errors.New("refusing symbolic-link input")
	}
	if !info.Mode().IsRegular() {
		return nil, 0, errors.New("refusing non-regular input; devices and pipes are not supported")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	openedInfo, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, 0, err
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		file.Close()
		return nil, 0, errors.New("input changed during open or is no longer the same regular file")
	}
	return file, openedInfo.Size(), nil
}

func parseHexText(data []byte) ([]byte, error) {
	var cleaned []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if index := strings.IndexByte(line, '#'); index >= 0 {
			line = line[:index]
		}
		cleaned = append(cleaned, line)
	}
	return parseHex(strings.Join(cleaned, " "))
}

func parseHex(value string) ([]byte, error) {
	replacer := strings.NewReplacer("0x", "", "0X", "", " ", "", "\t", "", "\r", "", "\n", "", ":", "", "-", "", "_", "")
	value = replacer.Replace(value)
	if value == "" {
		return nil, errors.New("empty hexadecimal input")
	}
	data, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("invalid hexadecimal input: %w", err)
	}
	return data, nil
}

func writeJSON(output io.Writer, value any) error {
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
