// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-lab/diskimage"
	"github.com/PhantoNull/phantowd-ex4/phantowd-lab/mcuproto"
	"github.com/PhantoNull/phantowd-ex4/phantowd-lab/rootfsinventory"
	"github.com/PhantoNull/phantowd-ex4/phantowd-lab/storageinventory"
	"github.com/PhantoNull/phantowd-ex4/phantowd-lab/storagerefs"
	"github.com/PhantoNull/phantowd-ex4/phantowd-lab/vendorupdate"
)

const maxCaptureSize = int64(16 * 1024 * 1024)

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

	case "inspect-ext-partition":
		return inspectExtPartition(args[1:], output)

	case "inspect-md-v1.2-partition":
		return inspectMDV12Partition(args[1:], output)

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
