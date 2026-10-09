//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Fixed disposable test only; never installed by a product package.
package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"golang.org/x/sys/unix"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "PHANTOWD_RUNTIME_BUNDLE_FAILED")
		os.Exit(1)
	}
}

func run() error {
	model, err := os.ReadFile("/sys/firmware/devicetree/base/model")
	if err != nil || string(model) != "ARM Versatile PB\x00" {
		return errors.New("fixture guard")
	}
	if len(os.Args) == 2 && os.Args[1] == "stage" && os.Getuid() == 0 && os.Geteuid() == 0 {
		return stageFixture()
	}
	if len(os.Args) == 2 && os.Args[1] == "native-lookup" && os.Getuid() == 0 && os.Geteuid() == 0 {
		return nativeLookupFixture(false)
	}
	if len(os.Args) == 2 && os.Args[1] == "native-lookup-bootstrap" && os.Getuid() == 0 && os.Geteuid() == 0 {
		return nativeLookupFixture(true)
	}
	if len(os.Args) == 2 && os.Args[1] == "native-startup-fault" && os.Getuid() == 0 && os.Geteuid() == 0 {
		return nativeIdentityStateFaultQEMU()
	}
	if len(os.Args) == 2 && os.Args[1] == "native-planned-source-fault" && os.Getuid() == 0 && os.Geteuid() == 0 {
		return nativePlannedSourceFaultQEMU()
	}
	if len(os.Args) == 2 && os.Args[1] == "native-planned-exit-fault" && os.Getuid() == 0 && os.Geteuid() == 0 {
		return nativePlannedExitFaultQEMU()
	}
	if len(os.Args) == 2 && os.Args[1] == "native-planned-file-source-fault" && os.Getuid() == 0 && os.Geteuid() == 0 {
		return nativePlannedFileSourceFaultQEMU()
	}
	if len(os.Args) == 2 && os.Args[1] == "native-credentials" && os.Getuid() == 0 && os.Geteuid() == 0 {
		err := nativeCredentialFixture(nativeCredentialsCampaignQEMU)
		if err != nil {
			// Only fixture-defined stages and redacted sentinel errors, never
			// command output, credential bytes or passdb records.
			fmt.Fprintln(os.Stderr, "native credential fixture:", err)
		}
		return err
	}
	if len(os.Args) == 2 && os.Args[1] == "native-lifecycle" && os.Getuid() == 0 && os.Geteuid() == 0 {
		err := nativeCredentialFixture(nativeLifecycleCampaignQEMU)
		if err != nil {
			fmt.Fprintln(os.Stderr, "native lifecycle fixture:", err)
		}
		return err
	}
	if len(os.Args) == 2 && os.Args[1] == "native-planned-candidate" && os.Getuid() == 0 && os.Geteuid() == 0 {
		err := nativeCredentialFixture(nativePlannedCandidateCampaignQEMU)
		if err != nil {
			fmt.Fprintln(os.Stderr, "native planned candidate fixture:", err)
		}
		return err
	}
	if len(os.Args) == 2 && os.Args[1] == "native-identity-fault" && os.Getuid() == 0 && os.Geteuid() == 0 {
		err := nativeCredentialFixture(nativeIdentityFaultCampaignQEMU)
		if err != nil {
			fmt.Fprintln(os.Stderr, "native identity fault fixture:", err)
		}
		return err
	}
	if len(os.Args) == 2 && os.Args[1] == "native-planned-data" && os.Getuid() == 0 && os.Geteuid() == 0 {
		err := nativeCredentialFixture(nativePlannedDataCampaignQEMU)
		if err != nil {
			fmt.Fprintln(os.Stderr, "native planned data fixture:", err)
		}
		return err
	}
	if len(os.Args) == 2 && os.Args[1] == "native-planned-held" && os.Getuid() == 0 && os.Geteuid() == 0 {
		err := nativeCredentialFixture(nativePlannedHeldCampaignQEMU)
		if err != nil {
			fmt.Fprintln(os.Stderr, "native planned held fixture:", err)
		}
		return err
	}
	if len(os.Args) == 2 && os.Args[1] == "native-planned-file" && os.Getuid() == 0 && os.Geteuid() == 0 {
		err := nativeCredentialFixture(nativePlannedOpenFileCampaignQEMU)
		if err != nil {
			fmt.Fprintln(os.Stderr, "native planned file fixture:", err)
		}
		return err
	}
	if len(os.Args) == 2 && os.Args[1] == "native-planned-file-source" && os.Getuid() == 0 && os.Geteuid() == 0 {
		err := nativeCredentialFixture(nativePlannedFileSourceCampaignQEMU)
		if err != nil {
			fmt.Fprintln(os.Stderr, "native planned file source fixture:", err)
		}
		return err
	}
	if len(os.Args) == 2 && os.Args[1] == "native-planned-exit" && os.Getuid() == 0 && os.Geteuid() == 0 {
		err := nativeCredentialFixture(nativePlannedExitCampaignQEMU)
		if err != nil {
			fmt.Fprintln(os.Stderr, "native planned exit fixture:", err)
		}
		return err
	}
	if len(os.Args) == 2 && os.Args[1] == "inspect-acl" && os.Getuid() == 0 && os.Geteuid() == 0 {
		return inspectACLFixture()
	}
	if len(os.Args) == 2 && os.Args[1] == "owner" && os.Getuid() == 0 && os.Geteuid() == 0 {
		return ownerFixture()
	}
	if len(os.Args) == 2 && os.Args[1] == "samba-code-owner" && os.Getuid() == 0 && os.Geteuid() == 0 {
		files, aliases, err := inputs()
		if err != nil {
			return err
		}
		plan, err := runtimebundle.NewPlan(files, aliases)
		if err != nil {
			return err
		}
		root := os.NewFile(3, "fixed-readonly-code-root")
		writer := os.NewFile(4, "fixed-qemu-fault-anchor")
		defer root.Close()
		defer writer.Close()
		return plan.ProbeSambaCodeLifetimeQEMU(context.Background(), root, writer)
	}
	if len(os.Args) == 2 && os.Args[1] == "samba-configuration-owner" && os.Getuid() == 0 && os.Geteuid() == 0 {
		files, aliases, err := inputs()
		if err != nil {
			return err
		}
		plan, err := runtimebundle.NewPlan(files, aliases)
		if err != nil {
			return err
		}
		code := os.NewFile(3, "fixed-config-case-code-root")
		configuration := os.NewFile(4, "fixed-protected-configuration")
		writer := os.NewFile(5, "fixed-config-fault-anchor")
		defer code.Close()
		defer configuration.Close()
		defer writer.Close()
		return plan.ProbeSambaConfigurationLifetimeQEMU(context.Background(), code, configuration, writer)
	}
	if len(os.Args) == 3 && os.Args[1] == "owner-child" && os.Getuid() == 1801 && os.Geteuid() == 1801 {
		return ownerFixtureChild()
	}
	composed := len(os.Args) == 2 && os.Args[1] == "composed-code"
	censusOnly := len(os.Args) == 2 && os.Args[1] == "census-only"
	if (len(os.Args) != 1 && !composed && !censusOnly) || os.Getuid() != 1801 || os.Geteuid() != 1801 {
		return errors.New("fixture guard")
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil || len(status) > 64<<10 {
		return errors.New("credential evidence")
	}
	required := map[string]string{
		"CapInh:": "0000000000000000", "CapPrm:": "0000000000000000",
		"CapEff:": "0000000000000000", "CapBnd:": "0000000000000000",
		"CapAmb:": "0000000000000000", "NoNewPrivs:": "1",
	}
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		if expected, found := required[fields[0]]; found {
			if fields[1] != expected {
				return errors.New("unexpected authority")
			}
			delete(required, fields[0])
		}
	}
	if len(required) != 0 {
		return errors.New("incomplete authority evidence")
	}
	if composed {
		return composedCodeFixture()
	}
	files, aliases, err := inputs()
	if err != nil {
		return err
	}
	p, err := runtimebundle.NewPlan(files, aliases)
	if err != nil {
		return err
	}
	root := os.NewFile(3, "fixed-readonly-runtime-root")
	defer root.Close()
	started := time.Now()
	got, err := p.Inspect(context.Background(), root)
	elapsed := time.Since(started)
	if err != nil || got.Files != len(files) || got.Aliases != len(aliases) {
		return errors.Join(errors.New("positive inspection"), err)
	}
	var total int64
	for _, file := range files {
		total += file.Size
	}
	if got.Bytes != total {
		return errors.New("byte accounting")
	}
	fmt.Printf("PHANTOWD_RUNTIME_SCAN_COST files=%d bytes=%d elapsed_ns=%d scope=qemu-emulation-only\n", got.Files, got.Bytes, elapsed.Nanoseconds())
	if censusOnly {
		// Every non-service guest hashes its OWN full tree under the SAME zero-cap
		// boundary. The service guest owns every original independent inspector
		// refusal/retention experiment; no proof or authority crosses boots.
		fmt.Println("PHANTOWD_SAMBA_ROOT_CENSUS_READY readonly=true complete_census=true hashes=true aliases=true negative_controls=false retained_control=false scope=qemu-only")
		return nil
	}
	refuse := func(f []runtimebundle.File, a []runtimebundle.Alias) error {
		bad, err := runtimebundle.NewPlan(f, a)
		if err != nil {
			return errors.New("negative input must itself be valid")
		}
		observation, err := bad.Inspect(context.Background(), root)
		if !errors.Is(err, runtimebundle.ErrMismatch) || observation != (runtimebundle.Observation{}) {
			return errors.New("negative inspection")
		}
		return nil
	}
	wrongHash := append([]runtimebundle.File(nil), files...)
	wrongHash[0].SHA256[0] ^= 1
	if err := refuse(wrongHash, aliases); err != nil {
		return err
	}
	wrongMode := append([]runtimebundle.File(nil), files...)
	wrongMode[0].Mode = 0444
	if err := refuse(wrongMode, aliases); err != nil {
		return err
	}
	wrongAlias := append([]runtimebundle.Alias(nil), aliases...)
	if len(wrongAlias) == 0 {
		return errors.New("actual aliases required")
	}
	for _, file := range files {
		if file.Path != wrongAlias[0].Target {
			wrongAlias[0].Target = file.Path
			break
		}
	}
	if err := refuse(files, wrongAlias); err != nil {
		return err
	}
	// Omit a real program and its aliases: undeclared existing runtime bytes must
	// refuse the entire observation, not return a partial dependency assessment.
	var missing []runtimebundle.File
	var remaining []runtimebundle.Alias
	for _, file := range files {
		if file.Path != "usr/sbin/smbd" {
			missing = append(missing, file)
		}
	}
	for _, alias := range aliases {
		if alias.Target != "usr/sbin/smbd" {
			remaining = append(remaining, alias)
		}
	}
	if len(missing) != len(files)-1 {
		return errors.New("fixed daemon path")
	}
	if err := refuse(missing, remaining); err != nil {
		return err
	}
	// A manifest may not reinterpret an actual symlink as a regular file.
	link := aliases[0]
	var target runtimebundle.File
	for _, file := range files {
		if file.Path == link.Target {
			target = file
		}
	}
	target.Path = link.Path
	retyped := append(append([]runtimebundle.File(nil), files...), target)
	if err := refuse(retyped, aliases[1:]); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if observation, err := p.Inspect(ctx, root); !errors.Is(err, context.Canceled) || observation != (runtimebundle.Observation{}) {
		return errors.New("cancellation")
	}
	retained, err := p.ProbeRetainedCodeQEMU(context.Background(), root)
	if err != nil || retained != got {
		fmt.Fprintln(os.Stderr, "PHANTOWD_SAMBA_ROOT_RETAINED_CODE_FAILED", err)
		return errors.Join(errors.New("retained dynamic code qualification"), err)
	}
	fmt.Println("PHANTOWD_SAMBA_ROOT_BUNDLE_READY readonly=true complete_census=true hashes=true aliases=true refusals=5 scope=qemu-only")
	fmt.Println("PHANTOWD_SAMBA_ROOT_RETAINED_CODE_READY complete_code_pins=true caller_close=true dynamic_elf=true generic_dynamic_refused=true generic_root_refused=true canceled_refused=true released=true no_fd_leak=true scope=qemu-only")
	return nil
}

func inputs() ([]runtimebundle.File, []runtimebundle.Alias, error) {
	f, err := os.Open("/usr/lib/phantowd/qemu-samba-root.manifest")
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(io.LimitReader(f, (128<<10)+1))
	scanner.Buffer(make([]byte, 8192), 8192)
	objects := make(map[string]runtimebundle.File)
	bindings := make(map[string]bool)
	var aliases []runtimebundle.Alias
	bytes := 0
	for scanner.Scan() {
		line := scanner.Text()
		bytes += len(line) + 1
		fields := strings.Fields(line)
		if bytes > 128<<10 || len(fields) != 3 || len(bindings) >= 1024 ||
			!strings.HasPrefix(fields[1], "/") || !strings.HasPrefix(fields[2], "/") {
			return nil, nil, errors.New("bounded fixture manifest")
		}
		digest, err := hex.DecodeString(fields[0])
		if err != nil || len(digest) != 32 {
			return nil, nil, errors.New("fixed digest")
		}
		canonical, alias := fields[1][1:], fields[2][1:]
		if bindings[alias] {
			return nil, nil, errors.New("duplicate binding")
		}
		bindings[alias] = true
		var hash [32]byte
		copy(hash[:], digest)
		if old, exists := objects[canonical]; exists {
			if old.SHA256 != hash {
				return nil, nil, errors.New("conflicting object")
			}
		} else {
			objects[canonical] = runtimebundle.File{Path: canonical, SHA256: hash, Size: 1, Mode: 0555}
		}
		if alias != canonical {
			aliases = append(aliases, runtimebundle.Alias{Path: alias, Target: canonical})
		}
	}
	if scanner.Err() != nil {
		return nil, nil, scanner.Err()
	}
	var files []runtimebundle.File
	for _, file := range objects {
		files = append(files, file)
	}
	// Validate all manifest paths/conflicts before any base-object lookup. The
	// placeholder sizes validate topology only; actual bounded sizes are checked
	// again by the final Plan. No canonical-file lookup may traverse a symlink.
	if _, err := runtimebundle.NewPlan(files, aliases); err != nil {
		return nil, nil, err
	}
	base, err := stageRoot("/")
	if err != nil {
		return nil, nil, err
	}
	defer base.Close()
	for i := range files {
		fd, err := unix.Openat2(int(base.Fd()), files[i].Path, &unix.OpenHow{
			Flags:   unix.O_PATH | unix.O_CLOEXEC | unix.O_NOFOLLOW,
			Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV,
		})
		if err != nil {
			return nil, nil, errors.New("base object lookup")
		}
		object := os.NewFile(uintptr(fd), "fixed-base-object")
		info, statErr := object.Stat()
		closeErr := object.Close()
		if statErr != nil || closeErr != nil || !info.Mode().IsRegular() {
			return nil, nil, errors.New("base object")
		}
		// This is the original guest base, not the copy under inspection. These
		// observed fixture sizes still do not authenticate a product manifest.
		files[i].Size = info.Size()
	}
	return files, aliases, nil
}
