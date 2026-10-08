// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"flag"
	"io"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-lab/releaseverify"
)

type releaseBuildValues []string

func (v *releaseBuildValues) String() string { return "" }

func (v *releaseBuildValues) Set(value string) error {
	if len(*v) >= 16 {
		return errors.New("release list exceeds 16 entries")
	}
	*v = append(*v, value)
	return nil
}

func buildReleaseManifest(args []string, output io.Writer) (int, error) {
	flags := flag.NewFlagSet("build-release-manifest", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var spec releaseverify.BuildSpec
	var revisions, artifacts releaseBuildValues
	flags.StringVar(&spec.ReleaseVersion, "release-version", "", "declared v-prefixed release version")
	flags.StringVar(&spec.Channel, "channel", "", "declared stable, beta, or nightly channel")
	flags.StringVar(&spec.ModelID, "model", "", "declared exact model identifier")
	flags.Var(&revisions, "revision", "declared exact revision; repeat up to 16 times")
	flags.StringVar(&spec.SourceCommit, "source-commit", "", "declared source commit; not build provenance")
	flags.StringVar(&spec.BuildrootVersion, "buildroot-version", "", "declared Buildroot version")
	flags.StringVar(&spec.KernelVersion, "kernel-version", "", "declared kernel version")
	flags.StringVar(&spec.MinimumInstaller, "minimum-installer", "", "declared v-prefixed minimum installer version")
	flags.Var(&artifacts, "artifact", "explicit NAME:ROLE payload; repeat up to 16 times")
	publicPath := flags.String("public-key", "", "raw 32-byte public key; no private key is accepted")
	directory := flags.String("artifacts", "", "existing directory containing regular payload files")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *publicPath == "" || *directory == "" ||
		len(revisions) == 0 || len(artifacts) == 0 {
		return 1, errors.New("usage: phantowd-lab build-release-manifest --artifacts DIR --public-key FILE --release-version VERSION --channel stable|beta|nightly --model ID --revision ID --source-commit SHA --buildroot-version VERSION --kernel-version VERSION --minimum-installer VERSION --artifact NAME:ROLE [--revision ID ...] [--artifact NAME:ROLE ...]")
	}
	spec.HardwareRevisions = revisions
	payloads := make([]releaseverify.PayloadSpec, len(artifacts))
	for i, value := range artifacts {
		name, role, ok := strings.Cut(value, ":")
		if !ok || name == "" || role == "" || strings.Contains(role, ":") {
			return 1, errors.New("release artifact must use NAME:ROLE")
		}
		payloads[i] = releaseverify.PayloadSpec{Name: name, Role: role}
	}
	keyFile, size, err := openRegular(*publicPath)
	if err != nil {
		return 1, err
	}
	defer keyFile.Close()
	if size != 32 {
		return 1, errors.New("Ed25519 public key must be exactly 32 bytes")
	}
	key, err := io.ReadAll(io.LimitReader(keyFile, 33))
	if err != nil || len(key) != 32 {
		return 1, errors.New("cannot read Ed25519 public key")
	}
	data, err := releaseverify.BuildUnsignedManifest(spec, payloads, *directory, key)
	if err != nil {
		return 1, err
	}
	n, err := output.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return 1, err
	}
	return 0, nil
}
