// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestTLSMaterialLinuxLeafOpen(t *testing.T) {
	const variable = "PHANTOWD_TLS_FIFO_TEST"
	if path := os.Getenv(variable); path != "" {
		if !filepath.IsAbs(path) || !strings.HasPrefix(filepath.Clean(path), filepath.Clean(os.TempDir())+string(os.PathSeparator)) ||
			!strings.HasPrefix(filepath.Base(filepath.Dir(filepath.Dir(path))), "TestTLSMaterialLinuxLeafOpen") {
			t.Fatal("only the disposable FIFO test path is allowed")
		}
		file, err := openTLSMaterialFile(path)
		if err != nil {
			t.Fatal("nonblocking FIFO open failed", err)
		}
		info, err := file.Stat()
		closeErr := file.Close()
		if err != nil || closeErr != nil || info.Mode()&os.ModeNamedPipe == 0 {
			t.Fatal("unexpected FIFO fixture")
		}
		return
	}
	certPath, keyPath := writeTestTLSFiles(t, "nas.home.arpa")
	for _, target := range []string{"certificate", "key"} {
		link := filepath.Join(t.TempDir(), "link")
		original := certPath
		if target == "key" {
			original = keyPath
		}
		if err := os.Symlink(original, link); err != nil {
			t.Fatal(err)
		}
		if file, err := openTLSMaterialFile(link); err == nil {
			_ = file.Close()
			t.Fatal("leaf symlink followed at actual Linux open")
		}
		cert, key := certPath, keyPath
		if target == "certificate" {
			cert = link
		} else {
			key = link
		}
		if config, err := loadAPITransportConfigFrom(transportEnvironment(tlsEnvironment("0.0.0.0:8443", "https://nas.home.arpa:8443", cert, key))); err == nil || config.TLSConfig != nil {
			t.Fatal("symlink TLS material admitted")
		}
	}
	path := filepath.Join(t.TempDir(), "fifo")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readTLSMaterial(path, maxTLSCertificatePEMBytes, false); err == nil {
		t.Fatal("FIFO admitted as TLS material")
	}
	// A child bounds the negative test if O_NONBLOCK is ever removed from the
	// Linux adapter. It has no writer and only opens/closes this synthetic FIFO.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestTLSMaterialLinuxLeafOpen$", "-test.v")
	child.Env = append(os.Environ(), variable+"="+path)
	output, err := child.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "--- PASS: TestTLSMaterialLinuxLeafOpen") {
		t.Fatalf("nonblocking FIFO child failed: %v\n%s", err, output)
	}
}
