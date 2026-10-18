// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestTLSMaterialLinuxPathResolution(t *testing.T) {
	certPath, keyPath := writeTestTLSFiles(t, "nas.home.arpa")
	// Positive controls preserve regular files, relative paths and the original
	// descriptor flags. No listener or non-temporary credential is involved.
	file, err := openTLSMaterialFile(keyPath)
	if err != nil {
		t.Fatal("plain key open refused", err)
	}
	connection, err := file.SyscallConn()
	if err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	var flags, fdFlags int
	var flagErr, fdErr error
	controlErr := connection.Control(func(fd uintptr) {
		flags, flagErr = unix.FcntlInt(fd, unix.F_GETFL, 0)
		fdFlags, fdErr = unix.FcntlInt(fd, unix.F_GETFD, 0)
	})
	closeErr := file.Close()
	if controlErr != nil || flagErr != nil || fdErr != nil || closeErr != nil || flags&unix.O_ACCMODE != unix.O_RDONLY ||
		flags&unix.O_NONBLOCK == 0 || fdFlags&unix.FD_CLOEXEC == 0 {
		t.Fatal("original read-only/nonblocking/close-on-exec flags lost")
	}
	working, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relCert, err := filepath.Rel(working, certPath)
	if err != nil {
		t.Fatal(err)
	}
	relKey, err := filepath.Rel(working, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if config, err := loadAPITransportConfigFrom(transportEnvironment(tlsEnvironment("0.0.0.0:8443", "https://nas.home.arpa:8443", relCert, relKey))); err != nil || config.TLSConfig == nil {
		t.Fatal("plain relative certificate/key pair refused", err)
	}
	directory, err := os.Open(filepath.Dir(certPath))
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	for _, kind := range []string{"absolute-parent", "relative-parent", "ancestor", "descriptor-parent"} {
		t.Run(kind, func(t *testing.T) {
			alias := filepath.Join(t.TempDir(), "parent")
			target := filepath.Dir(certPath)
			if kind == "ancestor" {
				target = filepath.Dir(target)
			} else if kind == "relative-parent" {
				target, err = filepath.Rel(filepath.Dir(alias), target)
				if err != nil {
					t.Fatal(err)
				}
			}
			if kind == "descriptor-parent" {
				alias = fmt.Sprintf("/proc/self/fd/%d", directory.Fd())
			} else if err := os.Symlink(target, alias); err != nil {
				t.Fatal(err)
			}
			if kind == "ancestor" {
				alias = filepath.Join(alias, filepath.Base(filepath.Dir(certPath)))
			}
			for _, selected := range []string{"certificate", "key"} {
				path := certPath
				if selected == "key" {
					path = keyPath
				}
				aliased := filepath.Join(alias, filepath.Base(path))
				// Reproduce the old leaf-only primitive's behavior with the same
				// regular fixture. It follows this parent despite O_NOFOLLOW.
				legacy, err := unix.Open(aliased, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
				if err != nil {
					t.Fatal("leaf-only comparison control failed", err)
				}
				if err := unix.Close(legacy); err != nil {
					t.Fatal(err)
				}
				opened, err := openTLSMaterialFile(aliased)
				if err == nil {
					_ = opened.Close()
					t.Fatal("TLS open followed a parent link")
				}
				if opened != nil || !errors.Is(err, unix.ELOOP) {
					t.Fatal("parent link did not produce complete refusal")
				}
				cert, key := certPath, keyPath
				if selected == "certificate" {
					cert = aliased
				} else {
					key = aliased
				}
				config, err := loadAPITransportConfigFrom(transportEnvironment(tlsEnvironment("0.0.0.0:8443", "https://nas.home.arpa:8443", cert, key)))
				if err == nil || config.Address != "" || config.AllowedOrigin != "" || config.TLSConfig != nil || strings.Contains(err.Error(), aliased) {
					t.Fatal("parent link admitted TLS or returned private path/partial config")
				}
			}
		})
	}
}

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
