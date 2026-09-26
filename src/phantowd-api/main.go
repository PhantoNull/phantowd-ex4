// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	selfTest := flag.Bool("self-test", false, "test the fixed guest-loopback endpoint; QEMU only")
	nfsTest := flag.String("qemu-nfs-test", "", "fixed NFS integration fixture; QEMU only")
	smbTest := flag.Bool("qemu-smb-test", false, "fixed SMB effective-access fixture; QEMU only")
	mountGuardTest := flag.Bool("qemu-mount-guard-test", false, "fixed descriptor/mount guard fixture; QEMU only")
	stateTest := flag.String("qemu-state-test", "", "fixed two-boot state fixture; QEMU only")
	flag.Parse()
	modes := 0
	for _, selected := range []bool{*selfTest, *nfsTest != "", *smbTest, *mountGuardTest, *stateTest != ""} {
		if selected {
			modes++
		}
	}
	if flag.NArg() != 0 || modes > 1 {
		log.Fatal("unexpected arguments")
	}
	if *stateTest != "" {
		if err := runQEMUStateTest(*stateTest); err != nil {
			fmt.Fprintf(os.Stderr, "PHANTOWD_API_ERROR %v\n", err)
			os.Exit(1)
		}
		return
	}
	if *mountGuardTest {
		if err := runQEMUMountGuardTest(); err != nil {
			fmt.Fprintf(os.Stderr, "PHANTOWD_API_ERROR %v\n", err)
			os.Exit(1)
		}
		return
	}
	if *smbTest {
		if err := runQEMUSMBTest(); err != nil {
			fmt.Fprintf(os.Stderr, "PHANTOWD_API_ERROR %v\n", err)
			os.Exit(1)
		}
		return
	}
	if *nfsTest != "" {
		if err := runQEMUNFSTest(*nfsTest); err != nil {
			fmt.Fprintf(os.Stderr, "PHANTOWD_API_ERROR %v\n", err)
			os.Exit(1)
		}
		return
	}
	if *selfTest {
		if err := runSelfTest(); err != nil {
			fmt.Fprintf(os.Stderr, "PHANTOWD_API_ERROR %v\n", err)
			os.Exit(1)
		}
		return
	}
	if os.Geteuid() == 0 {
		log.Fatal("refusing to serve as root")
	}
	stateDir, err := configuredAccountStateDirectory(os.Getenv("PHANTOWD_STATE_DIR"))
	if err != nil {
		log.Fatal("account state directory is not configured")
	}
	accounts, err := openAccountStore(stateDir)
	if err != nil {
		log.Fatal("account state is unavailable or insecure")
	}
	readPolicy, closePolicy, err := openSharePolicyReader(os.Getenv("PHANTOWD_SHARE_STATE_DIR"))
	if err != nil {
		log.Fatal("share configuration storage is unavailable or insecure")
	}
	defer closePolicy()
	transport, err := loadAPITransportConfig()
	if err != nil {
		log.Fatal("API transport configuration is invalid")
	}
	server := newConfiguredServer(newHandlerWithSharePolicy(func() (systemSnapshot, error) {
		return collectSystem(os.DirFS("/proc"), time.Now())
	}, func() (storageSnapshot, error) {
		return collectStorage(os.DirFS("/sys"))
	}, func() mdArraySnapshot {
		return collectMDArrayInventory(os.DirFS("/proc"), os.DirFS("/sys"), time.Now())
	}, func() (mountSnapshot, error) {
		return collectMountInventory(os.DirFS("/proc"), time.Now())
	}, newAuthController(accounts, transport.AllowedOrigin), readPolicy), transport)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		shutdown, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		_ = server.Shutdown(shutdown)
	}()
	log.Printf("PhantoWD development diagnostics listening on %s", server.Addr)
	serve := server.ListenAndServe
	if transport.TLSConfig != nil {
		serve = func() error { return server.ListenAndServeTLS("", "") }
	}
	if err := serve(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal("diagnostics server failed")
	}
	<-shutdownDone
}
