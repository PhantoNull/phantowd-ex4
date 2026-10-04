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
	storageBroker := flag.Bool("storage-broker", false, "serve the local read-only storage broker")
	nfsTest := flag.String("qemu-nfs-test", "", "fixed NFS integration fixture; QEMU only")
	smbTest := flag.Bool("qemu-smb-test", false, "fixed SMB effective-access fixture; QEMU only")
	mountGuardTest := flag.Bool("qemu-mount-guard-test", false, "fixed descriptor/mount guard fixture; QEMU only")
	mdStackTest := flag.Bool("qemu-md-stack-test", false, "fixed disposable MD stack/mount-guard fixture; QEMU only")
	mdV10Fixture := flag.Bool("qemu-md-v10-fixture", false, "write fixed MD v1.0 metadata to partition 1 on two disposable GPT QEMU disks; QEMU only")
	mdV10BrokerClient := flag.Bool("qemu-md-v10-broker-client", false, "fixed internal MD v1.0 broker client fixture; QEMU only")
	stateTest := flag.String("qemu-state-test", "", "fixed two-boot state fixture; QEMU only")
	identityClient := flag.String("qemu-identity-client", "", "fixed unprivileged identity-channel fixture; QEMU only")
	identityOwnerService := flag.Bool("qemu-identity-owner-service", false, "fixed root identity-owner service fixture; QEMU only")
	writableConsumer := flag.Bool("qemu-writable-backing-consumer", false, "fixed inherited-descriptor consumer; disposable QEMU only")
	flag.Parse()
	modes := 0
	for _, selected := range []bool{
		*selfTest, *storageBroker, *nfsTest != "", *smbTest, *mountGuardTest,
		*mdStackTest, *mdV10Fixture, *mdV10BrokerClient, *stateTest != "", *identityClient != "", *identityOwnerService, *writableConsumer,
	} {
		if selected {
			modes++
		}
	}
	if flag.NArg() != 0 || modes > 1 {
		log.Fatal("unexpected arguments")
	}
	if *writableConsumer {
		if err := runQEMUWritableBackingConsumer(); err != nil {
			fmt.Fprintln(os.Stderr, "PHANTOWD_WRITABLE_CONSUMER_ERROR fixture refused")
			os.Exit(1)
		}
		return
	}
	if *storageBroker {
		if err := runStorageBroker(); err != nil {
			fmt.Fprintln(os.Stderr, "PHANTOWD_STORAGE_BROKER_ERROR startup refused")
			os.Exit(1)
		}
		return
	}
	if *identityClient != "" {
		if err := runQEMUIdentityClient(*identityClient); err != nil {
			fmt.Fprintln(os.Stderr, "PHANTOWD_API_ERROR identity channel fixture failed")
			os.Exit(1)
		}
		return
	}
	if *identityOwnerService {
		if err := runQEMUIdentityOwnerService(); err != nil {
			fmt.Fprintln(os.Stderr, "PHANTOWD_IDENTITY_OWNER_ERROR startup refused")
			os.Exit(1)
		}
		return
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
	if *mdStackTest {
		if err := runQEMUMDStackTest(); err != nil {
			fmt.Fprintf(os.Stderr, "PHANTOWD_API_ERROR %v\n", err)
			os.Exit(1)
		}
		return
	}
	if *mdV10Fixture {
		if err := runQEMUMDV10Fixture(); err != nil {
			fmt.Fprintf(os.Stderr, "PHANTOWD_API_ERROR MD v1.0 QEMU fixture failed: %v\n", err)
			os.Exit(1)
		}
		if err := runQEMUMDV10M34Fixture(); err != nil {
			fmt.Fprintf(os.Stderr, "PHANTOWD_API_ERROR MD v1.0/M3.4 QEMU fixture failed: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if *mdV10BrokerClient {
		if err := runQEMUMDV10BrokerClient(); err != nil {
			fmt.Fprintln(os.Stderr, "PHANTOWD_MD_V10_BROKER_ERROR fixed read-only broker observation failed")
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
	defer accounts.Close()
	transport, err := loadAPITransportConfig()
	if err != nil {
		log.Fatal("API transport configuration is invalid")
	}
	shareDirectory, serviceDirectory := os.Getenv("PHANTOWD_SHARE_STATE_DIR"), os.Getenv("PHANTOWD_SERVICE_STATE_DIR")
	if validateServiceStateOptions(serviceDirectory, shareDirectory, transport) != nil {
		log.Fatal("service configuration options are invalid")
	}
	readPolicy, closePolicy, err := openSharePolicyReader(shareDirectory)
	if err != nil {
		log.Fatal("share configuration storage is unavailable or insecure")
	}
	defer closePolicy()
	serviceState, closeServiceState, err := openDevelopmentServiceState(serviceDirectory)
	if err != nil {
		log.Fatal("development service configuration storage is unavailable")
	}
	defer closeServiceState()
	server := newConfiguredServer(newHandlerWithStorageGPTObservation(func() (systemSnapshot, error) {
		return collectSystem(os.DirFS("/proc"), time.Now())
	}, func() (storageSnapshot, error) {
		return collectStorageFromBroker()
	}, func() mdArraySnapshot {
		return collectMDArrayInventory(os.DirFS("/proc"), os.DirFS("/sys"), time.Now())
	}, func() (mountSnapshot, error) {
		return collectMountInventory(os.DirFS("/proc"), time.Now())
	}, newAuthController(accounts, transport.AllowedOrigin), readPolicy, serviceState, func(ctx context.Context) (storageGPTObservationSummary, error) {
		return observeGPTPartitionIdentityFromBroker(ctx)
	}), transport)
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
