// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const rc0PrebindEnv = "PHANTOWD_RC0_PREBIND"

func main() {
	selfTest := flag.Bool("self-test", false, "test the fixed guest-loopback endpoint; QEMU only")
	storageBroker := flag.Bool("storage-broker", false, "serve the local read-only storage broker")
	registryCommit := flag.Bool("commit-volume-registry", false, "persist explicit claims using inherited directory 3; no storage adoption")
	registryExpected := flag.String("expected-registry-revision", "", "explicit expected revision for volume-registry commit")
	provisionNAS := flag.Bool("provision-nas-policy", false, "publish initial NAS policy from stdin under inherited directory 3")
	provisionAdmin := flag.Bool("provision-administrator", false, "initialize administrator from private stdin under inherited directory 3")
	provisionTLS := flag.Bool("provision-rc0-tls", false, "install the initial RC0 TLS identity from private stdin under inherited directory 3")
	provisionIdentities := flag.Bool("provision-rc0-service-identities", false, "initialize the service identity allocation range in inherited RC0 state directory 3")
	replaceTLS := flag.Bool("replace-rc0-tls", false, "replace the RC0 TLS identity while management is stopped")
	expectedTLS := flag.String("expected-tls-certificate", "", "SHA-256 fingerprint of the current TLS leaf certificate")
	superviseRC0 := flag.Bool("supervise-rc0", false, "launch RC0 management from inherited state and policy confirmation")
	superviseRC0Boot := flag.Bool("supervise-rc0-boot", false, "launch RC0 management from the trusted boot handoff")
	rc0BootService := flag.String("rc0-boot-service", "", "manage startup and shutdown of the RC0 boot service")
	nasInstallation := flag.String("nas-installation-id", "", "trusted installation ID for NAS policy provisioning")
	nfsTest := flag.String("qemu-nfs-test", "", "fixed NFS integration fixture; QEMU only")
	smbTest := flag.Bool("qemu-smb-test", false, "fixed SMB effective-access fixture; QEMU only")
	mountGuardTest := flag.Bool("qemu-mount-guard-test", false, "fixed descriptor/mount guard fixture; QEMU only")
	mdStackTest := flag.Bool("qemu-md-stack-test", false, "fixed disposable MD stack/mount-guard fixture; QEMU only")
	mdV10Fixture := flag.Bool("qemu-md-v10-fixture", false, "write fixed MD v1.0 metadata to partition 1 on two disposable GPT QEMU disks; QEMU only")
	mdV10BrokerClient := flag.Bool("qemu-md-v10-broker-client", false, "fixed internal MD v1.0 broker client fixture; QEMU only")
	stateTest := flag.String("qemu-state-test", "", "fixed two-boot state fixture; QEMU only")
	identityClient := flag.String("qemu-identity-client", "", "fixed unprivileged identity-channel fixture; QEMU only")
	nasPolicyClient := flag.String("qemu-nas-policy-client", "", "fixed unprivileged NAS-policy fixture; QEMU only")
	identityOwnerService := flag.Bool("qemu-identity-owner-service", false, "fixed root identity-owner service fixture; QEMU only")
	nasOwnerService := flag.Bool("qemu-nas-policy-owner-service", false, "fixed root NAS-policy provider; QEMU only")
	writableConsumer := flag.Bool("qemu-writable-backing-consumer", false, "fixed inherited-descriptor consumer; disposable QEMU only")
	targetConsumer := flag.Bool("qemu-target-backing-consumer", false, "fixed two-descriptor consumer; disposable QEMU only")
	lioCredentialTest := flag.Bool("qemu-lio-credential-test", false, "fixed root credential installation fixture; disposable LIO QEMU only")
	lioTargetTest := flag.Bool("qemu-lio-target-test", false, "fixed complete target lifetime fixture; disposable guarded LIO QEMU only")
	flag.Parse()
	modes := 0
	for _, selected := range []bool{
		*rc0BootService != "",
		*selfTest, *storageBroker, *registryCommit, *provisionNAS, *provisionAdmin, *provisionTLS, *provisionIdentities, *replaceTLS, *superviseRC0, *superviseRC0Boot, *nfsTest != "", *smbTest, *mountGuardTest,
		*mdStackTest, *mdV10Fixture, *mdV10BrokerClient, *stateTest != "", *identityClient != "", *nasPolicyClient != "", *identityOwnerService, *nasOwnerService, *writableConsumer, *targetConsumer, *lioCredentialTest, *lioTargetTest,
	} {
		if selected {
			modes++
		}
	}
	if flag.NArg() != 0 || modes > 1 {
		log.Fatal("unexpected arguments")
	}
	if !*registryCommit && *registryExpected != "" {
		log.Fatal("registry revision requires commit mode")
	}
	if *replaceTLS != (*expectedTLS != "") {
		log.Fatal("RC0 TLS replacement requires the current certificate fingerprint")
	}
	if !*provisionNAS && !*superviseRC0 && *nasInstallation != "" {
		log.Fatal("NAS installation ID requires provisioning or supervision mode")
	}
	if *rc0BootService != "" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		err := manageRC0BootService(ctx, *rc0BootService)
		stop()
		if err != nil {
			log.Fatal("RC0 boot service requires review")
		}
		return
	}
	if *superviseRC0 || *superviseRC0Boot {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		var err error
		if *superviseRC0Boot {
			err = runRC0BootManagement(ctx, nil)
		} else {
			err = runRC0Management(ctx, *nasInstallation, os.Getenv(listenAddressEnv), os.Getenv(publicOriginEnv))
		}
		stop()
		if err != nil {
			log.Fatal("RC0 management startup or shutdown requires review")
		}
		return
	}
	if *provisionNAS {
		if err := provisionInheritedNASPolicy(*nasInstallation); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *provisionAdmin {
		if err := provisionInheritedAdministrator(context.Background(), os.Stdin); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *provisionTLS || *replaceTLS {
		if err := provisionInheritedRC0TLS(os.Stdin, os.Getenv(publicOriginEnv), *expectedTLS); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *provisionIdentities {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		err := provisionInheritedRC0ServiceIdentities(ctx, os.Stdin)
		stop()
		if err != nil {
			log.Fatal("RC0 service identity provisioning requires review")
		}
		return
	}
	if *registryCommit {
		if err := commitInheritedVolumeRegistry(*registryExpected); err != nil {
			fmt.Fprintln(os.Stderr, "PHANTOWD_REGISTRY_COMMIT_ERROR", err)
			os.Exit(1)
		}
		return
	}
	if *writableConsumer {
		if err := runQEMUWritableBackingConsumer(); err != nil {
			fmt.Fprintln(os.Stderr, "PHANTOWD_WRITABLE_CONSUMER_ERROR fixture refused")
			os.Exit(1)
		}
		return
	}
	if *lioTargetTest {
		if runQEMULIOTargetTest() != nil {
			fmt.Fprintln(os.Stderr, "PHANTOWD_LIO_ERROR phase=owned-target")
			os.Exit(1)
		}
		return
	}
	if *lioCredentialTest {
		if runQEMULIOCredentialTest() != nil {
			fmt.Fprintln(os.Stderr, "PHANTOWD_LIO_ERROR phase=typed-credentials")
			os.Exit(1)
		}
		return
	}
	if *targetConsumer {
		if err := runQEMUTargetBackingConsumer(); err != nil {
			fmt.Fprintln(os.Stderr, "PHANTOWD_TARGET_CONSUMER_ERROR fixture refused")
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
	if *nasPolicyClient != "" {
		if runQEMUNASPolicyClient(*nasPolicyClient) != nil {
			fmt.Fprintln(os.Stderr, "PHANTOWD_NAS_POLICY_CHANNEL_ERROR fixed client refused")
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
	if *nasOwnerService {
		if runQEMUNASPolicyOwnerService() != nil {
			fmt.Fprintln(os.Stderr, "PHANTOWD_NAS_PROVIDER_ERROR startup refused")
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
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	accounts, err := openConfiguredAccountStore(os.Getenv("PHANTOWD_STATE_DIR"), os.Getenv("PHANTOWD_STATE_FD"))
	if err != nil {
		log.Fatal("account state is unavailable or insecure")
	}
	defer accounts.Close()
	if !developmentBrowserEnrollment {
		if configured, err := accounts.configured(); err != nil || !configured {
			log.Fatal("administrator must be provisioned locally before API startup")
		}
	}
	transport, err := loadAPITransportConfig()
	if err != nil {
		log.Fatal("API transport configuration is invalid")
	}
	shareDirectory, serviceDirectory := os.Getenv("PHANTOWD_SHARE_STATE_DIR"), os.Getenv("PHANTOWD_SERVICE_STATE_DIR")
	if validateServiceStateOptions(serviceDirectory, shareDirectory, transport) != nil {
		log.Fatal("service configuration options are invalid")
	}
	nasChannel := os.Getenv("PHANTOWD_NAS_POLICY_SOCKET")
	var boundListener net.Listener
	if prebind := os.Getenv(rc0PrebindEnv); prebind != "" {
		if prebind != "1" || developmentBrowserEnrollment || transport.TLSConfig == nil || nasChannel == "" {
			log.Fatal("invalid RC0 supervised listener configuration")
		}
		// The managed supervisor acknowledges the original policy peer. Bind
		// first so an occupied or unavailable address cannot race that receipt.
		boundListener, err = net.Listen("tcp", transport.Address)
		if err != nil {
			log.Fatal("RC0 HTTPS listener could not be bound")
		}
		defer boundListener.Close()
	}
	auth := newAuthController(accounts, transport.AllowedOrigin)
	auth.setupDisabled = !developmentBrowserEnrollment
	nas, closeNAS, err := openNASPolicyHTTP(auth, nasChannel, shareDirectory != "" || serviceDirectory != "", transport.TLSConfig != nil)
	if err != nil {
		log.Fatal("NAS policy channel configuration is unavailable")
	}
	defer closeNAS()
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
	server := newConfiguredServer(newHandlerWithNASPolicy(func() (systemSnapshot, error) {
		return collectSystem(os.DirFS("/proc"), time.Now())
	}, func() (storageSnapshot, error) {
		return collectStorageFromBroker()
	}, func() mdArraySnapshot {
		return collectMDArrayInventory(os.DirFS("/proc"), os.DirFS("/sys"), time.Now())
	}, func() (mountSnapshot, error) {
		return collectMountInventory(os.DirFS("/proc"), time.Now())
	}, auth, readPolicy, serviceState, func(ctx context.Context) (storageGPTObservationSummary, error) {
		return observeGPTPartitionIdentityFromBroker(ctx)
	}, nas), transport)
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
	if boundListener != nil {
		serve = func() error { return server.ServeTLS(boundListener, "", "") }
	} else if transport.TLSConfig != nil {
		serve = func() error { return server.ListenAndServeTLS("", "") }
	}
	if err := serve(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal("diagnostics server failed")
	}
	<-shutdownDone
	if closeNAS() != nil {
		log.Fatal("NAS policy channel disposal requires review")
	}
}
