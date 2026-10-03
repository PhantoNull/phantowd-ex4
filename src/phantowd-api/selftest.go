//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/passwordhash"
)

const (
	qemuTestSerial  = "PHANTOWD-QEMU-SERIAL-01"
	qemuTestWWN     = "500f000000000001"
	qemuDataSerial  = "PHANTOWD-QEMU-DATA-01"
	qemuDataWWN     = "500f000000000002"
	qemuCloneSerial = "PHANTOWD-QEMU-CLONE-01"
	qemuCloneWWN    = "500f000000000003"
	qemuGPTDiskGUID = "fedcba98-7654-3210-fedc-ba9876543210"
	qemuGPTPartUUID = "8fd20a43-e550-4632-9a8e-5241c40c0861"
	qemuGPTTypeGUID = "0fc63daf-8483-4772-8e79-3d69d8477de4"
)

var qemuDashboardAssets = []struct {
	path, contentType string
	markers           []string
}{
	{"/", "text/html; charset=utf-8", []string{"PhantoWD EX4", "Development image.", "profile-notice-title", "NOT RELEASE QUALIFIED", "policy-form", "NOT SAVED / NOT APPLIED / RUNTIME NOT VERIFIED", "saved-load", "SAVED POLICY / ACTIVATION NOT AVAILABLE"}},
	{"/assets/app.css", "text/css; charset=utf-8", []string{"@media", "prefers-reduced-motion"}},
	{"/assets/app.js", "text/javascript; charset=utf-8", []string{"/api/v1/system", "/api/v1/storage", "/api/v1/storage/gpt-observation", "gpt-observe", "/api/v1/arrays", "/api/v1/mounts", "/api/v1/file-services/preview", "invalidatePolicyPreview", "textContent", "/api/v1/shares/configuration", "clearSavedPolicy"}},
	{"/assets/service-policy.js", "text/javascript; charset=utf-8", []string{"/api/v1/file-services/configuration", "sameServiceDocument", "saveServiceChange", "clearServicePolicy"}},
	{"/assets/ghost.svg", "image/svg+xml", []string{"<svg", "PhantoWD ghost"}},
}

func runSelfTest() error {
	if runtime.GOARCH != "arm" || strings.Split(buildARMLevel(), ",")[0] != "5" {
		return errors.New("self-test requires the ARMv5 QEMU target")
	}
	if err := exerciseQEMUShareConfig(); err != nil {
		return err
	}
	fmt.Println("PHANTOWD_SHARE_POLICY_READY schema=1 scope=synthetic-policy-only")
	if err := exerciseQEMUShareStore(); err != nil {
		return err
	}
	fmt.Println("PHANTOWD_SHARE_STORE_READY revision=2 reopen=true scope=temporary-qemu-only")
	if err := exerciseQEMUSMBPreview(); err != nil {
		return err
	}
	fmt.Println("PHANTOWD_SMB_PREVIEW_READY parser=testparm grants=ro,rw scope=synthetic-config-only")
	if err := exerciseQEMUNFSPolicy(); err != nil {
		return err
	}
	fmt.Println("PHANTOWD_NFS_POLICY_READY schema=1 mapping=all-squash scope=synthetic-policy-only")
	if err := exerciseQEMUNetworkPolicy(); err != nil {
		return err
	}
	fmt.Println("PHANTOWD_NETWORK_POLICY_READY schema=1 dual_stack=true aliases=true conflict_refused=true strict_json=true apply=false scope=synthetic-policy-only")
	if err := exerciseQEMUNetworkInventory(); err != nil {
		return err
	}
	fmt.Println("PHANTOWD_NETWORK_INVENTORY_READY kernel=true repeated=true routes=true fib_only=true rules=true nexthops=true object_fixture=true counts_redacted=true json_refused=true apply=false scope=qemu-namespace-only")
	argon2Started := time.Now()
	verifier, err := passwordhash.Hash(context.Background(), []byte("qemu-self-test-only"))
	if err != nil {
		return errors.New("Argon2id self-test could not hash")
	}
	verified, err := passwordhash.Verify(context.Background(), []byte("qemu-self-test-only"), verifier)
	if err != nil || !verified {
		return errors.New("Argon2id self-test could not verify")
	}
	verified, err = passwordhash.Verify(context.Background(), []byte("not-the-test-password"), verifier)
	if err != nil || verified {
		return errors.New("Argon2id self-test accepted a wrong password")
	}
	if _, err := passwordhash.Verify(context.Background(), []byte("qemu-self-test-only"), "$argon2id$v=19$m=4294967295,t=2,p=1$AA$AA"); err == nil {
		return errors.New("Argon2id self-test accepted unbounded verifier parameters")
	}
	argon2CycleMillis := time.Since(argon2Started).Milliseconds()
	client := &http.Client{
		Timeout:       5 * time.Second,
		Transport:     &http.Transport{Proxy: nil, DisableKeepAlives: true},
		Jar:           newQEMUCookieJar(),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer client.CloseIdleConnections()
	if err := waitQEMUAPIReady(client, "http://"+listenAddress); err != nil {
		return err
	}
	bootstrap, err := exerciseQEMUAuth(client)
	if err != nil {
		return err
	}
	if err := exerciseQEMUFileServicePreview(client, "http://"+listenAddress); err != nil {
		return err
	}
	fmt.Println("PHANTOWD_FILE_SERVICE_PREVIEW_READY authenticated=true csrf=true applied=false scope=desired-policy-only")
	if err := exerciseQEMUTLS(); err != nil {
		return err
	}
	fmt.Printf("PHANTOWD_TLS_READY target=qemu-armv5 min_version=1.2 origin_enforced=true scope=loopback-test-only\n")
	var snapshot systemSnapshot
	for _, path := range []string{"/healthz", "/api/v1/system"} {
		response, err := client.Get("http://" + listenAddress + path)
		if err != nil {
			return fmt.Errorf("loopback request failed path=%s", path)
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
		response.Body.Close()
		if readErr != nil || len(data) > 4096 || response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" {
			return fmt.Errorf("invalid read response path=%s status=%d bytes=%d read_error=%t", path, response.StatusCode, len(data), readErr != nil)
		}
		if path == "/healthz" {
			var health map[string]string
			if json.Unmarshal(data, &health) != nil || health["status"] != "ok" || health["scope"] != "process_only" {
				return errors.New("invalid process health response")
			}
		} else if json.Unmarshal(data, &snapshot) != nil {
			return fmt.Errorf("invalid system JSON bytes=%d", len(data))
		}
	}
	if snapshot.SchemaVersion != 1 || snapshot.Target != "qemu-armv5" || snapshot.Mode != "development" ||
		snapshot.Flashable || snapshot.HardwareValidated || snapshot.Architecture != "arm" ||
		strings.Split(snapshot.GOARM, ",")[0] != "5" || snapshot.EffectiveUID <= 0 || snapshot.Kernel == "" ||
		snapshot.ObservedAt.IsZero() || snapshot.UptimeSeconds <= 0 || snapshot.Memory.TotalBytes == 0 ||
		snapshot.Memory.AvailableBytes == 0 || snapshot.Memory.AvailableBytes > snapshot.Memory.TotalBytes {
		return errors.New("invalid development snapshot or privileged server")
	}
	fmt.Println("PHANTOWD_SYSTEM_SNAPSHOT_READY schema=1 nonroot=true authenticated=true scope=qemu-loopback-only")
	sysfsStorage, err := collectStorage(os.DirFS("/sys"))
	if err != nil {
		return fmt.Errorf("QEMU sysfs storage collection failed: %w", err)
	}
	partitionNodes := 0
	for _, observation := range sysfsStorage.Observations {
		if observation.Kind == "partition" {
			partitionNodes++
		}
	}
	fmt.Printf("PHANTOWD_SYSFS_STORAGE_READY complete=true nodes=%d partitions=%d scope=qemu-fixture-only\n", sysfsStorage.DeviceCount, partitionNodes)
	if err := exerciseQEMUSMARTDiskCensus(); err != nil {
		return err
	}
	fmt.Println("PHANTOWD_SMART_SYSFS_CENSUS_READY complete=true leaves=7 mounted_root_included=true ambiguous_vpd_preserved=true device_opened=false command_admitted=false scope=qemu-fixture-only")
	storageResponse, err := client.Get("http://" + listenAddress + "/api/v1/storage")
	if err != nil {
		return errors.New("storage loopback request failed")
	}
	storageData, readErr := io.ReadAll(io.LimitReader(storageResponse.Body, 4097))
	storageResponse.Body.Close()
	if readErr != nil || len(storageData) > 4096 || storageResponse.StatusCode != http.StatusOK || storageResponse.Header.Get("Cache-Control") != "no-store" {
		return fmt.Errorf("invalid storage observation response status=%d bytes=%d read_error=%t", storageResponse.StatusCode, len(storageData), readErr != nil)
	}
	var storage storageSnapshot
	if err := json.Unmarshal(storageData, &storage); err != nil {
		return fmt.Errorf("invalid storage observation JSON bytes=%d", len(storageData))
	}
	if storage.SchemaVersion != 2 || storage.Scope != "broker-read-only-point-in-time" ||
		!storage.InventoryReadOnly || !storage.BlockDevicesOpened || storage.ContentRead || storage.MutationsPerformed ||
		storage.StableIdentityAvailable || storage.DeviceCount != len(storage.Observations) {
		return fmt.Errorf("storage observation contract invalid schema=%d scope=%s opened=%t count=%d observations=%d", storage.SchemaVersion, storage.Scope, storage.BlockDevicesOpened, storage.DeviceCount, len(storage.Observations))
	}
	fmt.Println("PHANTOWD_STORAGE_RESPONSE_READY schema=2 broker=true opened=true content_read=false scope=qemu-fixture-only")
	if err := verifyQEMUStorageBrokerFixture(); err != nil {
		return errors.New("read-only storage device rules or hotplug fixture did not hold")
	}
	if err := verifyQEMUBlockDevice(os.DirFS("/sys"), "sda", qemuTestSerial, qemuTestWWN); err != nil {
		return errors.New("QEMU root SCSI identity fixture was not present")
	}
	if err := verifyQEMUBlockDevice(os.DirFS("/sys"), "sdd", qemuTestSerial, qemuTestWWN); err != nil {
		return errors.New("QEMU duplicate SCSI identity fixture was not present")
	}
	var rootDisk, duplicateDisk *blockObservation
	for index := range storage.Observations {
		observation := &storage.Observations[index]
		if observation.Name == "sda" {
			rootDisk = observation
		}
		if observation.Name == "sdd" {
			duplicateDisk = observation
		}
	}
	if rootDisk == nil || rootDisk.Kind != "block" || rootDisk.SizeBytes == 0 {
		return errors.New("QEMU root block device was not observed through sysfs")
	}
	if duplicateDisk == nil || duplicateDisk.Kind != "block" || duplicateDisk.SizeBytes == 0 || !duplicateDisk.ReadOnly {
		return errors.New("QEMU duplicate-identity block device was not observed read-only through sysfs")
	}
	for _, observation := range []*blockObservation{rootDisk, duplicateDisk} {
		if observation.SerialStatus != identityAmbiguous || observation.WWNStatus != identityAmbiguous {
			return errors.New("duplicate QEMU serial and WWN were not reported as ambiguous")
		}
	}
	if strings.Contains(string(storageData), qemuTestSerial) || strings.Contains(string(storageData), qemuTestWWN) ||
		strings.Contains(string(storageData), qemuDataSerial) || strings.Contains(string(storageData), qemuDataWWN) ||
		strings.Contains(string(storageData), qemuCloneSerial) || strings.Contains(string(storageData), qemuCloneWWN) {
		return errors.New("raw QEMU storage identifiers leaked through the API")
	}
	fmt.Println("PHANTOWD_STORAGE_COLLISION_READY nodes=2 serial=ambiguous wwn=ambiguous redacted=true read_only=true scope=qemu-fixture-only")
	fmt.Println("PHANTOWD_STORAGE_BROKER_READY api_outside_device_group=true broker_nnp_all_threads=true broker_capabilities=none whole_disk_mode=0440 hotplug_rechecked=true nodes=2 serial=ambiguous wwn=ambiguous redacted=true read_only=true scope=qemu-fixture-only")
	for _, private := range []string{qemuGPTDiskGUID, qemuGPTPartUUID, qemuGPTTypeGUID} {
		if strings.Contains(string(storageData), private) {
			return errors.New("ordinary storage refresh exposed private GPT metadata")
		}
	}
	if err := exerciseQEMUGPTObservation(client, "http://"+listenAddress); err != nil {
		return err
	}
	arraysResponse, err := client.Get("http://" + listenAddress + "/api/v1/arrays")
	if err != nil {
		return errors.New("array inventory loopback request failed")
	}
	arraysData, readErr := io.ReadAll(io.LimitReader(arraysResponse.Body, 65537))
	arraysResponse.Body.Close()
	if readErr != nil || len(arraysData) > 65536 || arraysResponse.StatusCode != http.StatusOK || arraysResponse.Header.Get("Cache-Control") != "no-store" {
		return errors.New("invalid array inventory response")
	}
	var arrays mdArraySnapshot
	if json.Unmarshal(arraysData, &arrays) != nil || arrays.SchemaVersion != 1 || arrays.ObservedAt.IsZero() ||
		!validArrayInventoryStatus(arrays.Status) || !arrays.ReadOnly || arrays.BlockDevicesOpened || arrays.DiskContentRead ||
		arrays.MutationsPerformed || arrays.ArrayCount != len(arrays.Arrays) || arrays.Arrays == nil || arrays.ArrayCount > maxMDArrayEntries {
		return errors.New("array observation crossed or overstated its read-only boundary")
	}
	for _, array := range arrays.Arrays {
		if !validMDName(array.Name) || !validArrayHealth(array.Health) || len(array.Members) > maxMDMemberEntries {
			return errors.New("array observation contains an invalid bounded field")
		}
		if array.Health == arrayHealthHealthy && (array.DegradedDevices != 0 || array.SyncAction != "idle") {
			return errors.New("array health was reported healthy despite degraded or sync state")
		}
	}
	if strings.Contains(string(arraysData), qemuTestSerial) || strings.Contains(string(arraysData), qemuTestWWN) {
		return errors.New("raw QEMU disk identity leaked through the array API")
	}
	mountsResponse, err := client.Get("http://" + listenAddress + "/api/v1/mounts")
	if err != nil {
		return errors.New("mount inventory loopback request failed")
	}
	mountsData, readErr := io.ReadAll(io.LimitReader(mountsResponse.Body, 65537))
	mountsResponse.Body.Close()
	if readErr != nil || len(mountsData) > 65536 || mountsResponse.StatusCode != http.StatusOK || mountsResponse.Header.Get("Cache-Control") != "no-store" {
		return errors.New("invalid mount inventory response")
	}
	var mounts mountSnapshot
	if json.Unmarshal(mountsData, &mounts) != nil || mounts.SchemaVersion != 1 || mounts.ObservedAt.IsZero() ||
		mounts.Scope != "current-process-mount-namespace" || !mounts.ReadOnly || mounts.FilesystemContentsRead ||
		mounts.MountOperationsPerformed || mounts.MountCount != len(mounts.Mounts) || mounts.MountCount > maxMountEntries || mounts.Mounts == nil {
		return errors.New("mount observation crossed or overstated its read-only boundary")
	}
	for _, mount := range mounts.Mounts {
		if len(mount.MountPoint) == 0 || mount.MountPoint[0] != '/' || !validMountFilesystem(mount.Filesystem) {
			return errors.New("mount observation contains an invalid bounded field")
		}
	}
	if strings.Contains(string(mountsData), "/dev/sda") || strings.Contains(string(mountsData), "errors=continue") {
		return errors.New("mount source or raw mount option leaked through the API")
	}
	for _, asset := range qemuDashboardAssets {
		response, err := client.Get("http://" + listenAddress + asset.path)
		if err != nil {
			return errors.New("dashboard loopback request failed")
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, 65537))
		response.Body.Close()
		if readErr != nil || len(data) > 65536 || response.StatusCode != http.StatusOK ||
			response.Header.Get("Content-Type") != asset.contentType || response.Header.Get("Cache-Control") != "no-store" {
			return errors.New("invalid embedded dashboard asset")
		}
		for _, marker := range asset.markers {
			if !strings.Contains(string(data), marker) {
				return errors.New("dashboard asset failed its content assertion")
			}
		}
		if asset.path == "/" && response.Header.Get("Content-Security-Policy") != "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" {
			return errors.New("dashboard policy headers are missing or permissive")
		}
	}
	for _, check := range []struct {
		method, path string
		status       int
	}{
		{http.MethodPost, "/api/v1/system", http.StatusMethodNotAllowed},
		{http.MethodGet, "/api/v1/system?path=/dev/mtd3", http.StatusBadRequest},
		{http.MethodPost, "/api/v1/storage", http.StatusMethodNotAllowed},
		{http.MethodGet, "/api/v1/storage?device=/dev/sda", http.StatusBadRequest},
		{http.MethodPost, "/api/v1/arrays", http.StatusMethodNotAllowed},
		{http.MethodGet, "/api/v1/arrays?device=/dev/sda", http.StatusBadRequest},
		{http.MethodPost, "/api/v1/mounts", http.StatusMethodNotAllowed},
		{http.MethodGet, "/api/v1/mounts?path=/dev/sda", http.StatusBadRequest},
		{http.MethodPost, "/", http.StatusMethodNotAllowed},
		{http.MethodGet, "/assets/app.js?file=/etc/passwd", http.StatusBadRequest},
		{http.MethodGet, "/api/v1/reboot", http.StatusNotFound},
	} {
		request, err := http.NewRequest(check.method, "http://"+listenAddress+check.path, nil)
		if err != nil {
			return err
		}
		response, err := client.Do(request)
		if err != nil {
			return errors.New("negative loopback request failed")
		}
		response.Body.Close()
		if response.StatusCode != check.status {
			return errors.New("unsafe method, query, or route accepted")
		}
	}
	fmt.Printf("PHANTOWD_UI_READY mode=development assets_verified=true activation=false transport=guest-loopback-only\n")
	fmt.Printf("PHANTOWD_AUTH_READY algorithm=argon2id kdf_concurrency=1 bootstrap=%s login_enabled=yes transport=guest-loopback-http state=volatile-qemu session=memory-only kdf_cycle_ms=%d\n", bootstrap, argon2CycleMillis)
	fmt.Printf("PHANTOWD_API_READY target=qemu-armv5 goarm=%s uid=%d memory_total_bytes=%d storage_observations=%d arrays=%d array_status=%s identity_metadata=serial+naa-wwn flashable=no hardware_validated=no\n",
		snapshot.GOARM, snapshot.EffectiveUID, snapshot.Memory.TotalBytes, storage.DeviceCount, arrays.ArrayCount, arrays.Status)
	return nil
}

func validArrayInventoryStatus(status arrayInventoryStatus) bool {
	switch status {
	case arrayInventoryAvailable, arrayInventoryPartial, arrayInventoryUnavailable, arrayInventoryUnsupported:
		return true
	default:
		return false
	}
}

func validArrayHealth(health arrayHealth) bool {
	switch health {
	case arrayHealthHealthy, arrayHealthDegraded, arrayHealthSyncing, arrayHealthPaused, arrayHealthInactive, arrayHealthUnknown:
		return true
	default:
		return false
	}
}

func newQEMUCookieJar() *cookiejar.Jar {
	jar, _ := cookiejar.New(nil)
	return jar
}

func waitQEMUAPIReady(client *http.Client, baseURL string) error {
	const attempts = 20
	for attempt := 0; attempt < attempts; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/healthz", nil)
		if err != nil {
			cancel()
			return errors.New("invalid API readiness URL")
		}
		response, requestErr := client.Do(request)
		if requestErr == nil {
			data, readErr := io.ReadAll(io.LimitReader(response.Body, 257))
			response.Body.Close()
			if readErr == nil && len(data) <= 256 && response.StatusCode == http.StatusOK &&
				response.Header.Get("Cache-Control") == "no-store" {
				var health map[string]string
				if json.Unmarshal(data, &health) == nil && health["status"] == "ok" && health["scope"] == "process_only" {
					cancel()
					return nil
				}
			}
		}
		cancel()
		if attempt+1 < attempts {
			time.Sleep(250 * time.Millisecond)
		}
	}
	return errors.New("read-only API readiness probe timed out")
}

func exerciseQEMUAuth(client *http.Client) (string, error) {
	response, err := client.Get("http://" + listenAddress + authStatusPath)
	if err != nil {
		return "", errors.New("authentication status request failed")
	}
	data, err := readSelfTestResponse(response, 4096)
	if err != nil || response.StatusCode != http.StatusOK {
		return "", errors.New("authentication status response invalid")
	}
	var status authStatus
	if err := json.Unmarshal(data, &status); err != nil {
		return "", errors.New("authentication status JSON invalid")
	}
	unauthorized, err := client.Get("http://" + listenAddress + "/api/v1/system")
	if err != nil {
		return "", errors.New("unauthenticated diagnostics check failed")
	}
	unauthorized.Body.Close()
	if unauthorized.StatusCode != http.StatusUnauthorized {
		return "", errors.New("diagnostics were available before authentication")
	}
	bootstrap := "existing"
	credentials := loginRequest{Username: "qemu-admin", Password: "qemu-self-test-only"}
	if status.SetupRequired {
		body, _ := json.Marshal(setupRequest(credentials))
		response, err = postQEMUAuth(client, authSetupPath, body)
		if err != nil {
			return "", errors.New("first-account request failed")
		}
		response.Body.Close()
		if response.StatusCode != http.StatusCreated {
			return "", errors.New("first-account setup failed")
		}
		bootstrap = "created"
		body, _ = json.Marshal(setupRequest(credentials))
		response, err = postQEMUAuth(client, authSetupPath, body)
		if err != nil {
			return "", errors.New("one-time setup rejection request failed")
		}
		response.Body.Close()
		if response.StatusCode != http.StatusConflict {
			return "", errors.New("one-time administrator setup was not enforced")
		}
	} else {
		body, _ := json.Marshal(credentials)
		response, err = postQEMUAuth(client, authLoginPath, body)
		if err != nil {
			return "", errors.New("existing administrator login request failed")
		}
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return "", errors.New("existing administrator login failed")
		}
	}

	wrong := loginRequest{Username: credentials.Username, Password: "incorrect but sufficiently long"}
	body, _ := json.Marshal(wrong)
	response, err = postQEMUAuth(client, authLoginPath, body)
	if err != nil {
		return "", errors.New("wrong-password request failed")
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		return "", errors.New("wrong password was not rejected")
	}

	response, err = client.Get("http://" + listenAddress + authSessionPath)
	if err != nil {
		return "", errors.New("session request failed")
	}
	data, err = readSelfTestResponse(response, 4096)
	if err != nil || response.StatusCode != http.StatusOK {
		return "", errors.New("authenticated session response invalid")
	}
	var session struct {
		CSRFToken string `json:"csrf_token"`
	}
	if json.Unmarshal(data, &session) != nil || session.CSRFToken == "" {
		return "", errors.New("session CSRF token missing")
	}
	response, err = postQEMUAuth(client, authLogoutPath, nil)
	if err != nil {
		return "", errors.New("CSRF rejection request failed")
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		return "", errors.New("logout without CSRF token was accepted")
	}
	request, _ := http.NewRequest(http.MethodPost, "http://"+listenAddress+authLogoutPath, nil)
	request.Header.Set("Origin", "http://"+listenAddress)
	request.Header.Set("X-PhantoWD-CSRF", session.CSRFToken)
	response, err = client.Do(request)
	if err != nil {
		return "", errors.New("logout request failed")
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", errors.New("authenticated logout failed")
	}
	unauthorized, err = client.Get("http://" + listenAddress + "/api/v1/system")
	if err != nil {
		return "", errors.New("post-logout authorization check failed")
	}
	unauthorized.Body.Close()
	if unauthorized.StatusCode != http.StatusUnauthorized {
		return "", errors.New("revoked session remained authorized")
	}
	body, _ = json.Marshal(credentials)
	response, err = postQEMUAuth(client, authLoginPath, body)
	if err != nil {
		return "", errors.New("post-logout login request failed")
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", errors.New("login after logout failed")
	}
	if err := exerciseQEMURevokePanelSessions(client, credentials); err != nil {
		return "", err
	}
	return bootstrap, nil
}

func exerciseQEMURevokePanelSessions(client *http.Client, credentials loginRequest) error {
	peer := &http.Client{Timeout: client.Timeout, Jar: newQEMUCookieJar()}
	defer peer.CloseIdleConnections()
	body, _ := json.Marshal(credentials)
	response, err := postQEMUAuth(peer, authLoginPath, body)
	if err != nil {
		return err
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("peer session login failed")
	}
	response, err = peer.Get("http://" + listenAddress + authSessionPath)
	if err != nil {
		return err
	}
	data, err := readSelfTestResponse(response, 4096)
	var session struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err != nil || response.StatusCode != http.StatusOK || json.Unmarshal(data, &session) != nil || session.CSRFToken == "" {
		return errors.New("peer CSRF unavailable")
	}
	request, _ := http.NewRequest(http.MethodPost, "http://"+listenAddress+authLogoutAllPath, nil)
	request.Header.Set("Origin", "http://"+listenAddress)
	request.Header.Set("X-PhantoWD-CSRF", session.CSRFToken)
	response, err = peer.Do(request)
	if err != nil {
		return err
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("global session revocation failed")
	}
	for _, c := range []*http.Client{client, peer} {
		response, err := c.Get("http://" + listenAddress + "/api/v1/system")
		if err != nil {
			return err
		}
		response.Body.Close()
		if response.StatusCode != http.StatusUnauthorized {
			return errors.New("old panel session survived revocation")
		}
	}
	response, err = postQEMUAuth(client, authLoginPath, body)
	if err != nil {
		return err
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("fresh login after global revocation failed")
	}
	fmt.Println("PHANTOWD_SESSION_REVOCATION_READY peers=2 old_sessions_denied=true fresh_login=true scope=panel-sessions-only")
	return nil
}

func postQEMUAuth(client *http.Client, path string, body []byte) (*http.Response, error) {
	request, err := http.NewRequest(http.MethodPost, "http://"+listenAddress+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Origin", "http://"+listenAddress)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	return client.Do(request)
}

func readSelfTestResponse(response *http.Response, limit int64) ([]byte, error) {
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("response exceeded the self-test bound")
	}
	return data, nil
}

func exerciseQEMUGPTObservation(client *http.Client, origin string) error {
	sessionResponse, err := client.Get(origin + authSessionPath)
	if err != nil {
		return errors.New("GPT observation session request failed")
	}
	sessionData, err := readSelfTestResponse(sessionResponse, 4096)
	var session struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err != nil || sessionResponse.StatusCode != http.StatusOK || json.Unmarshal(sessionData, &session) != nil || session.CSRFToken == "" {
		return errors.New("GPT observation session was unavailable")
	}
	request, err := http.NewRequest(http.MethodPost, origin+storageGPTObservationPath, nil)
	if err != nil {
		return errors.New("GPT observation request could not be created")
	}
	request.Header.Set("Origin", origin)
	request.Header.Set("X-PhantoWD-CSRF", session.CSRFToken)
	response, err := client.Do(request)
	if err != nil {
		return errors.New("explicit GPT observation request failed")
	}
	data, err := readSelfTestResponse(response, 16384)
	if err != nil || response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" {
		return errors.New("explicit GPT observation returned an invalid response")
	}
	var summary storageGPTObservationSummary
	if json.Unmarshal(data, &summary) != nil || !validStorageGPTObservationSummary(summary) ||
		summary.EligibleCandidateCount != storageGPTObservationMaxDisks || summary.GPTDiskCount != 2 || summary.PartitionCount != 2 ||
		summary.AmbiguousDiskGUIDCount != 2 || summary.AmbiguousPARTUUIDCount != 2 {
		return errors.New("GPT observation did not summarize the complete cloned-GPT fixture as ambiguous")
	}
	for _, private := range []string{
		qemuGPTDiskGUID, qemuGPTPartUUID, qemuGPTTypeGUID,
		"2048", "63455",
		"sdd", "sdg", "/dev/", `"disk_guid":`, `"partuuid":`, `"partition_number":`,
		`"start_512b_sectors":`, `"kernel_name":`,
	} {
		if strings.Contains(string(data), private) {
			return errors.New("explicit GPT observation exposed private identifiers or geometry")
		}
	}
	fmt.Println("PHANTOWD_GPT_OBSERVATION_READY eligible=6 gpt_disks=2 partitions=2 duplicate_disk_guids=2 duplicate_partuuids=2 summary_only=true normal_refresh_redacted=true auth=true csrf=true manual=true read_only=true no_mount=true no_mutation=true scope=qemu-fixture-only")
	return nil
}
