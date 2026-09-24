// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"time"
)

const (
	qemuTestSerial = "PHANTOWD-QEMU-SERIAL-01"
	qemuTestWWN    = "500f000000000001"
)

func runSelfTest() error {
	if runtime.GOARCH != "arm" || strings.Split(buildARMLevel(), ",")[0] != "5" {
		return errors.New("self-test requires the ARMv5 QEMU target")
	}
	client := &http.Client{
		Timeout:       5 * time.Second,
		Transport:     &http.Transport{Proxy: nil, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer client.CloseIdleConnections()
	var snapshot systemSnapshot
	for _, path := range []string{"/healthz", "/api/v1/system"} {
		response, err := client.Get("http://" + listenAddress + path)
		if err != nil {
			return errors.New("loopback request failed")
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
		response.Body.Close()
		if readErr != nil || len(data) > 4096 || response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" {
			return errors.New("invalid read response")
		}
		if path == "/healthz" {
			var health map[string]string
			if json.Unmarshal(data, &health) != nil || health["status"] != "ok" || health["scope"] != "process_only" {
				return errors.New("invalid process health")
			}
		} else if json.Unmarshal(data, &snapshot) != nil {
			return errors.New("invalid system JSON")
		}
	}
	if snapshot.SchemaVersion != 1 || snapshot.Target != "qemu-armv5" || snapshot.Mode != "development" ||
		snapshot.Flashable || snapshot.HardwareValidated || snapshot.Architecture != "arm" ||
		strings.Split(snapshot.GOARM, ",")[0] != "5" || snapshot.EffectiveUID <= 0 || snapshot.Kernel == "" ||
		snapshot.ObservedAt.IsZero() || snapshot.UptimeSeconds <= 0 || snapshot.Memory.TotalBytes == 0 ||
		snapshot.Memory.AvailableBytes == 0 || snapshot.Memory.AvailableBytes > snapshot.Memory.TotalBytes {
		return errors.New("invalid development snapshot or privileged server")
	}
	storageResponse, err := client.Get("http://" + listenAddress + "/api/v1/storage")
	if err != nil {
		return errors.New("storage loopback request failed")
	}
	storageData, readErr := io.ReadAll(io.LimitReader(storageResponse.Body, 4097))
	storageResponse.Body.Close()
	if readErr != nil || len(storageData) > 4096 || storageResponse.StatusCode != http.StatusOK || storageResponse.Header.Get("Cache-Control") != "no-store" {
		return errors.New("invalid storage observation response")
	}
	var storage storageSnapshot
	if json.Unmarshal(storageData, &storage) != nil || storage.SchemaVersion != 1 || storage.Scope != "kernel-sysfs-only" ||
		!storage.InventoryReadOnly || storage.BlockDevicesOpened || storage.ContentRead || storage.MutationsPerformed ||
		storage.StableIdentityAvailable || storage.DeviceCount != len(storage.Observations) {
		return errors.New("storage observation crossed or overstated its read-only boundary")
	}
	rootDiskFound := false
	rootDiskIdentityPagesFound := false
	for _, observation := range storage.Observations {
		if observation.Name == "sda" && observation.Kind == "block" && observation.SizeBytes > 0 {
			rootDiskFound = true
			rootDiskIdentityPagesFound = observation.SerialStatus == identityPresent && observation.WWNStatus == identityPresent
		}
	}
	if !rootDiskFound {
		return errors.New("QEMU root block device was not observed through sysfs")
	}
	if !rootDiskIdentityPagesFound {
		return errors.New("QEMU SCSI identity pages were not observed and validated through sysfs")
	}
	if strings.Contains(string(storageData), qemuTestSerial) || strings.Contains(string(storageData), qemuTestWWN) {
		return errors.New("raw QEMU storage identifiers leaked through the API")
	}
	for _, asset := range []struct {
		path, contentType string
		markers           []string
	}{
		{"/", "text/html; charset=utf-8", []string{"PhantoWD EX4", "Development profile", "hardware_validated"}},
		{"/assets/app.css", "text/css; charset=utf-8", []string{"@media", "prefers-reduced-motion"}},
		{"/assets/app.js", "text/javascript; charset=utf-8", []string{"/api/v1/system", "/api/v1/storage", "textContent"}},
		{"/assets/ghost.svg", "image/svg+xml", []string{"<svg", "PhantoWD ghost"}},
	} {
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
	fmt.Printf("PHANTOWD_UI_READY mode=development read_only=true transport=guest-loopback-only\n")
	fmt.Printf("PHANTOWD_API_READY target=qemu-armv5 goarm=%s uid=%d memory_total_bytes=%d storage_observations=%d identity_metadata=serial+naa-wwn flashable=no hardware_validated=no\n",
		snapshot.GOARM, snapshot.EffectiveUID, snapshot.Memory.TotalBytes, storage.DeviceCount)
	return nil
}
