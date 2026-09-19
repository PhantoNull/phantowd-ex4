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
	for _, check := range []struct {
		method, path string
		status       int
	}{
		{http.MethodPost, "/api/v1/system", http.StatusMethodNotAllowed},
		{http.MethodGet, "/api/v1/system?path=/dev/mtd3", http.StatusBadRequest},
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
	fmt.Printf("PHANTOWD_API_READY target=qemu-armv5 goarm=%s uid=%d memory_total_bytes=%d flashable=no hardware_validated=no\n",
		snapshot.GOARM, snapshot.EffectiveUID, snapshot.Memory.TotalBytes)
	return nil
}
