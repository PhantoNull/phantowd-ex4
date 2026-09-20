// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

const maxProcBytes = 64 * 1024

type memoryInfo struct {
	TotalBytes     uint64 `json:"total_bytes"`
	AvailableBytes uint64 `json:"available_bytes"`
}

type systemSnapshot struct {
	SchemaVersion     int        `json:"schema_version"`
	Target            string     `json:"target"`
	Mode              string     `json:"mode"`
	Flashable         bool       `json:"flashable"`
	HardwareValidated bool       `json:"hardware_validated"`
	ObservedAt        time.Time  `json:"observed_at"`
	Architecture      string     `json:"architecture"`
	GOARM             string     `json:"goarm"`
	Kernel            string     `json:"kernel"`
	UptimeSeconds     float64    `json:"uptime_seconds"`
	Memory            memoryInfo `json:"memory"`
	EffectiveUID      int        `json:"effective_uid"`
}

// Only these fixed proc paths are ever opened. No request controls a file path.
func collectSystem(proc fs.FS, now time.Time) (systemSnapshot, error) {
	var snapshot systemSnapshot
	kernel, err := readBounded(proc, "sys/kernel/osrelease")
	if err != nil {
		return snapshot, err
	}
	kernelVersion := strings.TrimSpace(string(kernel))
	if len(kernelVersion) == 0 || len(kernelVersion) > 128 {
		return snapshot, errors.New("invalid kernel release")
	}
	for _, character := range kernelVersion {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_+", character) {
			return snapshot, errors.New("invalid kernel release")
		}
	}
	uptimeData, err := readBounded(proc, "uptime")
	if err != nil {
		return snapshot, err
	}
	uptime, err := parseUptime(string(uptimeData))
	if err != nil {
		return snapshot, err
	}
	memoryData, err := readBounded(proc, "meminfo")
	if err != nil {
		return snapshot, err
	}
	memory, err := parseMemory(string(memoryData))
	if err != nil {
		return snapshot, err
	}
	return systemSnapshot{
		SchemaVersion: 1, Target: "qemu-armv5", Mode: "development",
		Flashable: false, HardwareValidated: false, ObservedAt: now.UTC(),
		Architecture: runtime.GOARCH, GOARM: buildARMLevel(), Kernel: kernelVersion,
		UptimeSeconds: uptime, Memory: memory, EffectiveUID: os.Geteuid(),
	}, nil
}

func readBounded(source fs.FS, path string) ([]byte, error) {
	file, err := source.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxProcBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxProcBytes {
		return nil, errors.New("proc input exceeds size limit")
	}
	return data, nil
}

func parseUptime(data string) (float64, error) {
	fields := strings.Fields(data)
	if len(fields) != 2 {
		return 0, errors.New("invalid uptime")
	}
	for _, field := range fields {
		value, err := strconv.ParseFloat(field, 64)
		if err != nil || value < 0 || math.IsNaN(value) || math.IsInf(value, 0) {
			return 0, errors.New("invalid uptime")
		}
	}
	return strconv.ParseFloat(fields[0], 64)
}

func parseMemory(data string) (memoryInfo, error) {
	values := make(map[string]uint64, 2)
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || (fields[0] != "MemTotal:" && fields[0] != "MemAvailable:") {
			continue
		}
		if _, duplicate := values[fields[0]]; duplicate || len(fields) != 3 || fields[2] != "kB" {
			return memoryInfo{}, errors.New("invalid memory field")
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil || value > math.MaxUint64/1024 {
			return memoryInfo{}, errors.New("invalid memory value")
		}
		values[fields[0]] = value * 1024
	}
	total, hasTotal := values["MemTotal:"]
	available, hasAvailable := values["MemAvailable:"]
	if !hasTotal || !hasAvailable || total == 0 || available > total {
		return memoryInfo{}, fmt.Errorf("incomplete or inconsistent memory information")
	}
	return memoryInfo{TotalBytes: total, AvailableBytes: available}, nil
}

func buildARMLevel() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "GOARM" {
				return setting.Value
			}
		}
	}
	return ""
}
