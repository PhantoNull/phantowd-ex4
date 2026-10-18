// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"io"
	"io/fs"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const maxKernelThermalZones = 8

// Kernel reports only: these names/types do not identify physical sensors, and
// reading a driver attribute establishes neither calibration nor sample age.
type kernelThermalObservation struct {
	SchemaVersion     int                 `json:"schema_version"`
	Scope             string              `json:"scope"`
	ReadOnly          bool                `json:"read_only"`
	HardwareQualified bool                `json:"hardware_qualified"`
	ControlAvailable  bool                `json:"control_available"`
	Status            string              `json:"status"`
	Zones             []kernelThermalZone `json:"zones"`
}

type kernelThermalZone struct {
	Name         string `json:"name"`
	Type         string `json:"type,omitempty"`
	Status       string `json:"status"`
	MilliCelsius *int32 `json:"milli_celsius,omitempty"`
}

func collectKernelThermal(sysfs fs.FS) kernelThermalObservation {
	result := kernelThermalObservation{SchemaVersion: 1, Scope: "kernel-thermal-sysfs-only", ReadOnly: true,
		Status: "unavailable", Zones: []kernelThermalZone{}}
	if sysfs == nil {
		return result
	}
	names, err := kernelThermalNames(sysfs)
	if err != nil {
		return result
	}
	zones := make([]kernelThermalZone, 0, len(names))
	status := "available"
	for _, name := range names {
		zone := kernelThermalZone{Name: name, Status: "unavailable"}
		kind, kindErr := kernelThermalText(sysfs, "class/thermal/"+name+"/type")
		if kindErr == nil && len(kind) > 0 && len(kind) <= 64 && utf8.ValidString(kind) && !strings.ContainsFunc(kind, unicode.IsControl) {
			zone.Type = kind
			temp, tempErr := kernelThermalText(sysfs, "class/thermal/"+name+"/temp")
			if value, parseErr := strconv.ParseInt(temp, 10, 32); tempErr == nil && parseErr == nil && strconv.FormatInt(value, 10) == temp {
				milli := int32(value)
				zone.MilliCelsius, zone.Status = &milli, "reported"
			}
		}
		if zone.Status != "reported" {
			status = "partial"
		}
		zones = append(zones, zone)
	}
	// Name-set bracketing is only a limited consistency check. Same-name/type
	// replacement, driver caching and physical sensor identity are not qualified.
	after, err := kernelThermalNames(sysfs)
	if err != nil || !slices.Equal(names, after) {
		return result
	}
	result.Status, result.Zones = status, zones
	return result
}

// No eager ReadDir/ReadFile helper: bound directory entries and attribute bytes
// even when supplied by an unusual filesystem. No path is request-controlled.
func kernelThermalNames(source fs.FS) ([]string, error) {
	dir, err := source.Open("class/thermal")
	if err != nil {
		return nil, err
	}
	reader, ok := dir.(fs.ReadDirFile)
	var names []string
	if ok {
		for count := 0; ; {
			entries, readErr := reader.ReadDir(16)
			count += len(entries)
			if len(entries) > 16 || count > 128 {
				err = errors.New("thermal directory bound exceeded")
				break
			}
			for _, entry := range entries {
				if entry == nil {
					err = errors.New("invalid thermal entry")
					break
				}
				name := entry.Name()
				if !strings.HasPrefix(name, "thermal_zone") {
					continue
				}
				number := strings.TrimPrefix(name, "thermal_zone")
				n, parseErr := strconv.ParseUint(number, 10, 32)
				if parseErr != nil || strconv.FormatUint(n, 10) != number || slices.Contains(names, name) || len(names) >= maxKernelThermalZones {
					err = errors.New("invalid thermal zone set")
					break
				}
				names = append(names, name)
			}
			if err != nil {
				break
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil || len(entries) == 0 {
				err = errors.New("incomplete thermal directory")
				break
			}
		}
	} else {
		err = errors.New("thermal directory unavailable")
	}
	closeErr := dir.Close()
	if err != nil || closeErr != nil {
		return nil, errors.New("thermal directory unavailable")
	}
	slices.Sort(names)
	return names, nil
}

func kernelThermalText(source fs.FS, path string) (string, error) {
	file, err := source.Open(path)
	if err != nil {
		return "", err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, 129))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(data) > 128 {
		return "", errors.New("thermal attribute unavailable")
	}
	return strings.TrimSuffix(string(data), "\n"), nil
}

func collectSystemWithThermal(proc, sysfs fs.FS, now time.Time) (systemSnapshot, error) {
	snapshot, err := collectSystem(proc, now)
	if err != nil {
		return snapshot, err
	}
	thermal := collectKernelThermal(sysfs)
	snapshot.Thermal = &thermal
	return snapshot, nil
}
