// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func fixtureThermal() fstest.MapFS {
	return fstest.MapFS{
		"class/thermal/thermal_zone0/type":        {Data: []byte("synthetic-board\n")},
		"class/thermal/thermal_zone0/temp":        {Data: []byte("42125\n")},
		"class/thermal/thermal_zone1/type":        {Data: []byte("synthetic-other\n")},
		"class/thermal/thermal_zone1/temp":        {Data: []byte("0\n")},
		"class/thermal/cooling_device0/cur_state": {Data: []byte("DO-NOT-READ")},
	}
}

func TestKernelThermalReportedValuesAndBoundaries(t *testing.T) {
	for _, number := range []string{"0", "-1250", "42125", "-2147483648", "2147483647"} {
		f := fixtureThermal()
		f["class/thermal/thermal_zone0/temp"].Data = []byte(number + "\n")
		got := collectKernelThermal(f)
		if got.Status != "available" || len(got.Zones) != 2 || !got.ReadOnly || got.HardwareQualified || got.ControlAvailable || got.SchemaVersion != 1 || got.Scope != "kernel-thermal-sysfs-only" {
			t.Fatalf("lost kernel-report boundary: %+v", got)
		}
		if got.Zones[0].MilliCelsius == nil || fmt.Sprint(*got.Zones[0].MilliCelsius) != number || *got.Zones[1].MilliCelsius != 0 {
			t.Fatalf("reported integer lost: %+v", got.Zones)
		}
	}
	for _, text := range []string{"", "01\n", "+1\n", "-0\n", "1.5\n", "1e3\n", " 1\n", "1\r\n", "1\n\n", "2147483648\n", "-2147483649\n", strings.Repeat("1", 129)} {
		f := fixtureThermal()
		f["class/thermal/thermal_zone0/temp"].Data = []byte(text)
		got := collectKernelThermal(f)
		if got.Status != "partial" || got.Zones[0].MilliCelsius != nil || got.Zones[0].Status != "unavailable" || got.Zones[1].Status != "reported" {
			t.Fatalf("invalid sample became a value for %q", text)
		}
		wire, _ := json.Marshal(got.Zones[0])
		if strings.Contains(string(wire), "milli_celsius") {
			t.Fatal("missing sample encoded as zero")
		}
	}
	for _, kind := range []string{"", "bad\nlabel\n", "bad\x00", "bad\x7f", "bad\u0085", strings.Repeat("x", 65), "\xff"} {
		f := fixtureThermal()
		f["class/thermal/thermal_zone0/type"].Data = []byte(kind)
		spy := &thermalFS{base: f}
		if got := collectKernelThermal(spy); got.Status != "partial" || got.Zones[0].MilliCelsius != nil {
			t.Fatal("invalid type admitted")
		}
		for _, path := range spy.paths {
			if path == "class/thermal/thermal_zone0/temp" {
				t.Fatal("unidentified zone still measured")
			}
		}
	}
}

type thermalFS struct {
	base  fs.FS
	open  func(string, fs.File) (fs.File, error)
	paths []string
}

func (f *thermalFS) Open(path string) (fs.File, error) {
	f.paths = append(f.paths, path)
	file, err := f.base.Open(path)
	if err != nil {
		return nil, err
	}
	if f.open != nil {
		return f.open(path, file)
	}
	return file, nil
}

type thermalFaultFile struct {
	fs.File
	readError, closeError bool
	readBytes, closes     int
}

func (f *thermalFaultFile) Read(p []byte) (int, error) {
	if f.readError {
		return 0, errors.New("PRIVATE sample path")
	}
	n, err := f.File.Read(p)
	f.readBytes += n
	return n, err
}
func (f *thermalFaultFile) Close() error {
	f.closes++
	err := f.File.Close()
	if f.closeError {
		return errors.New("PRIVATE close path")
	}
	return err
}

type thermalFaultDir struct {
	fs.ReadDirFile
	empty      bool
	fault      bool
	closeError bool
	closes     int
}

func (d *thermalFaultDir) ReadDir(n int) ([]fs.DirEntry, error) {
	if d.empty {
		return nil, nil
	}
	if d.fault {
		return nil, errors.New("PRIVATE directory")
	}
	return d.ReadDirFile.ReadDir(n)
}
func (d *thermalFaultDir) Close() error {
	d.closes++
	err := d.ReadDirFile.Close()
	if d.closeError {
		return errors.New("PRIVATE directory close")
	}
	return err
}

func TestKernelThermalLimitsFailuresAndNoFallback(t *testing.T) {
	for _, failure := range []string{"read", "close", "oversize"} {
		base := fixtureThermal()
		if failure == "oversize" {
			base["class/thermal/thermal_zone0/temp"].Data = []byte(strings.Repeat("1", 10000))
		}
		var original *thermalFaultFile
		f := &thermalFS{base: base, open: func(path string, file fs.File) (fs.File, error) {
			if path != "class/thermal/thermal_zone0/temp" {
				return file, nil
			}
			original = &thermalFaultFile{File: file, readError: failure == "read", closeError: failure == "close"}
			return original, nil
		}}
		got := collectKernelThermal(f)
		if got.Status != "partial" || original == nil || original.closes != 1 || original.readBytes > 129 || got.Zones[0].MilliCelsius != nil {
			t.Fatalf("unbounded/retried fault %s", failure)
		}
		count := 0
		for _, path := range f.paths {
			if path == "class/thermal/thermal_zone0/temp" {
				count++
			}
			if strings.Contains(path, "cooling_device") {
				t.Fatal("cooling attribute read")
			}
		}
		if count != 1 {
			t.Fatal("sample retried")
		}
		wire, _ := json.Marshal(got)
		if strings.Contains(string(wire), "PRIVATE") {
			t.Fatal("error detail escaped")
		}
	}
	for _, failure := range []string{"empty", "read", "close"} {
		var original *thermalFaultDir
		f := &thermalFS{base: fixtureThermal(), open: func(path string, file fs.File) (fs.File, error) {
			if path != "class/thermal" {
				return file, nil
			}
			original = &thermalFaultDir{ReadDirFile: file.(fs.ReadDirFile), empty: failure == "empty", fault: failure == "read", closeError: failure == "close"}
			return original, nil
		}}
		got := collectKernelThermal(f)
		if got.Status != "unavailable" || len(got.Zones) != 0 || original.closes != 1 {
			t.Fatal("incomplete directory accepted")
		}
	}
	for _, f := range []fs.FS{nil, fstest.MapFS{}, fstest.MapFS{"class/thermal": {Mode: fs.ModeDir}}} {
		got := collectKernelThermal(f)
		if got.Zones == nil || got.HardwareQualified || got.ControlAvailable {
			t.Fatal("invalid empty/unavailable boundary")
		}
	}
	for _, count := range []int{8, 9, 129} {
		f := fstest.MapFS{}
		for i := 0; i < count; i++ {
			prefix := fmt.Sprintf("class/thermal/thermal_zone%d/", i)
			f[prefix+"type"] = &fstest.MapFile{Data: []byte("synthetic\n")}
			f[prefix+"temp"] = &fstest.MapFile{Data: []byte("0\n")}
		}
		got := collectKernelThermal(f)
		if count == 8 {
			if len(got.Zones) != 8 || got.Status != "available" {
				t.Fatal("inclusive maximum refused")
			}
		} else if got.Status != "unavailable" || len(got.Zones) != 0 {
			t.Fatal("oversized inventory published")
		}
	}
	for _, name := range []string{"thermal_zone01", "thermal_zone-1", "thermal_zone4294967296", "thermal_zoneoops"} {
		f := fixtureThermal()
		f["class/thermal/"+name+"/temp"] = &fstest.MapFile{Data: []byte("1\n")}
		if got := collectKernelThermal(f); got.Status != "unavailable" || len(got.Zones) != 0 {
			t.Fatal("malformed zone name accepted")
		}
	}
}

func TestKernelThermalCompleteDirectoryBound(t *testing.T) {
	for _, count := range []int{128, 129} {
		f := fstest.MapFS{}
		for i := 0; i < count; i++ {
			f[fmt.Sprintf("class/thermal/cooling_device%d/ignored", i)] = &fstest.MapFile{Data: []byte("not read")}
		}
		got := collectKernelThermal(f)
		if (count == 128 && got.Status != "available") || (count == 129 && got.Status != "unavailable") || len(got.Zones) != 0 {
			t.Fatal("directory entry bound not enforced")
		}
	}
}

func TestSystemThermalIntegrationAndNameSetChange(t *testing.T) {
	base := fixtureThermal()
	before := collectKernelThermal(base)
	if before.Status != "available" {
		t.Fatal("fixture invalid")
	}
	f := &thermalFS{base: base, open: func(path string, file fs.File) (fs.File, error) {
		if path == "class/thermal/thermal_zone1/temp" {
			base["class/thermal/thermal_zone2/type"] = &fstest.MapFile{Data: []byte("replacement\n")}
			base["class/thermal/thermal_zone2/temp"] = &fstest.MapFile{Data: []byte("1000\n")}
		}
		return file, nil
	}}
	if got := collectKernelThermal(f); got.Status != "unavailable" || len(got.Zones) != 0 {
		t.Fatal("changed roster published old values")
	}
	got, err := collectSystemWithThermal(fixtureProc(), fstest.MapFS{}, time.Now())
	if err != nil || got.Thermal == nil || got.Thermal.Status != "unavailable" || got.Kernel != "6.18.53" {
		t.Fatal("thermal failure hid valid system data")
	}
	spy := &thermalFS{base: fixtureThermal()}
	got, err = collectSystemWithThermal(fstest.MapFS{}, spy, time.Now())
	if err == nil || got.Thermal != nil || len(spy.paths) != 0 {
		t.Fatal("invalid system continued hardware reads")
	}
	first := collectKernelThermal(fixtureThermal())
	second := collectKernelThermal(fixtureThermal())
	if !reflect.DeepEqual(first, second) {
		t.Fatal("non-deterministic fixture")
	}
	maximum := fstest.MapFS{}
	for i := 0; i < 8; i++ {
		prefix := fmt.Sprintf("class/thermal/thermal_zone%d/", i)
		maximum[prefix+"type"] = &fstest.MapFile{Data: []byte(strings.Repeat("<", 64))}
		maximum[prefix+"temp"] = &fstest.MapFile{Data: []byte("-2147483648\n")}
	}
	full, err := collectSystemWithThermal(fixtureProc(), maximum, time.Now())
	wire, encodeErr := json.Marshal(full)
	if err != nil || encodeErr != nil || full.Thermal.Status != "available" || len(wire) > 16*1024 {
		t.Fatal("thermal envelope exceeds existing system reply budget")
	}
}
