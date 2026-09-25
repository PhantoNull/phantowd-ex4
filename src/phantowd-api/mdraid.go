// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"io/fs"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	maxMDArrayEntries  = 16
	maxMDMemberEntries = 32
	maxMDStatLineBytes = 4096
)

type arrayInventoryStatus string

const (
	arrayInventoryAvailable   arrayInventoryStatus = "available"
	arrayInventoryPartial     arrayInventoryStatus = "partial"
	arrayInventoryUnavailable arrayInventoryStatus = "unavailable"
	arrayInventoryUnsupported arrayInventoryStatus = "unsupported"
)

type arrayHealth string

const (
	arrayHealthHealthy  arrayHealth = "healthy"
	arrayHealthDegraded arrayHealth = "degraded"
	arrayHealthSyncing  arrayHealth = "syncing"
	arrayHealthInactive arrayHealth = "inactive"
	arrayHealthUnknown  arrayHealth = "unknown"
)

type mdArraySnapshot struct {
	SchemaVersion      int                  `json:"schema_version"`
	ObservedAt         time.Time            `json:"observed_at"`
	Status             arrayInventoryStatus `json:"status"`
	ReadOnly           bool                 `json:"read_only"`
	BlockDevicesOpened bool                 `json:"block_devices_opened"`
	DiskContentRead    bool                 `json:"disk_content_read"`
	MutationsPerformed bool                 `json:"mutations_performed"`
	ArrayCount         int                  `json:"array_count"`
	Arrays             []mdArrayObservation `json:"arrays"`
	Limitations        []string             `json:"limitations"`
}

type mdArrayObservation struct {
	Name                string                `json:"name"`
	Level               string                `json:"level"`
	State               string                `json:"state"`
	Health              arrayHealth           `json:"health"`
	ExpectedDevices     uint32                `json:"expected_devices,omitempty"`
	ActiveDevices       uint32                `json:"active_devices,omitempty"`
	DegradedDevices     uint32                `json:"degraded_devices,omitempty"`
	SyncAction          string                `json:"sync_action"`
	SyncProgressPercent *float64              `json:"sync_progress_percent,omitempty"`
	Members             []mdMemberObservation `json:"members"`
}

type mdMemberObservation struct {
	Name  string `json:"name"`
	State string `json:"state"`
}

type mdstatRecord struct {
	name            string
	state           string
	level           string
	expectedDevices uint32
	activeDevices   uint32
	countsKnown     bool
	members         []mdMemberObservation
	syncAction      string
	syncProgress    *float64
	memberSlots     string
}

// collectMDArrayInventory observes only the kernel's MD status text and
// sysfs metadata. It never opens a block node or reads/writes disk contents.
// A missing /proc/mdstat is reported as unsupported, never as an empty healthy
// inventory. Partial source disagreement keeps every affected health unknown.
func collectMDArrayInventory(proc, sysfs fs.FS, now time.Time) mdArraySnapshot {
	snapshot := mdArraySnapshot{
		SchemaVersion:      1,
		ObservedAt:         now.UTC(),
		Status:             arrayInventoryUnavailable,
		ReadOnly:           true,
		BlockDevicesOpened: false,
		DiskContentRead:    false,
		MutationsPerformed: false,
		Arrays:             []mdArrayObservation{},
		Limitations: []string{
			"healthy describes only a consistent operational kernel MD state; it does not imply redundancy, filesystem integrity or verified data integrity",
			"member names are transient kernel names; disk serials, bay mapping, SMART and filesystem identity are not inferred",
			"no block device is opened and no array is assembled, stopped, mounted, repaired or modified",
		},
	}

	blockEntries, err := fs.ReadDir(sysfs, "class/block")
	if err != nil || len(blockEntries) > maxBlockEntries {
		return snapshot
	}
	blockNames := make(map[string]bool, len(blockEntries))
	for _, entry := range blockEntries {
		blockNames[entry.Name()] = true
	}
	sysfsArrays := make([]string, 0)
	for name := range blockNames {
		if validMDName(name) {
			sysfsArrays = append(sysfsArrays, name)
		}
	}
	sort.Strings(sysfsArrays)
	if len(sysfsArrays) > maxMDArrayEntries {
		sysfsArrays = sysfsArrays[:maxMDArrayEntries]
		snapshot.Status = arrayInventoryPartial
	}

	data, err := readBounded(proc, "mdstat")
	if errors.Is(err, fs.ErrNotExist) {
		snapshot.Status = arrayInventoryUnsupported
		if len(sysfsArrays) > 0 {
			snapshot.Status = arrayInventoryPartial
			appendSysfsOnlyArrays(&snapshot, sysfs, sysfsArrays)
		}
		return finishMDArraySnapshot(snapshot)
	}
	if err != nil {
		if len(sysfsArrays) > 0 {
			snapshot.Status = arrayInventoryPartial
			appendSysfsOnlyArrays(&snapshot, sysfs, sysfsArrays)
		}
		return finishMDArraySnapshot(snapshot)
	}
	records, err := parseMDStat(string(data))
	if err != nil {
		snapshot.Status = arrayInventoryPartial
		appendSysfsOnlyArrays(&snapshot, sysfs, sysfsArrays)
		return finishMDArraySnapshot(snapshot)
	}
	if snapshot.Status != arrayInventoryPartial {
		snapshot.Status = arrayInventoryAvailable
	}

	arrayNames := make(map[string]bool, len(records))
	for _, record := range records {
		arrayNames[record.name] = true
		observation, complete := readMDArraySysfs(sysfs, record, blockNames[record.name])
		if !complete {
			snapshot.Status = arrayInventoryPartial
		}
		snapshot.Arrays = append(snapshot.Arrays, observation)
	}

	for _, name := range sysfsArrays {
		if arrayNames[name] {
			continue
		}
		observation, _ := readMDArraySysfs(sysfs, mdstatRecord{name: name}, true)
		observation.Health = arrayHealthUnknown
		if observation.State == "inactive" {
			observation.Health = arrayHealthInactive
		}
		snapshot.Status = arrayInventoryPartial
		snapshot.Arrays = append(snapshot.Arrays, observation)
	}

	return finishMDArraySnapshot(snapshot)
}

func appendSysfsOnlyArrays(snapshot *mdArraySnapshot, sysfs fs.FS, names []string) {
	for _, name := range names {
		observation, complete := readMDArraySysfs(sysfs, mdstatRecord{name: name}, true)
		observation.Health = arrayHealthUnknown
		if observation.State == "inactive" {
			observation.Health = arrayHealthInactive
		}
		if !complete {
			snapshot.Status = arrayInventoryPartial
		}
		snapshot.Arrays = append(snapshot.Arrays, observation)
	}
}

func finishMDArraySnapshot(snapshot mdArraySnapshot) mdArraySnapshot {
	sort.Slice(snapshot.Arrays, func(i, j int) bool { return snapshot.Arrays[i].Name < snapshot.Arrays[j].Name })
	if len(snapshot.Arrays) > maxMDArrayEntries {
		snapshot.Arrays = snapshot.Arrays[:maxMDArrayEntries]
		snapshot.Status = arrayInventoryPartial
	}
	snapshot.ArrayCount = len(snapshot.Arrays)
	if snapshot.Status != arrayInventoryPartial {
		if snapshot.Status != arrayInventoryUnsupported && snapshot.Status != arrayInventoryUnavailable {
			snapshot.Status = arrayInventoryAvailable
		}
	}
	return snapshot
}

func parseMDStat(data string) ([]mdstatRecord, error) {
	if len(data) > maxProcBytes {
		return nil, errors.New("mdstat input exceeds size limit")
	}
	records := make([]mdstatRecord, 0)
	byName := make(map[string]int)
	current := -1
	for _, line := range strings.Split(data, "\n") {
		if len(line) > maxMDStatLineBytes {
			return nil, errors.New("mdstat line exceeds size limit")
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == ":" && strings.HasPrefix(fields[0], "md") {
			if !validMDName(fields[0]) || len(fields) < 3 {
				return nil, errors.New("invalid mdstat array header")
			}
			if _, duplicate := byName[fields[0]]; duplicate || len(records) >= maxMDArrayEntries {
				return nil, errors.New("duplicate or excessive mdstat arrays")
			}
			state := fields[2]
			if state != "active" && state != "inactive" {
				return nil, errors.New("invalid mdstat array state")
			}
			record := mdstatRecord{
				name: fields[0], state: state, level: "unknown", syncAction: "idle",
				members: []mdMemberObservation{},
			}
			memberStart := 3
			if memberStart < len(fields) && strings.HasPrefix(fields[memberStart], "(") && strings.HasSuffix(fields[memberStart], ")") {
				memberStart++
			}
			if memberStart < len(fields) && validMDLevel(fields[memberStart]) {
				record.level = fields[memberStart]
				memberStart++
			}
			for _, field := range fields[memberStart:] {
				member, ok, parseErr := parseMDStatMember(field)
				if parseErr != nil {
					return nil, parseErr
				}
				if ok {
					record.members = append(record.members, member)
				}
			}
			if len(record.members) > maxMDMemberEntries {
				return nil, errors.New("excessive mdstat member count")
			}
			byName[record.name] = len(records)
			records = append(records, record)
			current = len(records) - 1
			continue
		}
		if current < 0 {
			continue
		}
		record := &records[current]
		for _, field := range fields {
			if expected, active, ok, countErr := parseMDDeviceCounts(field); countErr != nil {
				return nil, countErr
			} else if ok {
				if record.countsKnown && (record.expectedDevices != expected || record.activeDevices != active) {
					return nil, errors.New("conflicting mdstat device counts")
				}
				record.expectedDevices, record.activeDevices, record.countsKnown = expected, active, true
			}
			if slots, ok := parseMDMemberSlots(field); ok {
				if record.memberSlots != "" && record.memberSlots != slots {
					return nil, errors.New("conflicting mdstat member slots")
				}
				record.memberSlots = slots
			}
		}
		if action, progress, recognized, parseErr := parseMDSyncProgress(line); parseErr != nil {
			return nil, parseErr
		} else if recognized {
			record.syncAction = action
			record.syncProgress = progress
		}
	}
	for _, record := range records {
		if record.countsKnown && record.activeDevices > record.expectedDevices {
			return nil, errors.New("invalid mdstat active device count")
		}
		if record.memberSlots != "" && record.countsKnown && uint32(len(record.memberSlots)) != record.expectedDevices {
			return nil, errors.New("mdstat slot count does not match array size")
		}
		if record.memberSlots != "" && record.countsKnown && uint32(strings.Count(record.memberSlots, "U")) != record.activeDevices {
			return nil, errors.New("mdstat slot state does not match active count")
		}
	}
	return records, nil
}

func readMDArraySysfs(sysfs fs.FS, record mdstatRecord, blockNodePresent bool) (mdArrayObservation, bool) {
	observation := mdArrayObservation{
		Name: record.name, Level: record.level, State: record.state,
		Health: arrayHealthUnknown, SyncAction: record.syncAction,
		Members: append([]mdMemberObservation{}, record.members...),
	}
	complete := blockNodePresent
	if record.countsKnown {
		observation.ExpectedDevices = record.expectedDevices
		observation.ActiveDevices = record.activeDevices
		if record.expectedDevices >= record.activeDevices {
			observation.DegradedDevices = record.expectedDevices - record.activeDevices
		}
	}
	if record.syncProgress != nil {
		observation.SyncProgressPercent = record.syncProgress
	}
	if !blockNodePresent {
		return observation, false
	}

	base := "class/block/" + record.name + "/md/"
	level, levelErr := readSysfsAttribute(sysfs, base+"level")
	state, stateErr := readSysfsAttribute(sysfs, base+"array_state")
	degradedText, degradedErr := readSysfsAttribute(sysfs, base+"degraded")
	raidDisksText, raidDisksErr := readSysfsAttribute(sysfs, base+"raid_disks")
	syncAction, syncErr := readSysfsAttribute(sysfs, base+"sync_action")
	syncCompleted, syncCompletedErr := readSysfsAttribute(sysfs, base+"sync_completed")
	slaves, slavesErr := fs.ReadDir(sysfs, "class/block/"+record.name+"/slaves")
	if levelErr != nil || stateErr != nil || degradedErr != nil || raidDisksErr != nil || syncErr != nil || syncCompletedErr != nil || slavesErr != nil || len(slaves) > maxMDMemberEntries {
		return observation, false
	}
	levelValue := strings.TrimSpace(level)
	stateValue := strings.TrimSpace(state)
	degraded, degradedErr := parseBoundedMDInteger(degradedText, maxMDMemberEntries)
	raidDisks, raidDisksErr := parseBoundedMDInteger(raidDisksText, maxMDMemberEntries)
	actionValue := strings.TrimSpace(syncAction)
	if !validMDLevel(levelValue) || !validMDArrayState(stateValue) || degradedErr != nil || raidDisksErr != nil || degraded > raidDisks || !validMDSyncAction(actionValue) {
		return observation, false
	}
	observation.Level = levelValue
	observation.State = stateValue
	observation.ExpectedDevices = raidDisks
	observation.DegradedDevices = degraded
	observation.ActiveDevices = raidDisks - degraded
	observation.SyncAction = actionValue
	progress, progressErr := parseMDSyncCompleted(syncCompleted)
	if progressErr != nil {
		return observation, false
	}
	if progress != nil {
		observation.SyncProgressPercent = progress
	}
	memberNames := make([]string, 0, len(slaves))
	for _, slave := range slaves {
		if !validBlockName(slave.Name()) {
			return observation, false
		}
		memberNames = append(memberNames, slave.Name())
	}
	sort.Strings(memberNames)
	sysfsMembers := make([]mdMemberObservation, 0, len(memberNames))
	for _, member := range memberNames {
		sysfsMembers = append(sysfsMembers, mdMemberObservation{Name: member, State: "active"})
	}
	if len(record.members) != 0 && !sameMDMemberNames(record.members, sysfsMembers) {
		complete = false
	}
	for _, member := range record.members {
		if member.State == "faulty" && degraded == 0 {
			complete = false
		}
	}
	if record.countsKnown && (record.expectedDevices != raidDisks || record.expectedDevices-record.activeDevices != degraded) {
		complete = false
	}
	if record.level != "unknown" && record.level != levelValue {
		complete = false
	}
	if record.syncAction != "" && normalizeMDSyncAction(record.syncAction) != actionValue {
		complete = false
	}
	if record.state == "inactive" && stateValue != "inactive" && stateValue != "clear" && stateValue != "suspended" ||
		record.state == "active" && (stateValue == "inactive" || stateValue == "clear" || stateValue == "suspended") {
		complete = false
	}
	if len(record.members) == 0 {
		observation.Members = sysfsMembers
	}
	observation.Health = classifyMDHealth(stateValue, actionValue, levelValue, raidDisks, degraded, complete)
	return observation, complete
}

func parseMDStatMember(field string) (mdMemberObservation, bool, error) {
	open := strings.LastIndexByte(field, '[')
	if open < 0 {
		return mdMemberObservation{}, false, nil
	}
	close := strings.IndexByte(field[open+1:], ']')
	if close < 0 {
		return mdMemberObservation{}, false, errors.New("invalid mdstat member index")
	}
	close += open + 1
	name := field[:open]
	if !validBlockName(name) {
		return mdMemberObservation{}, false, errors.New("invalid mdstat member name")
	}
	indexText := field[open+1 : close]
	if _, err := strconv.ParseUint(indexText, 10, 32); err != nil {
		return mdMemberObservation{}, false, errors.New("invalid mdstat member index")
	}
	suffix := field[close+1:]
	state := "active"
	switch suffix {
	case "", "(A)":
	case "(S)":
		state = "spare"
	case "(F)":
		state = "faulty"
	default:
		return mdMemberObservation{}, false, errors.New("invalid mdstat member state")
	}
	return mdMemberObservation{Name: name, State: state}, true, nil
}

func parseMDDeviceCounts(field string) (uint32, uint32, bool, error) {
	if len(field) < 5 || field[0] != '[' || field[len(field)-1] != ']' {
		return 0, 0, false, nil
	}
	inside := field[1 : len(field)-1]
	parts := strings.Split(inside, "/")
	if len(parts) != 2 {
		return 0, 0, false, nil
	}
	expected, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return 0, 0, false, errors.New("invalid mdstat expected device count")
	}
	active, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil || expected == 0 || expected > maxMDMemberEntries {
		return 0, 0, false, errors.New("invalid mdstat active device count")
	}
	return uint32(expected), uint32(active), true, nil
}

func parseMDMemberSlots(field string) (string, bool) {
	if len(field) < 3 || field[0] != '[' || field[len(field)-1] != ']' {
		return "", false
	}
	slots := field[1 : len(field)-1]
	if slots == "" {
		return "", false
	}
	for _, slot := range slots {
		if slot != 'U' && slot != '_' {
			return "", false
		}
	}
	return slots, true
}

func parseMDSyncProgress(line string) (string, *float64, bool, error) {
	for _, action := range []string{"resync", "recovery", "reshape", "check", "repair"} {
		marker := action + " ="
		index := strings.Index(line, marker)
		if index < 0 {
			continue
		}
		rest := strings.Fields(line[index+len(marker):])
		if len(rest) == 0 {
			return action, nil, true, errors.New("missing mdstat sync progress")
		}
		if strings.EqualFold(rest[0], "DELAYED") {
			return action, nil, true, nil
		}
		value := strings.TrimSuffix(rest[0], "%")
		progress, err := strconv.ParseFloat(value, 64)
		if err != nil || math.IsNaN(progress) || math.IsInf(progress, 0) || progress < 0 || progress > 100 || !strings.HasSuffix(rest[0], "%") {
			return action, nil, true, errors.New("invalid mdstat sync progress")
		}
		return action, &progress, true, nil
	}
	return "", nil, false, nil
}

func parseBoundedMDInteger(value string, maximum int) (uint32, error) {
	parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
	if err != nil || parsed > uint64(maximum) {
		return 0, errors.New("invalid md sysfs integer")
	}
	return uint32(parsed), nil
}

func parseMDSyncCompleted(value string) (*float64, error) {
	fields := strings.Fields(value)
	if len(fields) != 3 || fields[1] != "/" {
		return nil, errors.New("invalid md sync completion")
	}
	completed, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		return nil, errors.New("invalid md sync completion")
	}
	total, err := strconv.ParseUint(fields[2], 10, 64)
	if err != nil || completed > total {
		return nil, errors.New("invalid md sync completion")
	}
	if total == 0 {
		return nil, nil
	}
	progress := float64(completed) * 100 / float64(total)
	if math.IsNaN(progress) || math.IsInf(progress, 0) || progress < 0 || progress > 100 {
		return nil, errors.New("invalid md sync completion")
	}
	return &progress, nil
}

func sameMDMemberNames(first, second []mdMemberObservation) bool {
	if len(first) != len(second) {
		return false
	}
	firstNames := make([]string, 0, len(first))
	secondNames := make([]string, 0, len(second))
	for _, member := range first {
		firstNames = append(firstNames, member.Name)
	}
	for _, member := range second {
		secondNames = append(secondNames, member.Name)
	}
	sort.Strings(firstNames)
	sort.Strings(secondNames)
	for index := range firstNames {
		if firstNames[index] != secondNames[index] {
			return false
		}
	}
	return true
}

func classifyMDHealth(state, action, level string, raidDisks, degraded uint32, consistent bool) arrayHealth {
	if !consistent {
		return arrayHealthUnknown
	}
	if state == "inactive" {
		return arrayHealthInactive
	}
	if raidDisks == 0 {
		return arrayHealthUnknown
	}
	if degraded > 0 || degraded >= raidDisks {
		return arrayHealthDegraded
	}
	if action != "idle" {
		return arrayHealthSyncing
	}
	if !supportsKernelHealthyState(level) {
		return arrayHealthUnknown
	}
	if state == "clean" || state == "active" || state == "active-idle" || state == "read-auto" {
		return arrayHealthHealthy
	}
	return arrayHealthUnknown
}

func validMDName(name string) bool {
	if !validBlockName(name) {
		return false
	}
	if strings.HasPrefix(name, "md_d") {
		name = strings.TrimPrefix(name, "md_d")
	} else if strings.HasPrefix(name, "md") {
		name = strings.TrimPrefix(name, "md")
	} else {
		return false
	}
	if name == "" {
		return false
	}
	for _, character := range name {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func validMDLevel(level string) bool {
	switch level {
	case "linear", "multipath", "faulty", "container", "raid0", "raid1", "raid4", "raid5", "raid6", "raid10":
		return true
	default:
		return false
	}
}

func supportsKernelHealthyState(level string) bool {
	switch level {
	case "linear", "multipath", "raid0", "raid1", "raid4", "raid5", "raid6", "raid10":
		return true
	default:
		return false
	}
}

func validMDArrayState(state string) bool {
	switch state {
	case "clear", "inactive", "suspended", "readonly", "read-auto", "clean", "active", "write-pending", "active-idle":
		return true
	default:
		return false
	}
}

func validMDSyncAction(action string) bool {
	switch action {
	case "idle", "resync", "recover", "check", "repair", "reshape", "frozen":
		return true
	default:
		return false
	}
}

func normalizeMDSyncAction(action string) string {
	if action == "recovery" {
		return "recover"
	}
	return action
}
