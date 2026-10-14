//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"strings"
	"testing"
)

// Command-boundary synthetic input, not actual server/client qualification.
func pendingStatusFixtureQEMU() string {
	return `{"version":"4.22.11","sessions":{"1000000000002":{"session_id":"1000000000002","username":"qpsecond","uid":2001,"gid":2001,"server_id":{"pid":"1002","task_id":"0","vnn":"4294967295","unique_id":"987654321"}}},"tcons":{"21":{"service":"writable","session_id":"1000000000002","tcon_id":"21","server_id":{"pid":"1002","task_id":"0","vnn":"4294967295","unique_id":"987654321"}}},"open_files":{"/shares/writable/pending-write":{"service_path":"/shares/writable","filename":"pending-write","fileid":{"devid":8,"inode":123456,"extid":0},"num_pending_deletes":0,"opens":{"1002/42":{"server_id":{"pid":"1002","task_id":"0","vnn":"4294967295","unique_id":"987654321"},"uid":2001,"share_file_id":"42","access_mask":{"hex":"0x0012019f","READ_DATA":true,"WRITE_DATA":true}}}}}}`
}

func TestPendingStatusLibSMBClientGenericReadWriteContract(t *testing.T) {
	// Pinned libsmb_file.c -> cli_open(O_RDWR) -> util.c maps FILE_GENERIC_READ
	// | FILE_GENERIC_WRITE (0x0012019f), unlike the old CLI open holder's 0x3.
	actual := pendingStatusFixtureQEMU()
	if _, err := parsePendingStatusQEMU([]byte(actual)); err != nil {
		t.Fatal("real libsmbclient O_RDWR producer contract refused:", err)
	}
	older := strings.Replace(actual, "0x0012019f", "0x00000003", 1)
	if _, err := parsePendingStatusQEMU([]byte(older)); err == nil {
		t.Fatal("older CLI-holder access mask substituted for the dedicated client")
	}
}

func TestPendingStatusUsesNativeDataConfiguredService(t *testing.T) {
	// The native data renderer declares [writable]. The separate old planned
	// service declares [Writable]; these are not interchangeable expected inputs.
	actual := strings.Replace(pendingStatusFixtureQEMU(), `"service":"Writable"`, `"service":"writable"`, 1)
	if _, err := parsePendingStatusQEMU([]byte(actual)); err != nil {
		t.Fatal("fixed native data renderer's service refused:", err)
	}
	older := strings.Replace(actual, `"service":"writable"`, `"service":"Writable"`, 1)
	if _, err := parsePendingStatusQEMU([]byte(older)); err == nil {
		t.Fatal("separate planned profile substituted for native data service")
	}
}

func TestPendingStatusExactPrivateObservationAndChangedGeneration(t *testing.T) {
	good := pendingStatusFixtureQEMU()
	first, err := parsePendingStatusQEMU([]byte(good))
	if err != nil || first.session != "1000000000002" || first.tree != "21" || first.device != 8 || first.inode != 123456 || first.shareFileID != 42 {
		t.Fatal("exact producer input refused:", err)
	}
	for _, pair := range [][2]string{{"987654321", "987654322"}, {"1000000000002", "1000000000003"}, {`"21"`, `"22"`}, {"1002/42", "1002/43"}} {
		changed := strings.ReplaceAll(good, pair[0], pair[1])
		if pair[0] == "1002/42" {
			changed = strings.Replace(changed, `"share_file_id":"42"`, `"share_file_id":"43"`, 1)
		}
		next, err := parsePendingStatusQEMU([]byte(changed))
		if err != nil || next == first {
			t.Fatal("coherent replacement failed to distinguish the original observation:", pair, err)
		}
	}
}

func TestPendingStatusRejectsIncompleteAmbiguousAndAliasedInputs(t *testing.T) {
	good := pendingStatusFixtureQEMU()
	for _, pair := range [][2]string{
		{`"version":"4.22.11"`, `"version":"4.22.10"`},
		{`"username":"qpsecond"`, `"username":"qpmanaged"`},
		{`"uid":2001`, `"uid":null`}, {`"gid":2001`, `"gid":2002`},
		{`"task_id":"0"`, `"task_id":"1"`}, {`"vnn":"4294967295"`, `"vnn":"0"`},
		{`"unique_id":"987654321"`, `"unique_id":"18446744073709551615"`},
		{`"session_id":"1000000000002"`, `"session_id":"01000000000002"`},
		{`"service":"writable"`, `"service":"Writable"`},
		{`"devid":8`, `"devid":0`}, {`"inode":123456`, `"inode":null`},
		{`"extid":0`, `"extid":1`}, {`"num_pending_deletes":0`, `"num_pending_deletes":1`},
		{`"share_file_id":"42"`, `"share_file_id":42`},
		{`"hex":"0x0012019f"`, `"hex":"0x00000001"`},
		{`"READ_DATA":true`, `"READ_DATA":false`}, {`"WRITE_DATA":true`, `"WRITE_DATA":null`},
		{`"filename":"pending-write"`, `"filename":"created"`},
		{`"uid":2001`, `"uid":2001,"UID":2001`},
		{`"extid":0`, `"extid":0,"extid":0`},
		{`"version":"4.22.11"`, `"version":"4.22.11","unknown":1,"unknown":2`},
		{`"sessions":{`, `"sessions":{"other":{},`},
		{`"tcons":{`, `"tcons":{"22":{},`},
		{`"open_files":{`, `"open_files":{"other":{},`},
		{`"opens":{`, `"opens":{"other":{},`},
	} {
		if observed, err := parsePendingStatusQEMU([]byte(strings.Replace(good, pair[0], pair[1], 1))); err == nil || observed != (pendingStatusQEMU{}) {
			t.Fatal("partial/ambiguous input accepted:", pair)
		}
	}
	for _, bad := range []string{"", "null", "{}", good + "{}", good + "x", strings.Repeat(" ", 1<<20) + good,
		strings.Replace(good, `"version":"4.22.11"`, `"version":"4.22.11","extra":`+strings.Repeat("[", 17)+"0"+strings.Repeat("]", 17), 1),
		strings.Replace(good, `"version":"4.22.11"`, `"version":"4.22.11","extra":[`+strings.Repeat("0,", 16384)+"0]", 1),
		strings.Replace(good, "qpsecond", "qpsecond\xff", 1)} {
		if observed, err := parsePendingStatusQEMU([]byte(bad)); err == nil || observed != (pendingStatusQEMU{}) {
			t.Fatal("malformed/unbounded input accepted")
		}
	}
}
