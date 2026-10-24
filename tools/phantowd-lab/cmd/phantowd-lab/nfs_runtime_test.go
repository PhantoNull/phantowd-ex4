// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-lab/rootfsinventory"
)

func TestInspectNFSRuntimeCLIRequiresCompleteUserspaceSet(t *testing.T) {
	root := t.TempDir()
	var output bytes.Buffer
	code, err := run([]string{"inspect-nfs-runtime", root}, &output)
	var got rootfsinventory.NFSRuntimeClosure
	if err != nil || code != 2 || json.Unmarshal(output.Bytes(), &got) != nil || len(got.ExpectedEntries) != 6 || got.StaticDependenciesResolved || got.RuntimeQualified || got.ExecutionAuthorized || len(got.Objects) != 0 || got.TotalBytes != 0 {
		t.Fatal("CLI confused incomplete NFS evidence with a usable runtime", code, err)
	}
	for _, args := range [][]string{{"inspect-nfs-runtime"}, {"inspect-nfs-runtime", root, "extra"}, {"inspect-nfs-runtime", filepath.Join(root, "missing")}} {
		output.Reset()
		if code, err := run(args, &output); code != 1 || err == nil || output.Len() != 0 {
			t.Fatal("CLI emitted evidence after argument or inventory failure", code, err)
		}
	}
}

func nfsCLIHeader(interpreter bool) []byte {
	raw := make([]byte, 104)
	copy(raw, []byte{0x7f, 'E', 'L', 'F', 1, 1, 1})
	binary.LittleEndian.PutUint16(raw[16:], 2)
	binary.LittleEndian.PutUint16(raw[18:], 40)
	binary.LittleEndian.PutUint32(raw[20:], 1)
	binary.LittleEndian.PutUint32(raw[36:], 0x05000200)
	binary.LittleEndian.PutUint16(raw[40:], 52)
	if interpreter {
		binary.LittleEndian.PutUint32(raw[28:], 52)
		binary.LittleEndian.PutUint16(raw[42:], 32)
		binary.LittleEndian.PutUint16(raw[44:], 1)
		binary.LittleEndian.PutUint32(raw[52:], 3)
		binary.LittleEndian.PutUint32(raw[56:], 84)
		binary.LittleEndian.PutUint32(raw[68:], uint32(copy(raw[84:], "/lib/ld-linux.so.3\x00")))
	}
	return raw
}

func TestInspectNFSRuntimeCLIProducesOnlyStaticEvidenceFromSyntheticFiles(t *testing.T) {
	root := t.TempDir()
	for _, entry := range []string{"rpcbind", "rpc.mountd", "exportfs", "rpc.nfsd", "rpc.statd", "sm-notify", "loader"} {
		name := filepath.Join(root, "usr", "sbin", entry)
		if entry == "loader" {
			name = filepath.Join(root, "lib", "ld-linux.so.3")
		}
		if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, nfsCLIHeader(entry != "loader"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var output bytes.Buffer
	code, err := run([]string{"inspect-nfs-runtime", root}, &output)
	var got rootfsinventory.NFSRuntimeClosure
	if err != nil || code != 0 || json.Unmarshal(output.Bytes(), &got) != nil || !got.StaticDependenciesResolved || got.RuntimeQualified || got.ExecutionAuthorized || len(got.ExpectedEntries) != 6 || len(got.Objects) != 7 {
		t.Fatal("complete synthetic input failed or became runtime authority", code, err)
	}
}
