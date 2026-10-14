// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package githubrelease

import (
	"encoding/json"
	"testing"
)

func FuzzDecodeReleaseMetadata(f *testing.F) {
	for _, seed := range []string{
		`null`, `[]`, `{}`, `{"immutable":false,"immutable":true}`,
		`{"id":77,"tag_name":"v0.1.0","draft":false,"prerelease":true,"immutable":true,"assets":[]}`,
		`{"id":77,"tag_name":"v0.1.0","draft":false,"prerelease":true,"immutable":true,"assets":[{"id":1,"name":"manifest.json","size":1,"url":"https://api.github.com/repos/fixture/project/releases/assets/1","state":"uploaded"}],"author":{"id":42}}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var decoded release
		if err := decodeRelease(data, &decoded); err != nil {
			return
		}
		if len(data) > maxReleaseJSON || len(decoded.Assets) > maxReleaseAssets {
			t.Fatal("decoded metadata exceeded its declared bound")
		}
		encoded, err := json.Marshal(decoded)
		if err != nil {
			t.Fatal(err)
		}
		// Encoding may expand HTML-sensitive or Unicode text. The input bound
		// applies to the received bytes, not to this independent re-encoding.
		if len(encoded) <= maxReleaseJSON && checkReleaseStructure(encoded) != nil {
			t.Fatal("accepted typed metadata cannot reproduce the required structure")
		}
		// Structural acceptance alone does not establish a published release,
		// valid asset URLs, signatures, payloads or installation authority.
	})
}
