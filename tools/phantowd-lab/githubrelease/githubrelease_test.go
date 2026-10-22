// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package githubrelease

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-lab/releaseverify"
)

func TestInspectDownloadsOnlySignedExactGitHubReleaseAssets(t *testing.T) {
	fixture := newReleaseFixture(t, []byte("synthetic firmware bundle"))
	fixture.serve(t, true, nil)
	result, err := Inspect(context.Background(), fixture.options())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Verification.Valid || result.Verification.InstallationAuthorized || result.Verification.HardwareQualified {
		t.Fatalf("unexpected release verification result: %+v", result)
	}
	if fixture.payloadRequests != 1 || fixture.manifestRequests != 1 || fixture.signatureRequests != 1 {
		t.Fatalf("expected one bounded request per signed asset; got manifest=%d signature=%d payload=%d", fixture.manifestRequests, fixture.signatureRequests, fixture.payloadRequests)
	}
}

func TestInspectAmbiguousImmutableMetadataNeverRequestsAssets(t *testing.T) {
	fixture := newReleaseFixture(t, []byte("synthetic payload"))
	fixture.metadataTransform = func(body string) string {
		changed := strings.Replace(body, `"immutable":true`, `"immutable":false,"immutable":true`, 1)
		if changed == body {
			t.Error("metadata mutation did not apply")
		}
		return changed
	}
	fixture.serve(t, true, nil)
	result, err := Inspect(context.Background(), fixture.options())
	if err == nil || result.Verification.Valid || fixture.manifestRequests != 0 || fixture.signatureRequests != 0 || fixture.payloadRequests != 0 {
		t.Fatalf("ambiguous immutable metadata crossed asset gate: report=%+v requests=%d/%d/%d err=%v",
			result.Verification, fixture.manifestRequests, fixture.signatureRequests, fixture.payloadRequests, err)
	}
}

func TestInspectMissingOrNullDraftNeverRequestsAssets(t *testing.T) {
	for _, replacement := range []string{"", `"draft":null,`} {
		t.Run(replacement, func(t *testing.T) {
			fixture := newReleaseFixture(t, []byte("synthetic payload"))
			fixture.metadataTransform = func(body string) string {
				changed := strings.Replace(body, `"draft":false,`, replacement, 1)
				if changed == body {
					t.Error("metadata mutation did not apply")
				}
				return changed
			}
			fixture.serve(t, true, nil)
			result, err := Inspect(context.Background(), fixture.options())
			if err == nil || result.Verification.Valid || fixture.manifestRequests != 0 || fixture.signatureRequests != 0 || fixture.payloadRequests != 0 {
				t.Fatalf("absent draft observation became published status: report=%+v requests=%d/%d/%d err=%v",
					result.Verification, fixture.manifestRequests, fixture.signatureRequests, fixture.payloadRequests, err)
			}
		})
	}
}

func TestInspectMalformedMetadataNeverRequestsAssets(t *testing.T) {
	for _, mutation := range []struct{ name, old, replacement string }{
		{"immutable case alias", `"immutable":true`, `"IMMUTABLE":true`},
		{"conflicting case alias", `"immutable":true`, `"immutable":false,"IMMUTABLE":true`},
		{"escaped duplicate", `"immutable":true`, `"\u0069mmutable":false,"immutable":true`},
		{"root id alias", `"id":77`, `"ID":77`},
		{"draft alias", `"draft":false`, `"Draft":false`},
		{"prerelease alias", `"prerelease":true`, `"Prerelease":true`},
		{"tag alias", `"tag_name":`, `"Tag_Name":`},
		{"assets alias", `"assets":`, `"Assets":`},
		{"immutable wrong shape", `"immutable":true`, `"immutable":{"immutable":true}`},
		{"draft wrong type", `"draft":false`, `"draft":"false"`},
		{"asset id alias", `"id":1,`, `"ID":1,`},
		{"asset name alias", `"name":"manifest.json"`, `"Name":"manifest.json"`},
		{"asset size alias", `"size":`, `"Size":`},
		{"asset url alias", `"url":`, `"URL":`},
		{"asset state alias", `"state":"uploaded"`, `"State":"uploaded"`},
		{"asset duplicate state", `"state":"uploaded"`, `"state":"new","state":"uploaded"`},
		{"asset escaped duplicate", `"state":"uploaded"`, `"\u0073tate":"new","state":"uploaded"`},
		{"asset name surrogate repair", `"name":"manifest.json"`, `"name":"manifest\ud800.json"`},
		{"tag surrogate repair", `"tag_name":"v0.1.0"`, `"tag_name":"v0.1.0\ud800"`},
		{"trailing JSON", `"id":77`, `"id":77`},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			fixture := newReleaseFixture(t, []byte("synthetic payload"))
			fixture.metadataTransform = func(body string) string {
				if mutation.name == "trailing JSON" {
					return body + "{}"
				}
				changed := strings.Replace(body, mutation.old, mutation.replacement, 1)
				if changed == body {
					t.Error("metadata mutation did not apply")
				}
				return changed
			}
			fixture.serve(t, true, nil)
			assertMetadataRefusedBeforeAssets(t, fixture)
		})
	}
}

func TestInspectRequiresEveryObservedReleaseAndAssetField(t *testing.T) {
	for _, scope := range []string{"release", "asset"} {
		keys := []string{"id", "tag_name", "draft", "prerelease", "immutable", "assets"}
		if scope == "asset" {
			keys = []string{"id", "name", "size", "url", "state"}
		}
		for _, key := range keys {
			for _, missing := range []bool{true, false} {
				t.Run(fmt.Sprintf("%s/%s/missing=%t", scope, key, missing), func(t *testing.T) {
					fixture := newReleaseFixture(t, []byte("synthetic payload"))
					fixture.metadataTransform = func(body string) string {
						var root map[string]json.RawMessage
						if err := json.Unmarshal([]byte(body), &root); err != nil {
							t.Error(err)
							return ""
						}
						selected := root
						var assets []map[string]json.RawMessage
						if scope == "asset" {
							if err := json.Unmarshal(root["assets"], &assets); err != nil || len(assets) == 0 {
								t.Error("missing fixture assets")
								return ""
							}
							selected = assets[0]
						}
						if missing {
							delete(selected, key)
						} else {
							selected[key] = json.RawMessage("null")
						}
						if scope == "asset" {
							root["assets"], _ = json.Marshal(assets)
						}
						encoded, err := json.Marshal(root)
						if err != nil {
							t.Error(err)
						}
						return string(encoded)
					}
					fixture.serve(t, true, nil)
					assertMetadataRefusedBeforeAssets(t, fixture)
				})
			}
		}
	}
}

func assertMetadataRefusedBeforeAssets(t *testing.T, fixture *releaseFixture) {
	t.Helper()
	result, err := Inspect(context.Background(), fixture.options())
	if err == nil || result.Verification.Valid || result.Verification.SignatureValid || result.ReleaseID != 0 ||
		fixture.manifestRequests != 0 || fixture.signatureRequests != 0 || fixture.payloadRequests != 0 {
		t.Fatalf("invalid API metadata crossed asset boundary: report=%+v requests=%d/%d/%d err=%v",
			result, fixture.manifestRequests, fixture.signatureRequests, fixture.payloadRequests, err)
	}
}

func TestInspectMetadataExtensionAndEscapingPreserveVerification(t *testing.T) {
	fixture := newReleaseFixture(t, []byte("synthetic payload"))
	fixture.metadataTransform = func(body string) string {
		body = strings.Replace(body, `"assets":`, `"author":{"login":"synthetic","other":[null,{"draft":true}]},"body":"Synthetic Unicode ✓","assets":`, 1)
		body = strings.Replace(body, `"immutable":`, `"\u0069mmutable":`, 1)
		return strings.Replace(body, `"name":"manifest.json"`, `"label":null,"uploader":{"id":42},"name":"manifest.json"`, 1)
	}
	fixture.serve(t, true, nil)
	result, err := Inspect(context.Background(), fixture.options())
	if err != nil || !result.Verification.Valid || !result.Verification.SignatureValid || !result.Verification.ArtifactsValid ||
		result.Verification.InstallationAuthorized || fixture.manifestRequests != 1 || fixture.signatureRequests != 1 || fixture.payloadRequests != 1 {
		t.Fatalf("valid extensible metadata changed the signature/payload boundary: result=%+v err=%v", result, err)
	}
}

func TestInspectMetadataEncodingAndAssetBoundsNeverRequestAssets(t *testing.T) {
	for _, mode := range []string{"invalid UTF-8", "oversized", "too many assets", "null asset", "non-object", "fractional id"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newReleaseFixture(t, []byte("synthetic payload"))
			fixture.metadataTransform = func(body string) string {
				switch mode {
				case "invalid UTF-8":
					return strings.Replace(body, `"immutable":true`, "\"unused\":\"\xff\",\"immutable\":true", 1)
				case "oversized":
					return strings.Replace(body, `"immutable":true`, `"unused":"`+strings.Repeat("x", maxReleaseJSON)+`","immutable":true`, 1)
				case "non-object":
					return "[" + body + "]"
				case "fractional id":
					return strings.Replace(body, `"id":77`, `"id":77.5`, 1)
				}
				var root map[string]json.RawMessage
				if err := json.Unmarshal([]byte(body), &root); err != nil {
					t.Error(err)
					return ""
				}
				if mode == "null asset" {
					root["assets"] = json.RawMessage("[null]")
				} else {
					var assets []releaseAsset
					if err := json.Unmarshal(root["assets"], &assets); err != nil {
						t.Error(err)
						return ""
					}
					for len(assets) <= maxReleaseAssets {
						id := int64(len(assets) + 1)
						assets = append(assets, releaseAsset{ID: id, Name: fmt.Sprintf("extra-%d", id), Size: 1, URL: fixture.assetURL(id), State: "uploaded"})
					}
					root["assets"], _ = json.Marshal(assets)
				}
				encoded, err := json.Marshal(root)
				if err != nil {
					t.Error(err)
				}
				return string(encoded)
			}
			fixture.serve(t, true, nil)
			assertMetadataRefusedBeforeAssets(t, fixture)
		})
	}
}

func TestInspectSignedMalformedStructureNeverDownloadsPayload(t *testing.T) {
	for _, mutation := range []struct{ name, old, replacement string }{
		{"root case alias", `"model_id":`, `"Model_ID":`},
		{"artifact case alias", `"size_bytes":`, `"SIZE_BYTES":`},
		{"case duplicate", `"model_id":"wd-my-cloud-ex4"`, `"model_id":"other-model","MODEL_ID":"wd-my-cloud-ex4"`},
		{"artifact missing", `"role":"swupdate-bundle",`, ``},
		{"null list", `"hardware_revisions":["board-r1"]`, `"hardware_revisions":null`},
		{"wrong shape", `"model_id":"wd-my-cloud-ex4"`, `"model_id":{"model_id":"wd-my-cloud-ex4"}`},
		{"surrogate repair", `"model_id":"wd-my-cloud-ex4"`, `"model_id":"wd-\ud800"`},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			fixture := newReleaseFixture(t, []byte("synthetic payload"))
			original := string(fixture.manifest)
			fixture.manifest = []byte(strings.Replace(original, mutation.old, mutation.replacement, 1))
			if string(fixture.manifest) == original {
				t.Fatal("HTTP regression mutation did not apply")
			}
			seed := sha256.Sum256([]byte("githubrelease deterministic synthetic fixture key"))
			fixture.signature = ed25519.Sign(ed25519.NewKeyFromSeed(seed[:]), fixture.manifest)
			fixture.serve(t, true, nil)
			result, err := Inspect(context.Background(), fixture.options())
			if err == nil || !result.Verification.SignatureValid || result.Verification.Valid || result.Verification.ArtifactsChecked ||
				fixture.manifestRequests != 1 || fixture.signatureRequests != 1 || fixture.payloadRequests != 0 {
				t.Fatalf("malformed signed metadata crossed payload gate: report=%+v requests=%d/%d/%d err=%v",
					result.Verification, fixture.manifestRequests, fixture.signatureRequests, fixture.payloadRequests, err)
			}
		})
	}
}

func TestInspectInstallerPreflightBeforePayloadDownload(t *testing.T) {
	for _, test := range []struct {
		version     string
		wantPayload int
		wantError   bool
		wantPolicy  bool
		compatible  bool
	}{
		{"", 1, false, false, false},
		{"v0.1.0", 1, false, true, true},
		{"v0.1.1", 1, false, true, true},
		{"v0.0.9", 0, false, true, false},
		{"v0.1.0-rc.1", 0, false, true, false},
		{"v00.1.0", 0, true, false, false},
	} {
		t.Run(test.version, func(t *testing.T) {
			fixture := newReleaseFixture(t, []byte("synthetic payload"))
			fixture.serve(t, true, nil)
			options := fixture.options()
			options.InstallerVersion = test.version
			result, err := Inspect(context.Background(), options)
			policy := result.Verification.InstallerPolicy
			if (err != nil) != test.wantError || (policy != nil) != test.wantPolicy || fixture.payloadRequests != test.wantPayload {
				t.Fatalf("unexpected preflight: result=%+v err=%v payloads=%d", result, err, fixture.payloadRequests)
			}
			if test.wantError && (fixture.manifestRequests != 0 || fixture.signatureRequests != 0) {
				t.Fatal("invalid host version reached release assets")
			}
			if policy != nil && (!policy.Evaluated || policy.Compatible != test.compatible || policy.MinimumInstaller != "v0.1.0" || policy.InstallationAuthorized) {
				t.Fatalf("wrong prerequisite assessment: %+v", policy)
			}
			if result.Verification.Valid != (test.wantPayload == 1) || result.Verification.ArtifactsChecked != (test.wantPayload == 1) || result.Verification.InstallationAuthorized || result.Verification.HardwareQualified {
				t.Fatalf("payload/authority boundary changed: %+v", result.Verification)
			}
		})
	}
}

func TestInspectInstallerPrerequisiteFollowsSignedTagAndTargetChecks(t *testing.T) {
	for _, mutation := range []string{"signature", "target", "tag"} {
		t.Run(mutation, func(t *testing.T) {
			fixture := newReleaseFixture(t, []byte("synthetic payload"))
			switch mutation {
			case "signature":
				fixture.signature[0] ^= 1
			case "target":
				fixture.optionsRevision = "board-r2"
			case "tag":
				fixture.optionsTag, fixture.releaseTag = "v0.2.0", "v0.2.0"
			}
			fixture.serve(t, true, nil)
			options := fixture.options()
			options.InstallerVersion = "v1.0.0"
			result, err := Inspect(context.Background(), options)
			if err != nil || result.Verification.InstallerPolicy != nil || result.Verification.Valid || result.Verification.ArtifactsChecked || fixture.payloadRequests != 0 {
				t.Fatalf("installer preflight crossed preceding gate: result=%+v err=%v", result, err)
			}
		})
	}
}

func TestInspectRequiredUpgradeBeforePayloadDownload(t *testing.T) {
	for _, test := range []struct {
		current string
		payload int
		invalid bool
	}{
		{"", 1, false}, {"v0.0.9", 1, false}, {"v0.1.0-rc.1", 1, false},
		{"v0.1.0", 0, false}, {"v0.2.0", 0, false},
		{"v00.1.0", 0, true}, {strings.Repeat("v", 129), 0, true},
	} {
		t.Run(test.current, func(t *testing.T) {
			fixture := newReleaseFixture(t, []byte("synthetic payload"))
			fixture.serve(t, true, nil)
			options := fixture.options()
			options.RequireUpgradeFrom = test.current
			result, err := Inspect(context.Background(), options)
			policy := result.Verification.UpgradePrerequisite
			if (err != nil) != test.invalid || fixture.payloadRequests != test.payload ||
				result.Verification.Valid != (test.payload == 1) || result.Verification.ArtifactsChecked != (test.payload == 1) ||
				result.Verification.InstallationAuthorized || result.Verification.HardwareQualified || result.Verification.UpdatePolicy != nil {
				t.Fatalf("upgrade boundary changed: result=%+v err=%v payloads=%d", result, err, fixture.payloadRequests)
			}
			if test.invalid {
				if fixture.metadataRequests != 0 || fixture.manifestRequests != 0 || fixture.signatureRequests != 0 || policy != nil {
					t.Fatal("invalid current version reached HTTP or gained prerequisite evidence")
				}
				return
			}
			if fixture.metadataRequests != 1 || fixture.manifestRequests != 1 || fixture.signatureRequests != 1 {
				t.Fatal("metadata was retried or skipped")
			}
			if test.current == "" {
				if policy != nil {
					t.Fatal("omitted prerequisite changed legacy behavior")
				}
			} else if policy == nil || !policy.Evaluated || policy.StrictlyNewer != (test.payload == 1) || policy.InstallationAuthorized {
				t.Fatalf("wrong metadata prerequisite: %+v", policy)
			}
		})
	}
}

func TestInspectUpgradePrerequisiteDoesNotBypassAuthenticationOrPayload(t *testing.T) {
	for _, mutation := range []string{"signature", "target", "channel", "signed tag", "installer", "payload"} {
		t.Run(mutation, func(t *testing.T) {
			fixture := newReleaseFixture(t, []byte("synthetic payload"))
			switch mutation {
			case "signature":
				fixture.signature[0] ^= 1
			case "target":
				fixture.optionsRevision = "board-r2"
			case "signed tag":
				fixture.optionsTag, fixture.releaseTag = "v0.2.0", "v0.2.0"
			case "payload":
				fixture.payload[0] ^= 1
			}
			fixture.serve(t, true, nil)
			options := fixture.options()
			options.RequireUpgradeFrom = "v0.0.9"
			options.InstallerVersion = "v0.1.0"
			if mutation == "installer" {
				options.InstallerVersion = "v0.0.9"
			}
			if mutation == "channel" {
				options.Channel = "beta"
			}
			result, err := Inspect(context.Background(), options)
			wantPayload := 0
			if mutation == "payload" {
				wantPayload = 1
			}
			if err != nil || result.Verification.Valid || fixture.payloadRequests != wantPayload ||
				result.Verification.ArtifactsChecked != (wantPayload == 1) ||
				(result.Verification.UpgradePrerequisite != nil) != (wantPayload == 1) ||
				result.Verification.InstallationAuthorized || result.Verification.HardwareQualified {
				t.Fatalf("%s gate bypassed: %+v err=%v", mutation, result, err)
			}
		})
	}
}

func TestInspectNonUpgradeRefusesBeforeTemporaryStaging(t *testing.T) {
	fixture := newReleaseFixture(t, []byte("synthetic payload"))
	fixture.serve(t, true, nil)
	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocked, []byte("synthetic staging sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(name, blocked)
	}
	options := fixture.options()
	options.RequireUpgradeFrom = "v0.1.0"
	result, err := Inspect(context.Background(), options)
	if err != nil || result.Verification.Valid || result.Verification.ArtifactsChecked || fixture.payloadRequests != 0 ||
		result.Verification.UpgradePrerequisite == nil || result.Verification.UpgradePrerequisite.StrictlyNewer {
		t.Fatalf("equal release attempted staging: %+v err=%v", result, err)
	}
	// Positive control: the same authenticated release with a lower supplied
	// current version reaches MkdirTemp and fails on the deliberate file parent.
	options.RequireUpgradeFrom = "v0.0.9"
	result, err = Inspect(context.Background(), options)
	if err == nil || !strings.Contains(err.Error(), "create temporary release-check directory") || fixture.payloadRequests != 0 ||
		result.Verification.UpgradePrerequisite == nil || !result.Verification.UpgradePrerequisite.StrictlyNewer ||
		result.Verification.Valid || result.Verification.ArtifactsChecked {
		t.Fatalf("staging sentinel did not distinguish gate from failure: %+v err=%v", result, err)
	}
}

func TestInspectInvalidInstallerNeverMakesHTTPRequest(t *testing.T) {
	fixture := newReleaseFixture(t, []byte("synthetic payload"))
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(w, "must not be reached", http.StatusInternalServerError)
	}))
	defer server.Close()
	fixture.server = server
	options := fixture.options()
	options.InstallerVersion = "v00.1.0"
	result, err := Inspect(context.Background(), options)
	if err == nil || requests.Load() != 0 || result.Verification.InstallerPolicy != nil || result.Verification.ArtifactsChecked {
		t.Fatalf("invalid installer caused HTTP or an assessment: requests=%d result=%+v err=%v", requests.Load(), result, err)
	}
}

func TestInspectFollowsSignedCDNRedirects(t *testing.T) {
	fixture := newReleaseFixture(t, []byte("synthetic signed redirect payload"))
	fixture.signedRedirects = true
	fixture.serve(t, true, nil)
	client, downloads := signedRedirectClient(t, fixture)
	options := fixture.options()
	options.Client = client
	result, err := Inspect(context.Background(), options)
	if err != nil {
		t.Fatalf("signed CDN redirect prevented release inspection: %v", err)
	}
	if !result.Verification.Valid || result.Verification.InstallationAuthorized || result.Verification.HardwareQualified {
		t.Fatalf("redirected release did not retain the verification boundary: %+v", result.Verification)
	}
	if fixture.manifestRequests != 1 || fixture.signatureRequests != 1 || fixture.payloadRequests != 1 {
		t.Fatal("expected one API redirect per signed asset")
	}
	for index := range downloads {
		if downloads[index].Load() != 1 {
			t.Fatalf("CDN asset %d requested %d times", index+1, downloads[index].Load())
		}
	}
}

func TestInspectSignedRedirectsRetainAuthenticationAndHashGates(t *testing.T) {
	t.Run("invalid signature never fetches payload", func(t *testing.T) {
		fixture := newReleaseFixture(t, []byte("synthetic payload"))
		fixture.signature[0] ^= 0x80
		fixture.signedRedirects = true
		fixture.serve(t, true, nil)
		client, downloads := signedRedirectClient(t, fixture)
		options := fixture.options()
		options.Client = client
		result, err := Inspect(context.Background(), options)
		if err != nil || result.Verification.Valid || result.Verification.SignatureValid || result.Verification.ArtifactsChecked {
			t.Fatalf("signature refusal failed through CDN redirects: result=%+v err=%v", result, err)
		}
		if fixture.payloadRequests != 0 || downloads[0].Load() != 1 || downloads[1].Load() != 1 || downloads[2].Load() != 0 {
			t.Fatal("redirected downloads crossed the signature gate")
		}
	})
	t.Run("same-size changed payload remains invalid", func(t *testing.T) {
		fixture := newReleaseFixture(t, []byte("synthetic payload"))
		fixture.payload[0] ^= 0x01
		fixture.signedRedirects = true
		fixture.serve(t, true, nil)
		client, downloads := signedRedirectClient(t, fixture)
		options := fixture.options()
		options.Client = client
		result, err := Inspect(context.Background(), options)
		if err != nil || result.Verification.Valid || !result.Verification.SignatureValid || !result.Verification.ArtifactsChecked || result.Verification.ArtifactsValid {
			t.Fatalf("hash refusal failed through CDN redirects: result=%+v err=%v", result, err)
		}
		if downloads[2].Load() != 1 || len(result.Verification.Artifacts) != 1 || result.Verification.Artifacts[0].SHA256Match || result.Verification.InstallationAuthorized || result.Verification.HardwareQualified {
			t.Fatal("redirected tampered payload gained verification or install authority")
		}
	})
}

func TestInspectRejectsQueryOnMetadataAssetEndpoint(t *testing.T) {
	fixture := newReleaseFixture(t, []byte("payload"))
	fixture.assetURLQuery = true
	fixture.serve(t, true, nil)
	result, err := Inspect(context.Background(), fixture.options())
	if err == nil || !strings.Contains(err.Error(), "asset URL") || result.Verification.Valid || fixture.manifestRequests != 0 || fixture.payloadRequests != 0 {
		t.Fatalf("query-bearing metadata endpoint was not refused before asset access: %v", err)
	}
}

func TestInspectDoesNotExposeSignedRedirectQueryInErrors(t *testing.T) {
	for _, assetID := range []int{1, 3} {
		t.Run(fmt.Sprintf("asset-%d", assetID), func(t *testing.T) {
			stageParent := t.TempDir()
			for _, variable := range []string{"TMPDIR", "TMP", "TEMP"} {
				t.Setenv(variable, stageParent)
			}
			fixture := newReleaseFixture(t, []byte("payload"))
			fixture.signedRedirects = true
			fixture.serve(t, true, nil)
			client, downloads := signedRedirectClient(t, fixture)
			refusal := errors.New("fixture redirect denied")
			client.CheckRedirect = func(request *http.Request, _ []*http.Request) error {
				if request.URL.Path == fmt.Sprintf("/fixture/%d", assetID) {
					return refusal
				}
				return nil
			}
			options := fixture.options()
			options.Client = client
			_, err := Inspect(context.Background(), options)
			if err == nil || !errors.Is(err, refusal) {
				t.Fatalf("caller redirect refusal was not retained: %v", err)
			}
			if strings.Contains(err.Error(), "sig=synthetic") || strings.Contains(err.Error(), "fixture-expiry") {
				t.Fatalf("signed redirect parameters leaked in public error: %v", err)
			}
			for index := range downloads {
				want := int32(0)
				if index+1 < assetID {
					want = 1
				}
				if downloads[index].Load() != want {
					t.Fatal("caller redirect refusal was bypassed or an earlier signed asset was omitted")
				}
			}
			remaining, err := os.ReadDir(stageParent)
			if err != nil || len(remaining) != 0 {
				t.Fatalf("failed redirected download left staging files: entries=%d err=%v", len(remaining), err)
			}
		})
	}
}

func TestInspectPreservesCanceledRequestCause(t *testing.T) {
	fixture := newReleaseFixture(t, []byte("payload"))
	fixture.serve(t, true, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Inspect(ctx, fixture.options())
	if !errors.Is(err, context.Canceled) || fixture.manifestRequests != 0 || fixture.payloadRequests != 0 {
		t.Fatalf("canceled request cause or no-asset boundary lost: %v", err)
	}
}

// Use real local HTTP/TLS and net/http redirects, never a public network or a
// replacement verification implementation. The TLS certificate is trusted only
// by this fixture client; production transport validation is unchanged.
func signedRedirectClient(t *testing.T, fixture *releaseFixture) (*http.Client, *[3]atomic.Int32) {
	t.Helper()
	downloads := new([3]atomic.Int32)
	cdn := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.Host != "release-assets.githubusercontent.com" || request.URL.RawQuery != "se=fixture-expiry&sig=synthetic" {
			http.Error(w, "unexpected synthetic CDN request", http.StatusBadRequest)
			return
		}
		var index int
		var data []byte
		switch request.URL.Path {
		case "/fixture/1":
			index, data = 0, fixture.manifest
		case "/fixture/2":
			index, data = 1, fixture.signature
		case "/fixture/3":
			index, data = 2, fixture.payload
		default:
			http.NotFound(w, request)
			return
		}
		downloads[index].Add(1)
		writeBytes(w, data)
	}))
	t.Cleanup(cdn.Close)
	roots := x509.NewCertPool()
	roots.AddCert(cdn.Certificate())
	cdnURL, err := url.Parse(cdn.URL)
	if err != nil {
		t.Fatal(err)
	}
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: cdnURL.Hostname(), MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			switch address {
			case "release-assets.githubusercontent.com:443":
				address = cdn.Listener.Addr().String()
			case fixture.server.Listener.Addr().String():
			default:
				return nil, fmt.Errorf("fixture refuses network destination %q", address)
			}
			return dialer.DialContext(ctx, network, address)
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}, downloads
}

func TestInspectDoesNotDownloadPayloadUntilManifestAuthenticates(t *testing.T) {
	fixture := newReleaseFixture(t, []byte("payload"))
	fixture.signature[0] ^= 0x80
	fixture.serve(t, true, nil)
	result, err := Inspect(context.Background(), fixture.options())
	if err != nil {
		t.Fatal(err)
	}
	if result.Verification.Valid || result.Verification.SignatureValid || result.Verification.ArtifactsChecked {
		t.Fatalf("invalid signature was not stopped at metadata gate: %+v", result.Verification)
	}
	if fixture.payloadRequests != 0 {
		t.Fatalf("downloaded payload before authenticating manifest: %d requests", fixture.payloadRequests)
	}
}

func TestInspectRejectsMutableAndMismatchedReleases(t *testing.T) {
	t.Run("mutable release", func(t *testing.T) {
		fixture := newReleaseFixture(t, []byte("payload"))
		fixture.immutable = false
		fixture.serve(t, true, nil)
		if _, err := Inspect(context.Background(), fixture.options()); err == nil || !strings.Contains(err.Error(), "immutable") {
			t.Fatalf("mutable release accepted: %v", err)
		}
		if fixture.manifestRequests != 0 || fixture.payloadRequests != 0 {
			t.Fatal("requested assets from mutable release")
		}
	})

	t.Run("wrong target", func(t *testing.T) {
		fixture := newReleaseFixture(t, []byte("payload"))
		fixture.optionsRevision = "board-r2"
		fixture.serve(t, true, nil)
		result, err := Inspect(context.Background(), fixture.options())
		if err != nil || result.Verification.Valid || result.Verification.TargetMatched {
			t.Fatalf("wrong hardware release accepted: result=%+v err=%v", result, err)
		}
		if fixture.payloadRequests != 0 {
			t.Fatal("downloaded payload for mismatched hardware")
		}
	})

	t.Run("tag mismatch", func(t *testing.T) {
		fixture := newReleaseFixture(t, []byte("payload"))
		fixture.optionsTag = "v0.1.1"
		fixture.releaseTag = "v0.1.1"
		fixture.serve(t, true, nil)
		result, err := Inspect(context.Background(), fixture.options())
		if err != nil || result.Verification.Valid || !strings.Contains(strings.Join(result.Verification.Findings, " "), "does not match") {
			t.Fatalf("signed tag mismatch accepted: result=%+v err=%v", result, err)
		}
		if fixture.payloadRequests != 0 {
			t.Fatal("downloaded payload for mismatched signed tag")
		}
	})
}

func TestInspectRejectsNonSemVerTagBeforeNetworkAccess(t *testing.T) {
	_, err := Inspect(context.Background(), Options{
		APIBase: "http://127.0.0.1:1", Owner: ProjectOwner, Repository: ProjectRepository,
		Tag: "v01.2.3", PublicKey: make([]byte, ed25519.PublicKeySize),
		ModelID: "wd-my-cloud-ex4", Revision: "board-r1", Channel: "nightly",
	})
	if err == nil || !strings.Contains(err.Error(), "strict v-prefixed SemVer") {
		t.Fatalf("non-SemVer release tag was not rejected during preflight: %v", err)
	}
}

func TestInspectRejectsUnlistedOrTamperedPayload(t *testing.T) {
	t.Run("unlisted asset", func(t *testing.T) {
		fixture := newReleaseFixture(t, []byte("payload"))
		fixture.extraAsset = true
		fixture.serve(t, true, nil)
		result, err := Inspect(context.Background(), fixture.options())
		if err != nil || result.Verification.Valid || !strings.Contains(strings.Join(result.Verification.Findings, " "), "unlisted") {
			t.Fatalf("unlisted asset accepted: result=%+v err=%v", result, err)
		}
		if fixture.payloadRequests != 0 {
			t.Fatal("downloaded payload from a release with unlisted assets")
		}
	})

	t.Run("changed bytes", func(t *testing.T) {
		fixture := newReleaseFixture(t, []byte("payload"))
		fixture.payload = []byte("tamper!") // Same size; manifest hash remains unchanged.
		fixture.serve(t, true, nil)
		result, err := Inspect(context.Background(), fixture.options())
		if err != nil || result.Verification.Valid || result.Verification.ArtifactsValid {
			t.Fatalf("tampered payload accepted: result=%+v err=%v", result, err)
		}
		if result.Verification.Artifacts[0].SHA256Match {
			t.Fatalf("tampered payload hash matched: %+v", result.Verification.Artifacts[0])
		}
	})
}

func TestInspectRejectsForeignAssetURLBeforeNetworkRequest(t *testing.T) {
	fixture := newReleaseFixture(t, []byte("payload"))
	fixture.foreignAssetURL = true
	fixture.serve(t, true, nil)
	if _, err := Inspect(context.Background(), fixture.options()); err == nil || !strings.Contains(err.Error(), "asset URL") {
		t.Fatalf("foreign asset URL accepted: %v", err)
	}
	if fixture.manifestRequests != 0 || fixture.payloadRequests != 0 {
		t.Fatal("requested bytes from an untrusted asset URL")
	}
}

func TestRedirectPolicyAllowsOnlyGitHubTransportHosts(t *testing.T) {
	base, _ := url.Parse("https://api.github.com")
	for _, target := range []string{
		"https://api.github.com/repos/PhantoNull/phantowd-ex4/releases/assets/1",
		"https://github.com/PhantoNull/phantowd-ex4/releases/download/v0.1.0/manifest.sig",
		"https://release-assets.githubusercontent.com/file",
		"https://release-assets.githubusercontent.com/file?se=fixture-expiry&sig=synthetic",
		"https://release-assets.githubusercontent.com:443/file?sig=synthetic",
	} {
		parsed, _ := url.Parse(target)
		if !isAllowedRedirect(parsed, base) {
			t.Errorf("trusted GitHub host rejected: %s", target)
		}
	}
	for _, target := range []string{
		"https://evil.example/payload",
		"https://github.com.evil.example/payload",
		"https://githubusercontent.com.evil.example/payload",
		"https://release-assets.githubusercontent.com:444/payload",
		"http://api.github.com/payload",
		"http://release-assets.githubusercontent.com/file?sig=synthetic",
		"https://release-assets.githubusercontent.com.evil.example/file?sig=synthetic",
		"https://api.github.com/payload?sig=synthetic",
		"https://github.com/payload?sig=synthetic",
		"https://objects.githubusercontent.com/payload?sig=synthetic",
		"https://user@release-assets.githubusercontent.com/file?sig=synthetic",
		"https://release-assets.githubusercontent.com/file?sig=synthetic#fragment",
		"https://release-assets.githubusercontent.com:444/file?sig=synthetic",
	} {
		parsed, _ := url.Parse(target)
		if isAllowedRedirect(parsed, base) {
			t.Errorf("untrusted redirect accepted: %s", target)
		}
	}
}

type releaseFixture struct {
	testingT          *testing.T
	server            *httptest.Server
	manifest          []byte
	signature         []byte
	publicKey         ed25519.PublicKey
	payload           []byte
	assets            []releaseAsset
	releaseTag        string
	optionsTag        string
	optionsRevision   string
	immutable         bool
	extraAsset        bool
	foreignAssetURL   bool
	signedRedirects   bool
	assetURLQuery     bool
	metadataTransform func(string) string
	metadataRequests  int
	manifestRequests  int
	signatureRequests int
	payloadRequests   int
}

func newReleaseFixture(t *testing.T, payload []byte) *releaseFixture {
	t.Helper()
	seed := sha256.Sum256([]byte("githubrelease deterministic synthetic fixture key"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	publicKeyHash := sha256.Sum256(publicKey)
	payloadHash := sha256.Sum256(payload)
	manifest := releaseverify.Manifest{
		Format: "phantowd-release-manifest", SchemaVersion: 1, Product: "phantowd",
		ReleaseVersion: "v0.1.0", Channel: "nightly", ModelID: "wd-my-cloud-ex4",
		HardwareRevisions: []string{"board-r1"}, SourceCommit: strings.Repeat("a", 40),
		BuildrootVersion: "2025.02.18", KernelVersion: "6.18.53", MinimumInstaller: "v0.1.0",
		SigningKeyID: "sha256:" + hex.EncodeToString(publicKeyHash[:]),
		Artifacts:    []releaseverify.Artifact{{Name: "firmware.swu", Role: "swupdate-bundle", SizeBytes: int64(len(payload)), SHA256: hex.EncodeToString(payloadHash[:])}},
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return &releaseFixture{
		manifest: manifestBytes, signature: ed25519.Sign(privateKey, manifestBytes), publicKey: publicKey,
		payload: append([]byte(nil), payload...), releaseTag: "v0.1.0", optionsTag: "v0.1.0",
		optionsRevision: "board-r1", immutable: true,
	}
}

func (f *releaseFixture) options() Options {
	return Options{
		APIBase: f.server.URL, Owner: "PhantoNull", Repository: "phantowd-ex4", Tag: f.optionsTag,
		PublicKey: f.publicKey, ModelID: "wd-my-cloud-ex4", Revision: f.optionsRevision, Channel: "nightly",
	}
}

func (f *releaseFixture) serve(t *testing.T, prerelease bool, payloadOverride []byte) {
	t.Helper()
	f.testingT = t
	if payloadOverride != nil {
		f.payload = append([]byte(nil), payloadOverride...)
	}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("User-Agent") != "phantowd-lab-release-inspector" {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/repos/PhantoNull/phantowd-ex4/") {
			http.Error(w, "unexpected path", http.StatusNotFound)
			return
		}
		if r.URL.Path == "/repos/PhantoNull/phantowd-ex4/releases/tags/"+f.optionsTag {
			f.metadataRequests++
			f.writeRelease(w, prerelease)
			return
		}
		switch r.URL.Path {
		case "/repos/PhantoNull/phantowd-ex4/releases/assets/1":
			f.manifestRequests++
			f.writeAsset(w, r, 1, f.manifest)
		case "/repos/PhantoNull/phantowd-ex4/releases/assets/2":
			f.signatureRequests++
			f.writeAsset(w, r, 2, f.signature)
		case "/repos/PhantoNull/phantowd-ex4/releases/assets/3":
			f.payloadRequests++
			f.writeAsset(w, r, 3, f.payload)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.server.Close)
}

func (f *releaseFixture) writeAsset(w http.ResponseWriter, request *http.Request, id int, data []byte) {
	if f.signedRedirects {
		http.Redirect(w, request, fmt.Sprintf("https://release-assets.githubusercontent.com/fixture/%d?se=fixture-expiry&sig=synthetic", id), http.StatusFound)
		return
	}
	writeBytes(w, data)
}

func (f *releaseFixture) writeRelease(w http.ResponseWriter, prerelease bool) {
	manifestURL := f.assetURL(1)
	if f.assetURLQuery {
		manifestURL += "?sig=synthetic"
	}
	if f.foreignAssetURL {
		manifestURL = "https://attacker.example/releases/assets/1"
	}
	f.assets = []releaseAsset{
		{ID: 1, Name: ManifestName, Size: int64(len(f.manifest)), URL: manifestURL, State: "uploaded"},
		{ID: 2, Name: SignatureName, Size: int64(len(f.signature)), URL: f.assetURL(2), State: "uploaded"},
		{ID: 3, Name: "firmware.swu", Size: int64(len(f.payload)), URL: f.assetURL(3), State: "uploaded"},
	}
	if f.extraAsset {
		f.assets = append(f.assets, releaseAsset{ID: 4, Name: "unexpected.bin", Size: 1, URL: f.assetURL(4), State: "uploaded"})
	}
	body := map[string]any{"id": 77, "tag_name": f.releaseTag, "draft": false, "prerelease": prerelease, "immutable": f.immutable, "assets": f.assets}
	w.Header().Set("Content-Type", "application/json")
	if f.metadataTransform != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			f.testingT.Error(err)
			return
		}
		_, _ = w.Write([]byte(f.metadataTransform(string(encoded))))
		return
	}
	_ = json.NewEncoder(w).Encode(body)
}

func (f *releaseFixture) assetURL(id int64) string {
	return fmt.Sprintf("%s/repos/PhantoNull/phantowd-ex4/releases/assets/%d", f.server.URL, id)
}

func writeBytes(w http.ResponseWriter, data []byte) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprint(len(data)))
	_, _ = w.Write(data)
}
