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
