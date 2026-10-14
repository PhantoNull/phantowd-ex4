// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package githubrelease

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

func TestInspectRedactsSignedManifestBodyReadFailure(t *testing.T) {
	assertSignedBodyFailure(t, 1)
}

func TestInspectRedactsSignedPayloadBodyReadFailure(t *testing.T) {
	assertSignedBodyFailure(t, 3)
}

func TestInspectRedactsSignedSignatureBodyReadFailure(t *testing.T) {
	assertSignedBodyFailure(t, 2)
}

func assertSignedBodyFailure(t *testing.T, assetID int) {
	t.Helper()
	stageParent := t.TempDir()
	for _, variable := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(variable, stageParent)
	}
	fixture := newReleaseFixture(t, []byte("synthetic payload"))
	fixture.signedRedirects = true
	fixture.serve(t, true, nil)
	client, downloads := signedRedirectClient(t, fixture)
	fault := &releaseBodyFaultTransport{inner: client.Transport, path: fmt.Sprintf("/fixture/%d", assetID)}
	client.Transport = fault
	options := fixture.options()
	options.Client = client
	result, err := Inspect(context.Background(), options)
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("body failure cause was lost: %v", err)
	}
	if strings.Contains(err.Error(), "sig=synthetic") || strings.Contains(err.Error(), "fixture-expiry") || strings.Contains(err.Error(), "release-assets.githubusercontent.com") {
		t.Fatalf("signed URL leaked from body-read failure: %v", err)
	}
	var requestCause *url.Error
	if !errors.As(err, &requestCause) || requestCause.URL != "https://release-assets.githubusercontent.com"+fault.path+"?se=fixture-expiry&sig=synthetic" {
		t.Fatal("redaction did not preserve the exact cause for trusted programmatic inspection")
	}
	if result.Verification.Valid || result.Verification.InstallationAuthorized || result.Verification.ArtifactsChecked || result.Verification.SignatureValid != (assetID == 3) {
		t.Fatalf("failed body read crossed verification boundary: %+v", result)
	}
	for index := range downloads {
		want := int32(0)
		if index < assetID {
			want = 1
		}
		if downloads[index].Load() != want {
			t.Fatalf("failed body read fetched another asset or retried: asset=%d requests=%d", index+1, downloads[index].Load())
		}
	}
	if fault.reads.Load() != 1 || fault.closes.Load() != 1 {
		t.Fatal("failed response body was retried or left open")
	}
	remaining, readErr := os.ReadDir(stageParent)
	if readErr != nil || len(remaining) != 0 {
		t.Fatalf("failed body read left staging data: entries=%d err=%v", len(remaining), readErr)
	}
}

// Only inject at the external HTTP body boundary, after the real local TLS
// redirect succeeds. Authentication, parsing, hashing and cleanup are real.
// The synthetic url.Error models a reader that includes its request URL;
// this is not evidence that every standard-library read error includes one.
type releaseBodyFaultTransport struct {
	inner  http.RoundTripper
	path   string
	reads  atomic.Int32
	closes atomic.Int32
}

func (t *releaseBodyFaultTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.inner.RoundTrip(request)
	if err != nil || request.URL.Hostname() != "release-assets.githubusercontent.com" || request.URL.Path != t.path {
		return response, err
	}
	response.Body = &releaseFaultBody{
		ReadCloser: response.Body,
		owner:      t,
		cause:      &url.Error{Op: "read", URL: request.URL.String(), Err: context.Canceled},
	}
	return response, nil
}

type releaseFaultBody struct {
	io.ReadCloser
	owner *releaseBodyFaultTransport
	cause error
}

func (body *releaseFaultBody) Read(buffer []byte) (int, error) {
	body.owner.reads.Add(1)
	if len(buffer) == 0 {
		return 0, body.cause
	}
	count, err := body.ReadCloser.Read(buffer[:1])
	if err != nil {
		return count, err
	}
	return count, body.cause
}

func (body *releaseFaultBody) Close() error {
	body.owner.closes.Add(1)
	return body.ReadCloser.Close()
}
