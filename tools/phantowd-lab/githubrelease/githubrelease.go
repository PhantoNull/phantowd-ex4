// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package githubrelease inspects versioned public GitHub Releases without an
// installation path. GitHub is treated as transport; releaseverify remains the
// authenticity and exact-target boundary.
package githubrelease

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-lab/releaseverify"
)

const (
	DefaultAPIBase    = "https://api.github.com"
	ProjectOwner      = "PhantoNull"
	ProjectRepository = "phantowd-ex4"
	ManifestName      = "manifest.json"
	SignatureName     = "manifest.sig"
	maxReleaseJSON    = 1 << 20
	maxReleaseAssets  = 18
)

var (
	repositoryPart = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$`)
)

// Options describes one exact, versioned public release. APIBase is exported
// for deterministic local tests; the product CLI uses only api.github.com.
type Options struct {
	Client     *http.Client
	APIBase    string
	Owner      string
	Repository string
	Tag        string
	PublicKey  []byte
	ModelID    string
	Revision   string
	Channel    string
}

// Result contains verification evidence, never an install authorization.
type Result struct {
	Tag          string               `json:"tag"`
	ReleaseID    int64                `json:"release_id"`
	Verification releaseverify.Report `json:"verification"`
}

type release struct {
	ID         int64          `json:"id"`
	TagName    string         `json:"tag_name"`
	Draft      bool           `json:"draft"`
	Prerelease bool           `json:"prerelease"`
	Immutable  bool           `json:"immutable"`
	Assets     []releaseAsset `json:"assets"`
}

type releaseAsset struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Size  int64  `json:"size"`
	URL   string `json:"url"`
	State string `json:"state"`
}

// Inspect downloads one exact release's signed manifest, then only the payloads
// named by that verified manifest. Payloads are written to a private temporary
// directory, hashed there, and removed before returning. No device is accessed.
func Inspect(ctx context.Context, options Options) (Result, error) {
	result := Result{Tag: options.Tag}
	if err := validateOptions(options); err != nil {
		return result, err
	}
	if options.APIBase == "" {
		options.APIBase = DefaultAPIBase
	}
	base, err := url.Parse(strings.TrimRight(options.APIBase, "/"))
	if err != nil || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || (base.Scheme != "https" && !(base.Scheme == "http" && isLoopbackHost(base.Hostname()))) {
		return result, errors.New("GitHub API base must be HTTPS; HTTP is allowed only for loopback tests")
	}
	if base.Scheme == "https" && (!strings.EqualFold(base.Host, "api.github.com") || base.Path != "") {
		return result, errors.New("public release inspection is restricted to api.github.com")
	}
	client := options.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Minute}
	}
	client = withSafeRedirects(client, base)

	releaseURL := *base
	releaseURL.Path = strings.TrimRight(base.Path, "/") + "/repos/" + options.Owner + "/" + options.Repository + "/releases/tags/" + options.Tag
	releaseData, err := getBounded(ctx, client, releaseURL.String(), "application/vnd.github+json", maxReleaseJSON)
	if err != nil {
		return result, fmt.Errorf("get GitHub release: %w", err)
	}
	var metadata release
	if err := decodeRelease(releaseData, &metadata); err != nil {
		return result, err
	}
	result.ReleaseID = metadata.ID
	if metadata.ID <= 0 || metadata.TagName != options.Tag || metadata.Draft || !metadata.Immutable {
		return result, errors.New("GitHub response is not the requested published immutable release")
	}
	if (options.Channel == "stable") == metadata.Prerelease {
		return result, errors.New("GitHub prerelease flag does not match the requested stable/non-stable channel")
	}
	assets, err := indexAssets(metadata.Assets)
	if err != nil {
		return result, err
	}
	manifestAsset, ok := assets[ManifestName]
	if !ok || manifestAsset.Size <= 0 || manifestAsset.Size > 64*1024 {
		return result, errors.New("release must contain one bounded manifest.json asset")
	}
	signatureAsset, ok := assets[SignatureName]
	if !ok || signatureAsset.Size != 64 {
		return result, errors.New("release must contain one 64-byte manifest.sig asset")
	}
	if err := validateAssetURL(manifestAsset.URL, base, options.Owner, options.Repository, manifestAsset.ID); err != nil {
		return result, err
	}
	if err := validateAssetURL(signatureAsset.URL, base, options.Owner, options.Repository, signatureAsset.ID); err != nil {
		return result, err
	}
	manifestBytes, err := getAssetBounded(ctx, client, manifestAsset.URL, manifestAsset.Size, 64*1024)
	if err != nil {
		return result, fmt.Errorf("download signed release manifest: %w", err)
	}
	signatureBytes, err := getAssetBounded(ctx, client, signatureAsset.URL, signatureAsset.Size, 64)
	if err != nil {
		return result, fmt.Errorf("download detached release signature: %w", err)
	}
	verified, report, err := releaseverify.InspectManifest(bytes.NewReader(manifestBytes), bytes.NewReader(signatureBytes), options.PublicKey, options.ModelID, options.Revision, options.Channel)
	result.Verification = report
	if err != nil {
		return result, err
	}
	if verified == nil {
		return result, nil
	}
	if verified.ReleaseVersion() != options.Tag {
		result.Verification.Findings = append(result.Verification.Findings, "signed release_version does not match the immutable GitHub tag")
		return result, nil
	}
	if verified.Channel() != options.Channel {
		result.Verification.Findings = append(result.Verification.Findings, "signed channel does not match the requested channel")
		return result, nil
	}

	specifications := verified.Artifacts()
	if len(assets) != len(specifications)+2 {
		result.Verification.Findings = append(result.Verification.Findings, "GitHub release has missing or unlisted assets")
		return result, nil
	}
	for _, specification := range specifications {
		if specification.Name == ManifestName || specification.Name == SignatureName {
			result.Verification.Findings = append(result.Verification.Findings, "signed payload name collides with a reserved release metadata asset")
			return result, nil
		}
		asset, ok := assets[specification.Name]
		if !ok || asset.Size != specification.SizeBytes {
			result.Verification.Findings = append(result.Verification.Findings, "GitHub asset is missing or its advertised size differs from the signed manifest: "+specification.Name)
			return result, nil
		}
		if err := validateAssetURL(asset.URL, base, options.Owner, options.Repository, asset.ID); err != nil {
			return result, err
		}
	}

	stage, err := os.MkdirTemp("", "phantowd-release-check-")
	if err != nil {
		return result, fmt.Errorf("create temporary release-check directory: %w", err)
	}
	defer os.RemoveAll(stage)
	for _, specification := range specifications {
		asset := assets[specification.Name]
		if err := downloadAsset(ctx, client, asset.URL, filepath.Join(stage, specification.Name), specification.SizeBytes); err != nil {
			return result, fmt.Errorf("download release payload %s: %w", specification.Name, err)
		}
	}
	result.Verification = verified.VerifyArtifacts(stage)
	return result, nil
}

func validateOptions(options Options) error {
	if !repositoryPart.MatchString(options.Owner) || !repositoryPart.MatchString(options.Repository) {
		return errors.New("GitHub owner and repository must be single path components")
	}
	if _, err := releaseverify.CompareVersions(options.Tag, options.Tag); err != nil {
		return errors.New("release tag must use strict v-prefixed SemVer 2.0 syntax")
	}
	if len(options.PublicKey) != 32 {
		return errors.New("trusted Ed25519 public key must be exactly 32 bytes")
	}
	if options.Channel != "stable" && options.Channel != "beta" && options.Channel != "nightly" {
		return errors.New("requested channel must be stable, beta, or nightly")
	}
	return nil
}

func decodeRelease(data []byte, destination *release) error {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode GitHub release metadata: %w", err)
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("GitHub release metadata has trailing JSON")
	}
	if len(destination.Assets) > maxReleaseAssets {
		return errors.New("GitHub release contains too many assets")
	}
	return nil
}

func indexAssets(input []releaseAsset) (map[string]releaseAsset, error) {
	if len(input) == 0 || len(input) > maxReleaseAssets {
		return nil, errors.New("GitHub release asset count is empty or exceeds the limit")
	}
	assets := make(map[string]releaseAsset, len(input))
	ids := make(map[int64]bool, len(input))
	for _, asset := range input {
		if asset.ID <= 0 || ids[asset.ID] || asset.Name == "" || asset.Size < 0 || asset.State != "uploaded" {
			return nil, errors.New("GitHub release contains an invalid or incomplete asset record")
		}
		if _, exists := assets[asset.Name]; exists {
			return nil, errors.New("GitHub release contains duplicate asset names")
		}
		assets[asset.Name] = asset
		ids[asset.ID] = true
	}
	return assets, nil
}

func validateAssetURL(raw string, base *url.URL, owner, repository string, id int64) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return errors.New("GitHub asset URL is malformed")
	}
	wantPath := strings.TrimRight(base.Path, "/") + "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repository) + "/releases/assets/" + fmt.Sprint(id)
	if parsed.Scheme != base.Scheme || !strings.EqualFold(parsed.Host, base.Host) || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != wantPath {
		return errors.New("GitHub asset URL does not match the requested release asset endpoint")
	}
	return nil
}

func getBounded(ctx context.Context, client *http.Client, target, accept string, maximum int64) ([]byte, error) {
	request, err := newRequest(ctx, target, accept)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status %d", response.StatusCode)
	}
	if response.ContentLength > maximum {
		return nil, errors.New("HTTP response exceeds size limit")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, errors.New("HTTP response exceeds size limit")
	}
	return data, nil
}

func getAssetBounded(ctx context.Context, client *http.Client, target string, expected, maximum int64) ([]byte, error) {
	if expected <= 0 || expected > maximum {
		return nil, errors.New("GitHub asset size is invalid or exceeds the metadata limit")
	}
	data, err := getBounded(ctx, client, target, "application/octet-stream", maximum)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != expected {
		return nil, errors.New("downloaded GitHub asset size differs from API metadata")
	}
	return data, nil
}

func downloadAsset(ctx context.Context, client *http.Client, target, destination string, expected int64) error {
	request, err := newRequest(ctx, target, "application/octet-stream")
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP status %d", response.StatusCode)
	}
	if response.ContentLength >= 0 && response.ContentLength != expected {
		return errors.New("HTTP content length differs from signed artifact size")
	}
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	count, copyErr := io.Copy(file, io.LimitReader(response.Body, expected+1))
	syncErr := file.Sync()
	closeErr := file.Close()
	if copyErr != nil {
		return copyErr
	}
	if syncErr != nil {
		return syncErr
	}
	if closeErr != nil {
		return closeErr
	}
	if count != expected {
		return errors.New("downloaded payload size differs from signed artifact size")
	}
	return nil
}

func newRequest(ctx context.Context, target, accept string) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", accept)
	request.Header.Set("User-Agent", "phantowd-lab-release-inspector")
	request.Header.Set("X-GitHub-Api-Version", "2026-03-10")
	return request, nil
}

func withSafeRedirects(client *http.Client, apiBase *url.URL) *http.Client {
	copyOfClient := *client
	prior := client.CheckRedirect
	copyOfClient.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) > 3 {
			return errors.New("GitHub download exceeded redirect limit")
		}
		if !isAllowedRedirect(request.URL, apiBase) {
			return errors.New("GitHub download redirected outside the trusted GitHub asset domains")
		}
		if prior != nil {
			return prior(request, via)
		}
		return nil
	}
	return &copyOfClient
}

func isAllowedRedirect(target, apiBase *url.URL) bool {
	if target.User != nil || target.RawQuery != "" || target.Fragment != "" || (target.Port() != "" && target.Port() != "443") {
		return false
	}
	if target.Scheme != "https" {
		return target.Scheme == "http" && target.Host == apiBase.Host && isLoopbackHost(target.Hostname())
	}
	host := strings.ToLower(target.Hostname())
	if strings.EqualFold(target.Host, apiBase.Host) || host == "github.com" || host == "githubusercontent.com" {
		return true
	}
	return strings.HasSuffix(host, ".githubusercontent.com")
}

func isLoopbackHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
