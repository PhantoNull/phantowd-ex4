//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"syscall"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicyrpc"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
	"golang.org/x/sys/unix"
)

const nasMainFixture = "/run/phantowd-nas-main"

// Real no-flag main, twice by explicit fixture choice, never automatic recovery.
// All state and credentials are fresh guest RAM; the original root Owner stays.
func exerciseQEMUNASPolicyMainProcess() error {
	if err := guardQEMUDataVolume(); err != nil {
		return err
	}
	if err := exerciseQEMUNASPolicyEvidence(); err != nil {
		return err
	}
	for _, entry := range []struct {
		path     string
		mode     os.FileMode
		uid, gid int
	}{
		{nasMainFixture, 0710, 0, 65534},
		{nasMainFixture + "/state", 0700, 0, 0},
		{nasMainFixture + "/accounts", 0700, 65534, 65534},
	} {
		if err := errors.Join(os.Mkdir(entry.path, entry.mode), os.Chown(entry.path, entry.uid, entry.gid)); err != nil {
			return err
		}
	}
	seed, err := naspolicystore.Open(nasMainFixture + "/state")
	if err != nil {
		return err
	}
	if err := errors.Join(seed.Commit(0, qemuPersistentNASPolicy(1)), seed.Close()); err != nil {
		return err
	}
	owner, err := naspolicystore.OpenOwner(nasMainFixture + "/state")
	if err != nil {
		return err
	}
	defer owner.Close()
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: nasMainFixture + "/channel", Net: "unix"})
	if err != nil {
		return err
	}
	defer l.Close()
	if err := errors.Join(os.Chmod(nasMainFixture+"/channel", 0660), os.Chown(nasMainFixture+"/channel", 0, 65534)); err != nil {
		return err
	}
	transport, err := qemuNASMainTLS()
	if err != nil {
		return err
	}
	defer transport.CloseIdleConnections()
	password := rand.Text()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for revision := uint64(1); revision <= 3; revision += 2 {
		if err := qemuNASMainLifetime(ctx, owner, l, transport, password, revision); err != nil {
			return fmt.Errorf("NAS standard main lifetime %d: %w", revision, err)
		}
	}
	if err := owner.Close(); err != nil {
		return err
	}
	fmt.Println("PHANTOWD_NAS_POLICY_MAIN_READY standard_main=true api_uid=65534 https=verified setup=true login=true lifetimes=2 credentials_retained=true original_owner=true busy=true commit=true conflict=true shutdown=clean peer_pid=true scope=disposable-qemu-only")
	fmt.Println("PHANTOWD_NAS_POLICY_SUMMARY_READY standard_main=true https=verified lifetimes=2 original_owner=true read_only=true counts=verified scope=disposable-qemu-only")
	fmt.Println("PHANTOWD_NAS_POLICY_BACKUP_READY standard_main=true https=verified lifetimes=2 original_owner=true read_only=true full_policy=true scope=disposable-qemu-only")
	fmt.Println("PHANTOWD_NAS_FILE_EDITOR_READY standard_main=true https=verified lifetimes=2 original_owner=true saved=true iscsi_preserved=true busy=true conflict=true scope=disposable-qemu-only")
	fmt.Println("PHANTOWD_NAS_RESTORE_PREVIEW_READY standard_main=true https=verified lifetimes=2 original_owner=true full_policy=true uint64_exact=true read_only=true scope=disposable-qemu-only")
	fmt.Println("PHANTOWD_NAS_RESTORE_DISPLAY_READY standard_main=true https=verified lifetimes=2 saved_and_candidate=true decimal_capacities=exact scope=disposable-qemu-only")
	return nil
}

func qemuNASMainTLS() (*http.Transport, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	encoded, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	public := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := errors.Join(os.WriteFile(nasMainFixture+"/cert.pem", public, 0644),
		os.WriteFile(nasMainFixture+"/key.pem", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: encoded}), 0600),
		os.Chown(nasMainFixture+"/key.pem", 65534, 65534)); err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(public) {
		return nil, errors.New("main fixture certificate refused")
	}
	return &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}, nil
}

type qemuNASMainHTTP struct {
	client       *http.Client
	origin, csrf string
}

func (h *qemuNASMainHTTP) request(ctx context.Context, path string, body any, want int, out any, headers ...[2]string) error {
	var payload bytes.Buffer
	method := http.MethodGet
	if body != nil {
		method = http.MethodPost
		if path == nasStatePath || path == serviceStatePath {
			method = http.MethodPut
		}
		if err := json.NewEncoder(&payload).Encode(body); err != nil {
			return err
		}
	}
	r, err := http.NewRequestWithContext(ctx, method, h.origin+path, &payload)
	if err != nil {
		return err
	}
	r.Header.Set("Origin", h.origin)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-PhantoWD-CSRF", h.csrf)
	for _, header := range headers {
		r.Header.Set(header[0], header[1])
	}
	response, err := h.client.Do(r)
	if err != nil {
		return errors.New("main fixture HTTPS request failed")
	}
	limit := int64(naspolicy.MaxInputBytes + 8192)
	if path == nasRestorePreviewPath {
		limit = 2*naspolicy.MaxInputBytes + 8192
	}
	data, err := readSelfTestResponse(response, limit)
	if err != nil || response.StatusCode != want || response.Header.Get("Cache-Control") != "no-store" {
		return fmt.Errorf("main fixture response refused: %s status=%d expected=%d", path, response.StatusCode, want)
	}
	if out != nil && json.Unmarshal(data, out) != nil {
		return errors.New("main fixture response malformed")
	}
	if path == nasStatePath && (want == 503 && response.Header.Get("Retry-After") != "1" || want == 409 && response.Header.Get("Retry-After") != "") {
		return errors.New("main fixture refusal retry metadata differs")
	}
	return nil
}

func qemuNASMainLifetime(ctx context.Context, owner *naspolicystore.Owner, listener *net.UnixListener, transport *http.Transport, password string, revision uint64) error {
	lease, err := owner.Acquire(ctx, revision)
	if err != nil {
		return err
	}
	defer lease.Release()
	port, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	address := port.Addr().String()
	if err := port.Close(); err != nil {
		return err
	}
	h := &qemuNASMainHTTP{client: &http.Client{Transport: transport, Timeout: 5 * time.Second}, origin: "https://" + address}
	cmd := exec.CommandContext(ctx, "/usr/bin/phantowd-api")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C", "PHANTOWD_STATE_DIR=" + nasMainFixture + "/accounts",
		listenAddressEnv + "=" + address, publicOriginEnv + "=" + h.origin, tlsCertFileEnv + "=" + nasMainFixture + "/cert.pem",
		tlsKeyFileEnv + "=" + nasMainFixture + "/key.pem", "PHANTOWD_NAS_POLICY_SOCKET=" + nasMainFixture + "/channel"}
	cmd.Dir, cmd.Stderr, cmd.WaitDelay = "/", os.Stderr, time.Second
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}, Setpgid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	waited, joined := false, false
	defer func() {
		if !waited {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()
	deadline, _ := ctx.Deadline()
	if err := listener.SetDeadline(deadline); err != nil {
		return err
	}
	conn, err := listener.AcceptUnix()
	if err != nil {
		return errors.New("main fixture policy connection missing")
	}
	defer conn.Close()
	if !qemuNASMainPeer(conn, cmd.Process.Pid) {
		return errors.New("main fixture policy peer differs")
	}
	server, err := naspolicyrpc.NewServer(owner, 65534)
	if err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, conn) }()
	defer func() {
		conn.Close()
		if !joined {
			<-done
		}
	}()
	ready := false
	for attempt := 0; attempt < 20 && ctx.Err() == nil; attempt++ {
		var health struct{ Status, Scope string }
		if h.request(ctx, "/healthz", nil, 200, &health) == nil && health.Status == "ok" && health.Scope == "process_only" {
			ready = true
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	if !ready {
		return errors.New("main fixture readiness failed")
	}
	if err := h.request(ctx, nasStatePath, nil, 401, nil); err != nil {
		return err
	}
	if err := h.request(ctx, nasSummaryPath, nil, 401, nil); err != nil {
		return err
	}
	if err := h.request(ctx, nasBackupPath, nil, 401, nil); err != nil {
		return err
	}
	var status authStatus
	if err := h.request(ctx, authStatusPath, nil, 200, &status); err != nil {
		return err
	}
	if status.SetupRequired != (revision == 1) || status.Authenticated {
		return errors.New("main fixture account lifecycle differs")
	}
	credentials, want := setupRequest{Username: "qemu-main", Password: password}, 201
	if revision != 1 {
		want = 409
	}
	h.client.Jar = newQEMUCookieJar()
	if err := h.request(ctx, authSetupPath, credentials, want, nil); err != nil {
		return err
	}
	h.client.Jar = newQEMUCookieJar()
	if err := h.request(ctx, authLoginPath, credentials, 200, nil); err != nil {
		return err
	}
	var session struct {
		CSRF string `json:"csrf_token"`
	}
	if err := h.request(ctx, authSessionPath, nil, 200, &session); err != nil {
		return err
	}
	if session.CSRF == "" {
		return errors.New("main fixture session missing")
	}
	h.csrf = session.CSRF
	check := func(wantRevision uint64) error {
		var reply nasStateResponse
		if err := h.request(ctx, nasStatePath, nil, 200, &reply); err != nil {
			return err
		}
		got, err := owner.Snapshot(ctx)
		if err != nil || !reflect.DeepEqual(got, qemuPersistentNASPolicy(wantRevision)) || reply.Configuration == nil || !reflect.DeepEqual(*reply.Configuration, got) || reply.Revision != wantRevision || reply.Saved || reply.Applied || reply.ActivationAvailable || reply.SchemaVersion != 1 || reply.Scope != "stored-desired-nas-policy-only" {
			return errors.New("main fixture original Owner readback differs")
		}
		if !reflect.DeepEqual(reply.BackingCapacities, nasBackingCapacities(got)) {
			return errors.New("main fixture saved capacity display differs")
		}
		var summary map[string]any
		if err := h.request(ctx, nasSummaryPath, nil, 200, &summary); err != nil {
			return err
		}
		luns := 0
		for _, target := range got.ISCSI.Targets {
			luns += len(target.LUNs)
		}
		want := map[string]any{"schema_version": float64(1), "scope": "stored-desired-nas-policy-summary-only", "revision": float64(wantRevision),
			"volumes": float64(len(got.FileServices.Shares.Volumes)), "users": float64(len(got.FileServices.Shares.Users)),
			"smb_shares": float64(len(got.FileServices.Shares.Shares)), "nfs_exports": float64(len(got.FileServices.NFS.Exports)),
			"iscsi_targets": float64(len(got.ISCSI.Targets)), "iscsi_backings": float64(len(got.ISCSI.Backings)), "iscsi_luns": float64(luns),
			"applied": false, "activation_available": false}
		if !reflect.DeepEqual(summary, want) {
			return errors.New("main fixture compact NAS summary differs")
		}
		var backup struct {
			Format        string           `json:"format"`
			SchemaVersion int              `json:"schema_version"`
			Configuration naspolicy.Config `json:"configuration"`
		}
		if err := h.request(ctx, nasBackupPath, nil, 200, &backup); err != nil {
			return err
		}
		if backup.Format != nasBackupFormat || backup.SchemaVersion != 1 || !reflect.DeepEqual(backup.Configuration, got) {
			return errors.New("main fixture complete NAS policy backup differs")
		}
		// The decoded download owns its values; neither the Owner nor got changes.
		backup.Configuration.ISCSI.Backings[0].CapacityBytes = (1 << 63) - 512
		var preview struct {
			Wire       string            `json:"candidate_json"`
			Capacities map[string]string `json:"backing_capacities"`
			Matches    bool              `json:"matches_current"`
			Saved      bool              `json:"saved"`
		}
		if err := h.request(ctx, nasRestorePreviewPath, backup, 200, &preview, [2]string{serviceExpectedRevisionHeader, strconv.FormatUint(wantRevision, 10)}); err != nil {
			return err
		}
		candidate, err := naspolicy.Decode(bytes.NewReader([]byte(preview.Wire)))
		next := wantRevision + 1
		wantRestore := backup.Configuration
		wantRestore.Revision, wantRestore.FileServices.Revision, wantRestore.FileServices.Shares.Revision = next, next, next
		wantRestore.FileServices.NFS.Revision, wantRestore.FileServices.NFS.VolumeRevision = next, next
		wantRestore.ISCSI.Revision, wantRestore.ISCSI.VolumeRevision = next, next
		after, observeErr := owner.Snapshot(ctx)
		if err != nil || observeErr != nil || preview.Matches || preview.Saved || !reflect.DeepEqual(candidate, wantRestore) || !reflect.DeepEqual(after, got) {
			return errors.New("main fixture lossless complete restore preview changed state or values")
		}
		if !reflect.DeepEqual(preview.Capacities, nasBackingCapacities(backup.Configuration)) {
			return errors.New("main fixture restore capacity display differs")
		}
		var editor serviceStateResponse
		if err := h.request(ctx, serviceStatePath, nil, 200, &editor); err != nil {
			return err
		}
		if !editor.Initialized || editor.Configuration == nil || !reflect.DeepEqual(*editor.Configuration, got.FileServices) || editor.Applied || editor.RuntimeValidated || editor.ActivationAvailable {
			return errors.New("main fixture NAS-backed editor read differs")
		}
		return nil
	}
	if err := check(revision); err != nil {
		return err
	}
	next := qemuPersistentNASPolicy(revision + 1)
	var refusal map[string]string
	if err := h.request(ctx, nasStatePath, next, 503, &refusal); err != nil {
		return err
	}
	if len(refusal) != 1 || refusal["error"] != "nas_configuration_busy" {
		return errors.New("main fixture busy refusal differs")
	}
	if err := h.request(ctx, serviceStatePath, next.FileServices, 503, &refusal); err != nil {
		return err
	}
	if err := errors.Join(lease.Verify(ctx), check(revision)); err != nil {
		return err
	}
	if err := lease.Release(); err != nil {
		return err
	}
	var saved nasStateResponse
	if err := h.request(ctx, nasStatePath, next, 200, &saved); err != nil {
		return err
	}
	if !saved.Saved || saved.Revision != revision+1 || saved.Configuration != nil || saved.Applied || saved.ActivationAvailable || saved.SchemaVersion != 1 || saved.Scope != "stored-desired-nas-policy-only" {
		return errors.New("main fixture save envelope differs")
	}
	if err := h.request(ctx, nasStatePath, next, 409, &refusal); err != nil {
		return err
	}
	if len(refusal) != 1 || refusal["error"] != "nas_configuration_conflict" {
		return errors.New("main fixture stale refusal differs")
	}
	if err := check(revision + 1); err != nil {
		return err
	}
	next = qemuPersistentNASPolicy(revision + 2)
	if err := h.request(ctx, serviceStatePath, next.FileServices, 200, &saved); err != nil {
		return err
	}
	if !saved.Saved || saved.Revision != next.Revision || saved.Applied || saved.ActivationAvailable || saved.Scope != "development-stored-file-service-policy-only" {
		return errors.New("main fixture NAS-backed editor save differs")
	}
	if err := h.request(ctx, serviceStatePath, next.FileServices, 409, &refusal); err != nil {
		return err
	}
	if err := check(revision + 2); err != nil {
		return err
	}
	transport.CloseIdleConnections()
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		return err
	}
	err = cmd.Wait()
	waited = true
	if err != nil {
		return errors.New("main fixture shutdown failed")
	}
	settled := <-done
	joined = true
	if !errors.Is(settled, naspolicystore.ErrReview) {
		return errors.New("main fixture channel settlement differs")
	}
	got, err := owner.Snapshot(ctx)
	if err != nil || !reflect.DeepEqual(got, next) {
		return errors.New("main fixture stop changed original Owner")
	}
	return nil
}

func qemuNASMainPeer(conn *net.UnixConn, pid int) bool {
	raw, err := conn.SyscallConn()
	if err != nil {
		return false
	}
	var peer *unix.Ucred
	var lookup error
	err = raw.Control(func(fd uintptr) { peer, lookup = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	return err == nil && lookup == nil && peer != nil && int(peer.Pid) == pid && peer.Uid == 65534 && peer.Gid == 65534
}
