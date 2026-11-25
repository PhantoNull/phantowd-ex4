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
	"net/http/cookiejar"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	root    = "/mnt/rc0-state"
	proof   = "/run/rc0-confirmed-policy.json"
	address = "127.0.0.1:18443"
	origin  = "https://" + address
	install = "c71c2ba76bd04d29816335c13c31a380"
	api     = "/usr/bin/phantowd-api"
	policy  = `{"format":"phantowd-nas-service-config","schema_version":1,"revision":1,"file_services":{"format":"phantowd-file-service-config","schema_version":1,"revision":1,"shares":{"format":"phantowd-share-config","schema_version":1,"revision":1,"volumes":[],"users":[],"shares":[]},"nfs":{"format":"phantowd-nfs-policy","schema_version":1,"revision":1,"volume_revision":1,"exports":[]}},"iscsi":{"format":"phantowd-iscsi-policy","schema_version":1,"revision":1,"volume_revision":1,"backings":[],"targets":[]}}`
)

func main() {
	if err := check(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("PHANTOWD_RC0_SUPERVISOR_READY phase=%s https_login=true tls=local_provisioned policy=confirmed same_file=refused wrong_bytes=refused synthetic_state=true clean_stop=true\n", os.Args[1])
}

func check() error {
	if len(os.Args) != 2 || (os.Args[1] != "seed" && os.Args[1] != "verify") {
		return errors.New("guest phase required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	secret, err := os.ReadFile("/rc0-fixture/password")
	if err != nil {
		return err
	}
	credentials, err := json.Marshal(map[string]string{"username": "rc0-admin", "password": strings.TrimSpace(string(secret))})
	if err != nil {
		return err
	}
	if os.Args[1] == "seed" {
		if err := seed(ctx, credentials); err != nil {
			return err
		}
	}
	if err := os.WriteFile(proof, []byte(policy), 0600); err != nil {
		return err
	}
	current := root + "/nas-policy/nas-services.json"
	if raw, err := os.ReadFile(current); err != nil || string(raw) != policy {
		return errors.New("persistent policy bytes differ before startup")
	}
	if err := expectRefusal(ctx, current); err != nil {
		return err
	}
	if err := os.WriteFile(proof+".wrong", []byte(policy+"\n"), 0600); err != nil {
		return err
	}
	if err := expectRefusal(ctx, proof+".wrong"); err != nil {
		return err
	}
	if os.Args[1] == "seed" {
		stage := root + "/.management-tls.provisioning"
		if err := os.WriteFile(stage, []byte("interrupted TLS fixture"), 0600); err != nil {
			return err
		}
		if err := expectRefusal(ctx, proof); err != nil {
			return err
		}
		if raw, err := os.ReadFile(stage); err != nil || string(raw) != "interrupted TLS fixture" {
			return errors.New("supervisor failed to preserve staged TLS evidence")
		}
		if err := os.Remove(stage); err != nil {
			return err
		}
	}
	if err := serve(ctx, credentials); err != nil {
		return err
	}
	if raw, err := os.ReadFile(current); err != nil || string(raw) != policy {
		return errors.New("persistent policy changed during startup")
	}
	if raw, err := os.ReadFile(root + "/accounts/accounts.json"); err != nil || bytes.Contains(raw, bytes.TrimSpace(secret)) {
		return errors.New("credential absent or held plaintext")
	}
	return nil
}

func seed(ctx context.Context, credentials []byte) error {
	if err := os.Mkdir(root, 0700); err != nil {
		return err
	}
	if err := os.Mkdir(root+"/accounts", 0700); err != nil {
		return err
	}
	principal, err := user.Lookup("phantowd")
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(principal.Uid)
	if err != nil || uid <= 0 {
		return errors.New("test principal UID refused")
	}
	gid, err := strconv.Atoi(principal.Gid)
	if err != nil || gid <= 0 {
		return errors.New("test principal GID refused")
	}
	if err := os.Chown(root+"/accounts", uid, gid); err != nil {
		return err
	}
	provisionAdmin := exec.CommandContext(ctx, api, "--provision-administrator")
	provisionAdmin.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}}
	if err := provision(ctx, provisionAdmin, root+"/accounts", credentials); err != nil {
		return fmt.Errorf("admin preparation: %w", err)
	}
	provisionPolicy := exec.CommandContext(ctx, api, "--provision-nas-policy", "--nas-installation-id", install)
	if err := provision(ctx, provisionPolicy, root, []byte(policy)); err != nil {
		return fmt.Errorf("policy preparation: %w", err)
	}
	return provisionCertificate(ctx)
}

func provision(ctx context.Context, cmd *exec.Cmd, directory string, input []byte) error {
	grant, err := os.Open(directory)
	if err != nil {
		return err
	}
	cmd.ExtraFiles = []*os.File{grant}
	cmd.Stdin = bytes.NewReader(input)
	cmd.Stderr = os.Stderr
	return errors.Join(cmd.Run(), grant.Close(), ctx.Err())
}

func provisionCertificate(ctx context.Context) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: big.NewInt(12), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	public := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pair := append(public, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})...)
	defer clear(pair)
	install := func(publicOrigin string) error {
		cmd := exec.CommandContext(ctx, api, "--provision-rc0-tls")
		cmd.Env = []string{"PHANTOWD_PUBLIC_ORIGIN=" + publicOrigin}
		return provision(ctx, cmd, root, pair)
	}
	identity := root + "/management-tls.pem"
	if err := install("https://localhost:18443"); err == nil || ctx.Err() != nil {
		return errors.New("TLS provisioning accepted a wrong origin or timed out")
	}
	if _, err := os.Stat(identity); !os.IsNotExist(err) {
		return errors.New("wrong origin left a TLS identity")
	}
	if err := install(origin); err != nil {
		return fmt.Errorf("TLS provisioning: %w", err)
	}
	if err := install(origin); err == nil || ctx.Err() != nil {
		return errors.New("TLS provisioning replaced an existing identity or timed out")
	}
	if info, err := os.Stat(identity); err != nil || info.Mode() != 0600 {
		return errors.New("TLS identity lacks private mode")
	}
	if raw, err := os.ReadFile(identity); err != nil || !bytes.Equal(raw, pair) {
		return errors.New("published TLS identity differs")
	}
	return nil
}

func command(ctx context.Context, confirmation string) (*exec.Cmd, error) {
	state, err := os.Open(root)
	if err != nil {
		return nil, err
	}
	grant, err := os.Open(confirmation)
	if err != nil {
		return nil, errors.Join(err, state.Close())
	}
	cmd := exec.CommandContext(ctx, api, "--supervise-rc0", "--nas-installation-id", install)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "PHANTOWD_LISTEN_ADDR=" + address, "PHANTOWD_PUBLIC_ORIGIN=" + origin}
	cmd.ExtraFiles = []*os.File{state, grant}
	return cmd, nil
}

func expectRefusal(ctx context.Context, confirmation string) error {
	cmd, err := command(ctx, confirmation)
	if err != nil {
		return err
	}
	output, err := cmd.CombinedOutput()
	if errors.Join(cmd.ExtraFiles[0].Close(), cmd.ExtraFiles[1].Close(), ctx.Err()) != nil || err == nil || !bytes.Contains(output, []byte("RC0 management startup or shutdown requires review")) {
		return errors.New("unexpected supervisor refusal evidence")
	}
	return runtimeAbsent()
}

func runtimeAbsent() error {
	if _, err := os.Lstat("/run/phantowd-rc0"); !os.IsNotExist(err) {
		return errors.New("RC0 runtime authority was retained")
	}
	return nil
}

func serve(ctx context.Context, credentials []byte) error {
	identity, err := os.ReadFile(root + "/management-tls.pem")
	if err != nil {
		return err
	}
	public, _ := pem.Decode(identity)
	roots := x509.NewCertPool()
	if public == nil || !roots.AppendCertsFromPEM(pem.EncodeToMemory(public)) {
		return errors.New("persistent certificate refused")
	}
	cmd, err := command(ctx, proof)
	if err != nil {
		return err
	}
	cmd.Stderr = os.Stderr
	startErr := cmd.Start()
	closeErr := errors.Join(cmd.ExtraFiles[0].Close(), cmd.ExtraFiles[1].Close())
	if startErr != nil {
		return errors.Join(startErr, closeErr)
	}
	joined := false
	defer func() {
		if !joined {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()
	if closeErr != nil {
		return closeErr
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	jar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, Jar: jar}
	ready := false
	for i := 0; i < 30; i++ {
		response, err := client.Get(origin + "/healthz")
		if err == nil {
			response.Body.Close()
			ready = response.StatusCode == 200
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		return errors.New("supervised HTTPS did not become ready")
	}
	request, err := http.NewRequest(http.MethodPost, origin+"/api/v1/auth/login", bytes.NewReader(credentials))
	if err != nil {
		return err
	}
	request.Header.Set("Origin", origin)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		return fmt.Errorf("secure login reply %d", response.StatusCode)
	}
	response, err = client.Get(origin + "/api/v1/nas-services/configuration")
	if err != nil {
		return err
	}
	var observed struct {
		Revision uint64
		Applied  bool
	}
	decodeErr := json.NewDecoder(response.Body).Decode(&observed)
	response.Body.Close()
	if response.StatusCode != 200 || decodeErr != nil || observed.Revision != 1 || observed.Applied {
		return fmt.Errorf("policy readback refused %d", response.StatusCode)
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		return err
	}
	err = cmd.Wait()
	joined = true
	return errors.Join(err, runtimeAbsent())
}
