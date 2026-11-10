//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"syscall"
	"time"
)

func exerciseQEMUNASBoot(phase string) error {
	if err := guardQEMUIdentityOwnerService(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if phase == "boot-missing" {
		uid, gid, err := qemuIdentityOwnerAPIIdentity()
		if err != nil {
			return err
		}
		cmd := exec.CommandContext(ctx, "/usr/bin/phantowd-api")
		cmd.Env = []string{"PHANTOWD_STATE_DIR=/run/phantowd-state", "PHANTOWD_NAS_POLICY_SOCKET=/run/phantowd-nas-policy-missing/channel",
			tlsCertFileEnv + "=" + nasBootRoot + "/cert.pem", tlsKeyFileEnv + "=" + nasBootRoot + "/key.pem"}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}}}
		output, err := cmd.CombinedOutput()
		if err == nil || ctx.Err() != nil || !bytes.Contains(output, []byte("NAS policy channel configuration is unavailable")) {
			return errors.New("missing provider did not refuse standard API startup")
		}
		fmt.Println("PHANTOWD_NAS_BOOT_MISSING_READY standard_main=true exit_nonzero=true no_fallback=true")
		return nil
	}
	public, err := os.ReadFile(nasBootRoot + "/cert.pem")
	pool := x509.NewCertPool()
	if err != nil || !pool.AppendCertsFromPEM(public) {
		return errors.New("boot TLS trust fixture unavailable")
	}
	h := &qemuNASMainHTTP{client: &http.Client{Timeout: 5 * time.Second, Jar: newQEMUCookieJar(),
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}, origin: "https://127.0.0.1:8443"}
	defer h.client.CloseIdleConnections()
	if err := waitQEMUAPIReady(h.client, h.origin); err != nil {
		return err
	}
	if err := h.request(ctx, nasStatePath, nil, 401, nil); err != nil {
		return err
	}
	if err := h.request(ctx, authSetupPath, setupRequest{Username: "qemu-boot", Password: rand.Text()}, 201, nil); err != nil {
		return err
	}
	var reply nasStateResponse
	if err := h.request(ctx, nasStatePath, nil, 200, &reply); err != nil {
		return err
	}
	if reply.Revision != 1 || reply.Configuration == nil || reply.Applied || reply.ActivationAvailable {
		return errors.New("boot API did not observe the root provider")
	}
	fmt.Println("PHANTOWD_NAS_BOOT_API_READY init=true nonroot=true https=verified authenticated=true config=provider scope=qemu-only")
	return nil
}
